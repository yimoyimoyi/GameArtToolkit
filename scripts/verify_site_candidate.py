#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""单站接入前验证器: 回答"这个站能不能接、该用哪条通道"。

用法:
    python scripts/verify_site_candidate.py hlib.cc
    python scripts/verify_site_candidate.py hlib.cc --path /n

它把项目现有的通道判据按顺序实测一遍, 输出一份可直接据以决策的报告:

  1. 解析层  —— DoH(1.1.1.1/8.8.8.8) 干净 IP vs 系统解析。两者不一致说明被投毒,
                该站才需要"钉 IP"(DIRECT)。同时用 `ech_tunnel.is_cloudflare_ip` 判是否在
                CF 网段 —— 在则 ECH 隧道是候选通道。
  2. TCP     —— 443 是否可达 (区分"IP 不可达"与"SNI 被阻断")。
  3. TLS     —— 真 SNI / 空 SNI / 掩护 SNI 各试一次, 读证书 SAN。
                · 真 SNI 通 + 证书属目标域  -> L7(host) 或 DIRECT 均可
                · 真 SNI RST + 空 SNI 通    -> "空 SNI + cert_families" 通道
                · 真 SNI RST + 空 SNI 也 RST -> 只能 ECH / 掩护 SNI
  4. HTTP    —— 对可握手的组合发真实 GET, 记状态码/字节数/关键响应头
                (`cf-mitigated` 出现即说明 CF 挑战 -> **不得接入**, 挑战页会被判成可用)。
  5. 判决    —— 依据上述证据给出建议通道, 并列出"必须由人确认"的点。

**本脚本不写任何文件、不改任何配置** —— 它只产出证据与建议, 决定由人做。
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import urllib.request
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "app"))

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False

try:
    from ech_tunnel import is_cloudflare_ip
except Exception:  # pragma: no cover
    def is_cloudflare_ip(ip):  # type: ignore
        return None

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


def doh_a(host: str) -> list:
    """DoH 取 A 记录 —— 绕开本机可能被投毒的解析。"""
    for url in (f"https://1.1.1.1/dns-query?name={host}&type=A",
                f"https://8.8.8.8/resolve?name={host}&type=A"):
        try:
            req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
            j = json.loads(urllib.request.urlopen(req, timeout=8).read())
            ips = [a["data"] for a in j.get("Answer", []) if a.get("type") == 1]
            if ips:
                return ips
        except Exception:
            pass
    return []


def doh_aaaa(host: str) -> list:
    for url in (f"https://1.1.1.1/dns-query?name={host}&type=AAAA",
                f"https://8.8.8.8/resolve?name={host}&type=AAAA"):
        try:
            req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
            j = json.loads(urllib.request.urlopen(req, timeout=8).read())
            ips = [a["data"] for a in j.get("Answer", []) if a.get("type") == 28]
            if ips:
                return ips
        except Exception:
            pass
    return []


def system_a(host: str) -> list:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443, socket.AF_INET)})
    except Exception:
        return []


def handshake(ip: str, sni, port: int = 443, timeout: float = 10.0):
    """返回 (ok, detail, cn, san, tls_version)"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except Exception as e:
        return False, f"TCP-FAIL {type(e).__name__}", [], [], ""
    try:
        s = ctx.wrap_socket(raw, server_hostname=(sni or None))
    except Exception as e:
        try:
            raw.close()
        except Exception:
            pass
        return False, f"TLS-FAIL {str(e)[:80]}", [], [], ""
    try:
        der = s.getpeercert(binary_form=True)
        cn, san = [], []
        if _HAVE_CRYPTO and der:
            c = x509.load_der_x509_certificate(der)
            cn = [a.value for a in c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
            try:
                san = list(c.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
            except Exception:
                pass
        return True, "OK", cn, san, s.version()
    except Exception as e:
        return False, f"CERT-FAIL {type(e).__name__}", [], [], ""
    finally:
        try:
            s.close()
        except Exception:
            pass


def http_get(ip: str, host: str, path: str, sni_mode: str, port: int = 443,
             timeout: float = 12.0):
    """在已确定可握手的组合上发真实 GET, 返回 (status, bytes, headers)"""
    if sni_mode == "empty":
        sni = None
    elif sni_mode == "host":
        sni = host
    else:
        sni = sni_mode
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    try:
        s = ctx.wrap_socket(socket.create_connection((ip, port), timeout=timeout),
                            server_hostname=sni)
    except Exception as e:
        return None, 0, {"error": f"{type(e).__name__}: {e}"}
    try:
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n"
               "Accept: text/html,application/xhtml+xml,*/*\r\nConnection: close\r\n\r\n")
        s.sendall(req.encode())
        buf = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            buf += c
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status = lines[0].decode("latin1") if lines else "(no response)"
        hdrs = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, _, v = ln.partition(b":")
                hdrs[k.decode("latin1").strip().lower()] = v.decode("latin1").strip()
        return status, len(body), hdrs
    except Exception as e:
        return None, 0, {"error": f"{type(e).__name__}: {e}"}
    finally:
        try:
            s.close()
        except Exception:
            pass


def fam(host: str) -> str:
    p = [x for x in str(host).lower().split(".") if x]
    return ".".join(p[-2:]) if len(p) >= 2 else host


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("host", help="目标主机名, 如 hlib.cc")
    ap.add_argument("--path", default="/", help="要 GET 的路径 (默认 /)")
    ap.add_argument("--apex", default="", help="另测的 apex 域 (默认自动从 host 推)")
    args = ap.parse_args()

    host = args.host.strip().lower()
    print("=" * 78)
    print(f"接入前验证: {host}   path={args.path}")
    print("=" * 78)

    # ---- 1. 解析层 ----
    v4 = doh_a(host)
    v6 = doh_aaaa(host)
    sysv4 = system_a(host)
    print("\n[1] 解析层")
    print(f"    DoH  A    : {v4}")
    print(f"    DoH  AAAA : {v6[:4]}{' ...' if len(v6) > 4 else ''}")
    print(f"    系统 A    : {sysv4}")
    cf = {ip: is_cloudflare_ip(ip) for ip in v4}
    print(f"    CF 网段?  : {cf}")
    poisoned = bool(sysv4 and v4 and not (set(sysv4) & set(v4)))
    print(f"    解析被投毒: {'是 (系统解析与 DoH 无交集)' if poisoned else '否/未知'}")

    ips = v4 or sysv4
    if not ips:
        print("\n!! 无任何可用 IPv4 地址, 无法继续")
        return 1

    # ---- 2/3. TCP + TLS 三种 SNI ----
    print("\n[2/3] TCP 与 TLS (真 SNI / 空 SNI / 掩护 SNI)")
    combos = [("host", host), ("empty", None), ("cover", "www.fastly.com"),
              ("cover", "steambroadcast.akamaized.net")]
    results = {}
    for ip in ips[:3]:
        print(f"    -- {ip}")
        for label, sni in combos:
            if label == "cover" and sni in [c[1] for c in combos if c[0] == "cover"][:0]:
                pass
            ok, detail, cn, san, ver = handshake(ip, sni)
            key = (ip, label if label != "cover" else f"cover:{sni}")
            results[key] = (ok, detail, cn, san)
            tag = f"{label if label!='cover' else 'cover='+str(sni)}"
            if ok:
                hit = fam(host) in {fam(s) for s in san} if san else False
                print(f"       {tag:<40} {detail:<8} CN={cn} SAN={san[:3]} "
                      f"目标族命中={hit}")
            else:
                print(f"       {tag:<40} {detail}")

    # ---- 4. HTTP ----
    print("\n[4] HTTP 真实 GET (仅在可握手的组合上)")
    good = [(k, v) for k, v in results.items() if v[0]]
    http_rows = []
    for (ip, label), _ in good[:6]:
        mode = "empty" if label == "empty" else ("host" if label == "host" else label.split(":", 1)[1])
        st, n, hd = http_get(ip, host, args.path, mode)
        http_rows.append({"ip": ip, "sni": label, "status": st, "bytes": n,
                          "cf_mitigated": hd.get("cf-mitigated", ""),
                          "server": hd.get("server", ""),
                          "location": hd.get("location", ""),
                          "content_type": hd.get("content-type", "")})
        print(f"    {ip:<18} {label:<26} {st}  bytes={n}")
        for k in ("server", "content-type", "location", "cf-mitigated", "cf-ray"):
            if k in hd:
                print(f"        {k}: {hd[k]}")
        if "error" in hd:
            print(f"        error: {hd['error']}")

    # ---- 5. 判决 ----
    print("\n[5] 建议")
    any_ok = any(r["status"] for r in http_rows)
    challenge = any(r.get("cf_mitigated") for r in http_rows)
    real_ok = any(k[1] == "host" and v[0] for k, v in results.items())
    empty_ok = any(k[1] == "empty" and v[0] for k, v in results.items())
    cover_ok = any(str(k[1]).startswith("cover") and v[0] for k, v in results.items())
    cert_hit = any(fam(host) in {fam(s) for s in v[3]} for k, v in results.items() if v[0] and v[3])

    print(f"    真 SNI 可握手: {real_ok} | 空 SNI 可握手: {empty_ok} | 掩护 SNI 可握手: {cover_ok}")
    print(f"    证书含目标域族({fam(host)}): {cert_hit}")
    print(f"    拿到 HTTP 响应: {any_ok} | 出现 CF 挑战: {challenge}")
    if challenge:
        print("    ⇒ **不得接入**: 命中 CF 托管挑战, 挑战页会被判成可用 (项目红线)")
    elif any(v for k, v in cf.items() if v is True) and not real_ok:
        print("    ⇒ 候选通道: **ECH 隧道** (地址在 CF 网段, 且真 SNI 不可用)")
    elif real_ok and cert_hit:
        print("    ⇒ 候选通道: **L7(host) 或 DIRECT** (真 SNI 可用且证书是目标自己的)")
    elif empty_ok and not real_ok:
        print("    ⇒ 候选通道: **空 SNI + cert_families** (真 SNI 被阻断, 空 SNI 可握手)")
    elif cover_ok and not real_ok:
        print("    ⇒ 候选通道: **掩护 SNI** (需实测证书是否仍属目标域)")
    else:
        print("    ⇒ 证据不足, 需人工判断")
    if poisoned:
        print("    ⚠ 解析被投毒 ⇒ 若走 DIRECT/L7, 必须把干净 IP 钉进候选池")
    print("\n    必须由人确认的点: 内容级可用性 (根路径 200 不等于服务可用; "
          "建议改用真实内容路径再验一次 --path)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
