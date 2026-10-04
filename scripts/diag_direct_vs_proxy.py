# -*- coding: utf-8 -*-
"""
诊断: 恒报错的图床/服务 —— **直连 vs 经本地代理 (Clash 7897)** 对照 (只读)

要回答的问题 (用户实测反馈):
  "部分恒错的服务是否为真实域名/服务不通, 还是我们的直连路径不通?"

方法 (同一 host、同一路径, 只换出网路径):
  A. 直连:   候选 IP 上直接 TLS (SNI=真实域名)
  B. 经代理: CONNECT 隧道 → 由代理侧解析并连接 → 隧道内 TLS (SNI=真实域名)
    ⇒ 代理路径**不依赖本机 DNS**, 因此同时回答"是否只是本机解析被投毒"。

判据:
  直连失败 + 代理成功 ⇒ **服务可用, 只是本机直连路径不通** (可修: 走 relay/代理上游)
  两者都失败         ⇒ 该服务/域名确实不可达 (或代理也到不了)

用法: python -X utf8 scripts/diag_direct_vs_proxy.py [--proxy 127.0.0.1:7897]
"""

import argparse
import socket
import ssl
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "app"))

from ip_pool import CANDIDATE_IPS       # noqa: E402
from service_profile import PROFILES_BY_ID  # noqa: E402

# 重点关注: 恒报错的图床 + 之前实测 RST/超时的服务
TARGETS = [
    ("ehentai_img", "ehgt.org", 443),
    ("nhentai_img", "i.nhentai.net", 443),
    ("nhentai_img", "t3.nhentai.net", 443),
    ("nhentai_img", "t.nhentai.net", 443),
    ("ehentai", "e-hentai.org", 443),
    ("nhentai", "nhentai.net", 443),
    ("pawchive", "pawchive.pw", 443),
    ("furaffinity", "www.furaffinity.net", 443),
    ("dlsite", "www.dlsite.com", 443),
    ("artstation_cdn", "cdna.artstation.com", 443),
    ("ehentai_img", "zdsadbt.lolowvmcdnxy.hath.network", 15443),
    # 对照: 已知正常的服务
    ("pypi", "pypi.org", 443),
    ("github_web", "github.com", 443),
]


def _read_status(ss, timeout: float = 8.0) -> str:
    """读到响应头结束再取状态行。

    ⚠ 为什么不能只 recv 一次 (实测踩到两个坑):
      ① 若允许协商 h2, 拿到的是**二进制帧**, 按文本读是乱码;
      ② 即便只协商 http/1.1, 状态行也可能被**拆到两个 TCP 段** —— 单次 recv(300)
         拿到空/半截, 于是打印出来的是"耗时"而不是状态码, 看起来像解析失败。
    """
    ss.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        c = ss.recv(4096)
        if not c:
            break
        buf += c
    if not buf:
        return "(无响应)"
    return buf.split(b"\r\n", 1)[0].decode("latin-1", "replace") or "(空状态行)"


def direct_tls(ip: str, host: str, port: int, timeout: float = 7.0):
    """A. 直连指定 IP (SNI=真实域名)。返回 (ok, status_line, note)"""
    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                          socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        ss = ctx.wrap_socket(s, server_hostname=host)
        ss.sendall((f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                    f"User-Agent: Mozilla/5.0 GameArtToolkit-diag\r\n"
                    f"Connection: close\r\n\r\n").encode())
        line = _read_status(ss)
        ss.close()
        return True, line, "%.0fms" % ((time.time() - t0) * 1000)
    except Exception as e:
        return False, "", "%s (%.0fms)" % (type(e).__name__, (time.time() - t0) * 1000)


def proxy_tls(proxy_host: str, proxy_port: int, host: str, port: int,
              timeout: float = 12.0):
    """B. 经 CONNECT 隧道连 host:port —— 由代理侧解析, 不依赖本机 DNS。

    这一步同时排除了"本机解析被投毒"这个变量: 目标由代理侧解析。
    """
    t0 = time.time()
    s = None
    try:
        s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall((f"CONNECT {host}:{port} HTTP/1.1\r\n"
                   f"Host: {host}:{port}\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = s.recv(4096)
            if not c:
                break
            buf += c
        first = buf.split(b"\r\n")[0].decode("latin-1", "replace")
        if " 200" not in first:
            s.close()
            return False, first, "CONNECT 被拒"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        ss = ctx.wrap_socket(s, server_hostname=host)
        ss.sendall((f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                    f"User-Agent: Mozilla/5.0 GameArtToolkit-diag\r\n"
                    f"Connection: close\r\n\r\n").encode())
        line = _read_status(ss)
        ss.close()
        return True, line, "%.0fms" % ((time.time() - t0) * 1000)
    except Exception as e:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
        return False, "", "%s (%.0fms)" % (type(e).__name__, (time.time() - t0) * 1000)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy", default="127.0.0.1:7897")
    ap.add_argument("--json", default=str(_ROOT / "scripts" / "diag_direct_vs_proxy.json"))
    args = ap.parse_args()
    ph, _, pp = args.proxy.partition(":")
    pp = int(pp or 7897)

    print(f"代理: {ph}:{pp}   (经 CONNECT 隧道, 目标由代理侧解析)")
    print()
    print("%-16s %-22s %-7s %-30s %-30s %s" % (
        "画像", "域名", "端口", "直连 (候选IP / SNI=真域名)", "经代理", "判定"))
    print("-" * 132)
    rows = []
    for sid, host, port in TARGETS:
        ips = list(CANDIDATE_IPS.get(sid) or [])
        d_ok, d_line, d_note = (False, "", "无候选IP")
        d_ip = ips[0] if ips else ""
        if d_ip:
            d_ok, d_line, d_note = direct_tls(d_ip, host, port)
        p_ok, p_line, p_note = proxy_tls(ph, pp, host, port)

        if not d_ok and p_ok:
            verdict = "★ 服务可用, 只是本机直连不通"
        elif d_ok and not p_ok:
            verdict = "直连通, 代理不通"
        elif d_ok and p_ok:
            verdict = "两条都通"
        else:
            verdict = "两条都不通 (确不可达)"
        rows.append({"profile": sid, "host": host, "port": port, "direct_ip": d_ip,
                     "direct_ok": d_ok, "direct_line": d_line, "direct_note": d_note,
                     "proxy_ok": p_ok, "proxy_line": p_line, "proxy_note": p_note,
                     "verdict": verdict})
        print("%-16s %-22s %-7s %-30s %-30s %s" % (
            sid, host, port,
            (d_line or d_note)[:30],
            (p_line or p_note)[:30],
            verdict))

    fixed = [r for r in rows if r["verdict"].startswith("★")]
    print()
    print("=" * 132)
    print(f"★ 本机直连不通、但经代理可用: **{len(fixed)} 条** "
          f"(涉及 {len({r['profile'] for r in fixed})} 个画像)")
    print("=" * 132)
    Path(args.json).write_text(json_dumps({"rows": rows, "fixable_via_proxy": fixed}),
                               encoding="utf-8")
    print(f"明细已写入 {args.json}")
    return 0


def json_dumps(o) -> str:
    import json
    return json.dumps(o, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    raise SystemExit(main())
