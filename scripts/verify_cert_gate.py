#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""候选池证书校验: 在"加 cert_families 门槛之前", 确认它**不会误杀整条池子**。

为什么必须有这一步 (2026-10-04):
    给画像加 `cert_families` 会让 `_cert_gate` 淘汰**证书域族不匹配**的候选。
    如果该画像的通道**设计上就打不到目标自己的证书** (实测反例: myanimelist 在
    Akamai 掩护 SNI 下拿到 `a248.e.akamai.net`; steam_akamai 拿到 `store.steampowered.com`),
    那么加门槛 = 静默把**全部好候选**判死 -> 服务从"可用"直接变"不可用"。
    这正是 `_cert_gate` 文档里警告的"误杀", 而它发生在探测阶段, 不会有 nginx 报错,
    只会表现为"这个服务突然全挂"。故加门槛前**必须**对现有候选池逐个实测。

用法:
    python scripts/verify_cert_gate.py --profile imgur
    python scripts/verify_cert_gate.py --profile imgur --families reddit.com   # 预演别的域族
    python scripts/verify_cert_gate.py --profile imgur --all-ips               # 校验整池而不是前 2 个

输出: 每个候选 IP 在**运行期真实 SNI** 下拿到的证书 SAN, 以及按给定域族的通过/淘汰判定。
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "app"))

from service_profile import PROFILES_BY_ID  # noqa: E402
import cover_sni  # noqa: E402

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
except Exception:  # pragma: no cover
    print("需要 cryptography 库", file=sys.stderr)
    raise SystemExit(2)


def pool_ips(sid: str) -> list:
    """从 app/pools.json 取该画像的当前候选池 (与运行期同一份来源)。"""
    try:
        d = json.loads((_ROOT / "app" / "pools.json").read_text(encoding="utf-8"))
    except Exception:
        return []
    for item in (d.get("pools") or []):
        if isinstance(item, dict) and item.get("pool_id") == sid:
            return [x for x in (item.get("entries") or []) if isinstance(x, str)]
    return []


def runtime_sni(p) -> tuple:
    """画像运行期真正会用的 SNI —— 与 nginx_generator / cover_sni 的判据一致。"""
    if p.ech_enabled or getattr(p, "h3_upstream", False):
        return "real(ECH/H3)", (list(p.domains)[0] if p.domains else None)
    if p.ssl_sni_mode == "empty":
        return "empty", None
    if p.ssl_sni_mode == "host":
        return "host", (list(p.domains)[0] if p.domains else None)
    return f"cover({p.ssl_sni_mode})", p.ssl_sni_mode


def probe(ip: str, sni):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    try:
        raw = socket.create_connection((ip, 443), timeout=10.0)
    except Exception as e:
        return False, f"TCP-FAIL {type(e).__name__}", []
    try:
        s = ctx.wrap_socket(raw, server_hostname=(sni or None))
    except Exception as e:
        try:
            raw.close()
        except Exception:
            pass
        return False, f"TLS-FAIL {str(e)[:60]}", []
    try:
        der = s.getpeercert(binary_form=True)
        san = []
        try:
            c = x509.load_der_x509_certificate(der)
            san = list(c.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
            if not san:
                san = [a.value for a in c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        except Exception:
            pass
        return True, "OK", san
    except Exception as e:
        return False, f"CERT-FAIL {type(e).__name__}", []
    finally:
        try:
            s.close()
        except Exception:
            pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True, help="画像 id")
    ap.add_argument("--families", default="", help="预演的域族 (逗号分隔); 省略则用画像已声明的")
    ap.add_argument("--all-ips", action="store_true", help="校验整池 (默认只前 2 个)")
    args = ap.parse_args()

    p = PROFILES_BY_ID.get(args.profile)
    if p is None:
        print(f"未知画像: {args.profile}", file=sys.stderr)
        return 2

    families = tuple(x.strip() for x in args.families.split(",") if x.strip()) \
        if args.families else tuple(p.cert_families or ())
    vendor = p.cdn_vendor or ""
    vendor_gate = bool(vendor and vendor in cover_sni.VENDOR_CERT_SUFFIXES)
    label, sni = runtime_sni(p)

    print("=" * 78)
    print(f"画像 {p.id}  group={p.group}")
    print(f"  mode={p.mode.value}  ech={p.ech_enabled}  h3={getattr(p,'h3_upstream',False)}")
    print(f"  运行期 SNI = {label}   (值: {sni!r})")
    print(f"  domains = {list(p.domains)[:6]}{' ...' if len(p.domains) > 6 else ''}")
    print(f"  cdn_vendor={vendor!r} (厂商门槛生效={vendor_gate})  cert_families={families}")
    print("=" * 78)

    ips = pool_ips(p.id) or list(p.candidate_ips or [])
    if not args.all_ips:
        ips = ips[:2]
    if not ips:
        print("!! 无候选 IP")
        return 1

    passed = failed = 0
    for ip in ips:
        ok, detail, san = probe(ip, sni)
        if not ok:
            print(f"  {ip:<18} {detail}")
            failed += 1
            continue
        fams = sorted({cover_sni._cert_family(s) for s in san})
        v_ok = cover_sni.cert_belongs_to_vendor(san, vendor) if vendor_gate else None
        f_ok = cover_sni.cert_matches_family(san, families) if families else None
        verdict = "PASS"
        if v_ok is False or f_ok is False:
            verdict = "REJECT"
            failed += 1
        else:
            passed += 1
        print(f"  {ip:<18} OK  SAN={san[:4]}")
        print(f"  {'':18} 域族={fams}  厂商门槛={v_ok}  域族门槛={f_ok}  -> {verdict}")

    print()
    print(f"结论: 通过 {passed} / 淘汰 {failed}")
    if failed and not passed:
        print("  ⇒ **危险**: 该门槛会淘汰整条池子 (服务将变不可用)。不要加。")
    elif failed:
        print("  ⇒ **部分淘汰**: 有候选会被丢弃, 需确认那是否是可接受的收紧。")
    else:
        print("  ⇒ **安全**: 现有候选全部通过, 加该门槛不会误杀。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
