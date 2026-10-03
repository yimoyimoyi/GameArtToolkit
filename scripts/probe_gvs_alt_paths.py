# -*- coding: utf-8 -*-
"""
googlevideo 替代通路探测 (只读, 不改任何配置)

目的: 回答"QUIC/IPv6 是唯一通路吗"——即「连接级失败」是否与**端口**或**传输**相关。
命中的 (端口/传输) 可以**立刻**变现为腿的 target_port / 传输选择, 不需要浏览器在环。

三个面:
  A. UDP 多端口 QUIC: 443(已知可用, 作为阳性对照) / 8443 / 80 / 8853 / 8080
  B. TCP + ALPN=h3: Google 边缘支持 "HTTP/3 over TCP" 变体; 若可用, 那是一条**平行通路**
     (也正好绕开"IPv6 TCP 在 TLS 握手中被 RST"那个现象 —— 如果它真能选到 h3)
  C. TCP + ALPN=h2: 已知结果(TCP 被压制), 作为阴性对照

用法: python -X utf8 scripts/probe_gvs_alt_paths.py [--timeout 6]
"""

import argparse
import socket
import ssl
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "app"))

QUIC_PORTS = (443, 8443, 80, 8853, 8080)

# 已知可用的 v6 地址 (阳性对照: 443 上应当命中 403 + gvs) 与判定失败的地址
CASES = [
    ("rr1---sn-p5qs7nd7", "2607:f8b0:4004:23::6", "可用(本次 A/B 8/8)"),
    ("rr1---sn-4g5edndy", "2a00:1450:4001:25::6", "可用(本次 A/B 8/8)"),
    ("rr4---sn-p5qs7nzr", "2607:f8b0:4004:19::9", "判死(本次 A/B 0/8)"),
]


def quic_on_port(ip: str, sni: str, port: int, timeout: float):
    """在指定 UDP 端口上跑一次 QUIC 握手; 返回 (ok, 说明)"""
    try:
        import asyncio

        from aioquic.asyncio.client import connect
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.quic.configuration import QuicConfiguration
    except Exception as e:
        return False, f"aioquic 缺失: {e}"

    async def go():
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                                verify_mode=ssl.CERT_NONE)
        cfg.server_name = sni
        async with connect(ip, port, configuration=cfg,
                           create_protocol=QuicConnectionProtocol,
                           wait_connected=True) as proto:
            return proto  # 能进到这里 = 握手完成

    try:
        asyncio.run(asyncio.wait_for(go(), timeout=timeout))
        return True, "QUIC 握手完成"
    except Exception as e:
        return False, f"{type(e).__name__}"


def tcp_alpn(ip: str, sni: str, alpn: list, timeout: float):
    """TCP:443 + TLS, 指定 ALPN; 返回 (协商到的协议, 说明)"""
    try:
        s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                          socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(alpn)
        ss = ctx.wrap_socket(s, server_hostname=sni)
        got = ss.selected_alpn_protocol()
        ss.close()
        return got, "TLS 完成"
    except Exception as e:
        return None, f"{type(e).__name__}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=6.0)
    args = ap.parse_args()

    print("=" * 78)
    print("A. UDP 多端口 QUIC (443 是阳性对照: 不通则本次测量无效)")
    print("=" * 78)
    print("%-22s %-24s %-30s" % ("节点", "地址", "各端口结果"))
    print("-" * 78)
    for node, ip, why in CASES:
        sni = f"{node}.googlevideo.com"
        cells = []
        for p in QUIC_PORTS:
            ok, note = quic_on_port(ip, sni, p, args.timeout)
            cells.append(f"{p}:{'OK' if ok else note[:9]}")
        print("%-22s %-24s %-30s  [%s]" % (node, ip, "  ".join(cells), why))
    print()
    print("=" * 78)
    print("B/C. TCP + ALPN=h3 (HTTP/3 over TCP) vs ALPN=h2 (阴性对照)")
    print("=" * 78)
    print("%-22s %-24s %-22s %-22s" % ("节点", "地址", "ALPN=h3", "ALPN=h2"))
    print("-" * 78)
    for node, ip, why in CASES:
        sni = f"{node}.googlevideo.com"
        got3, note3 = tcp_alpn(ip, sni, ["h3"], args.timeout)
        got2, note2 = tcp_alpn(ip, sni, ["h2", "http/1.1"], args.timeout)
        print("%-22s %-24s %-22s %-22s" % (
            node, ip,
            f"协商={got3}" if got3 else note3,
            f"协商={got2}" if got2 else note2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
