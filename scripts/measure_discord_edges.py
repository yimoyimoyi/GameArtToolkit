#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""实测 Discord"该用哪个边缘" —— 对比候选池里的地址 vs 各主机 DoH 真实地址。

背景 (2026-10-04, 用户报告"测速龟速加载但理论上能用"):
    `discord` 画像的 candidate_ips 只有 `162.159.137.232` / `162.159.136.232`
    (那是 **discord.com apex** 的地址), 而 ECH 隧道把它按 host 指派给全部 11 个主机,
    包括 `cdn.discordapp.com` (**图床/附件, 页面重量的大头**) 与 `gateway.discord.gg`
    (长连接网关) —— 而这两个主机在 DoH 里有**各自不同的 CF 段**:
        cdn.discordapp.com -> 162.159.129/130/133/134/135.233
        gateway.discord.gg -> 162.159.130/133/134/135/136.234

    本脚本对同一主机分别用"池里的地址"与"它自己的地址"发同样的真实请求, 对比
    TLS 握手时延与首字节, 用数据判断"换地址"是否真的能改善。

用法:
    python scripts/measure_discord_edges.py
"""
from __future__ import annotations

import json
import socket
import ssl
import statistics
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

# 池里现有的两个地址 (discord.com apex)
POOL = ["162.159.137.232", "162.159.136.232"]


def doh_a(host: str):
    for ep in (f"https://doh.pub/dns-query?name={host}&type=A",
               f"https://223.5.5.5/resolve?name={host}&type=A"):
        try:
            j = json.loads(urllib.request.urlopen(
                urllib.request.Request(ep, headers={"accept": "application/dns-json"}),
                timeout=8).read())
            ips = [a["data"] for a in j.get("Answer", []) if a.get("type") == 1]
            if ips:
                return ips
        except Exception:
            pass
    return []


def measure(ip: str, host: str, path: str = "/", rounds: int = 3):
    """返回 (tls_ms列表, ttfb_ms列表, status, bytes) —— 空 SNI (隧道对 CF 的做法)"""
    tls, ttfb, status, blen = [], [], None, 0
    for _ in range(rounds):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
        try:
            t0 = time.perf_counter()
            # 隧道对 CF 用的是 ECH/空 SNI 形态; 这里用空 SNI 复现"能否到达 + TTFB"
            s = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=10),
                                server_hostname=None)
            tls.append((time.perf_counter() - t0) * 1000)
        except Exception:
            continue
        try:
            s.settimeout(15)
            t0 = time.perf_counter()
            s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                       "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 Chrome/120 Safari/537.36\r\n"
                       "Accept: */*\r\nConnection: close\r\n\r\n").encode())
            buf = b""
            while len(buf) < 65536:
                c = s.recv(8192)
                if not c:
                    break
                buf += c
            if not ttfb:
                ttfb.append((time.perf_counter() - t0) * 1000)
            if status is None and buf:
                status = buf.split(b"\r\n", 1)[0].decode("latin1")
            blen = max(blen, len(buf))
            s.close()
        except Exception:
            try:
                s.close()
            except Exception:
                pass
    return tls, ttfb, status, blen


def main() -> int:
    targets = [
        ("discord.com", "/"),
        ("cdn.discordapp.com", "/attachments/0/0/x.png"),
        ("media.discordapp.net", "/"),
        ("gateway.discord.gg", "/"),
    ]
    print(f"{'host':<24} {'address':<18} {'来源':<10} {'tls中位':>8} {'ttfb':>8}  status")
    print("-" * 92)
    summary = []
    for host, path in targets:
        own = doh_a(host)
        rows = []
        for ip, src in ([(i, "池内") for i in POOL] + [(i, "自身DoH") for i in own[:3]]):
            tls, ttfb, status, blen = measure(ip, host, path, rounds=3)
            med = statistics.median(tls) if tls else -1
            ft = ttfb[0] if ttfb else -1
            print(f"{host:<24} {ip:<18} {src:<10} {med:>8.0f} {ft:>8.0f}  {status or '(无响应)'}")
            rows.append((ip, src, med, ft, status))
        summary.append((host, rows))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
