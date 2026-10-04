# -*- coding: utf-8 -*-
"""
诊断: "探测报不可用、实际可用"的**根本原因与规模** (只读, 不改配置、不起加速)

假设 (由 googlevideo 上已定因的同一形态推广而来):
    本机对**部分 CDN 的 TCP/443 会被握手中 RST**, 而**同一个地址的 QUIC/UDP443 正常**。
    生产探测 (`probe_ip_endpoint_v2`) 只用 TCP → 这些服务被判不可用;
    而浏览器优先走 QUIC → 用户侧实际可用。

判据 (严格: 同一 IP、同一 host, 只换传输):
    TCP 失败 (RST/超时)  且  QUIC 拿到 HTTP 响应  ⇒ **确认的探测假阴性**
    两者都失败 ⇒ 该地址在本机确实不可达 (不计入误判)
    两者都成功 ⇒ 无问题

用法: python -X utf8 scripts/diag_tcp_vs_quic.py [--per-profile 2] [--json out.json]
"""

import argparse
import asyncio
import json
import socket
import ssl
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "app"))

from ip_pool import CANDIDATE_IPS     # noqa: E402
from service_profile import PROFILES  # noqa: E402


def tcp_tls(ip: str, host: str, timeout: float = 5.0):
    """TCP:443 + TLS。返回 (ok, 说明)。ok=True 表示 TLS 建立成功。"""
    try:
        s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                          socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        ss = ctx.wrap_socket(s, server_hostname=host)
        ss.close()
        return True, "TLS OK"
    except Exception as e:
        return False, type(e).__name__


def quic_http(ip: str, host: str, timeout: float = 8.0):
    """QUIC/UDP443 + HTTP/3。返回 (ok, 状态码, server/错误)。"""
    try:
        from aioquic.asyncio.client import connect
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.h3.connection import H3_ALPN, H3Connection
        from aioquic.h3.events import DataReceived, HeadersReceived
        from aioquic.quic.configuration import QuicConfiguration
    except Exception as e:
        return False, None, f"aioquic 缺失: {e}"

    st = {"status": None, "server": ""}

    class _P(QuicConnectionProtocol):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._h3 = H3Connection(self._quic)
            self.ev = asyncio.Event()

        def quic_event_received(self, e):
            for x in self._h3.handle_event(e):
                if isinstance(x, HeadersReceived):
                    for k, v in x.headers:
                        if k == b":status":
                            try:
                                st["status"] = int(v)
                            except Exception:
                                pass
                        elif k == b"server":
                            st["server"] = v.decode("latin-1")
                    self.ev.set()
                elif isinstance(x, DataReceived):
                    try:
                        self._h3.acknowledge_data(x.stream_id, x.data)
                    except Exception:
                        pass

        async def go(self):
            sid = self._quic.get_next_available_stream_id()
            self._h3.send_headers(sid, [
                (b":method", b"GET"), (b":scheme", b"https"),
                (b":authority", host.encode()), (b":path", b"/"),
                (b"user-agent", b"GameArtToolkit-diag"), (b"accept", b"*/*")],
                end_stream=True)
            self.transmit()

    async def run():
        cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                verify_mode=ssl.CERT_NONE)
        cfg.server_name = host
        async with connect(ip, 443, configuration=cfg,
                           create_protocol=_P, wait_connected=True) as pr:
            await pr.go()
            try:
                await asyncio.wait_for(pr.ev.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                pass
            return st

    try:
        r = asyncio.run(run())
        return r["status"] is not None, r["status"], r["server"]
    except Exception as e:
        return False, None, type(e).__name__


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-profile", type=int, default=1)
    ap.add_argument("--json", default=str(_ROOT / "scripts" / "diag_tcp_vs_quic.json"))
    args = ap.parse_args()

    rows = []
    print("%-22s %-18s %-14s %-14s %s" % ("画像", "IP", "TCP+TLS", "QUIC", "判定"))
    print("-" * 100)
    for p in PROFILES:
        ips = list(CANDIDATE_IPS.get(p.id) or getattr(p, "candidate_ips", None) or [])
        if not ips or getattr(p, "skip_cdn_probe", False):
            continue
        host = (getattr(p, "probe_domains", None) or p.domains or [""])[0]
        for ip in ips[:args.per_profile]:
            t_ok, t_note = tcp_tls(ip, host)
            q_ok, q_st, q_note = quic_http(ip, host)
            if not t_ok and q_ok:
                verdict = "★ 确认假阴性 (TCP 挂, QUIC 通)"
            elif not t_ok and not q_ok:
                verdict = "两者都不通 (本机确实不可达)"
            elif t_ok and not q_ok:
                verdict = "TCP 通, QUIC 不通"
            else:
                verdict = "都通"
            rows.append({"profile": p.id, "ip": ip, "host": host,
                         "tcp_ok": t_ok, "tcp_note": t_note,
                         "quic_ok": q_ok, "quic_status": q_st, "quic_note": q_note,
                         "verdict": verdict})
            print("%-22s %-18s %-14s %-14s %s" % (
                p.id, ip[:18], t_note if not t_ok else "OK",
                (str(q_st) if q_ok else q_note)[:14], verdict))

    fn = [r for r in rows if r["verdict"].startswith("★")]
    both_dead = [r for r in rows if r["verdict"].startswith("两者")]
    print()
    print("=" * 100)
    print(f"探测组合 {len(rows)} 个:")
    print(f"  ★ 确认假阴性 (TCP 挂 / QUIC 通): {len(fn)} 个, 涉及 {len({r['profile'] for r in fn})} 个画像")
    print(f"    两者都不通                     : {len(both_dead)} 个, 涉及 {len({r['profile'] for r in both_dead})} 个画像")
    print("=" * 100)
    Path(args.json).write_text(
        json.dumps({"rows": rows, "confirmed_false_negative": fn,
                    "both_dead": both_dead}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    print(f"明细已写入 {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
