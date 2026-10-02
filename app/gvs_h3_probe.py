# -*- coding: utf-8 -*-
"""
GameArt Toolkit - googlevideo (YouTube 视频流) 的 HTTP/3 通道可用性探针

为什么需要这个模块 (2026-10-01 实测):
  googlevideo 是唯一**无法**走 L7+掩护SNI 的域 —— 经中转 IP 请求 /videoplayback 时上游回
  `Bandaid Misdirected Traffic Server` (Google 明确回"打错服务器"), 而真实 IPv6 节点的
  TCP 侧被压制。唯一到达真视频服务 (Server: gvs 1.0) 的通道是:
      HTTP/3 + IPv6 真实节点 + SNI=真实节点名

  但该通道**不是常量, 而是强时变的**。2026-10-01 同一小时内实测:
      22:20 窗口:  QUIC 5/5 命中 gvs 1.0, 112~619ms
      22:52 窗口:  4 种 (SNI, :authority) 组合全部 4/4 命中
      22:55 窗口:  交错 5 轮 × 4 组合 = 2/20
      23:0x 窗口:  交错 3 轮: 对照组 12/12 正常, googlevideo 各节点 1/9
  即**分钟级的 0% ↔ 100% 抖动**。

  因此"能不能用"必须作为**运行时状态**测量, 不能当作一次性结论写进画像 ——
  否则就是项目明令禁止的"假可用": 登记一个时而能播、时而转圈的服务。

本模块的定位 = **上线闸门**: 只有它判定通道稳定可用时, 才允许把 googlevideo 登记进
PROFILES。它同时做**控制组自检** —— 控制组不通时必须归因为"客户端/网络异常",
而不是错怪目标站 (这正是之前用被投毒的系统解析当控制组、误判成"客户端问题"的教训)。

判据分层:
  控制组不通            → CLIENT_BROKEN  (不评价目标, 先修本机)
  目标命中率 >= 0.8     → OK
  命中率 >= 0.3         → FLAKY         (可试播, 但不得作为默认通路)
  命中率 > 0            → UNSTABLE      (基本不可用)
  命中率 == 0           → BLOCKED
"""

import json
import ssl
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

# 版本前置检查 (与 cert_manager / quic_probe 一致)
if sys.version_info < (3, 10):
    sys.stderr.write(
        f"\n[错误] 需要 Python 3.10 及以上, 当前为 {sys.version.split()[0]}。\n"
        f"       当前解释器: {sys.executable}\n\n")
    raise SystemExit(2)

sys.path.insert(0, str(Path(__file__).resolve().parent))

DEFAULT_TIMEOUT = 6.0
DEFAULT_ROUNDS = 3

# 判定阈值 (命中率)
OK_THRESHOLD = 0.8
FLAKY_THRESHOLD = 0.3

# 期望的 Server 指纹 —— 真 Google Video Server 自报 "gvs 1.0";
# "打错服务器"的兜底服务自报 "Bandaid Misdirected Traffic Server" (必须区分!)
GVS_SERVER_MARK = "gvs"
BANDAID_MARK = "bandaid"

# 控制组: 项目候选池里已验证的 h3 站点 (用它证明"本机 h3 栈 + 网络"是好的)
# 刻意不用系统解析取 IP —— 实测系统解析对 reddit/discord 返回 Facebook 段投毒地址,
# 用投毒 IP 当控制组会把"目标被压制"误判成"客户端故障"。
DEFAULT_CONTROLS: List[Dict[str, str]] = [
    {"label": "cdn.jsdelivr.net(CF)", "ip": "104.17.208.5", "host": "cdn.jsdelivr.net",
     "path": "/npm/three@0.160.0/build/three.module.js"},
    {"label": "unpkg(CF)", "ip": "104.18.0.22", "host": "unpkg.com",
     "path": "/react@18.2.0/package.json"},
    {"label": "www.reddit.com(Fastly)", "ip": "199.232.161.140", "host": "www.reddit.com",
     "path": "/"},
]


# --------------------------------------------------------------------------- 纯逻辑 (可单测)
def classify_channel(total: int, ok: int) -> str:
    """按命中率给出通道状态 (纯函数, 便于单测)"""
    if total <= 0:
        return "NO_DATA"
    rate = ok / total
    if rate >= OK_THRESHOLD:
        return "OK"
    if rate >= FLAKY_THRESHOLD:
        return "FLAKY"
    if rate > 0:
        return "UNSTABLE"
    return "BLOCKED"


def is_gvs_response(status: Optional[int], server: str) -> bool:
    """是否命中**真视频服务**

    必须排除 Bandaid: 它也回 404/204, 容易被误当成"路由成立"。
    """
    if not status:
        return False
    srv = (server or "").lower()
    if BANDAID_MARK in srv:
        return False
    return GVS_SERVER_MARK in srv


def verdict(channel: str, control_ok: bool) -> Dict[str, str]:
    """综合判定 (纯函数): 控制组不通时不得归罪于目标"""
    if not control_ok:
        return {"state": "CLIENT_BROKEN",
                "advice": "控制组(已验证 h3 站点)也不通 —— 属本机/网络侧问题, 先修本机再评目标"}
    table = {
        "OK": ("可用", "可作为 QUIC 上游腿启用"),
        "FLAKY": ("不稳定", "命中率偏低, 不得作为默认通路; 需重试+熔断兜底"),
        "UNSTABLE": ("基本不可用", "命中率过低, 不应登记 (会造出假可用)"),
        "BLOCKED": ("不可用", "当前完全不可达, 不得登记"),
        "NO_DATA": ("无数据", "未取得任何结果"),
    }
    state, advice = table.get(channel, ("未知", ""))
    return {"state": state, "advice": advice}


def build_targets(ips: Sequence[str], node: str = "rr1---sn-i3b7kns6",
                  host_suffix: str = "googlevideo.com") -> List[Dict[str, str]]:
    """生成 googlevideo 探测目标 (SNI 与 :authority 均取真实节点名)

    为什么 SNI 用真实节点名而非别名域: 2026-10-01 交错实测四种 (SNI, :authority) 组合,
    在排除时间相关后**没有一种组合有稳定的因果优势** —— 单次观测出的"B 组合恒失败"
    经交错复测被证伪。既然无差异, 就用语义最正确的形态 (两者都等于请求的真实主机名)。
    """
    return [{"label": f"{node}@{ip}", "ip": ip, "host": f"{node}.{host_suffix}",
             "path": "/videoplayback?test=1"} for ip in ips]


# --------------------------------------------------------------------------- 网络执行
def _h3_request(ip: str, sni: str, authority: str, path: str,
                timeout: float) -> Dict[str, Any]:
    """执行一次真实 HTTP/3 请求, 返回状态与 Server 指纹 (aioquic 缺失时如实上报)"""
    try:
        import asyncio

        import ssl as _ssl

        from aioquic.asyncio.client import connect
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.h3.connection import H3_ALPN, H3Connection
        from aioquic.h3.events import DataReceived, HeadersReceived
        from aioquic.quic.configuration import QuicConfiguration
    except Exception as e:
        return {"ok": False, "status": None, "server": "", "bytes": 0,
                "error": f"缺少 aioquic: {e}"}

    st = {"status": None, "server": "", "bytes": 0}

    class _Probe(QuicConnectionProtocol):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._h3 = H3Connection(self._quic)
            self.headers_ready = asyncio.Event()

        def quic_event_received(self, event):
            for ev in self._h3.handle_event(event):
                if isinstance(ev, HeadersReceived):
                    for k, v in ev.headers:
                        if k == b":status":
                            try:
                                st["status"] = int(v)
                            except Exception:
                                pass
                        elif k == b"server":
                            st["server"] = v.decode("latin-1")
                    self.headers_ready.set()
                elif isinstance(ev, DataReceived):
                    st["bytes"] += len(ev.data)
                    try:
                        self._h3.acknowledge_data(ev.stream_id, ev.data)
                    except Exception:
                        pass

        async def send(self):
            sid = self._quic.get_next_available_stream_id()
            self._h3.send_headers(sid, [
                (b":method", b"GET"), (b":scheme", b"https"),
                (b":authority", authority.encode()), (b":path", path.encode()),
                (b"user-agent", b"GameArtToolkit/h3-probe"),
                (b"accept", b"*/*")], end_stream=True)
            self.transmit()

    async def _run():
        cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                verify_mode=_ssl.CERT_NONE)
        cfg.server_name = sni
        # aioquic 默认 idle_timeout 60s: 遇到静默丢包会白等到超时, 必须压到探测预算同量级
        cfg.idle_timeout = max(3.0, min(float(timeout), 15.0))
        t0 = time.perf_counter()
        try:
            async with connect(ip, 443, configuration=cfg, create_protocol=_Probe,
                               wait_connected=True) as client:
                hs = round((time.perf_counter() - t0) * 1000, 1)
                await client.send()
                try:
                    await asyncio.wait_for(client.headers_ready.wait(), timeout=timeout)
                except asyncio.TimeoutError:
                    pass
                return {"ok": st["status"] is not None, "status": st["status"],
                        "server": st["server"], "bytes": st["bytes"],
                        "hs_ms": hs, "error": "" if st["status"] else "no_response"}
        except Exception as e:
            return {"ok": False, "status": None, "server": "", "bytes": 0,
                    "hs_ms": None, "error": type(e).__name__}

    try:
        return asyncio.run(_run())
    except Exception as e:
        return {"ok": False, "status": None, "server": "", "bytes": 0,
                "error": f"{type(e).__name__}: {e}"}


def probe_targets(targets: Sequence[Dict[str, str]], rounds: int = DEFAULT_ROUNDS,
                  timeout: float = DEFAULT_TIMEOUT,
                  require_gvs: bool = True) -> List[Dict[str, Any]]:
    """对一组目标做多轮 HTTP/3 探测, 逐目标统计命中率"""
    out: List[Dict[str, Any]] = []
    for t in targets:
        hits, attempts = 0, 0
        servers: Dict[str, int] = {}
        errs: Dict[str, int] = {}
        best_ms = None
        for _ in range(max(1, rounds)):
            attempts += 1
            r = _h3_request(t["ip"], t["host"], t["host"], t.get("path", "/"), timeout)
            srv = r.get("server") or ""
            if srv:
                servers[srv] = servers.get(srv, 0) + 1
            if r.get("ok"):
                good = is_gvs_response(r["status"], srv) if require_gvs else True
                if good:
                    hits += 1
                    if r.get("hs_ms") and (best_ms is None or r["hs_ms"] < best_ms):
                        best_ms = r["hs_ms"]
            else:
                e = r.get("error") or "?"
                errs[e] = errs.get(e, 0) + 1
        out.append({"label": t["label"], "ip": t["ip"], "host": t["host"],
                    "attempts": attempts, "hits": hits,
                    "channel": classify_channel(attempts, hits),
                    "servers": servers, "errors": errs, "best_hs_ms": best_ms})
    return out


def probe_controls(controls: Optional[Sequence[Dict[str, str]]] = None,
                   rounds: int = DEFAULT_ROUNDS, timeout: float = DEFAULT_TIMEOUT
                   ) -> Dict[str, Any]:
    """控制组自检: 用已验证的 h3 站点证明"本机 h3 栈 + 网络"可用"""
    ctrls = list(controls if controls is not None else DEFAULT_CONTROLS)
    results, hits, total = [], 0, 0
    for c in ctrls:
        ok = 0
        for _ in range(max(1, rounds)):
            total += 1
            r = _h3_request(c["ip"], c["host"], c["host"], c.get("path", "/"), timeout)
            if r.get("ok"):
                ok += 1
        hits += ok
        results.append({"label": c["label"], "ip": c["ip"], "ok": ok,
                        "attempts": max(1, rounds)})
    return {"ok": classify_channel(total, hits) == "OK", "hit": hits, "total": total,
            "channel": classify_channel(total, hits), "details": results}


def run_check(ips: Sequence[str], node: str = "rr1---sn-i3b7kns6",
              rounds: int = DEFAULT_ROUNDS, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """完整检查: 控制组 + 目标, 给出可否上线的判定"""
    ctrl = probe_controls(rounds=rounds, timeout=timeout)
    targets = probe_targets(build_targets(ips, node), rounds=rounds, timeout=timeout)
    hits = sum(t["hits"] for t in targets)
    total = sum(t["attempts"] for t in targets)
    channel = classify_channel(total, hits)
    v = verdict(channel, ctrl["ok"])
    return {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "node": node,
            "channel": channel, "hit": hits, "total": total,
            "control": ctrl, "targets": targets,
            "state": v["state"], "advice": v["advice"],
            "enable_allowed": bool(ctrl["ok"] and channel == "OK")}


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        description="googlevideo (YouTube 视频流) HTTP/3 通道可用性探针")
    ap.add_argument("--ips", default="2404:6800:4005:a::6,2404:6800:4009:80b::6,"
                                    "2404:6800:4008:c07::6",
                    help="候选 IPv6 节点 (逗号分隔)")
    ap.add_argument("--node", default="rr1---sn-i3b7kns6", help="googlevideo 节点名")
    ap.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    ap.add_argument("--no-control", action="store_true", help="跳过控制组自检")
    args = ap.parse_args(argv)

    ips = [s.strip() for s in args.ips.split(",") if s.strip()]
    if args.no_control:
        tg = probe_targets(build_targets(ips, args.node), args.rounds, args.timeout)
        rep = {"targets": tg, "channel": classify_channel(
            sum(t["attempts"] for t in tg), sum(t["hits"] for t in tg))}
    else:
        rep = run_check(ips, args.node, args.rounds, args.timeout)

    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0 if rep.get("enable_allowed") else 1

    if "control" in rep:
        c = rep["control"]
        print(f"控制组自检: {c['hit']}/{c['total']} ({c['channel']}) "
              f"{'✅ 本机 h3 正常' if c['ok'] else '❌ 本机/网络异常'}")
        for d in c["details"]:
            print(f"    {d['label']:28s} {d['ok']}/{d['attempts']}")
        print()
    print(f"googlevideo 节点探测 (SNI=:authority=真实节点名, {args.rounds} 轮/节点):")
    for t in rep["targets"]:
        svr = ",".join(t["servers"]) or "-"
        err = ",".join(f"{k}×{v}" for k, v in t["errors"].items()) or "-"
        print(f"    {t['label']:34s} 命中 gvs {t['hits']}/{t['attempts']}  "
              f"Server={svr[:26]:28s} 错误={err[:22]:24s} {t['channel']}")
    print(f"\n通道状态: {rep['channel']}  合计 {rep['hit']}/{rep['total']}")
    if "state" in rep:
        print(f"判定     : {rep['state']} —— {rep['advice']}")
        print(f"可上线   : {'是' if rep['enable_allowed'] else '否'}")
    return 0 if rep.get("enable_allowed") else 1


if __name__ == "__main__":
    sys.exit(main())
