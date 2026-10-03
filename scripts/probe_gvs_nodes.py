# -*- coding: utf-8 -*-
"""
googlevideo (YouTube 视频流) 节点可用性实测 —— **经生产腿**逐节点测量

为什么不能用现成的 `app/gvs_h3_probe.py` 回答本任务
----------------------------------------------------
那个探针直接对 (ip, sni, authority) 自己发起 aioquic 请求 —— 它测的是**传输本身**,
而画像里未解决的那个问题是:

    "实测 20 条 SABR POST 里 11 条 upstream_no_response, 表现为卡顿/降码率"

`upstream_no_response` 是**腿内部**的判定 (`app/h3_upstream.py:711-714`, 首头 deadline
到期或连接被对端终止), 它同时受**解析 → 候选排序 → 族级跳过 → 连接池 → 超时预算**的
影响。直接用 aioquic 探测会把这些全部绕开, 得到的结论**不能**代表生产腿。

本脚本因此把请求**真正打进腿**(`H3UpstreamProxy`, 与生产同款: 同解析器、同候选排序、
同预算、同连接池), 再同时收集三面证据:

  ① 客户端面: HTTP 状态 / `X-H3-Upstream-Error` / 耗时 / 字节数
  ② 解析面: 该节点名下真实解析到的地址 (含族与是否落在 Google 段)
  ③ 腿内部: `forwarder.events` 事件环增量 (target_failed / family_unreachable /
            family_skipped / recovered / reresolve …) —— 每个地址的成败与**原因**

为什么必须多轮 + 交错
---------------------
googlevideo 的可用性是**分钟级时变**的 (`app/gvs_h3_probe.py` 头部实测记录:
同一小时内 0% ↔ 100% 抖动)。单轮采样只能得到"某时刻的快照", 因此:
  · 默认按**轮**交错遍历全部节点 (而不是先把一个节点测 3 次再换下一个) ——
    否则某个节点恰好落在黑障窗口里就会被误判为"坏节点";
  · 结果按**命中率**分类, 不按单次成败下结论。

为什么节点名要"挖"而不是"编"
-----------------------------
节点名形如 `rr1---sn-p5qs7nd7.googlevideo.com`, 中段是**不透明哈希**, 不可枚举
(见 `app/service_profile.py` googlevideo 段: "节点名动态且海量")。因此本脚本的默认
节点集来自**历史实测证据里真实出现过的节点名** (scripts/probe_playback_diag.json 等),
这样测的就是播放器真会去请求的那批节点。

用法
----
  python scripts/probe_gvs_nodes.py                       # 默认: 挖出的高频节点 × 3 轮
  python scripts/probe_gvs_nodes.py --rounds 5
  python scripts/probe_gvs_nodes.py --nodes rr1---sn-p5qs7nd7,rr4---sn-a5meknzr
  python scripts/probe_gvs_nodes.py --path /videoplayback?test=1
  python scripts/probe_gvs_nodes.py --json scripts/gvs_nodes.json
"""

import io
import os
import re
import sys
import json
import time
import glob
import socket
import pathlib
import argparse
import threading
import http.client
import collections
from typing import Any, Dict, List, Optional, Tuple

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "app"))

# 生产腿默认 44411; 这里刻意用另一个端口, 避免与正在运行的应用/腿抢端口
DEFAULT_PORT = 44511

# 每个 A/B 轴的**关闭/基线**取值 —— 非 A/B 模式下用的就是它 (即"生产当前行为")
AB_OFF_VALUE = {"addr_health": False, "retries": 0}

NODE_RE = re.compile(r"(rr\d+---sn-[a-z0-9\-]+)")

# 默认节点集 = 历史证据里出现频次最高的若干节点 (含画像探针默认用的那个做对照)
FALLBACK_NODES = [
    "rr1---sn-p5qs7nd7",
    "rr4---sn-a5meknzr",
    "rr2---sn-p5qlsnd6",
    "rr4---sn-4g5e6nzl",
    "rr4---sn-q4fl6ns6",
    "rr5---sn-ajaig5-5h",
    "rr3---sn-q4fl6ns6",
    "rr1---sn-5hne6nzk",
    "rr2---sn-q4fl6nd6",
    "rr1---sn-i3b7kns6",
]


def mine_nodes(limit: int = 12) -> List[str]:
    """从历史证据 JSON 里挖出真实出现过的节点名 (按频次排序)"""
    counter: "collections.Counter" = collections.Counter()
    for path in glob.glob(str(ROOT / "scripts" / "*.json")) + glob.glob(str(ROOT / "*.json")):
        try:
            text = pathlib.Path(path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for m in NODE_RE.findall(text):
            counter[m] += 1
    out = [n for n, _c in counter.most_common(limit)]
    return out or list(FALLBACK_NODES)


def scoreboard_nodes(limit: int = 20) -> List[str]:
    """从**节点成绩单**取目标 (2026-10-03 新增的 L1 数据源)

    优先取"在真实播放里成功过"的节点 (至少被证明能通一次), 再补上只失败过的
    (作为对照: 要能确认它们确实坏了, 而不是我们的探测姿势不对)。

    为什么它比"从历史 JSON 挖"更好: 成绩单由 h3 上游腿按**浏览器真实流量**累加并落盘
    (见 app/h3_upstream.py 的 _NodeScoreboard), 反映的是**最近会话**的实际可用性;
    而历史 JSON 是一周前的一次性快照。
    """
    try:
        sys.path.insert(0, str(ROOT / "app"))
        import h3_upstream as h3
        sb = h3._NodeScoreboard(autoload=True)
        rows = sb.ranked(min_samples=1)
    except Exception:
        return []
    good = [r["node"] for r in rows if r["ok"] > 0]
    bad = [r["node"] for r in rows if r["ok"] == 0]
    return (good + bad)[:limit]


def probe_controls(rounds: int = 2, timeout: float = 6.0) -> Dict[str, Any]:
    """控制组自检 —— 直接复用闸门 (`app/gvs_h3_probe`) 的那一套

    为什么必须带它: 若本机 h3 栈或网络本身坏了, 目标全灭是**我们的问题**而不是节点的问题。
    没有控制组, 一次全灭的扫描会得出"所有节点都不可用"的错误结论 —— 项目早期正是
    拿被投毒的系统解析当控制组, 把目标被压制误判成"客户端故障"。
    """
    try:
        sys.path.insert(0, str(ROOT / "app"))
        import gvs_h3_probe as gate
        return gate.probe_controls(rounds=rounds, timeout=timeout)
    except Exception as e:
        return {"ok": False, "channel": "ERROR", "hit": 0, "total": 0,
                "error": f"{type(e).__name__}: {e}", "details": []}


def free_port(preferred: int) -> int:
    """优先用 preferred; 被占用则让系统挑一个"""
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", preferred))
        return preferred
    except Exception:
        s2 = socket.socket()
        s2.bind(("127.0.0.1", 0))
        return s2.getsockname()[1]
    finally:
        try:
            s.close()
        except Exception:
            pass


def request_via_leg(port: int, host: str, path: str, timeout: float) -> Dict[str, Any]:
    """把一条请求打进腿, 记录状态/错误头/耗时/字节"""
    t0 = time.perf_counter()
    out: Dict[str, Any] = {"host": host, "path": path.split("?", 1)[0]}
    c = None
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        c.request("GET", path, headers={"Host": host, "User-Agent": "gamt-gvs-node-probe"})
        r = c.getresponse()
        body = r.read(400_000)
        out["status"] = int(r.status)
        out["h3_error"] = (r.getheader("X-H3-Upstream-Error") or "").strip()
        out["server"] = (r.getheader("Server") or "").strip()
        out["ctype"] = (r.getheader("Content-Type") or "").strip()
        out["bytes"] = len(body)
        out["ms"] = round((time.perf_counter() - t0) * 1000, 1)
    except Exception as e:
        out["status"] = None
        out["error"] = f"{type(e).__name__}: {e}"[:120]
        out["ms"] = round((time.perf_counter() - t0) * 1000, 1)
    finally:
        try:
            if c is not None:
                c.close()
        except Exception:
            pass
    return out


def resolve_face(host: str) -> Dict[str, Any]:
    """解析面证据: 该节点名下解析到什么 (用的是腿的同一条解析链)"""
    try:
        import h3_upstream as h3
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    try:
        ips = list(h3.default_resolver(host) or [])
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "ips": []}
    v6 = [i for i in ips if ":" in i]
    v4 = [i for i in ips if ":" not in i]
    google = []
    for i in ips:
        try:
            if h3.is_google_edge_ip(i):
                google.append(i)
        except Exception:
            pass
    return {"ips": ips, "v6": len(v6), "v4": len(v4), "google_nets": len(google),
            "attempt_order": h3.attempt_order(ips) if hasattr(h3, "attempt_order") else []}


def classify(attempts: int, ok: int, h3_errors: int) -> str:
    """按命中率分类 (阈值与 app/gvs_h3_probe.py 对齐, 便于两处结论互相对照)"""
    if attempts <= 0:
        return "NO_DATA"
    rate = ok / attempts
    if rate >= 0.8:
        return "OK"
    if rate >= 0.3:
        return "FLAKY"
    if rate > 0 or h3_errors:
        return "UNSTABLE"
    return "BLOCKED"


def main() -> int:
    ap = argparse.ArgumentParser(description="googlevideo 节点可用性实测 (经生产 h3 上游腿)")
    ap.add_argument("--nodes", default="", help="逗号分隔节点名; 默认从历史证据里挖")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--max-nodes", type=int, default=20,
                    help="节点数上限 (探测是有成本的: 每节点一轮 = 一次 QUIC 连接)")
    ap.add_argument("--path", default="/videoplayback?test=1",
                    help="请求路径 (真实链路上 gvs 对普通 GET 回 403 + server: gvs 1.0)")
    ap.add_argument("--timeout", type=float, default=20.0, help="单请求客户端超时")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--leg-retries", type=int, default=None,
                    help="腿的『同节点重试次数』默认值 (不传 = 生产默认 DEFAULT_RETRY_SAME_NODE)。 "
                         "非 A/B 模式用它; A/B 的 retries 轴仍由两条臂各自覆盖。")
    ap.add_argument("--leg-first-byte", type=float, default=None,
                    help="腿的『等首头』档位 (秒; 不传 = 生产默认 8s)。 "
                         "★ 为什么要能改: 单次首头失败会吃掉 ~8.4s, 而 RETRY_TIME_BUDGET=12s "
                         "⇒ 生产取值下**只容得下一次尝试**, 重试臂根本没有机会跑完 —— "
                         "§7.7 那次 A/B 就死在这里。降到 ~4s 才能让 2 次尝试落在预算内。 "
                         "⚠ 探测专用: 不改生产默认值。")
    ap.add_argument("--parallel", type=int, default=1,
                    help="并发请求数 (默认 1: 逐节点串行, 保证事件环增量可精确归属到该请求)")
    ap.add_argument("--ab", action="store_true",
                    help="同刻交错 A/B: 每个 (轮, 节点) 依次发两条请求, 两条只差**一个变量** "
                         "(见 --ab-var) —— 评估任一时变相关机制的唯一可信形态")
    ap.add_argument("--ab-var", choices=("addr_health", "retries"), default="addr_health",
                    help="A/B 要切换的变量: "
                         "addr_health=地址记忆 ON vs OFF (默认); "
                         "retries=同节点重试 1 次 vs 0 次 —— 走 DEFAULT_RETRY_SAME_NODE。 "
                         "后者针对 2026-10-04 的新发现: 失败**并非**按地址粘滞"
                         "(同一地址 5~12 分钟内成功率中位变化 44%%), 故『同地址重试』"
                         "本身有可依赖的机制, 而当初否决它的对比是**跨窗口**的、不成立。")
    ap.add_argument("--targets", choices=("auto", "scores", "history", "fallback"),
                    default="auto",
                    help="目标来源: auto=成绩单优先、不足则补历史证据 (默认); scores=只用节点成绩单; "
                         "history=只用历史证据 JSON; fallback=内置节点集")
    ap.add_argument("--no-control", action="store_true",
                    help="跳过控制组自检 (不推荐: 目标全灭时无法区分'节点坏'与'本机坏')")
    ap.add_argument("--json", default=str(ROOT / "scripts" / "gvs_nodes.json"))
    args = ap.parse_args()

    try:
        import h3_upstream as h3
    except Exception as e:
        print(f"  无法导入 h3_upstream: {e}")
        return 3

    cli_nodes = [n.strip() for n in args.nodes.split(",") if n.strip()]
    src = "命令行指定"
    if cli_nodes:
        nodes = cli_nodes
    elif args.targets == "scores":
        nodes, src = scoreboard_nodes(), "节点成绩单 (浏览器真实流量统计)"
    elif args.targets == "history":
        nodes, src = mine_nodes(), "历史实测证据 JSON"
    elif args.targets == "fallback":
        nodes, src = list(FALLBACK_NODES), "内置节点集"
    else:                                   # auto
        from_scores = scoreboard_nodes()
        from_hist = [n for n in mine_nodes() if n not in from_scores]
        nodes = (from_scores + from_hist)[:args.max_nodes]
        src = (f"节点成绩单 {len(from_scores)} 个 + 历史证据补齐 "
               f"{len(nodes) - len(from_scores)} 个")
    nodes = nodes[:args.max_nodes]
    port = free_port(args.port)

    print(f"  googlevideo 节点可用性实测 (经生产腿): {len(nodes)} 节点 × {args.rounds} 轮 "
          f"(交错采样), 腿端口 127.0.0.1:{port}")
    print(f"  节点集来源: {src}")

    control: Optional[Dict[str, Any]] = None
    if not args.no_control:
        print("\n  === 控制组自检 (已验通的 h3 站点: 证明本机 h3 栈与网络可用) ===")
        control = probe_controls(rounds=max(2, min(3, args.rounds)), timeout=6.0)
        for d in control.get("details", []):
            print(f"    {d.get('label', '?'):28s} {d.get('ok', 0)}/{d.get('attempts', 0)}")
        print(f"  控制组: {control.get('hit')}/{control.get('total')} ({control.get('channel')}) "
              f"{'✅ 本机 h3 正常' if control.get('ok') else '❌ 本机/网络异常'}")
        if not control.get("ok"):
            print("\n  控制组不通 ⇒ 本次扫描的目标结果**不可用**(先修本机/网络, 别错怪节点)。")
            pathlib.Path(args.json).write_text(json.dumps(
                {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "control": control,
                 "state": "CLIENT_BROKEN"}, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8")
            print(f"  证据已写入 {args.json}")
            return 3

    proxy = h3.H3UpstreamProxy(port=port, persist_scores=False,
                               first_byte=args.leg_first_byte,
                               retries=(args.leg_retries
                                        if args.leg_retries is not None
                                        else h3.DEFAULT_RETRY_SAME_NODE))
    ok, why = proxy.start()
    if not ok:
        print(f"  腿启动失败: {why}")
        return 3
    print(f"  腿已启动: {why or 'ok'}")
    print(f"  腿参数(本次探测): retries={proxy.forwarder.retries} "
          f"first_byte={proxy.budget.first_byte:g}s "
          f"connect={proxy.budget.connect:g}s "
          f"RETRY_TIME_BUDGET={h3.RETRY_TIME_BUDGET:g}s")
    # 预算可行性预检 (见 §7.6.3): 容不下 2 次尝试时, A/B 测的不是"重试有没有用"
    _feasible = 2 * (proxy.budget.first_byte + 0.4) <= h3.RETRY_TIME_BUDGET
    print(f"  ⚠ 2 次尝试预计需 {2*(proxy.budget.first_byte+0.4):.1f}s vs 预算 "
          f"{h3.RETRY_TIME_BUDGET:g}s ⇒ {'容得下 (可用于评估重试)' if _feasible else '容不下 (重试臂会被预算掐死, 结论无效)'}")

    fwd = proxy.forwarder
    # 捕获**本次探测开始时**的取值 —— 循环里会把 fwd.retries / addr_health 改来改去,
    # 末尾若直接读它们, 读到的会是被改过的值 (复原就成了空操作)。
    _retries0 = int(fwd.retries)
    _addr_health0 = bool(fwd.addr_health.enabled)
    rows: List[Dict[str, Any]] = []
    events_before = len(fwd.events.snapshot())
    try:
        for host in [f"{n}.googlevideo.com" for n in nodes]:
            rows.append({"node": h3.node_name_from_host(host), "host": host,
                         "resolve": resolve_face(host), "rounds": []})

        for rnd in range(1, max(1, args.rounds) + 1):
            print(f"\n  --- 第 {rnd}/{args.rounds} 轮 (交错遍历全部节点) ---")
            for row in rows:
                # A/B 轴: 两臂**只差一个变量**, 且同轮同节点交替发出 —— 通道是分钟级时变的,
                # 跨窗口比较会直接把时变误读成"该机制有害/无害"(项目已在 retries 上吃过一次)。
                if not args.ab:
                    # 非 A/B: retries 轴用 --leg-retries 给的值 (缺省 = 生产默认), 见上方构造
                    if args.ab_var == "retries":
                        arms = [("retries", fwd.retries)]
                    else:
                        arms = [("addr_health", AB_OFF_VALUE["addr_health"])]
                elif args.ab_var == "retries":
                    arms = [("retries", 1), ("retries", 0)]
                else:
                    arms = [("addr_health", True), ("addr_health", False)]
                for axis, val in arms:
                    if axis == "addr_health":
                        fwd.addr_health.enabled = bool(val)
                    else:
                        # 腿按 self.retries 决定**每个候选**的重试次数 (见 forward 的
                        # `for attempt in range(retries + 1)`); 默认 0 = 只试一次。
                        fwd.retries = int(val)
                    ev0 = len(fwd.events.snapshot())
                    res = request_via_leg(port, row["host"], args.path, args.timeout)
                    evs = fwd.events.snapshot()[ev0:]
                    res["round"] = rnd
                    res["ab_axis"] = axis
                    res["ab_val"] = val
                    # 向后兼容: 既有聚合器按 "addr_health" 取值; retries 轴下不再冒充它
                    res["addr_health"] = bool(val) if axis == "addr_health" else None
                    res["events"] = [{"kind": e["kind"], "detail": e["detail"]} for e in evs]
                    row["rounds"].append(res)
                    tag = (f"HTTP {res['status']}" if res.get("status") is not None
                           else f"ERR {res.get('error', '')[:36]}")
                    extra = f" 腿错误={res['h3_error'][:34]}" if res.get("h3_error") else ""
                    kinds = ",".join(sorted({e["kind"] for e in evs})) or "-"
                    arm_tag = "" if not args.ab else (
                        f"[记忆{'ON' if val else 'OFF'}] " if axis == "addr_health"
                        else f"[重试{int(val)}次] ")
                    print(f"    {arm_tag}{row['node']:22s} {tag:12s} {res['ms']:8.0f}ms"
                          f"{extra:40s} 事件[{kinds}]")
        # 复原到**本次探测开始时**的取值 (不是生产默认 —— 探测可能有 --leg-retries 覆盖)
        fwd.addr_health.enabled = _addr_health0
        fwd.retries = _retries0
    finally:
        all_events = fwd.events.snapshot()[events_before:]
        stats = dict(fwd.stats)
        tap = fwd.tap.snapshot()
        try:
            proxy.stop()
        except Exception:
            pass

    # ---------------- 聚合 ----------------
    print("\n  === 逐节点结论 ===")
    summary: List[Dict[str, Any]] = []
    for row in rows:
        attempts = len(row["rounds"])
        okn = sum(1 for r in row["rounds"] if isinstance(r.get("status"), int)
                  and r["status"] < 500)
        errs = collections.Counter(r.get("h3_error") or r.get("error") or "?"
                                   for r in row["rounds"] if not (isinstance(r.get("status"), int)
                                                                 and r["status"] < 500))
        h3err = sum(1 for r in row["rounds"] if r.get("h3_error"))
        best = min((r["ms"] for r in row["rounds"] if isinstance(r.get("status"), int)
                    and r["status"] < 500), default=None)
        cls = classify(attempts, okn, h3err)
        summary.append({"node": row["node"], "host": row["host"], "attempts": attempts,
                        "ok": okn, "failed": attempts - okn, "h3_errors": h3err,
                        "channel": cls, "best_ms": best,
                        "errors": dict(errs), "resolve": row["resolve"],
                        "rounds": row["rounds"]})
        r = row["resolve"]
        print(f"    {row['node']:22s} 成功 {okn}/{attempts}  {cls:9s} "
              f"解析 {r.get('v6', 0)}v6/{r.get('v4', 0)}v4 (Google段 {r.get('google_nets', 0)}) "
              f"最佳 {best if best is None else round(best)}ms  错误 {dict(errs) if errs else '-'}")

    good = [s for s in summary if s["channel"] == "OK"]
    flaky = [s for s in summary if s["channel"] == "FLAKY"]
    print(f"\n  可用节点 ({len(good)}): {', '.join(s['node'] for s in good) or '(无)'}")
    print(f"  抖动节点 ({len(flaky)}): {', '.join(s['node'] for s in flaky) or '(无)'}")

    arms: Dict[str, Dict[str, Any]] = {}
    if args.ab:
        axis = args.ab_var
        if axis == "retries":
            on_v, on_lbl, off_lbl = 1, "重试1次", "重试0次"
            note = ("注: 若可用性确实**时变**(2026-10-04 实测: 同一地址 5~12 分钟内成功率 "
                    "中位变化 44%), 重试就买到了『再掷一次骰子』; 但重试也让失败路径更慢 "
                    "(单次首头失败 ~8.4s, 预算 12s ⇒ 只容得下一次)。两臂**必须同刻交错**看, "
                    "跨窗口比较会把时变直接误读成机制效果。")
        else:
            on_v, on_lbl, off_lbl = True, "记忆ON ", "记忆OFF"
            note = ("注: 失败地址**并非**按 (节点, 地址) 粘滞 (2026-10-04 三重核实: 同会话 "
                    "+5/+12 分钟与隔一天的解析结果逐字相同, 而同一地址成功率中位变化 44%) "
                    "—— 因此 ON 臂的收益应表现为『同一节点在后续轮次改用另一地址并成功』; "
                    "若两臂持平, 只说明该窗口内没有『同节点多地址一死一活』的情形。")
        print(f"\n  === 同刻交错 A/B ({on_lbl.strip()} vs {off_lbl.strip()}) ===")
        for val in (on_v, False if on_v is True else 0):
            rs = [r for row in rows for r in row["rounds"]
                  if r.get("ab_val") == val and r.get("ab_axis") == axis]
            okn = sum(1 for r in rs if isinstance(r.get("status"), int) and r["status"] < 500)
            lat = sorted(r["ms"] for r in rs
                         if isinstance(r.get("status"), int) and r["status"] < 500)
            errs = collections.Counter(r.get("h3_error") or r.get("error") or "?"
                                       for r in rs
                                       if not (isinstance(r.get("status"), int)
                                               and r["status"] < 500))
            lbl = on_lbl if val == on_v else off_lbl
            arms[lbl.strip()] = {
                "attempts": len(rs), "ok": okn,
                "rate": round(okn / len(rs), 3) if rs else 0.0,
                "median_ms": lat[len(lat) // 2] if lat else None,
                "errors": dict(errs)}
            a = arms[lbl.strip()]
            print(f"    {lbl}: 成功 {a['ok']}/{a['attempts']} "
                  f"(命中率 {a['rate']}) 成功样本中位延迟 {a['median_ms']}  "
                  f"错误 {a['errors']}")
        print("    " + note)

    # === 排名输出 (L2 的产出): 这是"探查"要交给下游的东西 ——
    # 不是黑名单 (实测 20 分钟内 4/4 的节点会退化成 2/4, 名单会立刻过期), 而是**带 TTL 的排名**。
    rank = []
    for s in summary:
        rank.append({"node": s["node"], "ok": s["ok"], "attempts": s["attempts"],
                     "rate": round(s["ok"] / max(1, s["attempts"]), 3),
                     "channel": s["channel"], "best_ms": s["best_ms"],
                     "errors": s["errors"],
                     "resolved_ips": (s["resolve"].get("ips") or [])})
    rank.sort(key=lambda r: (-r["rate"], -r["ok"], r["node"]))
    print("\n  === 节点排名 (带 TTL; 不是黑名单) ===")
    print(f"  {'节点':22s} {'命中':>7s} {'可用率':>7s} {'判定':9s} {'最佳ms':>8s}  解析地址")
    for r in rank:
        print(f"  {r['node']:22s} {r['ok']:>3d}/{r['attempts']:<3d} {r['rate']:>7.2f} "
              f"{r['channel']:9s} {str(r['best_ms'] or '-'):>8s}  "
              f"{','.join(r['resolved_ips']) or '(解析为空)'}")
    rc = collections.Counter(r["channel"] for r in rank)
    print(f"  分布: {dict(rc)}")

    print(f"  腿统计: {stats}")
    print(f"  腿事件计数: {dict(collections.Counter(e['kind'] for e in all_events))}")

    out = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "rounds": args.rounds,
           "targets_source": src, "path": args.path, "port": port, "ab": bool(args.ab),
           "ab_var": args.ab_var if args.ab else None,
           "control": control, "stats": stats, "arms": arms, "rank": rank,
           "event_counts": dict(collections.Counter(e["kind"] for e in all_events)),
           "events": all_events, "tap": tap, "summary": summary}
    pathlib.Path(args.json).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
    print(f"\n  证据已写入 {args.json}")
    return 0 if good else 1


if __name__ == "__main__":
    if sys.version_info < (3, 10):
        sys.stderr.write("需要 Python 3.10+\n"); raise SystemExit(2)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
