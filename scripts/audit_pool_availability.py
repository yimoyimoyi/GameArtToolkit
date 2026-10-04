# -*- coding: utf-8 -*-
"""
全量候选池可用性审计（**绕开项目**: 不经 nginx / 不改 DNS / 不加路由）

要回答的问题 (用户): "剥离项目后的直连状态 —— 其他连接池都可以看看可用性"。

对每个画像的每个候选 IP, 做**与生产探测同口径**的三态探测 (TCP → TLS(按画像的
SNI 模式) → HTTP 状态码), 并输出:
  · 逐候选: 状态码 / 延迟 / 判定
  · 逐画像: 可用候选数、整体可用率、判定 (OK / FLAKY / UNSTABLE / BLOCKED)
  · **冻结名单**: 对多个域/多轮都恒坏的候选 (那是可以安全剔除的), 与"时好时坏"分开

口径说明 (与项目一致, 便于互相对照):
  · 拿到任何 HTTP 响应即算"到达" (403/404 等由画像的 probe_ok_statuses 决定是否放行);
  · SNI 按画像的 `effective_sni_mode` (host / 空 / 掩标域) —— 复刻 nginx 行为;
  · 逐候选先做 1 次快速探测, 对"失败项"再补 2 次, 以区分**恒坏**与**抖动**。

用法:
  python -X utf8 scripts/audit_pool_availability.py [--rounds 1] [--per-profile 0] [--json out.json]
    --per-profile 0 = 全部候选 (默认 0)
"""

import argparse
import json
import socket
import ssl
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "app"))

import cdn_optimizer as CO            # noqa: E402
from ip_pool import CANDIDATE_IPS     # noqa: E402
from service_profile import PROFILES  # noqa: E402


def probe(ip: str, host: str, sni_mode: str, tmo: float = 8.0):
    """返回 (ok, status, ms, err) —— ok 表示**拿到 HTTP 响应**"""
    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                          socket.SOCK_STREAM)
        s.settimeout(tmo)
        s.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        if sni_mode == "host":
            sh = host or None
        elif sni_mode == "empty":
            sh = None
        else:
            sh = sni_mode
        ss = ctx.wrap_socket(s, server_hostname=sh)
        ss.sendall((f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                    f"User-Agent: Mozilla/5.0 GameArtToolkit/audit\r\n"
                    f"Connection: close\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            c = ss.recv(4096)
            if not c:
                break
            buf += c
        ss.close()
        if not buf:
            return False, None, (time.time() - t0) * 1000, "无响应"
        first = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = first.split()
        st = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
        return True, st, (time.time() - t0) * 1000, ""
    except Exception as e:
        return False, None, (time.time() - t0) * 1000, type(e).__name__


def classify(reached: int, total: int) -> str:
    if total <= 0:
        return "NO_DATA"
    r = reached / total
    if r >= 0.8:
        return "OK"
    if r >= 0.3:
        return "FLAKY"
    if reached > 0:
        return "UNSTABLE"
    return "BLOCKED"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-profile", type=int, default=0, help="每画像取前 N 个候选 (0=全部)")
    ap.add_argument("--retries", type=int, default=2, help="失败项补测次数 (区分恒坏与抖动)")
    ap.add_argument("--json", default=str(_ROOT / "scripts" / "pool_availability.json"))
    args = ap.parse_args()

    all_rows = []
    print("=" * 112)
    print("全量候选池可用性审计 (绕开项目: 不经 nginx / 不改 DNS / 不加路由)")
    print("口径: 拿到任何 HTTP 响应即算到达; SNI 按画像 effective_sni_mode")
    print("=" * 112)
    summary = []
    for p in PROFILES:
        ips = list(CANDIDATE_IPS.get(p.id) or getattr(p, "candidate_ips", None) or [])
        if getattr(p, "skip_cdn_probe", False) or not ips:
            summary.append({"profile": p.id, "skipped": True, "total": 0, "reached": 0,
                            "state": "SKIP(无候选池/上游为本地)", "dead": []})
            continue
        if args.per_profile:
            ips = ips[:args.per_profile]
        host = (getattr(p, "probe_domains", None) or p.domains or [""])[0]
        sni = CO.effective_sni_mode(p.id)
        ok_set = set(getattr(p, "probe_ok_statuses", ()) or ())
        print()
        print(f"--- {p.id}  ({p.name})  host={host}  SNI={sni}  "
              f"ok_statuses={sorted(ok_set) or '(默认: 2xx/3xx + 5xx)'} ---")
        reached = 0
        dead, flaky = [], []
        for ip in ips:
            best = None
            for i in range(1 + args.retries):
                ok, st, ms, err = probe(ip, host, sni)
                if best is None or (ok and not best[0]):
                    best = (ok, st, ms, err)
                if ok:
                    break
            ok, st, ms, err = best
            if ok:
                reached += 1
                # 状态码是否被该画像放行 (可疑判定)
                suspect = (st is not None and st not in ok_set
                           and CO._suspect_status(st)) if ok_set or True else False
                tag = "OK " if not suspect else f"可疑({st})"
            else:
                suspect = True
                tag = err or "失败"
            if not ok:
                # 补测后仍失败 ⇒ 恒坏; 若中途成功过 ⇒ 抖动
                anyok = False
                for _ in range(args.retries):
                    o2, _, _, _ = probe(ip, host, sni)
                    anyok = anyok or o2
                (flaky if anyok else dead).append(ip)
            print("    %-24s %-10s %-9s %s" % (
                ip, (str(st) if st is not None else "-"), "%.0fms" % ms, tag))
            all_rows.append({"profile": p.id, "ip": ip, "host": host, "sni": sni,
                             "reached": ok, "status": st, "ms": round(ms, 1),
                             "suspect": bool(suspect)})
        state = classify(reached, len(ips))
        print("    ⇒ %d/%d 到达  [%s]%s" % (
            reached, len(ips), state,
            ("  恒坏: " + ", ".join(dead)) if dead else ""))
        summary.append({"profile": p.id, "host": host, "sni": sni, "total": len(ips),
                        "reached": reached, "state": state,
                        "dead": dead, "flaky": flaky,
                        "ok_statuses": sorted(ok_set)})

    print()
    print("=" * 112)
    print("汇总 (按可用率升序 —— 最差的排前面)")
    print("=" * 112)
    live = [s for s in summary if not s.get("skipped")]
    live.sort(key=lambda s: (s["reached"] / max(1, s["total"]), s["profile"]))
    print("%-18s %-9s %-10s %-9s %s" % ("画像", "到达", "可用率", "判定", "恒坏候选"))
    print("-" * 112)
    for s in live:
        print("%-18s %-9s %-10.2f %-9s %s" % (
            s["profile"], "%d/%d" % (s["reached"], s["total"]),
            s["reached"] / max(1, s["total"]), s["state"],
            ", ".join(s["dead"])[:52] or "-"))
    skipped = [s for s in summary if s.get("skipped")]
    print()
    print("跳过 %d 个 (无候选池 / 上游为本地腿/隧道): %s" % (
        len(skipped), ", ".join(s["profile"] for s in skipped)))
    tot = sum(s["total"] for s in live)
    rc = sum(s["reached"] for s in live)
    print()
    print("总计: %d/%d 到达 (%.1f%%), 覆盖 %d 个画像" % (
        rc, tot, 100 * rc / max(1, tot), len(live)))
    Path(args.json).write_text(json.dumps(
        {"rows": all_rows, "summary": summary}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    print(f"明细已写入 {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
