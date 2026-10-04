# -*- coding: utf-8 -*-
"""
诊断: 哪些服务的**探测判据**与**实际可用性**脱节 (只读, 不发起加速、不改配置)

背景: 用户报告"部分服务检测不可用, 实际可用"。本项目已有一座同类事故的完整记录
(googlevideo: 探测是纯假阴性; http_verdict 误判 xbox 6 个候选), 故先量化再改。

做法: 对每个有候选池的画像, 取**前 2 个候选 IP**, 用生产判据
(cdn_optimizer.probe_ip_endpoint_v2) 跑一次, 并同时**独立**记录原始 HTTP 状态码。
两者不一致 = 误判面:
  · 生产判 "可疑/失败", 但原始状态码是"真服务能给的状态" ⇒ 假阴性嫌疑
  · 生产判 "可用", 但其实是托管挑战页 ⇒ 假阳性 (用户会看到"连得上却打不开")

用法: python -X utf8 scripts/diag_probe_false_negatives.py [--per-profile 2] [--json out.json]
"""

import argparse
import json
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "app"))
sys.path.insert(0, str(_ROOT))

import cdn_optimizer as CO            # noqa: E402
from ip_pool import CANDIDATE_IPS     # noqa: E402
from service_profile import PROFILES  # noqa: E402


def _raw_status(ip: str, domain: str, timeout: float = 4.0):
    """独立取一次原始 HTTP 状态码 + Server 头 (不经生产判据), 作为对照面"""
    import socket
    import ssl
    try:
        s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                          socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=domain)
        ss.sendall((f"GET / HTTP/1.1\r\nHost: {domain}\r\n"
                    f"User-Agent: Mozilla/5.0 GameArtToolkit-diag\r\n"
                    f"Connection: close\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            c = ss.recv(4096)
            if not c:
                break
            buf += c
        ss.close()
        line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = line.split()
        st = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
        srv = ""
        cf = ""
        for h in buf.decode("latin-1", "replace").split("\r\n"):
            lh = h.lower()
            if lh.startswith("server:"):
                srv = h.split(":", 1)[1].strip()
            if lh.startswith("cf-mitigated:"):
                cf = h.split(":", 1)[1].strip()
        return st, srv, cf
    except Exception as e:
        return None, type(e).__name__, ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-profile", type=int, default=2,
                    help="每个画像取前 N 个候选 IP (默认 2: 够看出判据是否系统性误判)")
    ap.add_argument("--json", default=str(_ROOT / "scripts" / "diag_probe_fn.json"))
    args = ap.parse_args()

    rows = []
    print("%-22s %-20s %-6s %-9s %-8s %-7s %s" % (
        "画像", "候选IP", "原始", "生产判据", "http_ok", "可疑", "Server/说明"))
    print("-" * 118)
    for p in PROFILES:
        ips = list(CANDIDATE_IPS.get(p.id) or getattr(p, "candidate_ips", None) or [])
        if not ips or getattr(p, "skip_cdn_probe", False):
            continue
        domain = (getattr(p, "probe_domains", None) or p.domains or [""])[0]
        ok_statuses = set(getattr(p, "probe_ok_statuses", ()) or ()) or None
        for ip in ips[:args.per_profile]:
            raw_st, srv, cf = _raw_status(ip, domain)
            try:
                r = CO.probe_ip_endpoint_v2(
                    ip, domain, timeout=6.0,
                    probe_domains=getattr(p, "probe_domains", None) or (),
                    ok_statuses=ok_statuses)
            except Exception as e:
                r = {"error": f"{type(e).__name__}: {e}"}
            prod_ok = bool(r.get("http_ok")) and not r.get("http_suspect")
            suspect = bool(r.get("http_suspect"))
            # 误判面: 生产判可疑, 但原始响应是"真服务"的特征 (非挑战页 + 非网关错误)
            challenge = bool(cf) or "challenge" in (srv or "").lower()
            false_neg = suspect and raw_st is not None and not challenge
            rows.append({"profile": p.id, "ip": ip, "domain": domain,
                         "raw_status": raw_st, "raw_server": srv, "cf": cf,
                         "prod_http_status": r.get("http_status"),
                         "prod_http_ok": bool(r.get("http_ok")),
                         "prod_suspect": suspect, "prod_ok": prod_ok,
                         "false_negative_suspect": false_neg})
            flag = "  ← 假阴性嫌疑" if false_neg else ""
            print("%-22s %-20s %-6s %-9s %-8s %-7s %s%s" % (
                p.id, ip[:20], raw_st, r.get("http_status"), r.get("http_ok"),
                suspect, (srv or cf or "")[:26], flag))

    fn = [r for r in rows if r["false_negative_suspect"]]
    print()
    print("=" * 118)
    print(f"共探测 {len(rows)} 个 (画像, IP) 组合; "
          f"其中**假阴性嫌疑** {len(fn)} 个, 涉及 "
          f"{len({r['profile'] for r in fn})} 个画像")
    print("=" * 118)
    Path(args.json).write_text(json.dumps({"rows": rows,
                                           "false_negative": fn},
                                          ensure_ascii=False, indent=2),
                               encoding="utf-8")
    print(f"明细已写入 {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
