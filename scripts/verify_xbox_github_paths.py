# -*- coding: utf-8 -*-
"""
验证: xbox 与 GitHub 家族的**可达性 / 稳定性** (只读, 不改配置)

用户反馈: "类似的还有 xbox 和完全不稳定的 github"。
本脚本对每个画像的**前 N 个候选**逐条走**直连**与**经本地代理**, 并报告:
  · HTTP 状态行 + 延迟 + 响应体特征 (是否真内容)
  · 直连成功率 / 代理成功率 —— "完全不稳定的 github" 应表现为直连命中率低

判据 (与项目口径一致): 拿到**任何 HTTP 响应**即视为到达 (含 403/404/500 —— 根路径
本就该 4xx 的服务不能因此判死)。所以这里看的是**能不能拿到响应**, 不是内容对不对。

用法: python -X utf8 scripts/verify_xbox_github_paths.py [--per-profile 5] [--proxy 127.0.0.1:7897]
"""

import argparse
import re
import socket
import ssl
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "app"))

from ip_pool import CANDIDATE_IPS       # noqa: E402
from service_profile import PROFILES_BY_ID  # noqa: E402

TARGETS = ("xbox", "github_web", "github_raw", "github_release",
           "github_assets", "github_s3")
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"


def _read_status(ss, timeout=8.0):
    ss.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        c = ss.recv(4096)
        if not c:
            break
        buf += c
    if not buf:
        return None, 0
    line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", line)
    return (int(m.group(1)) if m else None), len(buf)


def direct(ip, host, port=443, timeout=7.0):
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
        ss.sendall((f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {_UA}\r\n"
                    f"Connection: close\r\n\r\n").encode())
        st, _ = _read_status(ss)
        ss.close()
        return st, (time.time() - t0) * 1000, ""
    except Exception as e:
        return None, (time.time() - t0) * 1000, type(e).__name__


def via_proxy(proxy, host, port=443, timeout=15.0):
    t0 = time.time()
    s = None
    try:
        s = socket.create_connection(proxy, timeout=timeout)
        s.settimeout(timeout)
        s.sendall((f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").encode())
        b = b""
        while b"\r\n\r\n" not in b:
            c = s.recv(4096)
            if not c:
                break
            b += c
        if b" 200" not in b.split(b"\r\n")[0]:
            s.close()
            return None, (time.time() - t0) * 1000, "CONNECT 被拒"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        ss = ctx.wrap_socket(s, server_hostname=host)
        ss.sendall((f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {_UA}\r\n"
                    f"Connection: close\r\n\r\n").encode())
        st, _ = _read_status(ss)
        ss.close()
        return st, (time.time() - t0) * 1000, ""
    except Exception as e:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
        return None, (time.time() - t0) * 1000, type(e).__name__


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-profile", type=int, default=5)
    ap.add_argument("--proxy", default="127.0.0.1:7897")
    args = ap.parse_args()
    ph, _, pp = args.proxy.partition(":")
    proxy = (ph, int(pp or 7897))

    summary = {}
    for sid in TARGETS:
        p = PROFILES_BY_ID.get(sid)
        ips = list(CANDIDATE_IPS.get(sid) or [])
        host = (getattr(p, "probe_domains", None) or p.domains or [""])[0]
        print("=" * 104)
        print(f"{sid}  ({p.name})   探测域名={host}   候选 {len(ips)} 个")
        print("=" * 104)
        print("%-20s %-10s %-10s   %-10s %-10s  %s" % (
            "候选 IP", "直连", "直连ms", "代理", "代理ms", "说明"))
        print("-" * 104)
        d_ok = p_ok = n = 0
        for ip in ips[:args.per_profile]:
            n += 1
            dst, dms, derr = direct(ip, host)
            pst, pms, perr = via_proxy(proxy, host)
            d_ok += dst is not None
            p_ok += pst is not None
            note = []
            if dst is None and pst is not None:
                note.append("★ 直连不通/代理通")
            print("%-20s %-10s %-10.0f   %-10s %-10.0f  %s" % (
                ip[:20], dst if dst is not None else (derr or "-"), dms,
                pst if pst is not None else (perr or "-"), pms, " ".join(note)))
        summary[sid] = {"host": host, "n": n, "direct_ok": d_ok, "proxy_ok": p_ok}
        print(f"  ⇒ 直连 {d_ok}/{n} 成功;  经代理 {p_ok}/{n} 成功")
        print()

    print("=" * 104)
    print("%-16s %-26s %-14s %-14s %s" % ("画像", "探测域名", "直连成功率", "代理成功率", "判定"))
    print("-" * 104)
    for sid, s in summary.items():
        dr = f"{s['direct_ok']}/{s['n']}"
        pr = f"{s['proxy_ok']}/{s['n']}"
        if s["direct_ok"] == 0 and s["proxy_ok"] > 0:
            v = "★ 直连全挂, 需走代理/隧道"
        elif s["direct_ok"] < s["n"]:
            v = f"⚠ 直连不稳定 ({s['n']-s['direct_ok']} 条失败)"
        else:
            v = "直连稳定"
        print("%-16s %-26s %-14s %-14s %s" % (sid, s["host"][:26], dr, pr, v))
    print("=" * 104)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
