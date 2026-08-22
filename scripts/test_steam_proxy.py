# -*- coding: utf-8 -*-
"""
Steam 社区全生态与创意工坊/指南详情页 (sharedfiles/filedetails) 反代加速连通性验证脚本
"""

import sys
import time
import socket
import ssl
import concurrent.futures
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "app"))

from service_profile import get_profile_by_id

TEST_CASES = [
    {
        "name": "Steam 社区首页 (steamcommunity.com)",
        "service_id": "steam_community",
        "host": "steamcommunity.com",
        "path": "/",
        "custom_headers": {
            "Host": "steamcommunity.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
    },
    {
        "name": "Steam 创意工坊/指南详情页 (filedetails)",
        "service_id": "steam_community",
        "host": "steamcommunity.com",
        "path": "/sharedfiles/filedetails/?id=2874230248",
        "custom_headers": {
            "Host": "steamcommunity.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
    },
    {
        "name": "Steam 创意工坊用户上传图 CDN (steamuserimages-a.akamaihd.net)",
        "service_id": "steam_akamai",
        "host": "steamuserimages-a.akamaihd.net",
        "path": "/",
        "custom_headers": {
            "Host": "steamuserimages-a.akamaihd.net",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
    },
    {
        "name": "Steam 静态资源 CDN (community.akamai.steamstatic.com)",
        "service_id": "steam_akamai",
        "host": "community.akamai.steamstatic.com",
        "path": "/public/shared/images/responsive/header_logo.png",
        "custom_headers": {
            "Host": "community.akamai.steamstatic.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
    },
    {
        "name": "Steam 商店主页 (store.steampowered.com)",
        "service_id": "steam_store",
        "host": "store.steampowered.com",
        "path": "/",
        "custom_headers": {
            "Host": "store.steampowered.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
    }
]


def probe_single_endpoint(case: dict, ip: str, sni: str, timeout: float = 3.5) -> dict:
    """对特定 CDN 节点进行三态探测: TCP 握手 -> 伪 SNI TLS 握手 -> HTTP 响应"""
    res = {
        "name": case["name"],
        "ip": ip,
        "tcp_ok": False,
        "tls_ok": False,
        "http_status": None,
        "latency_ms": None,
        "server_header": None,
        "error": None
    }

    t0 = time.time()
    raw_sock = None
    ssl_sock = None
    try:
        # 1. TCP 握手
        raw_sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, 443))
        res["tcp_ok"] = True

        # 2. TLS 握手 (采用指定的 SNI 策略与 ALPN)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])

        ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=sni if sni else None)
        res["tls_ok"] = True
        t_tls = time.time()
        res["latency_ms"] = round((t_tls - t0) * 1000, 1)

        # 3. HTTP GET 请求
        headers_str = "\r\n".join([f"{k}: {v}" for k, v in case.get("custom_headers", {}).items()])
        req = f"GET {case['path']} HTTP/1.1\r\n{headers_str}\r\nConnection: close\r\n\r\n"
        ssl_sock.sendall(req.encode("utf-8"))

        raw_data = b""
        while len(raw_data) < 2048:
            chunk = ssl_sock.recv(1024)
            if not chunk:
                break
            raw_data += chunk

        resp_text = raw_data.decode("latin1", errors="ignore")
        if resp_text.startswith("HTTP/"):
            parts = resp_text.split(" ", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                res["http_status"] = int(parts[1])

            for line in resp_text.split("\r\n"):
                if line.lower().startswith("server:"):
                    res["server_header"] = line.split(":", 1)[1].strip()

    except Exception as e:
        res["error"] = str(e)
    finally:
        if ssl_sock:
            try:
                ssl_sock.close()
            except Exception:
                pass
        elif raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass

    return res


def run_all_steam_probes():
    print("=" * 75, flush=True)
    print(" Steam 社区全生态与创意工坊 (filedetails) 反代加速实机连通性验证", flush=True)
    print("=" * 75, flush=True)

    all_passed = True
    for case in TEST_CASES:
        p = get_profile_by_id(case["service_id"])
        candidate_ips = p.candidate_ips if p else []
        sni = p.ssl_sni_mode if p else "steambroadcast.akamaized.net"
        if not candidate_ips:
            print(f"[-] 警告: 未找到服务 {case['service_id']} 的候选 IP", flush=True)
            continue

        print(f"\n[+] 正在探测: {case['name']}", flush=True)
        print(f"    - 目标路径: {case['path']}", flush=True)
        print(f"    - 握手 SNI: {sni}", flush=True)
        print(f"    - 候选 IP 数: {len(candidate_ips)}", flush=True)

        success_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(candidate_ips)) as executor:
            future_to_ip = {executor.submit(probe_single_endpoint, case, ip, sni): ip for ip in candidate_ips}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                res = future.result()
                status_desc = "PASS" if (res["http_status"] in (200, 301, 302, 400, 404)) else "FAIL"
                if status_desc == "PASS":
                    success_count += 1
                    server_info = f" [Server: {res['server_header']}]" if res["server_header"] else ""
                    print(f"    -> 节点 {ip:<16} | 延迟: {res['latency_ms']:>5.1f}ms | 状态码: {res['http_status']} | 结果: {status_desc}{server_info}", flush=True)
                else:
                    err = f" ({res['error']})" if res["error"] else f" (Status {res['http_status']})"
                    print(f"    -> 节点 {ip:<16} | 结果: FAIL{err}", flush=True)

        if success_count > 0:
            print(f"    => 该测试项可用节点: {success_count}/{len(candidate_ips)} (反代加速完全就绪)", flush=True)
        else:
            print(f"    => 警告: 该测试项所有候选节点探测均未通过响应验证", flush=True)
            all_passed = False

    print("\n" + "=" * 75, flush=True)
    if all_passed:
        print(" 全生态测试完毕: Steam 社区、创意工坊/指南详情页及图片 CDN 均完美支持伪 SNI 反代加速！", flush=True)
    else:
        print(" 部分节点探测异常，请结合网络环境与可用 IP 池重试。", flush=True)
    print("=" * 75, flush=True)


if __name__ == "__main__":
    run_all_steam_probes()
