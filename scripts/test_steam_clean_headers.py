# -*- coding: utf-8 -*-
"""
Steam 社区与静态图片 CDN 纯净化全链路端到端验证脚本
测试各项关键请求路径、模拟真实浏览器 User-Agent 及图片 CDN 缓存行为
"""

import sys
import time
import socket
import ssl
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "app"))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def test_steam_endpoint(name: str, domain: str, path: str, target_ip: str = "23.46.229.9", sni: str = "steambroadcast.akamaized.net"):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])

    t0 = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((target_ip, 443), timeout=3.5)
        ss = ctx.wrap_socket(sock, server_hostname=sni)
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
            f"Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
            f"Connection: close\r\n\r\n"
        )
        ss.sendall(req.encode("utf-8"))
        raw = b""
        while len(raw) < 8192:
            chunk = ss.recv(2048)
            if not chunk:
                break
            raw += chunk
        ss.close()
        lat = (time.perf_counter() - t0) * 1000.0
        text = raw.decode("utf-8", errors="ignore")
        first_line = text.split("\r\n")[0]
        has_rate_limit = "您最近作出的请求太多了" in text or "too many requests" in text.lower() or "429" in first_line
        
        status_tag = "✅ PASS" if ("200" in first_line or "302" in first_line) and not has_rate_limit else "❌ FAIL"
        print(f"[{status_tag}] {name:<35} | IP: {target_ip:<15} | {first_line:<22} | 耗时: {lat:>5.1f}ms | 限频: {has_rate_limit}")
        return not has_rate_limit and ("200" in first_line or "302" in first_line)
    except Exception as e:
        print(f"[❌ FAIL] {name:<35} | IP: {target_ip:<15} | 异常: {e}")
        return False

def main():
    print("=" * 85)
    print(" Steam 社区纯净化与防 429 风控拦截端到端实测")
    print("=" * 85)

    test_cases = [
        ("Steam 社区主页", "steamcommunity.com", "/", "23.46.229.9"),
        ("创意工坊详情页 (Mod详情)", "steamcommunity.com", "/sharedfiles/filedetails/?id=2874230248", "23.1.179.144"),
        ("Steam 社区市场", "steamcommunity.com", "/market/", "104.91.87.202"),
        ("个人资料重定向", "steamcommunity.com", "/my/profile", "23.32.91.49"),
        ("Steam 社区图标 CDN", "community.akamai.steamstatic.com", "/public/shared/images/header/globalheader_logo.png", "23.46.229.9"),
        ("Steam 静态资源 CDN", "cdn.akamai.steamstatic.com", "/store/home/store_home_share.jpg", "23.1.179.144"),
    ]

    all_pass = True
    for name, domain, path, ip in test_cases:
        ok = test_steam_endpoint(name, domain, path, ip)
        if not ok:
            all_pass = False
        time.sleep(0.1)

    print("=" * 85)
    print(f"全链路测试结果: {'全部通过 100% PASS' if all_pass else '部分失败'}")
    print("=" * 85)

if __name__ == "__main__":
    main()
