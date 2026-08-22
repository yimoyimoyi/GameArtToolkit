# -*- coding: utf-8 -*-
"""
PixivToolkit - 全加速项实机真实连通性与反代可用性探测脚本 (纯文本安全版)
"""

import sys
import time
import ssl
import json
import socket
import concurrent.futures
from pathlib import Path

TARGET_SERVICES = [
    # 游戏生态
    {"group": "游戏生态", "name": "Steam 商店与结账", "host": "store.steampowered.com", "ips": ["23.1.179.144", "104.71.154.102"], "path": "/"},
    {"group": "游戏生态", "name": "Steam 社区主页", "host": "steamcommunity.com", "ips": ["23.1.179.144", "96.7.99.225"], "path": "/"},
    {"group": "游戏生态", "name": "Steam Akamai 静态 CDN", "host": "community.akamai.steamstatic.com", "ips": ["184.27.185.73", "23.202.34.90"], "path": "/public/images/v6/logo_steam.svg"},
    {"group": "游戏生态", "name": "Ubisoft 育碧商城", "host": "store.ubi.com", "ips": ["23.41.142.46", "104.91.87.202"], "path": "/"},
    {"group": "游戏生态", "name": "EA App / Origin", "host": "api.origin.com", "ips": ["23.41.142.46", "104.91.87.202"], "path": "/"},
    {"group": "游戏生态", "name": "GOG Galaxy 商城", "host": "gog.com", "ips": ["151.101.194.133", "151.101.66.133"], "path": "/"},
    {"group": "游戏生态", "name": "暴雪战网商城", "host": "shop.battle.net", "ips": ["137.221.64.1"], "path": "/"},

    # 二次元 & 创作
    {"group": "二次元创作", "name": "Pixiv 网页与 API", "host": "www.pixiv.net", "ips": ["210.140.139.151", "210.140.139.155"], "path": "/"},
    {"group": "二次元创作", "name": "Pixiv pximg 插画 CDN", "host": "i.pximg.net", "ips": ["210.140.139.131", "210.140.139.133"], "path": "/"},
    {"group": "二次元创作", "name": "Pixiv Fanbox 赞助", "host": "fanbox.cc", "ips": ["172.64.146.116", "172.64.146.247"], "path": "/"},
    {"group": "二次元创作", "name": "BOOTH 同人商城", "host": "booth.pm", "ips": ["151.101.65.140", "151.101.129.140"], "path": "/"},
    {"group": "二次元创作", "name": "Danbooru 图库", "host": "danbooru.donmai.us", "ips": ["104.21.49.191", "172.67.168.170"], "path": "/"},
    {"group": "二次元创作", "name": "ArtStation 艺术库", "host": "www.artstation.com", "ips": ["151.101.194.133", "151.101.66.133"], "path": "/"},
    {"group": "二次元创作", "name": "VNDB 视觉小说库", "host": "vndb.org", "ips": ["217.182.194.133"], "path": "/"},
    {"group": "二次元创作", "name": "Kemono 创作者归档", "host": "kemono.su", "ips": ["104.21.61.122", "172.67.147.234"], "path": "/"},

    # 开发者 & AI
    {"group": "开发者 & AI", "name": "GitHub 主站 Web", "host": "github.com", "ips": ["20.205.243.166", "140.82.112.3"], "path": "/"},
    {"group": "开发者 & AI", "name": "GitHub Raw 直连", "host": "raw.githubusercontent.com", "ips": ["185.199.108.133", "185.199.109.133"], "path": "/"},
    {"group": "开发者 & AI", "name": "GitHub Releases 附件", "host": "objects.githubusercontent.com", "ips": ["185.199.108.133", "185.199.111.133"], "path": "/"},
    {"group": "开发者 & AI", "name": "HuggingFace 模型库", "host": "huggingface.co", "ips": ["18.164.124.63", "18.164.124.71"], "path": "/"},
    {"group": "开发者 & AI", "name": "Civitai C站 AI 模型", "host": "civitai.com", "ips": ["104.18.22.203", "104.18.23.203"], "path": "/"},
    {"group": "开发者 & AI", "name": "Docker Hub 镜像", "host": "hub.docker.com", "ips": ["44.205.64.79", "34.205.207.139"], "path": "/"},
    {"group": "开发者 & AI", "name": "GitLab 国际版", "host": "gitlab.com", "ips": ["172.65.251.78"], "path": "/"},
    {"group": "开发者 & AI", "name": "Stack Overflow 问答", "host": "stackoverflow.com", "ips": ["151.101.65.69", "151.101.129.69"], "path": "/"},

    # 综合与日常
    {"group": "综合工具", "name": "Wikipedia 维基百科", "host": "en.wikipedia.org", "ips": ["198.35.26.96", "208.80.154.224"], "path": "/"},
    {"group": "综合工具", "name": "Discord 网页/静态", "host": "discord.com", "ips": ["162.159.138.232", "162.159.135.232"], "path": "/"},
    {"group": "综合工具", "name": "Reddit 论坛社区", "host": "www.reddit.com", "ips": ["151.101.65.140", "151.101.129.140"], "path": "/"},
    {"group": "综合工具", "name": "OneDrive 个人版", "host": "onedrive.live.com", "ips": ["13.107.42.13"], "path": "/"}
]

def test_service_proxy_capability(item: dict) -> dict:
    host = item["host"]
    path = item.get("path", "/")
    ips = item["ips"]

    res = {
        "group": item["group"],
        "name": item["name"],
        "host": host,
        "tcp_ok": False,
        "tcp_latency": -1,
        "tls_empty_sni_ok": False,
        "tls_custom_sni_ok": False,
        "http_status": None,
        "best_ip": None,
        "recommended_method": "不可用",
        "verdict_level": 0, # 2: 直连可用, 1: 需策略, 0: 不可用
        "verdict": "[FAIL] 不可用"
    }

    # 1. 测试各 IP 的 TCP 握手
    valid_ip = None
    min_lat = 9999
    for ip in ips:
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        try:
            sock.connect((ip, 443))
            sock.close()
            elapsed = (time.perf_counter() - start) * 1000.0
            if elapsed < min_lat:
                min_lat = round(elapsed, 1)
                valid_ip = ip
        except Exception:
            try:
                sock.close()
            except Exception:
                pass

    if not valid_ip:
        res["verdict"] = "[FAIL] IP阻断(TCP超时)"
        return res

    res["tcp_ok"] = True
    res["tcp_latency"] = min_lat
    res["best_ip"] = valid_ip

    # 2. 测试 TLS 握手 (清空 SNI)
    ctx_empty = ssl.create_default_context()
    ctx_empty.check_hostname = False
    ctx_empty.verify_mode = ssl.CERT_NONE

    empty_sni_success = False
    try:
        raw_sock = socket.create_connection((valid_ip, 443), timeout=2.0)
        tls_sock = ctx_empty.wrap_socket(raw_sock, server_hostname=None)
        tls_sock.close()
        empty_sni_success = True
        res["tls_empty_sni_ok"] = True
    except Exception:
        pass

    # 3. 测试 TLS 握手 (标准 SNI)
    standard_sni_success = False
    try:
        raw_sock = socket.create_connection((valid_ip, 443), timeout=2.0)
        tls_sock = ctx_empty.wrap_socket(raw_sock, server_hostname=host)
        tls_sock.close()
        standard_sni_success = True
        res["tls_custom_sni_ok"] = True
    except Exception:
        pass

    # 4. 模拟实际 HTTP 请求
    http_status = None
    try:
        raw_sock = socket.create_connection((valid_ip, 443), timeout=2.5)
        target_sni = None if empty_sni_success else (host if standard_sni_success else None)
        tls_sock = ctx_empty.wrap_socket(raw_sock, server_hostname=target_sni)

        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        tls_sock.sendall(req.encode("utf-8"))

        resp_header = tls_sock.recv(1024).decode("utf-8", errors="ignore")
        tls_sock.close()

        if resp_header.startswith("HTTP/"):
            parts = resp_header.split()
            if len(parts) >= 2:
                http_status = int(parts[1])
                res["http_status"] = http_status
    except Exception:
        pass

    # 5. 综合评判
    if empty_sni_success and (http_status in [200, 301, 302, 307, 403, 404] if http_status else True):
        res["verdict_level"] = 2
        res["verdict"] = "[PASS-PERFECT] 直连可用(空SNI纯反代)"
        res["recommended_method"] = "清空SNI + IP优选"
    elif standard_sni_success and http_status:
        res["verdict_level"] = 2
        res["verdict"] = "[PASS-STABLE] 标准SNI直连可用"
        res["recommended_method"] = "标准SNI直连反代"
    elif empty_sni_success:
        res["verdict_level"] = 1
        res["verdict"] = "[PASS-FAST] 可用(空SNI穿透)"
        res["recommended_method"] = "空SNI反代"
    elif standard_sni_success:
        res["verdict_level"] = 1
        res["verdict"] = "[PASS-302] 可用(需SNI伪装/302)"
        res["recommended_method"] = "302重定向/白名单SNI"
    else:
        res["verdict_level"] = 0
        res["verdict"] = "[BLOCKED] SNI强阻断(需TCP分片)"
        res["recommended_method"] = "TCP分片/302"

    return res

def run_probe():
    print("================================================================")
    print("      PixivToolkit 全平台候选加速项真实网络可用性探测")
    print(f"      测试时间: {time.strftime('%Y-%m-%d %H:%M:%S')}  目标数量: {len(TARGET_SERVICES)}")
    print("================================================================\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(test_service_proxy_capability, item) for item in TARGET_SERVICES]
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            results.append(r)
            status_text = f"HTTP {r['http_status']}" if r['http_status'] else "NoResp"
            print(f"[{r['group']}] {r['name']:<18} | 延迟: {str(r['tcp_latency']) + 'ms':<8} | 状态: {r['verdict']:<28} | 策略: {r['recommended_method']}")

    # 保存 JSON
    out_file = Path(__file__).resolve().parent / "probe_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print("\n================================================================")
    print("                      可用性总结统计表")
    print("================================================================")

    pass_perfect = [r for r in results if r["verdict_level"] == 2]
    pass_good = [r for r in results if r["verdict_level"] == 1]
    failed = [r for r in results if r["verdict_level"] == 0]

    print(f"\n>> 完美免梯直连/反代可用: {len(pass_perfect)} 项")
    for r in pass_perfect:
        print(f"   [+] {r['name']:<20} 延迟: {r['tcp_latency']}ms ({r['host']})")

    print(f"\n>> 需特定策略/白名单SNI可用: {len(pass_good)} 项")
    for r in pass_good:
        print(f"   [~] {r['name']:<20} 延迟: {r['tcp_latency']}ms ({r['host']})")

    print(f"\n>> 当前网络被强阻断/需TCP分片: {len(failed)} 项")
    for r in failed:
        print(f"   [-] {r['name']:<20} ({r['host']}) -> {r['verdict']}")

if __name__ == "__main__":
    run_probe()
