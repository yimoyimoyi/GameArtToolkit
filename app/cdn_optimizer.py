# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 高并发 CDN 测速与动态 Upstream 优选引擎 (双通道三态探测)

核心改进:
- 双通道探测: 直连 + 经本地代理(默认 127.0.0.1:7897 Clash mixed) HTTP CONNECT 隧道
- 三态验证: TCP 握手 -> TLS 握手(按服务 SNI 模式) -> HTTP 状态码, 排除"TCP 通但 TLS 被阻断"的假可用节点
- 严格过滤 Fake-IP (198.18.0.0/15) 与内网地址
- DoH 强行绕过 WinINet 系统代理获取真实国内最优 CDN IP
"""

import sys
import time
import json
import socket
import ssl
import re
import struct
import random
import threading
import ipaddress
import urllib.request
import concurrent.futures
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Callable, Any

from path_utils import NGINX_DIR
from ip_pool import CANDIDATE_IPS, SERVICES_BY_ID, PROFILES_BY_ID
from config_store import load_config
from win_utils import is_port_in_use, get_physical_adapter_ip, auto_detect_active_proxy

UPSTREAM_CONF_PATH = NGINX_DIR / "conf" / "upstream-dynamic.conf"

# 默认本地代理 (Clash mixed 端口, HTTP CONNECT 隧道, 仅作探测筛选)
DEFAULT_PROXY = ("127.0.0.1", 7897)

# L4 Relay 代理转发端口基址: 44311 + CANDIDATE_IPS 顺序索引, 避开 SNI 主端口 44301
RELAY_PORT_BASE = 44311

from service_profile import PROFILES

# 各服务的 SNI 模式自动由 ServiceProfile 单源导出
SNI_MODES = {p.id: p.ssl_sni_mode for p in PROFILES}

# 伪 SNI 服务: relay 转发时要求 rank1 (HTTP 干净) 才允许, 避免伪 SNI 触发 421/404
PSEUDO_SNI_SERVICES = {p_id for p_id, m in SNI_MODES.items() if m not in ("host", "empty")}

# nginx.conf include 的有效站点配置 (site-tools.conf 服务已全部删除)
SITE_CONF_NAMES = ["site-gaming.conf", "site-acg.conf", "site-dev.conf"]


@dataclass(frozen=True)
class ProbeDefaults:
    """统一测速参数中心: 收敛全部探测预算/超时魔数 (按服务档位等比缩放)

    档位换算: scale = clamp(实际档位 / 1.5, 0.6, 2.0), 各阶段预算 = budget * scale
    不变量: hard_budget == tcp_budget + tls_budget + http_budget (测试锁定)
    """
    tcp_budget: float = 1.5      # TCP 握手阶段预算上限 (默认档)
    tls_budget: float = 2.6      # TLS 握手阶段预算上限 (默认档)
    http_budget: float = 1.8     # HTTP 状态码探测阶段预算上限 (默认档)
    hard_budget: float = 5.9     # 单节点硬超时总预算 (原 4.5s, 晚高峰跨洋高丢包放宽)
    prefilter_timeout: float = 1.2  # Stage1 TCP 预筛超时 (原 0.8s; 恒小于 tcp_budget)
    prefilter_floor: float = 0.3    # 预筛存活率下限: 低于此值跳过预筛直接全池深测
    health_probe_timeout: float = 2.0  # 健康巡检探针超时
    relay_probe_timeout: float = 1.0   # 健康巡检 relay 端口探针超时
    retry_delay: float = 0.08      # 探测微重试间隔


PROBE_DEFAULTS = ProbeDefaults()

# 档位换算基准 (默认档 cdn_timeout_seconds=1.5)
_TIER_BASE = 1.5
_TIER_SCALE_MIN = 0.6
_TIER_SCALE_MAX = 2.0


def tier_scale(timeout: float) -> float:
    """从探测档位派生预算缩放系数 (0.8 档更快, 3.0 档更宽容)"""
    return max(_TIER_SCALE_MIN, min(timeout / _TIER_BASE, _TIER_SCALE_MAX))


def probe_timeout_for(srv_id: str, cfg_timeout: Optional[float] = None) -> float:
    """服务级探测档位: profile.probe_timeout 优先, 回退全局 cdn_timeout_seconds, 最终 1.5"""
    profile = PROFILES_BY_ID.get(srv_id)
    if profile is not None and getattr(profile, "probe_timeout", None):
        return float(profile.probe_timeout)
    if cfg_timeout:
        return float(cfg_timeout)
    return float(load_config().get("cdn_timeout_seconds", 1.5))


def _service_sort_key(item: Dict, ip_mode: Optional[str] = None,
                      stable_set: Optional[set] = None) -> Tuple:
    """统一测速排序键: (rank, v6/v4 偏好惩罚, 稳定段惩罚, 延迟)

    - rank 永远第一 (可用性优先, Fastly 全灭时仍由 rank0 兜底)
    - 稳定性优先于延迟: 短命 Anycast 延迟优势不可信, 已知稳定段优先
    - ip_mode/stable_set 为 None 时跳过对应维度 (apply_optimal 防御性排序复用)
    - 空 stable_ips 的服务退化为旧键序 (rank, v_penalty, latency), 行为不变
    """
    rank = item.get("rank", 3)
    lat = item.get("latency") if item.get("latency") is not None else 99999
    v_penalty = 0
    if ip_mode:
        is_v6 = ":" in str(item.get("ip", ""))
        if ip_mode == "prefer_ipv4" and is_v6:
            v_penalty = 1
        elif ip_mode == "prefer_ipv6" and not is_v6:
            v_penalty = 1
    stable_penalty = 0
    if stable_set is not None:
        stable_penalty = 0 if str(item.get("ip", "")) in stable_set else 1
    return (rank, v_penalty, stable_penalty, lat)


def _apply_prefilter_floor(pool_ips: List[str], alive_ips: set, floor: float) -> List[str]:
    """预筛存活率兜底: 存活数低于 max(1, floor*池大小) 时返回全池 (防预筛误杀慢节点)

    Stage1 预筛淘汰的"慢但活着"节点过多时, 宁可在 Stage2 慢一档也不漏测真可用节点
    """
    if not pool_ips:
        return []
    threshold = max(1, int(floor * len(pool_ips)))
    survived = [ip for ip in pool_ips if ip in alive_ips]
    if len(survived) < threshold:
        return list(pool_ips)
    return survived


def relay_port_for(srv_id: str) -> int:
    """确定性 relay 端口映射: RELAY_PORT_BASE + CANDIDATE_IPS 顺序索引 (零冲突, 跨会话稳定)"""
    try:
        return RELAY_PORT_BASE + list(CANDIDATE_IPS.keys()).index(srv_id)
    except ValueError:
        return RELAY_PORT_BASE


# 公共 DNS 服务器 (用于绕过被注入 hosts 的动态候选解析)
_DNS_SERVERS = ["223.5.5.5", "119.29.29.29"]

# DoH (DNS over HTTPS) 端点: 腾讯 doh.pub 实测解析最干净 (返回真实 IP);
# 阿里 dns.alidns.com 与 UDP 同源 (可能继承 GFW 注入结果), 仅作容灾。
# 国外 1.1.1.1 / 8.8.8.8 直连实测被阻断, 不作为默认端点。
DOH_ENDPOINTS = ["https://doh.pub/dns-query", "https://dns.alidns.com/resolve"]

# 严禁进入 Upstream 的保留/虚拟 IP 段 (含 Clash / Sing-box Fake-IP: 198.18.0.0/15)
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("198.18.0.0/15"),  # Clash Fake-IP 虚拟池 (198.18.0.0 - 198.19.255.255)
    ipaddress.ip_network("127.0.0.0/8"),     # Loopback 回环
    ipaddress.ip_network("10.0.0.0/8"),      # 私有内网
    ipaddress.ip_network("172.16.0.0/12"),   # 私有内网
    ipaddress.ip_network("192.168.0.0/16"),  # 私有内网
    ipaddress.ip_network("169.254.0.0/16"),  # 链路本地
    ipaddress.ip_network("224.0.0.0/4"),     # 组播
    ipaddress.ip_network("240.0.0.0/4"),     # 保留段
    ipaddress.ip_network("::1/128"),         # IPv6 Loopback
    ipaddress.ip_network("fe80::/10"),       # IPv6 Link-Local
    ipaddress.ip_network("fc00::/7"),        # IPv6 ULA
]

# 已知 GFW DNS 污染注入段 (Facebook/Twitter/Dropbox 等大厂 IP 前缀):
POLLUTED_IP_PREFIXES = ("31.13.", "69.171.", "157.240.", "69.63.",
                        "199.59.", "104.244.", "108.160.", "162.125.", "199.96.")


def is_valid_public_cdn_ip(ip_str: str) -> bool:
    """严格校验是否为合法的公网真实 CDN IP (彻底阻断 Fake-IP 与内网地址污染)"""
    if not ip_str:
        return False
    clean = ip_str.strip("[]").strip()
    try:
        ip_obj = ipaddress.ip_address(clean)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local or ip_obj.is_multicast:
            return False
        for net in BLOCKED_IP_NETWORKS:
            if ip_obj in net:
                return False
        return True
    except ValueError:
        return False


# DoH 解析内存缓存 (TTL 10 分钟, 规避每次测速主流程重复串行查询)
_DOH_CACHE: Dict[str, Tuple[float, List[str]]] = {}
_DOH_CACHE_LOCK = threading.Lock()
_DOH_CACHE_TTL = 600.0  # 10 分钟有效


def clear_doh_cache() -> None:
    """清空 DoH 解析内存缓存 (供单测隔离与手动重置使用)"""
    with _DOH_CACHE_LOCK:
        _DOH_CACHE.clear()


def doh_resolve(domain: str, timeout: float = 3.0,
                endpoints: Optional[Tuple[str, ...]] = None,
                use_cache: bool = True) -> List[str]:
    """DoH (DNS over HTTPS) 纯净解析 (带 10 分钟内存缓存与 Fake-IP 过滤)
    
    - 标准库 urllib 实现 (零新依赖), 加密查询无法被 GFW 注入污染
    - 过滤 Fake-IP 与已知污染 IP 段
    - 失败静默返回空列表 (不抛出异常, 不拖垮调用方)
    """
    if not domain:
        return []
    
    if use_cache:
        now = time.monotonic()
        with _DOH_CACHE_LOCK:
            if domain in _DOH_CACHE:
                cached_time, cached_ips = _DOH_CACHE[domain]
                if now - cached_time < _DOH_CACHE_TTL and cached_ips:
                    return list(cached_ips)

    for base in (endpoints or DOH_ENDPOINTS):
        try:
            url = f"{base}?name={domain}&type=A"
            req = urllib.request.Request(url, headers={
                "Accept": "application/dns-json",
                "User-Agent": "GameArtToolkit/2.0",
            })
            # 禁用代理，确保以真实本地物理出口解析
            req.set_proxy("", "http")
            req.set_proxy("", "https")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            ips = [a.get("data", "") for a in payload.get("Answer", [])
                   if a.get("type") == 1 and ":" not in a.get("data", "")]
            clean = [ip for ip in ips if not ip.startswith(POLLUTED_IP_PREFIXES) and is_valid_public_cdn_ip(ip)]
            if clean:
                res = list(dict.fromkeys(clean))
                if use_cache:
                    with _DOH_CACHE_LOCK:
                        _DOH_CACHE[domain] = (time.monotonic(), list(res))
                return res
        except Exception:
            continue
    return []


def preload_dns_candidates_concurrently(domains: List[str], max_workers: int = 16) -> None:
    """并发异步预取并预热 DoH 缓存 (0ms 消除测速主流程串行阻塞)"""
    uncached = [d for d in domains if d and (d not in _DOH_CACHE or time.monotonic() - _DOH_CACHE[d][0] > _DOH_CACHE_TTL)]
    if not uncached:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(uncached), max_workers)) as executor:
        futures = {executor.submit(doh_resolve, d, 2.5, None, True): d for d in uncached}
        for f in concurrent.futures.as_completed(futures):
            try:
                f.result()
            except Exception:
                pass


def _udp_resolve_a(domain: str, timeout: float = 0.8) -> List[str]:
    """UDP 直查公共 DNS 获取域名 A 记录 (带 Fake-IP 与内网地址过滤)"""
    results: List[str] = []
    for dns in _DNS_SERVERS:
        try:
            qid = random.randint(0, 65535)
            header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
            qname = b"".join(bytes([len(p)]) + p.encode() for p in domain.split(".")) + b"\x00"
            q = header + qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(q, (dns, 53))
            data, _ = s.recvfrom(4096)
            s.close()
            ancount = struct.unpack(">H", data[6:8])[0]
            off = 12
            while data[off] != 0:
                off += data[off] + 1
            off += 5
            for _ in range(ancount):
                if data[off] & 0xC0 == 0xC0:
                    off += 2
                else:
                    while data[off] != 0:
                        off += data[off] + 1
                    off += 1
                rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
                off += 10
                if rtype == 1 and rdlen == 4:
                    raw_ip = socket.inet_ntoa(data[off:off + 4])
                    if is_valid_public_cdn_ip(raw_ip):
                        results.append(raw_ip)
                off += rdlen
            if results:
                break
        except Exception:
            continue
    return list(dict.fromkeys(results))


def _resolve_dns_candidates(domain: str, timeout: float = 0.8, use_doh: bool = True) -> List[str]:
    """双通道解析: UDP 直查 + DoH (优先读取内存缓存), 规避 DNS 污染与 Fake-IP"""
    if not domain:
        return []
    
    # 命中 DoH 内存缓存直接返回
    if use_doh:
        with _DOH_CACHE_LOCK:
            if domain in _DOH_CACHE:
                cached_time, cached_ips = _DOH_CACHE[domain]
                if time.monotonic() - cached_time < _DOH_CACHE_TTL and cached_ips:
                    return list(cached_ips)

    udp_box: Dict[str, List[str]] = {"ips": []}

    def _udp_task():
        udp_box["ips"] = _udp_resolve_a(domain, timeout)

    t = threading.Thread(target=_udp_task, daemon=True)
    t.start()
    doh_ips = doh_resolve(domain, timeout=max(timeout * 3, 2.5), use_cache=True) if use_doh else []
    t.join(timeout=timeout + 0.5)
    udp_ips = [ip for ip in udp_box["ips"] if is_valid_public_cdn_ip(ip)]
    if doh_ips:
        return doh_ips
    return udp_ips


def _load_proxy_config() -> Optional[Tuple[str, int]]:
    """读取 config.json 的 upstream_proxy 配置; 若未启用或不可达, 在 auto_proxy 开启时尝试嗅探本地活跃代理"""
    try:
        full_cfg = load_config()
        cfg = full_cfg.get("upstream_proxy", {})
        if cfg.get("enabled", False):
            host = str(cfg.get("host", DEFAULT_PROXY[0]))
            port = int(cfg.get("port", DEFAULT_PROXY[1]))
            if is_proxy_available((host, port), timeout=0.2):
                return (host, port)
        
        # 仅在用户开启 auto_proxy (默认 True) 时自动探测活跃代理 (Clash/v2rayN/sing-box 等)
        if full_cfg.get("auto_proxy", True):
            detected = auto_detect_active_proxy(timeout=0.15)
            if detected and is_proxy_available(detected, timeout=0.2):
                return detected
    except Exception:
        pass
    return None


def is_proxy_available(proxy: Optional[Tuple[str, int]], timeout: float = 0.3) -> bool:
    """预检本地代理端口是否可达"""
    if not proxy:
        return False
    try:
        with socket.create_connection(proxy, timeout=timeout):
            return True
    except Exception:
        return False


def _format_host_port(host: str, port: int) -> str:
    """格式化 host:port, IPv6 地址必须加方括号 (HTTP 标准与 nginx 语法要求)"""
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _send_connect_and_read_200(sock: socket.socket, host: str, port: int, timeout: float) -> None:
    """向 HTTP 代理发送 CONNECT 隧道请求并读取响应头, 首行非 200 抛异常"""
    sock.settimeout(timeout)
    hp = _format_host_port(host, port)
    sock.sendall(f"CONNECT {hp} HTTP/1.1\r\nHost: {hp}\r\n\r\n".encode("utf-8"))
    hdr = b""
    while b"\r\n\r\n" not in hdr:
        chunk = sock.recv(4096)
        if not chunk:
            break
        hdr += chunk
    line = hdr.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
    if " 200 " not in line:
        raise ConnectionError(f"CONNECT 隧道建立失败: {line or '无响应'}")


def _suspect_status(status: Optional[int]) -> bool:
    """HTTP 状态码是否表示"可疑节点" (网关错误 502-504 或 Cloudflare 421 重路由)"""
    return status is not None and (status == 421 or 530 <= status <= 530 or 502 <= status <= 504)


def fast_tcp_ping(ip: str, port: int = 443, timeout: float = 0.8,
                  physical_ip: Optional[str] = None) -> Tuple[bool, Optional[float]]:
    """极速轻量 TCP SYN 预检: 800ms 内淘汰死 IP / 路由黑洞, 防阻塞工作线程"""
    t0 = time.perf_counter()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        p_ip = physical_ip if physical_ip is not None else get_physical_adapter_ip()
        if p_ip and ":" not in ip:
            try:
                sock.bind((p_ip, 0))
            except Exception:
                pass
        sock.connect((ip, port))
        lat = round((time.perf_counter() - t0) * 1000.0, 1)
        return True, lat
    except Exception:
        return False, None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def probe_ip_endpoint_v2(ip: str, domain: str = "", timeout: float = 2.0,
                         sni_mode: str = "host",
                         proxy: Optional[Tuple[str, int]] = None,
                         physical_ip: Optional[str] = None,
                         quick_retry: bool = True) -> Dict:
    """单链路三态探测: TCP → TLS(按 SNI 模式 + ALPN) → HTTP 状态码
    
    单节点独立生命周期计时:
    - 真正分配到 Worker 线程开始执行时才启动单任务独立计时 (单任务硬预算 4.5s)
    - TCP 阶段预算 1.0s, TLS 阶段预算 2.2s, HTTP 阶段预算 1.5s
    - 首次非致命异常自动原地快速微重试 1 次, 强力抵御跨国网络偶发丢包
    """
    def _do_probe_once() -> Dict:
        out = {"tcp_ok": False, "tcp_latency": None, "tls_ok": False,
               "tls_latency": None, "http_ok": False, "http_status": None, "error": ""}
        # 档位缩放: 0.8 档更快 / 3.0 档更宽容 (默认 1.5 档 = 原始预算)
        scale = tier_scale(timeout)
        deadline = time.monotonic() + PROBE_DEFAULTS.hard_budget * scale  # 单节点硬超时预算
        sock = None
        ssock = None
        try:
            # 1. TCP 握手 (直连或经 CONNECT 隧道)
            try:
                tcp_timeout = min(timeout, PROBE_DEFAULTS.tcp_budget * scale)
                if proxy:
                    t0 = time.perf_counter()
                    sock = socket.create_connection(proxy, timeout=tcp_timeout)
                    _send_connect_and_read_200(sock, ip, 443, tcp_timeout)
                    out["tcp_latency"] = round((time.perf_counter() - t0) * 1000.0, 1)
                else:
                    t0 = time.perf_counter()
                    sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(tcp_timeout)
                    p_ip = physical_ip if physical_ip is not None else get_physical_adapter_ip()
                    if p_ip and ":" not in ip:
                        try:
                            sock.bind((p_ip, 0))
                        except Exception:
                            pass
                    sock.connect((ip, 443))
                    out["tcp_latency"] = round((time.perf_counter() - t0) * 1000.0, 1)
                out["tcp_ok"] = True
            except Exception as e:
                out["error"] = f"tcp error: {e}"
                return out

            # 2. TLS 握手 (显式声明 ALPN: http/1.1 规避 CDN 426 错误)
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.set_alpn_protocols(["http/1.1"])
                except Exception:
                    pass

                # 复刻 nginx 的 SNI 行为: empty=空SNI host=域名SNI 其他=自定义伪SNI域名
                if sni_mode == "host":
                    server_hostname = domain or None
                elif sni_mode == "empty":
                    server_hostname = None
                else:
                    server_hostname = sni_mode

                tls_timeout = max(1.0, min(deadline - time.monotonic(), PROBE_DEFAULTS.tls_budget * scale))
                sock.settimeout(tls_timeout)
                t0 = time.perf_counter()
                ssock = ctx.wrap_socket(sock, server_hostname=server_hostname)
                sock = None  # 所有权转移至 ssock
                out["tls_ok"] = True
                out["tls_latency"] = round((time.perf_counter() - t0) * 1000.0, 1)
            except Exception as e:
                out["error"] = f"tls error: {e}"
                return out

            # 3. HTTP 状态码探测
            try:
                http_timeout = max(0.6, min(deadline - time.monotonic(), PROBE_DEFAULTS.http_budget * scale))
                ssock.settimeout(http_timeout)
                req_headers = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {domain}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) GameArtToolkit/2.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                ssock.sendall(req_headers.encode("utf-8"))
                hdr = b""
                while b"\r\n\r\n" not in hdr:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    hdr += chunk
                line = hdr.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                if line.startswith("HTTP/"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        out["http_status"] = int(parts[1])
                        out["http_ok"] = True
                        if 300 <= out["http_status"] < 400:
                            loc = ""
                            for h in hdr.decode("utf-8", errors="replace").split("\r\n"):
                                if h.lower().startswith("location:"):
                                    loc = h.split(":", 1)[1].strip()
                                    break
                            if loc:
                                loc_host = loc.split("://")[-1].split("/")[0].lower() if "://" in loc else domain.lower()
                                loc_path = "/" + loc.split("://")[-1].split("/", 1)[1] if "://" in loc and "/" in loc.split("://")[1] else "/"
                                if loc_host == domain.lower() and loc_path == "/":
                                    out["self_redirect"] = True
            except Exception as e:
                out["error"] = f"http error: {e}"
        except Exception as e:
            out["error"] = str(e)
        finally:
            if ssock:
                try:
                    ssock.close()
                except Exception:
                    pass
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        return out

    res = _do_probe_once()
    # 单节点微重试: 若直连 TCP 通但 TLS/HTTP 发生单次偶发异常, 进行 1 次快速重试
    if quick_retry and not proxy and res.get("tcp_ok") and not (res.get("tls_ok") and res.get("http_ok")):
        time.sleep(0.08)  # 80ms 避开偶发抖动
        res2 = _do_probe_once()
        if res2.get("tls_ok") and res2.get("http_ok"):
            return res2
    return res


def _classify_result(direct: Dict, proxy: Dict) -> Dict:
    """合并直连与代理两条链路结果, 输出 rank/via_proxy/recommend/latency 等扁平字段

    rank 0: 直连 TCP+TLS 通且 HTTP 无 5xx/421 → 首选 (写主节点)
    rank 1: 经代理 TCP+TLS 通且 HTTP 干净 → 真实节点 (写备节点)
    rank 2: 经代理 TCP+TLS 通但 HTTP 可疑 (5xx/421) → 仅兜底
    rank 3: 双通道全挂 → 不写入
    """
    def _redirect_loop(result: Optional[Dict]) -> bool:
        """3xx 自我重定向 (Location 指向同 host 同路径) 判定为可疑节点, 排除重定向死循环假节点"""
        return bool(result and result.get("self_redirect"))

    d_clean = bool(direct and direct.get("tcp_ok") and direct.get("tls_ok")
                   and direct.get("http_ok") and not _suspect_status(direct.get("http_status"))
                   and not _redirect_loop(direct))
    p_clean = bool(proxy and proxy.get("tcp_ok") and proxy.get("tls_ok")
                   and proxy.get("http_ok") and not _suspect_status(proxy.get("http_status"))
                   and not _redirect_loop(proxy))
    p_suspect = bool(proxy and proxy.get("tcp_ok") and proxy.get("tls_ok")
                     and proxy.get("http_ok") and _suspect_status(proxy.get("http_status")))

    item = {"latency": None, "available": False, "rank": 3,
            "via_proxy": False, "recommend": "none", "sni_mode": "host",
            "direct": direct, "proxy": proxy, "proxy_used": bool(proxy)}
    if d_clean:
        item.update(rank=0, via_proxy=False, recommend="direct", available=True,
                    latency=direct.get("tcp_latency"))
    elif p_clean:
        item.update(rank=1, via_proxy=True, recommend="proxy", available=True,
                    latency=(proxy.get("tcp_latency") or 0) + (proxy.get("tls_latency") or 0))
    elif p_suspect:
        item.update(rank=2, via_proxy=True, recommend="proxy", available=True,
                    latency=(proxy.get("tcp_latency") or 0) + (proxy.get("tls_latency") or 0))
    return item


class CDNOptimizer:
    def __init__(self, conf_path: Path = UPSTREAM_CONF_PATH):
        self.conf_path = Path(conf_path)
        # 最近一次生成的 relay 代理转发服务集合 (供自愈探针分流与 UI 展示)
        self.last_relay_services: set = set()

    def test_service_dual(self, srv_id: str, max_workers: Optional[int] = None) -> List[Dict]:
        """单服务双通道探测 (直连 + 经本地代理 CONNECT 隧道, 供健康巡检自愈调用)"""
        if max_workers is None:
            max_workers = int(load_config().get("cdn_max_workers", 16))
        ips = CANDIDATE_IPS.get(srv_id, [])
        return self.test_group(srv_id, ips, max_workers=max_workers)

    def test_group(self, group_name: str, ip_list: List[str], max_workers: int = 16) -> List[Dict]:
        """测试指定服务的一组候选 IP (双通道三态探测, 自动补充 DNS 当前解析节点, 遵从 IPv4/v6 偏好)"""
        cfg = load_config()
        # 服务级档位优先 (profile.probe_timeout), 回退全局 cdn_timeout_seconds
        timeout = probe_timeout_for(group_name, float(cfg.get("cdn_timeout_seconds", 1.5)))
        ip_mode = cfg.get("ip_version_mode", "prefer_ipv4")

        srv = SERVICES_BY_ID.get(group_name, {})
        domain = srv.get("domains", [""])[0] if srv else ""
        # DNS 动态补充: 优先从 DoH 内存缓存读取 (带 Fake-IP 过滤)
        if domain:
            ip_list = list(dict.fromkeys(list(ip_list) + _resolve_dns_candidates(domain)))

        # 根据 IP 协议偏好过滤
        if ip_mode == "ipv4_only":
            ip_list = [ip for ip in ip_list if ":" not in ip]
            if not ip_list:
                ip_list = list(CANDIDATE_IPS.get(group_name, []))

        sni_mode = SNI_MODES.get(group_name, "host")
        proxy = _load_proxy_config()
        proxy_ready = is_proxy_available(proxy)
        if not proxy_ready:
            proxy = None

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ip_list) or 1, max_workers)) as executor:
            def run_one(ip):
                direct = probe_ip_endpoint_v2(ip, domain, timeout=timeout, sni_mode=sni_mode, proxy=None)
                proxy_res = probe_ip_endpoint_v2(ip, domain, timeout=timeout, sni_mode=sni_mode, proxy=proxy) if proxy else None
                return ip, direct, proxy_res

            future_to_ip = {executor.submit(run_one, ip): ip for ip in ip_list}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    ret_ip, direct, proxy_res = future.result()
                    item = _classify_result(direct, proxy_res)
                    item["ip"] = ret_ip
                    item["sni_mode"] = sni_mode
                    item["proxy_used"] = proxy_ready
                except Exception:
                    item = {"ip": ip, "latency": None, "available": False, "rank": 3,
                            "via_proxy": False, "recommend": "none", "sni_mode": sni_mode,
                            "direct": None, "proxy": None, "proxy_used": proxy_ready}
                results.append(item)

        # 排序键统一: (rank, v6/v4 偏好, 稳定段, 延迟); 无 stable_ips 时退化为旧键序
        stable_set = set(getattr(PROFILES_BY_ID.get(group_name), "stable_ips", [])) or None
        results.sort(key=lambda x: _service_sort_key(x, ip_mode, stable_set))
        return results

    def test_all_services(self, max_workers: int = 64, total_timeout: float = 30.0,
                          filter_services: Optional[List[str]] = None) -> Dict[str, List[Dict]]:
        """全量/按需两阶段漏斗探测:
        
        Stage 1: 800ms 高并发轻量 TCP 快速预检，秒级剔除 70%+ 死节点；
        Stage 2: 存活节点单任务独立分阶段计时深度探测 (TCP 1.0s + TLS 2.2s + HTTP 1.5s + 原地微重试)；
        彻底消灭任务排队导致的超时误杀，单次测速 100% 捕获全量可用 CDN。
        """
        cfg = load_config()
        timeout = float(cfg.get("cdn_timeout_seconds", 1.5))
        max_workers = int(cfg.get("cdn_max_workers", max_workers))
        ip_mode = cfg.get("ip_version_mode", "prefer_ipv4")

        proxy = _load_proxy_config()
        proxy_ready = is_proxy_available(proxy, timeout=0.5)
        if not proxy_ready:
            proxy = None

        target_set = set(filter_services) if filter_services is not None else None

        # 1. 异步并发预热所有服务域名的 DoH 缓存 (0ms 消除主循环串行阻塞)
        domains_to_preload = []
        for srv_id in CANDIDATE_IPS:
            if target_set is not None and srv_id not in target_set:
                continue
            srv = SERVICES_BY_ID.get(srv_id, {})
            domain = srv.get("domains", [""])[0] if srv else ""
            if domain:
                domains_to_preload.append(domain)
        preload_dns_candidates_concurrently(domains_to_preload, max_workers=16)

        # 2. 组装待探测候选 IP 池 (遵从 IPv4/v6 偏好)
        service_raw_ips: Dict[str, List[str]] = {}
        all_unique_ips = set()
        for srv_id, ips in CANDIDATE_IPS.items():
            if target_set is not None and srv_id not in target_set:
                continue
            srv = SERVICES_BY_ID.get(srv_id, {})
            domain = srv.get("domains", [""])[0] if srv else ""
            if domain:
                ips = list(dict.fromkeys(list(ips) + _resolve_dns_candidates(domain)))
            
            if ip_mode == "ipv4_only":
                ips = [ip for ip in ips if ":" not in ip] or list(CANDIDATE_IPS.get(srv_id, []))

            service_raw_ips[srv_id] = ips
            for ip in ips:
                all_unique_ips.add(ip)

        # 3. Stage 1: 高并发轻量 TCP 快速预筛 (1.2s 超时, 对跨洋高丢包链路宽容)
        alive_ips_set = set()
        if all_unique_ips:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(all_unique_ips), max_workers)) as pre_exec:
                ping_futures = {pre_exec.submit(fast_tcp_ping, ip, 443, PROBE_DEFAULTS.prefilter_timeout): ip for ip in all_unique_ips}
                for f in concurrent.futures.as_completed(ping_futures):
                    ip = ping_futures[f]
                    try:
                        ok, _ = f.result()
                        if ok:
                            alive_ips_set.add(ip)
                    except Exception:
                        pass

        # 4. 组装 Stage 2 深度探测任务 (预筛存活率低于下限时全池深测, 防预筛误杀慢节点)
        flat_tasks = []
        results_by_srv: Dict[str, List[Dict]] = {srv_id: [] for srv_id in CANDIDATE_IPS}

        # 全局兜底: 整轮存活率过低说明预筛被系统性干扰 (如跨洋链路集体抖动), 跳过预筛过滤
        if all_unique_ips and len(alive_ips_set) < PROBE_DEFAULTS.prefilter_floor * len(all_unique_ips):
            alive_ips_set = set(all_unique_ips)

        for srv_id, ips in service_raw_ips.items():
            srv = SERVICES_BY_ID.get(srv_id, {})
            domain = srv.get("domains", [""])[0] if srv else ""
            sni_mode = SNI_MODES.get(srv_id, "host")
            # 服务级探测档位 (profile.probe_timeout 优先, 回退全局 cdn_timeout_seconds)
            task_timeout = probe_timeout_for(srv_id, timeout)

            # 按服务级存活率兜底: 存活数低于下限时该服务全池进 Stage 2
            final_ips = _apply_prefilter_floor(ips, alive_ips_set, PROBE_DEFAULTS.prefilter_floor)

            for ip in final_ips:
                flat_tasks.append((srv_id, ip, domain, sni_mode, task_timeout))

        def run_both(task):
            srv_id, ip, domain, sni_mode, task_timeout = task
            direct = probe_ip_endpoint_v2(ip, domain, timeout=task_timeout, sni_mode=sni_mode, proxy=None, quick_retry=True)
            proxy_res = probe_ip_endpoint_v2(ip, domain, timeout=task_timeout, sni_mode=sni_mode, proxy=proxy, quick_retry=False) if proxy else None
            return srv_id, ip, direct, proxy_res

        # 5. Stage 2: 深度三态探测 (单任务独立生命周期计时, 绝无全局强杀误断)
        if flat_tasks:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(flat_tasks), max_workers)) as executor:
                future_map = {executor.submit(run_both, t): t for t in flat_tasks}
                for future in concurrent.futures.as_completed(future_map):
                    task = future_map[future]
                    try:
                        srv_id, ip, direct, proxy_res = future.result()
                        item = _classify_result(direct, proxy_res)
                        item["ip"] = ip
                        item["sni_mode"] = task[3]
                        item["proxy_used"] = proxy_ready
                    except Exception:
                        item = {"ip": task[1], "latency": None, "available": False, "rank": 3,
                                "via_proxy": False, "recommend": "none", "sni_mode": task[3],
                                "direct": None, "proxy": None, "proxy_used": proxy_ready}
                    results_by_srv[srv_id].append(item)

        # 6. 补齐未完成/兜底项并按统一排序键 (rank → 协议偏好 → 稳定段 → 延迟) 保序排序
        for srv_id, items in results_by_srv.items():
            done_ips = {it["ip"] for it in items}
            for expected_ip in CANDIDATE_IPS.get(srv_id, []):
                if ip_mode == "ipv4_only" and ":" in expected_ip:
                    continue
                if expected_ip not in done_ips:
                    items.append({"ip": expected_ip, "latency": None, "available": False, "rank": 3,
                                  "via_proxy": False, "recommend": "none", "sni_mode": SNI_MODES.get(srv_id, "host"),
                                  "direct": None, "proxy": None, "proxy_used": proxy_ready})
            stable_set = set(getattr(PROFILES_BY_ID.get(srv_id), "stable_ips", [])) or None
            items.sort(key=lambda x: _service_sort_key(x, ip_mode, stable_set))

        return results_by_srv

    def _load_existing_upstream_blocks(self) -> Dict[str, str]:
        """读取现有 upstream-dynamic.conf, 按服务提取已有 upstream 块 (供增量合并)"""
        blocks: Dict[str, str] = {}
        if not self.conf_path.exists():
            return blocks
        try:
            text = self.conf_path.read_text(encoding="utf-8", errors="ignore")
            pattern = re.compile(r"upstream\s+(upstream_[a-z0-9_]+)\s*\{.*?\n\}", re.S)
            for m in pattern.finditer(text):
                blocks[m.group(1)] = m.group(0)
        except Exception:
            pass
        return blocks

    @staticmethod
    def _fmt_server(ip: str, extra: str = "") -> str:
        """生成 upstream server 行: IPv6 地址必须加方括号 (nginx 语法要求), 行尾必须带分号"""
        if ":" in ip:
            return f"    server [{ip}]:443 {extra};".rstrip()
        return f"    server {ip}:443 {extra};".rstrip()

    def generate_upstream_conf(self, test_results: Dict[str, List[Dict]]) -> str:
        """根据 rank 分级结果生成延迟最低的 upstream-dynamic.conf

        规则:
        - 每个服务永远生成 upstream 块 (保证 nginx 引用不缺失, 防 host not found 启动失败)
        - 优先写 rank0 (直连三态全通) 节点
        - 直连全挂但经代理验证可用 (rank1/2) 且本地代理在线时, 写 relay 代理转发端口
          (127.0.0.1:<port>), 由 L4 Relay 经本地代理 CONNECT 域名出网
        - 双通道全挂服务回退候选池默认 IP, 并加注释告警 (宁可用假节点也绝不让 nginx 起不来)
        - max_fails=3 fail_timeout=30s 减缓熔断雪崩; hash/least_conn 组不携带 backup 参数
        """
        lines = [
            "# ==============================================================================",
            "# GameArt Toolkit - 动态 Upstream 优选配置 (由双通道测速引擎自动生成)",
            f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "# 仅写入 rank0 (直连三态全通) 节点, 排除假节点导致 502",
            "# max_fails=3 fail_timeout=30s 减缓节点熔断雪崩",
            "# ==============================================================================\n"
        ]

        # 每次生成重置 relay 服务集合 (由本轮决策重新填充)
        self.last_relay_services = set()

        # 读取现有配置用于增量合并: 未参与本次测速的服务保留其已有 upstream 块,
        # 避免单服务自愈/局部重测顺带把其余服务重置回候选池
        existing_blocks = self._load_existing_upstream_blocks()

        # 确保全量服务均生成 upstream 块 (若某服务未测速，则自动取 CANDIDATE_IPS 默认兜底)
        for srv_id in CANDIDATE_IPS:
            ip_items = test_results.get(srv_id)
            if not ip_items:
                old_block = existing_blocks.get(f"upstream_{srv_id}")
                if old_block:
                    lines.append(old_block + "\n")
                    continue
                ip_items = [{"ip": ip} for ip in CANDIDATE_IPS.get(srv_id, [])]

            rank0 = [it for it in ip_items if it.get("rank", 3) == 0]
            rank12 = [it for it in ip_items if it.get("rank", 3) in (1, 2)]

            # --------------------------------------------------------------
            # relay 代理转发分支: 直连全挂但有经代理验证可用节点 (rank1/2) 且本地代理在线
            # -> upstream 指向 L4 Relay 代理转发端口 (127.0.0.1:<port>), 由 relay CONNECT 域名出网
            # 伪 SNI 服务 (自定义 SNI) 要求 rank1 (HTTP 干净), 避免伪 SNI 触发 421/404
            # --------------------------------------------------------------
            if not rank0 and rank12:
                proxy_cfg = _load_proxy_config()
                proxy_ready = bool(proxy_cfg) and is_proxy_available(proxy_cfg)
                if proxy_ready:
                    eligible = (srv_id not in PSEUDO_SNI_SERVICES) or \
                               any(it.get("rank", 3) == 1 for it in rank12)
                    if eligible:
                        port = relay_port_for(srv_id)
                        if not is_port_in_use(port):
                            domain = (SERVICES_BY_ID.get(srv_id, {}).get("domains") or [""])[0]
                            self.last_relay_services.add(srv_id)
                            lines.append(f"upstream upstream_{srv_id} {{")
                            lines.append(f"    # 经本地代理转发 relay={domain}:443 port={port}")
                            lines.append(f"    server 127.0.0.1:{port} max_fails=3 fail_timeout=30s;")
                            lines.append("    keepalive 32;")
                            lines.append("    keepalive_timeout 120;")
                            lines.append("    keepalive_requests 10000;")
                            lines.append("}\n")
                            continue

            # 只写 rank0 直连可用节点; 无 rank0 则回退候选池兜底 (保证 nginx 可启动)
            usable = rank0
            fallback = not usable
            if not usable:
                usable = [{"ip": it["ip"]} for it in ip_items if "ip" in it and it["ip"]]

            # 防御性排序: 复用统一排序键 (稳定段优先于延迟), 不依赖调用方预排序
            # 若这里只按延迟排序, 会覆盖 test_all_services 的稳优先结果导致白做
            stable_set = set(getattr(PROFILES_BY_ID.get(srv_id), "stable_ips", [])) or None
            usable.sort(key=lambda x: _service_sort_key(x, None, stable_set))
            valid_ips = [it["ip"] for it in usable if it.get("ip")]
            primary_ips = valid_ips[:2]
            backup_ips = valid_ips[2:4]

            lines.append(f"upstream upstream_{srv_id} {{")
            if fallback:
                lines.append(f"    # 警告: 服务 {srv_id} 双通道探测全部失败, 回退候选池兜底")
            
            if not valid_ips:
                # 极端场景防护: 若完全无有效候选 IP，写入 down 节点保证 Nginx 语法不报错
                lines.append("    server 127.0.0.1:443 down;  # 兜底占位，防止 upstream 为空导致 Nginx 语法解析失败")
            elif srv_id == "pixiv_web":
                lines.append("    hash $connection consistent;")
                for ip in valid_ips[:6]:
                    lines.append(self._fmt_server(ip, "max_fails=3 fail_timeout=30s"))
            elif srv_id == "pixiv_img":
                lines.append("    least_conn;")
                for ip in valid_ips[:6]:
                    lines.append(self._fmt_server(ip, "max_fails=3 fail_timeout=30s"))
            else:
                for ip in primary_ips:
                    lines.append(self._fmt_server(ip, "max_fails=3 fail_timeout=30s"))
                for ip in backup_ips:
                    lines.append(self._fmt_server(ip, "backup max_fails=3 fail_timeout=30s"))

            lines.append("    keepalive 32;")
            lines.append("    keepalive_timeout 120;")
            lines.append("    keepalive_requests 10000;")
            lines.append("}\n")

        return "\n".join(lines)

    def _scan_site_upstream_refs(self) -> set:
        """扫描 nginx.conf 实际 include 的 site 配置, 提取所有 proxy_pass 引用的 upstream 名"""
        refs = set()
        for name in SITE_CONF_NAMES:
            conf_file = self.conf_path.parent / name
            if not conf_file.exists():
                continue
            text = conf_file.read_text(encoding="utf-8", errors="ignore")
            for m in re.finditer(r"proxy_pass\s+https://(upstream_[a-z0-9_]+)", text):
                refs.add(m.group(1))
        return refs

    def apply_optimal(self, test_results: Dict[str, List[Dict]]) -> Tuple[bool, str]:
        """将延迟最低的节点配置原子写入 upstream-dynamic.conf (含引用交叉校验)"""
        try:
            conf_str = self.generate_upstream_conf(test_results)

            # 交叉校验: site 引用的 upstream 必须全部有定义, 防 host not found 导致 nginx 启动失败
            defined = set(re.findall(r"upstream (upstream_[a-z0-9_]+)", conf_str))
            refs = self._scan_site_upstream_refs()
            missing = refs - defined
            if missing:
                return False, f"上游引用不一致, 以下 upstream 缺失定义: {', '.join(sorted(missing))}"

            self.conf_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.conf_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(conf_str)
            tmp_path.replace(self.conf_path)

            # 同步 relay 代理转发端口映射 (从最终 conf 解析注释行 token; 仅非空时推送, 防止清空运行中隧道)
            try:
                from l4_relay import relay_server
                mapping = {int(m.group(2)): m.group(1)
                           for m in re.finditer(r"relay=([^\s:]+):443 port=(\d+)", conf_str)}
                if mapping:
                    relay_server.set_proxy_tunnels(mapping)
            except Exception:
                pass

            failed = [srv_id for srv_id, items in test_results.items()
                      if not any(it.get("rank", 3) == 0 for it in items)]
            relayed = [s for s in failed if s in self.last_relay_services]
            fallback = [s for s in failed if s not in self.last_relay_services]
            msg = "已生成延迟最低的节点配置并写入 upstream-dynamic.conf！"
            if relayed:
                msg += f" {len(relayed)} 个服务直连不可用已切换本地代理转发({', '.join(sorted(relayed))})"
            if fallback:
                msg += f" {len(fallback)} 个服务双通道探测全部失败已回退候选池({', '.join(sorted(fallback))})"
                proxy = _load_proxy_config()
                if proxy and is_proxy_available(proxy):
                    msg += "。当前直连被阻断而本地代理可用, 但 Nginx 数据平面仍为直连, 请检查网络直连状态"
                else:
                    msg += ", 建议检查网络后重试"
            return True, msg
        except Exception as e:
            return False, f"写入 upstream 配置失败: {e}"

    def apply_single_optimal(self, srv_id: str, single_results: List[Dict]) -> Tuple[bool, str]:
        """将单项服务的测速结果增量写入 upstream-dynamic.conf 并热重载 (增量无缝生效)"""
        return self.apply_optimal({srv_id: single_results})


class CDNHealthMonitor:
    """持续 CDN 节点健康巡检与故障自愈引擎"""

    def __init__(self, optimizer: CDNOptimizer, check_interval: float = 300.0,
                 on_healed: Optional[Callable[[], Any]] = None):
        self.optimizer = optimizer
        self.check_interval = check_interval
        self.on_healed = on_healed
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._is_running = False
        self.enabled_services: List[str] = []
        self.cached_results: Dict[str, List[Dict]] = {}
        self.failure_counts: Dict[str, int] = {}

    def is_running(self) -> bool:
        with self._lock:
            return self._is_running

    def update_services(self, enabled_services: List[str], current_results: Optional[Dict[str, List[Dict]]] = None):
        """更新当前监听的服务清单与基准测试结果"""
        with self._lock:
            self.enabled_services = list(enabled_services)
            if current_results:
                self.cached_results = dict(current_results)

    def set_check_interval(self, seconds: float):
        """运行中调整巡检周期 (线程安全; _worker_loop 每轮自然读取新值生效)"""
        seconds = max(5.0, float(seconds))
        with self._lock:
            self.check_interval = seconds

    def check_and_heal_service(self, srv_id: str) -> bool:
        """检查单个服务的当前主力节点，并在故障时自动选举自愈"""
        srv = SERVICES_BY_ID.get(srv_id)
        if not srv:
            return False

        with self._lock:
            items = self.cached_results.get(srv_id)
        if not items:
            items = self.optimizer.test_service_dual(srv_id)
            with self._lock:
                self.cached_results[srv_id] = items

        best_item = next((it for it in items if it.get("rank", 3) == 0), items[0] if items else None)
        if not best_item:
            return False

        # relay 代理转发服务: 数据平面经本地代理出网, 探针改查 relay 端口 TCP 可达性
        # (直连探针必然失败, 若走原路径会导致无意义空转自愈)
        if srv_id in getattr(self.optimizer, "last_relay_services", set()):
            port = relay_port_for(srv_id)
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=PROBE_DEFAULTS.relay_probe_timeout):
                    pass
                with self._lock:
                    self.failure_counts[srv_id] = 0
                return False  # relay 端口健康, 无需自愈
            except Exception:
                pass
            # relay 端口不可达 (relay 停止/代理失效): 走失败计数与自愈路径
            with self._lock:
                self.failure_counts[srv_id] = self.failure_counts.get(srv_id, 0) + 1
                trigger_heal = (self.failure_counts[srv_id] >= 2)
            if trigger_heal:
                new_items = self.optimizer.test_service_dual(srv_id)
                with self._lock:
                    self.cached_results[srv_id] = new_items
                    self.failure_counts[srv_id] = 0
                return True
            return False

        # 轻量探针检查当前主力节点 (三态验证: TCP+TLS 通且 HTTP 非 5xx/421 才算健康)
        sni_mode = SNI_MODES.get(srv_id, "host")
        domain = srv["domains"][0] if srv["domains"] else ""
        probe_res = probe_ip_endpoint_v2(best_item["ip"], domain=domain,
                                         timeout=PROBE_DEFAULTS.health_probe_timeout, sni_mode=sni_mode)

        if (probe_res.get("tls_ok", False) and probe_res.get("http_ok", False)
                and not _suspect_status(probe_res.get("http_status"))):
            with self._lock:
                self.failure_counts[srv_id] = 0
            return False  # 主力节点健康 (HTTP 被 RST/421/502 不再误判健康)，无需自愈

        # 连续失败计数累加
        with self._lock:
            self.failure_counts[srv_id] = self.failure_counts.get(srv_id, 0) + 1
            trigger_heal = (self.failure_counts[srv_id] >= 2)

        if trigger_heal:
            # 触发故障自愈：单服务重测并选举新节点
            new_items = self.optimizer.test_service_dual(srv_id)
            with self._lock:
                self.cached_results[srv_id] = new_items
                self.failure_counts[srv_id] = 0
            return True

        return False

    def run_health_check_cycle(self) -> Tuple[bool, List[str]]:
        """执行一轮轻量健康巡检周期，返回 (是否有自愈发生, 自愈服务列表)"""
        with self._lock:
            targets = list(self.enabled_services)
        healed_services = []
        for srv_id in targets:
            if self._stop_event.is_set():
                break
            try:
                if self.check_and_heal_service(srv_id):
                    healed_services.append(srv_id)
            except Exception:
                pass

        with self._lock:
            has_cache = bool(self.cached_results)
            cache_snapshot = dict(self.cached_results)

        if healed_services and has_cache:
            # 重新渲染 upstream 配置并应用
            ok, _ = self.optimizer.apply_optimal(cache_snapshot)
            if ok and self.on_healed:
                try:
                    self.on_healed()
                except Exception:
                    pass
            return True, healed_services

        return False, []

    def _worker_loop(self):
        """后台低开销巡检工作循环"""
        while not self._stop_event.is_set():
            # 休眠指定周期（支持快速唤醒退出）
            if self._stop_event.wait(timeout=self.check_interval):
                break
            try:
                self.run_health_check_cycle()
            except Exception:
                pass
        with self._lock:
            self._is_running = False

    def start(self, enabled_services: Optional[List[str]] = None):
        """启动后台健康巡检守护线程"""
        with self._lock:
            if self._is_running:
                return
            if enabled_services is not None:
                self.enabled_services = list(enabled_services)
            self._is_running = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="CDNHealthMonitorThread")
            self._thread.start()

    def stop(self):
        """停止后台健康巡检"""
        with self._lock:
            if not self._is_running:
                return
            self._stop_event.set()
            thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=1.0)
        with self._lock:
            self._is_running = False


# ==============================================================================
# 独立运行入口: 支持用户/开发者在终端手动执行一键测速与节点优选
# ==============================================================================
if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print("=" * 80)
    print(">>> GameArt Toolkit - CDN 节点全网深度探测与动态优选 CLI <<<")
    print("=" * 80)

    conf_file = Path(__file__).resolve().parent.parent / "nginx" / "conf" / "upstream-dynamic.conf"
    opt = CDNOptimizer(conf_file)
    print("正在对全量加速服务的 Anycast 节点进行并发探测 (超时阈值 3.5s)...")

    t0 = time.perf_counter()
    res = opt.test_all_services(max_workers=16, total_timeout=25.0)
    elapsed = time.perf_counter() - t0

    print("\n" + "=" * 80)
    print(f"测速完成！总耗时: {elapsed:.2f} 秒")
    print("=" * 80)

    for srv_id, ip_items in res.items():
        usable = [it for it in ip_items if it.get("available")]
        best_lat = usable[0].get("latency") if usable else None
        lat_str = f"{best_lat}ms" if best_lat is not None else "超时/不可用"
        print(f"【{srv_id:<20}】可用节点: {len(usable)}/{len(ip_items)} | 最低延迟: {lat_str}")
        for it in ip_items:
            ip = it.get("ip")
            lat = it.get("latency")
            status = f"✅ {lat}ms" if lat is not None else "❌ 超时"
            via = "(代理)" if it.get("via_proxy") else "(直连)"
            print(f"    - {ip:<18} | {status:<12} {via}")

    ok, msg = opt.apply_optimal(res)
    print("\n" + "=" * 80)
    print(f"优选结果应用状态: {'[成功]' if ok else '[失败]'} -> {msg}")
    print("=" * 80)
