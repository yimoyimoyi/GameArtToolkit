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
import zlib
import urllib.request
import concurrent.futures
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Callable, Any

from path_utils import NGINX_DIR
from ip_pool import CANDIDATE_IPS, SERVICES_BY_ID, PROFILES_BY_ID
from config_store import load_config
from win_utils import is_port_in_use, get_physical_adapter_ip, auto_detect_active_proxy
from ech_tunnel import ech_tunnel

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

# 上游节点熔断策略 (写进 upstream-dynamic.conf 的 server 行)
#
# 为什么是 max_fails=1 / fail_timeout=5s (而非早期的 3 / 30s):
#   实测 GFW 的封锁是**逐段分钟级轮换** —— 日志里同段三个主力可同时 "while connecting"
#   超时, 而数秒后的独立探测又全部可达。3 次失败才熔断, 意味着一次段封锁期内要白白
#   失败 3 轮请求; 30s 的熔断期又跨过了封锁段的实际轮换周期, 结果是"节点早已不可达,
#   却仍在被轮询"。改为 1 次即熔断 + 5s 后重试: 坏节点在一个请求内被踢出, 封锁解除后
#   5s 内自动回归, 与轮换周期同量级。
UPSTREAM_MAX_FAILS = 1
UPSTREAM_FAIL_TIMEOUT = "5s"

# QUIC 直连服务的单节点测速预算 (秒)。QUIC 握手正常在 250ms 内完成, 6s 已足够覆盖
# 跨洋高丢包; 该值同时作为 aioquic 的 idle_timeout 上限, 避免静默丢包时按默认 60s 空等。
QUIC_PROBE_TIMEOUT = 6.0


def _upstream_server_opts() -> str:
    """生成 server 行的熔断参数"""
    return f"max_fails={UPSTREAM_MAX_FAILS} fail_timeout={UPSTREAM_FAIL_TIMEOUT}"


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
    throughput_budget: float = 1.6    # 吞吐测量阶段预算上限 (默认档, 随档位等比缩放)
    throughput_max_bytes: int = 256 * 1024  # 吞吐测量上限 (256 KiB, 足够判定量级且不拖慢测速)


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
    """统一测速排序键: (rank, 稳定段惩罚, 副域验证, 吞吐逆序, 延迟, v6/v4 偏好兜底)

    - rank 永远第一 (可用性优先, Fastly 全灭时仍由 rank0 兜底)
    - 稳定性优先于延迟: 短命 Anycast 延迟优势不可信, 已知稳定段优先
    - 副域全验证软降权: 多域验证失败的节点排在验证通过节点后 (不淘汰, 防 GFW 特判封锁误杀)
    - 吞吐逆序 (越高越优): 对「握手 200 但下载慢」的节点降权, 让测速结果真正代表
      大文件/git pack 的下载体验。仅在测到吞吐 (throughput 非空) 时参与比较,
      未测吞吐的项退化为旧键序 (rank, 稳定段, 延迟), 兼容历史调用方。
    - 协议偏好仅在延迟平局时兜底: IPv6 快节点正常竞争 (修复 GitHub 原生
      IPv6 85ms 优于 IPv4 230ms 却被 prefer_ipv4 硬降权的问题)
    - ip_mode/stable_set 为 None 时跳过对应维度 (apply_optimal 防御性排序复用)
    - 空 stable_ips 的服务退化为键序 (rank, latency), 行为不变
    """
    rank = item.get("rank", 3)
    lat = item.get("latency") if item.get("latency") is not None else 99999
    stable_penalty = 0
    if stable_set is not None:
        stable_penalty = 0 if str(item.get("ip", "")) in stable_set else 1
    v_penalty = 0
    if ip_mode:
        is_v6 = ":" in str(item.get("ip", ""))
        if ip_mode == "prefer_ipv4" and is_v6:
            v_penalty = 1
        elif ip_mode == "prefer_ipv6" and not is_v6:
            v_penalty = 1
    # 副域全验证软降权: 副域验证失败 (如 api.github.com 被 GFW 特判封锁) 排在正常节点后,
    # 但不淘汰 (主域网页仍可用, 避免瞬时抖动/特判封锁下整服务全挂)
    sub_penalty = 0 if item.get("http_subdomains_ok") is not False else 1
    # 吞吐逆序: 测到吞吐的项优先; 未测到的用 -0 表示"无偏好"(不压过已测项)
    thp = item.get("throughput")
    thp_penalty = (-float(thp)) if (thp is not None and thp > 0) else MEDIOCRE_THROUGHPUT_SENTINEL
    return (rank, stable_penalty, sub_penalty, thp_penalty, lat, v_penalty)


# 吞吐排序哨兵: 小于任何实际测得的正吞吐, 使"未测吞吐"的项排在"测到吞吐"的后面,
# 但在同组未测项之间仍按延迟比较 (避免未测项彼此被 -0 且 latency 兜底失效)。
# 取一个大负数即可满足 "未测 < 已测(正)" 的单调关系。
MEDIOCRE_THROUGHPUT_SENTINEL = -1.0

# 健康巡检吞吐自愈阈值: 当前主力节点实测吞吐 < 最优候选吞吐 x 该比例时, 触发重新选举。
# 0.45 = 主力慢于最优 55% 才换, 避免晚高峰抖动导致频繁无谓重选。
THROUGHPUT_HEAL_RATIO = 0.45


def _best_throughput_among_rank0(items: List[Dict]) -> Optional[float]:
    """取 rank0 (直连三态全通) 候选中的最大下载吞吐 (B/s); 无 rank0 或未测吞吐返回 None"""
    best = None
    for it in items:
        if it.get("rank", 3) != 0:
            continue
        thp = it.get("throughput")
        if thp is not None and thp > 0:
            best = max(best, float(thp)) if best is not None else float(thp)
    return best


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


_RELAY_PORT_MAP: Dict[str, int] = {}


def relay_port_for(srv_id: str) -> int:
    """确定性 relay 端口映射: crc32 稳定哈希 + 全量线性探测防冲突

    - 按服务 ID 排序后统一分配, 不依赖 CANDIDATE_IPS 插入顺序
      (新增 Profile 不再引发既有服务端口漂移冲突, 跨会话/跨进程稳定)
    - 哈希基址落在 [RELAY_PORT_BASE, RELAY_PORT_BASE+64), 冲突时
      线性探测取下一个未被其他服务最终占用的空闲端口
    - 未知服务回退基址 (保持向后兼容)
    """
    if not _RELAY_PORT_MAP:
        used: set = set()
        for sid in sorted(CANDIDATE_IPS.keys()):
            port = RELAY_PORT_BASE + (zlib.crc32(sid.encode("utf-8")) % 64)
            while port in used:
                port += 1
            used.add(port)
            _RELAY_PORT_MAP[sid] = port
    return _RELAY_PORT_MAP.get(srv_id, RELAY_PORT_BASE)


# 公共 DNS 服务器 (用于绕过被注入 hosts 的动态候选解析)
_DNS_SERVERS = ["223.5.5.5", "119.29.29.29"]

# DoH (DNS over HTTPS) 端点: 腾讯 doh.pub 实测解析最干净 (返回真实 IP);
# 阿里 dns.alidns.com 与 UDP 同源 (可能继承 GFW 注入结果), 仅作容灾。
# 国外 1.1.1.1 / 8.8.8.8 直连实测被阻断, 不作为默认端点。
DOH_ENDPOINTS = ["https://doh.pub/dns-query", "https://dns.alidns.com/resolve"]

# 严禁进入 Upstream 的保留/虚拟 IP 段 (含 Clash / Sing-box Fake-IP: 198.18.0.0/15 与高校/企业非标私网)
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("198.18.0.0/15"),  # Clash Fake-IP 虚拟池 (198.18.0.0 - 198.19.255.255)
    ipaddress.ip_network("127.0.0.0/8"),     # Loopback 回环
    ipaddress.ip_network("10.0.0.0/8"),      # 私有内网 (RFC 1918)
    ipaddress.ip_network("172.16.0.0/12"),   # 私有内网 (RFC 1918: 172.16.0.0 - 172.31.255.255)
    ipaddress.ip_network("172.100.0.0/16"),  # 高校深澜 srun 等网关广泛滥用的 172.100.x.x
    ipaddress.ip_network("172.200.0.0/16"),  # 高校/企业网关滥用的 172.200.x.x
    ipaddress.ip_network("192.168.0.0/16"),  # 私有内网 (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT 运营商级 NAT 保留段 (RFC 6598)
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


def is_internet_available(target: str = "www.baidu.com", timeout: float = 1.0) -> bool:
    """检测外网公网连通性 (带毫秒级快速探测与多端点容灾, 准确感知校园网未认证/掉线)

    策略:
    1. 优先尝试向国内高可用公网 DNS (223.5.5.5 / 119.29.29.29:53) 或目标域 (80 端口) 发起 TCP 握手
    2. 若 Socket 探测失败，则回退执行系统原生 ICMP Ping 单包探测 (与校园网登录脚本判定一致)
    """
    targets = [(target, 80), ("223.5.5.5", 53), ("119.29.29.29", 53)]
    for host, port in targets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.close()
            return True
        except Exception:
            pass

    # ICMP Ping 兜底
    try:
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        res = subprocess.run(
            ["ping", "-n", "1", "-w", str(int(timeout * 1000)), target],
            capture_output=True,
            creationflags=flags
        )
        return res.returncode == 0
    except Exception:
        return False


# DoH 解析内存缓存 (TTL 10 分钟, 规避每次测速主流程重复串行查询)
_DOH_CACHE: Dict[str, Tuple[float, List[str]]] = {}
_DOH_CACHE_LOCK = threading.Lock()
_DOH_CACHE_TTL = 600.0  # 10 分钟有效

# DoH 专用 opener: ProxyHandler({}) 表示"不使用任何代理", 同时继承系统 CA
_DOH_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _doh_fetch(url: str, timeout: float) -> bytes:
    """DoH 请求发出口 (独立函数便于单测打桩, 返回原始响应体)

    必须走独立 opener 而非 urllib.request.urlopen: 探测链路若命中系统代理,
    代理的 Fake-IP 会污染解析结果, 必须显式绕过代理。
    注意不能用 Request.set_proxy("", "https") 来禁代理 —— 该调用会把 req.host
    置为空串, 请求退化为 URLError("no host given") 并被调用方的 except 静默吞掉,
    使整条 DoH 通道恒返回空 (实测修复前对任何域名都是空, 候选池因此彻底丧失
    自补充能力)。
    """
    req = urllib.request.Request(url, headers={
        "Accept": "application/dns-json",
        "User-Agent": "GameArtToolkit/2.0",
    })
    with _DOH_OPENER.open(req, timeout=timeout) as resp:
        return resp.read()


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
            payload = json.loads(_doh_fetch(url, timeout).decode("utf-8", errors="replace"))
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
                    # 与 DoH 通道一致: 过滤 GFW 污染注入段 (Facebook/Twitter/Dropbox 等大厂 IP),
                    # 防止污染 IP 混入候选池 (实测曾混入 162.125.x / 199.59.x 并返回假 200)
                    if (is_valid_public_cdn_ip(raw_ip)
                            and not raw_ip.startswith(POLLUTED_IP_PREFIXES)):
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
    """HTTP 状态码是否表示"可疑节点" (网关错误 502-504 / Cloudflare 421 重路由 / 4xx 假阳性)

    400/403/404 判定为可疑: 根路径探测对正常虚拟主机应返回 2xx/3xx (或 500),
    返回 4xx 说明 IP 不是该域的有效前端 (S3 403 / Fastly 403 等假阳性)。
    对"根路径本应 4xx"的服务 (S3 403, githubassets 404) 由 profile.probe_ok_statuses 显式放行。
    """
    if status is None:
        return False
    if status == 421 or status == 530 or 502 <= status <= 504:
        return True
    # 4xx 客户端错误: 错误虚拟主机/区域不匹配/无根文档 (500 保持放行, githubassets 根路径实测曾返回 500)
    return 400 <= status <= 404


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
                         quick_retry: bool = True,
                         measure_throughput: bool = False,
                         probe_domains: Optional[List[str]] = None,
                         ok_statuses: Optional[set] = None,
                         proxy_connect_domain: bool = False) -> Dict:
    """单链路三态探测: TCP → TLS(按 SNI 模式 + ALPN) → HTTP 状态码

    单节点独立生命周期计时:
    - 真正分配到 Worker 线程开始执行时才启动单任务独立计时 (单任务硬预算 4.5s)
    - TCP 阶段预算 1.0s, TLS 阶段预算 2.2s, HTTP 阶段预算 1.5s
    - 首次非致命异常自动原地快速微重试 1 次, 强力抵御跨国网络偶发丢包
    - measure_throughput: 在 HTTP 状态码通过后继续读取有限的响应体, 计算下行吞吐 (B/s)
      存入 out["throughput"]。仅对下载链路过慢/过大包 (如 git pack / 大文件 CDN) 有意义,
      用于把「握手 200 但下载慢」的节点在排序中降权。
    - probe_domains: 多域全验证 (防 GFW 按子域特判封锁)。主域 GET (保持兼容与吞吐测量),
      副域 HEAD (无 body, 复用同一 TLS 连接串行验证, 服务器主动关闭连接时保守判可疑)。
      任一副域状态码可疑 → 输出 http_suspect=True, 调用方不得判 rank0。
    - ok_statuses: 该服务显式放行的状态码集合 (如 S3 根路径 403 / githubassets 根路径 404,
      这些 4xx 是虚拟主机"无根文档/无权限"的正常响应而非假节点特征)
    """
    def _do_probe_once() -> Dict:
        out = {"tcp_ok": False, "tcp_latency": None, "tls_ok": False,
               "tls_latency": None, "http_ok": False, "http_status": None, "error": "",
               "http_suspect": False, "http_subdomains_ok": True, "throughput": None}
        # http_suspect: 主域状态码可疑 (硬淘汰, 防假阳性)
        # http_subdomains_ok: 副域多域验证是否全部通过 (软信号, 失败仅排序降权不淘汰,
        #   防 GFW 特判封锁子域/瞬时抖动误杀整服务)
        # 档位缩放: 0.8 档更快 / 3.0 档更宽容 (默认 1.5 档 = 原始预算)
        scale = tier_scale(timeout)
        deadline = time.monotonic() + PROBE_DEFAULTS.hard_budget * scale  # 单节点硬超时预算
        # 物理网卡 IP (IPv4 直连绑定源地址; 供主域 TCP 与副域验证共用)
        p_ip = physical_ip if physical_ip is not None else get_physical_adapter_ip()
        sock = None
        ssock = None
        try:
            # 1. TCP 握手 (直连或经 CONNECT 隧道)
            try:
                tcp_timeout = min(timeout, PROBE_DEFAULTS.tcp_budget * scale)
                if proxy:
                    t0 = time.perf_counter()
                    sock = socket.create_connection(proxy, timeout=tcp_timeout)
                    # proxy_connect_domain: CONNECT 域名而非候选 IP (适配 Clash 按 IP 段 DIRECT
                    # 直连规则与 CDN geo 限制中国 IP 的场景; 与 relay 转发路径 (CONNECT 域名) 一致)
                    connect_target = domain if proxy_connect_domain else ip
                    _send_connect_and_read_200(sock, connect_target, 443, tcp_timeout)
                    out["tcp_latency"] = round((time.perf_counter() - t0) * 1000.0, 1)
                else:
                    t0 = time.perf_counter()
                    sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(tcp_timeout)
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

            # 3. HTTP 状态码探测 (主域 GET + 副域独立 TLS 验证)
            # 多域全验证: 副域必须用独立 TLS 握手 (SNI 与 Host 必须一致, 复用主域连接会触发
            # Fastly/S3 的 SNI/Host 一致性校验返回 421/400, 导致误判)。防 GFW 按子域特判封锁
            # (如只封 api.github.com 的 SNI) 与 S3 区域不匹配假节点。
            try:
                http_timeout = max(0.6, min(deadline - time.monotonic(), PROBE_DEFAULTS.http_budget * scale))
                ssock.settimeout(http_timeout)
                # 探测域去重保序 (probe_domains 与主域重复时只发一次)
                domains_to_probe = list(probe_domains) if probe_domains else []
                if domain and domain not in domains_to_probe:
                    domains_to_probe.insert(0, domain)
                ok_set = set(ok_statuses) if ok_statuses else set()

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
                if line.startswith("HTTP/") and len(line.split()) >= 2 and line.split()[1].isdigit():
                    out["http_status"] = int(line.split()[1])
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

                            # 校园网 Portal / 深澜 srun 网关劫持防御:
                            # 若重定向指向 portal/srun/auth/login 关键字, 或目标属于非标内网 IP, 严厉硬淘汰
                            loc_lower = loc.lower()
                            loc_target_ip = loc_host.split(":")[0]
                            if (any(k in loc_lower for k in ("srun", "portal", "172.100.", "172.200.", "10.0.", "192.168."))
                                    or (loc_target_ip.replace(".", "").isdigit() and not is_valid_public_cdn_ip(loc_target_ip))):
                                out["http_suspect"] = True

                    # 主域状态码干净判定 (ok_statuses 显式放行或非可疑)
                    if not ((out["http_status"] in ok_set) or not _suspect_status(out["http_status"])):
                        out["http_suspect"] = True

                    # 吞吐测量: 仅对主域干净 2xx 响应进行; 继承 hdr 中已读到的首个 body 分片
                    if measure_throughput and 200 <= out["http_status"] < 300:
                        try:
                            thp_deadline = time.monotonic() + max(0.6, min(PROBE_DEFAULTS.throughput_budget * scale,
                                                                            deadline - time.monotonic()))
                            body = hdr.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in hdr else b""
                            total = len(body)
                            ssock.settimeout(min(1.0, max(0.3, thp_deadline - time.monotonic())))
                            t0 = time.perf_counter()
                            while (time.monotonic() < thp_deadline and total < PROBE_DEFAULTS.throughput_max_bytes):
                                try:
                                    chunk = ssock.recv(65536)
                                except socket.timeout:
                                    break
                                if not chunk:
                                    break
                                total += len(chunk)
                            dt = max(time.perf_counter() - t0, 1e-6)
                            if total > 0:
                                out["throughput"] = round(total / dt, 1)  # B/s
                        except Exception:
                            out["throughput"] = None

                    # 副域独立 TLS 验证 (SNI=副域 + HEAD), 每个副域独立连接与预算
                    # 链路模式跟随主域: 经代理 CONNECT 隧道时副域也走隧道 (GFW 封锁直连 SNI 时
                    # 代理链路仍应通过, 避免误杀 rank1 候选); 主域已可疑则跳过省预算
                    if not out.get("http_suspect"):
                        for extra in domains_to_probe[1:]:
                            if time.monotonic() >= deadline:
                                out["http_subdomains_ok"] = False  # 预算耗尽未完成全验证 -> 软降权
                                break
                            extra_timeout = max(0.8, min(deadline - time.monotonic(), 1.5))
                            extra_sock = None
                            extra_tls = None
                            try:
                                if proxy:
                                    extra_sock = socket.create_connection(proxy, timeout=min(extra_timeout, 1.2))
                                    extra_target = extra if proxy_connect_domain else ip
                                    _send_connect_and_read_200(extra_sock, extra_target, 443, min(extra_timeout, 1.2))
                                else:
                                    extra_sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                                                               socket.SOCK_STREAM)
                                    extra_sock.settimeout(min(extra_timeout, 1.2))
                                    if p_ip and ":" not in ip:
                                        try:
                                            extra_sock.bind((p_ip, 0))
                                        except Exception:
                                            pass
                                    extra_sock.connect((ip, 443))
                                ctx_extra = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                                ctx_extra.check_hostname = False
                                ctx_extra.verify_mode = ssl.CERT_NONE
                                try:
                                    ctx_extra.set_alpn_protocols(["http/1.1"])
                                except Exception:
                                    pass
                                if sni_mode == "host":
                                    sni_host = extra
                                elif sni_mode == "empty":
                                    sni_host = None
                                else:
                                    sni_host = sni_mode
                                extra_tls = ctx_extra.wrap_socket(extra_sock, server_hostname=sni_host)
                                extra_sock = None
                                extra_tls.settimeout(extra_timeout)
                                extra_tls.sendall(
                                    f"HEAD / HTTP/1.1\r\nHost: {extra}\r\n"
                                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) GameArtToolkit/2.0\r\n"
                                    f"Connection: close\r\n\r\n".encode("utf-8"))
                                extra_hdr = b""
                                while b"\r\n\r\n" not in extra_hdr:
                                    chunk = extra_tls.recv(4096)
                                    if not chunk:
                                        break
                                    extra_hdr += chunk
                                extra_line = extra_hdr.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                                extra_parts = extra_line.split()
                                if (extra_line.startswith("HTTP/") and len(extra_parts) >= 2
                                        and extra_parts[1].isdigit()):
                                    extra_code = int(extra_parts[1])
                                    # 副域状态码: ok_statuses 显式放行或非可疑 (与主域同一套判定)
                                    if not ((extra_code in ok_set) or not _suspect_status(extra_code)):
                                        out["http_subdomains_ok"] = False  # 副域可疑 -> 软降权不淘汰
                                        break
                                    # 干净副域继续验证下一个域
                                else:
                                    out["http_subdomains_ok"] = False  # 副域非 HTTP 响应 -> 软降权
                                    break
                            except Exception:
                                # 副域 TLS/HTTP 失败 (GFW SNI RST / 区域不匹配):
                                # 不淘汰节点 (特判封锁/瞬时抖动易误杀整服务), 记录为排序降权信号
                                out["http_subdomains_ok"] = False
                                break
                            finally:
                                for s_ in (extra_sock, extra_tls):
                                    if s_:
                                        try:
                                            s_.close()
                                        except Exception:
                                            pass
                else:
                    raise ConnectionError(f"非 HTTP 响应: {line[:80] or '空'}")
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
    # 单节点微重试: TCP 抖动 (GFW 间歇 RST) 或 TLS/HTTP 偶发异常时快速重试 1 次
    # 注意: http_ok 为 True 的 5xx (如 Akamai 反爬 503) 不触发重试, 避免放大无效探测时长
    if quick_retry and not proxy and not (res.get("tcp_ok") and res.get("tls_ok") and res.get("http_ok")):
        time.sleep(0.08)  # 80ms 避开偶发抖动
        res2 = _do_probe_once()
        if res2.get("tcp_ok") and res2.get("tls_ok") and res2.get("http_ok"):
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

    def _http_clean(result: Optional[Dict]) -> bool:
        """HTTP 层干净判定: 收到响应 + 状态码非可疑 + 多域验证通过

        - 新版探测输出含 http_suspect 字段 (已融合 profile.probe_ok_statuses 显式放行,
          如 S3 403 / githubassets 404), 以该字段为准, 不再二次硬判状态码
        - 无该字段的旧版/测试构造结果回退状态码硬判, 保持兼容
        """
        if not (result and result.get("tcp_ok") and result.get("tls_ok") and result.get("http_ok")):
            return False
        if result.get("http_suspect"):
            return False
        if "http_suspect" not in result and _suspect_status(result.get("http_status")):
            return False
        if _redirect_loop(result):
            return False
        return True

    d_clean = _http_clean(direct)
    p_clean = _http_clean(proxy)
    p_suspect = bool(proxy and proxy.get("tcp_ok") and proxy.get("tls_ok")
                     and proxy.get("http_ok")
                     and (proxy.get("http_suspect")
                          or ("http_suspect" not in proxy and _suspect_status(proxy.get("http_status")))))

    item = {"latency": None, "available": False, "rank": 3,
            "via_proxy": False, "recommend": "none", "sni_mode": "host",
            "direct": direct, "proxy": proxy, "proxy_used": bool(proxy),
            "throughput": None, "http_subdomains_ok": None}
    if d_clean:
        item.update(rank=0, via_proxy=False, recommend="direct", available=True,
                    latency=direct.get("tcp_latency"))
        item["throughput"] = direct.get("throughput")
        item["http_subdomains_ok"] = direct.get("http_subdomains_ok")
    elif p_clean:
        item.update(rank=1, via_proxy=True, recommend="proxy", available=True,
                    latency=(proxy.get("tcp_latency") or 0) + (proxy.get("tls_latency") or 0))
        item["throughput"] = proxy.get("throughput")
        item["http_subdomains_ok"] = proxy.get("http_subdomains_ok")
    elif p_suspect:
        item.update(rank=2, via_proxy=True, recommend="proxy", available=True,
                    latency=(proxy.get("tcp_latency") or 0) + (proxy.get("tls_latency") or 0))
        item["throughput"] = proxy.get("throughput")
        item["http_subdomains_ok"] = proxy.get("http_subdomains_ok")
    return item


class CDNOptimizer:
    def __init__(self, conf_path: Path = UPSTREAM_CONF_PATH):
        self.conf_path = Path(conf_path)
        # 最近一次生成的 relay 代理转发服务集合 (供自愈探针分流与 UI 展示)
        self.last_relay_services: set = set()
        # 最近一次走 ECH 隧道直连的服务集合
        self.last_ech_services: set = set()
        # 标记了 ech_enabled 但隧道未就绪、已退回常规分支的服务
        self.last_ech_degraded: set = set()
        # 单轮生成内的兜底探测缓存 (key=ip, value=(ok, latency))
        # 各服务的候选池大量重叠 (如 github_raw/release/assets 共用 185.199.108-111 段),
        # 按 IP 去重后同一轮只需探测一次。实测全量兜底 33 个服务串行重复探测耗时 105s,
        # 去重后只剩约 113 个唯一 IP 的探测量。
        self._probe_cache: Dict[str, Tuple[bool, Optional[float]]] = {}

    def test_service_dual(self, srv_id: str, max_workers: Optional[int] = None) -> List[Dict]:
        """单服务双通道探测 (直连 + 经本地代理 CONNECT 隧道, 供健康巡检自愈调用)

        QUIC 直连服务必须分流到真实 QUIC 探测: 它们的 TCP 侧必然全挂, 走下面的 TCP/TLS
        路径会让**单项测速按钮**恒显示失败 (界面表现即"检测失败"), 这是纯误报。
        """
        profile = PROFILES_BY_ID.get(srv_id)
        if getattr(profile, "skip_cdn_probe", False):
            holder: Dict[str, List[Dict]] = {srv_id: []}
            self._probe_quic_services(holder)
            return holder.get(srv_id) or []

        if max_workers is None:
            max_workers = int(load_config().get("cdn_max_workers", 16))
        ips = CANDIDATE_IPS.get(srv_id, [])
        return self.test_group(srv_id, ips, max_workers=max_workers)

    def test_group(self, group_name: str, ip_list: List[str], max_workers: int = 16) -> List[Dict]:
        """测试指定服务的一组候选 IP (双通道三态探测, 自动补充 DNS 当前解析节点, 遵从 IPv4/v6 偏好)"""
        # 直接以 test_group 调用进 QUIC 服务时同样分流 (工具箱测速页可能直接调它)
        profile = PROFILES_BY_ID.get(group_name)
        if getattr(profile, "skip_cdn_probe", False):
            holder: Dict[str, List[Dict]] = {group_name: []}
            self._probe_quic_services(holder)
            return holder.get(group_name) or []
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
        # 是否实测吞吐: 取决于服务 profile.measure_throughput (大文件/git pack 服务才启用,
        # 其余服务保持旧三态探测, 避免额外拖慢整体测速)
        profile = PROFILES_BY_ID.get(group_name)
        measure_thp = bool(getattr(profile, "measure_throughput", False))
        # 多域全验证与状态码放行: 由 profile 声明 (防 GFW 按子域特判封锁 / S3 403 假阳性)
        probe_domains = list(getattr(profile, "probe_domains", ()) or ()) or None
        ok_statuses = set(getattr(profile, "probe_ok_statuses", ()) or ()) or None
        # 代理通道 CONNECT 域名 (适配 Clash IP 段 DIRECT 规则 / CDN geo 限制)
        proxy_connect_domain = bool(getattr(profile, "proxy_connect_by_domain", False))
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ip_list) or 1, max_workers)) as executor:
            def run_one(ip):
                direct = probe_ip_endpoint_v2(ip, domain, timeout=timeout, sni_mode=sni_mode, proxy=None,
                                              measure_throughput=measure_thp,
                                              probe_domains=probe_domains, ok_statuses=ok_statuses)
                proxy_res = probe_ip_endpoint_v2(ip, domain, timeout=timeout, sni_mode=sni_mode, proxy=proxy,
                                                 measure_throughput=False,
                                                 probe_domains=probe_domains, ok_statuses=ok_statuses,
                                                 proxy_connect_domain=proxy_connect_domain) if proxy else None
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

    def test_all_services(self, max_workers: int = 64, total_timeout: float = 45.0,
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

        # 跳过 TCP/TLS 探测的服务 (QUIC 直连类: 其 TCP 侧 SNI 本就被 RST, 探测只会得到
        # 假阴性并把静态实测 IP 判死; 这类服务的 IP 由实测数据静态维护)
        skip_probe_ids = {sid for sid, p in PROFILES_BY_ID.items()
                          if getattr(p, "skip_cdn_probe", False)}

        # 1. 异步并发预热所有服务域名的 DoH 缓存 (0ms 消除主循环串行阻塞)
        domains_to_preload = []
        for srv_id in CANDIDATE_IPS:
            if target_set is not None and srv_id not in target_set:
                continue
            if srv_id in skip_probe_ids:
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
            if srv_id in skip_probe_ids:
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
            profile = PROFILES_BY_ID.get(srv_id)
            measure_thp = bool(getattr(profile, "measure_throughput", False))
            # 多域全验证与状态码放行: 由 profile 声明 (防 GFW 按子域特判封锁 / S3 403 假阳性)
            probe_domains = list(getattr(profile, "probe_domains", ()) or ()) or None
            ok_statuses = set(getattr(profile, "probe_ok_statuses", ()) or ()) or None
            # 代理通道 CONNECT 域名 (适配 Clash IP 段 DIRECT 规则 / CDN geo 限制)
            proxy_connect_domain = bool(getattr(profile, "proxy_connect_by_domain", False))

            # 按服务级存活率兜底: 存活数低于下限时该服务全池进 Stage 2
            final_ips = _apply_prefilter_floor(ips, alive_ips_set, PROBE_DEFAULTS.prefilter_floor)

            for ip in final_ips:
                flat_tasks.append((srv_id, ip, domain, sni_mode, task_timeout, measure_thp,
                                   probe_domains, ok_statuses, proxy_connect_domain))

        def run_both(task):
            srv_id, ip, domain, sni_mode, task_timeout, measure_thp, probe_domains, ok_statuses, proxy_connect_domain = task
            direct = probe_ip_endpoint_v2(ip, domain, timeout=task_timeout, sni_mode=sni_mode, proxy=None,
                                          quick_retry=True, measure_throughput=measure_thp,
                                          probe_domains=probe_domains, ok_statuses=ok_statuses)
            proxy_res = probe_ip_endpoint_v2(ip, domain, timeout=task_timeout, sni_mode=sni_mode, proxy=proxy,
                                             quick_retry=False, measure_throughput=False,
                                             probe_domains=probe_domains, ok_statuses=ok_statuses,
                                             proxy_connect_domain=proxy_connect_domain) if proxy else None
            return srv_id, ip, direct, proxy_res

        # 5. Stage 2: 深度三态探测 (单任务独立生命周期计时, 绝无全局强杀误断)
        #    软性总时限: deadline 到点后不再等待新结果 (已完成结果保留, 未完成任务
        #    由线程自然结束后回收, 对应 IP 走下方补齐兜底), 避免慢服务无限拖长整体时长
        if flat_tasks:
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(len(flat_tasks), max_workers))
            future_map = {executor.submit(run_both, t): t for t in flat_tasks}
            deadline = (time.monotonic() + total_timeout) if (total_timeout and total_timeout > 0) else None
            for future in concurrent.futures.as_completed(future_map):
                if deadline is not None and time.monotonic() > deadline:
                    break
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
            executor.shutdown(wait=False, cancel_futures=True)

        # 5.5 QUIC 直连服务: 用真实 QUIC 握手测速替换 (必须在此处完成, 不能放到 apply_optimal)
        #     这类服务在 TCP 侧必然全挂, 若不在此替换, 第 6 步的"补齐未完成项"会把它们全部
        #     标成 rank3 不可用 —— UI 表现为"测速失败"; 同时又因为 apply_optimal 是在 UI 线程
        #     被按钮回调调用, 若把真实 QUIC 握手放在那里就会**冻结界面**。测速必须在 worker 里做。
        #     总开关停用时整体跳过 (见 quic_probe.QUIC_ENABLED), 此时线上也没有 QUIC_DIRECT 画像。
        self._probe_quic_services(results_by_srv)

        # 6. 补齐未完成/兜底项并按统一排序键 (rank → 协议偏好 → 稳定段 → 延迟) 保序排序
        for srv_id, items in results_by_srv.items():
            if getattr(PROFILES_BY_ID.get(srv_id), "skip_cdn_probe", False):
                # QUIC 直连服务的候选项已由 _probe_quic_services 完整给出, 不再补 rank3 噪声项
                items.sort(key=lambda x: _service_sort_key(x, ip_mode, None))
                continue
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

        # 7. 低存活率复核: 全量高并发探测对敏感目标 (GitHub 类) 易触发 GFW 高频干扰/限速,
        #    单服务低并发复核可显著降低误杀 (消除"全量全挂/节点骤减、单测可用"的假象)。
        #    阈值 rank0 < 3: 覆盖"节点少"服务 (全量并发下可能被误杀到只剩 2-3 个)。
        #    复核结果直接替换该服务结果; 复核后仍低存活则保留诚实结果。
        if target_set is None or len(target_set) > 1:
            recheck_list = [sid for sid, items in results_by_srv.items()
                            if items and sum(1 for it in items if it.get("rank", 3) == 0) < 3
                            and not getattr(PROFILES_BY_ID.get(sid), "skip_cdn_probe", False)]
            if recheck_list:
                rlock = threading.Lock()

                def _recheck(sid):
                    try:
                        single = self.test_service_dual(sid, max_workers=6)
                        with rlock:
                            results_by_srv[sid] = single
                    except Exception:
                        pass

                recheck_threads = [threading.Thread(target=_recheck, args=(sid,), daemon=True)
                                   for sid in recheck_list]
                for t in recheck_threads:
                    t.start()
                for t in recheck_threads:
                    t.join(timeout=90)

        return results_by_srv

    def _probe_quic_services(self, results_by_srv: Dict[str, List[Dict]]) -> None:
        """为 QUIC 直连服务写入真实 QUIC 测速结果 (在测速 worker 线程内执行)

        为什么必须在测速阶段完成, 而不是在 apply_optimal 里补:
          1. apply_optimal 由 UI 线程的按钮回调直接调用 —— 在其中做真实 QUIC 握手会冻结界面;
          2. 本阶段结果会进入统一排序与 UI 渲染, 若缺失则服务显示为"测速失败/全挂"。

        结果项与常规探测保持一致的结构, 以便排序/徽章/应用逻辑复用同一套代码。

        总开关 (quic_probe.QUIC_ENABLED) 停用时整体跳过 —— 此时线上也没有 QUIC_DIRECT 画像。
        """
        try:
            from quic_probe import is_enabled as _quic_enabled
            if not _quic_enabled():
                return
        except Exception:
            return
        try:
            from quic_probe import probe_candidates, set_optimal_ips, get_optimal_ips
        except Exception as e:
            print(f"[QUIC] 测速跳过: {e}")
            return

        # 并行处理各服务: 串行时每个服务都要等自身握手/响应头 (实测 3 个服务就要 ~20s,
        # 吃掉了全量测速 45s 预算的一半), 并行后与 optimize_quic_services 同量级。
        quic_ids = [sid for sid in list(results_by_srv)
                    if getattr(PROFILES_BY_ID.get(sid), "skip_cdn_probe", False)]
        if not quic_ids:
            return

        def _one(srv_id: str):
            profile = PROFILES_BY_ID.get(srv_id)
            if profile is None:
                return
            domain = (profile.domains or [""])[0]
            candidates = list(dict.fromkeys(
                list(get_optimal_ips(srv_id)) + list(profile.candidate_ips or [])))
            if not candidates:
                return
            try:
                probed = probe_candidates(candidates, domain, timeout=QUIC_PROBE_TIMEOUT)
            except Exception as e:
                print(f"[QUIC] {srv_id} 测速异常: {e}")
                return

            new_items: List[Dict] = []
            for r in probed:
                ok = bool(r.get("ok"))
                new_items.append({
                    "ip": r.get("ip"),
                    "latency": r.get("latency_ms") if ok else None,
                    "available": ok,
                    "rank": 0 if ok else 3,
                    "via_proxy": False,
                    "recommend": "direct" if ok else "none",
                    "sni_mode": "quic",
                    "direct": {"http_status": r.get("status"), "quic": True},
                    "proxy": None,
                    "proxy_used": False,
                    "quic_error": r.get("error") or "",
                    "handshake_ms": r.get("handshake_ms"),
                })
            if new_items:
                results_by_srv[srv_id] = new_items
                usable = [it["ip"] for it in new_items if it["rank"] == 0]
                if usable:
                    # 顺序持久化供 DNS / Hosts 读取 (可用节点在前)
                    set_optimal_ips(srv_id, usable + [it["ip"] for it in new_items if it["rank"] != 0])

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(quic_ids))) as pool:
            list(pool.map(_one, quic_ids))

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
    def _probe_one(ip: str, timeout: float) -> Tuple[bool, Optional[float]]:
        """单点探测 + 抖动补偿

        实测同一 IP 会在 70ms 与超时之间剧烈跳变 (20.27.177.113 六次采样:
        70/1072/超时/71/244/1076), 单次采样容易把可用节点误判为死节点。故在
        "失败"或"结果明显偏慢"时补测一次取更优值。恒定节点(如 20.205.243.166
        六次均为 83~106ms)不会触发补测, 因此不增加常规开销。
        """
        ok, lat = fast_tcp_ping(ip, 443, timeout)
        if not ok or (lat is not None and lat > 300):
            ok2, lat2 = fast_tcp_ping(ip, 443, timeout)
            if ok2 and lat2 is not None and (not ok or (lat is not None and lat2 < lat)):
                return ok2, lat2
        return ok, lat

    def _cached_probe(self, ip: str, timeout: float) -> Tuple[bool, Optional[float]]:
        """带单轮缓存的 TCP 探测

        各服务候选池重叠度很高(如 185.199.108-111 段被 github_raw/release 共用),
        逐服务重复探测是纯浪费。缓存以 IP 为键, 由 generate_upstream_conf 在每轮
        开始时清空。并发下可能存在两次探测同一 IP 的竞态, 但结果一致, 无副作用。
        """
        try:
            return self._probe_cache[ip]
        except KeyError:
            result = CDNOptimizer._probe_one(ip, timeout)
            self._probe_cache[ip] = result
            return result

    @staticmethod
    def _tls_pass_count(ip: str, sni: str, timeout: float = 2.5, attempts: int = 4) -> int:
        """TLS 层复验: 返回 attempts 次握手中成功的次数 (用于批内横向比较)

        为什么仅靠 TCP 测速不够: 实测 github_raw 的 IPv6 节点 TCP 81ms 握手通过,
        TLS 阶段却超时(IPv6 路径上存在 SNI 层阻断); 而同批次的 gitlab IPv6 节点
        TCP 76ms / TLS 151ms 完全正常 —— 两者在纯 TCP 维度无法区分。

        这类阻断是概率性的: github_raw 四个 IPv6 节点各采 10 次, 通过数只有
        0/1/2/0, 而 IPv4 同域名 10/10。单次采样会有 10~20% 概率把"绝大部分时候
        用不了"的节点误判成可用, 故取多次采样, 交由调用方做批内比较。

        返回次数而非布尔值, 是因为网络本身会整体抖动: 实测同一 IPv4 节点在数分钟
        内从 10/10 掉到 0/3。若用绝对阈值, 抖动期会把所有节点一并判死, 排序退化。
        """
        if not sni or sni.startswith("*"):
            return attempts
        ok = 0
        for _ in range(max(1, attempts)):
            sock = None
            try:
                fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
                sock = socket.socket(fam, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((ip, 443))
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.wrap_socket(sock, server_hostname=sni).close()
                ok += 1
            except Exception:
                pass
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
        return ok

    def _probe_fallback_candidates(self, items: List[Dict], timeout: float = 1.2,
                                   sni: str = "", verify_top: int = 4,
                                   tls_attempts: int = 4) -> List[Dict]:
        """兜底候选池的现场测速: 补齐 latency 字段并按延迟重排

        为什么必须补这一步: 兜底分支构造出的项只有 {"ip": ...}, 没有 rank/latency/
        throughput, _service_sort_key 的各维度于是全部退化为常量 —— 排序结果等同于
        candidate_ips 的手工书写顺序。而那份顺序并不反映当前网络: 实测 github_web
        前三位 140.82.113.x 建连 264ms, 而 76ms 的 20.205.243.166 排在其后, 经
        [:3]/[3:8] 主备切分后, 最快的三台恰好全被划入 backup —— nginx 语义下 backup
        只在主力全失效时才启用, 等于永不参与, 代理因此比直连还慢 3 倍以上。

        探测失败的节点保留在末尾而非丢弃: upstream 为空会让 nginx 启动失败, 宁可
        留一个假节点也要保证配置可用(与既有兜底策略一致)。
        """
        if not items:
            return items
        alive: List[Dict] = []
        dead: List[Dict] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(items))) as ex:
            futures = {ex.submit(self._cached_probe, it["ip"], timeout): it for it in items}
            for fut in concurrent.futures.as_completed(futures):
                item = futures[fut]
                try:
                    ok, lat = fut.result()
                except Exception:
                    ok, lat = False, None
                if ok and lat is not None:
                    # TCP 可达: 保留调用方预设的 rank (来自主探测三态), 未预设则视为可用
                    alive.append({**item, "latency": lat, "rank": item.get("rank", 0)})
                else:
                    # TCP 都不可达: 明确降权, 使其退居 backup 而非占据主力位参与轮询
                    dead.append({**item, "rank": 3})
        alive.sort(key=lambda x: x["latency"])

        # TCP 可达 ≠ 真能用: 对排名靠前的候选做 TLS 复验, 把"握手能过但 TLS 被
        # 阻断"的节点降权(不淘汰 —— 段封锁会来回变化, 留作后续轮次的候选)。
        # 用 rank 字段承载结论: _service_sort_key 以 rank 为第一排序键, 因此下面的
        # 防御性排序会自然地把复验通过的节点排到前面。
        # 只复验 IPv6 候选: 实测 TLS 层阻断集中出现在 IPv6 路径上(github_raw 四个
        # IPv6 节点通过率 0~2/10, 而同域名 IPv4 是 10/10, gitlab 的 IPv6 则完全正常),
        # IPv4 候选极少出现"TCP 通 TLS 断", 对其复验纯属浪费 —— 全量复验会让单轮
        # 兜底生成从约 20s 涨到 130s, 而去掉后正常服务几乎零开销。
        # IPv4 万一遇到 TLS 层问题, 仍有 nginx 的 max_fails/fail_timeout 兜底。
        v6_candidates = [it for it in alive if ":" in str(it["ip"])][:verify_top]
        if sni and v6_candidates:
            sample = v6_candidates
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(sample))) as ex:
                futures = {ex.submit(CDNOptimizer._tls_pass_count, it["ip"], sni, 2.5,
                                     tls_attempts): it
                           for it in sample}
                passes = {futures[fut]["ip"]: fut.result()
                          for fut in concurrent.futures.as_completed(futures)}
            # 判据必须相对化, 不能是绝对阈值:
            # 1) 阻断是概率性的 —— github_raw 的 IPv6 通过率 0~2/10, 单次采样有
            #    10~20% 概率把"绝大部分时候用不了"的节点误判成可用; 而同域名 IPv4
            #    是 10/10。用 attempts 次采样后的通过率可以稳定区分这两类。
            # 2) 网络本身会整体抖动 —— 实测 raw.githubusercontent.com 数分钟内从
            #    10/10 掉到 0/2(同期 github.com / gitlab 仍 2/2, 属针对该域名的
            #    间歇阻断)。若用绝对阈值, 抖动期会把所有节点一并判死, 排序退化。
            # 故: 以批内最好成绩为及格线, 及格线以上才做区分; 整批都不及格说明是
            # 暂时性网络问题, 不降权任何节点, 交回延迟排序。
            if passes:
                best = max(passes.values())
                if best * 2 >= tls_attempts:
                    for it in alive:
                        # 只降不升: 复验通过者保留调用方预设的 rank (兜底构造时已按主探测
                        # 的三态结论写入 —— TLS 通者 0、仅 TCP 通者 3), 否则会把"TCP 通但
                        # TLS 被 RST"的节点重新提回主力位。缺失 rank 的项才补默认 0
                        # (缺失会被 _service_sort_key 当作 3 直接沉底)。
                        if it["ip"] in passes and passes[it["ip"]] * 2 < tls_attempts:
                            it["rank"] = 3      # IPv6 复验不达标: 降权
                        else:
                            it.setdefault("rank", 0)   # 复验通过或未参与复验: 维持原判
        return alive + dead

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
        - max_fails=1 fail_timeout=5s 快速熔断 (对准 GFW 逐段分钟级轮换, 见 UPSTREAM_MAX_FAILS 注释);
          hash/least_conn 组不携带 backup 参数
        """
        lines = [
            "# ==============================================================================",
            "# GameArt Toolkit - 动态 Upstream 优选配置 (由双通道测速引擎自动生成)",
            f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "# 仅写入 rank0 (直连三态全通) 节点, 排除假节点导致 502",
            "# 3 主力 + 最多 5 备份冗余; max_fails=1 fail_timeout=5s 快速熔断 (对准分钟级段轮换)",
            "# ==============================================================================\n"
        ]

        # 每次生成重置 relay / ECH 服务集合 (由本轮决策重新填充)
        self.last_relay_services = set()
        self.last_ech_services = set()
        self.last_ech_degraded = set()
        # 重置兜底探测缓存: 结果只在一轮生成内复用, 跨轮必须重新探测以反映网络变化
        self._probe_cache.clear()

        # 读取现有配置用于增量合并: 未参与本次测速的服务保留其已有 upstream 块,
        # 避免单服务自愈/局部重测顺带把其余服务重置回候选池
        existing_blocks = self._load_existing_upstream_blocks()

        # 确保全量服务均生成 upstream 块 (若某服务未测速，则自动取 CANDIDATE_IPS 默认兜底)
        for srv_id in CANDIDATE_IPS:
            ip_items = test_results.get(srv_id)

            # --------------------------------------------------------------
            # ECH 隧道分支 (优先级: ECH > relay > 候选池):
            # 标记 ech_enabled 的服务一律交给本地 ECH 隧道, 隧道在回环上提供明文
            # HTTP 入口, 自行发起带 ECH 的 TLS 连接。
            #
            # 为什么判据只看隧道健康、不看探测结果: 探测发的是普通 TLS 握手, 其
            # 成败与"带 ECH 的连接能否成功"无关, 不能用它证伪 ECH。实测反例:
            # pixiv_web 的候选池含 210.140.139.x (Pixiv 源站, 非 Cloudflare 托管),
            # 这些 IP 的普通握手会间歇性通过, 于是 rank0 非空、判据翻向候选池 ——
            # 而候选池必须走 https:// + 明文 SNI, 正是被阻断的那条路。
            # (原注释断言"rank0 恒为空", 该断言在上述候选池下不成立)
            #
            # 为什么置于增量合并之前: ECH 服务的上游是本地隧道端口, 与探测结果
            # 无关, 必须每轮重新评估 —— 否则隧道状态变化会被旧块掩盖
            # (实测: 该分支原本在合并之后, 未测速的服务直接沿用旧块, ECH 永不生效)。
            # --------------------------------------------------------------
            if getattr(PROFILES_BY_ID.get(srv_id), "ech_enabled", False):
                if ech_tunnel.is_healthy():
                    lines.append(f"upstream upstream_{srv_id} {{")
                    lines.append(f"    # 经本地 ECH 隧道直连 Cloudflare (port={ech_tunnel.port})")
                    lines.append(f"    server 127.0.0.1:{ech_tunnel.port} {_upstream_server_opts()};")
                    lines.append("    keepalive 32;")
                    lines.append("    keepalive_timeout 30;")
                    lines.append("    keepalive_requests 10000;")
                    lines.append("}\n")
                    self.last_ech_services.add(srv_id)
                    continue
                # 隧道未就绪: 不静默兜底, 记下来供上层告警, 再走常规分支。
                # 此时 upstream 会落到候选池 (https 后端), 对应 site 配置必须写
                # https:// —— 由 NginxConfGenerator 依据本文件实际内容决定, 见
                # _ech_services_from_upstream。两处判据不一致会产出
                # "http:// 打向 :443" 的错配, 上游直接回 400 (已实测)。
                self.last_ech_degraded.add(srv_id)

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
                            lines.append(f"    server 127.0.0.1:{port} {_upstream_server_opts()};")
                            lines.append("    keepalive 32;")
                            lines.append("    keepalive_timeout 30;")
                            lines.append("    keepalive_requests 10000;")
                            lines.append("}\n")
                            continue

            # 只写 rank0 直连可用节点; 无 rank0 则回退候选池兜底 (保证 nginx 可启动)
            usable = rank0
            fallback = not usable
            if not usable:
                # 兜底: 主探测虽未产出 rank0, 但其分阶段三态结果 (tcp/tls/http) 仍能
                # 区分节点质量 —— 原先只取 ip 字段, 把"TCP 通但 TLS 被 RST"的节点与
                # "TLS/HTTP 都通、仅状态码可疑"的节点一视同仁。
                # 实测 i.pximg.net 在 210.140.139.131~134 上 TCP 全通而 TLS 全部 RST:
                # 这类节点会被纯 TCP 探测判为健康并占住主力位, nginx 每次转发都失败。
                # rank 语义与 _service_sort_key 一致 (0 优先 / 3 垫后)。
                usable = []
                for it in ip_items:
                    if not it.get("ip"):
                        continue
                    d = it.get("direct") or {}
                    p = it.get("proxy") or {}
                    if d or p:
                        # 有主探测三态结果: 以 TLS 是否握手成功分层
                        tls_ok = bool(d.get("tls_ok") or p.get("tls_ok"))
                        usable.append({"ip": it["ip"], "rank": 0 if tls_ok else 3})
                    else:
                        # 无探测数据 (首轮生成 / 增量合并): 不预设 rank —— 排序键会退化为
                        # "稳定段优先 + 候选池顺序", 这已经足够; 真正的分层由测速阶段给出。
                        usable.append({"ip": it["ip"]})
                # 这里**刻意不做任何网络探测**:
                # generate_upstream_conf 会被 apply_optimal 调用, 而 apply_optimal 处于 UI
                # 线程 (按钮回调 / 测速完成回调)。早期版本在此处现场做 TCP/TLS 探测补齐
                # latency, 遇到"无测速结果且无旧块"的服务 (典型就是刚新增的服务) 时会在
                # 主线程连续握手数十次, 表现为**界面冻结数十秒** —— 这正是本项目实测过的
                # "单个用例要等 40s+" 的来源。延迟必须由测速阶段 (worker 线程) 提供;
                # 缺数据时按 稳定段 → 候选池顺序 输出, 由 nginx 的
                # max_fails=1/fail_timeout=5s 快速故障转移到可用节点。

            # 防御性排序: 复用统一排序键 (稳定段优先于延迟), 不依赖调用方预排序
            # 若这里只按延迟排序, 会覆盖 test_all_services 的稳优先结果导致白做
            stable_set = set(getattr(PROFILES_BY_ID.get(srv_id), "stable_ips", [])) or None
            usable.sort(key=lambda x: _service_sort_key(x, None, stable_set))
            valid_ips = [it["ip"] for it in usable if it.get("ip")]
            # 可用性分层: rank0 (TLS 可通) 优先占主力位, 其余退到 backup。
            # nginx 语义下 backup 只在主力全部失效时才启用, 因此"TCP 通但 TLS 超时"的
            # 死节点不再参与日常轮询 —— 否则候选池小的服务会被它们占满主力位:
            # 实测 nuget_api 仅 3 个候选, 三个全进主力后每次轮到 .113/.8.183 都要等满
            # proxy_connect_timeout 才交棒 (error.log 中可见连串 upstream timed out),
            # 表现为"打开 nuget 偶尔卡数秒"。全死时回退原行为 (前 3 主力 + 其余备份)。
            healthy = [it["ip"] for it in usable if it.get("ip") and it.get("rank", 3) == 0]
            degraded = [it["ip"] for it in usable if it.get("ip") and it.get("rank", 3) != 0]
            # 稳定性冗余: 3 主力 + 最多 5 备份 (原 2+2 单节点被封即单点故障;
            # GitHub/Fastly 段被 GFW 逐段封锁时, 多备份保证 nginx 自动故障转移)
            if healthy:
                primary_ips = healthy[:3]
                backup_ips = (healthy[3:] + degraded)[:5]
            else:
                # 全死: 回退原行为 (前 3 主力 + 其余备份), 保证 upstream 仍有节点可用
                primary_ips = degraded[:3]
                backup_ips = degraded[3:8]

            lines.append(f"upstream upstream_{srv_id} {{")
            if fallback:
                lines.append(f"    # 警告: 服务 {srv_id} 双通道探测全部失败, 回退候选池兜底")
            
            if not valid_ips:
                # 极端场景防护: 若完全无有效候选 IP，写入 down 节点保证 Nginx 语法不报错
                lines.append("    server 127.0.0.1:443 down;  # 兜底占位，防止 upstream 为空导致 Nginx 语法解析失败")
            elif srv_id == "pixiv_web":
                lines.append("    hash $connection consistent;")
                for ip in valid_ips[:6]:
                    lines.append(self._fmt_server(ip, _upstream_server_opts()))
            elif srv_id == "pixiv_img":
                lines.append("    least_conn;")
                for ip in valid_ips[:6]:
                    lines.append(self._fmt_server(ip, _upstream_server_opts()))
            else:
                for ip in primary_ips:
                    lines.append(self._fmt_server(ip, _upstream_server_opts()))
                for ip in backup_ips:
                    lines.append(self._fmt_server(ip, "backup " + _upstream_server_opts()))

            lines.append("    keepalive 32;")
            lines.append("    keepalive_timeout 30;")
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
            # 必须同时匹配 http:// —— ECH 隧道的上游是本地回环上的明文 HTTP 入口,
            # 只匹配 https 会让这几个服务的引用游离在校验之外 (上游漏定义也拦不下,
            # nginx 直接启动失败)
            for m in re.finditer(r"proxy_pass\s+https?://(upstream_[a-z0-9_]+)", text):
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
            # ECH 服务不参与 rank 判定: 探测层复现不了 ECH 路径 (空 SNI 被 CF 拒绝、
            # 明文 SNI 被阻断), 其 rank0 必然为空, 但服务实际由隧道直连 —— 不排除
            # 就会误报"双通道探测全部失败已回退候选池", 掩盖真实状态。
            ech_ok = self.last_ech_services
            failed = [s for s in failed if s not in ech_ok]
            relayed = [s for s in failed if s in self.last_relay_services]
            fallback = [s for s in failed if s not in self.last_relay_services]
            # 低存活率服务: rank0 直连节点不足 2 个 (单点依赖, GFW 逐段封锁下随时全挂)
            # QUIC 直连服务除外: 其候选池本就小 (2~3 个 IP 即够), 且"启用本地代理"对它们无意义
            low_avail = [srv_id for srv_id, items in test_results.items()
                         if srv_id not in ech_ok
                         and not getattr(PROFILES_BY_ID.get(srv_id), "skip_cdn_probe", False)
                         and sum(1 for it in items if it.get("rank", 3) == 0) < 2]
            msg = "已生成延迟最低的节点配置并写入 upstream-dynamic.conf！"
            if ech_ok:
                msg += f" {len(ech_ok)} 个服务经 ECH 隧道直连({', '.join(sorted(ech_ok))})"
            if self.last_ech_degraded:
                msg += (f" ⚠️ {len(self.last_ech_degraded)} 个服务标记了 ECH 但隧道未就绪, "
                        f"已回退常规分支({', '.join(sorted(self.last_ech_degraded))})")
            if relayed:
                msg += f" {len(relayed)} 个服务直连不可用已切换本地代理转发({', '.join(sorted(relayed))})"
            if fallback:
                msg += f" {len(fallback)} 个服务双通道探测全部失败已回退候选池({', '.join(sorted(fallback))})"
                proxy = _load_proxy_config()
                if proxy and is_proxy_available(proxy):
                    msg += "。当前直连被阻断而本地代理可用, 但 Nginx 数据平面仍为直连, 请检查网络直连状态"
                else:
                    msg += ", 建议检查网络后重试"
            if low_avail:
                proxy_now = _load_proxy_config()
                hint = "。检测到本地代理可用, 建议开启上游代理以启用 relay 兜底" if proxy_now else \
                       ", 可用节点过少, 建议启用本地代理后重测"
                msg += f" ⚠️ {len(low_avail)} 个服务可用节点不足({', '.join(sorted(low_avail))}){hint}"

            # QUIC 直连服务的优选结果已在测速阶段 (_probe_quic_services) 完成并持久化 ——
            # 这里绝不能再发起网络探测: apply_optimal 由 UI 线程的按钮回调调用, 任何真实
            # 握手都会直接冻结界面 (早期版本正是这样引入 UI 冻结的)。
            try:
                from service_profile import ServiceMode as _SM
                from quic_probe import get_optimal_ips
                quic_ids = [p.id for p in PROFILES_BY_ID.values()
                            if getattr(p, "mode", None) == _SM.QUIC_DIRECT
                            and p.id in test_results]
                if quic_ids:
                    ready = [sid for sid in quic_ids if get_optimal_ips(sid)]
                    pending = [sid for sid in quic_ids if not get_optimal_ips(sid)]
                    if ready:
                        detail = ", ".join(f"{sid}({get_optimal_ips(sid)[0]})" for sid in ready)
                        msg += f" | QUIC 直连已优选: {detail}"
                    if pending:
                        msg += (f" | ⚠️ QUIC 直连服务 {', '.join(pending)} 暂无可用节点"
                                f" (其解析需由本机 DNS 后端下发, Hosts 模式不生效)")
            except Exception as e:
                print(f"[CDN] QUIC 结果汇总跳过: {e}")

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

    def _check_and_heal_quic(self, srv_id: str) -> bool:
        """QUIC 直连服务的健康巡检与自愈

        这类服务的 TCP 侧 SNI 必然被 RST, 常规双通道探针只会永久判定"故障"并触发无意义
        自愈, 因此改用**真实 QUIC 握手**复测候选池:
          - 当前主力 IP 仍可用 -> 健康, 无需自愈
          - 当前主力失效但池中另有可用节点 -> 持久化新顺序 (自愈), 返回 True
          - 全部不可用 -> 记一次失败, 不谎报自愈

        总开关停用时直接返回 False (不探测、不误报自愈)。
        """
        try:
            from quic_probe import is_enabled as _quic_enabled
            if not _quic_enabled():
                return False
        except Exception:
            return False
        try:
            from quic_probe import optimize_service, current_best_ip
        except Exception as e:
            print(f"[Health] QUIC 巡检跳过 ({srv_id}): {e}")
            return False

        try:
            current = current_best_ip(srv_id)
            report = optimize_service(srv_id, persist=True)
            ok_ips = {r["ip"] for r in report.get("results", []) if r.get("ok")}

            if current and current in ok_ips:
                with self._lock:
                    self.failure_counts[srv_id] = 0
                return False
            if ok_ips:
                new_best = report.get("best_ip") or ""
                with self._lock:
                    self.failure_counts[srv_id] = 0
                if new_best and new_best != current:
                    print(f"[Health] QUIC 服务 {srv_id} 主力节点 {current} 失效, 已自愈切换至 {new_best}")
                    return True
                return False
            with self._lock:
                self.failure_counts[srv_id] = self.failure_counts.get(srv_id, 0) + 1
            return False
        except Exception as e:
            print(f"[Health] QUIC 服务 {srv_id} 巡检异常: {e}")
            return False

    def check_and_heal_service(self, srv_id: str) -> bool:
        """检查单个服务的当前主力节点，并在故障时自动选举自愈"""
        srv = SERVICES_BY_ID.get(srv_id)
        if not srv:
            return False

        # QUIC 直连服务必须**最先**分流: 其 TCP 侧 SNI 必然被 RST, 若先走下面的常规
        # 双通道探针, 每轮巡检都要白等一次注定失败的 TCP/TLS 超时, 再被判"故障"。
        try:
            from service_profile import ServiceMode as _SM
            _is_quic = getattr(PROFILES_BY_ID.get(srv_id), "mode", None) == _SM.QUIC_DIRECT
        except Exception:
            _is_quic = False
        if _is_quic:
            return self._check_and_heal_quic(srv_id)

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

        # QUIC 直连服务: TCP 侧 SNI 必然被 RST, 常规探针只会永久失败并触发无意义"自愈"。
        # (已在函数入口分流到 _check_and_heal_quic, 此处不再处理)

        # 轻量探针检查当前主力节点 (三态验证 + 多域全验证 + 状态码放行, 全部通过才算健康)
        # 与测速判定完全一致: 假阳性节点 (S3 403 / 多域任一可疑) 不再被误判健康, 可被自愈替换

        # 轻量探针检查当前主力节点 (三态验证 + 多域全验证 + 状态码放行, 全部通过才算健康)
        profile = PROFILES_BY_ID.get(srv_id)
        sni_mode = SNI_MODES.get(srv_id, "host")
        domain = srv["domains"][0] if srv["domains"] else ""
        measure_thp = bool(getattr(profile, "measure_throughput", False))
        probe_domains = list(getattr(profile, "probe_domains", ()) or ()) or None
        ok_statuses = set(getattr(profile, "probe_ok_statuses", ()) or ()) or None
        proxy_connect_domain = bool(getattr(profile, "proxy_connect_by_domain", False))
        probe_res = probe_ip_endpoint_v2(best_item["ip"], domain=domain,
                                         timeout=PROBE_DEFAULTS.health_probe_timeout, sni_mode=sni_mode,
                                         measure_throughput=measure_thp,
                                         probe_domains=probe_domains, ok_statuses=ok_statuses,
                                         proxy_connect_domain=proxy_connect_domain)

        if (probe_res.get("tls_ok", False) and probe_res.get("http_ok", False)
                and not _suspect_status(probe_res.get("http_status"))
                and not probe_res.get("http_suspect")):
            # 主力节点健康, 但对"下载吞吐敏感"的服务, 若实测发现其吞吐显著落后于
            # 候选中最佳吞吐, 仍触发重选: 让"握手 200 但下载慢"的节点被自动替换。
            # 仅在能拿到新旧两个吞吐读数时才启用, 避免抖动误判 (需明显差距)。
            if measure_thp and probe_res.get("throughput"):
                cached_best_thp = _best_throughput_among_rank0(items)
                if cached_best_thp is not None and probe_res["throughput"] > 0:
                    ratio = probe_res["throughput"] / max(cached_best_thp, 1.0)
                    # 当前主力吞吐低于最优候选 45% 时判为"慢节点", 触发重新选举
                    if ratio < THROUGHPUT_HEAL_RATIO:
                        new_items = self.optimizer.test_service_dual(srv_id)
                        with self._lock:
                            self.cached_results[srv_id] = new_items
                            self.failure_counts[srv_id] = 0
                        return True
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
    res = opt.test_all_services(max_workers=16)
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

