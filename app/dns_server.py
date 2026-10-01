# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 本地轻量 DNS 解析与递归转发服务 (Local DNS Resolver)

核心特性:
- 零外部依赖 (纯标准库 socket / struct 实现 RFC 1035 DNS 协议)
- 智能分流: 命中 Service Profile 的域名直接应答 127.0.0.1 或最优 CDN Anycast IP
- 透明递归: 未匹配的公网域名自动上游转发 (默认 223.5.5.5 / 119.29.29.29)
- 独立生命周期管理 (可作为高级选项开启，补充 Hosts 无法覆盖的应用)
"""

import sys
import socket
import struct
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from service_profile import ServiceMode, get_profile_by_domain, PROFILES


def parse_dns_query(data: bytes) -> Tuple[int, str, int, int]:
    """
    解析 DNS 请求包头部与首个 Question 块
    返回: (transaction_id, domain_name, qtype, qclass)
    """
    if len(data) < 12:
        return 0, "", 0, 0

    tx_id, flags, qd_count = struct.unpack("!HHH", data[:6])
    if qd_count < 1:
        return tx_id, "", 0, 0

    # 解析 QNAME (Label 序列)
    pos = 12
    labels = []
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        # 兼容指针 (一般 Question 块为纯 label)
        if length >= 192:  # 0xC0
            pos += 2
            break
        pos += 1
        label = data[pos:pos + length].decode("ascii", errors="ignore")
        labels.append(label)
        pos += length

    domain = ".".join(labels).lower()
    if pos + 4 <= len(data):
        qtype, qclass = struct.unpack("!HH", data[pos:pos + 4])
    else:
        qtype, qclass = 1, 1

    return tx_id, domain, qtype, qclass


def _extract_a_ips(resp: bytes) -> List[str]:
    """从 DNS 响应报文中提取全部 A 记录 (IPv4) IP 列表 (供污染与 Fake-IP 检测)"""
    if len(resp) < 12:
        return []
    ancount = struct.unpack("!H", resp[6:8])[0]
    if ancount == 0:
        return []
    # 跳过 Question 块 (兼容压缩指针)
    off = 12
    while off < len(resp):
        length = resp[off]
        if length == 0:
            off += 5  # 0x00 + QType(2B) + QClass(2B)
            break
        if length >= 192:  # 0xC0 指针
            off += 2
            break
        off += 1 + length
    ips: List[str] = []
    for _ in range(ancount):
        if off + 2 > len(resp):
            break
        # Answer Name: 压缩指针 (2B) 或 label 序列
        if resp[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while off < len(resp) and resp[off] != 0:
                off += resp[off] + 1
            off += 1
        if off + 10 > len(resp):
            break
        rtype, _, _, rdlen = struct.unpack("!HHIH", resp[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4 and off + 4 <= len(resp):
            raw_ip = socket.inet_ntoa(resp[off:off + 4])
            ips.append(raw_ip)
        off += rdlen
    return ips


def build_dns_a_response(raw_query: bytes, tx_id: int, ip_str: str, ttl: int = 60) -> bytes:
    """构建标准 DNS A 记录应答报文"""
    # 找到 Question 块的结束位置
    pos = 12
    while pos < len(raw_query):
        length = raw_query[pos]
        if length == 0:
            pos += 5  # 0x00 + QType(2B) + QClass(2B)
            break
        pos += 1 + length

    question_bytes = raw_query[12:pos]

    # DNS 响应头: ID, Flags(0x8180 Standard query response, No error), QDCount(1), ANCount(1), NSCount(0), ARCount(0)
    header = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)

    # Answer 记录: Name(0xC00C 压缩指针), Type(1=A), Class(1=IN), TTL(4B), RDLENGTH(4), RDATA(4B IP)
    ip_bytes = socket.inet_aton(ip_str)
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, ttl, 4) + ip_bytes

    return header + question_bytes + answer


def build_dns_empty_response(raw_query: bytes, tx_id: int) -> bytes:
    """构建标准 DNS NOERROR 空应答 (用于屏蔽 AAAA / HTTPS 记录避免 IPv6 绕过代理)"""
    pos = 12
    while pos < len(raw_query):
        length = raw_query[pos]
        if length == 0:
            pos += 5
            break
        pos += 1 + length
    question_bytes = raw_query[12:pos]
    header = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 0, 0, 0)
    return header + question_bytes


def build_dns_https_response(raw_query: bytes, tx_id: int, ip_str: str = "",
                             alpn: Tuple[str, ...] = ("h3", "h2"), ttl: int = 60) -> bytes:
    """构建 HTTPS(RR type 65) 应答, 用于向浏览器声明"本域名支持 HTTP/3"

    背景: 部分站点的 TCP+TLS 标准 SNI 会被 RST, 但 UDP/443 的 QUIC 通路放行。浏览器只有在
    知道该源支持 h3 时才会直接使用 QUIC (否则会先试 TCP 并被 RST 掉), 而 HTTPS RR 的 alpn
    参数正是这个"声明"的权威来源 —— 在自家解析器上应答它, 浏览器即可自行走 QUIC 直连,
    全程不需要本机终止 TLS。

    报文结构 (RFC 9460): SvcPriority(2B) + TargetName(根域名, 1B=0x00) + SvcParams
      SvcParam 均为 key(2B) + length(2B) + value:
        key=1 alpn     : 长度前缀字符串序列, 如 \x02h3\x02h2
        key=4 ipv4hint : 若干 4 字节 IPv4 地址
    """
    pos = 12
    while pos < len(raw_query):
        length = raw_query[pos]
        if length == 0:
            pos += 5
            break
        pos += 1 + length
    question_bytes = raw_query[12:pos]

    header = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)

    alpn_value = b"".join(bytes([len(a)]) + str(a).encode("ascii", "ignore") for a in alpn if a)
    params = struct.pack("!HH", 1, len(alpn_value)) + alpn_value

    if ip_str and ":" not in ip_str:
        try:
            hint = socket.inet_aton(ip_str)
            params += struct.pack("!HH", 4, len(hint)) + hint
        except OSError:
            pass

    rdata = struct.pack("!H", 1) + b"\x00" + params          # SvcPriority=1, TargetName="."
    answer = struct.pack("!HHHIH", 0xC00C, 65, 1, ttl, len(rdata)) + rdata
    return header + question_bytes + answer


class LocalDnsServer:
    """本地轻量 DNS 服务器与智能路由"""

    DEFAULT_PORT = 5353

    def __init__(self, host: str = "127.0.0.1", port: Optional[int] = None,
                 upstream_dns: str = "223.5.5.5", upstream_port: int = 53):
        self.host = host
        self.default_port = LocalDnsServer.DEFAULT_PORT
        self.last_bind_error = ""

        cfg: Dict = {}
        try:
            from config_store import load_config
            cfg = load_config() or {}
        except Exception:
            cfg = {}
        try:
            self.default_port = int(cfg.get("dns_listen_port", LocalDnsServer.DEFAULT_PORT))
        except Exception:
            self.default_port = LocalDnsServer.DEFAULT_PORT

        # 端口优先级: 显式传参 > 配置默认端口 (NRPT 模式会临时改绑到 53)
        self.port = int(port) if port is not None else self.default_port

        cfg_dns = cfg.get("upstream_dns_servers")
        if cfg_dns and isinstance(cfg_dns, list):
            self.upstream_dns_list = list(cfg_dns)
        else:
            self.upstream_dns_list = [upstream_dns, "119.29.29.29", "1.1.1.1"]

        self.upstream_dns = self.upstream_dns_list[0] if self.upstream_dns_list else upstream_dns
        self.upstream_port = upstream_port
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False
        self.custom_mappings: Dict[str, str] = {}

    def set_upstream_dns_list(self, dns_list: List[str]):
        """动态更新上游公共 DNS 服务器列表"""
        if dns_list:
            self.upstream_dns_list = list(dns_list)
            self.upstream_dns = dns_list[0]

    def set_port(self, port: Optional[int] = None) -> Tuple[bool, str]:
        """切换监听端口 (None = 恢复配置默认端口); 正在运行时先安全停止, 由调用方按需重启"""
        try:
            target = self.default_port if port is None else int(port)
        except Exception as e:
            return False, f"非法监听端口: {e}"
        if target == self.port:
            return True, f"DNS 监听端口已是 {self.port}"
        if self._is_running:
            self.stop()
        self.port = target
        return True, f"DNS 监听端口已切换为 {self.port}"

    def ensure_bind(self, port: int, host: Optional[str] = None) -> Tuple[bool, str]:
        """确保本机解析器运行在指定端口/地址上 (NRPT 的 NameServers 固定发往 53)

        为什么要支持指定地址: 第三方代理常占用 53, 但**只占某一个地址族** —— 实测
        mihomo 只绑 `:::53` 时 IPv4 侧完全空闲, 我们绑 127.0.0.1:53 可正常收到查询;
        反之若代理占满 `0.0.0.0:53`, 则 IPv6 回环 ::1:53 仍可用 (Windows 下两个地址族
        互不冲突, 而 SO_REUSEADDR 在 IPv4 通配被占时无效)。据此可按地址族共存, 无需
        改动用户代理配置。
        """
        try:
            target = int(port)
        except Exception as e:
            return False, f"非法监听端口: {e}"
        target_host = (host or self.host or "127.0.0.1").strip()

        changed = (self.port != target) or (target_host != self.host)
        if changed and self._is_running:
            self.stop()
        self.port = target
        self.host = target_host
        if self._is_running:
            return True, f"本地 DNS 服务已在运行中 ({self.host}:{self.port})"

        ok, msg = self.start()
        if not ok:
            # 绑定失败 (典型为第三方 DNS 已占用 53) 时立即回退默认端口, 避免后续状态判断错乱
            self.port = self.default_port
        return ok, msg

    def is_running(self) -> bool:
        return self._is_running

    def add_custom_mapping(self, domain: str, ip: str):
        """注册自定义域名 -> IP 映射"""
        self.custom_mappings[domain.lower()] = ip

    def _resolve_local_entry(self, domain: str) -> Optional[Tuple[str, bool]]:
        """判定域名是否由本地加速规则应答

        返回 (应答 IP, 是否为 QUIC 直连模式); None 表示未命中, 应透明转发上游。
        QUIC 直连模式必须额外下发 HTTPS RR(alpn=h3), 否则浏览器无从得知可走 HTTP/3。
        """
        d_lower = domain.lower()
        if d_lower in self.custom_mappings:
            return self.custom_mappings[d_lower], False

        profile = get_profile_by_domain(d_lower)
        if profile:
            if profile.mode == ServiceMode.QUIC_DIRECT:
                # QUIC 直连: 优先用 QUIC 实测优选结果 (静态池一旦被封就永久失效, 无自愈能力)
                # 总开关停用时不再劫持该域: 交回上游解析, 避免把域名钉到一个已停用通道的 IP 上
                # (QUIC 服务在 nginx 侧没有 server 块, 劫持到 127.0.0.1 只会得到必然失败的连接)。
                try:
                    from quic_probe import is_enabled as _quic_enabled
                    if not _quic_enabled():
                        return None
                except Exception:
                    pass
                try:
                    from quic_probe import current_best_ip
                    ip = current_best_ip(profile.id)
                except Exception:
                    ip = profile.candidate_ips[0] if profile.candidate_ips else ""
                if ip:
                    return ip, True
                # 无任何可用 IP 时不得降级为 127.0.0.1: QUIC 服务在 nginx 侧没有 server 块
                # (已在生成器排除), 劫持到本机只会得到一个必然失败的连接。交给上游解析。
                return None
            if profile.mode == ServiceMode.DIRECT:
                try:
                    from quic_probe import get_optimal_ips
                    ips = get_optimal_ips(profile.id)
                    if ips:
                        return ips[0], False
                except Exception:
                    pass
                if profile.candidate_ips:
                    return profile.candidate_ips[0], False
            return "127.0.0.1", False

        return None

    def _resolve_locally(self, domain: str) -> Optional[str]:
        """判定域名是否应由本地加速规则应答 (兼容接口: 仅返回 IP)"""
        entry = self._resolve_local_entry(domain)
        return entry[0] if entry else None

    def _forward_upstream(self, raw_query: bytes) -> Optional[bytes]:
        """将非目标 DNS 查询透明递归转发给上游公共 DNS (UDP + DoH 双通道容灾)

        UDP 响应命中已知污染 IP 段或 Fake-IP (198.18.x.x) 时,
        改用 DoH 干净解析重建 A 记录响应 (DoH 加密查询无法被注入)。
        """
        from cdn_optimizer import doh_resolve, is_valid_public_cdn_ip
        tx_id, q_domain, qtype, _ = parse_dns_query(raw_query)
        for dns_ip in self.upstream_dns_list:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up_sock:
                    up_sock.settimeout(1.0)
                    up_sock.sendto(raw_query, (dns_ip, self.upstream_port))
                    resp, _ = up_sock.recvfrom(4096)
                    if resp:
                        # 检查 A 记录是否合法: 若为 Fake-IP 或污染 IP，改用 DoH 重建纯净响应
                        if q_domain and qtype == 1:
                            udp_ips = _extract_a_ips(resp)
                            if udp_ips and not all(is_valid_public_cdn_ip(ip) for ip in udp_ips):
                                doh_ips = doh_resolve(q_domain)
                                if doh_ips:
                                    return build_dns_a_response(raw_query, tx_id, doh_ips[0])
                        return resp
            except Exception:
                continue
        return None

    def _handle_request(self, data: bytes, client_addr: Tuple[str, int]):
        """处理单条 DNS 查询请求"""
        tx_id, domain, qtype, _ = parse_dns_query(data)
        if not domain or tx_id == 0:
            return

        # 对命中加速规则的域名执行智能分流
        entry = self._resolve_local_entry(domain)
        if entry:
            local_ip, is_quic = entry
            resp = None
            if qtype == 1:  # A 记录 (IPv4)
                resp = build_dns_a_response(data, tx_id, local_ip)
            elif qtype == 65 and is_quic:
                # QUIC 直连: 声明 alpn=h3, 让浏览器在 TCP 被 RST 的情况下改走 HTTP/3
                resp = build_dns_https_response(data, tx_id, local_ip)
            elif qtype in (28, 65):  # 28=AAAA (IPv6), 65=HTTPS (SVCB) 屏蔽返回 NODATA，强制客户端降级 IPv4 A 记录
                resp = build_dns_empty_response(data, tx_id)
            if resp is not None:
                try:
                    if self._sock:
                        self._sock.sendto(resp, client_addr)
                except Exception:
                    pass
                return

        # 其他未匹配情况透明转发给上游 DNS
        upstream_resp = self._forward_upstream(data)
        if upstream_resp and self._sock:
            try:
                self._sock.sendto(upstream_resp, client_addr)
            except Exception:
                pass

    def _worker_loop(self):
        """后台 UDP 监听与请求调度循环"""
        try:
            # 按监听地址选择地址族: NRPT 在 IPv4 53 被代理占用时可改指向 ::1 共存
            family = socket.AF_INET6 if ":" in (self.host or "") else socket.AF_INET
            self._sock = socket.socket(family, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                try:
                    # 仅监听指定回环地址, 不做 v4 映射 (避免与占用者抢 IPv4 流量)
                    self._sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                except Exception:
                    pass
            self._sock.bind((self.host, self.port))
            self._sock.settimeout(0.5)
            self._is_running = True
            self.last_bind_error = ""
        except Exception as e:
            # 绑定失败详情必须留存: NRPT 模式下 53 端口被第三方 DNS 占用是常见场景,
            # 上层要靠这条信息告诉用户"谁占着 53", 而不是笼统的"端口冲突"
            self.last_bind_error = f"{e.__class__.__name__}: {e}"
            self._is_running = False
            return

        while not self._stop_event.is_set():
            try:
                data, client_addr = self._sock.recvfrom(4096)
                if data:
                    self._handle_request(data, client_addr)
            except socket.timeout:
                continue
            except Exception:
                break

        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        self._is_running = False

    def start(self) -> Tuple[bool, str]:
        """启动本地 DNS 服务守护线程"""
        if self._is_running:
            return True, f"DNS 服务器已经在运行中 ({self.host}:{self.port})"
        try:
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="LocalDnsThread")
            self._thread.start()
            import time
            time.sleep(0.1)
            if self._is_running:
                return True, f"本地 DNS 服务启动成功 ({self.host}:{self.port})"
            if self.last_bind_error:
                return False, f"本地 DNS 启动失败 ({self.host}:{self.port}): {self.last_bind_error}"
            return False, "本地 DNS 启动失败，请检查端口是否冲突"
        except Exception as e:
            return False, f"启动 DNS 异常: {e}"

    def stop(self) -> Tuple[bool, str]:
        """停止本地 DNS 服务"""
        if not self._is_running:
            return True, "DNS 服务器未在运行"
        try:
            self._stop_event.set()
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=1.0)
            self._is_running = False
            return True, "本地 DNS 服务已安全停止"
        except Exception as e:
            return False, f"停止 DNS 异常: {e}"


# 全局单例
local_dns_server = LocalDnsServer()
