# -*- coding: utf-8 -*-
"""
PixivToolkit - 本地轻量 DNS 解析与递归转发服务 (Local DNS Resolver)

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


class LocalDnsServer:
    """本地轻量 DNS 服务器与智能路由"""

    def __init__(self, host: str = "127.0.0.1", port: int = 5353,
                 upstream_dns: str = "223.5.5.5", upstream_port: int = 53):
        self.host = host
        self.port = port
        self.upstream_dns_list = [upstream_dns, "119.29.29.29", "1.1.1.1"]
        self.upstream_dns = upstream_dns
        self.upstream_port = upstream_port
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False
        self.custom_mappings: Dict[str, str] = {}

    def is_running(self) -> bool:
        return self._is_running

    def add_custom_mapping(self, domain: str, ip: str):
        """注册自定义域名 -> IP 映射"""
        self.custom_mappings[domain.lower()] = ip

    def _resolve_locally(self, domain: str) -> Optional[str]:
        """判定域名是否应由本地加速规则应答"""
        d_lower = domain.lower()
        if d_lower in self.custom_mappings:
            return self.custom_mappings[d_lower]

        profile = get_profile_by_domain(d_lower)
        if profile:
            if profile.mode == ServiceMode.DIRECT and profile.candidate_ips:
                return profile.candidate_ips[0]
            else:
                return "127.0.0.1"

        return None

    def _forward_upstream(self, raw_query: bytes) -> Optional[bytes]:
        """将非目标 DNS 查询透明递归转发给上游公共 DNS (支持多上游自动容灾)"""
        for dns_ip in self.upstream_dns_list:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up_sock:
                    up_sock.settimeout(1.0)
                    up_sock.sendto(raw_query, (dns_ip, self.upstream_port))
                    resp, _ = up_sock.recvfrom(4096)
                    if resp:
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
        local_ip = self._resolve_locally(domain)
        if local_ip:
            if qtype == 1:  # A 记录 (IPv4)
                resp = build_dns_a_response(data, tx_id, local_ip)
                try:
                    if self._sock:
                        self._sock.sendto(resp, client_addr)
                except Exception:
                    pass
                return
            elif qtype in (28, 65):  # 28=AAAA (IPv6), 65=HTTPS (SVCB) 屏蔽返回 NODATA，强制客户端降级 IPv4 A 记录
                resp = build_dns_empty_response(data, tx_id)
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
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.host, self.port))
            self._sock.settimeout(0.5)
            self._is_running = True
        except Exception:
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
