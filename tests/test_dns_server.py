# -*- coding: utf-8 -*-
"""
PixivToolkit - 本地轻量 DNS 解析服务单元与集成测试集
"""

import sys
import socket
import struct
import unittest
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP_DIR))

from dns_server import parse_dns_query, build_dns_a_response, LocalDnsServer


class TestDnsServer(unittest.TestCase):
    """测试 DNS 报文编解码与 LocalDnsServer 路由分流"""

    def _build_dns_query_packet(self, domain: str, tx_id: int = 0x1234) -> bytes:
        """构建标准 DNS A 记录查询 UDP 报文"""
        header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
        qname = b""
        for part in domain.split("."):
            qname += bytes([len(part)]) + part.encode("ascii")
        qname += b"\x00"
        question = qname + struct.pack("!HH", 1, 1)  # Type A, Class IN
        return header + question

    def test_parse_and_build(self):
        """测试 DNS 请求解析与 A 记录应答报文构造"""
        query_pkt = self._build_dns_query_packet("pixiv.net", tx_id=0x5678)
        tx_id, domain, qtype, qclass = parse_dns_query(query_pkt)

        self.assertEqual(tx_id, 0x5678)
        self.assertEqual(domain, "pixiv.net")
        self.assertEqual(qtype, 1)
        self.assertEqual(qclass, 1)

        # 构造响应
        resp_pkt = build_dns_a_response(query_pkt, tx_id, "127.0.0.1", ttl=60)
        self.assertTrue(len(resp_pkt) > len(query_pkt))

        # 验证响应 Header
        resp_id, flags, qd, an, _, _ = struct.unpack("!HHHHHH", resp_pkt[:12])
        self.assertEqual(resp_id, 0x5678)
        self.assertEqual(flags, 0x8180)
        self.assertEqual(an, 1)

    def test_dns_server_routing_and_lifecycle(self):
        """测试 LocalDnsServer 服务端真实 UDP 解析与分流"""
        server = LocalDnsServer(host="127.0.0.1", port=53535)
        ok, msg = server.start()
        self.assertTrue(ok)
        self.assertTrue(server.is_running())

        try:
            # 向测试 DNS 服务器发送 UDP 查询
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(2.0)
                query = self._build_dns_query_packet("www.pixiv.net", tx_id=0xABCD)
                client.sendto(query, ("127.0.0.1", 53535))

                data, _ = client.recvfrom(4096)
                self.assertIsNotNone(data)
                # 提取 Answer 的最后 4 字节 IP
                ip_bytes = data[-4:]
                ip_str = socket.inet_ntoa(ip_bytes)
                self.assertEqual(ip_str, "127.0.0.1")

                # 自定义映射测试
                server.add_custom_mapping("custom.test.local", "192.168.1.100")
                custom_query = self._build_dns_query_packet("custom.test.local", tx_id=0xEF01)
                client.sendto(custom_query, ("127.0.0.1", 53535))
                c_data, _ = client.recvfrom(4096)
                c_ip = socket.inet_ntoa(c_data[-4:])
                self.assertEqual(c_ip, "192.168.1.100")

        finally:
            server.stop()
            self.assertFalse(server.is_running())


if __name__ == "__main__":
    unittest.main()
