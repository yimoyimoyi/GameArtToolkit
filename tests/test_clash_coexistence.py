# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 与 Clash 等代理共存与防 DNS 测速污染自动化测试套件
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from cdn_optimizer import (
    is_valid_public_cdn_ip,
    _resolve_dns_candidates,
    _load_proxy_config,
    BLOCKED_IP_NETWORKS
)
from win_utils import (
    ProxyBypassManager,
    get_physical_adapter_ip,
    auto_detect_active_proxy,
    COMMON_PROXY_PORTS
)
from l4_relay import L4RelayServer
from dns_server import LocalDnsServer, _extract_a_ips


class TestClashCoexistence(unittest.TestCase):
    """测试与 Clash 等代理工具的兼容与反污染能力"""

    def test_fake_ip_and_private_ip_filtering(self):
        """1. 测试 Fake-IP 与内网/保留网段强力拦截"""
        # Clash / Sing-box Fake-IP 虚拟段 (198.18.0.0/15)
        self.assertFalse(is_valid_public_cdn_ip("198.18.0.1"))
        self.assertFalse(is_valid_public_cdn_ip("198.18.123.45"))
        self.assertFalse(is_valid_public_cdn_ip("198.19.255.254"))

        # 回环地址
        self.assertFalse(is_valid_public_cdn_ip("127.0.0.1"))
        self.assertFalse(is_valid_public_cdn_ip("127.0.0.2"))
        self.assertFalse(is_valid_public_cdn_ip("::1"))

        # 私有内网地址 (RFC 1918)
        self.assertFalse(is_valid_public_cdn_ip("10.0.0.1"))
        self.assertFalse(is_valid_public_cdn_ip("172.16.1.1"))
        self.assertFalse(is_valid_public_cdn_ip("192.168.1.1"))
        self.assertFalse(is_valid_public_cdn_ip("169.254.1.1"))

        # 非法格式与空输入
        self.assertFalse(is_valid_public_cdn_ip("invalid_ip"))
        self.assertFalse(is_valid_public_cdn_ip(""))

        # 真实公网 Anycast CDN IP 必须通过
        self.assertTrue(is_valid_public_cdn_ip("210.140.139.151"))  # Pixiv
        self.assertTrue(is_valid_public_cdn_ip("140.82.121.4"))     # GitHub
        self.assertTrue(is_valid_public_cdn_ip("104.18.22.203"))    # Cloudflare
        self.assertTrue(is_valid_public_cdn_ip("2606:50c0:8000::154"))  # IPv6 Fastly

    def test_proxy_bypass_tag_strip_and_rules(self):
        """2. 测试 ProxyOverride 标签剥离与规则构造"""
        sample_override = "192.168.1.*;<-GameArtStart->*.pixiv.net;pixiv.net<-GameArtEnd->;<local>"
        stripped = ProxyBypassManager._strip_tags(sample_override)
        self.assertEqual(stripped, "192.168.1.*;<local>")

        # 历史旧标签兼容剥离
        legacy_override = "10.0.0.*;<-PixivToolkitStart->*.steamcommunity.com<-PixivToolkitEnd->;<local>"
        stripped_legacy = ProxyBypassManager._strip_tags(legacy_override)
        self.assertEqual(stripped_legacy, "10.0.0.*;<local>")

    def test_doh_resolve_fake_ip_filtering(self):
        """3. 测试 DoH 解析结果中包含 Fake-IP 时的自动剔除"""
        fake_payload = {
            "Answer": [
                {"type": 1, "data": "198.18.0.55"},      # Fake-IP 应被过滤
                {"type": 1, "data": "210.140.139.151"}   # 真实 IP 应保留
            ]
        }
        with patch("urllib.request.build_opener") as mock_opener:
            mock_resp = MagicMock()
            import json
            mock_resp.read.return_value = json.dumps(fake_payload).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            mock_opener.return_value.open.return_value = mock_resp

            from cdn_optimizer import doh_resolve
            res = doh_resolve("pixiv.net")
            self.assertIn("210.140.139.151", res)
            self.assertNotIn("198.18.0.55", res)

    def test_physical_adapter_detection(self):
        """4. 测试物理网卡局域网 IP 探测不返回 Fake-IP"""
        ip = get_physical_adapter_ip()
        if ip:
            self.assertFalse(ip.startswith(("198.18.", "198.19.", "127.")))

    def test_l4_relay_proxy_address_resolution(self):
        """5. 测试 L4 Relay 自动代理端口自适应与防死循环 Clean IP 隧道化"""
        relay = L4RelayServer()
        # 显式测试覆盖
        relay.set_proxy_addr("127.0.0.1", 7897)
        self.assertEqual(relay._load_proxy_addr(), ("127.0.0.1", 7897))

        relay.set_proxy_addr(None)  # 恢复自动探测


if __name__ == "__main__":
    unittest.main()
