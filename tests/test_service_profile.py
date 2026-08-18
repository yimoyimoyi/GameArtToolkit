# -*- coding: utf-8 -*-
"""
PixivToolkit - Service Profile, Env Detector, L4 Relay & Nginx 架构集成测试集
"""

import sys
import struct
import unittest
from pathlib import Path

# 将 app 目录加入环境变量
APP_DIR = Path(__file__).resolve().parent.parent / "app"
NGINX_DIR = Path(__file__).resolve().parent.parent / "nginx"
sys.path.insert(0, str(APP_DIR))

from service_profile import (
    PROFILES, PROFILES_BY_ID, ServiceMode, get_profile_by_id, get_profile_by_domain
)
from ip_pool import (
    SERVICE_GROUPS, SERVICES_LIST, SERVICES_BY_ID, CANDIDATE_IPS, DEFAULT_ENABLED_SERVICES
)
from env_detector import EnvDetector
from l4_relay import extract_sni_from_client_hello, L4RelayServer
from nginx_manager import NginxManager


class TestServiceProfile(unittest.TestCase):
    """验证 Service Profile 单源配置模型与兼容性"""

    def test_profiles_count(self):
        """验证 21 项服务 Profile 完整性 (包含 google_translate, fandom 与 wikipedia)"""
        self.assertEqual(len(PROFILES), 21)
        self.assertEqual(len(SERVICES_LIST), 21)
        self.assertEqual(len(SERVICES_BY_ID), 21)
        self.assertEqual(len(CANDIDATE_IPS), 21)
        self.assertIn("fandom", SERVICES_BY_ID)
        self.assertIn("wikipedia", SERVICES_BY_ID)
        self.assertIn("google_translate", SERVICES_BY_ID)

    def test_profile_lookup(self):
        """测试服务根据 ID 与域名的动态查找与通配匹配"""
        p_steam = get_profile_by_id("steam_community")
        self.assertIsNotNone(p_steam)
        self.assertEqual(p_steam.ssl_sni_mode, "statuspage.akamaized.net")

        # 域名查找
        p_pixiv = get_profile_by_domain("i.pximg.net")
        self.assertIsNotNone(p_pixiv)
        self.assertEqual(p_pixiv.id, "pixiv_img")
        self.assertTrue(p_pixiv.enable_cache)

        # 泛域名匹配
        p_sub_pixiv = get_profile_by_domain("sketch.pixiv.net")
        self.assertIsNotNone(p_sub_pixiv)
        self.assertEqual(p_sub_pixiv.id, "pixiv_web")

    def test_ip_pool_compatibility(self):
        """验证向后兼容 ip_pool.py 对外暴露的接口数据格式"""
        for s in SERVICES_LIST:
            self.assertIn("id", s)
            self.assertIn("name", s)
            self.assertIn("domains", s)
            self.assertIn("group", s)
            self.assertIn(s["id"], CANDIDATE_IPS)
            self.assertTrue(len(CANDIDATE_IPS[s["id"]]) > 0)


class TestEnvDetector(unittest.TestCase):
    """验证环境与代理冲突检测器"""

    def test_system_proxy_detection(self):
        """测试系统代理读取逻辑 (不崩溃且返回标准字段)"""
        res = EnvDetector.get_system_proxy()
        self.assertIn("enabled", res)
        self.assertIn("server", res)
        self.assertIn("raw_status", res)
        self.assertIsInstance(res["enabled"], bool)

    def test_port_scan(self):
        """测试本地常用代理端口扫描"""
        active_ports = EnvDetector.scan_active_proxy_ports()
        self.assertIsInstance(active_ports, list)

    def test_hosts_conflict_check(self):
        """测试 Hosts 外部冲突检测逻辑"""
        sample_hosts = (
            "127.0.0.1 localhost\n"
            "0.0.0.0 steamcommunity.com\n"
            "# >>>>> PixivToolkit Rules Start >>>>>\n"
            "127.0.0.1 pixiv.net\n"
            "# <<<<< PixivToolkit Rules End <<<<<\n"
            "1.2.3.4 github.com\n"
        )
        conflicts = EnvDetector.check_hosts_conflicts(sample_hosts)
        # steamcommunity.com 和 github.com 在 PTK block 之外，应被精准捕获为冲突
        conflict_domains = [c["domain"] for c in conflicts]
        self.assertIn("steamcommunity.com", conflict_domains)
        self.assertIn("github.com", conflict_domains)
        self.assertNotIn("pixiv.net", conflict_domains)


class TestL4Relay(unittest.TestCase):
    """验证 L4 TCP Relay 与 SNI 嗅探"""

    def _build_mock_client_hello(self, sni: str) -> bytes:
        """构造一个标准的 TLS ClientHello 二进制包 (用于单元测试)"""
        sni_bytes = sni.encode("ascii")
        sni_entry = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
        server_name_ext = struct.pack("!H", len(sni_entry)) + sni_entry
        ext_block = struct.pack("!HH", 0x0000, len(server_name_ext)) + server_name_ext
        ext_total = struct.pack("!H", len(ext_block)) + ext_block

        client_hello_body = (
            b"\x03\x03"  # Client Version TLS 1.2
            + b"\x00" * 32  # Random
            + b"\x00"  # Session ID Length = 0
            + struct.pack("!H", 2) + b"\x00\x9c"  # Cipher Suites (1 suite)
            + b"\x01\x00"  # Compression (1 method)
            + ext_total
        )
        handshake_header = b"\x01" + struct.pack("!I", len(client_hello_body))[1:] + client_hello_body
        record_header = b"\x16\x03\x01" + struct.pack("!H", len(handshake_header))
        return record_header + handshake_header

    def test_sni_extraction(self):
        """测试从 ClientHello 二进制包中提取 SNI 域名"""
        mock_packet = self._build_mock_client_hello("objects.githubusercontent.com")
        extracted = extract_sni_from_client_hello(mock_packet)
        self.assertEqual(extracted, "objects.githubusercontent.com")

        mock_packet_pixiv = self._build_mock_client_hello("i.pximg.net")
        extracted_pixiv = extract_sni_from_client_hello(mock_packet_pixiv)
        self.assertEqual(extracted_pixiv, "i.pximg.net")

        # 异常数据包测试
        self.assertIsNone(extract_sni_from_client_hello(b"GET / HTTP/1.1\r\n\r\n"))
        self.assertIsNone(extract_sni_from_client_hello(b""))

    def test_relay_server_lifecycle(self):
        """测试 L4RelayServer 启动与停止生命周期"""
        server = L4RelayServer(host="127.0.0.1", port=44399)
        ok, msg = server.start()
        self.assertTrue(ok)
        self.assertTrue(server.is_running())

        stop_ok, stop_msg = server.stop()
        self.assertTrue(stop_ok)
        self.assertFalse(server.is_running())


class TestCDNHealthMonitor(unittest.TestCase):
    """验证 CDN 持续健康巡检与自愈机制"""

    def test_health_monitor_lifecycle(self):
        """测试 CDNHealthMonitor 启停与状态"""
        from cdn_optimizer import CDNOptimizer, CDNHealthMonitor
        opt = CDNOptimizer()
        monitor = CDNHealthMonitor(opt, check_interval=60.0)
        self.assertFalse(monitor.is_running())

        monitor.start(["pixiv_web"])
        self.assertTrue(monitor.is_running())

        monitor.stop()
        self.assertFalse(monitor.is_running())


class TestHostsMultiMode(unittest.TestCase):
    """验证 Hosts 多模式 (Direct 与 Proxy) 注入分流"""

    def test_hosts_direct_and_proxy_rules(self):
        """测试 HostsManager 根据 ServiceProfile.mode 正确生成 Direct IP 或 127.0.0.1"""
        from hosts_manager import HostsManager
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8") as tf:
            tf.write("127.0.0.1 localhost\n")
            tmp_hosts_path = Path(tf.name)

        try:
            hm = HostsManager(tmp_hosts_path)
            # 测试应用 pixiv_web (l7_nginx 模式)
            ok, msg = hm.apply_rules(["pixiv_web"])
            self.assertTrue(ok)
            content = tmp_hosts_path.read_text(encoding="utf-8")
            self.assertIn("127.0.0.1 pixiv.net", content)

            # 清理
            hm.remove_rules()
            clean_content = tmp_hosts_path.read_text(encoding="utf-8")
            self.assertNotIn("pixiv.net", clean_content)
        finally:
            tmp_hosts_path.unlink(missing_ok=True)


class TestNginxConfigValidation(unittest.TestCase):
    """验证 Nginx 配置文件语法与 upstream 连通性预检"""

    def test_nginx_syntax(self):
        """执行 nginx -t 语法预检"""
        mgr = NginxManager(NGINX_DIR)
        ok, msg = mgr.test_config()
        self.assertTrue(ok, f"Nginx 配置测试失败: {msg}")


if __name__ == "__main__":
    unittest.main()
