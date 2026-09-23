# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 校园网网关防劫持与启动延迟测速编排自动化测试集
"""

import sys
import unittest
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "app"
NGINX_DIR = Path(__file__).resolve().parent.parent / "nginx"
sys.path.insert(0, str(APP_DIR))

from config_store import DEFAULT_CONFIG, load_config
from cdn_optimizer import is_valid_public_cdn_ip, is_internet_available
from nginx_generator import NginxConfGenerator
from nginx_manager import NginxManager


class TestGatewayAntiHijack(unittest.TestCase):
    """测试校园网/深澜 srun 网关防劫持与启动编排逻辑"""

    def test_blocked_ip_networks(self):
        """测试非标私网 (172.100.x.x 等) 与常规内网过滤，同时确保合规 CDN 不被误杀"""
        # 1. 必须被拦截的网关与内网 IP
        blocked_ips = [
            "172.100.20.2",   # 用户报告的深澜校园网网关
            "172.100.1.1",    # 172.100.0.0/16 网段
            "172.200.5.10",   # 172.200.0.0/16 网段
            "198.18.0.1",     # Clash Fake-IP
            "127.0.0.1",      # 本地回环
            "10.0.0.1",       # RFC 1918 私网
            "172.16.0.1",     # RFC 1918 私网
            "172.31.255.254", # RFC 1918 私网
            "192.168.1.1",    # RFC 1918 私网
            "100.64.0.1",     # CGNAT 运营商私网
        ]
        for ip in blocked_ips:
            self.assertFalse(is_valid_public_cdn_ip(ip), f"IP 应被拦截但放行了: {ip}")

        # 2. 必须正常放行的公网真实 CDN IP (包含 Cloudflare 172.64.0.0/13 段)
        valid_ips = [
            "23.1.179.144",   # Akamai
            "104.91.87.202",  # Akamai
            "172.67.182.201", # Cloudflare 官方网段 (严禁被 172.x 误杀)
            "104.16.132.229", # Cloudflare
            "119.29.29.29",   # 腾讯公共 DNS
        ]
        for ip in valid_ips:
            self.assertTrue(is_valid_public_cdn_ip(ip), f"真实公网 CDN IP 被误杀了: {ip}")

    def test_config_store_defaults(self):
        """测试新配置项存在且默认值正确"""
        self.assertIn("auto_cdn_wait_network_ready", DEFAULT_CONFIG)
        self.assertTrue(DEFAULT_CONFIG["auto_cdn_wait_network_ready"])

        self.assertIn("auto_cdn_network_stable_delay_seconds", DEFAULT_CONFIG)
        self.assertEqual(DEFAULT_CONFIG["auto_cdn_network_stable_delay_seconds"], 60)

        self.assertIn("auto_proxy_after_cdn", DEFAULT_CONFIG)
        self.assertTrue(DEFAULT_CONFIG["auto_proxy_after_cdn"])

        self.assertIn("network_probe_target", DEFAULT_CONFIG)
        self.assertEqual(DEFAULT_CONFIG["network_probe_target"], "www.baidu.com")

    def test_internet_available_probe(self):
        """测试外网连通性探测接口返回 bool 值且不抛异常"""
        res = is_internet_available(target="www.baidu.com", timeout=1.0)
        self.assertIsInstance(res, bool)

    def test_nginx_anti_hijack_rule_generation(self):
        """测试生成的 Nginx site-gaming.conf 包含防网关劫持重定向规则并通过 nginx -t 语法验证"""
        conf_dir = NGINX_DIR / "conf"
        results = NginxConfGenerator.generate_all(conf_dir)

        self.assertIn("site-gaming.conf", results)
        gaming_conf = results["site-gaming.conf"]

        # 必须包含针对 172/srun/portal 的 proxy_redirect 拦截改写
        self.assertIn("proxy_redirect ~*^https?://(?:172\\.|192\\.168\\.|10\\.|.*srun.*|.*portal.*)(.*)$ /;", gaming_conf)

        # 语法验证
        mgr = NginxManager(NGINX_DIR)
        ok, msg = mgr.test_config()
        self.assertTrue(ok, f"Nginx 语法验证失败: {msg}")

    def test_startup_worker_stop_responsive(self):
        """测试 StartupAutoCDNWorker 在等待阶段能够迅速响应 stop 请求"""
        from PySide6.QtCore import QCoreApplication
        app = QCoreApplication.instance() or QCoreApplication([])

        from pyside_app import StartupAutoCDNWorker
        worker = StartupAutoCDNWorker(
            wait_network=True,
            stable_delay_sec=10,
            skip_cdn_test=True
        )
        worker.start()
        # 稍等片刻后发出 stop 请求
        import time
        time.sleep(0.2)
        worker.request_stop()
        worker.wait(2000)
        self.assertFalse(worker.isRunning(), "Worker 应当在收到 request_stop 后 2 秒内停止")


if __name__ == "__main__":
    unittest.main()
