# -*- coding: utf-8 -*-
"""
GameArt Toolkit - CDN 测速页面默认显示上次与全量目标支持专项自动化测试
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

os.environ["QT_QPA_PLATFORM"] = "offscreen"

APP_DIR = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP_DIR))

from PySide6.QtWidgets import QApplication
from config_store import DEFAULT_CONFIG, load_config
from ip_pool import SERVICES_LIST, SERVICES_BY_ID, CANDIDATE_IPS


def get_qapp():
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)
    return app


class TestCDNSpeedTestPage:
    def test_default_config_has_cached_cdn_full_results(self):
        """验证默认配置包含 cached_cdn_full_results 字典"""
        assert "cached_cdn_full_results" in DEFAULT_CONFIG
        assert isinstance(DEFAULT_CONFIG["cached_cdn_full_results"], dict)

    def test_cdn_page_renders_all_targets_immediately(self):
        """验证进入 CDN 测速页时，无需用户手动点击即可默认呈现全部测速目标"""
        get_qapp()
        from pyside_app import MainWindow

        with patch("pyside_app.nginx_mgr.is_running", return_value=False), \
             patch("pyside_app.hosts_mgr.is_applied", return_value=False), \
             patch("pyside_app.cert_mgr.is_cert_installed", return_value=True):
            win = MainWindow()

            # 验证所有服务均已生成测速卡片与独立测速按钮
            for srv in SERVICES_LIST:
                sid = srv["id"]
                assert sid in win.cdn_card_widgets, f"服务 {sid} 未在 CDN 测速页渲染卡片"
                assert sid in win.cdn_single_buttons, f"服务 {sid} 缺少独立测速按钮"

    def test_cdn_page_renders_previous_cached_results(self):
        """验证测速页能正确加载并回显上次测速的具体延迟数据与最优节点星标"""
        get_qapp()
        from pyside_app import MainWindow

        mock_cached_results = {
            "pixiv_web": [
                {"ip": "210.140.131.226", "latency": 45, "available": True, "rank": 1},
                {"ip": "210.140.131.227", "latency": 120, "available": True, "rank": 2},
            ],
            "steam_store": [
                {"ip": "104.101.218.73", "latency": 32, "available": True, "rank": 1},
            ]
        }

        with patch("pyside_app.nginx_mgr.is_running", return_value=False), \
             patch("pyside_app.hosts_mgr.is_applied", return_value=False), \
             patch("pyside_app.cert_mgr.is_cert_installed", return_value=True):
            win = MainWindow()
            win.render_cdn_results(mock_cached_results)

            assert win.cached_cdn_results is not None
            assert win.btn_apply_cdn.isEnabled() is True

    def test_single_cdn_ping_callback_updates_and_persists(self):
        """验证单服务独立测速完成后局部刷新并持久化保存数据"""
        get_qapp()
        from pyside_app import MainWindow

        with patch("pyside_app.nginx_mgr.is_running", return_value=False), \
             patch("pyside_app.hosts_mgr.is_applied", return_value=False), \
             patch("pyside_app.cert_mgr.is_cert_installed", return_value=True), \
             patch("pyside_app.cdn_opt.apply_single_optimal", return_value=(True, "OK")):
            win = MainWindow()

            test_results = [
                {"ip": "210.140.131.226", "latency": 58, "available": True, "rank": 1}
            ]

            win.on_single_cdn_ping_finished("pixiv_web", test_results)
            assert win.cached_cdn_results["pixiv_web"] == test_results
            assert "pixiv_web" in win.cdn_card_widgets

    def test_on_cdn_ping_finished_updates_all_and_persists(self):
        """验证全量测速完成后更新全部目标并启用应用按钮"""
        get_qapp()
        from pyside_app import MainWindow

        with patch("pyside_app.nginx_mgr.is_running", return_value=False), \
             patch("pyside_app.hosts_mgr.is_applied", return_value=False), \
             patch("pyside_app.cert_mgr.is_cert_installed", return_value=True):
            win = MainWindow()

            full_mock = {
                srv["id"]: [{"ip": CANDIDATE_IPS.get(srv["id"], ["127.0.0.1"])[0], "latency": 40, "available": True, "rank": 1}]
                for srv in SERVICES_LIST
            }

            win.on_cdn_ping_finished(full_mock)
            assert win.cached_cdn_results == full_mock
            assert win.btn_apply_cdn.isEnabled() is True
            assert win.btn_start_ping.isEnabled() is True
