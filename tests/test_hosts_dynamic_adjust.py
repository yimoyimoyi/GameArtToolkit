# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 关闭加速自动调整 Hosts 与规则同步专项单元测试
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

os.environ["QT_QPA_PLATFORM"] = "offscreen"

APP_DIR = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP_DIR))

from PySide6.QtWidgets import QApplication
from hosts_manager import HostsManager, BLOCK_START, BLOCK_END
from config_store import _sanitize_config, DEFAULT_CONFIG
from ip_pool import SERVICES_BY_ID, SERVICES_LIST, DEFAULT_ENABLED_SERVICES


def get_qapp():
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)
    return app


class TestHostsDynamicAdjustment:
    def test_sanitize_config_preserves_user_disabled_state(self):
        """验证配置清洗不会将用户主动关闭的服务强制重新开启"""
        # 用户仅启用了 steam_store (关闭了 pixiv, github 等默认项)
        data = {"enabled_services": ["steam_store"]}
        res = _sanitize_config(data)
        assert res["enabled_services"] == ["steam_store"]

        # 用户清空了所有服务
        data_empty = {"enabled_services": []}
        res_empty = _sanitize_config(data_empty)
        assert res_empty["enabled_services"] == []

    def test_hosts_apply_rules_excludes_disabled_service_domains(self, tmp_path):
        """验证 apply_rules 时已关闭的服务域名绝对不会出现在 hosts 文件中"""
        test_hosts = tmp_path / "hosts"
        test_hosts.write_text("127.0.0.1 localhost\r\n", encoding="utf-8")

        hm = HostsManager(hosts_file=test_hosts, backup_dir=tmp_path / "bak")

        # 1. 仅启用 pixiv_web 与 steam_store
        ok, msg = hm.apply_rules(["pixiv_web", "steam_store"])
        assert ok is True
        content = test_hosts.read_text(encoding="utf-8")
        assert "www.pixiv.net" in content
        assert "store.steampowered.com" in content
        assert "github.com" not in content
        assert "huggingface.co" not in content

        # 2. 关闭 pixiv_web (仅保留 steam_store)
        ok, msg = hm.apply_rules(["steam_store"])
        assert ok is True
        content_after = test_hosts.read_text(encoding="utf-8")
        assert "store.steampowered.com" in content_after
        # pixiv 域名必须被完全剥离
        assert "www.pixiv.net" not in content_after
        assert "pixiv.net" not in content_after
        assert "pximg.net" not in content_after

    def test_hosts_apply_empty_rules_clears_all_injections(self, tmp_path):
        """验证当所有服务均被关闭时，hosts 文件被彻底还原为原始文本"""
        test_hosts = tmp_path / "hosts"
        orig_text = "127.0.0.1 localhost\r\n192.168.1.1 router\r\n"
        test_hosts.write_text(orig_text, encoding="utf-8")

        hm = HostsManager(hosts_file=test_hosts, backup_dir=tmp_path / "bak")
        hm.apply_rules(["pixiv_web"])
        assert BLOCK_START in test_hosts.read_text(encoding="utf-8")

        # 应用空列表
        ok, msg = hm.apply_rules([])
        assert ok is True
        final_content = test_hosts.read_text(encoding="utf-8")
        assert BLOCK_START not in final_content
        assert BLOCK_END not in final_content
        assert "localhost" in final_content
        assert "router" in final_content

    def test_ui_toggle_service_auto_adjusts_hosts_when_active(self, tmp_path):
        """验证在加速运行状态下，UI 中切换单项或整组服务开关会即刻调用 apply_rules 同步调整 hosts"""
        get_qapp()
        from pyside_app import MainWindow

        test_hosts = tmp_path / "hosts"
        test_hosts.write_text("127.0.0.1 localhost\r\n", encoding="utf-8")
        test_hm = HostsManager(hosts_file=test_hosts, backup_dir=tmp_path / "bak")

        # 必须隔离配置读写: on_service_toggled 会调用 save_config 写真实 config.json,
        # 不隔离会把用户的 enabled_services 覆写成测试数据 (实测被改成仅剩 steam_store,
        # 且首次运行后又被后续运行读到, 造成时通时断的偶发失败)。
        base_cfg = {"enabled_services": ["pixiv_web", "steam_store"], "auto_proxy": False}

        with patch("pyside_app.load_config", side_effect=lambda: dict(base_cfg)), \
             patch("pyside_app.save_config"), \
             patch("pyside_app.nginx_mgr.is_running", return_value=True), \
             patch("pyside_app.hosts_mgr", test_hm), \
             patch("pyside_app.cert_mgr.is_cert_installed", return_value=True), \
             patch.object(test_hm, "diagnose_and_repair", return_value={"issues": [], "fixes": []}):
            win = MainWindow()

            # 初始注入
            test_hm.apply_rules(["pixiv_web", "steam_store"])
            assert "www.pixiv.net" in test_hosts.read_text(encoding="utf-8")

            # 在 UI 中关闭 pixiv_web
            win.on_service_toggled("pixiv_web", False)
            content = test_hosts.read_text(encoding="utf-8")
            assert "www.pixiv.net" not in content
            assert "store.steampowered.com" in content

            # 在 UI 中重新开启 pixiv_web
            win.on_service_toggled("pixiv_web", True)
            content = test_hosts.read_text(encoding="utf-8")
            assert "www.pixiv.net" in content

    def test_start_acceleration_honors_user_disabled_services(self, tmp_path):
        """验证 start_acceleration 启动加速时严格尊重用户已关闭项，不强制追加默认项"""
        get_qapp()
        from pyside_app import MainWindow

        test_hosts = tmp_path / "hosts"
        test_hosts.write_text("127.0.0.1 localhost\r\n", encoding="utf-8")
        test_hm = HostsManager(hosts_file=test_hosts, backup_dir=tmp_path / "bak")

        # 模拟配置中仅启用了 steam_store (pixiv_web 被用户关闭)
        user_cfg = {"enabled_services": ["steam_store"], "auto_proxy": False}

        # save_config 必须一并隔离: start_acceleration 会把生效的服务列表写回配置,
        # 只 mock 读不 mock 写, 这个 user_cfg 就会被写进用户的真实 config.json
        # (实测把 enabled_services 从 33 项覆写成 ["steam_store"])。
        with patch("pyside_app.load_config", return_value=dict(user_cfg)), \
             patch("pyside_app.save_config"), \
             patch("pyside_app.nginx_mgr.start", return_value=(True, "OK")), \
             patch("pyside_app.nginx_mgr.is_running", return_value=True), \
             patch("pyside_app.hosts_mgr", test_hm), \
             patch("pyside_app.cert_mgr.is_cert_installed", return_value=True), \
             patch.object(test_hm, "diagnose_and_repair", return_value={"issues": [], "fixes": []}), \
             patch("pyside_app.health_monitor.start"):
            win = MainWindow()
            win.start_acceleration(show_toast_on_fail=False)

            content = test_hosts.read_text(encoding="utf-8")
            assert "store.steampowered.com" in content
            # pixiv_web 不得被强制追加
            assert "www.pixiv.net" not in content
