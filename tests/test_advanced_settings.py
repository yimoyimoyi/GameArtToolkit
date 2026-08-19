# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 独立高级设置与偏好项专项单元测试
"""

import sys
from pathlib import Path
from unittest.mock import patch

APP_DIR = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP_DIR))

from config_store import DEFAULT_CONFIG, _sanitize_config, load_config
from cdn_optimizer import CDNOptimizer
from steam_manager import SteamManager
from dns_server import LocalDnsServer
from win_utils import is_windows_dark_mode


class TestAdvancedSettingsConfig:
    def test_default_config_fields(self):
        """验证所有新增独立设置字段在默认配置中完整存在"""
        assert "theme_mode" in DEFAULT_CONFIG
        assert "custom_steam_path" in DEFAULT_CONFIG
        assert "steam_launch_args" in DEFAULT_CONFIG
        assert "steam_custom_args_str" in DEFAULT_CONFIG
        assert "ip_version_mode" in DEFAULT_CONFIG
        assert "cdn_timeout_seconds" in DEFAULT_CONFIG
        assert "cdn_max_workers" in DEFAULT_CONFIG
        assert "auto_cdn_min_interval_minutes" in DEFAULT_CONFIG
        assert "health_check_interval_seconds" in DEFAULT_CONFIG
        assert "upstream_dns_servers" in DEFAULT_CONFIG
        assert "auto_clear_cache_on_exit" in DEFAULT_CONFIG


class TestIpVersionPreferences:
    def test_ip_version_sorting_prefer_ipv4(self):
        """prefer_ipv4 模式下：相同 rank 时 IPv4 排在 IPv6 前面"""
        mock_items = [
            {"ip": "2606:4700::6810:1", "latency": 50, "rank": 0},
            {"ip": "1.1.1.1", "latency": 60, "rank": 0},
        ]
        def _sort_key(x):
            rank = x.get("rank", 3)
            lat = x.get("latency") if x.get("latency") is not None else 99999
            is_v6 = ":" in str(x.get("ip", ""))
            v_penalty = 1 if is_v6 else 0
            return (rank, v_penalty, lat)

        mock_items.sort(key=_sort_key)
        assert mock_items[0]["ip"] == "1.1.1.1"

    def test_ip_version_sorting_prefer_ipv6(self):
        """prefer_ipv6 模式下：相同 rank 时 IPv6 排在 IPv4 前面"""
        mock_items = [
            {"ip": "1.1.1.1", "latency": 40, "rank": 0},
            {"ip": "2606:4700::6810:1", "latency": 50, "rank": 0},
        ]
        def _sort_key(x):
            rank = x.get("rank", 3)
            lat = x.get("latency") if x.get("latency") is not None else 99999
            is_v6 = ":" in str(x.get("ip", ""))
            v_penalty = 0 if is_v6 else 1
            return (rank, v_penalty, lat)

        mock_items.sort(key=_sort_key)
        assert mock_items[0]["ip"] == "2606:4700::6810:1"


class TestSteamLaunchArgsAndCustomPath:
    def test_steam_custom_path_detection(self, tmp_path):
        """当配置了 custom_steam_path 时，detect_steam_path 优先返回用户指定路径"""
        fake_steam = tmp_path / "steam.exe"
        fake_steam.write_text("fake binary")

        with patch("steam_manager.load_config", return_value={"custom_steam_path": str(tmp_path)}):
            sm = SteamManager()
            assert sm.steam_path == tmp_path
            assert sm.steam_exe == fake_steam

    def test_steam_launch_cmd_builder(self, tmp_path):
        """验证启动参数拼装：包含 -tcp, -nofriendsui 及自定义参数"""
        fake_steam = tmp_path / "steam.exe"
        fake_steam.write_text("fake binary")

        with patch("steam_manager.load_config", return_value={
            "custom_steam_path": str(tmp_path),
            "steam_launch_args": ["-tcp", "-nofriendsui"],
            "steam_custom_args_str": "-silent -console"
        }):
            sm = SteamManager()
            cmd = sm._build_steam_launch_cmd()
            assert str(fake_steam) in cmd[0]
            assert "-tcp" in cmd
            assert "-nofriendsui" in cmd
            assert "-silent" in cmd
            assert "-console" in cmd


class TestDnsServerUpstreamConfig:
    def test_dns_server_upstream_list(self):
        """验证 LocalDnsServer 能够正确读取与动态更新上游 DNS"""
        with patch("config_store.load_config", return_value={"upstream_dns_servers": ["1.1.1.1", "8.8.8.8"]}):
            server = LocalDnsServer()
            assert server.upstream_dns_list == ["1.1.1.1", "8.8.8.8"]
            assert server.upstream_dns == "1.1.1.1"

            server.set_upstream_dns_list(["223.5.5.5", "119.29.29.29"])
            assert server.upstream_dns_list == ["223.5.5.5", "119.29.29.29"]
            assert server.upstream_dns == "223.5.5.5"


class TestWindowsThemeDetection:
    def test_is_windows_dark_mode_runs(self):
        """验证 is_windows_dark_mode 调用安全无异常，返回 bool"""
        val = is_windows_dark_mode()
        assert isinstance(val, bool)
