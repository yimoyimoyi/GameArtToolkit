# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 控制页分块收揽与折叠展开专项自动化测试
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

os.environ["QT_QPA_PLATFORM"] = "offscreen"

APP_DIR = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP_DIR))

from PySide6.QtWidgets import QApplication
from config_store import DEFAULT_CONFIG
from svg_icons import SvgIconFactory
from ip_pool import SERVICE_GROUPS, SERVICES_LIST


def get_qapp():
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)
    return app


class TestSvgChevronIcons:
    def test_chevron_icons_available(self):
        """验证 SvgIconFactory 包含新增的 chevron 图标模版且能正确生成图标"""
        get_qapp()
        for name in ["chevron_down", "chevron_up", "chevron_right", "chevron_left"]:
            pix = SvgIconFactory.get_pixmap(name, "#7EB9F5", 18)
            assert not pix.isNull(), f"图标 {name} 生成失败或为空"
            icon = SvgIconFactory.get_icon(name, "#7EB9F5", 18)
            assert not icon.isNull(), f"QIcon {name} 生成失败"


class TestDashboardCollapsible:
    def test_default_config_has_collapsed_sections(self):
        """验证默认配置包含 collapsed_dashboard_sections 字段"""
        assert "collapsed_dashboard_sections" in DEFAULT_CONFIG
        assert isinstance(DEFAULT_CONFIG["collapsed_dashboard_sections"], list)

    def test_dashboard_collapsible_widgets_initialized(self):
        """验证 MainWindow 初始化后正确创建分块收拢控件与分组内容容器"""
        get_qapp()
        from pyside_app import MainWindow

        with patch("pyside_app.nginx_mgr.is_running", return_value=False), \
             patch("pyside_app.hosts_mgr.is_applied", return_value=False), \
             patch("pyside_app.cert_mgr.is_cert_installed", return_value=True):
            win = MainWindow()

            # 验证流量图折叠按钮与容器
            assert hasattr(win, "chart_collapse_btn")
            assert win.chart_collapse_btn is not None
            assert hasattr(win, "traffic_chart")
            assert win.traffic_chart is not None

            for gid in SERVICE_GROUPS:
                assert gid in win.group_cards
                assert gid in win.group_collapse_buttons
                assert gid in win.group_content_widgets

    def test_toggle_section_collapse_traffic_chart(self):
        """验证流量图分块的折叠与展开交互及状态持久化"""
        get_qapp()
        from pyside_app import MainWindow

        with patch("pyside_app.nginx_mgr.is_running", return_value=False), \
             patch("pyside_app.hosts_mgr.is_applied", return_value=False), \
             patch("pyside_app.cert_mgr.is_cert_installed", return_value=True):
            win = MainWindow()
            win.show()
            win.collapsed_sections.clear()

            # 初始状态为展开
            assert not win.traffic_chart.isHidden()

            # 折叠流量图
            win.toggle_section_collapse("traffic_chart")
            assert "traffic_chart" in win.collapsed_sections
            assert win.traffic_chart.isHidden()
            assert win.chart_collapse_btn.text() == "展开"

            # 再次展开流量图
            win.toggle_section_collapse("traffic_chart")
            assert "traffic_chart" not in win.collapsed_sections
            assert not win.traffic_chart.isHidden()
            assert win.chart_collapse_btn.text() == "收起"

    def test_toggle_section_collapse_service_groups(self):
        """验证生态分组卡片的折叠与展开交互"""
        get_qapp()
        from pyside_app import MainWindow

        with patch("pyside_app.nginx_mgr.is_running", return_value=False), \
             patch("pyside_app.hosts_mgr.is_applied", return_value=False), \
             patch("pyside_app.cert_mgr.is_cert_installed", return_value=True):
            win = MainWindow()
            win.show()
            win.collapsed_sections.clear()

            for gid in SERVICE_GROUPS:
                # 初始展开
                assert not win.group_content_widgets[gid].isHidden()
                assert win.group_collapse_buttons[gid].text() == "收起"

                # 折叠
                win.toggle_section_collapse(gid)
                assert gid in win.collapsed_sections
                assert win.group_content_widgets[gid].isHidden()
                assert win.group_collapse_buttons[gid].text() == "展开"

                # 展开
                win.toggle_section_collapse(gid)
                assert gid not in win.collapsed_sections
                assert not win.group_content_widgets[gid].isHidden()
                assert win.group_collapse_buttons[gid].text() == "收起"

    def test_toggle_all_sections_collapse(self):
        """验证一键全部折叠与全部展开功能"""
        get_qapp()
        from pyside_app import MainWindow

        with patch("pyside_app.nginx_mgr.is_running", return_value=False), \
             patch("pyside_app.hosts_mgr.is_applied", return_value=False), \
             patch("pyside_app.cert_mgr.is_cert_installed", return_value=True):
            win = MainWindow()
            win.show()
            win.collapsed_sections.clear()

            # 执行一键全部折叠
            win.toggle_all_sections_collapse()
            all_ids = set(SERVICE_GROUPS.keys()) | {"traffic_chart"}
            assert win.collapsed_sections == all_ids
            assert win.traffic_chart.isHidden()
            for gid in SERVICE_GROUPS:
                assert win.group_content_widgets[gid].isHidden()
            assert win.btn_toggle_all_collapse.text() == "全部展开"

            # 再次点击 -> 全部展开
            win.toggle_all_sections_collapse()
            assert len(win.collapsed_sections) == 0
            assert not win.traffic_chart.isHidden()
            for gid in SERVICE_GROUPS:
                assert not win.group_content_widgets[gid].isHidden()
            assert win.btn_toggle_all_collapse.text() == "全部折叠"

    def test_search_auto_expand_collapsed_group(self):
        """验证即时搜索时若匹配项位于已折叠分组，自动临时展开该组并在清空搜索时恢复用户折叠偏好"""
        get_qapp()
        from pyside_app import MainWindow

        with patch("pyside_app.nginx_mgr.is_running", return_value=False), \
             patch("pyside_app.hosts_mgr.is_applied", return_value=False), \
             patch("pyside_app.cert_mgr.is_cert_installed", return_value=True):
            win = MainWindow()
            win.show()
            # 用户折叠 gaming 分组
            win.collapsed_sections = {"gaming"}
            win._update_section_collapse_ui("gaming", True)
            assert win.group_content_widgets["gaming"].isHidden()

            # 用户搜索 "steam" (属于 gaming 组)
            win.on_service_search_changed("steam")
            assert not win.group_cards["gaming"].isHidden()
            # 自动临时展开
            assert not win.group_content_widgets["gaming"].isHidden()

            # 清空搜索框 -> 恢复原有的折叠偏好
            win.on_service_search_changed("")
            assert win.group_content_widgets["gaming"].isHidden()
