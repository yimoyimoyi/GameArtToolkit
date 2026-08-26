# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 端口操作、快捷导航与以图搜图自动化测试套件
"""

import os
import sys
import time
import socket
from pathlib import Path

# 注入 app 目录到 sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = BASE_DIR / "app"
sys.path.insert(0, str(APP_DIR))

import unittest
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QImage

from win_utils import (
    get_port_process_info, get_critical_ports_status, kill_process_by_pid_safe, is_port_in_use
)
from service_profile import NAVIGATOR_SERVICES, SERVICE_GROUPS
from reverse_search import (
    SEARCH_ENGINES, save_image_to_temp, ImageSearchWorker
)
from svg_icons import SvgIconFactory


class TestPortOperations(unittest.TestCase):
    """测试端口查询与进程操作底层函数"""

    def test_critical_ports_structure(self):
        statuses = get_critical_ports_status([80, 443, 53])
        self.assertEqual(len(statuses), 3)
        ports = [s["port"] for s in statuses]
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(53, ports)
        for s in statuses:
            self.assertIn("in_use", s)
            self.assertIn("processes", s)
            self.assertIsInstance(s["processes"], list)

    def test_custom_port_query_with_dummy_socket(self):
        # 绑定一个随机测试本地端口
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        test_port = s.getsockname()[1]

        try:
            procs = get_port_process_info(test_port)
            self.assertTrue(len(procs) >= 1)
            p = procs[0]
            self.assertEqual(p["port"], test_port)
            self.assertGreater(p["pid"], 0)
            self.assertEqual(p["pid"], os.getpid())
            self.assertIn("proto", p)
        finally:
            s.close()

    def test_kill_process_safety_checks(self):
        # 自身 PID 禁止杀死
        ok, msg = kill_process_by_pid_safe(os.getpid())
        self.assertFalse(ok)
        self.assertIn("当前客户端", msg)

        # 非法 PID 处理
        ok, msg = kill_process_by_pid_safe(-1)
        self.assertFalse(ok)
        self.assertIn("无效", msg)


class TestNavigatorAndSearch(unittest.TestCase):
    """测试导航列表数据与以图搜图模块"""

    def test_navigator_services_integrity(self):
        self.assertTrue(len(NAVIGATOR_SERVICES) >= 10)
        for item in NAVIGATOR_SERVICES:
            self.assertIn("id", item)
            self.assertIn("group", item)
            self.assertIn("name", item)
            self.assertIn("url", item)
            self.assertIn("domain", item)
            self.assertTrue(item["url"].startswith("http"))
            self.assertIn(item["group"], SERVICE_GROUPS)

    def test_search_engines_definitions(self):
        self.assertIn("saucenao", SEARCH_ENGINES)
        self.assertIn("ascii2d", SEARCH_ENGINES)
        self.assertIn("google", SEARCH_ENGINES)
        self.assertIn("iqdb", SEARCH_ENGINES)

    def test_save_image_to_temp(self):
        # 创建一个 100x100 纯白 QImage
        img = QImage(100, 100, QImage.Format_RGB32)
        img.fill(0xFFFFFF)
        temp_path = save_image_to_temp(img)
        self.assertTrue(os.path.exists(temp_path))
        self.assertTrue(temp_path.endswith(".jpg"))
        # 清理
        try:
            os.remove(temp_path)
        except Exception:
            pass

    def test_search_bridge_and_results_generation(self):
        from reverse_search import (
            _image_to_base64, build_auto_submit_bridge_html, generate_saucenao_results_html
        )
        img = QImage(50, 50, QImage.Format_RGB32)
        img.fill(0xFF0000)
        temp_path = save_image_to_temp(img)
        try:
            # 1. 验证 base64 生成
            b64_str = _image_to_base64(temp_path)
            self.assertTrue(b64_str.startswith("data:image/"))

            # 2. 验证各个引擎的表单桥梁 HTML 生成
            for eid in ["saucenao", "ascii2d", "iqdb", "google"]:
                bridge_file = build_auto_submit_bridge_html(eid, temp_path)
                self.assertTrue(os.path.exists(bridge_file))
                with open(bridge_file, "r", encoding="utf-8") as f:
                    content = f.read()
                self.assertIn("data:image/", content)
                self.assertIn(SEARCH_ENGINES[eid]["upload_url"], content)
                os.remove(bridge_file)

            # 3. 验证 SauceNAO JSON 结果渲染为本地 HTML
            mock_json = {
                "results": [
                    {
                        "header": {"similarity": "96.5", "thumbnail": "https://example.com/thumb.jpg"},
                        "data": {
                            "title": "测试作品",
                            "member_name": "测试画师",
                            "pixiv_id": 12345678,
                            "member_id": 87654321,
                            "ext_urls": ["https://www.pixiv.net/artworks/12345678"]
                        }
                    }
                ]
            }
            res_file = generate_saucenao_results_html(temp_path, mock_json)
            self.assertTrue(os.path.exists(res_file))
            with open(res_file, "r", encoding="utf-8") as f:
                res_content = f.read()
            self.assertIn("96.5%", res_content)
            self.assertIn("12345678", res_content)
            self.assertIn("测试作品", res_content)
            self.assertIn("测试画师", res_content)
            os.remove(res_file)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_svg_icons_factory_expansion(self):
        icons_to_test = ["compass", "external_link", "search", "trash", "upload", "copy", "network", "grid", "arrow_left"]
        for icon_name in icons_to_test:
            pixmap = SvgIconFactory.get_pixmap(icon_name, "#7EB9F5", 18)
            self.assertFalse(pixmap.isNull(), f"Icon {icon_name} should not be null")


class TestMainWindowIntegration(unittest.TestCase):
    """测试主窗口对新建页面的挂载与渲染"""

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_main_window_pages_and_nav(self):
        from pyside_app import MainWindow
        win = MainWindow()
        try:
            # 应该包含 5 个主页面
            self.assertEqual(win.stack.count(), 5)
            # 侧边栏按钮应该包含 5 个
            self.assertEqual(len(win.nav_group.buttons()), 5)
            # 验证各页面属性存在
            self.assertIsNotNone(win.page_dashboard)
            self.assertIsNotNone(win.page_toolbox)
            self.assertIsNotNone(win.page_steam)
            self.assertIsNotNone(win.page_cdn)
            self.assertIsNotNone(win.page_settings)

            # 验证工具箱子页面栈 (共 4 个视图: 大厅、以图搜图、端口管理、生态导航)
            self.assertIsNotNone(win.toolbox_stack)
            self.assertEqual(win.toolbox_stack.count(), 4)

            # 验证以图搜图组件与主站卡片数量
            self.assertIsNotNone(win.drop_image_widget)
            self.assertTrue(len(win.nav_card_widgets) >= len(NAVIGATOR_SERVICES))

            # 验证端口体检组件
            self.assertIn(80, win.critical_port_labels)
            self.assertIn(443, win.critical_port_labels)
            self.assertIn(53, win.critical_port_labels)

            # 1. 模拟切换到实用工具箱 (index 1)
            win.on_nav_clicked(1)
            self.assertEqual(win.stack.currentIndex(), 1)
            # 默认停留在工具箱大厅 (index 0)
            self.assertEqual(win.toolbox_stack.currentIndex(), 0)

            # 2. 模拟进入子页面 1: 以图搜图
            win.toolbox_stack.setCurrentIndex(1)
            self.assertEqual(win.toolbox_stack.currentIndex(), 1)

            # 3. 模拟进入子页面 2: 端口管理
            win.toolbox_stack.setCurrentIndex(2)
            self.assertEqual(win.toolbox_stack.currentIndex(), 2)

            # 4. 模拟进入子页面 3: 官方主站导航
            win.toolbox_stack.setCurrentIndex(3)
            self.assertEqual(win.toolbox_stack.currentIndex(), 3)

            # 模拟搜索过滤
            win._filter_navigator_cards("steam")
            visible_count = sum(1 for card, _ in win.nav_card_widgets if not card.isHidden())
            self.assertTrue(visible_count >= 2)

            # 还原搜索
            win._filter_navigator_cards("")
            all_visible_count = sum(1 for card, _ in win.nav_card_widgets if not card.isHidden())
            self.assertEqual(all_visible_count, len(win.nav_card_widgets))

            # 返回大厅
            win.toolbox_stack.setCurrentIndex(0)
            self.assertEqual(win.toolbox_stack.currentIndex(), 0)
        finally:
            win.close()


if __name__ == "__main__":
    unittest.main()

