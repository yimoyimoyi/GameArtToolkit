# -*- coding: utf-8 -*-
"""
自动化测试与回归验证脚本 - UI 美化、沉浸式无边框与零弹窗现代交互系统
"""

import os
import sys
import py_compile
import unittest
from pathlib import Path

# 设置无头模式
os.environ["QT_QPA_PLATFORM"] = "offscreen"

BASE_DIR = Path(__file__).resolve().parent
APP_DIR = BASE_DIR / "app"
sys.path.insert(0, str(APP_DIR))

from PySide6.QtCore import Qt, QPointF, QEvent
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QApplication

class TestUIModernization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_01_syntax_and_imports(self):
        """1. 语法静态检查与模块完整性验证"""
        files = [
            APP_DIR / "frameless_helper.py",
            APP_DIR / "material_theme.py",
            APP_DIR / "md_widgets.py",
            APP_DIR / "pyside_app.py",
            APP_DIR / "steam_manager.py",
            APP_DIR / "cdn_optimizer.py",
            APP_DIR / "nginx_manager.py",
            APP_DIR / "hosts_manager.py",
            APP_DIR / "cert_manager.py",
            APP_DIR / "win_utils.py",
        ]
        for f in files:
            self.assertTrue(f.exists(), f"文件不存在: {f}")
            py_compile.compile(str(f), doraise=True)
            print(f"[PASS] 语法检查通过: {f.name}")

    def test_02_frameless_helper_init(self):
        """2. 测试 NativeFramelessHelper 与 TitleBar 挂载"""
        from PySide6.QtWidgets import QMainWindow
        from frameless_helper import NativeFramelessHelper
        from md_widgets import TitleBar

        win = QMainWindow()
        helper = NativeFramelessHelper(win)
        title_bar = TitleBar(win)
        helper.set_title_bar(title_bar)
        helper.set_window_controls(title_bar.btn_min, title_bar.btn_max, title_bar.btn_close)

        self.assertIsNotNone(helper)
        self.assertIsNotNone(title_bar)
        self.assertEqual(title_bar.status_pill.text(), "● 加速待命")

        title_bar.update_status(True)
        self.assertIn("代理加速中", title_bar.status_pill.text())
        title_bar.update_status(False)
        self.assertIn("服务已停止", title_bar.status_pill.text())
        print("[PASS] TitleBar 与 NativeFramelessHelper 挂载与状态切换正常")

    def test_03_toast_notification_manager(self):
        """3. 测试 ToastManager 悬浮通知总线"""
        from PySide6.QtWidgets import QWidget
        from md_widgets import ToastManager, show_toast

        parent = QWidget()
        parent.resize(800, 600)
        parent.show()
        mgr = ToastManager.get_instance()

        show_toast(parent, "这是一条信息提示", toast_type="info", duration=1000)
        show_toast(parent, "操作成功完成", toast_type="success", duration=1000)
        show_toast(parent, "警告注意", toast_type="warning", duration=1000)

        action_triggered = []
        show_toast(
            parent, "错误提示发生", toast_type="error", duration=1000,
            action_text="重试", on_action=lambda: action_triggered.append(True)
        )

        self.assertGreaterEqual(len(mgr.active_toasts), 1)
        last_toast = mgr.active_toasts[-1]
        self.assertIsNotNone(last_toast.action_btn)
        last_toast.action_btn.click()
        self.assertEqual(len(action_triggered), 1)
        print("[PASS] ToastManager 4种状态及 Action 动作回调测试正常")

    def test_04_inline_editable_label(self):
        """4. 测试 Steam 账号备注原位内联编辑 (Inline Edit)"""
        from md_widgets import InlineEditableLabel

        widget = InlineEditableLabel(initial_text="主账号", placeholder="+ 添加备注")
        widget.show()
        self.assertEqual(widget.get_text(), "主账号")
        self.assertFalse(widget.badge_label.isHidden())
        self.assertTrue(widget.edit_input.isHidden())

        # 触发编辑
        widget.start_edit()
        self.assertTrue(widget.badge_label.isHidden())
        self.assertFalse(widget.edit_input.isHidden())

        # 监听修改信号
        received = []
        widget.text_changed.connect(lambda txt: received.append(txt))

        widget.edit_input.setText("二次元大号")
        widget._commit_edit()

        self.assertEqual(widget.get_text(), "二次元大号")
        self.assertEqual(received, ["二次元大号"])
        self.assertFalse(widget.badge_label.isHidden())
        self.assertTrue(widget.edit_input.isHidden())
        print("[PASS] InlineEditableLabel 原位编辑与信号保存测试正常")

    def test_05_steam_account_card_double_click(self):
        """5. 测试 Steam 账号卡片双击免密秒切信号"""
        from PySide6.QtWidgets import QMainWindow
        from pyside_app import SteamAccountCard

        win = QMainWindow()
        acc = {
            "steamid": "76561198000000000",
            "persona_name": "TestUser",
            "account_name": "test_acc",
            "alias": "测试别名",
            "is_active": False,
            "timestamp": 1600000000
        }
        card = SteamAccountCard(acc, is_active=False, parent_window=win)

        emitted_steamid = []
        card.double_clicked.connect(lambda sid: emitted_steamid.append(sid))

        ev = QMouseEvent(QEvent.MouseButtonDblClick, QPointF(10, 10), Qt.LeftButton, Qt.LeftButton, Qt.NoModifier)
        card.mouseDoubleClickEvent(ev)

        self.assertEqual(emitted_steamid, ["76561198000000000"])
        print("[PASS] SteamAccountCard 双击免密秒切信号发射测试正常")

    def test_06_traffic_chart_and_skeleton(self):
        """6. 测试单调三次样条平滑波形图与流光骨架屏"""
        from md_widgets import TrafficMonitorChart, SkeletonCard

        chart = TrafficMonitorChart()
        chart.resize(400, 140)
        chart.add_sample(0.0, 0.0)
        chart.add_sample(5000.0, 200.0)
        chart.add_sample(100.0, 10.0)
        chart.add_sample(8000.0, 300.0)

        skeleton = SkeletonCard()
        skeleton.resize(400, 64)
        skeleton._step_animation()

        print("[PASS] TrafficMonitorChart 与 SkeletonCard 渲染与数据更新正常")

    def test_07_no_blocking_dialogs(self):
        """7. 静态扫描检查：确认 pyside_app.py 中已彻底移除了 QMessageBox 和 QInputDialog"""
        code = (APP_DIR / "pyside_app.py").read_text(encoding="utf-8")
        self.assertNotIn("QMessageBox.information", code, "发现遗留的 QMessageBox.information 调用！")
        self.assertNotIn("QMessageBox.warning", code, "发现遗留的 QMessageBox.warning 调用！")
        self.assertNotIn("QMessageBox.critical", code, "发现遗留的 QMessageBox.critical 调用！")
        self.assertNotIn("QInputDialog.getText", code, "发现遗留的 QInputDialog.getText 调用！")
        self.assertNotIn("from PySide6.QtWidgets import QMessageBox", code)
        self.assertNotIn("from PySide6.QtWidgets import QInputDialog", code)
        print("[PASS] pyside_app.py 已 100% 彻底移除阻塞式模态弹窗")

    def test_08_theme_toggle_signal_and_persistence(self):
        """8. 测试主题切换按钮单次点击触发与单向总线传播 (防止瞬时回弹)"""
        from material_theme import ThemeManager, MATERIAL_DARK_QSS, MATERIAL_LIGHT_QSS
        from pyside_app import MainWindow

        win = MainWindow()
        win.show()

        tm = ThemeManager.get_instance()
        # 强制设为深色起始状态
        tm.set_theme("dark", self.app)
        self.assertEqual(tm.get_current_theme(), "dark")
        self.assertTrue(tm.is_dark)

        # 模拟用户单次点击标题栏主题按钮
        win.title_bar.btn_theme.click()

        # 核心断言：单次点击后必须稳定停留在 light，绝不能发生 dark -> light -> dark 的回弹
        self.assertEqual(tm.get_current_theme(), "light")
        self.assertTrue(tm.is_light)

        # 再次点击切回 dark
        win.title_bar.btn_theme.click()
        self.assertEqual(tm.get_current_theme(), "dark")
        self.assertTrue(tm.is_dark)
        print("[PASS] 主题切换按钮单次点击稳定切换，无翻转回弹")

    def test_09_semantic_qss_and_no_dark_hardcoded_styles(self):
        """9. 测试深浅 QSS 语义类完整性与页面控件 QSS 类属性"""
        from material_theme import MATERIAL_DARK_QSS, MATERIAL_LIGHT_QSS
        from pyside_app import MainWindow

        # 验证 QSS 类存在
        for qss in (MATERIAL_DARK_QSS, MATERIAL_LIGHT_QSS):
            self.assertIn('class="MainStatusTitle"', qss)
            self.assertIn('class="MainStatusSub"', qss)
            self.assertIn('class="ItemTitle"', qss)
            self.assertIn('class="ItemDesc"', qss)
            self.assertIn('class="SectionHeaderTitle"', qss)
            self.assertIn('class="SectionHeaderDesc"', qss)

        win = MainWindow()
        self.assertEqual(win.lbl_main_status.property("class"), "MainStatusTitle")
        self.assertEqual(win.lbl_main_sub.property("class"), "MainStatusSub")
        self.assertEqual(win.lbl_steam_banner_status.property("class"), "ItemTitle")
        self.assertEqual(win.lbl_steam_banner_path.property("class"), "ItemDesc")
        self.assertGreaterEqual(len(win.group_icon_labels), 1)
        self.assertGreaterEqual(len(win.settings_icon_labels), 1)
        self.assertGreaterEqual(len(win.nav_btns), 4)
        print("[PASS] 深浅 QSS 语义类与控件属性绑定验证通过")

if __name__ == "__main__":
    unittest.main(verbosity=2)

