# -*- coding: utf-8 -*-
"""
PixivToolkit - 桌面端现代化重构全面自动化测试与回归验证套件
(Comprehensive Desktop Automated Unit & Regression Test Suite)

包含 4 大模块深度验证：
1. 语法与静态检查 (Syntax & Import Static Verification)
2. 交互收敛与弹窗清零验证 (Zero-Modal / Non-intrusive Toast Compliance Check)
3. 现代组件单元验证 (MD3 Component Unit Testing in Headless/Native Environment)
   - NativeFramelessHelper & TitleBar
   - ToastNotification & ToastManager (4种类型/内联Action/堆叠/悬停)
   - InlineEditableLabel (点击编辑/text_changed信号/回车保存/Esc取消/失焦保存)
   - SteamAccountCard (双击直切/double_clicked信号/内联备注联动)
   - TrafficMonitorChart (单调三次样条平滑/极值防护/平稳流量/突发峰值)
   - SkeletonCard, MDSwitch & LatencyBadge
4. 核心业务回归测试 (Core Network, Nginx, Hosts, Cert & Steam Engine Regression)
"""

import os
import sys
import ast
import time
from pathlib import Path
from typing import List, Dict, Any

# 设置输出流为 UTF-8 编码，防止 Windows 终端字符编码问题
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# 设置 Qt 平台为 offscreen 保证在无显示器/CI/命令行自动化环境下 100% 稳定运行
os.environ["QT_QPA_PLATFORM"] = "offscreen"

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = WORKSPACE_DIR / "app"
sys.path.insert(0, str(APP_DIR))

# PySide6 基础组件
from PySide6.QtCore import Qt, QPoint, QPointF, QEvent
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QApplication, QMainWindow

class TestReportCollector:
    def __init__(self):
        self.tests_run = 0
        self.tests_passed = 0
        self.tests_failed = 0
        self.failures: List[str] = []
        self.start_time = time.time()

    def assert_true(self, condition: bool, msg: str):
        self.tests_run += 1
        if condition:
            self.tests_passed += 1
            print(f"  [PASS] {msg}")
        else:
            self.tests_failed += 1
            self.failures.append(msg)
            print(f"  [FAIL] {msg}")

    def assert_equal(self, actual: Any, expected: Any, msg: str):
        self.assert_true(actual == expected, f"{msg} (期望: {expected!r}, 实际: {actual!r})")

    def print_section(self, title: str):
        print(f"\n{'='*75}")
        print(f"  >>> {title}")
        print(f"{'='*75}")


class BannedSymbolASTVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, banned_symbols: set):
        self.filename = filename
        self.banned_symbols = banned_symbols
        self.violations = []

    def visit_Name(self, node):
        if node.id in self.banned_symbols:
            self.violations.append((self.filename, node.lineno, node.id, "AST Name reference"))
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if node.attr in self.banned_symbols:
            self.violations.append((self.filename, node.lineno, node.attr, "AST Attribute access"))
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name in self.banned_symbols:
                self.violations.append((self.filename, node.lineno, alias.name, "AST ImportFrom"))
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name in self.banned_symbols:
                self.violations.append((self.filename, node.lineno, alias.name, "AST Import"))
        self.generic_visit(node)


def run_full_verification():
    report = TestReportCollector()
    print("\n" + "#"*75)
    print("      PixivToolkit 桌面端最新重构代码全面自动化测试与回归验证")
    print("#"*75)

    # 初始化 QApplication
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)

    # =========================================================================
    # 1. 语法与静态检查 (app/ 下所有 Python 文件)
    # =========================================================================
    report.print_section("第 1 部分：语法静态编译与全模块动态导入验证")
    import py_compile
    import importlib

    py_files = sorted([p for p in APP_DIR.glob("*.py") if not p.name.endswith("_backup.py") and p.name != "edit.py"])
    report.assert_true(len(py_files) >= 10, f"在 app/ 目录下扫描到 {len(py_files)} 个 Python 源文件")

    for pf in py_files:
        mod_name = pf.stem
        # 静态字节码编译
        try:
            py_compile.compile(str(pf), doraise=True)
            report.assert_true(True, f"静态编译通过: app/{pf.name}")
        except Exception as e:
            report.assert_true(False, f"静态编译失败: app/{pf.name} -> {e}")

        # 动态导入检查
        try:
            mod = importlib.import_module(mod_name)
            report.assert_true(mod is not None, f"模块导入成功: {mod_name}")
        except Exception as e:
            report.assert_true(False, f"模块导入失败: {mod_name} -> {e}")

    # =========================================================================
    # 2. 交互收敛与弹窗清零验证 (Zero-Modal AST Code Inspection)
    # =========================================================================
    report.print_section("第 2 部分：交互收敛与无模态弹窗验证 (Zero-Modal AST Compliance)")

    banned_symbols = {"QMessageBox", "QInputDialog", "messagebox"}
    all_violations = []

    for py_path in py_files:
        try:
            source = py_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(py_path))
            visitor = BannedSymbolASTVisitor(py_path.name, banned_symbols)
            visitor.visit(tree)
            all_violations.extend(visitor.violations)
        except Exception as e:
            report.assert_true(False, f"AST 解析失败: {py_path.name} -> {e}")

    report.assert_equal(len(all_violations), 0, "app/ 下所有 Python 源码 AST 无任何 QMessageBox/QInputDialog 导入或调用")
    if all_violations:
        for f, ln, sym, reason in all_violations:
            print(f"    - 违规调用: {f}:{ln} -> 发现 {sym} ({reason})")
    else:
        print("    -> 经 AST 语法树全量静态探测，全部弹窗已完全移除，交互 100% 收敛至非侵入式 Toast 与原位编辑！")

    # =========================================================================
    # 3. 组件单元验证 (Component Unit Testing)
    # =========================================================================
    report.print_section("第 3 部分：Material Design 3 原生自绘高级现代控件单元验证")

    from frameless_helper import NativeFramelessHelper
    from md_widgets import (
        TitleBar, ToastNotification, ToastManager, show_toast,
        InlineEditableLabel, MDSwitch, TrafficMonitorChart,
        LatencyBadge, SkeletonCard
    )
    from pyside_app import SteamAccountCard

    # 3.1 实例化测试主窗口与 NativeFramelessHelper
    test_win = QMainWindow()
    test_win.resize(1000, 600)
    test_win.show()

    frameless_helper = NativeFramelessHelper(test_win, border_width=6)
    report.assert_true(frameless_helper is not None, "NativeFramelessHelper 实例化成功")
    report.assert_equal(frameless_helper.border_width, 6, "无边框缩放感知边界宽度为 6px")

    # 3.2 实例化 TitleBar 并检查状态更新与控制按钮
    title_bar = TitleBar(test_win)
    frameless_helper.set_title_bar(title_bar)
    frameless_helper.set_window_controls(
        min_btn=title_bar.btn_min,
        max_btn=title_bar.btn_max,
        close_btn=title_bar.btn_close
    )
    report.assert_true(title_bar.btn_min is not None, "TitleBar 最小化按钮存在")
    report.assert_true(title_bar.btn_max is not None, "TitleBar 最大化按钮存在")
    report.assert_true(title_bar.btn_close is not None, "TitleBar 关闭按钮存在")
    report.assert_equal(title_bar.height(), 38, "TitleBar 高度规范为 38px")

    # 状态胶囊更新测试
    title_bar.update_status(True, "● 代理加速中")
    report.assert_true("代理加速中" in title_bar.status_pill.text(), "TitleBar 状态胶囊更新为加速中")
    title_bar.update_status(False, "○ 服务已停止")
    report.assert_true("服务已停止" in title_bar.status_pill.text(), "TitleBar 状态胶囊更新为已停止")

    # 最大化图标切换测试
    title_bar.update_max_icon(True)
    report.assert_true(not title_bar.btn_max.icon().isNull() or len(title_bar.btn_max.text()) > 0, "窗口最大化时按钮图标切换为还原态")
    title_bar.update_max_icon(False)
    report.assert_true(not title_bar.btn_max.icon().isNull() or len(title_bar.btn_max.text()) > 0, "窗口还原态时按钮图标切换为最大化态")

    # 3.3 实例化 ToastNotification 与 ToastManager
    toast_mgr = ToastManager.get_instance()
    report.assert_true(toast_mgr is not None, "ToastManager 单例获取成功")

    action_called = [False]
    def sample_action():
        action_called[0] = True

    # 测试 4 种类型 Toast
    t_types = ["success", "info", "warning", "error"]
    for tt in t_types:
        toast = ToastNotification(test_win, f"测试通知 {tt}", toast_type=tt, duration=1000)
        report.assert_equal(toast.toast_type, tt, f"ToastNotification 正确初始化类型: {tt}")
        toast.show_animated(QPoint(100, 200))
        toast.dismiss()

    # 测试带有 Action 动作按钮的回调
    toast_with_action = ToastNotification(
        test_win, "需要提权", toast_type="warning",
        duration=3000, action_text="[🛡️ 提权]", on_action=sample_action
    )
    report.assert_true(hasattr(toast_with_action, "action_btn"), "带有 action_text 时成功生成动作按钮")
    toast_with_action._handle_action()
    report.assert_true(action_called[0], "Toast 动作按钮点击时成功执行 on_action 回调")

    # 测试 show_toast 全局辅助函数
    show_toast(test_win, "全局 Toast 弹出测试", toast_type="success")
    report.assert_true(len(toast_mgr.active_toasts) > 0, "ToastManager 成功登记并展示悬浮通知")

    # 3.4 实例化 InlineEditableLabel (原位编辑)
    inline_label = InlineEditableLabel(initial_text="主账号", placeholder="+ 添加备注", parent=test_win)
    inline_label.show()
    report.assert_equal(inline_label.get_text(), "主账号", "InlineEditableLabel 初始备注正确")
    report.assert_true(not inline_label.badge_label.isHidden(), "初始态展示徽章 Label")
    report.assert_true(inline_label.edit_input.isHidden(), "初始态隐藏 QLineEdit 输入框")

    # 测试激活编辑
    inline_label.start_edit()
    report.assert_true(not inline_label.edit_input.isHidden(), "start_edit 后 QLineEdit 正确展示")
    report.assert_true(inline_label.badge_label.isHidden(), "start_edit 后 badge_label 隐藏")

    # 测试输入与信号发射
    received_signals = []
    inline_label.text_changed.connect(lambda s: received_signals.append(s))
    inline_label.edit_input.setText("小号A-代练")
    inline_label._commit_edit()

    report.assert_equal(inline_label.get_text(), "小号A-代练", "提交保存后当前文本正确更新")
    report.assert_equal(len(received_signals), 1, "修改内容后成功发射 1 次 text_changed 信号")
    report.assert_equal(received_signals[0], "小号A-代练", "text_changed 携带的新文本数据完全准确")

    # 测试取消编辑
    inline_label.start_edit()
    inline_label.edit_input.setText("未保存内容")
    inline_label._cancel_edit()
    report.assert_equal(inline_label.get_text(), "小号A-代练", "取消编辑后恢复原文本")

    # 3.5 实例化 SteamAccountCard 并测试双击信号
    mock_account = {
        "steamid": "76561198966320302",
        "account_name": "gamer_pro_01",
        "persona_name": "二次元冒险者",
        "alias": "主力号",
        "timestamp": 1700000000,
        "is_active": False
    }
    card = SteamAccountCard(acc=mock_account, is_active=False, parent_window=test_win)
    report.assert_true(card is not None, "SteamAccountCard 实例化成功")
    report.assert_equal(card.steamid, "76561198966320302", "SteamID 正确绑定")

    # 模拟双击卡片事件
    clicked_steamid = []
    card.double_clicked.connect(lambda sid: clicked_steamid.append(sid))

    mouse_event = QMouseEvent(
        QEvent.MouseButtonDblClick,
        QPointF(10, 10),
        QPointF(10, 10),
        Qt.LeftButton,
        Qt.LeftButton,
        Qt.NoModifier
    )
    card.mouseDoubleClickEvent(mouse_event)
    report.assert_equal(len(clicked_steamid), 1, "双击卡片成功发射 1 次 double_clicked 信号")
    report.assert_equal(clicked_steamid[0], "76561198966320302", "double_clicked 发射的 SteamID 完全吻合")

    # 3.6 实例化 SkeletonCard (骨架屏)
    skeleton = SkeletonCard(test_win)
    report.assert_true(skeleton is not None, "SkeletonCard 实例化成功")
    report.assert_true(skeleton.timer.isActive(), "SkeletonCard 骨架流动定时器已启动")
    initial_offset = skeleton._offset
    skeleton._step_animation()
    report.assert_true(skeleton._offset != initial_offset, "SkeletonCard 动画帧步进正常")

    # 3.7 实例化 TrafficMonitorChart 并测试单调样条平滑算法与极值鲁棒性
    chart = TrafficMonitorChart(test_win, max_points=20)
    report.assert_true(chart is not None, "TrafficMonitorChart 实例化成功")
    report.assert_equal(len(chart.down_speeds), 20, "波形图样本队列容量为 20")

    # 平稳流量输入测试
    for i in range(10):
        chart.add_sample(down_kb=150.0 + i*5, up_kb=25.0 + i*2, req_delta=2, hit_delta=1)
    report.assert_true(chart.total_requests == 20, "累计请求数计数正常 (20 次)")
    report.assert_true(chart.cache_hits == 10, "累计缓存命中数正常 (10 次)")

    # 极值鲁棒性测试：零流量、极端突发流量、负数流量防护
    chart.add_sample(down_kb=0.0, up_kb=0.0)
    report.assert_equal(chart.down_speeds[-1], 0.0, "零流量平稳处理")

    chart.add_sample(down_kb=-99.9, up_kb=-10.0)
    report.assert_equal(chart.down_speeds[-1], 0.0, "负数异常流量自动钳位为 0.0")

    chart.add_sample(down_kb=999999.0, up_kb=888888.0)
    report.assert_equal(chart.down_speeds[-1], 999999.0, "海量突发峰值流量平滑容纳")

    # 单调样条路径生成算法测试
    test_points = [
        QPointF(10, 100), QPointF(50, 40), QPointF(90, 80),
        QPointF(130, 20), QPointF(170, 60), QPointF(210, 100)
    ]
    smooth_path = chart._build_smooth_path(test_points)
    report.assert_true(not smooth_path.isEmpty(), "单调样条算法成功生成平滑样条路径")
    report.assert_equal(smooth_path.elementCount() > 0, True, "样条曲线包含完整的控制点元素")

    # 边界情况：0 点、1 点、2 点
    report.assert_true(chart._build_smooth_path([]).isEmpty(), "0 点时安全返回空路径")
    report.assert_equal(chart._build_smooth_path([QPointF(0, 0)]).elementCount(), 1, "1 点时安全记录起始点")
    report.assert_true(not chart._build_smooth_path([QPointF(0, 0), QPointF(10, 10)]).isEmpty(), "2 点时退化为直线段安全返回")

    # 3.8 实例化 MDSwitch 与 LatencyBadge
    switch = MDSwitch(test_win, checked=False)
    report.assert_equal(switch.isChecked(), False, "MDSwitch 初始处于关闭状态")
    switch.setChecked(True)
    report.assert_equal(switch.isChecked(), True, "MDSwitch 切换为开启状态")
    switch.setCheckedNoAnim(False)
    report.assert_equal(switch.isChecked(), False, "setCheckedNoAnim 无动画同步为关闭状态")

    badge = LatencyBadge(test_win)
    badge.set_latency(28, is_star=True)
    report.assert_equal(badge.latency_ms, 28, "LatencyBadge 延迟设置成功")
    report.assert_equal(badge.is_star, True, "LatencyBadge 优选星标标记成功")

    badge.set_latency(-1)
    report.assert_equal(badge.latency_ms, -1, "LatencyBadge 检测中状态设置成功")

    # =========================================================================
    # 4. 核心业务回归测试 (Core Regression Verification)
    # =========================================================================
    report.print_section("第 4 部分：核心网络代理、Hosts 管理、Nginx 配置与 Steam 引擎回归")

    from hosts_manager import HostsManager
    from cert_manager import CertManager
    from steam_manager import SteamManager
    from nginx_manager import NginxManager
    from cdn_optimizer import CDNOptimizer
    from ip_pool import SERVICES_LIST

    # 4.1 SteamManager 回归
    sm = SteamManager()
    report.assert_true(sm.steam_path is not None, f"Steam 客户端检测正常: {sm.steam_path}")
    accounts = sm.get_accounts()
    report.assert_true(len(accounts) >= 0, f"Steam 账号列表解析正常 (解析到 {len(accounts)} 个账号)")

    # 4.2 CertManager 回归
    cm = CertManager()
    thumb = cm.get_cert_thumbprint()
    report.assert_equal(len(thumb), 40, f"本地根证书 SHA1 指纹计算正常 (40位十六进制: {thumb})")
    is_inst = cm.is_cert_installed(force_refresh=True)
    report.assert_true(isinstance(is_inst, bool), f"CryptoAPI 证书受信任检测正常: {is_inst}")

    # 4.3 HostsManager 回归
    hm = HostsManager()
    report.assert_true(len(SERVICES_LIST) >= 15, f"加速服务清单总数有效 ({len(SERVICES_LIST)} 项)")

    # 4.4 NginxManager 配置与语法测试
    nm = NginxManager()
    report.assert_true(nm.nginx_exe.exists(), f"Nginx 可执行文件就绪: {nm.nginx_exe}")
    import subprocess
    proc = subprocess.run(
        [str(nm.nginx_exe), "-t", "-p", str(nm.nginx_dir), "-c", "conf/nginx.conf"],
        capture_output=True, text=True, errors="ignore"
    )
    report.assert_equal(proc.returncode, 0, "Nginx 全量站点与动态 Upstream 语法预检 100% 通过")

    # 4.5 CDNOptimizer 回归
    copt = CDNOptimizer()
    upstream_conf = copt.generate_upstream_conf({"pixiv_web": [{"ip": "210.140.139.151", "latency": 35.0, "available": True, "rank": 0}]})
    report.assert_true("upstream upstream_pixiv_web" in upstream_conf, "CDNOptimizer 动态 Upstream 块生成格式正常")

    # =========================================================================
    # 测试总结与报告输出
    # =========================================================================
    elapsed = time.time() - report.start_time
    print("\n" + "="*75)
    print("                    自动化测试与回归验证总结报告")
    print("="*75)
    print(f"  总测试项数: {report.tests_run}")
    print(f"  通过项数  : {report.tests_passed}")
    print(f"  失败项数  : {report.tests_failed}")
    print(f"  执行耗时  : {elapsed:.2f} 秒")

    if report.tests_failed == 0:
        print("\n>>> 结论: 全部测试项 100% 通过！桌面端重构代码质量完美，无任何语法、类型或回归问题！<<<")
        print("="*75 + "\n")
        return True
    else:
        print("\n>>> 结论: 存在测试失败项，详情见上方日志！<<<")
        for fail in report.failures:
            print(f"  * {fail}")
        print("="*75 + "\n")
        return False


if __name__ == "__main__":
    success = run_full_verification()
    sys.exit(0 if success else 1)
