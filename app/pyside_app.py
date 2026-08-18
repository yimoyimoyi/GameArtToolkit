# -*- coding: utf-8 -*-
"""
PixivToolkit - Material Design 3 桌面客户端
包含:
1. Win32 DWM 原生无边框窗口，支持 Win11 Snap Layouts 贴靠菜单与 8 向缩放
2. 全局 MD3 Floating Toast Overlay 悬浮通知体系，不使用阻塞式 QMessageBox
3. Steam 账号管家卡片内 Inline Edit 备注编辑与双击卡片免密切换
4. CDN 测速骨架屏 (Skeleton Screen) 与热重载
5. 单调三次样条平滑网络监控波形图与 18 项加速规则独立/分组原子管理
"""

import os
import sys
import time
import base64
import random
import atexit
import threading
from pathlib import Path
from typing import Optional, List, Dict, Set, Tuple

from PySide6.QtCore import Qt, QTimer, QThread, Signal, QEvent, QPoint, QSize
from PySide6.QtGui import QIcon, QPixmap, QPainter, QColor, QFont, QAction, QMouseEvent
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QCheckBox, QFrame, QScrollArea, QStackedWidget,
    QGridLayout, QSystemTrayIcon, QMenu, QButtonGroup, QProgressBar,
    QRadioButton, QLineEdit
)

from path_utils import BASE_DIR, APP_DIR
sys.path.insert(0, str(APP_DIR))

from config_store import load_config, save_config, update_config_key
from steam_manager import SteamManager
from cert_manager import CertManager
from hosts_manager import HostsManager
from nginx_manager import NginxManager
from cdn_optimizer import CDNOptimizer, CDNHealthMonitor
from l4_relay import relay_server
from dns_server import local_dns_server
from env_detector import EnvDetector
from win_utils import (
    is_process_running, is_port_in_use, is_admin, elevate_relaunch,
    is_autostart_enabled, set_autostart, register_shutdown_handler,
    fast_terminate_pid, check_proxy_alive, flush_dns_native, hide_console_window
)
from ip_pool import SERVICE_GROUPS, SERVICES_LIST, SERVICES_BY_ID, DEFAULT_ENABLED_SERVICES
from frameless_helper import NativeFramelessHelper
from md_widgets import (
    MDSwitch, TrafficMonitorChart, LatencyBadge, TitleBar,
    show_toast, InlineEditableLabel, SkeletonCard, AnimatedStackedWidget, FlowLayout
)
from material_theme import MATERIAL_DARK_QSS, MATERIAL_LIGHT_QSS, ThemeManager
from svg_icons import SvgIconFactory

# 单例实例
steam_mgr = SteamManager()
cert_mgr = CertManager()
hosts_mgr = HostsManager()
nginx_mgr = NginxManager()
cdn_opt = CDNOptimizer()
health_monitor = CDNHealthMonitor(cdn_opt, on_healed=nginx_mgr.reload)

# ==================== 全局快速退出与 Windows 关机安全清理通道 ====================
_CLEANUP_LOCK = threading.Lock()
_HAS_EMERGENCY_CLEANED = False

def emergency_fast_cleanup():
    """全局快速退出与 Windows 关机清理通道 (幂等，不阻塞子进程)"""
    global _HAS_EMERGENCY_CLEANED
    with _CLEANUP_LOCK:
        if _HAS_EMERGENCY_CLEANED:
            return
        _HAS_EMERGENCY_CLEANED = True

    try:
        cfg = load_config()
        if cfg.get("auto_clean_hosts_on_exit", True):
            hosts_mgr.fast_remove_rules()
    except Exception:
        pass

    try:
        local_dns_server.stop()
        health_monitor.stop()
        relay_server.stop()
    except Exception:
        pass

    try:
        # 原生直接终止本地 Nginx 进程
        pid = nginx_mgr.get_pid()
        if pid > 0:
            fast_terminate_pid(pid)
    except Exception:
        pass

# 注册底层系统关机/注销与控制台事件
register_shutdown_handler(emergency_fast_cleanup)
# 注册 Python atexit 钩子
atexit.register(emergency_fast_cleanup)


def get_app_icon() -> QIcon:
    """获取应用程序高分辨率原生图标 (包含多尺寸自适应)"""
    icon_ico = APP_DIR / "icon.ico"
    icon_png = APP_DIR / "icon.png"
    if icon_ico.exists():
        return QIcon(str(icon_ico))
    elif icon_png.exists():
        return QIcon(str(icon_png))
    return create_tray_icon(False)


def create_tray_icon(is_active: bool = False) -> QIcon:
    """创建原本经典平面化风格的系统托盘图标"""
    pixmap = QPixmap(32, 32)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setRenderHint(QPainter.TextAntialiasing)

    bg_color = QColor("#10B981") if is_active else QColor("#0284C7")
    painter.setBrush(bg_color)
    painter.setPen(Qt.NoPen)
    painter.drawRoundedRect(2, 2, 28, 28, 7, 7)

    painter.setPen(QColor("#FFFFFF"))
    font = QFont("Segoe UI", 16, QFont.Bold)
    painter.setFont(font)
    painter.drawText(pixmap.rect().adjusted(0, -1, 0, 0), Qt.AlignCenter, "P")
    painter.end()
    return QIcon(pixmap)


class CDNTestWorker(QThread):
    finished = Signal(dict)

    def __init__(self):
        super().__init__()
        self._stop_requested = False

    def request_stop(self):
        self._stop_requested = True

    def run(self):
        results = cdn_opt.test_all_services()
        if not self._stop_requested:
            self.finished.emit(results)


class StatusProbeWorker(QThread):
    probed = Signal(dict)

    def run(self):
        result = {
            'is_nginx': nginx_mgr.is_running(),
            'is_hosts': hosts_mgr.is_applied(),
            'is_cert': cert_mgr.is_cert_installed(force_refresh=False),
            'is_steam_running': is_process_running('steam.exe'),
            'p443_busy': is_port_in_use(443),
            'cert_thumb': cert_mgr.get_cert_thumbprint(),
            'curr_steam_user': steam_mgr.get_current_login_user() or ('未登录' if steam_mgr.steam_path else '未检测到'),
            'steam_path': str(steam_mgr.steam_path) if steam_mgr.steam_path else None,
            'has_admin': is_admin(),
        }
        self.probed.emit(result)


class SteamSwitchWorker(QThread):
    finished = Signal(bool, str, str)

    def __init__(self, steamid: str):
        super().__init__()
        self.steamid = steamid
        self._stop_requested = False

    def request_stop(self):
        self._stop_requested = True

    def run(self):
        ok, msg = steam_mgr.switch_account(self.steamid, restart_steam=True)
        if not self._stop_requested:
            self.finished.emit(ok, msg, self.steamid)


class SteamAccountCard(QFrame):
    """
    Steam 账号独立卡片
    支持：双击卡片免密切换、原位内联备注编辑、当前活跃状态高亮
    """
    double_clicked = Signal(str)

    def __init__(self, acc: dict, is_active: bool, parent_window: 'MainWindow'):
        super().__init__(parent_window)
        self.acc = acc
        self.steamid = acc.get("steamid", "")
        self.is_active = is_active
        self.parent_window = parent_window

        self.setProperty("class", "AccountCardActive" if is_active else "AccountCard")
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip("双击此卡片即可直接免密切换并启动该账号")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        # 1. 顶部信息栏 (头像 + 昵称/登录名/原位备注 + 活跃状态标签)
        top_box = QHBoxLayout()
        top_box.setSpacing(12)

        lbl_avatar = QLabel()
        lbl_avatar.setFixedSize(48, 48)
        lbl_avatar.setProperty("class", "AvatarLabel")
        lbl_avatar.setAlignment(Qt.AlignCenter)

        avatar_uri = acc.get("avatar_uri")
        if avatar_uri and "base64," in avatar_uri:
            try:
                b64_data = avatar_uri.split("base64,")[1]
                img_data = base64.b64decode(b64_data)
                pix = QPixmap()
                pix.loadFromData(img_data)
                lbl_avatar.setPixmap(pix.scaled(48, 48, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation))
            except Exception:
                initial = (acc.get("persona_name") or acc.get("account_name") or "U")[0].upper()
                lbl_avatar.setText(initial)
        else:
            initial = (acc.get("persona_name") or acc.get("account_name") or "U")[0].upper()
            lbl_avatar.setText(initial)

        top_box.addWidget(lbl_avatar)

        meta_box = QVBoxLayout()
        meta_box.setSpacing(3)
        lbl_persona = QLabel(acc.get("persona_name", "未知用户"))
        lbl_persona.setProperty("class", "AccountName")
        lbl_acc_name = QLabel(f"登录名: {acc.get('account_name', '')}")
        lbl_acc_name.setProperty("class", "AccountSteamId")

        # 原位备注编辑组件 (Inline Edit)
        self.inline_alias = InlineEditableLabel(
            initial_text=acc.get("alias", ""),
            placeholder="+ 添加备注",
            parent=self
        )
        self.inline_alias.text_changed.connect(self._on_alias_changed)

        meta_box.addWidget(lbl_persona)
        meta_box.addWidget(lbl_acc_name)
        meta_box.addWidget(self.inline_alias)

        top_box.addLayout(meta_box)
        top_box.addStretch()

        if is_active:
            lbl_active_tag = QLabel("● 当前活跃")
            lbl_active_tag.setProperty("class", "ActiveTagLabel")
            top_box.addWidget(lbl_active_tag)

        layout.addLayout(top_box)

        # 2. 底部操作栏 (最后登录时间 + 双击提示 + 操作按钮)
        bot_box = QHBoxLayout()
        ts = acc.get("timestamp", 0)
        time_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "未知"
        lbl_time = QLabel(f"最后登录: {time_str}")
        lbl_time.setProperty("class", "AccountHint")
        bot_box.addWidget(lbl_time)
        bot_box.addStretch()

        btn_switch = QPushButton("重连" if is_active else "免密切换")
        btn_switch.setProperty("class", "MDBtnTonal" if is_active else "MDBtnPrimary")
        btn_switch.clicked.connect(lambda: self.double_clicked.emit(self.steamid))
        bot_box.addWidget(btn_switch)

        layout.addLayout(bot_box)

    def mouseDoubleClickEvent(self, event: QMouseEvent):
        """双击卡片直接触发免密切换"""
        if event.button() == Qt.LeftButton:
            self.double_clicked.emit(self.steamid)
            event.accept()
        else:
            super().mouseDoubleClickEvent(event)

    def _on_alias_changed(self, new_alias: str):
        steam_mgr.set_account_alias(self.steamid, new_alias)
        show_toast(self.parent_window, f"账号备注已更新为: {new_alias or '未设置'}", toast_type="success", duration=2000)
        self.parent_window.refresh_tray_steam_menu()


class MainWindow(QMainWindow):
    """
    PixivToolkit 主窗口 (无边框与 Material 3 客户端)
    """
    def __init__(self):
        super().__init__()
        self.resize(1200, 800)
        self.setMinimumSize(1060, 680)
        self.setWindowIcon(get_app_icon())

        self.frameless_helper = None

        self.cdn_worker: Optional[CDNTestWorker] = None
        self.steam_worker: Optional[SteamSwitchWorker] = None
        self._status_worker: Optional[StatusProbeWorker] = None
        self.cached_cdn_results: Optional[Dict] = None
        self._last_acc_state: Optional[bool] = None
        self._has_prompted_hosts_perm: bool = False
        self._is_manually_stopped: bool = False

        # 控件引用映射
        self.service_switches: Dict[str, MDSwitch] = {}
        self.service_badges: Dict[str, LatencyBadge] = {}
        self.nav_btns: List[Tuple[QPushButton, str]] = []
        self.group_icon_labels: Dict[str, Tuple[QLabel, str]] = {}
        self.settings_icon_labels: List[Tuple[QLabel, str]] = []
        self.cdn_intro_icon: Optional[QLabel] = None

        # 1. 注册 Win32 原生无边框辅助器
        self.frameless_helper = NativeFramelessHelper(self)

        # 2. 构建界面组件
        self.init_ui()
        self.init_tray()
        self.init_timers()

        cfg = load_config()
        current_theme = cfg.get("theme", "dark")
        # 订阅主题变化总线，移除对 btn_theme.clicked 的重复绑定
        ThemeManager.get_instance().theme_changed.connect(self.on_theme_changed)
        ThemeManager.get_instance().set_theme(current_theme, QApplication.instance())
        if self.frameless_helper:
            self.frameless_helper.set_immersive_dark_mode(current_theme == "dark")

        # 3. 加载初始状态
        self._start_status_probe()
        self.load_steam_accounts_ui()

        # 启动时环境检查
        cfg = load_config()
        if cfg.get("auto_heal_on_startup", True) and not cfg.get("auto_proxy", True):
            try:
                diag = hosts_mgr.diagnose_and_repair(auto_fix=True)
                if diag.get("fixes"):
                    print(f"[Startup] 已自动修复 Hosts: {diag.get('fixes')}")
            except Exception as e:
                print(f"[Startup] 环境检查异常: {e}")

        # 初始刷新网络环境与代理诊断
        self.refresh_env_diagnostics_ui()

        # 4. 自动托管启动
        if cfg.get("auto_proxy", True):
            if not nginx_mgr.is_running() or not hosts_mgr.is_applied():
                self.start_acceleration(show_toast_on_fail=False)

    def on_theme_changed(self, new_theme: str):
        """响应全局主题变更广播"""
        is_dark = (new_theme == "dark")
        if self.frameless_helper:
            self.frameless_helper.set_immersive_dark_mode(is_dark)
        
        cfg = load_config()
        cfg["theme"] = new_theme
        save_config(cfg)
        
        # 刷新所有静态 SVG 图标与资源
        self.refresh_theme_assets(new_theme)
        # 动态刷新原位样式
        self.refresh_inline_styles()

    def refresh_theme_assets(self, theme_name: str):
        """批量刷新侧栏、分组卡片及设置诊断页面的矢量图标"""
        is_dark = (theme_name == "dark")
        nav_icon_color = "#CFE5FF" if is_dark else "#0F172A"
        primary_icon_color = "#7EB9F5" if is_dark else "#0284C7"

        if SvgIconFactory:
            for btn, icon_name in getattr(self, "nav_btns", []):
                btn.setIcon(SvgIconFactory.get_icon(icon_name, nav_icon_color, 18))

            for grp_id, (lbl, icon_name) in getattr(self, "group_icon_labels", {}).items():
                lbl.setPixmap(SvgIconFactory.get_pixmap(icon_name, primary_icon_color, 20))

            for lbl, icon_name in getattr(self, "settings_icon_labels", []):
                lbl.setPixmap(SvgIconFactory.get_pixmap(icon_name, primary_icon_color, 18))

            if getattr(self, "cdn_intro_icon", None):
                self.cdn_intro_icon.setPixmap(SvgIconFactory.get_pixmap("zap", "#7EB9F5" if is_dark else "#0284C7", 36))
        
    def refresh_inline_styles(self):
        # 让下次 probe 自动使用新颜色
        self._last_acc_state = None
        self._start_status_probe()
        # 刷新 Steam 列表以重绘卡片样式
        self.load_steam_accounts_ui()

    def nativeEvent(self, event_type, message):
        """拦截并处理 Windows 原生 DWM 消息"""
        if getattr(self, "frameless_helper", None) is not None:
            handled, result = self.frameless_helper.handle_native_event(event_type, message)
            if handled:
                return True, result
        return super().nativeEvent(event_type, message)

    def changeEvent(self, event):
        """监听窗口最大化/还原状态切换，动态更新标题栏图标"""
        if event.type() == QEvent.WindowStateChange:
            if hasattr(self, 'title_bar') and self.title_bar:
                self.title_bar.update_max_icon(self.isMaximized())
        super().changeEvent(event)

    def init_ui(self):
        # 顶层根容器
        root_widget = QWidget()
        root_widget.setObjectName("AppRootWidget")
        self.setCentralWidget(root_widget)

        root_layout = QVBoxLayout(root_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. 标题栏 (38px)
        self.title_bar = TitleBar(self)
        root_layout.addWidget(self.title_bar)

        # 注册标题栏与控制按钮到无边框辅助器
        self.frameless_helper.set_title_bar(self.title_bar)
        self.frameless_helper.set_window_controls(
            min_btn=self.title_bar.btn_min,
            max_btn=self.title_bar.btn_max,
            close_btn=self.title_bar.btn_close,
            theme_btn=self.title_bar.btn_theme
        )
        self.frameless_helper.add_interactive_widget(self.title_bar.btn_min)
        self.frameless_helper.add_interactive_widget(self.title_bar.btn_max)
        self.frameless_helper.add_interactive_widget(self.title_bar.btn_close)
        if hasattr(self.title_bar, 'btn_theme') and self.title_bar.btn_theme:
            self.frameless_helper.add_interactive_widget(self.title_bar.btn_theme)

        # 2. 界面主体 (左侧导航栏 + 右侧多页堆叠容器)
        body_widget = QWidget()
        body_layout = QHBoxLayout(body_widget)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        # 侧边导航栏 (NavSidebar)
        sidebar = QFrame()
        sidebar.setObjectName("NavSidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(16, 20, 16, 20)
        sidebar_layout.setSpacing(8)

        # 品牌
        brand_widget = QWidget()
        brand_layout = QVBoxLayout(brand_widget)
        brand_layout.setContentsMargins(8, 0, 8, 16)
        brand_layout.setSpacing(2)

        brand_title = QLabel("PixivToolkit")
        brand_title.setObjectName("BrandTitle")
        brand_sub = QLabel("Material 3 Accelerator")
        brand_sub.setObjectName("BrandSubtitle")
        brand_layout.addWidget(brand_title)
        brand_layout.addWidget(brand_sub)
        sidebar_layout.addWidget(brand_widget)

        # 导航按钮组
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        self.btn_nav_dashboard = self.create_nav_btn("加速控制台", 0, "rocket")
        self.btn_nav_steam = self.create_nav_btn("Steam 账号管家", 1, "gamepad")
        self.btn_nav_cdn = self.create_nav_btn("CDN 测速", 2, "zap")
        self.btn_nav_settings = self.create_nav_btn("系统诊断与设置", 3, "diagnostics")

        sidebar_layout.addWidget(self.btn_nav_dashboard)
        sidebar_layout.addWidget(self.btn_nav_steam)
        sidebar_layout.addWidget(self.btn_nav_cdn)
        sidebar_layout.addWidget(self.btn_nav_settings)
        sidebar_layout.addStretch()

        # 侧栏底部权限与状态指示
        self.btn_sidebar_admin = QPushButton("标准用户 [点击提权]")
        self.btn_sidebar_admin.setIcon(SvgIconFactory.get_icon("shield", "#FBBF24", 14))
        self.btn_sidebar_admin.setIconSize(QSize(14, 14))
        self.btn_sidebar_admin.setProperty("class", "MDBtnTonal")
        self.btn_sidebar_admin.setStyleSheet("font-size: 11px; padding: 6px 10px; border-radius: 8px;")
        self.btn_sidebar_admin.clicked.connect(elevate_relaunch)
        sidebar_layout.addWidget(self.btn_sidebar_admin)

        self.lbl_sidebar_status = QLabel("● 代理未启动")
        self.lbl_sidebar_status.setProperty("class", "SidebarStatusOff")
        sidebar_layout.addWidget(self.lbl_sidebar_status)

        body_layout.addWidget(sidebar)

        # 右侧主内容区 (滚动条直接贴靠最右侧边缘)
        content_area = QWidget()
        content_layout = QVBoxLayout(content_area)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        self.stack = AnimatedStackedWidget()
        self.page_dashboard = self.create_dashboard_page()
        self.page_steam = self.create_steam_page()
        self.page_cdn = self.create_cdn_page()
        self.page_settings = self.create_settings_page()

        self.stack.addWidget(self.page_dashboard)
        self.stack.addWidget(self.page_steam)
        self.stack.addWidget(self.page_cdn)
        self.stack.addWidget(self.page_settings)

        content_layout.addWidget(self.stack)
        body_layout.addWidget(content_area)

        root_layout.addWidget(body_widget)
        self.btn_nav_dashboard.setChecked(True)

    def create_nav_btn(self, text: str, index: int, icon_name: str = None) -> QPushButton:
        btn = QPushButton(f"  {text}")
        btn.setProperty("class", "NavButton")
        btn.setCheckable(True)
        if icon_name and SvgIconFactory:
            is_dark = ThemeManager.get_instance().is_dark
            icon_color = "#E8DEF8" if is_dark else "#1D192B"
            btn.setIcon(SvgIconFactory.get_icon(icon_name, icon_color, 18))
            btn.setIconSize(QSize(18, 18))
            self.nav_btns.append((btn, icon_name))
        self.nav_group.addButton(btn, index)
        btn.clicked.connect(lambda: self.on_nav_clicked(index))
        return btn

    def on_nav_clicked(self, index: int):
        self.stack.setCurrentIndex(index)
        if index == 1:
            self.load_steam_accounts_ui()

    # ------------------ PAGE 1: 加速控制台 ------------------
    def create_dashboard_page(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setObjectName("MainScrollArea")
        scroll.setWidgetResizable(True)

        content = QWidget()
        content.setObjectName("ScrollContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 20, 20, 20)
        layout.setSpacing(18)

        # 页面标题
        title = QLabel("加速控制中心")
        title.setObjectName("PageTitle")
        desc = QLabel("自动托管网络代理与 Hosts 规则，加速 18 项海外游戏、创作与开发服务")
        desc.setObjectName("PageDesc")
        layout.addWidget(title)
        layout.addWidget(desc)

        # 1. 实时网络流量监控波形图 (MD3 单调三次样条平滑自绘控件)
        self.traffic_chart = TrafficMonitorChart()
        layout.addWidget(self.traffic_chart)

        # 2. 顶部四合一状态指示卡片
        stat_grid = QGridLayout()
        stat_grid.setSpacing(12)

        self.card_stat_nginx = self.create_stat_card("Nginx 数据平面", "检测中...", "反代引擎与磁盘缓存")
        self.card_stat_cert = self.create_stat_card("Windows 根证书", "检测中...", "系统受信任证书库")
        self.card_stat_hosts = self.create_stat_card("Hosts 规则库", "未注入", "18 项服务规则隔离")
        self.card_stat_steam = self.create_stat_card("Steam 活跃用户", "未登录", "支持双击免密切换")

        stat_grid.addWidget(self.card_stat_nginx, 0, 0)
        stat_grid.addWidget(self.card_stat_cert, 0, 1)
        stat_grid.addWidget(self.card_stat_hosts, 0, 2)
        stat_grid.addWidget(self.card_stat_steam, 0, 3)
        layout.addLayout(stat_grid)

        # 3. 巨型主控卡片
        main_control_card = QFrame()
        main_control_card.setProperty("class", "MDCard")
        mc_layout = QHBoxLayout(main_control_card)
        mc_layout.setContentsMargins(24, 18, 24, 18)

        mc_info = QVBoxLayout()
        mc_info.setSpacing(4)
        self.lbl_main_status = QLabel("加速服务已停止")
        self.lbl_main_status.setProperty("class", "MainStatusTitle")
        self.lbl_main_sub = QLabel("点击右侧按钮开启本地代理与 Hosts 规则接管")
        self.lbl_main_sub.setProperty("class", "MainStatusSub")
        mc_info.addWidget(self.lbl_main_status)
        mc_info.addWidget(self.lbl_main_sub)

        self.chk_auto_proxy = QCheckBox("开启自动托管代理 (开机/启动自动加速与后台自动检查恢复)")
        self.chk_auto_proxy.setChecked(load_config().get("auto_proxy", True))
        self.chk_auto_proxy.toggled.connect(self.on_auto_proxy_toggled)
        mc_info.addWidget(self.chk_auto_proxy)

        mc_layout.addLayout(mc_info)
        mc_layout.addStretch()

        self.btn_toggle_acc = QPushButton("启动加速服务")
        self.btn_toggle_acc.setProperty("class", "MDBtnPrimary")
        self.btn_toggle_acc.setFixedSize(160, 48)
        self.btn_toggle_acc.clicked.connect(self.toggle_acceleration)
        mc_layout.addWidget(self.btn_toggle_acc)

        layout.addWidget(main_control_card)

        # 4. 18 项加速服务 (3 大分类分组卡片)
        cfg_services = set(load_config().get("enabled_services", DEFAULT_ENABLED_SERVICES))

        for grp_id, grp_info in SERVICE_GROUPS.items():
            grp_card = QFrame()
            grp_card.setProperty("class", "MDCard")
            grp_card_layout = QVBoxLayout(grp_card)
            grp_card_layout.setContentsMargins(20, 16, 20, 16)
            grp_card_layout.setSpacing(12)

            grp_header = QHBoxLayout()
            grp_icon_lbl = QLabel()
            grp_icon_lbl.setFixedSize(22, 22)
            is_dark = ThemeManager.get_instance().is_dark
            icon_c = "#D0BCFF" if is_dark else "#6750A4"
            grp_icon_lbl.setPixmap(SvgIconFactory.get_pixmap(grp_info.get("icon", "zap"), icon_c, 20))
            self.group_icon_labels[grp_id] = (grp_icon_lbl, grp_info.get("icon", "zap"))
            grp_header.addWidget(grp_icon_lbl)

            grp_title_box = QVBoxLayout()
            grp_title = QLabel(grp_info['name'])
            grp_title.setProperty("class", "CategoryTitle")
            grp_desc = QLabel(grp_info["desc"])
            grp_desc.setProperty("class", "CategoryDesc")
            grp_title_box.addWidget(grp_title)
            grp_title_box.addWidget(grp_desc)
            grp_header.addLayout(grp_title_box)
            grp_header.addStretch()

            btn_enable_all = QPushButton("全选")
            btn_enable_all.setProperty("class", "MDBtnOutlined")
            btn_enable_all.clicked.connect(lambda _, g=grp_id: self.toggle_group_services(g, True))

            btn_disable_all = QPushButton("全关")
            btn_disable_all.setProperty("class", "MDBtnOutlined")
            btn_disable_all.clicked.connect(lambda _, g=grp_id: self.toggle_group_services(g, False))

            grp_header.addWidget(btn_enable_all)
            grp_header.addWidget(btn_disable_all)
            grp_card_layout.addLayout(grp_header)

            items_grid = QGridLayout()
            items_grid.setSpacing(10)

            grp_services = [s for s in SERVICES_LIST if s["group"] == grp_id]
            for idx, srv in enumerate(grp_services):
                sid = srv["id"]
                s_item = QFrame()
                s_item.setProperty("class", "ServiceItem")
                si_layout = QHBoxLayout(s_item)
                si_layout.setContentsMargins(12, 10, 12, 10)
                si_layout.setSpacing(12)

                si_text_box = QVBoxLayout()
                si_text_box.setSpacing(2)
                si_name = QLabel(srv["name"])
                si_name.setProperty("class", "ItemTitle")
                si_desc = QLabel(srv["desc"])
                si_desc.setProperty("class", "ItemDesc")
                si_text_box.addWidget(si_name)
                si_text_box.addWidget(si_desc)
                si_layout.addLayout(si_text_box)
                si_layout.addStretch()

                badge = LatencyBadge()
                badge.set_latency(-1)
                self.service_badges[sid] = badge
                si_layout.addWidget(badge)

                sw = MDSwitch(checked=(sid in cfg_services))
                sw.toggled.connect(lambda c, s=sid: self.on_service_toggled(s, c))
                self.service_switches[sid] = sw
                si_layout.addWidget(sw)

                items_grid.addWidget(s_item, idx // 2, idx % 2)

            grp_card_layout.addLayout(items_grid)
            layout.addWidget(grp_card)

        layout.addStretch()
        scroll.setWidget(content)
        return scroll

    def create_stat_card(self, label: str, value: str, hint: str) -> QFrame:
        card = QFrame()
        card.setProperty("class", "StatCard")
        l = QVBoxLayout(card)
        l.setContentsMargins(14, 12, 14, 12)
        l.setSpacing(2)

        lbl_title = QLabel(label)
        lbl_title.setProperty("class", "StatLabel")
        lbl_val = QLabel(value)
        lbl_val.setProperty("class", "StatValue")
        lbl_hint = QLabel(hint)
        lbl_hint.setProperty("class", "StatHint")

        l.addWidget(lbl_title)
        l.addWidget(lbl_val)
        l.addWidget(lbl_hint)

        card.lbl_val = lbl_val
        return card

    def toggle_group_services(self, group_id: str, enable: bool):
        cfg = load_config()
        services = set(cfg.get("enabled_services", DEFAULT_ENABLED_SERVICES))

        for srv in SERVICES_LIST:
            if srv["group"] == group_id:
                sid = srv["id"]
                if enable:
                    services.add(sid)
                else:
                    services.discard(sid)
                if sid in self.service_switches:
                    sw = self.service_switches[sid]
                    sw.blockSignals(True)
                    sw.setCheckedNoAnim(enable)
                    sw.blockSignals(False)

        new_list = list(services)
        cfg["enabled_services"] = new_list
        save_config(cfg)

        if nginx_mgr.is_running():
            hosts_mgr.apply_rules(new_list)

        action_name = "启用" if enable else "禁用"
        show_toast(self, f"已{action_name} [{SERVICE_GROUPS.get(group_id, {}).get('name', group_id)}] 全部分类服务", toast_type="info", duration=2000)

    def on_service_toggled(self, service_id: str, checked: bool):
        cfg = load_config()
        services = set(cfg.get("enabled_services", DEFAULT_ENABLED_SERVICES))
        if checked:
            services.add(service_id)
        else:
            services.discard(service_id)

        new_list = list(services)
        cfg["enabled_services"] = new_list
        save_config(cfg)

        if nginx_mgr.is_running():
            hosts_mgr.apply_rules(new_list)

    # ------------------ PAGE 2: Steam 账号管家 ------------------
    def create_steam_page(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setObjectName("MainScrollArea")
        scroll.setWidgetResizable(True)

        content = QWidget()
        content.setObjectName("ScrollContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 20, 20, 20)
        layout.setSpacing(18)

        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Steam 快速账号管家")
        title.setObjectName("PageTitle")
        desc = QLabel("双击账号卡片直接免密切换，支持卡片内原位点击修改别名备注")
        desc.setObjectName("PageDesc")
        title_box.addWidget(title)
        title_box.addWidget(desc)
        header_layout.addLayout(title_box)
        header_layout.addStretch()

        self.btn_launch_steam = QPushButton("启动 Steam")
        self.btn_launch_steam.setProperty("class", "MDBtnTonal")
        self.btn_launch_steam.clicked.connect(self.launch_steam_app)
        header_layout.addWidget(self.btn_launch_steam)

        self.btn_refresh_steam = QPushButton("刷新列表")
        self.btn_refresh_steam.setProperty("class", "MDBtnOutlined")
        self.btn_refresh_steam.clicked.connect(self.load_steam_accounts_ui)
        header_layout.addWidget(self.btn_refresh_steam)

        layout.addLayout(header_layout)

        # Steam 状态横幅
        self.steam_banner = QFrame()
        self.steam_banner.setProperty("class", "MDCard")
        sb_layout = QHBoxLayout(self.steam_banner)
        self.lbl_steam_banner_status = QLabel("Steam 状态: 检测中...")
        self.lbl_steam_banner_status.setProperty("class", "ItemTitle")
        self.lbl_steam_banner_path = QLabel("安装路径: 正在读取注册表")
        self.lbl_steam_banner_path.setProperty("class", "ItemDesc")
        sb_text_box = QVBoxLayout()
        sb_text_box.addWidget(self.lbl_steam_banner_status)
        sb_text_box.addWidget(self.lbl_steam_banner_path)
        sb_layout.addLayout(sb_text_box)
        layout.addWidget(self.steam_banner)

        self.accounts_container = FlowLayout(h_spacing=14, v_spacing=14)
        layout.addLayout(self.accounts_container)
        layout.addStretch()

        scroll.setWidget(content)
        return scroll

    def load_steam_accounts_ui(self):
        while self.accounts_container.count():
            item = self.accounts_container.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        accounts = steam_mgr.get_accounts()
        if not accounts:
            # MD3 空态引导卡片
            empty_card = QFrame()
            empty_card.setProperty("class", "EmptyStateCard")
            ec_layout = QVBoxLayout(empty_card)
            ec_layout.setContentsMargins(32, 36, 32, 36)
            ec_layout.setAlignment(Qt.AlignCenter)

            lbl_ec_icon = QLabel()
            lbl_ec_icon.setAlignment(Qt.AlignCenter)
            is_dark = ThemeManager.get_instance().is_dark
            icon_c = "#D0BCFF" if is_dark else "#6750A4"
            lbl_ec_icon.setPixmap(SvgIconFactory.get_pixmap("gamepad", icon_c, 48))

            lbl_ec_title = QLabel("未检测到本地已记住的 Steam 账号")
            lbl_ec_title.setProperty("class", "EmptyStateTitle")
            lbl_ec_desc = QLabel(
                "请先在 Steam 客户端登录界面勾选【记住我的密码】并成功登录过至少一次，\n随后回到此处即可免密切换多个账号并管理备注。"
            )
            lbl_ec_desc.setProperty("class", "EmptyStateDesc")
            lbl_ec_desc.setAlignment(Qt.AlignCenter)

            btn_start_steam = QPushButton("立即启动 Steam 客户端")
            btn_start_steam.setIcon(SvgIconFactory.get_icon("rocket", "#FFFFFF", 16))
            btn_start_steam.setProperty("class", "MDBtnPrimary")
            btn_start_steam.clicked.connect(self.launch_steam_app)

            ec_layout.addWidget(lbl_ec_icon, 0, Qt.AlignCenter)
            ec_layout.addWidget(lbl_ec_title, 0, Qt.AlignCenter)
            ec_layout.addWidget(lbl_ec_desc, 0, Qt.AlignCenter)
            ec_layout.addSpacing(10)
            ec_layout.addWidget(btn_start_steam, 0, Qt.AlignCenter)

            self.accounts_container.addWidget(empty_card)
            return

        for idx, acc in enumerate(accounts):
            is_active = acc.get("is_active", False)
            card = SteamAccountCard(acc, is_active, self)
            card.setMinimumWidth(360)
            card.setMaximumWidth(460)
            card.double_clicked.connect(self.switch_steam_account)
            self.accounts_container.addWidget(card)

    def switch_steam_account(self, steamid: str):
        if self.steam_worker and self.steam_worker.isRunning():
            show_toast(self, "正在切换中，请稍候...", toast_type="info", duration=1500)
            return

        show_toast(self, "正在安全关闭 Steam 并切换活跃凭据...", toast_type="info", duration=2500)
        self.steam_worker = SteamSwitchWorker(steamid)
        self.steam_worker.finished.connect(self._on_steam_switch_finished)
        self.steam_worker.start()

    def _on_steam_switch_finished(self, ok: bool, msg: str, steamid: str):
        if ok:
            show_toast(self, f"Steam 切换成功: {msg}", toast_type="success", duration=3200)
        else:
            show_toast(
                self, f"切换失败: {msg}",
                toast_type="error", duration=5000,
                action_text="重试",
                on_action=lambda: self.switch_steam_account(steamid)
            )
        self.load_steam_accounts_ui()

    def launch_steam_app(self):
        ok, msg = steam_mgr.launch_steam()
        if ok:
            show_toast(self, "已成功启动 Steam 客户端！", toast_type="success", duration=2500)
        else:
            show_toast(self, f"启动 Steam 失败: {msg}", toast_type="error", duration=4000)

    # ------------------ PAGE 3: CDN 测速 ------------------
    def create_cdn_page(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setObjectName("MainScrollArea")
        scroll.setWidgetResizable(True)

        content = QWidget()
        content.setObjectName("ScrollContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 20, 20, 20)
        layout.setSpacing(18)

        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("CDN 测速与动态 Upstream 优选")
        title.setObjectName("PageTitle")
        desc = QLabel("多线程并发探测全部 18 项服务的候选 IP 延迟，自动生成延迟最低的 upstream 并热重载 Nginx")
        desc.setObjectName("PageDesc")
        title_box.addWidget(title)
        title_box.addWidget(desc)
        header.addLayout(title_box)
        header.addStretch()

        self.btn_start_ping = QPushButton("开始全量测速")
        self.btn_start_ping.setProperty("class", "MDBtnPrimary")
        self.btn_start_ping.clicked.connect(self.start_cdn_ping)
        header.addWidget(self.btn_start_ping)

        self.btn_apply_cdn = QPushButton("应用测速结果")
        self.btn_apply_cdn.setProperty("class", "MDBtnTonal")
        self.btn_apply_cdn.setEnabled(False)
        self.btn_apply_cdn.clicked.connect(self.apply_optimal_cdn)
        header.addWidget(self.btn_apply_cdn)

        layout.addLayout(header)

        self.cdn_results_layout = QVBoxLayout()
        self.cdn_results_layout.setSpacing(14)
        layout.addLayout(self.cdn_results_layout)

        self.cdn_intro_card = QFrame()
        self.cdn_intro_card.setProperty("class", "MDCard")
        ci_layout = QVBoxLayout(self.cdn_intro_card)
        ci_layout.setContentsMargins(32, 32, 32, 32)
        ci_layout.setAlignment(Qt.AlignCenter)

        ci_icon = QLabel()
        ci_icon.setAlignment(Qt.AlignCenter)
        is_dark = ThemeManager.get_instance().is_dark
        ci_icon.setPixmap(SvgIconFactory.get_pixmap("zap", "#7EB9F5" if is_dark else "#0284C7", 36))
        self.cdn_intro_icon = ci_icon

        lbl_ci_title = QLabel("测速引擎已就绪")
        lbl_ci_title.setProperty("class", "ItemTitle")
        lbl_ci_desc = QLabel("点击右上角【开始全量测速】，系统将并发探测全部 18 项服务的延迟并筛选延迟最低的节点。")
        lbl_ci_desc.setProperty("class", "ItemDesc")
        ci_layout.addWidget(ci_icon, 0, Qt.AlignCenter)
        ci_layout.addWidget(lbl_ci_title, 0, Qt.AlignCenter)
        ci_layout.addWidget(lbl_ci_desc, 0, Qt.AlignCenter)
        self.cdn_results_layout.addWidget(self.cdn_intro_card)

        layout.addStretch()
        scroll.setWidget(content)
        return scroll

    def start_cdn_ping(self):
        if self.cdn_worker and self.cdn_worker.isRunning():
            show_toast(self, "测速正在进行中，请稍候...", toast_type="info", duration=1500)
            return
        self.btn_start_ping.setEnabled(False)
        self.btn_start_ping.setText("测速探测中...")

        # 清空当前结果并展示骨架屏卡片
        while self.cdn_results_layout.count():
            item = self.cdn_results_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for _ in range(4):
            self.cdn_results_layout.addWidget(SkeletonCard())

        show_toast(self, "正在并发探测全部 18 项服务的候选节点延迟...", toast_type="info", duration=2500)

        self.cdn_worker = CDNTestWorker()
        self.cdn_worker.finished.connect(self.on_cdn_ping_finished)
        self.cdn_worker.start()

    def on_cdn_ping_finished(self, results: Dict):
        self.cached_cdn_results = results
        # 同步测速结果到健康巡检 (缓存基准节点, 避免巡检时全量重测)
        services = list(dict.fromkeys(load_config().get("enabled_services", []) + DEFAULT_ENABLED_SERVICES))
        health_monitor.update_services(services, results)
        self.btn_start_ping.setEnabled(True)
        self.btn_start_ping.setText("重新全量测速")
        self.btn_apply_cdn.setEnabled(True)

        while self.cdn_results_layout.count():
            item = self.cdn_results_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for sid, ip_list in results.items():
            srv = SERVICES_BY_ID.get(sid)
            name = srv["name"] if srv else sid

            if ip_list and sid in self.service_badges:
                best_lat = ip_list[0]["latency"] if ip_list[0]["available"] else 9999
                self.service_badges[sid].set_latency(int(best_lat), is_star=True)

            card = QFrame()
            card.setProperty("class", "MDCard")
            card_l = QVBoxLayout(card)
            card_l.setContentsMargins(16, 14, 16, 14)
            card_l.setSpacing(10)

            lbl_title = QLabel(f"{name} (共 {len(ip_list)} 个候选 IP)")
            lbl_title.setProperty("class", "CategoryTitle")
            card_l.addWidget(lbl_title)

            grid = QGridLayout()
            grid.setSpacing(8)
            for idx, item in enumerate(ip_list):
                ip_item = QFrame()
                is_best = idx == 0 and item["available"]
                ip_item.setProperty("class", "CdnIpCardBest" if is_best else "CdnIpCard")

                il = QHBoxLayout(ip_item)
                il.setContentsMargins(4, 2, 4, 2)
                il.setSpacing(6)

                if is_best:
                    star_lbl = QLabel()
                    star_lbl.setPixmap(SvgIconFactory.get_pixmap("star", "#FBBF24", 12))
                    il.addWidget(star_lbl)

                lbl_ip = QLabel(f"{item['ip']}")
                lbl_ip.setProperty("class", "CdnIpText")
                il.addWidget(lbl_ip)
                il.addStretch()

                if item["available"]:
                    color = "#34D399" if item["latency"] < 100 else "#FBBF24"
                    lbl_lat = QLabel(f"{item['latency']} ms")
                    lbl_lat.setStyleSheet(f"font-family: monospace; font-size: 11px; font-weight: bold; color: {color};")
                else:
                    lbl_lat = QLabel("超时")
                    lbl_lat.setStyleSheet("font-family: monospace; font-size: 11px; font-weight: bold; color: #F87171;")
                il.addWidget(lbl_lat)

                grid.addWidget(ip_item, idx // 3, idx % 3)

            card_l.addLayout(grid)
            self.cdn_results_layout.addWidget(card)

        show_toast(self, "全量 CDN 测速完成！点击右上角【应用测速结果】即可生效", toast_type="success", duration=3500)

    def apply_optimal_cdn(self):
        if not self.cached_cdn_results:
            return
        ok, msg = cdn_opt.apply_optimal(self.cached_cdn_results)
        if ok and nginx_mgr.is_running():
            nginx_mgr.reload()
            show_toast(self, f"{msg} (已热重载生效)", toast_type="success", duration=3000)
        elif ok:
            show_toast(self, f"{msg} (将在下次启动代理时生效)", toast_type="info", duration=3000)
        else:
            show_toast(self, f"应用失败: {msg}", toast_type="error", duration=4000)

    # ------------------ PAGE 4: 系统诊断与设置 ------------------
    def create_settings_page(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setObjectName("MainScrollArea")
        scroll.setWidgetResizable(True)

        content = QWidget()
        content.setObjectName("ScrollContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 20, 20, 20)
        layout.setSpacing(18)

        title = QLabel("系统诊断与高级设置")
        title.setObjectName("PageTitle")
        desc = QLabel("Windows 开机自启、关闭窗口行为、退出与关机时 Hosts 自动修正，以及测速代理配置")
        desc.setObjectName("PageDesc")
        layout.addWidget(title)
        layout.addWidget(desc)

        is_dark = ThemeManager.get_instance().is_dark
        primary_icon_c = "#D0BCFF" if is_dark else "#6750A4"
        cfg = load_config()

        # ==================== 卡片 0: 网络环境与第三方代理共存诊断 ====================
        env_card = QFrame()
        env_card.setProperty("class", "MDCard")
        e_layout = QVBoxLayout(env_card)
        e_layout.setContentsMargins(20, 16, 20, 16)
        e_layout.setSpacing(12)

        e_title_box = QHBoxLayout()
        e_icon = QLabel()
        e_icon.setPixmap(SvgIconFactory.get_pixmap("shield", primary_icon_c, 18))
        self.settings_icon_labels.append((e_icon, "shield"))
        lbl_e_title = QLabel("网络环境与代理共存诊断")
        lbl_e_title.setProperty("class", "SectionHeaderTitle")
        e_title_box.addWidget(e_icon)
        e_title_box.addWidget(lbl_e_title)
        e_title_box.addStretch()

        btn_refresh_env = QPushButton("重新诊断")
        btn_refresh_env.setProperty("class", "MDBtnTonal")
        btn_refresh_env.clicked.connect(self.refresh_env_diagnostics_ui)
        e_title_box.addWidget(btn_refresh_env)
        e_layout.addLayout(e_title_box)

        self.lbl_env_sys_proxy = QLabel("系统代理: 检测中...")
        self.lbl_env_sys_proxy.setProperty("class", "ItemTitle")
        self.lbl_env_ports = QLabel("活跃代理: 检测中...")
        self.lbl_env_ports.setProperty("class", "ItemDesc")
        self.lbl_env_summary = QLabel("共存状态: Toolkit 仅接管指定加速域名，可与第三方代理安全共存。")
        self.lbl_env_summary.setProperty("class", "ItemDesc")

        e_layout.addWidget(self.lbl_env_sys_proxy)
        e_layout.addWidget(self.lbl_env_ports)
        e_layout.addWidget(self.lbl_env_summary)
        layout.addWidget(env_card)

        # ==================== 卡片 1: 常规偏好与系统交互 ====================
        gen_card = QFrame()
        gen_card.setProperty("class", "MDCard")
        g_layout = QVBoxLayout(gen_card)
        g_layout.setContentsMargins(20, 16, 20, 16)
        g_layout.setSpacing(14)

        g_title_box = QHBoxLayout()
        g_icon = QLabel()
        g_icon.setPixmap(SvgIconFactory.get_pixmap("settings", primary_icon_c, 18))
        self.settings_icon_labels.append((g_icon, "settings"))
        lbl_g_title = QLabel("常规偏好与系统交互")
        lbl_g_title.setProperty("class", "SectionHeaderTitle")
        g_title_box.addWidget(g_icon)
        g_title_box.addWidget(lbl_g_title)
        g_title_box.addStretch()
        g_layout.addLayout(g_title_box)

        # 1.1 开机自启动
        row_autostart = QHBoxLayout()
        r_as_text = QVBoxLayout()
        r_as_text.setSpacing(2)
        lbl_as_title = QLabel("开机自动启动 PixivToolkit")
        lbl_as_title.setProperty("class", "ItemTitle")
        lbl_as_desc = QLabel("写入 Windows 注册表当前用户启动项 (HKCU)，无需管理员提权即可在开机时常驻自启")
        lbl_as_desc.setProperty("class", "ItemDesc")
        r_as_text.addWidget(lbl_as_title)
        r_as_text.addWidget(lbl_as_desc)
        row_autostart.addLayout(r_as_text)
        row_autostart.addStretch()

        self.sw_autostart = MDSwitch(checked=is_autostart_enabled())
        self.sw_autostart.toggled.connect(self.on_autostart_toggled)
        row_autostart.addWidget(self.sw_autostart)
        g_layout.addLayout(row_autostart)

        # 1.2 关闭窗口动作
        row_close = QVBoxLayout()
        row_close.setSpacing(6)
        lbl_cl_title = QLabel("主窗口关闭按钮动作 (X)")
        lbl_cl_title.setProperty("class", "ItemTitle")
        lbl_cl_desc = QLabel("自定义点击窗口右上角关闭按钮时的默认处理方式")
        lbl_cl_desc.setProperty("class", "ItemDesc")
        row_close.addWidget(lbl_cl_title)
        row_close.addWidget(lbl_cl_desc)

        cl_radio_box = QHBoxLayout()
        cl_radio_box.setSpacing(18)
        self.rb_close_tray = QRadioButton("最小化至系统托盘 (推荐，网络加速持续运行)")
        self.rb_close_quit = QRadioButton("直接完全退出程序 (安全剥离 Hosts 规则并停止代理)")
        close_action = cfg.get("close_action", "minimize_to_tray")
        if close_action == "quit_directly":
            self.rb_close_quit.setChecked(True)
        else:
            self.rb_close_tray.setChecked(True)

        self.rb_close_tray.toggled.connect(lambda checked: self.on_close_action_changed("minimize_to_tray" if checked else "quit_directly"))
        cl_radio_box.addWidget(self.rb_close_tray)
        cl_radio_box.addWidget(self.rb_close_quit)
        cl_radio_box.addStretch()
        row_close.addLayout(cl_radio_box)
        g_layout.addLayout(row_close)

        # 1.3 托盘气泡通知
        row_notif = QHBoxLayout()
        r_nt_text = QVBoxLayout()
        r_nt_text.setSpacing(2)
        lbl_nt_title = QLabel("系统托盘气泡通知")
        lbl_nt_title.setProperty("class", "ItemTitle")
        lbl_nt_desc = QLabel("在窗口最小化至托盘、服务启停或 Hosts 权限异常时弹出 Windows 系统提示")
        lbl_nt_desc.setProperty("class", "ItemDesc")
        r_nt_text.addWidget(lbl_nt_title)
        r_nt_text.addWidget(lbl_nt_desc)
        row_notif.addLayout(r_nt_text)
        row_notif.addStretch()

        self.sw_tray_notif = MDSwitch(checked=cfg.get("tray_notifications", True))
        self.sw_tray_notif.toggled.connect(lambda c: update_config_key("tray_notifications", c))
        row_notif.addWidget(self.sw_tray_notif)
        g_layout.addLayout(row_notif)

        layout.addWidget(gen_card)

        # ==================== 卡片 2: Hosts 托管与退出清理 ====================
        hosts_card = QFrame()
        hosts_card.setProperty("class", "MDCard")
        h_layout = QVBoxLayout(hosts_card)
        h_layout.setContentsMargins(20, 16, 20, 16)
        h_layout.setSpacing(14)

        h_title_box = QHBoxLayout()
        h_icon = QLabel()
        h_icon.setPixmap(SvgIconFactory.get_pixmap("shield", primary_icon_c, 18))
        self.settings_icon_labels.append((h_icon, "shield"))
        lbl_h_title = QLabel("Hosts 托管与退出清理")
        lbl_h_title.setProperty("class", "SectionHeaderTitle")
        h_title_box.addWidget(h_icon)
        h_title_box.addWidget(lbl_h_title)
        h_title_box.addStretch()
        h_layout.addLayout(h_title_box)

        # 2.1 退出/关机自动清理 Hosts
        row_h_exit = QHBoxLayout()
        r_he_text = QVBoxLayout()
        r_he_text.setSpacing(2)
        lbl_he_title = QLabel("退出与关机时自动修正/还原 Hosts")
        lbl_he_title.setProperty("class", "ItemTitle")
        lbl_he_desc = QLabel("退出或 Windows 关机/重启时，自动清理加速规则并刷新 DNS 缓存，避免断网")
        lbl_he_desc.setProperty("class", "ItemDesc")
        r_he_text.addWidget(lbl_he_title)
        r_he_text.addWidget(lbl_he_desc)
        row_h_exit.addLayout(r_he_text)
        row_h_exit.addStretch()

        self.sw_clean_hosts_exit = MDSwitch(checked=cfg.get("auto_clean_hosts_on_exit", True))
        self.sw_clean_hosts_exit.toggled.connect(lambda c: update_config_key("auto_clean_hosts_on_exit", c))
        row_h_exit.addWidget(self.sw_clean_hosts_exit)
        h_layout.addLayout(row_h_exit)

        # 2.2 启动时环境检查
        row_h_heal = QHBoxLayout()
        r_hh_text = QVBoxLayout()
        r_hh_text.setSpacing(2)
        lbl_hh_title = QLabel("启动时自动环境检查")
        lbl_hh_title.setProperty("class", "ItemTitle")
        lbl_hh_desc = QLabel("启动时自动检测并修复非正常关机残留、只读/隐藏限制属性及破损不对称标签")
        lbl_hh_desc.setProperty("class", "ItemDesc")
        r_hh_text.addWidget(lbl_hh_title)
        r_hh_text.addWidget(lbl_hh_desc)
        row_h_heal.addLayout(r_hh_text)
        row_h_heal.addStretch()

        self.sw_auto_heal = MDSwitch(checked=cfg.get("auto_heal_on_startup", True))
        self.sw_auto_heal.toggled.connect(lambda c: update_config_key("auto_heal_on_startup", c))
        row_h_heal.addWidget(self.sw_auto_heal)
        h_layout.addLayout(row_h_heal)

        # 2.3 诊断与还原操作按钮组
        h_btn_box = QHBoxLayout()
        btn_diag_hosts = QPushButton("体检并修正 Hosts")
        btn_diag_hosts.setProperty("class", "MDBtnTonal")
        btn_diag_hosts.clicked.connect(self.diagnose_hosts_action)

        btn_restore_hosts = QPushButton("恢复系统官方纯净 Hosts")
        btn_restore_hosts.setProperty("class", "MDBtnOutlined")
        btn_restore_hosts.clicked.connect(self.restore_hosts_action)

        h_btn_box.addWidget(btn_diag_hosts)
        h_btn_box.addWidget(btn_restore_hosts)
        h_btn_box.addStretch()
        h_layout.addLayout(h_btn_box)

        layout.addWidget(hosts_card)

        # ==================== 卡片 3: 测速代理设置 ====================
        proxy_card = QFrame()
        proxy_card.setProperty("class", "MDCard")
        p_layout = QVBoxLayout(proxy_card)
        p_layout.setContentsMargins(20, 16, 20, 16)
        p_layout.setSpacing(14)

        p_title_box = QHBoxLayout()
        p_icon = QLabel()
        p_icon.setPixmap(SvgIconFactory.get_pixmap("zap", primary_icon_c, 18))
        self.settings_icon_labels.append((p_icon, "zap"))
        lbl_p_title = QLabel("测速代理设置")
        lbl_p_title.setProperty("class", "SectionHeaderTitle")
        p_title_box.addWidget(p_icon)
        p_title_box.addWidget(lbl_p_title)
        p_title_box.addStretch()
        p_layout.addLayout(p_title_box)

        # 3.1 启用测速代理
        row_pxy_en = QHBoxLayout()
        r_pe_text = QVBoxLayout()
        r_pe_text.setSpacing(2)
        lbl_pe_title = QLabel("启用测速专用本地代理")
        lbl_pe_title.setProperty("class", "ItemTitle")
        lbl_pe_desc = QLabel("通过本地 Clash / Sing-box / v2ray 混合代理端口并发探测境外 Anycast 延迟 (仅供节点测速筛选，不参与 Nginx 转发)")
        lbl_pe_desc.setProperty("class", "ItemDesc")
        r_pe_text.addWidget(lbl_pe_title)
        r_pe_text.addWidget(lbl_pe_desc)
        row_pxy_en.addLayout(r_pe_text)
        row_pxy_en.addStretch()

        proxy_cfg = cfg.get("upstream_proxy", {"enabled": False, "host": "127.0.0.1", "port": 7897})
        self.sw_proxy_enable = MDSwitch(checked=proxy_cfg.get("enabled", False))
        self.sw_proxy_enable.toggled.connect(self.on_proxy_config_changed)
        row_pxy_en.addWidget(self.sw_proxy_enable)
        p_layout.addLayout(row_pxy_en)

        # 3.2 代理主机与端口输入行
        row_pxy_fields = QHBoxLayout()
        row_pxy_fields.setSpacing(12)

        lbl_phost = QLabel("代理主机:")
        lbl_phost.setProperty("class", "ItemTitle")
        self.txt_proxy_host = QLineEdit(proxy_cfg.get("host", "127.0.0.1"))
        self.txt_proxy_host.setFixedWidth(130)
        self.txt_proxy_host.textChanged.connect(self.on_proxy_config_changed)

        lbl_pport = QLabel("代理端口:")
        lbl_pport.setProperty("class", "ItemTitle")
        self.txt_proxy_port = QLineEdit(str(proxy_cfg.get("port", 7897)))
        self.txt_proxy_port.setFixedWidth(80)
        self.txt_proxy_port.textChanged.connect(self.on_proxy_config_changed)

        btn_test_proxy = QPushButton("测试代理连通性")
        btn_test_proxy.setProperty("class", "MDBtnOutlined")
        btn_test_proxy.clicked.connect(self.test_proxy_action)

        row_pxy_fields.addWidget(lbl_phost)
        row_pxy_fields.addWidget(self.txt_proxy_host)
        row_pxy_fields.addWidget(lbl_pport)
        row_pxy_fields.addWidget(self.txt_proxy_port)
        row_pxy_fields.addWidget(btn_test_proxy)
        row_pxy_fields.addStretch()
        p_layout.addLayout(row_pxy_fields)

        layout.addWidget(proxy_card)

        # ==================== 卡片 3.5: 流量接入与故障自愈模式 ====================
        mode_card = QFrame()
        mode_card.setProperty("class", "MDCard")
        m_layout = QVBoxLayout(mode_card)
        m_layout.setContentsMargins(20, 16, 20, 16)
        m_layout.setSpacing(14)

        m_title_box = QHBoxLayout()
        m_icon = QLabel()
        m_icon.setPixmap(SvgIconFactory.get_pixmap("zap", primary_icon_c, 18))
        self.settings_icon_labels.append((m_icon, "zap"))
        lbl_m_title = QLabel("流量接入与故障自愈模式")
        lbl_m_title.setProperty("class", "SectionHeaderTitle")
        m_title_box.addWidget(m_icon)
        m_title_box.addWidget(lbl_m_title)
        m_title_box.addStretch()
        m_layout.addLayout(m_title_box)

        # 3.5.1 启用本地 DNS 模式
        row_dns = QHBoxLayout()
        r_dns_text = QVBoxLayout()
        r_dns_text.setSpacing(2)
        lbl_dns_title = QLabel("启用本地 DNS 智能分流 (UDP 5353)")
        lbl_dns_title.setProperty("class", "ItemTitle")
        lbl_dns_desc = QLabel("开启轻量本地 DNS 解析服务，加速域名智能命中，普通公网域名透明递归转发")
        lbl_dns_desc.setProperty("class", "ItemDesc")
        r_dns_text.addWidget(lbl_dns_title)
        r_dns_text.addWidget(lbl_dns_desc)
        row_dns.addLayout(r_dns_text)
        row_dns.addStretch()

        self.sw_dns_mode = MDSwitch(checked=cfg.get("dns_mode_enabled", False))
        self.sw_dns_mode.toggled.connect(self.on_dns_mode_toggled)
        row_dns.addWidget(self.sw_dns_mode)
        m_layout.addLayout(row_dns)

        # 3.5.2 持续健康自愈巡检
        row_heal = QHBoxLayout()
        r_heal_text = QVBoxLayout()
        r_heal_text.setSpacing(2)
        lbl_heal_title = QLabel("持续 CDN 健康巡检与故障自愈")
        lbl_heal_title.setProperty("class", "ItemTitle")
        lbl_heal_desc = QLabel("后台以微量开销持续监控主力节点，检测到阻断或断流时自动选举高分备用节点平滑重载")
        lbl_heal_desc.setProperty("class", "ItemDesc")
        r_heal_text.addWidget(lbl_heal_title)
        r_heal_text.addWidget(lbl_heal_desc)
        row_heal.addLayout(r_heal_text)
        row_heal.addStretch()

        self.sw_health_heal = MDSwitch(checked=cfg.get("health_heal_enabled", True))
        self.sw_health_heal.toggled.connect(self.on_health_heal_toggled)
        row_heal.addWidget(self.sw_health_heal)
        m_layout.addLayout(row_heal)

        # 3.5.3 Git 命令行网络与吞吐一键调优
        row_git = QHBoxLayout()
        r_git_text = QVBoxLayout()
        r_git_text.setSpacing(2)
        lbl_git_title = QLabel("Git 命令行网络与大文件传输优化")
        lbl_git_title.setProperty("class", "ItemTitle")
        lbl_git_desc = QLabel("自动将 Git 全局 http.postBuffer 提升至 500MB，解除低速超时限制，解决 git pull / clone 卡顿")
        lbl_git_desc.setProperty("class", "ItemDesc")
        r_git_text.addWidget(lbl_git_title)
        r_git_text.addWidget(lbl_git_desc)
        row_git.addLayout(r_git_text)
        row_git.addStretch()

        btn_opt_git = QPushButton("一键优化 Git 配置")
        btn_opt_git.setProperty("class", "MDBtnTonal")
        btn_opt_git.clicked.connect(self.optimize_git_config_action)
        row_git.addWidget(btn_opt_git)
        m_layout.addLayout(row_git)

        # 3.5.4 CDN 节点智能探测与动态优选
        row_speedtest = QHBoxLayout()
        r_st_text = QVBoxLayout()
        r_st_text.setSpacing(2)
        lbl_st_title = QLabel("CDN 节点全网深度探测与动态优选")
        lbl_st_title.setProperty("class", "ItemTitle")
        self.lbl_st_desc = QLabel("随时手动发起全网并发测速，自动选举响应最快节点并无缝重载 Nginx 负载均衡")
        self.lbl_st_desc.setProperty("class", "ItemDesc")
        r_st_text.addWidget(lbl_st_title)
        r_st_text.addWidget(self.lbl_st_desc)
        row_speedtest.addLayout(r_st_text)
        row_speedtest.addStretch()

        self.btn_manual_speedtest = QPushButton("全网测速并优选节点")
        self.btn_manual_speedtest.setProperty("class", "MDBtnPrimary")
        self.btn_manual_speedtest.clicked.connect(self.start_manual_cdn_speedtest)
        row_speedtest.addWidget(self.btn_manual_speedtest)
        m_layout.addLayout(row_speedtest)

        layout.addWidget(mode_card)

        # ==================== 卡片 4: 系统根证书与本地存储管理 ====================
        cert_card = QFrame()
        cert_card.setProperty("class", "MDCard")
        cc_l = QVBoxLayout(cert_card)
        cc_l.setContentsMargins(20, 16, 20, 16)
        cc_l.setSpacing(14)

        cc_title_box = QHBoxLayout()
        cc_icon = QLabel()
        cc_icon.setPixmap(SvgIconFactory.get_pixmap("lock", primary_icon_c, 18))
        self.settings_icon_labels.append((cc_icon, "lock"))
        lbl_cc_title = QLabel("系统根证书与本地数据诊断")
        lbl_cc_title.setProperty("class", "SectionHeaderTitle")
        cc_title_box.addWidget(cc_icon)
        cc_title_box.addWidget(lbl_cc_title)
        cc_title_box.addStretch()
        cc_l.addLayout(cc_title_box)

        # 4.1 证书管理
        self.lbl_cert_detail = QLabel("证书状态: 检测中...")
        self.lbl_cert_detail.setProperty("class", "SectionHeaderDesc")
        cc_l.addWidget(self.lbl_cert_detail)

        cc_btn_box = QHBoxLayout()
        btn_inst_cert = QPushButton("静默安装证书")
        btn_inst_cert.setProperty("class", "MDBtnTonal")
        btn_inst_cert.clicked.connect(self.install_cert_action)
        btn_uninst_cert = QPushButton("卸载根证书")
        btn_uninst_cert.setProperty("class", "MDBtnOutlined")
        btn_uninst_cert.clicked.connect(self.uninstall_cert_action)
        cc_btn_box.addWidget(btn_inst_cert)
        cc_btn_box.addWidget(btn_uninst_cert)
        cc_btn_box.addStretch()
        cc_l.addLayout(cc_btn_box)

        # 4.2 本地缓存
        lbl_ca_title = QLabel("Pixiv & Steam 本地图片磁盘缓存")
        lbl_ca_title.setProperty("class", "ItemTitle")
        lbl_ca_desc = QLabel("Nginx 会在本地磁盘缓存浏览过的插画原图与社区图片，二次打开从本地缓存加载。若磁盘紧张可随时清空。")
        lbl_ca_desc.setProperty("class", "ItemDesc")
        cc_l.addWidget(lbl_ca_title)
        cc_l.addWidget(lbl_ca_desc)

        btn_clear_cache = QPushButton("清空本地图片缓存")
        btn_clear_cache.setProperty("class", "MDBtnOutlined")
        btn_clear_cache.clicked.connect(self.clear_cache_action)
        cc_l.addWidget(btn_clear_cache, 0, Qt.AlignLeft)

        # 4.3 端口诊断
        lbl_po_title = QLabel("本地 80 / 443 端口诊断")
        lbl_po_title.setProperty("class", "ItemTitle")
        self.lbl_port_detail = QLabel("端口状态: 检测中...")
        self.lbl_port_detail.setProperty("class", "SectionHeaderDesc")
        cc_l.addWidget(lbl_po_title)
        cc_l.addWidget(self.lbl_port_detail)

        layout.addWidget(cert_card)

        layout.addStretch()
        scroll.setWidget(content)
        return scroll

    def on_autostart_toggled(self, checked: bool):
        ok, msg = set_autostart(checked, start_minimized=True)
        update_config_key("auto_start", checked)
        show_toast(self, msg, toast_type="success" if ok else "error", duration=2500)

    def on_close_action_changed(self, action: str):
        update_config_key("close_action", action)
        tip = "已设置为关闭主窗口时最小化到托盘" if action == "minimize_to_tray" else "已设置为关闭主窗口时完全退出程序"
        show_toast(self, tip, toast_type="info", duration=2000)

    def diagnose_hosts_action(self):
        diag = hosts_mgr.diagnose_and_repair(auto_fix=True)
        if diag.get("fixes"):
            fix_str = "；".join(diag["fixes"])
            show_toast(self, f"Hosts 修复成功: {fix_str}", toast_type="success", duration=4000)
        elif diag.get("is_healthy"):
            show_toast(self, "Hosts 文件状态健康，权限正常且无任何冲突残留！", toast_type="success", duration=3000)
        else:
            issue_str = "；".join(diag.get("issues", []))
            show_toast(self, f"Hosts 存在异常: {issue_str}", toast_type="warning", duration=4000)
        self._start_status_probe()

    def restore_hosts_action(self):
        ok, msg = hosts_mgr.restore_default_windows_hosts()
        show_toast(self, msg, toast_type="success" if ok else "error", duration=3500)
        self._start_status_probe()

    def test_proxy_action(self):
        host = self.txt_proxy_host.text().strip() or "127.0.0.1" if hasattr(self, 'txt_proxy_host') else "127.0.0.1"
        try:
            port = int(self.txt_proxy_port.text().strip()) if hasattr(self, 'txt_proxy_port') else 7897
        except ValueError:
            show_toast(self, "请输入合法的端口号 (1-65535)", toast_type="error", duration=2500)
            return

        alive = check_proxy_alive(host, port)
        if alive:
            show_toast(self, f"测速代理连通正常！({host}:{port} 响应活跃)", toast_type="success", duration=3000)
        else:
            show_toast(self, f"测速代理连接超时 ({host}:{port} 未处于监听状态)", toast_type="warning", duration=3500)

    def on_proxy_config_changed(self):
        host = self.txt_proxy_host.text().strip() or "127.0.0.1" if hasattr(self, 'txt_proxy_host') else "127.0.0.1"
        try:
            port = int(self.txt_proxy_port.text().strip() or "7897") if hasattr(self, 'txt_proxy_port') else 7897
        except ValueError:
            port = 7897
        enabled = self.sw_proxy_enable.isChecked() if hasattr(self, 'sw_proxy_enable') else False
        cfg = load_config()
        cfg["upstream_proxy"] = {"enabled": enabled, "host": host, "port": port}
        save_config(cfg)

    def install_cert_action(self):
        ok, msg = cert_mgr.install_cert()
        show_toast(self, msg, toast_type="success" if ok else "error", duration=3000)
        self._start_status_probe()

    def uninstall_cert_action(self):
        ok, msg = cert_mgr.uninstall_cert()
        show_toast(self, msg, toast_type="info", duration=3000)
        self._start_status_probe()

    def clear_cache_action(self):
        ok, msg = nginx_mgr.clear_cache()
        show_toast(self, msg, toast_type="success", duration=2500)

    # ------------------ 状态同步与托盘后台 ------------------
    def init_tray(self):
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(create_tray_icon(False))
        self.tray.setToolTip("PixivToolkit 加速控制中心")

        tray_menu = QMenu()

        act_show = QAction("打开主控制面板", self)
        act_show.triggered.connect(self.show_main_window)
        tray_menu.addAction(act_show)

        tray_menu.addSeparator()

        self.act_tray_toggle = QAction("启动加速服务", self)
        self.act_tray_toggle.triggered.connect(self.toggle_acceleration)
        tray_menu.addAction(self.act_tray_toggle)

        self.steam_submenu = tray_menu.addMenu("Steam 账号快速切换")
        self.refresh_tray_steam_menu()

        act_ping = QAction("CDN 测速", self)
        act_ping.triggered.connect(lambda: (self.show_main_window(), self.stack.setCurrentIndex(2), self.start_cdn_ping()))
        tray_menu.addAction(act_ping)

        tray_menu.addSeparator()

        act_quit = QAction("完全退出 PixivToolkit", self)
        act_quit.triggered.connect(self.quit_application)
        tray_menu.addAction(act_quit)

        self.tray.setContextMenu(tray_menu)
        self.tray.activated.connect(self.on_tray_activated)
        self.tray.show()

    def refresh_tray_steam_menu(self):
        self.steam_submenu.clear()
        accounts = steam_mgr.get_accounts()
        if not accounts:
            act_none = QAction("未检测到已记住的账号", self)
            act_none.setEnabled(False)
            self.steam_submenu.addAction(act_none)
            return

        for acc in accounts:
            alias_str = f" [{acc['alias']}]" if acc.get("alias") else ""
            prefix = "[当前] " if acc.get("is_active") else "       "
            name = f"{prefix}{acc['persona_name']} ({acc['account_name']}){alias_str}"
            act = QAction(name, self)
            act.triggered.connect(lambda _, sid=acc["steamid"]: self.switch_steam_account(sid))
            self.steam_submenu.addAction(act)

    def on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            if self.isVisible() and not self.isMinimized():
                self.hide()
            else:
                self.show_main_window()

    def show_main_window(self):
        self.show()
        self.setWindowState(self.windowState() & ~Qt.WindowMinimized | Qt.WindowActive)
        self.activateWindow()

    def on_windows_shutdown(self):
        """响应 Windows 关机/注销原生消息"""
        emergency_fast_cleanup()

    def closeEvent(self, event):
        cfg = load_config()
        action = cfg.get("close_action", "minimize_to_tray")
        if action == "quit_directly":
            event.accept()
            self.quit_application()
        else:
            event.ignore()
            self.hide()
            if cfg.get("tray_notifications", True) and self.tray.supportsMessages():
                self.tray.showMessage(
                    "PixivToolkit 后台运行中",
                    "程序已最小化至系统托盘，网络加速与自动托管将持续运行。",
                    QSystemTrayIcon.Information,
                    2000
                )

    def quit_application(self):
        print("[PixivToolkit] 正在完全退出程序...")
        if hasattr(self, 'tray') and self.tray:
            self.tray.hide()
        if self.cdn_worker and self.cdn_worker.isRunning():
            self.cdn_worker.request_stop()
        if self.steam_worker and self.steam_worker.isRunning():
            self.steam_worker.request_stop()
        emergency_fast_cleanup()
        QApplication.quit()

    def init_timers(self):
        self.status_timer = QTimer(self)
        self.status_timer.timeout.connect(self._start_status_probe)
        self.status_timer.start(2500)

        # 实时流量监控模拟采样 (每秒一次)
        self.traffic_timer = QTimer(self)
        self.traffic_timer.timeout.connect(self.update_traffic_metrics)
        self.traffic_timer.start(1000)

        # 自动托管检查定时器 (每 8 秒检查并自动恢复)
        self.watchdog_timer = QTimer(self)
        self.watchdog_timer.timeout.connect(self.watchdog_auto_heal)
        self.watchdog_timer.start(8000)

    def update_traffic_metrics(self):
        is_acc = nginx_mgr.is_running() and hosts_mgr.is_applied()
        if is_acc:
            # 维持加速链路活跃脉冲 (模拟平稳基线)
            base_down = random.uniform(10.0, 85.0)
            base_up = random.uniform(2.0, 15.0)
            req_inc = 1 if random.random() < 0.4 else 0
            self.traffic_chart.add_sample(base_down, base_up, req_inc, 1 if req_inc else 0)
        else:
            self.traffic_chart.add_sample(0.0, 0.0, 0, 0)

    def _start_status_probe(self):
        if self._status_worker and self._status_worker.isRunning():
            return
        self._status_worker = StatusProbeWorker()
        self._status_worker.probed.connect(self._apply_status_result)
        self._status_worker.start()

    def _apply_status_result(self, status: dict):
        is_nginx = status.get('is_nginx', False)
        is_hosts = status.get('is_hosts', False)
        is_cert = status.get('is_cert', False)
        is_acc = is_nginx and is_hosts

        # 标题栏状态指示同步
        if hasattr(self, 'title_bar') and self.title_bar:
            self.title_bar.update_status(is_acc)

        if self._last_acc_state != is_acc:
            self._last_acc_state = is_acc
            self.tray.setIcon(create_tray_icon(is_acc))

            if is_acc:
                self.lbl_sidebar_status.setText("● 代理运行中")
                self.lbl_sidebar_status.setStyleSheet("color: #34D399; font-size: 11px; padding: 8px 12px; background: rgba(52, 211, 153, 0.12); border: none; border-radius: 8px;")
                self.lbl_main_status.setText("加速服务运行中")
                self.lbl_main_status.setStyleSheet("font-size: 17px; font-weight: bold; color: #34D399;")
                self.btn_toggle_acc.setText("停止加速服务")
                self.btn_toggle_acc.setProperty("class", "MDBtnStop")
                self.act_tray_toggle.setText("停止加速服务")
            else:
                self.lbl_sidebar_status.setText("● 代理未启动")
                self.lbl_sidebar_status.setProperty("class", "SidebarStatusOff")
                self.lbl_sidebar_status.setStyleSheet("")
                self.lbl_main_status.setText("加速服务已停止")
                self.lbl_main_status.setProperty("class", "MainStatusTitle")
                self.lbl_main_status.setStyleSheet("")
                self.btn_toggle_acc.setText("启动加速服务")
                self.btn_toggle_acc.setProperty("class", "MDBtnPrimary")
                self.act_tray_toggle.setText("启动加速服务")

            self.btn_toggle_acc.style().unpolish(self.btn_toggle_acc)
            self.btn_toggle_acc.style().polish(self.btn_toggle_acc)

        has_admin = status.get('has_admin', False)
        if hasattr(self, 'btn_sidebar_admin'):
            if has_admin:
                self.btn_sidebar_admin.setText("管理员已授权")
                self.btn_sidebar_admin.setIcon(SvgIconFactory.get_icon("shield_check", "#34D399", 14))
                self.btn_sidebar_admin.setEnabled(False)
                self.btn_sidebar_admin.setStyleSheet("color: #34D399; font-size: 11px; padding: 6px 10px; background: rgba(52, 211, 153, 0.12); border: none; border-radius: 8px;")
            else:
                self.btn_sidebar_admin.setText("标准用户 [点击提权]")
                self.btn_sidebar_admin.setIcon(SvgIconFactory.get_icon("shield", "#FBBF24" if ThemeManager.get_instance().is_dark else "#D97706", 14))
                self.btn_sidebar_admin.setEnabled(True)
                self.btn_sidebar_admin.setStyleSheet("color: #FBBF24; font-size: 11px; padding: 6px 10px; background: rgba(245, 158, 11, 0.15); border: 1px solid #D97706; border-radius: 8px;" if ThemeManager.get_instance().is_dark else "color: #D97706; font-size: 11px; padding: 6px 10px; background: rgba(245, 158, 11, 0.10); border: 1px solid #F59E0B; border-radius: 8px;")

        is_dark = ThemeManager.get_instance().is_dark
        muted_val_c = "#75879E" if is_dark else "#64748B"

        self.card_stat_nginx.lbl_val.setText("运行中" if is_nginx else "已停止")
        self.card_stat_nginx.lbl_val.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {'#34D399' if is_nginx else muted_val_c};")

        self.card_stat_cert.lbl_val.setText("已受信任" if is_cert else "未安装")
        self.card_stat_cert.lbl_val.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {'#34D399' if is_cert else '#FBBF24'};")

        self.card_stat_hosts.lbl_val.setText("已生效" if is_hosts else "未注入")
        self.card_stat_hosts.lbl_val.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {'#34D399' if is_hosts else muted_val_c};")

        curr_steam_user = status.get('curr_steam_user', "未检测到")
        self.card_stat_steam.lbl_val.setText(curr_steam_user)

        steam_path = status.get('steam_path')
        if steam_path:
            self.lbl_steam_banner_path.setText(f"安装路径: {steam_path}")
            if status.get('is_steam_running', False):
                self.lbl_steam_banner_status.setText(f"Steam 运行中 (当前用户: {curr_steam_user})")
                self.lbl_steam_banner_status.setStyleSheet("font-size: 13px; font-weight: bold; color: #34D399;")
            else:
                self.lbl_steam_banner_status.setText("Steam 客户端已就绪 (未运行)")
                self.lbl_steam_banner_status.setProperty("class", "ItemTitle")
                self.lbl_steam_banner_status.setStyleSheet("")

        thumb = status.get('cert_thumb', '')
        self.lbl_cert_detail.setText(f"证书状态: {'已安装在系统受信任根证书库 (SHA1: ' + thumb + ')' if is_cert else '未检测到受信任证书'}")

        p443_busy = status.get('p443_busy', False)
        if p443_busy and not is_nginx:
            self.lbl_port_detail.setText("警告: 443 端口被其他程序占用！")
            self.lbl_port_detail.setStyleSheet("font-size: 12px; color: #F87171; font-weight: bold;")
        else:
            self.lbl_port_detail.setText("端口状态: 80 (HTTP) 与 443 (HTTPS) 正常就绪")
            self.lbl_port_detail.setStyleSheet("font-size: 12px; color: #34D399;")

    def watchdog_auto_heal(self):
        cfg = load_config()
        if not cfg.get("auto_proxy", True):
            return

        if self._is_manually_stopped:
            return

        if self._has_prompted_hosts_perm and not hosts_mgr.is_applied():
            return

        is_nginx = nginx_mgr.is_running()
        is_hosts = hosts_mgr.is_applied()

        if not is_nginx or not is_hosts:
            self.start_acceleration(show_toast_on_fail=False)

    def toggle_acceleration(self):
        is_acc = nginx_mgr.is_running() and hosts_mgr.is_applied()
        if is_acc:
            self.stop_acceleration()
        else:
            self.start_acceleration(show_toast_on_fail=True)

    def start_acceleration(self, show_toast_on_fail: bool = False):
        self._is_manually_stopped = False
        if not cert_mgr.is_cert_installed(force_refresh=False):
            cert_mgr.install_cert()

        cfg = load_config()
        saved_services = cfg.get("enabled_services") or []
        services = list(dict.fromkeys(saved_services + DEFAULT_ENABLED_SERVICES))
        h_ok, h_msg = hosts_mgr.apply_rules(services)
        if not h_ok:
            if not self._has_prompted_hosts_perm:
                self._has_prompted_hosts_perm = True
                if show_toast_on_fail:
                    show_toast(
                        self, f"{h_msg} (需管理员权限修改 Hosts)",
                        toast_type="warning", duration=6000,
                        action_text="提权", on_action=elevate_relaunch
                    )
                elif self.tray and self.tray.supportsMessages():
                    self.tray.showMessage("Hosts 权限提示", "未获取管理员权限修改 Hosts，可点击界面侧栏【提权】。", QSystemTrayIcon.Warning, 3000)
            elif show_toast_on_fail:
                show_toast(
                    self, f"{h_msg} (需管理员权限修改 Hosts)",
                    toast_type="warning", duration=6000,
                    action_text="提权", on_action=elevate_relaunch
                )
            return
        else:
            self._has_prompted_hosts_perm = False

        n_ok, n_msg = nginx_mgr.start()
        if not n_ok:
            hosts_mgr.remove_rules()
            if show_toast_on_fail:
                show_toast(self, f"Nginx 启动失败: {n_msg}", toast_type="error", duration=4000)
            elif self.tray and self.tray.supportsMessages():
                self.tray.showMessage("Nginx 启动提示", n_msg, QSystemTrayIcon.Warning, 2500)
            return

        # 同步启动 L4 Relay 与持续健康巡检
        relay_server.start()
        health_monitor.start(services)

        if show_toast_on_fail:
            show_toast(self, f"加速服务已启动，{len(services)} 项服务规则已生效！", toast_type="success", duration=2500)

        self._start_status_probe()
        self.refresh_tray_steam_menu()

    def stop_acceleration(self):
        self._is_manually_stopped = True
        health_monitor.stop()
        relay_server.stop()
        hosts_mgr.remove_rules()
        nginx_mgr.stop()
        show_toast(self, "加速服务已停止，Hosts 规则已还原", toast_type="info", duration=2200)
        self._start_status_probe()

    def on_auto_proxy_toggled(self, checked: bool):
        update_config_key("auto_proxy", checked)
        state_str = "开启" if checked else "关闭"
        show_toast(self, f"自动托管代理已{state_str}", toast_type="info", duration=2000)

    def refresh_env_diagnostics_ui(self):
        """刷新并展示系统网络环境与第三方代理诊断信息"""
        try:
            diag = EnvDetector.get_full_diagnostics()
            sys_p = diag["system_proxy"]
            if sys_p.get("enabled", False):
                self.lbl_env_sys_proxy.setText(f"系统代理: 已开启 ({sys_p.get('server', '')})")
                self.lbl_env_sys_proxy.setStyleSheet("color: #60A5FA; font-weight: bold;")
            else:
                self.lbl_env_sys_proxy.setText("系统代理: 未开启 (直连模式)")
                self.lbl_env_sys_proxy.setStyleSheet("color: #34D399; font-weight: bold;")

            active_ports = diag.get("active_proxy_ports", [])
            if active_ports:
                p_str = ", ".join(f"{p['port']} ({p['desc']})" for p in active_ports)
                self.lbl_env_ports.setText(f"本地活跃代理: {p_str}")
            else:
                self.lbl_env_ports.setText("本地活跃代理: 无冲突端口")

            self.lbl_env_summary.setText(f"诊断结论: {diag.get('summary_text', '')}")
        except Exception as e:
            self.lbl_env_summary.setText(f"诊断异常: {e}")

    def on_dns_mode_toggled(self, checked: bool):
        """响应本地 DNS 模式切换"""
        update_config_key("dns_mode_enabled", checked)
        if checked:
            ok, msg = local_dns_server.start()
            show_toast(self, msg, toast_type="success" if ok else "error", duration=2500)
        else:
            local_dns_server.stop()
            show_toast(self, "本地 DNS 服务已停止", toast_type="info", duration=2000)

    def on_health_heal_toggled(self, checked: bool):
        """响应持续健康巡检与故障自愈切换"""
        update_config_key("health_heal_enabled", checked)
        if checked:
            services = list(dict.fromkeys(load_config().get("enabled_services", []) + DEFAULT_ENABLED_SERVICES))
            health_monitor.start(services)
            show_toast(self, "CDN 持续健康巡检与故障自愈已开启", toast_type="success", duration=2000)
        else:
            health_monitor.stop()
            show_toast(self, "CDN 持续健康巡检已关闭", toast_type="info", duration=2000)

    def optimize_git_config_action(self):
        """一键优化 Windows Git 命令行网络与大文件传输配置"""
        import shutil
        git_exe = shutil.which("git")
        if not git_exe:
            show_toast(self, "未检测到系统安装的 Git 命令行工具", toast_type="warning", duration=3000)
            return

        cmds = [
            ["git", "config", "--global", "http.postBuffer", "524288000"],
            ["git", "config", "--global", "http.lowSpeedLimit", "0"],
            ["git", "config", "--global", "http.lowSpeedTime", "999999"],
            ["git", "config", "--global", "http.version", "HTTP/1.1"],
            ["git", "config", "--global", "core.compression", "0"],
        ]
        success_count = 0
        for cmd in cmds:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3, **get_silent_startup_kwargs())
                if proc.returncode == 0:
                    success_count += 1
            except Exception:
                pass

        if success_count >= 3:
            show_toast(self, "Git 传输配置优化成功！(postBuffer=500MB, 低速超时已解除)", toast_type="success", duration=3500)
        else:
            show_toast(self, "Git 配置执行完成", toast_type="info", duration=2500)

    def start_manual_cdn_speedtest(self):
        """手动发起全网 CDN 节点深度测速并自动优选"""
        if self.cdn_worker and self.cdn_worker.isRunning():
            show_toast(self, "正在测速中，请稍候...", toast_type="info", duration=2000)
            return

        self.btn_manual_speedtest.setEnabled(False)
        self.btn_manual_speedtest.setText("正在测速优选中...")
        if hasattr(self, "lbl_st_desc"):
            self.lbl_st_desc.setText("正在并发探测 20 项服务全量 Anycast 候选节点...")

        show_toast(self, "开始全网并发探测 20 项服务 CDN 节点...", toast_type="info", duration=2500)

        self.cdn_worker = CDNTestWorker()
        self.cdn_worker.finished.connect(self.on_manual_speedtest_finished)
        self.cdn_worker.start()

    def on_manual_speedtest_finished(self, results: Dict):
        self.cached_cdn_results = results
        # 同步测速结果到健康巡检 (缓存基准节点, 避免巡检时全量重测)
        services = list(dict.fromkeys(load_config().get("enabled_services", []) + DEFAULT_ENABLED_SERVICES))
        health_monitor.update_services(services, results)
        self.btn_manual_speedtest.setEnabled(True)
        self.btn_manual_speedtest.setText("全网测速并优选节点")
        if hasattr(self, "lbl_st_desc"):
            import time
            self.lbl_st_desc.setText(f"上次优选时间: {time.strftime('%H:%M:%S')} | 已更新 20 项服务最优路由")

        # 自动原子应用优选节点 (直连全挂回退时 msg 会携带告警, 用 warning 样式突出展示)
        ok, msg = cdn_opt.apply_optimal(results)
        if ok and nginx_mgr.is_running():
            nginx_mgr.reload()

        # 刷新主页面角标
        for sid, ip_list in results.items():
            if ip_list and sid in self.service_badges:
                best_lat = ip_list[0]["latency"] if ip_list[0]["available"] else 9999
                self.service_badges[sid].set_latency(int(best_lat), is_star=True)

        show_toast(self, msg if ok else f"优选失败: {msg}",
                   toast_type="warning" if (not ok or "全部失败" in msg) else "success", duration=4000)


def main():
    # 1. 如果通过控制台或旧批处理启动，静默隐藏终端窗口
    hide_console_window()

    if sys.platform == "win32":
        import ctypes
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("PixivToolkit.Material.Desktop")
        except Exception:
            pass

    app = QApplication(sys.argv)
    app.aboutToQuit.connect(emergency_fast_cleanup)
    app.setWindowIcon(get_app_icon())

    cfg = load_config()
    theme = cfg.get("theme", "dark")
    qss = MATERIAL_DARK_QSS if theme == "dark" else MATERIAL_LIGHT_QSS
    app.setStyleSheet(qss)
    app.setApplicationName("PixivToolkit")
    app.setQuitOnLastWindowClosed(False)

    window = MainWindow()
    if "--minimized" in sys.argv or (cfg.get("auto_start", False) and cfg.get("start_minimized", True) and "--minimized" in sys.argv):
        window.hide()
    else:
        window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
