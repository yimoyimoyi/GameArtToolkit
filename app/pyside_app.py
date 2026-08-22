# -*- coding: utf-8 -*-
"""
GameArt Toolkit - Material Design 3 桌面客户端
包含:
1. Win32 DWM 原生无边框窗口，支持 Win11 Snap Layouts 贴靠菜单与 8 向缩放
2. 全局 MD3 Floating Toast Overlay 悬浮通知体系，不使用阻塞式 QMessageBox
3. Steam 账号管家卡片内 Inline Edit 备注编辑与双击卡片免密切换
4. CDN 测速骨架屏 (Skeleton Screen) 与热重载
5. 单调三次样条平滑网络监控波形图与 18 项加速规则独立/分组原子管理
"""

import os
import sys
import re
import time
import base64
import random
import atexit
import threading
from pathlib import Path
from typing import Optional, List, Dict, Set, Tuple

from PySide6.QtCore import Qt, QTimer, QThread, Signal, QEvent, QPoint, QSize, QRectF, QPointF
from PySide6.QtGui import (
    QIcon, QPixmap, QPainter, QColor, QFont, QAction, QMouseEvent,
    QLinearGradient, QPen, QBrush, QPainterPath
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QCheckBox, QFrame, QScrollArea, QStackedWidget,
    QGridLayout, QSystemTrayIcon, QMenu, QButtonGroup, QProgressBar,
    QRadioButton, QLineEdit, QComboBox, QFileDialog
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
    fast_terminate_pid, check_proxy_alive, flush_dns_native, hide_console_window,
    is_windows_dark_mode
)
from ip_pool import SERVICE_GROUPS, SERVICES_LIST, SERVICES_BY_ID, DEFAULT_ENABLED_SERVICES, TOTAL_SERVICES_COUNT
from frameless_helper import NativeFramelessHelper
from md_widgets import (
    MDSwitch, TrafficMonitorChart, LatencyBadge, TitleBar,
    show_toast, InlineEditableLabel, SkeletonCard, AnimatedStackedWidget, FlowLayout,
    NoWheelComboBox
)
from material_theme import MATERIAL_DARK_QSS, MATERIAL_LIGHT_QSS, MATERIAL_PINK_QSS, ThemeManager
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
        cert_mgr.restore_dev_environments()
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
    """创建 GameArt Toolkit 现代矢量系统托盘与任务栏图标 (支持活跃/待命动态变色)"""
    size = 32
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setRenderHint(QPainter.SmoothPixmapTransform)

    # 圆角渐变底座
    margin = 1.5
    rect = QRectF(margin, margin, size - 2 * margin, size - 2 * margin)
    radius = 7.0

    grad = QLinearGradient(0, 0, size, size)
    if is_active:
        grad.setColorAt(0.0, QColor("#047857"))
        grad.setColorAt(0.5, QColor("#059669"))
        grad.setColorAt(1.0, QColor("#10B981"))
        border_c = QColor("#34D399")
    else:
        grad.setColorAt(0.0, QColor("#0F172A"))
        grad.setColorAt(0.5, QColor("#0369A1"))
        grad.setColorAt(1.0, QColor("#0284C7"))
        border_c = QColor("#38BDF8")

    painter.setBrush(QBrush(grad))
    painter.setPen(QPen(border_c, 1.2))
    painter.drawRoundedRect(rect, radius, radius)

    # 居中绘制纯白极速矢量火箭
    scale = size / 24.0
    rocket_path = QPainterPath()
    rocket_path.moveTo(12.0 * scale, 5.0 * scale)
    rocket_path.cubicTo(14.2 * scale, 7.5 * scale, 16.0 * scale, 11.5 * scale, 16.0 * scale, 14.5 * scale)
    rocket_path.lineTo(14.0 * scale, 14.5 * scale)
    rocket_path.lineTo(13.2 * scale, 17.5 * scale)
    rocket_path.lineTo(10.8 * scale, 17.5 * scale)
    rocket_path.lineTo(10.0 * scale, 14.5 * scale)
    rocket_path.lineTo(8.0 * scale, 14.5 * scale)
    rocket_path.cubicTo(8.0 * scale, 11.5 * scale, 9.8 * scale, 7.5 * scale, 12.0 * scale, 5.0 * scale)
    rocket_path.closeSubpath()

    painter.setBrush(QBrush(QColor("#FFFFFF")))
    painter.setPen(Qt.NoPen)
    painter.drawPath(rocket_path)

    # 尾翼动力光晕
    painter.setBrush(QBrush(QColor("#38BDF8") if not is_active else QColor("#A7F3D0")))
    painter.drawEllipse(QRectF(11.0 * scale, 18.0 * scale, 2.0 * scale, 2.0 * scale))

    painter.end()
    return QIcon(pixmap)


# ==============================================================================
# 异步 Worker 线程与主窗口类
# ==============================================================================
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

    def __init__(self):
        super().__init__()
        self._stop_requested = False

    def request_stop(self):
        self._stop_requested = True

    def run(self):
        if self._stop_requested:
            return
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
        if not self._stop_requested:
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


class SingleCDNTestWorker(QThread):
    finished = Signal(str, list)

    def __init__(self, srv_id: str):
        super().__init__()
        self.srv_id = srv_id
        self._stop_requested = False

    def request_stop(self):
        self._stop_requested = True

    def run(self):
        results = cdn_opt.test_service_dual(self.srv_id)
        if not self._stop_requested:
            self.finished.emit(self.srv_id, results)


class StartupAutoCDNWorker(QThread):
    finished = Signal(dict)

    def __init__(self, filter_services: Optional[List[str]] = None):
        super().__init__()
        self.filter_services = filter_services
        self._stop_requested = False

    def request_stop(self):
        self._stop_requested = True

    def run(self):
        results = cdn_opt.test_all_services(filter_services=self.filter_services)
        if not self._stop_requested:
            self.finished.emit(results)


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
        lbl_persona.setWordWrap(True)
        lbl_acc_name = QLabel(f"登录名: {acc.get('account_name', '')}")
        lbl_acc_name.setProperty("class", "AccountSteamId")
        lbl_acc_name.setWordWrap(True)

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
        lbl_time.setWordWrap(True)
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
    GameArt Toolkit 主窗口 (无边框与 Material 3 客户端)
    """
    def __init__(self):
        super().__init__()
        self.resize(1200, 800)
        self.setMinimumSize(1080, 680)
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
        self.service_icon_labels: Dict[str, Tuple[QLabel, str]] = {}
        self.nav_btns: List[Tuple[QPushButton, str]] = []
        self.group_icon_labels: Dict[str, Tuple[QLabel, str]] = {}
        self.settings_icon_labels: List[Tuple[QLabel, str]] = []
        self.cdn_intro_icon: Optional[QLabel] = None
        self.lbl_main_icon: Optional[QLabel] = None
        self.lbl_sidebar_logo: Optional[QLabel] = None

        # 搜索与单项测速引用
        self.service_cards: Dict[str, QFrame] = {}
        self.group_cards: Dict[str, QFrame] = {}
        self.cdn_card_widgets: Dict[str, QFrame] = {}
        self.cdn_single_buttons: Dict[str, QPushButton] = {}
        self._single_cdn_workers: Dict[str, SingleCDNTestWorker] = {}
        self._startup_cdn_worker: Optional[StartupAutoCDNWorker] = None

        # 1. 注册 Win32 原生无边框辅助器
        self.frameless_helper = NativeFramelessHelper(self)

        # 2. 构建界面组件
        self.init_ui()
        self.init_tray()
        self.init_timers()

        cfg = load_config()
        theme_mode = cfg.get("theme_mode", "dark")
        if theme_mode == "system":
            current_theme = "dark" if is_windows_dark_mode() else "light"
        else:
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

        # 5. 启动时后台静默 CDN 测速并优选 (延迟 2.5 秒，避开启动竞争高峰)
        if cfg.get("auto_cdn_optimize_on_startup", True):
            QTimer.singleShot(2500, self.trigger_startup_auto_cdn)

    def _update_service_icon(self, sid: str, is_checked: bool):
        """根据开关状态与当前主题动态调整服务卡片图标色彩"""
        if sid not in self.service_icon_labels or not SvgIconFactory:
            return
        lbl, icon_name = self.service_icon_labels[sid]
        tm = ThemeManager.get_instance()
        palette = tm.get_palette()
        if is_checked:
            color = palette.get("primary", "#7EB9F5")
        else:
            color = palette.get("text_muted", "#94A3B8")
        lbl.setPixmap(SvgIconFactory.get_pixmap(icon_name, color, 20))

    def on_theme_changed(self, new_theme: str):
        """响应全局主题变更广播 (支持标题栏与设置页双向同步)"""
        is_dark = (new_theme == "dark")
        if self.frameless_helper:
            self.frameless_helper.set_immersive_dark_mode(is_dark)
        
        cfg = load_config()
        cfg["theme"] = new_theme
        if cfg.get("theme_mode") != "system":
            cfg["theme_mode"] = new_theme
        save_config(cfg)
        
        # 同步更新设置页面下拉框选中项
        if hasattr(self, "cmb_theme_mode") and self.cmb_theme_mode:
            self.cmb_theme_mode.blockSignals(True)
            if new_theme == "light":
                self.cmb_theme_mode.setCurrentIndex(1)
            elif new_theme == "pink":
                self.cmb_theme_mode.setCurrentIndex(2)
            else:
                self.cmb_theme_mode.setCurrentIndex(0)
            self.cmb_theme_mode.blockSignals(False)

        # 刷新所有静态 SVG 图标与资源
        self.refresh_theme_assets(new_theme)
        # 动态刷新原位样式
        self.refresh_inline_styles()

    def _render_sidebar_logo(self):
        """自绘 34x34 GameArt Toolkit 极光/樱粉品牌矢量微徽标 (侧边栏)"""
        if not getattr(self, "lbl_sidebar_logo", None):
            return
        size = 34
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setRenderHint(QPainter.SmoothPixmapTransform)

        tm = ThemeManager.get_instance()
        is_dark = tm.is_dark
        is_pink = tm.is_pink

        painter.setPen(Qt.NoPen)
        grad = QLinearGradient(0, 0, size, size)
        if is_dark:
            grad.setColorAt(0.0, QColor("#0B132B"))
            grad.setColorAt(0.5, QColor("#1C2541"))
            grad.setColorAt(1.0, QColor("#7EB9F5"))
            border_c = QColor(255, 255, 255, 30)
        elif is_pink:
            grad.setColorAt(0.0, QColor("#BE123C"))
            grad.setColorAt(0.5, QColor("#E11D48"))
            grad.setColorAt(1.0, QColor("#FDA4AF"))
            border_c = QColor("#FECDD3")
        else:
            grad.setColorAt(0.0, QColor("#0369A1"))
            grad.setColorAt(0.5, QColor("#0284C7"))
            grad.setColorAt(1.0, QColor("#38BDF8"))
            border_c = QColor("#BAE0FD")

        painter.setBrush(QBrush(grad))
        painter.setPen(QPen(border_c, 1.0))
        painter.drawRoundedRect(QRectF(1, 1, size - 2, size - 2), 8.0, 8.0)

        # 居中纯白极速火箭与双翼徽标
        scale = size / 24.0
        rocket_path = QPainterPath()
        rocket_path.moveTo(12.0 * scale, 4.5 * scale)
        rocket_path.cubicTo(14.5 * scale, 7.5 * scale, 16.5 * scale, 12.0 * scale, 16.5 * scale, 15.0 * scale)
        rocket_path.lineTo(14.5 * scale, 15.0 * scale)
        rocket_path.lineTo(13.5 * scale, 18.0 * scale)
        rocket_path.lineTo(10.5 * scale, 18.0 * scale)
        rocket_path.lineTo(9.5 * scale, 15.0 * scale)
        rocket_path.lineTo(7.5 * scale, 15.0 * scale)
        rocket_path.cubicTo(7.5 * scale, 12.0 * scale, 9.5 * scale, 7.5 * scale, 12.0 * scale, 4.5 * scale)
        rocket_path.closeSubpath()

        painter.setBrush(QBrush(QColor("#FFFFFF")))
        painter.setPen(Qt.NoPen)
        painter.drawPath(rocket_path)

        # 尾翼发光粒子
        tail_c = QColor("#38BDF8") if is_dark else (QColor("#FFE4E6") if is_pink else QColor("#BAE6FD"))
        painter.setBrush(QBrush(tail_c))
        painter.drawEllipse(QRectF(11.0 * scale, 18.5 * scale, 2.0 * scale, 2.0 * scale))

        painter.end()
        self.lbl_sidebar_logo.setPixmap(pixmap)

    def refresh_theme_assets(self, theme_name: str):
        """批量刷新侧栏、分组卡片及设置诊断页面的矢量图标"""
        tm = ThemeManager.get_instance()
        palette = tm.get_palette()
        nav_icon_color = palette.get("nav_icon", "#CFE5FF")
        primary_icon_color = palette.get("primary", "#7EB9F5")

        # 刷新侧边栏品牌 Logo 渐变
        self._render_sidebar_logo()

        if SvgIconFactory:
            for btn, icon_name in getattr(self, "nav_btns", []):
                btn.setIcon(SvgIconFactory.get_icon(icon_name, nav_icon_color, 18))

            for grp_id, (lbl, icon_name) in getattr(self, "group_icon_labels", {}).items():
                lbl.setPixmap(SvgIconFactory.get_pixmap(icon_name, primary_icon_color, 20))

            for lbl, icon_name in getattr(self, "settings_icon_labels", []):
                lbl.setPixmap(SvgIconFactory.get_pixmap(icon_name, primary_icon_color, 18))

            if getattr(self, "cdn_intro_icon", None):
                self.cdn_intro_icon.setPixmap(SvgIconFactory.get_pixmap("zap", primary_icon_color, 36))

        
    def refresh_inline_styles(self):
        # 让下次 probe 自动使用新颜色
        self._last_acc_state = None
        self._start_status_probe()
        # 刷新 Steam 列表以重绘卡片样式
        self.load_steam_accounts_ui()
        # 刷新主控制台全部服务项延迟微徽章重绘
        for badge in self.service_badges.values():
            badge.update()
        # 刷新所有服务卡片图标颜色
        cfg_services = set(load_config().get("enabled_services", DEFAULT_ENABLED_SERVICES))
        for sid in self.service_icon_labels:
            self._update_service_icon(sid, sid in cfg_services)
        # 刷新 CDN 测速结果列表以自适应新主题的高对比度色彩
        if getattr(self, 'cached_cdn_results', None):
            self.render_cdn_results(self.cached_cdn_results)

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

        # 品牌区域 (34x34 专属矢量 Logo + 标题 + 副标题)
        brand_widget = QWidget()
        brand_layout = QHBoxLayout(brand_widget)
        brand_layout.setContentsMargins(4, 0, 4, 16)
        brand_layout.setSpacing(10)

        self.lbl_sidebar_logo = QLabel()
        self.lbl_sidebar_logo.setFixedSize(34, 34)
        self.lbl_sidebar_logo.setAlignment(Qt.AlignCenter)
        self._render_sidebar_logo()
        brand_layout.addWidget(self.lbl_sidebar_logo)

        brand_text_box = QVBoxLayout()
        brand_text_box.setSpacing(1)
        brand_title = QLabel("GameArt Toolkit")
        brand_title.setObjectName("BrandTitle")
        brand_sub = QLabel("Game & Art Accelerator")
        brand_sub.setObjectName("BrandSubtitle")
        brand_text_box.addWidget(brand_title)
        brand_text_box.addWidget(brand_sub)
        brand_layout.addLayout(brand_text_box)
        sidebar_layout.addWidget(brand_widget)

        # 导航按钮组
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        self.btn_nav_dashboard = self.create_nav_btn("加速控制台", 0, "rocket")
        self.btn_nav_steam = self.create_nav_btn("Steam 账号管家", 1, "gamepad")
        self.btn_nav_cdn = self.create_nav_btn("CDN 测速", 2, "zap")
        self.btn_nav_settings = self.create_nav_btn("系统诊断与设置", 3, "settings")

        sidebar_layout.addWidget(self.btn_nav_dashboard)
        sidebar_layout.addWidget(self.btn_nav_steam)
        sidebar_layout.addWidget(self.btn_nav_cdn)
        sidebar_layout.addWidget(self.btn_nav_settings)
        sidebar_layout.addStretch()

        # 侧栏底部权限指示
        self.btn_sidebar_admin = QPushButton("标准用户 [点击提权]")
        self.btn_sidebar_admin.setIcon(SvgIconFactory.get_icon("shield", "#FBBF24", 14))
        self.btn_sidebar_admin.setIconSize(QSize(14, 14))
        self.btn_sidebar_admin.setProperty("class", "MDBtnTonal")
        self.btn_sidebar_admin.setStyleSheet("font-size: 11px; padding: 6px 10px; border-radius: 8px;")
        self.btn_sidebar_admin.clicked.connect(elevate_relaunch)
        sidebar_layout.addWidget(self.btn_sidebar_admin)

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
        desc = QLabel(f"自动托管网络代理与 Hosts 规则，加速 {TOTAL_SERVICES_COUNT} 项海外游戏、创作与开发服务")
        desc.setObjectName("PageDesc")
        layout.addWidget(title)
        layout.addWidget(desc)

        # 1. 实时网络流量监控波形图 (MD3 单调三次样条平滑自绘控件)
        self.traffic_chart = TrafficMonitorChart()
        layout.addWidget(self.traffic_chart)

        # 2. 顶部四合一状态指示卡片
        stat_grid = QGridLayout()
        stat_grid.setSpacing(12)
        for c_idx in range(4):
            stat_grid.setColumnStretch(c_idx, 1)

        self.card_stat_nginx = self.create_stat_card("Nginx 数据平面", "检测中...", "反代引擎与磁盘缓存", "server")
        self.card_stat_cert = self.create_stat_card("Windows 根证书", "检测中...", "系统受信任证书库", "lock")
        self.card_stat_hosts = self.create_stat_card("Hosts 规则库", "未注入", f"{TOTAL_SERVICES_COUNT} 项服务规则隔离", "file_text")
        self.card_stat_steam = self.create_stat_card("Steam 活跃用户", "未登录", "支持双击免密切换", "gamepad")

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
        mc_layout.setSpacing(16)

        is_dark = ThemeManager.get_instance().is_dark
        self.lbl_main_icon = QLabel()
        self.lbl_main_icon.setFixedSize(40, 40)
        self.lbl_main_icon.setAlignment(Qt.AlignCenter)
        if SvgIconFactory:
            self.lbl_main_icon.setPixmap(SvgIconFactory.get_pixmap("rocket", "#7EB9F5" if is_dark else "#0284C7", 36))
        mc_layout.addWidget(self.lbl_main_icon)

        mc_info = QVBoxLayout()
        mc_info.setSpacing(4)
        self.lbl_main_status = QLabel("加速服务已停止")
        self.lbl_main_status.setProperty("class", "MainStatusTitle")
        self.lbl_main_sub = QLabel("点击右侧按钮开启本地代理与 Hosts 规则接管")
        self.lbl_main_sub.setProperty("class", "MainStatusSub")
        self.lbl_main_sub.setWordWrap(True)
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

        # 3.5 服务即时搜索与过滤栏
        search_box = QHBoxLayout()
        search_box.setSpacing(10)
        self.txt_service_search = QLineEdit()
        self.txt_service_search.setProperty("class", "ServiceSearchInput")
        self.txt_service_search.setPlaceholderText("快速搜索加速服务 (支持名称/描述/拼音首字母，如: GitHub / Pixiv / Steam / EA)...")
        if SvgIconFactory:
            self.txt_service_search.addAction(SvgIconFactory.get_icon("search", "#75879E" if is_dark else "#94A3B8", 16), QLineEdit.LeadingPosition)
        self.txt_service_search.setClearButtonEnabled(True)
        self.txt_service_search.textChanged.connect(self.on_service_search_changed)
        search_box.addWidget(self.txt_service_search)
        layout.addLayout(search_box)

        # 4. 18 项加速服务 (3 大分类分组卡片, FlowLayout 流式自适应排布)
        cfg_services = set(load_config().get("enabled_services", DEFAULT_ENABLED_SERVICES))

        for grp_id, grp_info in SERVICE_GROUPS.items():
            grp_card = QFrame()
            grp_card.setProperty("class", "MDCard")
            self.group_cards[grp_id] = grp_card
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
            grp_title.setWordWrap(True)
            grp_desc = QLabel(grp_info["desc"])
            grp_desc.setProperty("class", "CategoryDesc")
            grp_desc.setWordWrap(True)
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

            items_flow = FlowLayout(margin=0, h_spacing=12, v_spacing=10, min_item_width=320, max_item_width=520)

            grp_services = [s for s in SERVICES_LIST if s["group"] == grp_id]
            for idx, srv in enumerate(grp_services):
                sid = srv["id"]
                s_item = QFrame()
                s_item.setProperty("class", "ServiceItem")
                s_item.setMinimumHeight(56)
                self.service_cards[sid] = s_item
                si_layout = QHBoxLayout(s_item)
                si_layout.setContentsMargins(14, 10, 14, 10)
                si_layout.setSpacing(10)

                # 服务专属矢量图标
                is_checked = (sid in cfg_services)
                srv_icon_name = srv.get("icon", "zap")
                si_icon = QLabel()
                si_icon.setFixedSize(24, 24)
                si_icon.setAlignment(Qt.AlignCenter)
                self.service_icon_labels[sid] = (si_icon, srv_icon_name)
                self._update_service_icon(sid, is_checked)
                si_layout.addWidget(si_icon)

                si_text_box = QVBoxLayout()
                si_text_box.setSpacing(2)
                si_name = QLabel(srv["name"])
                si_name.setProperty("class", "ItemTitle")
                si_name.setWordWrap(True)
                si_desc = QLabel(srv["desc"])
                si_desc.setProperty("class", "ItemDesc")
                si_desc.setWordWrap(True)
                si_text_box.addWidget(si_name)
                si_text_box.addWidget(si_desc)
                si_layout.addLayout(si_text_box)
                si_layout.addStretch()

                cached_lats = load_config().get("cached_latencies", {})
                badge = LatencyBadge()
                badge.setCursor(Qt.PointingHandCursor)
                badge.setToolTip("点击直接进行单项独立测速与热重载")
                badge.mousePressEvent = lambda e, s=sid: self.start_single_cdn_ping(s)
                if sid in cached_lats:
                    c_info = cached_lats[sid]
                    c_lat = c_info.get("latency", -1) if isinstance(c_info, dict) else int(c_info)
                    c_proxy = c_info.get("via_proxy", False) if isinstance(c_info, dict) else False
                    badge.set_latency(int(c_lat), is_star=True, via_proxy=c_proxy)
                else:
                    badge.set_latency(-1)
                self.service_badges[sid] = badge
                si_layout.addWidget(badge)

                sw = MDSwitch(checked=is_checked)
                sw.toggled.connect(lambda c, s=sid: self.on_service_toggled(s, c))
                self.service_switches[sid] = sw
                si_layout.addWidget(sw)

                items_flow.addWidget(s_item)

            grp_card_layout.addLayout(items_flow)
            layout.addWidget(grp_card)

        layout.addStretch()
        scroll.setWidget(content)
        return scroll

    def create_stat_card(self, label: str, value: str, hint: str, icon_name: str = "zap") -> QFrame:
        card = QFrame()
        card.setProperty("class", "StatCard")
        card.setMinimumWidth(140)
        l = QVBoxLayout(card)
        l.setContentsMargins(14, 12, 14, 12)
        l.setSpacing(4)

        top_l = QHBoxLayout()
        lbl_title = QLabel(label)
        lbl_title.setProperty("class", "StatLabel")
        lbl_title.setWordWrap(True)
        top_l.addWidget(lbl_title)
        top_l.addStretch()

        icon_lbl = QLabel()
        icon_lbl.setFixedSize(18, 18)
        icon_lbl.setAlignment(Qt.AlignCenter)
        is_dark = ThemeManager.get_instance().is_dark
        if SvgIconFactory:
            icon_lbl.setPixmap(SvgIconFactory.get_pixmap(icon_name, "#7EB9F5" if is_dark else "#0284C7", 18))
        top_l.addWidget(icon_lbl)
        l.addLayout(top_l)

        lbl_val = QLabel(value)
        lbl_val.setProperty("class", "StatValue")
        lbl_val.setWordWrap(True)
        lbl_hint = QLabel(hint)
        lbl_hint.setProperty("class", "StatHint")
        lbl_hint.setWordWrap(True)

        l.addWidget(lbl_val)
        l.addWidget(lbl_hint)

        card.lbl_val = lbl_val
        card.lbl_title = lbl_title
        card.lbl_hint = lbl_hint
        card.icon_lbl = icon_lbl
        card.icon_name = icon_name
        return card

    def on_service_search_changed(self, keyword: str):
        """主控制台加速服务实时模糊搜索与分类动态折叠 (支持中文/英文/缩写别名)"""
        kw = keyword.strip().lower()
        if not kw:
            for s_card in self.service_cards.values():
                s_card.setVisible(True)
            for g_card in self.group_cards.values():
                g_card.setVisible(True)
            return

        # 别名映射辅助快速检索 (如 'gh' 匹配 github, 'px' 匹配 pixiv)
        alias_map = {
            "gh": ["github"], "px": ["pixiv"], "st": ["steam"], "hf": ["huggingface"],
            "db": ["danbooru"], "gl": ["gitlab"], "fb": ["fanbox"], "bt": ["booth"],
            "vn": ["vndb"], "ubi": ["ubisoft"], "origin": ["ea_app"],
            "ea": ["ea_app"], "art": ["pixiv", "fanbox", "booth", "danbooru"],
            "game": ["steam", "ea_app", "ubisoft"], "dev": ["github", "gitlab", "huggingface"]
        }
        expanded_keywords = [kw]
        if kw in alias_map:
            expanded_keywords.extend(alias_map[kw])

        group_has_visible = {gid: False for gid in SERVICE_GROUPS}

        for srv in SERVICES_LIST:
            sid = srv["id"]
            name = srv.get("name", "").lower()
            desc = srv.get("desc", "").lower()
            gid = srv.get("group", "")

            matched = any(
                k in sid.lower() or k in name or k in desc
                for k in expanded_keywords
            )

            if sid in self.service_cards:
                self.service_cards[sid].setVisible(matched)
                if matched:
                    group_has_visible[gid] = True

        for gid, grp_card in self.group_cards.items():
            grp_card.setVisible(group_has_visible.get(gid, False))

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
                self._update_service_icon(sid, enable)

        new_list = list(services)
        cfg["enabled_services"] = new_list
        save_config(cfg)

        if nginx_mgr.is_running():
            hosts_mgr.apply_rules(new_list)

        action_name = "启用" if enable else "禁用"
        show_toast(self, f"已{action_name} [{SERVICE_GROUPS.get(group_id, {}).get('name', group_id)}] 全部分类服务", toast_type="info", duration=2000)

    def on_service_toggled(self, service_id: str, checked: bool):
        self._update_service_icon(service_id, checked)
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

        self.accounts_container = FlowLayout(h_spacing=14, v_spacing=14, min_item_width=320, max_item_width=480)
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
            card.setMinimumWidth(320)
            card.setMaximumWidth(480)
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
        desc = QLabel(f"多线程并发探测全部 {TOTAL_SERVICES_COUNT} 项服务的候选 IP 延迟，自动生成延迟最低的 upstream 并热重载 Nginx")
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
        lbl_ci_desc = QLabel(f"点击右上角【开始全量测速】，系统将并发探测全部 {TOTAL_SERVICES_COUNT} 项服务的延迟并筛选延迟最低的节点。")
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

        show_toast(self, f"正在并发探测全部 {TOTAL_SERVICES_COUNT} 项服务的候选节点延迟...", toast_type="info", duration=2500)

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

        self.render_cdn_results(results)
        show_toast(self, "全量 CDN 测速完成！点击右上角【应用测速结果】即可生效", toast_type="success", duration=3500)

    def render_cdn_results(self, results: Dict):
        """根据当前主题 (Dark/Light) 渲染高对比度自适应测速结果列表"""
        while self.cdn_results_layout.count():
            item = self.cdn_results_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        is_dark = ThemeManager.get_instance().is_dark
        primary_c = "#7EB9F5" if is_dark else "#0284C7"
        star_color = "#FBBF24" if is_dark else "#D97706"
        new_cached_lats = {}

        for sid, ip_list in results.items():
            srv = SERVICES_BY_ID.get(sid)
            name = srv["name"] if srv else sid

            if ip_list and sid in self.service_badges:
                best_lat = ip_list[0]["latency"] if ip_list[0]["available"] else 9999
                is_proxy = (sid in cdn_opt.last_relay_services)
                self.service_badges[sid].set_latency(
                    int(best_lat),
                    is_star=True,
                    via_proxy=is_proxy
                )
                new_cached_lats[sid] = {"latency": int(best_lat), "via_proxy": is_proxy}

            card = QFrame()
            card.setProperty("class", "MDCard")
            self.cdn_card_widgets[sid] = card
            card_l = QVBoxLayout(card)
            card_l.setContentsMargins(16, 14, 16, 14)
            card_l.setSpacing(10)

            card_top = QHBoxLayout()
            lbl_title = QLabel(f"{name} (共 {len(ip_list)} 个候选 IP)")
            lbl_title.setProperty("class", "CategoryTitle")
            lbl_title.setWordWrap(True)
            card_top.addWidget(lbl_title)
            card_top.addStretch()

            btn_single = QPushButton("独立测速")
            btn_single.setIcon(SvgIconFactory.get_icon("zap", primary_c, 12) if SvgIconFactory else QIcon())
            btn_single.setProperty("class", "MDBtnTiny")
            btn_single.setCursor(Qt.PointingHandCursor)
            btn_single.setToolTip(f"仅探测 {name} 的候选 IP 延迟并热重载生效")
            btn_single.clicked.connect(lambda _, s=sid: self.start_single_cdn_ping(s))
            self.cdn_single_buttons[sid] = btn_single
            card_top.addWidget(btn_single)
            card_l.addLayout(card_top)

            grid = FlowLayout(margin=0, h_spacing=8, v_spacing=8, min_item_width=230, max_item_width=380)
            for idx, item in enumerate(ip_list):
                ip_item = QFrame()
                is_best = idx == 0 and item["available"]
                ip_item.setProperty("class", "CdnIpCardBest" if is_best else "CdnIpCard")
                ip_item.setMinimumHeight(32)

                il = QHBoxLayout(ip_item)
                il.setContentsMargins(10, 6, 10, 6)
                il.setSpacing(6)

                if is_best:
                    star_lbl = QLabel()
                    star_lbl.setPixmap(SvgIconFactory.get_pixmap("star", star_color, 12))
                    il.addWidget(star_lbl)

                lbl_ip = QLabel(f"{item['ip']}")
                lbl_ip.setProperty("class", "CdnIpText")
                il.addWidget(lbl_ip)
                il.addStretch()

                if item["available"]:
                    lat = int(item["latency"])
                    if is_dark:
                        color = "#34D399" if lat < 100 else ("#FBBF24" if lat < 250 else "#F87171")
                    else:
                        color = "#059669" if lat < 100 else ("#D97706" if lat < 250 else "#DC2626")
                    lbl_lat = QLabel(f"{lat} ms")
                    lbl_lat.setStyleSheet(f"font-family: monospace; font-size: 11px; font-weight: bold; color: {color};")
                else:
                    color = "#F87171" if is_dark else "#DC2626"
                    lbl_lat = QLabel("超时")
                    lbl_lat.setStyleSheet(f"font-family: monospace; font-size: 11px; font-weight: bold; color: {color};")
                il.addWidget(lbl_lat)

                # 显式 polish 确保动态添加时 QSS 属性选择器 100% 刷新
                ip_item.style().unpolish(ip_item)
                ip_item.style().polish(ip_item)

                grid.addWidget(ip_item)

            card_l.addLayout(grid)
            self.cdn_results_layout.addWidget(card)

        if new_cached_lats:
            cfg = load_config()
            cfg["cached_latencies"] = new_cached_lats
            save_config(cfg)

    def start_single_cdn_ping(self, sid: str):
        """单服务独立测速 (秒级并发探测 + 增量热重载)"""
        if sid in self._single_cdn_workers and self._single_cdn_workers[sid].isRunning():
            show_toast(self, f"[{SERVICES_BY_ID.get(sid, {}).get('name', sid)}] 正在测速中...", toast_type="info", duration=1500)
            return

        srv_name = SERVICES_BY_ID.get(sid, {}).get("name", sid)
        if sid in self.cdn_single_buttons:
            self.cdn_single_buttons[sid].setEnabled(False)
            self.cdn_single_buttons[sid].setText("探测中...")

        show_toast(self, f"正在对 [{srv_name}] 进行独立测速与节点优选...", toast_type="info", duration=2000)

        worker = SingleCDNTestWorker(sid)
        self._single_cdn_workers[sid] = worker
        worker.finished.connect(self.on_single_cdn_ping_finished)
        worker.start()

    def on_single_cdn_ping_finished(self, sid: str, results: List[Dict]):
        """单服务独立测速完成回调 (增量写入 upstream 并平滑生效)"""
        if sid in self._single_cdn_workers:
            self._single_cdn_workers.pop(sid, None)

        if sid in self.cdn_single_buttons:
            self.cdn_single_buttons[sid].setEnabled(True)
            self.cdn_single_buttons[sid].setText("独立测速")

        if not self.cached_cdn_results:
            self.cached_cdn_results = {}
        self.cached_cdn_results[sid] = results

        srv_name = SERVICES_BY_ID.get(sid, {}).get("name", sid)

        # 1. 增量写入 upstream 配置并热重载 Nginx
        ok, msg = cdn_opt.apply_single_optimal(sid, results)
        if ok and nginx_mgr.is_running():
            nginx_mgr.reload()

        # 2. 更新主控制台 LatencyBadge
        best_lat = 9999
        is_proxy = False
        if results and results[0].get("available"):
            best_lat = results[0]["latency"]
            is_proxy = (sid in cdn_opt.last_relay_services)

        if sid in self.service_badges:
            self.service_badges[sid].set_latency(
                int(best_lat) if best_lat != 9999 else -1,
                is_star=True,
                via_proxy=is_proxy
            )

        # 3. 持久化缓存延迟
        cfg = load_config()
        cached_lats = cfg.get("cached_latencies", {})
        cached_lats[sid] = {"latency": int(best_lat), "via_proxy": is_proxy}
        cfg["cached_latencies"] = cached_lats
        save_config(cfg)

        # 4. 若在 CDN 测速页面，局部重绘该卡片
        if self.stack.currentIndex() == 2 and self.cached_cdn_results:
            self.render_cdn_results(self.cached_cdn_results)

        if best_lat != 9999:
            show_toast(self, f"[{srv_name}] 节点优化完成！最低延迟: {int(best_lat)} ms (已热重载生效)", toast_type="success", duration=3000)
        else:
            show_toast(self, f"[{srv_name}] 节点探测超时，已回退默认候选池", toast_type="warning", duration=3500)

    def trigger_startup_auto_cdn(self):
        """启动后后台静默触发 CDN 自动测速优选 (含防抖保护与按需探测)"""
        cfg = load_config()
        if not cfg.get("auto_cdn_optimize_on_startup", True):
            return

        # 检查最小防抖时间 (默认 30 分钟)
        last_time = cfg.get("last_optimal_time", 0)
        min_interval_sec = cfg.get("auto_cdn_min_interval_minutes", 30) * 60
        now = time.time()
        if now - last_time < min_interval_sec:
            print(f"[AutoCDN] 距离上次自动测速仅 {int((now - last_time)/60)} 分钟 (< {int(min_interval_sec/60)} 分钟)，跳过启动重复测速")
            return

        only_enabled = cfg.get("auto_cdn_only_enabled", True)
        target_services = cfg.get("enabled_services", DEFAULT_ENABLED_SERVICES) if only_enabled else None

        print(f"[AutoCDN] 启动后台静默 CDN 测速 (目标: {'当前已启用服务' if only_enabled else '全量服务'})...")
        self._startup_cdn_worker = StartupAutoCDNWorker(target_services)
        self._startup_cdn_worker.finished.connect(self.on_startup_auto_cdn_finished)
        self._startup_cdn_worker.start()

    def on_startup_auto_cdn_finished(self, results: Dict):
        """启动后台静默测速完成回调 (自动应用并静默热重载)"""
        self.cached_cdn_results = results
        ok, msg = cdn_opt.apply_optimal(results)
        cfg = load_config()
        cfg["last_optimal_time"] = int(time.time())

        new_cached_lats = {}
        for sid, ip_list in results.items():
            if ip_list and sid in self.service_badges:
                best_lat = ip_list[0]["latency"] if ip_list[0]["available"] else 9999
                is_proxy = (sid in cdn_opt.last_relay_services)
                self.service_badges[sid].set_latency(
                    int(best_lat),
                    is_star=True,
                    via_proxy=is_proxy
                )
                new_cached_lats[sid] = {"latency": int(best_lat), "via_proxy": is_proxy}

        cfg["cached_latencies"] = new_cached_lats
        save_config(cfg)

        if nginx_mgr.is_running():
            nginx_mgr.reload()

        health_monitor.update_services(
            list(dict.fromkeys(cfg.get("enabled_services", []) + DEFAULT_ENABLED_SERVICES)),
            results
        )

        success_count = sum(1 for items in results.values() if items and items[0].get("available"))
        show_toast(
            self, f"已自动优选并热重载 {success_count}/{len(results)} 项服务最佳 CDN 节点",
            toast_type="success", duration=3200
        )

    def apply_optimal_cdn(self):
        if not self.cached_cdn_results:
            return
        ok, msg = cdn_opt.apply_optimal(self.cached_cdn_results)
        if ok:
            cfg = load_config()
            cfg["last_optimal_time"] = int(time.time())
            # 同步更新主控制台全部 18 项服务延迟微徽章与持久化
            saved_lats = {}
            for sid, ip_list in self.cached_cdn_results.items():
                if ip_list and sid in self.service_badges:
                    best_lat = ip_list[0]["latency"] if ip_list[0]["available"] else 9999
                    is_proxy = (sid in cdn_opt.last_relay_services)
                    self.service_badges[sid].set_latency(
                        int(best_lat),
                        is_star=True,
                        via_proxy=is_proxy
                    )
                    saved_lats[sid] = {"latency": int(best_lat), "via_proxy": is_proxy}

            cfg["cached_latencies"] = saved_lats
            save_config(cfg)

            if nginx_mgr.is_running():
                nginx_mgr.reload()
                show_toast(self, f"{msg} (已热重载生效)", toast_type="success", duration=3000)
            else:
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
        desc = QLabel("个性化外观、IPv4/IPv6 测速偏好、Steam 启动参数、自定义 DNS 及磁盘缓存维护")
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
        lbl_e_title.setWordWrap(True)
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
        self.lbl_env_sys_proxy.setWordWrap(True)
        self.lbl_env_ports = QLabel("活跃代理: 检测中...")
        self.lbl_env_ports.setProperty("class", "ItemDesc")
        self.lbl_env_ports.setWordWrap(True)
        self.lbl_env_summary = QLabel("共存状态: GameArt Toolkit 仅接管指定加速域名，可与第三方代理安全共存。")
        self.lbl_env_summary.setProperty("class", "ItemDesc")
        self.lbl_env_summary.setWordWrap(True)

        e_layout.addWidget(self.lbl_env_sys_proxy)
        e_layout.addWidget(self.lbl_env_ports)
        e_layout.addWidget(self.lbl_env_summary)
        layout.addWidget(env_card)

        # ==================== 卡片 1: 常规偏好与系统外观 ====================
        gen_card = QFrame()
        gen_card.setProperty("class", "MDCard")
        g_layout = QVBoxLayout(gen_card)
        g_layout.setContentsMargins(20, 16, 20, 16)
        g_layout.setSpacing(14)

        g_title_box = QHBoxLayout()
        g_icon = QLabel()
        g_icon.setPixmap(SvgIconFactory.get_pixmap("settings", primary_icon_c, 18))
        self.settings_icon_labels.append((g_icon, "settings"))
        lbl_g_title = QLabel("常规偏好与系统外观")
        lbl_g_title.setProperty("class", "SectionHeaderTitle")
        lbl_g_title.setWordWrap(True)
        g_title_box.addWidget(g_icon)
        g_title_box.addWidget(lbl_g_title)
        g_title_box.addStretch()
        g_layout.addLayout(g_title_box)

        # 1.1 主题模式
        row_theme = QHBoxLayout()
        r_th_text = QVBoxLayout()
        r_th_text.setSpacing(2)
        lbl_th_title = QLabel("外观主题模式")
        lbl_th_title.setProperty("class", "ItemTitle")
        lbl_th_title.setWordWrap(True)
        lbl_th_desc = QLabel("支持跟随 Windows 10/11 系统明暗模式自动切换，或强制指定深色/浅色")
        lbl_th_desc.setProperty("class", "ItemDesc")
        lbl_th_desc.setWordWrap(True)
        r_th_text.addWidget(lbl_th_title)
        r_th_text.addWidget(lbl_th_desc)
        row_theme.addLayout(r_th_text)
        row_theme.addStretch()

        self.cmb_theme_mode = NoWheelComboBox()
        self.cmb_theme_mode.addItems(["深色模式 (Dark)", "浅色模式 (Light)", "粉色模式 (Pink)", "跟随 Windows 系统 (Auto)"])
        th_mode = cfg.get("theme_mode", "dark")
        if th_mode == "light":
            self.cmb_theme_mode.setCurrentIndex(1)
        elif th_mode == "pink":
            self.cmb_theme_mode.setCurrentIndex(2)
        elif th_mode == "system":
            self.cmb_theme_mode.setCurrentIndex(3)
        else:
            self.cmb_theme_mode.setCurrentIndex(0)
        self.cmb_theme_mode.currentIndexChanged.connect(self.on_theme_mode_changed)
        row_theme.addWidget(self.cmb_theme_mode)
        g_layout.addLayout(row_theme)

        # 1.2 开机自启动
        row_autostart = QHBoxLayout()
        r_as_text = QVBoxLayout()
        r_as_text.setSpacing(2)
        lbl_as_title = QLabel("开机自动启动 GameArt Toolkit")
        lbl_as_title.setProperty("class", "ItemTitle")
        lbl_as_title.setWordWrap(True)
        lbl_as_desc = QLabel("写入 Windows 注册表当前用户启动项 (HKCU)，无需管理员提权即可在开机时常驻自启")
        lbl_as_desc.setProperty("class", "ItemDesc")
        lbl_as_desc.setWordWrap(True)
        r_as_text.addWidget(lbl_as_title)
        r_as_text.addWidget(lbl_as_desc)
        row_autostart.addLayout(r_as_text)
        row_autostart.addStretch()

        self.sw_autostart = MDSwitch(checked=is_autostart_enabled())
        self.sw_autostart.toggled.connect(self.on_autostart_toggled)
        row_autostart.addWidget(self.sw_autostart)
        g_layout.addLayout(row_autostart)

        # 1.3 启动时最小化至系统托盘 (直接在后台运行)
        row_minimized = QHBoxLayout()
        r_min_text = QVBoxLayout()
        r_min_text.setSpacing(2)
        lbl_min_title = QLabel("启动时最小化至系统托盘 (直接在后台运行)")
        lbl_min_title.setProperty("class", "ItemTitle")
        lbl_min_title.setWordWrap(True)
        lbl_min_desc = QLabel("程序启动时不显示主窗口界面，直接最小化至右下角系统托盘静默常驻")
        lbl_min_desc.setProperty("class", "ItemDesc")
        lbl_min_desc.setWordWrap(True)
        r_min_text.addWidget(lbl_min_title)
        r_min_text.addWidget(lbl_min_desc)
        row_minimized.addLayout(r_min_text)
        row_minimized.addStretch()

        self.sw_start_minimized = MDSwitch(checked=cfg.get("start_minimized", False))
        self.sw_start_minimized.toggled.connect(self.on_start_minimized_toggled)
        row_minimized.addWidget(self.sw_start_minimized)
        g_layout.addLayout(row_minimized)

        # 1.4 关闭窗口动作
        row_close = QVBoxLayout()
        row_close.setSpacing(6)
        lbl_cl_title = QLabel("主窗口关闭按钮动作 (X)")
        lbl_cl_title.setProperty("class", "ItemTitle")
        lbl_cl_title.setWordWrap(True)
        lbl_cl_desc = QLabel("自定义点击窗口右上角关闭按钮时的默认处理方式")
        lbl_cl_desc.setProperty("class", "ItemDesc")
        lbl_cl_desc.setWordWrap(True)
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

        # 1.5 系统托盘与运行气泡提示 (不再弹出提示)
        row_notif = QHBoxLayout()
        r_nt_text = QVBoxLayout()
        r_nt_text.setSpacing(2)
        lbl_nt_title = QLabel("系统托盘与运行气泡提示")
        lbl_nt_title.setProperty("class", "ItemTitle")
        lbl_nt_title.setWordWrap(True)
        lbl_nt_desc = QLabel("关闭后将彻底静默，在窗口最小化、后台运行、服务启停或异常时均不再弹出 Windows 系统提示")
        lbl_nt_desc.setProperty("class", "ItemDesc")
        lbl_nt_desc.setWordWrap(True)
        r_nt_text.addWidget(lbl_nt_title)
        r_nt_text.addWidget(lbl_nt_desc)
        row_notif.addLayout(r_nt_text)
        row_notif.addStretch()

        self.sw_tray_notif = MDSwitch(checked=cfg.get("tray_notifications", True))
        self.sw_tray_notif.toggled.connect(self.on_tray_notif_toggled)
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
        h_icon.setPixmap(SvgIconFactory.get_pixmap("file_text", primary_icon_c, 18))
        self.settings_icon_labels.append((h_icon, "file_text"))
        lbl_h_title = QLabel("Hosts 托管与退出清理")
        lbl_h_title.setProperty("class", "SectionHeaderTitle")
        lbl_h_title.setWordWrap(True)
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
        lbl_he_title.setWordWrap(True)
        lbl_he_desc = QLabel("退出或 Windows 关机/重启时，自动清理加速规则并刷新 DNS 缓存，避免断网")
        lbl_he_desc.setProperty("class", "ItemDesc")
        lbl_he_desc.setWordWrap(True)
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
        lbl_hh_title.setWordWrap(True)
        lbl_hh_desc = QLabel("启动时自动检测并修复非正常关机残留、只读/隐藏限制属性及破损不对称标签")
        lbl_hh_desc.setProperty("class", "ItemDesc")
        lbl_hh_desc.setWordWrap(True)
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

        # ==================== 卡片 3: IPv4/IPv6 协议偏好与 CDN 性能微调 ====================
        cdn_tune_card = QFrame()
        cdn_tune_card.setProperty("class", "MDCard")
        ct_layout = QVBoxLayout(cdn_tune_card)
        ct_layout.setContentsMargins(20, 16, 20, 16)
        ct_layout.setSpacing(14)

        ct_title_box = QHBoxLayout()
        ct_icon = QLabel()
        ct_icon.setPixmap(SvgIconFactory.get_pixmap("zap", primary_icon_c, 18))
        self.settings_icon_labels.append((ct_icon, "zap"))
        lbl_ct_title = QLabel("IPv4 / IPv6 协议偏好与 CDN 性能微调")
        lbl_ct_title.setProperty("class", "SectionHeaderTitle")
        lbl_ct_title.setWordWrap(True)
        ct_title_box.addWidget(ct_icon)
        ct_title_box.addWidget(lbl_ct_title)
        ct_title_box.addStretch()
        ct_layout.addLayout(ct_title_box)

        # 3.1 IP 协议版本偏好
        row_ip_mode = QHBoxLayout()
        r_im_text = QVBoxLayout()
        r_im_text.setSpacing(2)
        lbl_im_title = QLabel("测速与节点优选协议偏好")
        lbl_im_title.setProperty("class", "ItemTitle")
        lbl_im_title.setWordWrap(True)
        lbl_im_desc = QLabel("推荐 IPv4 优先以防止部分宽带 IPv6 Anycast 跨洋绕路；纯 v6 环境可选择 IPv6 优先")
        lbl_im_desc.setProperty("class", "ItemDesc")
        lbl_im_desc.setWordWrap(True)
        r_im_text.addWidget(lbl_im_title)
        r_im_text.addWidget(lbl_im_desc)
        row_ip_mode.addLayout(r_im_text)
        row_ip_mode.addStretch()

        self.cmb_ip_mode = NoWheelComboBox()
        self.cmb_ip_mode.addItem("优先 IPv4 节点 (推荐稳定)", "prefer_ipv4")
        self.cmb_ip_mode.addItem("双栈延迟优先 (谁快选谁)", "dual_stack")
        self.cmb_ip_mode.addItem("仅探测 IPv4 (彻底禁用 v6)", "ipv4_only")
        self.cmb_ip_mode.addItem("优先 IPv6 节点 (教育网/纯v6)", "prefer_ipv6")
        
        cur_ip_mode = cfg.get("ip_version_mode", "prefer_ipv4")
        for idx in range(self.cmb_ip_mode.count()):
            if self.cmb_ip_mode.itemData(idx) == cur_ip_mode:
                self.cmb_ip_mode.setCurrentIndex(idx)
                break
        self.cmb_ip_mode.currentIndexChanged.connect(self.on_ip_mode_changed)
        row_ip_mode.addWidget(self.cmb_ip_mode)
        ct_layout.addLayout(row_ip_mode)

        # 3.2 测速超时与并发线程数
        row_cdn_params = QHBoxLayout()
        row_cdn_params.setSpacing(16)

        lbl_to = QLabel("单节点超时门限:")
        lbl_to.setProperty("class", "ItemTitle")
        lbl_to.setWordWrap(True)
        self.cmb_timeout = NoWheelComboBox()
        self.cmb_timeout.addItem("0.8 秒 (极速探测)", 0.8)
        self.cmb_timeout.addItem("1.5 秒 (推荐标准)", 1.5)
        self.cmb_timeout.addItem("2.5 秒 (弱网宽容)", 2.5)
        self.cmb_timeout.addItem("3.0 秒 (超长等待)", 3.0)
        cur_to = cfg.get("cdn_timeout_seconds", 1.5)
        for idx in range(self.cmb_timeout.count()):
            if abs(float(self.cmb_timeout.itemData(idx)) - float(cur_to)) < 0.1:
                self.cmb_timeout.setCurrentIndex(idx)
                break
        self.cmb_timeout.currentIndexChanged.connect(self.on_cdn_timeout_changed)

        lbl_wk = QLabel("最大并发线程:")
        lbl_wk.setProperty("class", "ItemTitle")
        lbl_wk.setWordWrap(True)
        self.cmb_workers = NoWheelComboBox()
        self.cmb_workers.addItem("8 线程 (低占用)", 8)
        self.cmb_workers.addItem("16 线程 (推荐标准)", 16)
        self.cmb_workers.addItem("24 线程", 24)
        self.cmb_workers.addItem("32 线程 (极速并发)", 32)
        cur_wk = cfg.get("cdn_max_workers", 16)
        for idx in range(self.cmb_workers.count()):
            if int(self.cmb_workers.itemData(idx)) == int(cur_wk):
                self.cmb_workers.setCurrentIndex(idx)
                break
        self.cmb_workers.currentIndexChanged.connect(self.on_cdn_workers_changed)

        row_cdn_params.addWidget(lbl_to)
        row_cdn_params.addWidget(self.cmb_timeout)
        row_cdn_params.addSpacing(12)
        row_cdn_params.addWidget(lbl_wk)
        row_cdn_params.addWidget(self.cmb_workers)
        row_cdn_params.addStretch()
        ct_layout.addLayout(row_cdn_params)

        # 3.3 启动时自动测速
        row_cdn_startup = QHBoxLayout()
        r_cs_text = QVBoxLayout()
        r_cs_text.setSpacing(2)
        lbl_cs_title = QLabel("启动时自动测速并优选 CDN 节点")
        lbl_cs_title.setProperty("class", "ItemTitle")
        lbl_cs_title.setWordWrap(True)
        lbl_cs_desc = QLabel("客户端启动后在后台静默并发探测候选节点延迟，自动选举最低延迟 IP 并热重载生效")
        lbl_cs_desc.setProperty("class", "ItemDesc")
        lbl_cs_desc.setWordWrap(True)
        r_cs_text.addWidget(lbl_cs_title)
        r_cs_text.addWidget(lbl_cs_desc)
        row_cdn_startup.addLayout(r_cs_text)
        row_cdn_startup.addStretch()

        self.sw_auto_cdn_startup = MDSwitch(checked=cfg.get("auto_cdn_optimize_on_startup", True))
        self.sw_auto_cdn_startup.toggled.connect(lambda c: update_config_key("auto_cdn_optimize_on_startup", c))
        row_cdn_startup.addWidget(self.sw_auto_cdn_startup)
        ct_layout.addLayout(row_cdn_startup)

        # 3.4 仅测速当前已开启的服务
        row_cdn_only_en = QHBoxLayout()
        r_coe_text = QVBoxLayout()
        r_coe_text.setSpacing(2)
        lbl_coe_title = QLabel("仅测速当前已勾选启用的加速服务")
        lbl_coe_title.setProperty("class", "ItemTitle")
        lbl_coe_title.setWordWrap(True)
        lbl_coe_desc = QLabel("开启时启动测速仅探测已启用的服务 (耗时缩短至 2~3 秒)；关闭时将探测全量 18 项服务")
        lbl_coe_desc.setProperty("class", "ItemDesc")
        lbl_coe_desc.setWordWrap(True)
        r_coe_text.addWidget(lbl_coe_title)
        r_coe_text.addWidget(lbl_coe_desc)
        row_cdn_only_en.addLayout(r_coe_text)
        row_cdn_only_en.addStretch()

        self.sw_auto_cdn_only_enabled = MDSwitch(checked=cfg.get("auto_cdn_only_enabled", True))
        self.sw_auto_cdn_only_enabled.toggled.connect(lambda c: update_config_key("auto_cdn_only_enabled", c))
        row_cdn_only_en.addWidget(self.sw_auto_cdn_only_enabled)
        ct_layout.addLayout(row_cdn_only_en)

        # 3.5 防抖周期与自愈频率
        row_intervals = QHBoxLayout()
        row_intervals.setSpacing(16)

        lbl_db = QLabel("启动测速防抖间隔:")
        lbl_db.setProperty("class", "ItemTitle")
        lbl_db.setWordWrap(True)
        self.cmb_debounce = NoWheelComboBox()
        self.cmb_debounce.addItem("15 分钟", 15)
        self.cmb_debounce.addItem("30 分钟 (推荐)", 30)
        self.cmb_debounce.addItem("60 分钟 (1小时)", 60)
        self.cmb_debounce.addItem("240 分钟 (4小时)", 240)
        cur_db = cfg.get("auto_cdn_min_interval_minutes", 30)
        for idx in range(self.cmb_debounce.count()):
            if int(self.cmb_debounce.itemData(idx)) == int(cur_db):
                self.cmb_debounce.setCurrentIndex(idx)
                break
        self.cmb_debounce.currentIndexChanged.connect(self.on_cdn_debounce_changed)

        lbl_hl = QLabel("健康巡检周期:")
        lbl_hl.setProperty("class", "ItemTitle")
        lbl_hl.setWordWrap(True)
        self.cmb_health_freq = NoWheelComboBox()
        self.cmb_health_freq.addItem("15 秒 (高灵敏)", 15)
        self.cmb_health_freq.addItem("30 秒 (推荐)", 30)
        self.cmb_health_freq.addItem("60 秒 (1分钟)", 60)
        self.cmb_health_freq.addItem("300 秒 (5分钟)", 300)
        cur_hl = cfg.get("health_check_interval_seconds", 30)
        for idx in range(self.cmb_health_freq.count()):
            if int(self.cmb_health_freq.itemData(idx)) == int(cur_hl):
                self.cmb_health_freq.setCurrentIndex(idx)
                break
        self.cmb_health_freq.currentIndexChanged.connect(self.on_health_interval_changed)

        row_intervals.addWidget(lbl_db)
        row_intervals.addWidget(self.cmb_debounce)
        row_intervals.addSpacing(12)
        row_intervals.addWidget(lbl_hl)
        row_intervals.addWidget(self.cmb_health_freq)
        row_intervals.addStretch()
        ct_layout.addLayout(row_intervals)

        layout.addWidget(cdn_tune_card)

        # ==================== 卡片 4: 测速代理设置 ====================
        proxy_card = QFrame()
        proxy_card.setProperty("class", "MDCard")
        p_layout = QVBoxLayout(proxy_card)
        p_layout.setContentsMargins(20, 16, 20, 16)
        p_layout.setSpacing(14)

        p_title_box = QHBoxLayout()
        p_icon = QLabel()
        p_icon.setPixmap(SvgIconFactory.get_pixmap("wifi", primary_icon_c, 18))
        self.settings_icon_labels.append((p_icon, "wifi"))
        lbl_p_title = QLabel("测速代理设置")
        lbl_p_title.setProperty("class", "SectionHeaderTitle")
        lbl_p_title.setWordWrap(True)
        p_title_box.addWidget(p_icon)
        p_title_box.addWidget(lbl_p_title)
        p_title_box.addStretch()
        p_layout.addLayout(p_title_box)

        row_pxy_en = QHBoxLayout()
        r_pe_text = QVBoxLayout()
        r_pe_text.setSpacing(2)
        lbl_pe_title = QLabel("启用测速专用本地代理")
        lbl_pe_title.setProperty("class", "ItemTitle")
        lbl_pe_title.setWordWrap(True)
        lbl_pe_desc = QLabel("通过本地 Clash / Sing-box / v2ray 混合代理端口并发探测境外 Anycast 延迟 (仅供节点筛选)")
        lbl_pe_desc.setProperty("class", "ItemDesc")
        lbl_pe_desc.setWordWrap(True)
        r_pe_text.addWidget(lbl_pe_title)
        r_pe_text.addWidget(lbl_pe_desc)
        row_pxy_en.addLayout(r_pe_text)
        row_pxy_en.addStretch()

        proxy_cfg = cfg.get("upstream_proxy", {"enabled": False, "host": "127.0.0.1", "port": 7897})
        self.sw_proxy_enable = MDSwitch(checked=proxy_cfg.get("enabled", False))
        self.sw_proxy_enable.toggled.connect(self.on_proxy_config_changed)
        row_pxy_en.addWidget(self.sw_proxy_enable)
        p_layout.addLayout(row_pxy_en)

        row_pxy_fields = QHBoxLayout()
        row_pxy_fields.setSpacing(12)

        lbl_phost = QLabel("代理主机:")
        lbl_phost.setProperty("class", "ItemTitle")
        lbl_phost.setWordWrap(True)
        self.txt_proxy_host = QLineEdit(proxy_cfg.get("host", "127.0.0.1"))
        self.txt_proxy_host.setFixedWidth(130)
        self.txt_proxy_host.textChanged.connect(self.on_proxy_config_changed)

        lbl_pport = QLabel("代理端口:")
        lbl_pport.setProperty("class", "ItemTitle")
        lbl_pport.setWordWrap(True)
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

        # ==================== 卡片 5: 本地 DNS 智能分流与上游解析 ====================
        dns_card = QFrame()
        dns_card.setProperty("class", "MDCard")
        d_layout = QVBoxLayout(dns_card)
        d_layout.setContentsMargins(20, 16, 20, 16)
        d_layout.setSpacing(14)

        d_title_box = QHBoxLayout()
        d_icon = QLabel()
        d_icon.setPixmap(SvgIconFactory.get_pixmap("activity", primary_icon_c, 18))
        self.settings_icon_labels.append((d_icon, "activity"))
        lbl_d_title = QLabel("本地 DNS 智能分流与上游解析服务器")
        lbl_d_title.setProperty("class", "SectionHeaderTitle")
        lbl_d_title.setWordWrap(True)
        d_title_box.addWidget(d_icon)
        d_title_box.addWidget(lbl_d_title)
        d_title_box.addStretch()
        d_layout.addLayout(d_title_box)

        # 5.1 启用本地 DNS
        row_dns = QHBoxLayout()
        r_dns_text = QVBoxLayout()
        r_dns_text.setSpacing(2)
        lbl_dns_title = QLabel("启用本地 DNS 智能分流 (UDP 5353)")
        lbl_dns_title.setProperty("class", "ItemTitle")
        lbl_dns_title.setWordWrap(True)
        lbl_dns_desc = QLabel("开启轻量本地 DNS 解析服务，加速域名智能命中，普通公网域名透明递归转发")
        lbl_dns_desc.setProperty("class", "ItemDesc")
        lbl_dns_desc.setWordWrap(True)
        r_dns_text.addWidget(lbl_dns_title)
        r_dns_text.addWidget(lbl_dns_desc)
        row_dns.addLayout(r_dns_text)
        row_dns.addStretch()

        self.sw_dns_mode = MDSwitch(checked=cfg.get("dns_mode_enabled", True))
        self.sw_dns_mode.toggled.connect(self.on_dns_mode_toggled)
        row_dns.addWidget(self.sw_dns_mode)
        d_layout.addLayout(row_dns)

        # 5.2 上游公共 DNS 预设胶囊
        row_presets = QHBoxLayout()
        row_presets.setSpacing(8)
        lbl_pr_title = QLabel("常用公共 DNS 快速填入:")
        lbl_pr_title.setProperty("class", "ItemTitle")
        lbl_pr_title.setWordWrap(True)
        row_presets.addWidget(lbl_pr_title)

        dns_presets = [
            ("阿里 DNS", "223.5.5.5", "223.6.6.6"),
            ("腾讯 DNSPod", "119.29.29.29", "182.254.116.116"),
            ("Cloudflare", "1.1.1.1", "1.0.0.1"),
            ("Google", "8.8.8.8", "8.8.4.4"),
            ("114 DNS", "114.114.114.114", "114.114.115.115")
        ]
        for name, p_dns, s_dns in dns_presets:
            btn_p = QPushButton(name)
            btn_p.setProperty("class", "MDBtnTiny")
            btn_p.clicked.connect(lambda _, p=p_dns, s=s_dns: self.apply_preset_dns(p, s))
            row_presets.addWidget(btn_p)
        row_presets.addStretch()
        d_layout.addLayout(row_presets)

        # 5.3 主备 DNS 输入行
        row_dns_fields = QHBoxLayout()
        row_dns_fields.setSpacing(12)

        up_dns = cfg.get("upstream_dns_servers", ["223.5.5.5", "119.29.29.29"])
        primary_dns = up_dns[0] if len(up_dns) > 0 else "223.5.5.5"
        sec_dns = up_dns[1] if len(up_dns) > 1 else "119.29.29.29"

        lbl_pdns = QLabel("主力上游 DNS:")
        lbl_pdns.setProperty("class", "ItemTitle")
        lbl_pdns.setWordWrap(True)
        self.txt_dns_primary = QLineEdit(primary_dns)
        self.txt_dns_primary.setFixedWidth(130)
        self.txt_dns_primary.textChanged.connect(self.on_custom_dns_changed)

        lbl_sdns = QLabel("备用上游 DNS:")
        lbl_sdns.setProperty("class", "ItemTitle")
        lbl_sdns.setWordWrap(True)
        self.txt_dns_secondary = QLineEdit(sec_dns)
        self.txt_dns_secondary.setFixedWidth(130)
        self.txt_dns_secondary.textChanged.connect(self.on_custom_dns_changed)

        row_dns_fields.addWidget(lbl_pdns)
        row_dns_fields.addWidget(self.txt_dns_primary)
        row_dns_fields.addWidget(lbl_sdns)
        row_dns_fields.addWidget(self.txt_dns_secondary)
        row_dns_fields.addStretch()
        d_layout.addLayout(row_dns_fields)

        layout.addWidget(dns_card)

        # ==================== 卡片 6: Steam 路径与游戏高级启动参数 ====================
        steam_card = QFrame()
        steam_card.setProperty("class", "MDCard")
        s_layout = QVBoxLayout(steam_card)
        s_layout.setContentsMargins(20, 16, 20, 16)
        s_layout.setSpacing(14)

        s_title_box = QHBoxLayout()
        s_icon = QLabel()
        s_icon.setPixmap(SvgIconFactory.get_pixmap("users", primary_icon_c, 18))
        self.settings_icon_labels.append((s_icon, "users"))
        lbl_s_title = QLabel("Steam 客户端路径与游戏高级启动参数")
        lbl_s_title.setProperty("class", "SectionHeaderTitle")
        lbl_s_title.setWordWrap(True)
        s_title_box.addWidget(s_icon)
        s_title_box.addWidget(lbl_s_title)
        s_title_box.addStretch()
        s_layout.addLayout(s_title_box)

        # 6.1 Steam 安装路径
        row_sp = QHBoxLayout()
        row_sp.setSpacing(10)
        lbl_sp = QLabel("Steam 路径:")
        lbl_sp.setProperty("class", "ItemTitle")
        lbl_sp.setWordWrap(True)
        current_sp = str(steam_mgr.steam_path) if steam_mgr.steam_path else ""
        self.txt_steam_path = QLineEdit(current_sp)
        self.txt_steam_path.setPlaceholderText("自动检测或点击右侧浏览选择 steam.exe 路径")
        self.txt_steam_path.textChanged.connect(lambda t: update_config_key("custom_steam_path", t.strip()))

        btn_browse_steam = QPushButton("浏览 📁")
        btn_browse_steam.setProperty("class", "MDBtnTonal")
        btn_browse_steam.clicked.connect(self.browse_steam_path_action)

        btn_redetect_steam = QPushButton("重新探测 🔄")
        btn_redetect_steam.setProperty("class", "MDBtnOutlined")
        btn_redetect_steam.clicked.connect(self.redetect_steam_path_action)

        row_sp.addWidget(lbl_sp)
        row_sp.addWidget(self.txt_steam_path)
        row_sp.addWidget(btn_browse_steam)
        row_sp.addWidget(btn_redetect_steam)
        s_layout.addLayout(row_sp)

        # 6.2 常用启动参数预设
        lbl_args_intro = QLabel("快捷启动参数预设 (启动 Steam 或免密切号时自动追加):")
        lbl_args_intro.setProperty("class", "ItemTitle")
        lbl_args_intro.setWordWrap(True)
        s_layout.addWidget(lbl_args_intro)

        current_args = cfg.get("steam_launch_args", ["-tcp"])
        args_grid = QGridLayout()
        args_grid.setSpacing(10)

        self.chk_steam_tcp = QCheckBox("-tcp (强制 TCP 传输，解决好友列表/聊天转圈丢包)")
        self.chk_steam_tcp.setChecked("-tcp" in current_args)
        self.chk_steam_tcp.toggled.connect(self.on_steam_launch_args_changed)

        self.chk_steam_nofriends = QCheckBox("-nofriendsui (轻量极简好友列表，极大节省内存)")
        self.chk_steam_nofriends.setChecked("-nofriendsui" in current_args)
        self.chk_steam_nofriends.toggled.connect(self.on_steam_launch_args_changed)

        self.chk_steam_nobrowser = QCheckBox("-no-browser (纯净运行模式，禁用内置 Chromium 网页)")
        self.chk_steam_nobrowser.setChecked("-no-browser" in current_args)
        self.chk_steam_nobrowser.toggled.connect(self.on_steam_launch_args_changed)

        self.chk_steam_dev = QCheckBox("-dev (启用开发者模式与原生调试控制台)")
        self.chk_steam_dev.setChecked("-dev" in current_args)
        self.chk_steam_dev.toggled.connect(self.on_steam_launch_args_changed)

        args_grid.addWidget(self.chk_steam_tcp, 0, 0)
        args_grid.addWidget(self.chk_steam_nofriends, 0, 1)
        args_grid.addWidget(self.chk_steam_nobrowser, 1, 0)
        args_grid.addWidget(self.chk_steam_dev, 1, 1)
        s_layout.addLayout(args_grid)

        # 6.3 自定义附加参数
        row_cust_args = QHBoxLayout()
        row_cust_args.setSpacing(10)
        lbl_ca = QLabel("自定义附加参数:")
        lbl_ca.setProperty("class", "ItemTitle")
        lbl_ca.setWordWrap(True)
        self.txt_steam_custom_args = QLineEdit(cfg.get("steam_custom_args_str", ""))
        self.txt_steam_custom_args.setPlaceholderText("例如: -silent -console -language schinese")
        self.txt_steam_custom_args.textChanged.connect(lambda t: update_config_key("steam_custom_args_str", t.strip()))

        btn_launch_steam_now = QPushButton("以当前参数启动 Steam")
        btn_launch_steam_now.setProperty("class", "MDBtnTonal")
        btn_launch_steam_now.clicked.connect(self.launch_steam_with_custom_args_action)

        row_cust_args.addWidget(lbl_ca)
        row_cust_args.addWidget(self.txt_steam_custom_args)
        row_cust_args.addWidget(btn_launch_steam_now)
        s_layout.addLayout(row_cust_args)

        layout.addWidget(steam_card)

        # ==================== 卡片 7: 系统根证书与本地存储管理 ====================
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
        lbl_cc_title.setWordWrap(True)
        cc_title_box.addWidget(cc_icon)
        cc_title_box.addWidget(lbl_cc_title)
        cc_title_box.addStretch()
        cc_l.addLayout(cc_title_box)

        # 7.1 证书管理
        self.lbl_cert_detail = QLabel("证书状态: 检测中...")
        self.lbl_cert_detail.setProperty("class", "SectionHeaderDesc")
        self.lbl_cert_detail.setWordWrap(True)
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

        # 7.2 本地缓存与退出自动清理
        row_cache_mgmt = QHBoxLayout()
        r_cm_text = QVBoxLayout()
        r_cm_text.setSpacing(2)
        lbl_ca_title = QLabel("GameArt 本地图片与静态资源磁盘缓存")
        lbl_ca_title.setProperty("class", "ItemTitle")
        lbl_ca_title.setWordWrap(True)
        self.lbl_cache_size_desc = QLabel(f"Nginx 会在本地磁盘缓存浏览过的插画原图与社区图片 (当前已占用: {self._get_cache_size_str()})。")
        self.lbl_cache_size_desc.setProperty("class", "ItemDesc")
        self.lbl_cache_size_desc.setWordWrap(True)
        r_cm_text.addWidget(lbl_ca_title)
        r_cm_text.addWidget(self.lbl_cache_size_desc)
        row_cache_mgmt.addLayout(r_cm_text)
        row_cache_mgmt.addStretch()

        btn_clear_cache = QPushButton("清空本地图片缓存")
        btn_clear_cache.setProperty("class", "MDBtnOutlined")
        btn_clear_cache.clicked.connect(self.clear_cache_action)
        row_cache_mgmt.addWidget(btn_clear_cache)
        cc_l.addLayout(row_cache_mgmt)

        row_auto_clear = QHBoxLayout()
        r_ac_text = QVBoxLayout()
        r_ac_text.setSpacing(2)
        lbl_ac_title = QLabel("退出程序时自动清空图片磁盘缓存")
        lbl_ac_title.setProperty("class", "ItemTitle")
        lbl_ac_title.setWordWrap(True)
        lbl_ac_desc = QLabel("开启后每次完全退出程序时自动清理临时图片缓存，保持磁盘空间清爽")
        lbl_ac_desc.setProperty("class", "ItemDesc")
        lbl_ac_desc.setWordWrap(True)
        r_ac_text.addWidget(lbl_ac_title)
        r_ac_text.addWidget(lbl_ac_desc)
        row_auto_clear.addLayout(r_ac_text)
        row_auto_clear.addStretch()

        self.sw_auto_clear_cache = MDSwitch(checked=cfg.get("auto_clear_cache_on_exit", False))
        self.sw_auto_clear_cache.toggled.connect(lambda c: update_config_key("auto_clear_cache_on_exit", c))
        row_auto_clear.addWidget(self.sw_auto_clear_cache)
        cc_l.addLayout(row_auto_clear)

        # 7.3 Git 命令行调优
        row_git = QHBoxLayout()
        r_git_text = QVBoxLayout()
        r_git_text.setSpacing(2)
        lbl_git_title = QLabel("Git 命令行网络与大文件传输优化")
        lbl_git_title.setProperty("class", "ItemTitle")
        lbl_git_title.setWordWrap(True)
        lbl_git_desc = QLabel("自动将 Git 全局 http.postBuffer 提升至 500MB，解除低速超时限制，解决 git pull / clone 卡顿")
        lbl_git_desc.setProperty("class", "ItemDesc")
        lbl_git_desc.setWordWrap(True)
        r_git_text.addWidget(lbl_git_title)
        r_git_text.addWidget(lbl_git_desc)
        row_git.addLayout(r_git_text)
        row_git.addStretch()

        btn_opt_git = QPushButton("一键优化 Git 配置")
        btn_opt_git.setProperty("class", "MDBtnTonal")
        btn_opt_git.clicked.connect(self.optimize_git_config_action)
        row_git.addWidget(btn_opt_git)
        cc_l.addLayout(row_git)

        # 7.4 端口诊断
        lbl_po_title = QLabel("本地 80 / 443 端口诊断")
        lbl_po_title.setProperty("class", "ItemTitle")
        lbl_po_title.setWordWrap(True)
        self.lbl_port_detail = QLabel("端口状态: 检测中...")
        self.lbl_port_detail.setProperty("class", "SectionHeaderDesc")
        self.lbl_port_detail.setWordWrap(True)
        cc_l.addWidget(lbl_po_title)
        cc_l.addWidget(self.lbl_port_detail)

        layout.addWidget(cert_card)

        layout.addStretch()
        scroll.setWidget(content)
        return scroll

    # ==================== 设置页事件响应方法 ====================
    def on_theme_mode_changed(self, index: int):
        modes = ["dark", "light", "pink", "system"]
        mode = modes[index] if 0 <= index < len(modes) else "dark"
        update_config_key("theme_mode", mode)
        target_theme = mode
        if mode == "system":
            target_theme = "dark" if is_windows_dark_mode() else "light"
        update_config_key("theme", target_theme)
        ThemeManager.get_instance().set_theme(target_theme, QApplication.instance())
        if self.frameless_helper:
            self.frameless_helper.set_immersive_dark_mode(target_theme == "dark")
        show_toast(self, f"已切换主题为: {self.cmb_theme_mode.currentText()}", toast_type="info", duration=2000)

    def on_ip_mode_changed(self, index: int):
        val = self.cmb_ip_mode.itemData(index)
        if val:
            update_config_key("ip_version_mode", val)
            show_toast(self, f"已切换测速偏好为: {self.cmb_ip_mode.currentText()}", toast_type="success", duration=2000)

    def on_cdn_timeout_changed(self, index: int):
        val = self.cmb_timeout.itemData(index)
        if val is not None:
            update_config_key("cdn_timeout_seconds", float(val))

    def on_cdn_workers_changed(self, index: int):
        val = self.cmb_workers.itemData(index)
        if val is not None:
            update_config_key("cdn_max_workers", int(val))

    def on_cdn_debounce_changed(self, index: int):
        val = self.cmb_debounce.itemData(index)
        if val is not None:
            update_config_key("auto_cdn_min_interval_minutes", int(val))

    def on_health_interval_changed(self, index: int):
        val = self.cmb_health_freq.itemData(index)
        if val is not None:
            update_config_key("health_check_interval_seconds", int(val))

    def apply_preset_dns(self, primary: str, secondary: str):
        if hasattr(self, "txt_dns_primary") and hasattr(self, "txt_dns_secondary"):
            self.txt_dns_primary.setText(primary)
            self.txt_dns_secondary.setText(secondary)
            self.on_custom_dns_changed()
            show_toast(self, f"已应用上游 DNS 预设: {primary}, {secondary}", toast_type="success", duration=2000)

    def on_custom_dns_changed(self):
        p = self.txt_dns_primary.text().strip() if hasattr(self, "txt_dns_primary") else "223.5.5.5"
        s = self.txt_dns_secondary.text().strip() if hasattr(self, "txt_dns_secondary") else "119.29.29.29"
        dns_list = [d for d in [p, s] if d]
        if dns_list:
            update_config_key("upstream_dns_servers", dns_list)
            local_dns_server.set_upstream_dns_list(dns_list)

    def browse_steam_path_action(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择 Steam 可执行文件", "C:\\", "Steam (steam.exe);;可执行文件 (*.exe)")
        if path:
            p = Path(path)
            self.txt_steam_path.setText(str(p.parent if p.name.lower() == "steam.exe" else p))
            update_config_key("custom_steam_path", str(p.parent if p.name.lower() == "steam.exe" else p))
            steam_mgr.refresh_paths()
            self.load_steam_accounts_ui()
            self.refresh_tray_steam_menu()
            show_toast(self, "Steam 路径更新成功！", toast_type="success", duration=2500)

    def redetect_steam_path_action(self):
        update_config_key("custom_steam_path", "")
        steam_mgr.refresh_paths()
        new_p = str(steam_mgr.steam_path) if steam_mgr.steam_path else ""
        if hasattr(self, "txt_steam_path"):
            self.txt_steam_path.setText(new_p)
        self.load_steam_accounts_ui()
        self.refresh_tray_steam_menu()
        if new_p:
            show_toast(self, f"已自动探测到 Steam 安装路径: {new_p}", toast_type="success", duration=3000)
        else:
            show_toast(self, "未能在系统中自动探测到 Steam，请手动点击【浏览】选择", toast_type="warning", duration=3500)

    def on_steam_launch_args_changed(self):
        args = []
        if getattr(self, "chk_steam_tcp", None) and self.chk_steam_tcp.isChecked():
            args.append("-tcp")
        if getattr(self, "chk_steam_nofriends", None) and self.chk_steam_nofriends.isChecked():
            args.append("-nofriendsui")
        if getattr(self, "chk_steam_nobrowser", None) and self.chk_steam_nobrowser.isChecked():
            args.append("-no-browser")
        if getattr(self, "chk_steam_dev", None) and self.chk_steam_dev.isChecked():
            args.append("-dev")
        update_config_key("steam_launch_args", args)

    def launch_steam_with_custom_args_action(self):
        ok, msg = steam_mgr.launch_steam()
        show_toast(self, msg, toast_type="success" if ok else "error", duration=3000)

    def on_autostart_toggled(self, checked: bool):
        cfg = load_config()
        start_min = cfg.get("start_minimized", True)
        ok, msg = set_autostart(checked, start_minimized=start_min)
        update_config_key("auto_start", checked)
        show_toast(self, msg, toast_type="success" if ok else "error", duration=2500)

    def on_start_minimized_toggled(self, checked: bool):
        update_config_key("start_minimized", checked)
        if is_autostart_enabled():
            set_autostart(True, start_minimized=checked)
        tip = "已开启启动时最小化到后台" if checked else "已关闭启动时最小化 (启动时显示主窗口)"
        show_toast(self, tip, toast_type="info", duration=2000)

    def on_tray_notif_toggled(self, checked: bool):
        update_config_key("tray_notifications", checked)
        tip = "已开启系统托盘与运行气泡提示" if checked else "已关闭所有气泡提示 (彻底静默模式)"
        show_toast(self, tip, toast_type="info", duration=2000)

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

    def _get_cache_size_str(self) -> str:
        try:
            from path_utils import NGINX_DIR
            cache_dir = NGINX_DIR / "temp" / "cache"
            if not cache_dir.exists():
                return "0.0 MB"
            total_size = sum(f.stat().st_size for f in cache_dir.rglob("*") if f.is_file())
            return f"{total_size / (1024 * 1024):.1f} MB"
        except Exception:
            return "0.0 MB"

    def clear_cache_action(self):
        ok, msg = nginx_mgr.clear_cache()
        if hasattr(self, 'lbl_cache_size_desc') and self.lbl_cache_size_desc:
            self.lbl_cache_size_desc.setText(f"Nginx 会在本地磁盘缓存浏览过的插画原图与社区图片 (当前已占用: {self._get_cache_size_str()})。")
        show_toast(self, msg, toast_type="success", duration=2500)

    # ------------------ 状态同步与托盘后台 ------------------
    def init_tray(self):
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(create_tray_icon(False))
        self.tray.setToolTip("GameArt Toolkit 加速控制中心")

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

        act_quit = QAction("完全退出 GameArt Toolkit", self)
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

    def notify_tray(self, title: str, message: str, icon=QSystemTrayIcon.Information, duration: int = 2000):
        """统一托盘通知网关，集中遵从 tray_notifications 配置实现彻底静默"""
        cfg = load_config()
        if not cfg.get("tray_notifications", True):
            return
        if hasattr(self, "tray") and self.tray and self.tray.supportsMessages():
            try:
                self.tray.showMessage(title, message, icon, duration)
            except Exception as e:
                print(f"[Tray] 弹出通知异常: {e}")

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

    def safe_shutdown(self):
        """安全回收所有定时器与异步工作线程，防止进程退出时发生 0xC0000409 崩溃"""
        # 1. 停止所有活跃定时器
        for timer_name in ["status_timer", "traffic_timer", "watchdog_timer"]:
            if hasattr(self, timer_name):
                t = getattr(self, timer_name)
                if t and t.isActive():
                    t.stop()

        # 2. 优雅终止所有 QThread 工作线程
        workers = [
            getattr(self, "_status_worker", None),
            getattr(self, "cdn_worker", None),
            getattr(self, "steam_worker", None),
            getattr(self, "_startup_cdn_worker", None),
            *list(getattr(self, "_single_cdn_workers", {}).values())
        ]
        for w in workers:
            if w and w.isRunning():
                if hasattr(w, "request_stop"):
                    w.request_stop()
                w.quit()
                w.wait(500)

    def closeEvent(self, event):
        if getattr(self, "_is_force_quit", False):
            self.safe_shutdown()
            event.accept()
            return

        cfg = load_config()
        action = cfg.get("close_action", "minimize_to_tray")
        if action == "quit_directly":
            self.safe_shutdown()
            event.accept()
            self.quit_application()
        else:
            event.ignore()
            self.hide()
            self.notify_tray(
                "GameArt Toolkit 后台运行中",
                "程序已最小化至系统托盘，网络加速与自动托管将持续运行。",
                QSystemTrayIcon.Information,
                2000
            )

    def quit_application(self):
        print("[GameArt Toolkit] 正在完全退出程序...")
        if hasattr(self, 'tray') and self.tray:
            self.tray.hide()
        cfg = load_config()
        if cfg.get("auto_clear_cache_on_exit", False):
            try:
                nginx_mgr.clear_cache()
            except Exception:
                pass
        self.safe_shutdown()
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

        tm = ThemeManager.get_instance()
        palette = tm.get_palette()
        is_dark = tm.is_dark

        success_val_c = palette.get("success", "#34D399")
        warning_val_c = palette.get("warning", "#FBBF24")
        error_val_c = palette.get("error", "#F87171")
        muted_val_c = palette.get("text_muted", "#75879E")
        primary_val_c = palette.get("primary", "#7EB9F5")

        if self._last_acc_state != is_acc:
            self._last_acc_state = is_acc
            self.tray.setIcon(create_tray_icon(is_acc))
            self.tray.setToolTip(f"GameArt Toolkit - 加速服务{'运行中' if is_acc else '已停止'}")

            if is_acc:
                self.lbl_main_status.setStyleSheet(f"font-size: 17px; font-weight: bold; color: {success_val_c};")
                self.lbl_main_status.setText("加速服务运行中")
                self.btn_toggle_acc.setText("停止加速服务")
                self.btn_toggle_acc.setProperty("class", "MDBtnStop")
                self.act_tray_toggle.setText("停止加速服务")
            else:
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
                self.btn_sidebar_admin.setIcon(SvgIconFactory.get_icon("shield_check", success_val_c, 14))
                self.btn_sidebar_admin.setEnabled(False)
                if is_dark:
                    self.btn_sidebar_admin.setStyleSheet(f"color: {success_val_c}; font-size: 11px; padding: 6px 10px; background: rgba(52, 211, 153, 0.12); border: none; border-radius: 8px;")
                else:
                    self.btn_sidebar_admin.setStyleSheet(f"color: {success_val_c}; font-size: 11px; padding: 6px 10px; background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px;")
            else:
                self.btn_sidebar_admin.setText("标准用户 [点击提权]")
                self.btn_sidebar_admin.setIcon(SvgIconFactory.get_icon("shield", warning_val_c, 14))
                self.btn_sidebar_admin.setEnabled(True)
                self.btn_sidebar_admin.setStyleSheet(f"color: {warning_val_c}; font-size: 11px; padding: 6px 10px; background: rgba(245, 158, 11, 0.12); border: 1px solid {warning_val_c}; border-radius: 8px;")

        # 主控卡片大图标联动变色 (运行中翠绿 / 停止待命主色)
        if getattr(self, 'lbl_main_icon', None) and SvgIconFactory:
            self.lbl_main_icon.setPixmap(SvgIconFactory.get_pixmap("rocket", success_val_c if is_acc else primary_val_c, 36))

        self.card_stat_nginx.lbl_val.setText("运行中" if is_nginx else "已停止")
        self.card_stat_nginx.lbl_val.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {success_val_c if is_nginx else muted_val_c};")
        if hasattr(self.card_stat_nginx, 'icon_lbl') and SvgIconFactory:
            self.card_stat_nginx.icon_lbl.setPixmap(SvgIconFactory.get_pixmap("server", success_val_c if is_nginx else muted_val_c, 18))

        self.card_stat_cert.lbl_val.setText("已受信任" if is_cert else "未安装")
        self.card_stat_cert.lbl_val.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {success_val_c if is_cert else warning_val_c};")
        if hasattr(self.card_stat_cert, 'icon_lbl') and SvgIconFactory:
            self.card_stat_cert.icon_lbl.setPixmap(SvgIconFactory.get_pixmap("lock", success_val_c if is_cert else warning_val_c, 18))

        self.card_stat_hosts.lbl_val.setText("已生效" if is_hosts else "未注入")
        self.card_stat_hosts.lbl_val.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {success_val_c if is_hosts else muted_val_c};")
        if hasattr(self.card_stat_hosts, 'icon_lbl') and SvgIconFactory:
            self.card_stat_hosts.icon_lbl.setPixmap(SvgIconFactory.get_pixmap("file_text", success_val_c if is_hosts else muted_val_c, 18))

        curr_steam_user = status.get('curr_steam_user', "未检测到")
        self.card_stat_steam.lbl_val.setText(curr_steam_user)
        if hasattr(self.card_stat_steam, 'icon_lbl') and SvgIconFactory:
            steam_icon_c = primary_val_c if curr_steam_user != "未检测到" else muted_val_c
            self.card_stat_steam.icon_lbl.setPixmap(SvgIconFactory.get_pixmap("gamepad", steam_icon_c, 18))

        steam_path = status.get('steam_path')
        if steam_path:
            self.lbl_steam_banner_path.setText(f"安装路径: {steam_path}")
            if status.get('is_steam_running', False):
                self.lbl_steam_banner_status.setText(f"Steam 运行中 (当前用户: {curr_steam_user})")
                self.lbl_steam_banner_status.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {success_val_c};")
            else:
                self.lbl_steam_banner_status.setText("Steam 客户端已就绪 (未运行)")
                self.lbl_steam_banner_status.setProperty("class", "ItemTitle")
                self.lbl_steam_banner_status.setStyleSheet("")

        thumb = status.get('cert_thumb', '')
        self.lbl_cert_detail.setText(f"证书状态: {'已安装在系统受信任根证书库 (SHA1: ' + thumb + ')' if is_cert else '未检测到受信任证书'}")

        p443_busy = status.get('p443_busy', False)
        if p443_busy and not is_nginx:
            self.lbl_port_detail.setText("警告: 443 端口被其他程序占用！")
            self.lbl_port_detail.setStyleSheet(f"font-size: 12px; color: {error_val_c}; font-weight: bold;")
        else:
            self.lbl_port_detail.setText("端口状态: 80 (HTTP) 与 443 (HTTPS) 正常就绪")
            self.lbl_port_detail.setStyleSheet(f"font-size: 12px; color: {success_val_c};")

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
                else:
                    self.notify_tray("Hosts 权限提示", "未获取管理员权限修改 Hosts，可点击界面侧栏【提权】。", QSystemTrayIcon.Warning, 3000)
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
            else:
                self.notify_tray("Nginx 启动提示", n_msg, QSystemTrayIcon.Warning, 2500)
            return

        # 同步启动 L4 Relay 代理转发器 (预检端口 + 恢复既有 relay 路由) 与持续健康巡检
        relay_ok, relay_msg = self._start_relay()
        health_monitor.start(services)

        # 为 Git / 开发生态注入作用域证书
        try:
            cert_mgr.inject_dev_environments()
        except Exception:
            pass

        if show_toast_on_fail:
            extra = f" | {relay_msg}" if relay_ok else f" | ⚠ {relay_msg}"
            show_toast(self, f"加速服务已启动，{len(services)} 项服务规则已生效！{extra}", toast_type="success", duration=2500)

        self._start_status_probe()
        self.refresh_tray_steam_menu()

    def _start_relay(self) -> Tuple[bool, str]:
        """启动 L4 Relay 代理转发器: 端口预检 + 从现有 upstream 配置恢复 relay 端口路由"""
        if is_port_in_use(relay_server.port) and not relay_server.is_running():
            return False, f"L4 Relay 端口 {relay_server.port} 被占用, 代理转发服务不可用"
        ok, msg = relay_server.start()
        if not ok:
            return False, msg
        # 从现有 upstream-dynamic.conf 恢复 relay 端口映射 (上次会话的代理转发路由)
        try:
            from cdn_optimizer import CDNOptimizer
            opt = CDNOptimizer()
            if opt.conf_path.exists():
                conf_text = opt.conf_path.read_text(encoding="utf-8", errors="ignore")
                mapping = {int(m.group(2)): m.group(1)
                           for m in re.finditer(r"relay=([^\s:]+):443 port=(\d+)", conf_text)}
                if mapping:
                    relay_server.set_proxy_tunnels(mapping)
        except Exception:
            pass
        return True, msg

    def stop_acceleration(self):
        self._is_manually_stopped = True
        health_monitor.stop()
        relay_server.stop()
        relay_server.clear_proxy_routes()
        hosts_mgr.remove_rules()
        try:
            cert_mgr.restore_dev_environments()
        except Exception:
            pass
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


def main():
    # 0. 命令行极速静默响应 (安装包/卸载器/脚本调用，无界面 0.1s 极速还原)
    if "--clean-hosts-silent" in sys.argv or "--clean-hosts" in sys.argv:
        try:
            from hosts_manager import HostsManager
            ok, msg = HostsManager().remove_rules()
            print(f"[CleanHosts] {msg}")
        except Exception as e:
            print(f"[CleanHosts Error] {e}")
        sys.exit(0)

    # 1. 如果通过控制台或旧批处理启动，静默隐藏终端窗口
    hide_console_window()

    if sys.platform == "win32":
        import ctypes
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("GameArtToolkit.Material.Desktop")
        except Exception:
            pass
        try:
            # 声明 Per-Monitor V2 DPI 感知，避免多显示器与高分屏缩放模糊
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

    # 显式配置 Qt 6 High-DPI 缩放舍入策略为 PassThrough，杜绝非整数倍 DPI (125%/150%) 舍入失真
    if hasattr(Qt, "HighDpiScaleFactorRoundingPolicy"):
        QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)

    app = QApplication(sys.argv)
    app.aboutToQuit.connect(emergency_fast_cleanup)
    app.setWindowIcon(get_app_icon())

    cfg = load_config()
    theme_mode = cfg.get("theme_mode", "dark")
    if theme_mode == "system":
        theme = "dark" if is_windows_dark_mode() else "light"
    else:
        theme = cfg.get("theme", "dark")

    if theme == "dark":
        qss = MATERIAL_DARK_QSS
    elif theme == "pink":
        qss = MATERIAL_PINK_QSS
    else:
        qss = MATERIAL_LIGHT_QSS
    app.setStyleSheet(qss)
    app.setApplicationName("GameArtToolkit")
    app.setApplicationDisplayName("GameArt Toolkit")
    app.setQuitOnLastWindowClosed(False)

    window = MainWindow()
    is_minimized = ("--minimized" in sys.argv) or cfg.get("start_minimized", False)
    if is_minimized:
        window.hide()
    else:
        window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
