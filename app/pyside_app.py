# -*- coding: utf-8 -*-
"""
GameArt Toolkit - Material Design 3 桌面客户端
包含:
1. Win32 DWM 原生无边框窗口，支持 Win11 Snap Layouts 贴靠菜单与 8 向缩放
2. 全局 MD3 Floating Toast Overlay 悬浮通知体系，不使用阻塞式 QMessageBox
3. Steam 账号管家卡片内 Inline Edit 备注编辑与双击卡片免密切换
4. CDN 测速骨架屏 (Skeleton Screen) 与热重载
5. 单调三次样条平滑网络监控波形图与加速规则独立/分组原子管理
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
from typing import Optional, List, Dict, Set, Tuple, Any

# 强制设置环境语言与标准 I/O 编码，避免 Windows 多语言环境或非 UTF-8 控制台下报错
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
os.environ.setdefault("LANG", "zh_CN.UTF-8")
os.environ.setdefault("LC_ALL", "zh_CN.UTF-8")

from PySide6.QtCore import Qt, QTimer, QThread, Signal, QEvent, QPoint, QSize, QRectF, QPointF, QUrl
from PySide6.QtGui import (
    QIcon, QPixmap, QPainter, QColor, QFont, QAction, QMouseEvent,
    QLinearGradient, QPen, QBrush, QPainterPath, QDesktopServices, QDragEnterEvent, QDropEvent
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
from nrpt_manager import NrptManager, NRPT_DNS_PORT
from redirect_manager import (
    apply_redirect, remove_redirect, fast_remove_redirect, is_redirect_applied,
    normalize_mode as normalize_redirect_mode, MODE_NRPT
)
from nginx_manager import NginxManager
from cdn_optimizer import CDNOptimizer, CDNHealthMonitor, is_internet_available
from l4_relay import relay_server
from ech_tunnel import ech_tunnel
from dns_server import local_dns_server
from env_detector import EnvDetector
from win_utils import (
    is_process_running, is_port_in_use, is_admin, elevate_relaunch,
    is_autostart_enabled, set_autostart, register_shutdown_handler,
    fast_terminate_pid, check_proxy_alive, flush_dns_native, hide_console_window,
    is_windows_dark_mode, get_port_process_info, get_critical_ports_status, kill_process_by_pid_safe,
    get_pids_by_name
)
from ip_pool import SERVICE_GROUPS, SERVICES_LIST, SERVICES_BY_ID, DEFAULT_ENABLED_SERVICES, TOTAL_SERVICES_COUNT, CANDIDATE_IPS
from service_profile import NAVIGATOR_SERVICES, get_profile_by_domain, ServiceMode
from reverse_search import (
    SEARCH_ENGINES, ImageSearchWorker, get_image_from_clipboard, save_image_to_temp
)
from frameless_helper import NativeFramelessHelper
from md_widgets import (
    MDSwitch, TrafficMonitorChart, LatencyBadge, TitleBar,
    show_toast, InlineEditableLabel, SkeletonCard, AnimatedStackedWidget, FlowLayout,
    NoWheelComboBox, safe_theme_handler
)
from material_theme import MATERIAL_DARK_QSS, MATERIAL_LIGHT_QSS, MATERIAL_PINK_QSS, ThemeManager
from svg_icons import SvgIconFactory

# 单例实例
steam_mgr = SteamManager()
cert_mgr = CertManager()
hosts_mgr = HostsManager()
nrpt_mgr = NrptManager()
nginx_mgr = NginxManager()
cdn_opt = CDNOptimizer()

# 域名重定向分派层的运行态 (实际生效的后端 / 是否回退 / 回退原因), 供界面与日志展示
REDIRECT_STATE: Dict[str, Any] = {}


def is_ech_service(sid: str) -> bool:
    """该服务的直连是否由 ECH 隧道承担

    模块级而非 MainWindow 方法: render_cdn_results 会被轻量替身对象调用
    (见 tests/test_theme_and_layout.py 的 DummyWindow), 实例方法会导致其
    AttributeError; 本函数只依赖 cdn_opt, 不需要实例状态。

    优先看 last_ech_services (反映实际生效的状态: 隧道未就绪时会退化为常规
    直连, 此时不应显示为 ECH); 启动早期尚未跑过优化时回退到 profile 配置。
    """
    if sid in getattr(cdn_opt, "last_ech_services", set()):
        return True
    from service_profile import PROFILES_BY_ID

    profile = PROFILES_BY_ID.get(sid)
    return bool(profile and getattr(profile, "ech_enabled", False))


# 巡检周期从配置读取 (health_check_interval_seconds), 支持设置页运行中调整
health_monitor = CDNHealthMonitor(cdn_opt,
                                  check_interval=float(load_config().get("health_check_interval_seconds") or 30),
                                  on_healed=nginx_mgr.reload)

# ==================== 全局快速退出与 Windows 关机安全清理通道 ====================
_CLEANUP_LOCK = threading.Lock()
_HAS_EMERGENCY_CLEANED = False
_LAST_CLEANUP_RESULT: Dict[str, Any] = {"ok": True, "detail": "", "nrpt_left": 0}

def emergency_fast_cleanup() -> Dict[str, Any]:
    """全局快速退出与 Windows 关机清理通道 (幂等，不阻塞子进程)

    返回清理结果并**记录失败**: 删除 NRPT 规则需要管理员权限, 而非管理员运行时删除会
    静默失败 —— 残留的规则会把数百个域名指向无人监听的 127.0.0.1:53, 在整机范围内造成
    解析失败 (实测事故)。因此这里必须复查"规则是否真的没了", 并把结论落盘, 供下次启动
    提示用户 (下次提权启动时也会由 cleanup_orphans 自动回收)。
    """
    global _HAS_EMERGENCY_CLEANED, _LAST_CLEANUP_RESULT
    with _CLEANUP_LOCK:
        if _HAS_EMERGENCY_CLEANED:
            return dict(_LAST_CLEANUP_RESULT)
        _HAS_EMERGENCY_CLEANED = True

    result: Dict[str, Any] = {"ok": True, "detail": "", "nrpt_left": 0}
    redirect_ok = True
    try:
        cfg = load_config()
        if cfg.get("auto_clean_hosts_on_exit", True):
            # NRPT 规则必须一并清理: 规则残留而本机解析器已退出时, 命中域名的解析会被
            # 导向无人监听的 127.0.0.1:53, 比 Hosts 残留严重得多
            redirect_ok = bool(fast_remove_redirect(cfg, hosts_mgr, nrpt_mgr, local_dns_server))
        cert_mgr.restore_dev_environments()
    except Exception as e:
        redirect_ok = False
        result["detail"] = f"清理异常: {e}"

    # 复查 NRPT 是否真的清空 (查询不需要管理员权限, 因此这一步对非管理员运行同样有效)
    try:
        left = len(nrpt_mgr.list_own_rules())
    except Exception:
        left = 0
    result["nrpt_left"] = left
    result["ok"] = redirect_ok and left == 0
    if not result["ok"] and not result["detail"]:
        result["detail"] = (f"退出清理未完全成功: 重定向清={redirect_ok}, "
                            f"残留 NRPT 规则 {left} 条 (删除规则需管理员权限)")
    if not result["ok"]:
        print(f"[Cleanup] {result['detail']}")
        try:
            cfg = load_config()
            cfg["last_cleanup_warning"] = {"ts": int(time.time()), "detail": result["detail"]}
            save_config(cfg)
        except Exception:
            pass

    try:
        local_dns_server.stop()
        health_monitor.stop()
        relay_server.stop()
        # ECH 隧道: 与"停止加速"保持一致。遗漏的后果不只是端口(44401)被占 ——
        # 下次 start() 会发现 is_running() 为真而直接复用该进程, 若期间域名
        # 白名单变化过, 新域名不会被加载, 表现为部分站点静默不通。
        ech_tunnel.stop()
    except Exception:
        pass

    try:
        # 原生终止全部本地 Nginx 进程。必须杀"全部 nginx.exe"而非 pid 文件里的
        # 单个 PID: fast_terminate_pid 是 TerminateProcess, 不连带终止子进程,
        # 只杀 master 会留下孤儿 worker 占着 80/443 —— 它能继续服务请求, 却
        # 永远无法 reload/stop (信号通道以已死的 master 为基准), 并阻塞下次启动。
        # 仍保持本函数"不启动子进程"的约束 (不用 taskkill/nginx -s stop)。
        pids = get_pids_by_name("nginx.exe")
        if not pids:
            # 进程名枚举失败时退回 pid 文件 (至少中断 master)
            fallback = nginx_mgr.get_pid()
            pids = [fallback] if fallback > 0 else []
        for pid in pids:
            fast_terminate_pid(pid)
    except Exception:
        pass

    _LAST_CLEANUP_RESULT = result
    return dict(result)


def _register_exit_cleanup() -> None:
    """注册进程退出清理 (只能由主程序入口 main() 调用)

    绝不可放在模块级: 那样**任何** import 本模块的进程在退出时都会执行
    emergency_fast_cleanup, 而后者会终止 nginx master —— 于是留下一个孤儿 worker
    占着 80/443 (能服务请求却无法 reload/stop, 还阻塞下次启动)。
    最典型的受害者是测试套件: conftest.py 的 autouse fixture 会 import pyside_app,
    导致每跑完一次 pytest 就把用户正在运行的 nginx 打死。
    正常 GUI 退出路径已由 main() 中的 app.aboutToQuit 信号覆盖, 无需 atexit 重复兜底。
    """
    register_shutdown_handler(emergency_fast_cleanup)
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
class BackgroundTaskWorker(QThread):
    """把任意"重活"搬到后台线程执行, 完成后把结果发回 UI 线程

    用途: 子进程 (证书安装 / nginx reload / git config)、端口与进程扫描、带超时的网络探测
    这类操作放在按钮回调里会让界面冻结。统一走本 worker, 结果通过信号回到 UI 线程后再更新
    界面 —— Qt 要求所有控件操作都在主线程, 因此任务函数本身不得触碰任何 Qt 对象。
    """
    done = Signal(object)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self):
        try:
            result = self._fn(*self._args, **self._kwargs)
        except Exception as e:                      # 异常也必须回传, 否则界面永远等不到结果
            result = e
        self.done.emit(result)


class NetProbeWorker(QThread):
    """公网探活 (带超时的真实网络请求): 后台执行, 避免堵住按钮回调"""
    result = Signal(bool)

    def __init__(self, target: str, timeout: float = 0.8):
        super().__init__()
        self.target = target
        self.timeout = timeout

    def run(self):
        try:
            ok = is_internet_available(self.target, timeout=self.timeout)
        except Exception:
            ok = False
        self.result.emit(ok)


class EnvDiagnosticsWorker(QThread):
    """环境与代理诊断: 端口扫描 + 进程探测全在后台执行

    为什么必须搬离 UI 线程: EnvDetector.get_full_diagnostics 要逐个探测常见代理端口,
    在防火墙 DROP 的环境下每个端口都要等满超时, 实测可达数秒 —— 放在按钮回调/启动流程
    里就是一次明显的界面冻结。
    """
    ready = Signal(dict)

    def run(self):
        try:
            diag = EnvDetector.get_full_diagnostics()
        except Exception as e:
            diag = {"error": str(e)}
        self.ready.emit(diag)


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
    status_changed = Signal(str)

    def __init__(self, filter_services: Optional[List[str]] = None,
                 wait_network: bool = True,
                 stable_delay_sec: int = 60,
                 probe_target: str = "www.baidu.com",
                 skip_cdn_test: bool = False):
        super().__init__()
        self.filter_services = filter_services
        self.wait_network = wait_network
        self.stable_delay_sec = max(0, stable_delay_sec)
        self.probe_target = probe_target
        self.skip_cdn_test = skip_cdn_test
        self._stop_requested = False

    def request_stop(self):
        self._stop_requested = True

    def run(self):
        # 阶段 1: 外网连通性探测 (针对校园网/Portal 认证环境, 循环等待 autologin 或用户登录成功)
        if self.wait_network:
            print(f"[StartupFlow] 开始探测外网连通性 (目标: {self.probe_target})...")
            self.status_changed.emit("正在等待外网连接 (校园网认证中)...")
            max_wait_seconds = 180  # 最长探测等待 3 分钟
            deadline = time.time() + max_wait_seconds
            is_online = False
            while time.time() < deadline:
                if self._stop_requested:
                    return
                if is_internet_available(self.probe_target, timeout=0.8):
                    is_online = True
                    print("[StartupFlow] 外网探测已通畅！")
                    break
                # 每 2.5 秒探测一次，其间高频响应 stop 请求
                for _ in range(5):
                    if self._stop_requested:
                        return
                    time.sleep(0.5)

            if not is_online:
                print("[StartupFlow] 等待外网连通超时 (超过 180 秒)，结束启动流程。")
                if not self._stop_requested:
                    self.finished.emit({})
                return

        # 阶段 2: 网络稳定缓冲等待 (默认 60 秒，确保深澜网关 NAT 会话与 DNS 缓存就绪)
        if self.stable_delay_sec > 0:
            print(f"[StartupFlow] 外网已就绪，进入稳定缓冲等待 ({self.stable_delay_sec} 秒)...")
            self.status_changed.emit(f"外网已连通，等待网络稳定 ({self.stable_delay_sec}s)...")
            remain = float(self.stable_delay_sec)
            while remain > 0:
                if self._stop_requested:
                    return
                step = min(remain, 1.0)
                time.sleep(step)
                remain -= step

        # 阶段 3: 执行 CDN 测速 (在干净、稳定的公网环境下)
        if self.skip_cdn_test:
            print("[StartupFlow] 跳过 CDN 测速步骤，直接就绪。")
            results = {}
        else:
            print("[StartupFlow] 缓冲等待完毕，开始执行启动 CDN 测速优选...")
            self.status_changed.emit("正在执行 CDN 测速优选...")
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


class DropImageWidget(QFrame):
    """支持拖拽图片、粘贴与点击选择的轻量图片放置与预览区域"""
    image_selected = Signal(str)

    def __init__(self, parent_window=None):
        super().__init__(parent_window)
        self.parent_window = parent_window
        self.setAcceptDrops(True)
        self.current_image_path: Optional[str] = None
        self.setProperty("class", "DropZoneCard")
        self.setMinimumHeight(120)
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip("拖拽图片到此区域，或点击从剪贴板粘贴 / 选择文件")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)
        layout.setAlignment(Qt.AlignCenter)

        self.lbl_icon = QLabel()
        self.lbl_icon.setAlignment(Qt.AlignCenter)
        self.lbl_icon.setFixedSize(36, 36)

        self.lbl_text = QLabel("拖拽图片到此区域，或点击粘贴剪贴板 / 选择文件")
        self.lbl_text.setProperty("class", "ItemTitle")
        self.lbl_text.setAlignment(Qt.AlignCenter)

        self.lbl_subtext = QLabel("支持 JPG, PNG, WEBP, GIF, BMP (毫秒级拉起，零性能常驻)")
        self.lbl_subtext.setProperty("class", "ItemDesc")
        self.lbl_subtext.setAlignment(Qt.AlignCenter)

        layout.addWidget(self.lbl_icon, 0, Qt.AlignCenter)
        layout.addWidget(self.lbl_text)
        layout.addWidget(self.lbl_subtext)

        self.refresh_icon()

    def refresh_icon(self):
        tm = ThemeManager.get_instance()
        color = tm.get_palette().get("primary", "#7EB9F5")
        if SvgIconFactory and not self.current_image_path:
            self.lbl_icon.setPixmap(SvgIconFactory.get_pixmap("image", color, 28))

    def set_image(self, path: str):
        if not path or not os.path.exists(path):
            return
        self.current_image_path = path
        filename = os.path.basename(path)
        file_size_kb = os.path.getsize(path) / 1024
        self.lbl_text.setText(f"已选定图片: {filename} ({file_size_kb:.1f} KB)")
        self.lbl_subtext.setText("点击右侧【立即以图搜图】即可在默认浏览器打开解析结果")
        pix = QPixmap(path)
        if not pix.isNull():
            scaled_pix = pix.scaled(36, 36, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.lbl_icon.setPixmap(scaled_pix)
        self.image_selected.emit(path)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    ext = Path(url.toLocalFile()).suffix.lower()
                    if ext in [".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"]:
                        event.acceptProposedAction()
                        return
        event.ignore()

    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            if url.isLocalFile():
                file_path = url.toLocalFile()
                ext = Path(file_path).suffix.lower()
                if ext in [".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"]:
                    self.set_image(file_path)
                    event.acceptProposedAction()
                    return

    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            img = get_image_from_clipboard()
            if img:
                tmp_p = save_image_to_temp(img)
                self.set_image(tmp_p)
                if self.parent_window:
                    show_toast(self.parent_window, "已自动从剪贴板读取并加载图片！", toast_type="success", duration=2000)
                return
            path, _ = QFileDialog.getOpenFileName(
                self, "选择要检索的图片", "",
                "图片文件 (*.jpg *.jpeg *.png *.webp *.bmp *.gif);;所有文件 (*.*)"
            )
            if path:
                self.set_image(path)


class NavigatorCard(QFrame):
    """加速对象官方主站直达卡片"""
    def __init__(self, data: dict, parent_window: 'MainWindow'):
        super().__init__(parent_window)
        self.data = data
        self.parent_window = parent_window
        self.url = data.get("url", "")
        self.setProperty("class", "ServiceCard")
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip(f"双击或点击右侧按钮直接在浏览器中打开 {data.get('name', '')}")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        # 1. 矢量图标
        self.lbl_icon = QLabel()
        self.lbl_icon.setFixedSize(36, 36)
        self.lbl_icon.setAlignment(Qt.AlignCenter)
        self.lbl_icon.setProperty("class", "ServiceIconBox")
        icon_name = data.get("icon", "globe")
        tm = ThemeManager.get_instance()
        palette = tm.get_palette()
        primary_c = palette.get("primary", "#7EB9F5")
        if SvgIconFactory:
            self.lbl_icon.setPixmap(SvgIconFactory.get_pixmap(icon_name, primary_c, 20))
        layout.addWidget(self.lbl_icon)

        # 2. 中间信息区
        text_box = QVBoxLayout()
        text_box.setSpacing(2)

        row_title = QHBoxLayout()
        row_title.setSpacing(8)
        lbl_name = QLabel(data.get("name", ""))
        lbl_name.setProperty("class", "ItemTitle")
        lbl_name.setWordWrap(True)
        row_title.addWidget(lbl_name)

        lbl_domain = QLabel(data.get("domain", ""))
        lbl_domain.setProperty("class", "LatencyBadgeIdle")
        row_title.addWidget(lbl_domain)
        row_title.addStretch()
        text_box.addLayout(row_title)

        lbl_desc = QLabel(data.get("desc", ""))
        lbl_desc.setProperty("class", "ItemDesc")
        lbl_desc.setWordWrap(True)
        text_box.addWidget(lbl_desc)

        layout.addLayout(text_box, stretch=1)

        # 3. 右侧直达按钮
        btn_open = QPushButton("访问官网")
        btn_open.setProperty("class", "MDBtnTonal")
        if SvgIconFactory:
            btn_open.setIcon(SvgIconFactory.get_icon("external_link", primary_c, 14))
            btn_open.setIconSize(QSize(14, 14))
        btn_open.clicked.connect(self.open_url)
        layout.addWidget(btn_open)

        # 4. QUIC 直连按钮 (仅对"TCP 侧 SNI 被 RST、仅 UDP/443 可达"的服务显示)
        #    总开关停用时不显示 (见 quic_probe.QUIC_ENABLED)
        self.quic_profile = None
        try:
            from quic_probe import is_enabled as _quic_enabled
            _quic_on = _quic_enabled()
        except Exception:
            _quic_on = False
        try:
            prof = get_profile_by_domain(data.get("domain", ""))
            if _quic_on and prof and prof.mode == ServiceMode.QUIC_DIRECT and prof.candidate_ips:
                self.quic_profile = prof
        except Exception:
            self.quic_profile = None

        if self.quic_profile is not None:
            btn_quic = QPushButton("QUIC 直连")
            btn_quic.setProperty("class", "MDBtnTonal")
            btn_quic.setToolTip("该站点 TCP 侧 TLS 被阻断, 以 HTTP/3(QUIC) 直连方式打开 "
                                "(独立浏览器配置目录; 不走代理)")
            btn_quic.clicked.connect(self.open_quic)
            layout.addWidget(btn_quic)

    def open_quic(self):
        """以 QUIC(HTTP/3) 直连方式启动浏览器打开本站"""
        prof = self.quic_profile
        if prof is None:
            return
        domain = prof.domains[0]
        import quic_launcher
        ok, msg, _ = quic_launcher.launch(domain, extra_domains=prof.domains[1:], url=self.url)
        if self.parent_window:
            show_toast(self.parent_window, msg,
                       toast_type="success" if ok else "error", duration=4500)

    def open_url(self):
        if self.url:
            QDesktopServices.openUrl(QUrl(self.url))
            if self.parent_window:
                show_toast(self.parent_window, f"已在浏览器中打开: {self.data.get('name', '')}", toast_type="info", duration=2000)

    def mouseDoubleClickEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            self.open_url()
            event.accept()
        else:
            super().mouseDoubleClickEvent(event)


class ToolHubCard(QFrame):
    """工具箱功能入口大卡片"""
    clicked = Signal()

    def __init__(self, title: str, tag: str, desc: str, icon_name: str, parent=None):
        super().__init__(parent)
        self.setProperty("class", "MDCard")
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip(f"点击进入 {title}")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(18)

        # 1. 矢量图标容器 (46x46 圆角微底色盒子)
        self.lbl_icon = QLabel()
        self.lbl_icon.setFixedSize(46, 46)
        self.lbl_icon.setAlignment(Qt.AlignCenter)
        self.lbl_icon.setProperty("class", "ServiceIconBox")
        tm = ThemeManager.get_instance()
        palette = tm.get_palette()
        primary_c = palette.get("primary", "#7EB9F5")
        if SvgIconFactory:
            self.lbl_icon.setPixmap(SvgIconFactory.get_pixmap(icon_name, primary_c, 24))
        layout.addWidget(self.lbl_icon)

        # 2. 中间说明文案
        text_box = QVBoxLayout()
        text_box.setSpacing(4)

        row_title = QHBoxLayout()
        row_title.setSpacing(10)
        lbl_t = QLabel(title)
        lbl_t.setProperty("class", "SectionHeaderTitle")
        lbl_t.setStyleSheet("font-size: 15px; font-weight: bold;")
        row_title.addWidget(lbl_t)

        lbl_tag = QLabel(f" {tag} ")
        lbl_tag.setProperty("class", "LatencyBadgeIdle")
        row_title.addWidget(lbl_tag)
        row_title.addStretch()
        text_box.addLayout(row_title)

        lbl_d = QLabel(desc)
        lbl_d.setProperty("class", "ItemDesc")
        lbl_d.setWordWrap(True)
        text_box.addWidget(lbl_d)

        layout.addLayout(text_box, stretch=1)

        # 3. 右侧进入按钮
        btn_enter = QPushButton("进入工具 →")
        btn_enter.setProperty("class", "MDBtnPrimary")
        btn_enter.clicked.connect(self.clicked.emit)
        layout.addWidget(btn_enter)

    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
            event.accept()
        else:
            super().mousePressEvent(event)


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
        self._startup_flow_in_progress: bool = False

        # 控制台分块折叠
        self.collapsed_sections: Set[str] = set(load_config().get("collapsed_dashboard_sections", []))
        self.group_collapse_buttons: Dict[str, QPushButton] = {}
        self.group_content_widgets: Dict[str, QWidget] = {}
        self.chart_collapse_btn: Optional[QPushButton] = None
        self.chart_container: Optional[QWidget] = None
        self.btn_toggle_all_collapse: Optional[QPushButton] = None

        # CDN 测速页面状态横幅
        self.cdn_status_banner: Optional[QFrame] = None
        self.lbl_cdn_status_summary: Optional[QLabel] = None
        self.lbl_cdn_last_time: Optional[QLabel] = None

        # 实用工具箱主栈
        self.toolbox_stack: Optional[AnimatedStackedWidget] = None

        # 以图搜图与快捷导航引用
        self.search_worker: Optional[ImageSearchWorker] = None
        self.drop_image_widget: Optional[DropImageWidget] = None
        self.cmb_search_engine: Optional[NoWheelComboBox] = None
        self.nav_card_widgets: List[Tuple[QFrame, Dict[str, Any]]] = []
        self.nav_group_cards: Dict[str, QFrame] = {}

        # 端口操作引用
        self.critical_port_labels: Dict[int, QLabel] = {}
        self.critical_port_btn_release: Dict[int, QPushButton] = {}
        self.port_results_layout: Optional[QVBoxLayout] = None
        self.txt_custom_port: Optional[QLineEdit] = None
        self.lbl_custom_port_summary: Optional[QLabel] = None

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
        ThemeManager.get_instance().theme_changed.connect(safe_theme_handler(self, "on_theme_changed"))
        ThemeManager.get_instance().set_theme(current_theme, QApplication.instance())
        if self.frameless_helper:
            self.frameless_helper.set_immersive_dark_mode(current_theme == "dark")

        # 3. 加载初始状态
        self._start_status_probe()
        self.load_steam_accounts_ui()

        # 上次退出/异常终止遗留的清理告警必须显式告知: 残留的 NRPT 规则会把数百个域名
        # 指向无人监听的 127.0.0.1:53, 表现为"突然所有加速站点都打不开"。静默失败等于
        # 让用户自己去猜原因 (实测事故)。这里在界面拉起后提示, 并给出可执行的处理方式。
        try:
            warn = load_config().get("last_cleanup_warning") or {}
            if warn.get("detail"):
                QTimer.singleShot(1200, lambda d=warn.get("detail"): show_toast(
                    self,
                    f"上次退出未清理干净: {d}。请以管理员身份启动本程序以自动回收残留。",
                    toast_type="warning", duration=9000))
        except Exception:
            pass

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

        # 4. 自动托管与启动测速编排流程 (支持"外网连通并测速后再开启代理劫持")
        auto_proxy_enabled = cfg.get("auto_proxy", True)
        auto_cdn_enabled = cfg.get("auto_cdn_optimize_on_startup", True)
        defer_proxy = cfg.get("auto_proxy_after_cdn", True)

        if defer_proxy and (auto_proxy_enabled or auto_cdn_enabled):
            # 开启了"延迟到测速后启用代理": 开机不立即写入 hosts 劫持流量,
            # 而是由启动编排 Worker 先探活外网、缓冲稳定并测速, 测速成功后再正式启用代理
            self._startup_flow_in_progress = True
            print("[StartupFlow] 已启用测速后启动代理策略，等待外网就绪与测速完成...")
            QTimer.singleShot(1500, self.trigger_startup_auto_cdn)
        else:
            # 传统模式: 立即启用加速
            if auto_proxy_enabled:
                if not nginx_mgr.is_running() or not self._is_redirect_active():
                    self.start_acceleration(show_toast_on_fail=False)
            if auto_cdn_enabled:
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

            if getattr(self, "chart_collapse_btn", None):
                is_c = ("traffic_chart" in self.collapsed_sections)
                self.chart_collapse_btn.setIcon(SvgIconFactory.get_icon("chevron_down" if is_c else "chevron_up", primary_icon_color, 14))

            for gid, btn in getattr(self, "group_collapse_buttons", {}).items():
                is_c = (gid in self.collapsed_sections)
                btn.setIcon(SvgIconFactory.get_icon("chevron_down" if is_c else "chevron_up", primary_icon_color, 14))

            for sid, btn in getattr(self, "cdn_single_buttons", {}).items():
                btn.setIcon(SvgIconFactory.get_icon("zap", primary_icon_color, 12))

            if getattr(self, "drop_image_widget", None):
                self.drop_image_widget.refresh_icon()

        
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
        brand_layout.setContentsMargins(0, 0, 0, 16)
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
        self.btn_nav_toolbox = self.create_nav_btn("实用工具箱", 1, "grid")
        self.btn_nav_steam = self.create_nav_btn("Steam 账号管家", 2, "gamepad")
        self.btn_nav_cdn = self.create_nav_btn("CDN 测速", 3, "zap")
        self.btn_nav_settings = self.create_nav_btn("系统诊断与设置", 4, "settings")

        sidebar_layout.addWidget(self.btn_nav_dashboard)
        sidebar_layout.addWidget(self.btn_nav_toolbox)
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
        self.page_toolbox = self.create_toolbox_page()
        self.page_steam = self.create_steam_page()
        self.page_cdn = self.create_cdn_page()
        self.page_settings = self.create_settings_page()

        self.stack.addWidget(self.page_dashboard)
        self.stack.addWidget(self.page_toolbox)
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
        if index == 2:
            self.load_steam_accounts_ui()
        elif index == 4:
            self.refresh_ports_diagnostics_ui()

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

        # 页面标题与一键收拢/展开操作
        header_row = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("加速控制中心")
        title.setObjectName("PageTitle")
        desc = QLabel("自动托管网络代理与 Hosts 规则，加速热门海外游戏、创作与开发服务")
        desc.setObjectName("PageDesc")
        title_box.addWidget(title)
        title_box.addWidget(desc)
        header_row.addLayout(title_box)
        header_row.addStretch()

        is_all_collapsed = (len(self.collapsed_sections) >= len(SERVICE_GROUPS) + 1)
        self.btn_toggle_all_collapse = QPushButton("全部展开" if is_all_collapsed else "全部折叠")
        self.btn_toggle_all_collapse.setProperty("class", "MDBtnOutlined")
        self.btn_toggle_all_collapse.setCursor(Qt.PointingHandCursor)
        self.btn_toggle_all_collapse.clicked.connect(self.toggle_all_sections_collapse)
        header_row.addWidget(self.btn_toggle_all_collapse)
        layout.addLayout(header_row)

        # 1. 实时网络流量监控波形图 (带独立收拢折叠控制)
        is_dark = ThemeManager.get_instance().is_dark
        primary_c = "#7EB9F5" if is_dark else "#0284C7"
        chart_card = QFrame()
        chart_card.setProperty("class", "MDCard")
        cc_layout = QVBoxLayout(chart_card)
        cc_layout.setContentsMargins(20, 14, 20, 14)
        cc_layout.setSpacing(10)

        chart_head = QHBoxLayout()
        lbl_chart_icon = QLabel()
        lbl_chart_icon.setFixedSize(20, 20)
        if SvgIconFactory:
            lbl_chart_icon.setPixmap(SvgIconFactory.get_pixmap("activity", primary_c, 18))
        chart_head.addWidget(lbl_chart_icon)

        lbl_chart_title = QLabel("实时网络流量监控")
        lbl_chart_title.setProperty("class", "CategoryTitle")
        chart_head.addWidget(lbl_chart_title)
        chart_head.addStretch()

        is_chart_collapsed = ("traffic_chart" in self.collapsed_sections)
        self.chart_collapse_btn = QPushButton("展开" if is_chart_collapsed else "收起")
        self.chart_collapse_btn.setProperty("class", "MDBtnOutlined")
        self.chart_collapse_btn.setCursor(Qt.PointingHandCursor)
        chart_btn_icon = "chevron_down" if is_chart_collapsed else "chevron_up"
        self.chart_collapse_btn.setIcon(SvgIconFactory.get_icon(chart_btn_icon, primary_c, 14) if SvgIconFactory else QIcon())
        self.chart_collapse_btn.clicked.connect(lambda: self.toggle_section_collapse("traffic_chart"))
        chart_head.addWidget(self.chart_collapse_btn)
        cc_layout.addLayout(chart_head)

        self.traffic_chart = TrafficMonitorChart()
        cc_layout.addWidget(self.traffic_chart)
        if is_chart_collapsed:
            self.traffic_chart.setVisible(False)
        self.chart_container = chart_card
        layout.addWidget(chart_card)

        # 2. 顶部四合一状态指示卡片
        stat_grid = QGridLayout()
        stat_grid.setSpacing(12)
        for c_idx in range(4):
            stat_grid.setColumnStretch(c_idx, 1)

        self.card_stat_nginx = self.create_stat_card("Nginx 数据平面", "检测中...", "反代引擎与磁盘缓存", "server")
        self.card_stat_cert = self.create_stat_card("Windows 根证书", "检测中...", "系统受信任证书库", "lock")
        self.card_stat_hosts = self.create_stat_card("Hosts 规则库", "未注入", "专属规则块隔离", "file_text")
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

        # 4. 加速服务列表 (3 大分类分组卡片, 具备一键收起/展开功能, FlowLayout 流式排布)
        cfg_services = set(load_config().get("enabled_services", DEFAULT_ENABLED_SERVICES))
        for grp_id, grp_info in SERVICE_GROUPS.items():
            grp_card = self._build_service_group_card(grp_id, grp_info, cfg_services)
            layout.addWidget(grp_card)

        layout.addStretch()
        scroll.setWidget(content)
        return scroll

    def _build_service_group_card(self, grp_id: str, grp_info: dict, cfg_services: set) -> QFrame:
        """构建单个服务生态分类卡片 (包含头部操作栏、收起/展开折叠控件与 FlowLayout 服务列表)"""
        grp_card = QFrame()
        grp_card.setProperty("class", "MDCard")
        self.group_cards[grp_id] = grp_card
        grp_card_layout = QVBoxLayout(grp_card)
        grp_card_layout.setContentsMargins(20, 16, 20, 16)
        grp_card_layout.setSpacing(12)

        grp_header = QHBoxLayout()
        grp_header.setSpacing(10)

        grp_icon_lbl = QLabel()
        grp_icon_lbl.setFixedSize(22, 22)
        is_dark = ThemeManager.get_instance().is_dark
        icon_c = "#D0BCFF" if is_dark else "#6750A4"
        grp_icon_lbl.setPixmap(SvgIconFactory.get_pixmap(grp_info.get("icon", "zap"), icon_c, 20))
        self.group_icon_labels[grp_id] = (grp_icon_lbl, grp_info.get("icon", "zap"))
        grp_header.addWidget(grp_icon_lbl)

        grp_title_box = QVBoxLayout()
        grp_title_box.setSpacing(2)
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
        btn_enable_all.setCursor(Qt.PointingHandCursor)
        btn_enable_all.clicked.connect(lambda _, g=grp_id: self.toggle_group_services(g, True))

        btn_disable_all = QPushButton("全关")
        btn_disable_all.setProperty("class", "MDBtnOutlined")
        btn_disable_all.setCursor(Qt.PointingHandCursor)
        btn_disable_all.clicked.connect(lambda _, g=grp_id: self.toggle_group_services(g, False))

        # 收起/展开折叠切换按钮
        is_collapsed = (grp_id in self.collapsed_sections)
        btn_collapse = QPushButton("展开" if is_collapsed else "收起")
        btn_collapse.setProperty("class", "MDBtnOutlined")
        btn_collapse.setCursor(Qt.PointingHandCursor)
        btn_icon_name = "chevron_down" if is_collapsed else "chevron_up"
        btn_collapse.setIcon(SvgIconFactory.get_icon(btn_icon_name, "#7EB9F5" if is_dark else "#0284C7", 14) if SvgIconFactory else QIcon())
        btn_collapse.clicked.connect(lambda _, g=grp_id: self.toggle_section_collapse(g))
        self.group_collapse_buttons[grp_id] = btn_collapse

        grp_header.addWidget(btn_enable_all)
        grp_header.addWidget(btn_disable_all)
        grp_header.addWidget(btn_collapse)
        grp_card_layout.addLayout(grp_header)

        # 折叠主体内容容器
        grp_content = QWidget()
        self.group_content_widgets[grp_id] = grp_content
        grp_content_layout = QVBoxLayout(grp_content)
        grp_content_layout.setContentsMargins(0, 4, 0, 0)
        grp_content_layout.setSpacing(0)

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

        grp_content_layout.addLayout(items_flow)
        grp_card_layout.addWidget(grp_content)

        if is_collapsed:
            grp_content.setVisible(False)

        return grp_card

    def toggle_section_collapse(self, section_id: str):
        """折叠/展开主控制台指定分块并持久化状态"""
        cfg = load_config()
        collapsed = set(cfg.get("collapsed_dashboard_sections", []))
        if section_id in collapsed:
            collapsed.discard(section_id)
            is_collapsed = False
        else:
            collapsed.add(section_id)
            is_collapsed = True

        cfg["collapsed_dashboard_sections"] = list(collapsed)
        save_config(cfg)
        self.collapsed_sections = collapsed

        self._update_section_collapse_ui(section_id, is_collapsed)
        self._update_toggle_all_button_text()

    def toggle_all_sections_collapse(self):
        """一键全部折叠或全部展开控制台分块"""
        all_ids = set(SERVICE_GROUPS.keys()) | {"traffic_chart"}
        cfg = load_config()
        if len(self.collapsed_sections) >= len(all_ids):
            # 当前全部处于折叠状态 -> 全部展开
            self.collapsed_sections.clear()
        else:
            # 否则全部折叠
            self.collapsed_sections = set(all_ids)

        cfg["collapsed_dashboard_sections"] = list(self.collapsed_sections)
        save_config(cfg)

        for sid in all_ids:
            self._update_section_collapse_ui(sid, sid in self.collapsed_sections)
        self._update_toggle_all_button_text()

    def _update_toggle_all_button_text(self):
        if hasattr(self, "btn_toggle_all_collapse") and self.btn_toggle_all_collapse:
            all_ids = set(SERVICE_GROUPS.keys()) | {"traffic_chart"}
            if len(self.collapsed_sections) >= len(all_ids):
                self.btn_toggle_all_collapse.setText("全部展开")
            else:
                self.btn_toggle_all_collapse.setText("全部折叠")

    def _update_section_collapse_ui(self, section_id: str, is_collapsed: bool):
        """刷新指定分块在折叠/展开状态下的可视性与按钮图标文字"""
        is_dark = ThemeManager.get_instance().is_dark
        primary_c = "#7EB9F5" if is_dark else "#0284C7"
        if section_id == "traffic_chart":
            if hasattr(self, "traffic_chart") and self.traffic_chart:
                self.traffic_chart.setVisible(not is_collapsed)
            if hasattr(self, "chart_collapse_btn") and self.chart_collapse_btn:
                self.chart_collapse_btn.setText("展开" if is_collapsed else "收起")
                icon_name = "chevron_down" if is_collapsed else "chevron_up"
                self.chart_collapse_btn.setIcon(SvgIconFactory.get_icon(icon_name, primary_c, 14) if SvgIconFactory else QIcon())
        elif section_id in self.group_content_widgets:
            self.group_content_widgets[section_id].setVisible(not is_collapsed)
            btn = self.group_collapse_buttons.get(section_id)
            if btn:
                btn.setText("展开" if is_collapsed else "收起")
                icon_name = "chevron_down" if is_collapsed else "chevron_up"
                btn.setIcon(SvgIconFactory.get_icon(icon_name, primary_c, 14) if SvgIconFactory else QIcon())

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
        """主控制台加速服务实时模糊搜索与分类动态折叠联动 (支持中文/英文/缩写别名，命中时自动展开折叠)"""
        kw = keyword.strip().lower()
        if not kw:
            for s_card in self.service_cards.values():
                s_card.setVisible(True)
            for gid, g_card in self.group_cards.items():
                g_card.setVisible(True)
                # 恢复用户持久化的折叠状态
                is_col = (gid in self.collapsed_sections)
                if gid in self.group_content_widgets:
                    self.group_content_widgets[gid].setVisible(not is_col)
            return

        # 别名映射辅助快速检索 (如 'gh' 匹配 github, 'px' 匹配 pixiv)
        alias_map = {
            "gh": ["github"], "px": ["pixiv"], "st": ["steam"], "hf": ["huggingface"],
            "gl": ["gitlab"], "fb": ["fanbox"], "bt": ["booth"],
            "vn": ["vndb"], "ubi": ["ubisoft"],
            "art": ["pixiv", "fanbox", "booth"],
            "game": ["steam", "ubisoft"], "dev": ["github", "gitlab", "huggingface"]
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
            has_match = group_has_visible.get(gid, False)
            grp_card.setVisible(has_match)
            # 若该组有匹配结果，自动临时展开内容以便用户即时查看与操作
            if has_match and gid in self.group_content_widgets:
                self.group_content_widgets[gid].setVisible(True)

    def toggle_group_services(self, group_id: str, enable: bool):
        """批量启用或关闭某生态分组全量服务，并即刻同步 Hosts 与界面胶囊"""
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

        new_list = sorted(list(services))
        cfg["enabled_services"] = new_list
        save_config(cfg)

        # 若加速运行中或重定向规则已注入，即刻动态调整规则并刷新 DNS
        if nginx_mgr.is_running() or self._is_redirect_active():
            self._apply_redirect(new_list)

        action_name = "启用" if enable else "禁用"
        show_toast(self, f"已{action_name} [{SERVICE_GROUPS.get(group_id, {}).get('name', group_id)}] 全部分类服务并同步更新 Hosts", toast_type="info", duration=2000)

    def on_service_toggled(self, service_id: str, checked: bool):
        """单个加速服务开关切换: 立即更新配置并在加速激活时自动调整 Hosts 规则"""
        self._update_service_icon(service_id, checked)
        cfg = load_config()
        services = set(cfg.get("enabled_services", DEFAULT_ENABLED_SERVICES))
        if checked:
            services.add(service_id)
        else:
            services.discard(service_id)

        new_list = sorted(list(services))
        cfg["enabled_services"] = new_list
        save_config(cfg)

        srv_info = SERVICES_BY_ID.get(service_id)

        # 若加速处于运行状态或重定向规则已注入，即刻动态调整
        if nginx_mgr.is_running() or self._is_redirect_active():
            h_ok, h_msg = self._apply_redirect(new_list)
            srv_name = srv_info["name"] if srv_info else service_id
            if not checked:
                show_toast(self, f"已关闭 [{srv_name}] 加速，已自动移除对应重定向规则", toast_type="info", duration=1800)
            elif h_ok:
                show_toast(self, f"已开启 [{srv_name}] 加速并注入重定向规则", toast_type="success", duration=1800)

    # ------------------ PAGE 2: 实用工具箱 (Toolbox Hub & Sub-pages) ------------------
    def create_toolbox_page(self) -> QWidget:
        self.toolbox_stack = AnimatedStackedWidget()

        # Index 0: 工具箱大厅 (Hub)
        self.toolbox_hub_view = self._build_toolbox_hub_view()
        # Index 1: 以图搜图工作台 (Search)
        self.toolbox_search_view = self._build_toolbox_search_view()
        # Index 2: 端口管理与释放 (Ports)
        self.toolbox_ports_view = self._build_toolbox_ports_view()
        # Index 3: 加速生态主站导航 (Navigator)
        self.toolbox_nav_view = self._build_toolbox_nav_view()

        self.toolbox_stack.addWidget(self.toolbox_hub_view)
        self.toolbox_stack.addWidget(self.toolbox_search_view)
        self.toolbox_stack.addWidget(self.toolbox_ports_view)
        self.toolbox_stack.addWidget(self.toolbox_nav_view)

        return self.toolbox_stack

    def _build_toolbox_hub_view(self) -> QWidget:
        """工具箱大厅：展示三大功能卡片入口"""
        scroll = QScrollArea()
        scroll.setObjectName("MainScrollArea")
        scroll.setWidgetResizable(True)

        content = QWidget()
        content.setObjectName("ScrollContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 20, 20, 20)
        layout.setSpacing(18)

        # 页面标题
        header_box = QVBoxLayout()
        header_box.setSpacing(4)
        title = QLabel("实用工具箱")
        title.setObjectName("PageTitle")
        desc = QLabel("聚合以图搜图、端口管理与加速生态快捷导航，即点即用，极低资源占用")
        desc.setObjectName("PageDesc")
        header_box.addWidget(title)
        header_box.addWidget(desc)
        layout.addLayout(header_box)

        # 1. 以图搜图卡片
        card_search = ToolHubCard(
            title="以图搜图工作台 (Reverse Image Search)",
            tag="二次元 / 画师检索",
            desc="支持系统剪贴板图片快速抓取与本地文件拖拽，内置 SauceNAO、Ascii2d、Google Lens、IQDB 多引擎，秒级定位 Pixiv PID、推特画师与高清原图。",
            icon_name="image",
            parent=self
        )
        card_search.clicked.connect(lambda: self.toolbox_stack.setCurrentIndex(1))
        layout.addWidget(card_search)

        # 2. 端口管理与释放卡片
        card_ports = ToolHubCard(
            title="端口占用诊断与进程释放 (Port Manager)",
            tag="系统排障 / 冲突自愈",
            desc="支持任意端口 (1-65535) 精准搜索与连接进程强杀，提供 80 / 443 / 53 加速核心端口状态一键体检与冲突释放。",
            icon_name="network",
            parent=self
        )
        card_ports.clicked.connect(self._enter_toolbox_ports_action)
        layout.addWidget(card_ports)

        # 3. 生态主站快捷导航卡片
        card_nav = ToolHubCard(
            title="加速生态官方主站直达 (Service Navigator)",
            tag="官方入口 / 极速直达",
            desc="聚合 Pixiv、FANBOX、BOOTH、Steam 商店/社区、育碧、战网、GOG、GitHub、HuggingFace 等官方入口，支持关键词实时筛选与一键打开。",
            icon_name="compass",
            parent=self
        )
        card_nav.clicked.connect(lambda: self.toolbox_stack.setCurrentIndex(3))
        layout.addWidget(card_nav)

        layout.addStretch()
        scroll.setWidget(content)
        return scroll

    def _enter_toolbox_ports_action(self):
        self.toolbox_stack.setCurrentIndex(2)
        self.refresh_ports_diagnostics_ui()

    def _create_toolbox_subpage_header(self, title_text: str, back_target_idx: int = 0) -> QHBoxLayout:
        """生成统一规范的子页面返回导航头"""
        h_layout = QHBoxLayout()
        h_layout.setSpacing(12)

        btn_back = QPushButton(" 返回工具箱")
        btn_back.setProperty("class", "MDBtnTonal")
        tm = ThemeManager.get_instance()
        primary_c = tm.get_palette().get("primary", "#7EB9F5")
        if SvgIconFactory:
            btn_back.setIcon(SvgIconFactory.get_icon("arrow_left", primary_c, 14))
            btn_back.setIconSize(QSize(14, 14))
        btn_back.clicked.connect(lambda: self.toolbox_stack.setCurrentIndex(back_target_idx))
        h_layout.addWidget(btn_back)

        lbl_sub_title = QLabel(title_text)
        lbl_sub_title.setObjectName("PageTitle")
        lbl_sub_title.setStyleSheet("font-size: 18px;")
        h_layout.addWidget(lbl_sub_title)
        h_layout.addStretch()
        return h_layout

    def _build_toolbox_search_view(self) -> QWidget:
        """子页面 1: 以图搜图工作台"""
        scroll = QScrollArea()
        scroll.setObjectName("MainScrollArea")
        scroll.setWidgetResizable(True)

        content = QWidget()
        content.setObjectName("ScrollContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 20, 20, 20)
        layout.setSpacing(18)

        # 返回头
        layout.addLayout(self._create_toolbox_subpage_header("以图搜图工作台 (Reverse Image Search)"))

        is_dark = ThemeManager.get_instance().is_dark
        primary_c = "#7EB9F5" if is_dark else "#0284C7"

        search_box_card = QFrame()
        search_box_card.setProperty("class", "MDCard")
        s_layout = QVBoxLayout(search_box_card)
        s_layout.setContentsMargins(20, 16, 20, 16)
        s_layout.setSpacing(14)

        # 图片拖拽与选择区域
        self.drop_image_widget = DropImageWidget(self)
        self.drop_image_widget.image_selected.connect(self._on_image_selected_for_search)
        s_layout.addWidget(self.drop_image_widget)

        # 搜图引擎选择与控制栏
        ctrl_row = QHBoxLayout()
        ctrl_row.setSpacing(10)

        lbl_engine = QLabel("搜图引擎:")
        lbl_engine.setProperty("class", "ItemTitle")
        ctrl_row.addWidget(lbl_engine)

        self.cmb_search_engine = NoWheelComboBox()
        for eid, edata in SEARCH_ENGINES.items():
            self.cmb_search_engine.addItem(edata["name"], eid)
        ctrl_row.addWidget(self.cmb_search_engine)

        btn_paste = QPushButton("粘贴剪贴板图片")
        btn_paste.setProperty("class", "MDBtnTonal")
        if SvgIconFactory:
            btn_paste.setIcon(SvgIconFactory.get_icon("copy", primary_c, 14))
            btn_paste.setIconSize(QSize(14, 14))
        btn_paste.clicked.connect(self._paste_image_from_clipboard_action)
        ctrl_row.addWidget(btn_paste)

        btn_browse = QPushButton("选择本地图片")
        btn_browse.setProperty("class", "MDBtnTonal")
        if SvgIconFactory:
            btn_browse.setIcon(SvgIconFactory.get_icon("upload", primary_c, 14))
            btn_browse.setIconSize(QSize(14, 14))
        btn_browse.clicked.connect(self._browse_image_file_action)
        ctrl_row.addWidget(btn_browse)

        ctrl_row.addStretch()

        self.btn_do_search = QPushButton("立即以图搜图")
        self.btn_do_search.setProperty("class", "MDBtnPrimary")
        if SvgIconFactory:
            self.btn_do_search.setIcon(SvgIconFactory.get_icon("search", "#FFFFFF", 14))
            self.btn_do_search.setIconSize(QSize(14, 14))
        self.btn_do_search.clicked.connect(self.start_reverse_image_search)
        ctrl_row.addWidget(self.btn_do_search)

        s_layout.addLayout(ctrl_row)
        layout.addWidget(search_box_card)

        # 使用指南与说明卡片
        tip_card = QFrame()
        tip_card.setProperty("class", "MDCard")
        t_layout = QVBoxLayout(tip_card)
        t_layout.setContentsMargins(20, 16, 20, 16)
        t_layout.setSpacing(6)

        lbl_t_title = QLabel("使用提示与搜图引擎推荐")
        lbl_t_title.setProperty("class", "ItemTitle")
        t_layout.addWidget(lbl_t_title)

        tips = [
            "• SauceNAO：二次元插画主力，识别率极高，可直接精准定位 Pixiv PID、画师 UID 与 Fanbox 出处。",
            "• Ascii2d：推特插画神器，特别适合查找 Twitter 同人画师发布的作品推文与原图。",
            "• IQDB：二次元动漫壁纸检索站，适合检索动漫截图与各大图库收录图。",
            "• Google Lens：通用智能识图，适合全网广域搜索与物品/人物识别。"
        ]
        for tip in tips:
            lbl_tip = QLabel(tip)
            lbl_tip.setProperty("class", "ItemDesc")
            lbl_tip.setWordWrap(True)
            t_layout.addWidget(lbl_tip)

        layout.addWidget(tip_card)
        layout.addStretch()
        scroll.setWidget(content)
        return scroll

    def _build_toolbox_ports_view(self) -> QWidget:
        """子页面 2: 端口管理与进程释放"""
        scroll = QScrollArea()
        scroll.setObjectName("MainScrollArea")
        scroll.setWidgetResizable(True)

        content = QWidget()
        content.setObjectName("ScrollContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 20, 20, 20)
        layout.setSpacing(18)

        # 返回头
        layout.addLayout(self._create_toolbox_subpage_header("端口占用诊断与进程释放 (Port Manager)"))

        is_dark = ThemeManager.get_instance().is_dark
        primary_c = "#7EB9F5" if is_dark else "#0284C7"

        # 核心端口卡片
        crit_card = QFrame()
        crit_card.setProperty("class", "MDCard")
        c_layout = QVBoxLayout(crit_card)
        c_layout.setContentsMargins(20, 16, 20, 16)
        c_layout.setSpacing(12)

        c_header = QHBoxLayout()
        lbl_c_title = QLabel("加速核心端口状态 (80 / 443 / 53)")
        lbl_c_title.setProperty("class", "SectionHeaderTitle")
        c_header.addWidget(lbl_c_title)
        c_header.addStretch()

        btn_refresh_ports = QPushButton("重新体检")
        btn_refresh_ports.setProperty("class", "MDBtnTonal")
        btn_refresh_ports.clicked.connect(self.refresh_ports_diagnostics_ui)
        c_header.addWidget(btn_refresh_ports)
        c_layout.addLayout(c_header)

        crit_box = QVBoxLayout()
        crit_box.setSpacing(8)

        for port, port_name in [(80, "80 (HTTP / 本地反代)"), (443, "443 (HTTPS / 本地反代)"), (53, "53 (DNS / 本地分流)")]:
            row = QHBoxLayout()
            row.setSpacing(10)
            lbl_name = QLabel(port_name)
            lbl_name.setProperty("class", "ItemDesc")
            lbl_name.setFixedWidth(180)
            row.addWidget(lbl_name)

            lbl_status = QLabel("检测中...")
            lbl_status.setProperty("class", "ItemDesc")
            row.addWidget(lbl_status, stretch=1)
            self.critical_port_labels[port] = lbl_status

            btn_rel = QPushButton("释放端口")
            btn_rel.setProperty("class", "MDBtnDanger")
            btn_rel.setVisible(False)
            btn_rel.clicked.connect(lambda p=port: self.release_critical_port_action(p))
            row.addWidget(btn_rel)
            self.critical_port_btn_release[port] = btn_rel

            crit_box.addLayout(row)

        c_layout.addLayout(crit_box)
        layout.addWidget(crit_card)

        # 指定端口搜索与精准释放卡片
        search_port_card = QFrame()
        search_port_card.setProperty("class", "MDCard")
        sp_layout = QVBoxLayout(search_port_card)
        sp_layout.setContentsMargins(20, 16, 20, 16)
        sp_layout.setSpacing(12)

        lbl_sp_title = QLabel("指定端口精准查询与释放")
        lbl_sp_title.setProperty("class", "SectionHeaderTitle")
        sp_layout.addWidget(lbl_sp_title)

        search_row = QHBoxLayout()
        search_row.setSpacing(10)

        self.txt_custom_port = QLineEdit()
        self.txt_custom_port.setPlaceholderText("输入要查询的端口号 (1-65535，如 8080, 7890, 3000)...")
        self.txt_custom_port.setProperty("class", "SearchInput")
        self.txt_custom_port.returnPressed.connect(self.search_custom_port_action)
        search_row.addWidget(self.txt_custom_port, stretch=1)

        btn_search_p = QPushButton("查询占用")
        btn_search_p.setProperty("class", "MDBtnPrimary")
        if SvgIconFactory:
            btn_search_p.setIcon(SvgIconFactory.get_icon("search", "#FFFFFF", 14))
            btn_search_p.setIconSize(QSize(14, 14))
        btn_search_p.clicked.connect(self.search_custom_port_action)
        search_row.addWidget(btn_search_p)
        sp_layout.addLayout(search_row)

        # 搜索结果容器
        self.port_results_layout = QVBoxLayout()
        self.port_results_layout.setSpacing(6)
        self.lbl_custom_port_summary = QLabel("输入任意端口号并点击【查询占用】，可毫秒级查看占用该端口的 PID 与程序路径。")
        self.lbl_custom_port_summary.setProperty("class", "ItemDesc")
        self.port_results_layout.addWidget(self.lbl_custom_port_summary)
        sp_layout.addLayout(self.port_results_layout)

        layout.addWidget(search_port_card)
        layout.addStretch()
        scroll.setWidget(content)
        return scroll

    def refresh_ports_diagnostics_ui(self):
        """刷新核心端口占用诊断状态 (端口/进程扫描放后台, 避免点击即卡)"""
        worker = getattr(self, "_ports_diag_worker", None)
        if worker is not None and worker.isRunning():
            return
        self._run_in_background(lambda: get_critical_ports_status([80, 443, 53]),
                                self._apply_ports_diagnostics,
                                busy_attr="_ports_diag_worker")

    def _apply_ports_diagnostics(self, statuses):
        """把后台端口诊断结果写进界面 (仅在 UI 线程执行)"""
        if isinstance(statuses, Exception) or not statuses:
            return
        for item in statuses:
            port = item["port"]
            lbl = self.critical_port_labels.get(port)
            btn = self.critical_port_btn_release.get(port)
            if not lbl:
                continue

            procs = item.get("processes", [])
            if not item["in_use"] or not procs:
                lbl.setText("● 空闲可用 (无冲突)")
                lbl.setStyleSheet("color: #10B981; font-weight: 500;")
                if btn:
                    btn.setVisible(False)
            else:
                p_names = ", ".join([f"{p.get('name', '未知')} (PID: {p.get('pid', '')})" for p in procs])
                my_nginx_pid = nginx_mgr.get_pid()
                is_my_nginx = any(p.get("pid") == my_nginx_pid for p in procs) if my_nginx_pid > 0 else False
                if is_my_nginx:
                    lbl.setText(f"● 正常监听 (GameArt Toolkit 本地 Nginx, PID: {my_nginx_pid})")
                    lbl.setStyleSheet("color: #38BDF8; font-weight: 500;")
                    if btn:
                        btn.setVisible(False)
                else:
                    lbl.setText(f"▲ 被占用: {p_names}")
                    lbl.setStyleSheet("color: #EF4444; font-weight: bold;")
                    if btn:
                        btn.setVisible(True)

    def release_critical_port_action(self, port: int):
        """释放加速核心端口"""
        procs = get_port_process_info(port)
        if not procs:
            show_toast(self, f"端口 {port} 当前未被占用", toast_type="info", duration=2000)
            self.refresh_ports_diagnostics_ui()
            return

        success_count = 0
        for p in procs:
            pid = p.get("pid", 0)
            if pid > 0:
                ok, msg = kill_process_by_pid_safe(pid)
                if ok:
                    success_count += 1

        if success_count > 0:
            show_toast(self, f"已成功结束占用 {port} 端口的冲突进程！", toast_type="success", duration=2500)
        else:
            show_toast(self, f"结束进程失败，可能需要管理员权限或为系统受保护进程", toast_type="error", duration=3000)
        self.refresh_ports_diagnostics_ui()

    def search_custom_port_action(self):
        """查询指定端口号的占用情况并展示"""
        if not self.txt_custom_port:
            return
        text = self.txt_custom_port.text().strip()
        if not text or not text.isdigit():
            show_toast(self, "请输入合法的端口号数字 (1-65535)", toast_type="warning", duration=2500)
            return

        port = int(text)
        if port < 1 or port > 65535:
            show_toast(self, "端口号超出范围 (1-65535)", toast_type="warning", duration=2500)
            return

        # 清除旧结果控件
        if self.port_results_layout:
            while self.port_results_layout.count() > 0:
                child = self.port_results_layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()

        procs = get_port_process_info(port)
        if not procs:
            lbl_res = QLabel(f"✓ 端口 {port} 当前处于空闲状态，未被任何进程占用。")
            lbl_res.setStyleSheet("color: #10B981; font-weight: 500; padding: 6px 0;")
            self.port_results_layout.addWidget(lbl_res)
            show_toast(self, f"端口 {port} 空闲可用", toast_type="success", duration=2000)
            return

        lbl_header = QLabel(f"发现 {len(procs)} 个连接/进程占用端口 {port}:")
        lbl_header.setProperty("class", "ItemTitle")
        self.port_results_layout.addWidget(lbl_header)

        for p in procs:
            card = QFrame()
            card.setProperty("class", "ServiceCard")
            c_layout = QHBoxLayout(card)
            c_layout.setContentsMargins(12, 8, 12, 8)
            c_layout.setSpacing(10)

            info_box = QVBoxLayout()
            info_box.setSpacing(2)
            lbl_p_name = QLabel(f"进程: {p.get('name', '未知')}  (PID: {p.get('pid', '')})  |  协议: {p.get('proto', 'TCP')}  状态: {p.get('status', 'LISTEN')}")
            lbl_p_name.setProperty("class", "ItemTitle")
            lbl_p_name.setWordWrap(True)
            info_box.addWidget(lbl_p_name)

            exe_path = p.get("exe", "")
            lbl_p_exe = QLabel(f"程序路径: {exe_path if exe_path else '系统受保护或无权限读取'}")
            lbl_p_exe.setProperty("class", "ItemDesc")
            lbl_p_exe.setWordWrap(True)
            info_box.addWidget(lbl_p_exe)

            c_layout.addLayout(info_box, stretch=1)

            btn_kill = QPushButton("结束进程")
            btn_kill.setProperty("class", "MDBtnDanger")
            pid = p.get("pid", 0)
            btn_kill.clicked.connect(lambda pid=pid, port=port: self.release_port_pid_action(pid, port))
            c_layout.addWidget(btn_kill)

            self.port_results_layout.addWidget(card)

    def release_port_pid_action(self, pid: int, port: int):
        """精准结束指定 PID 进程"""
        ok, msg = kill_process_by_pid_safe(pid)
        if ok:
            show_toast(self, f"已成功结束进程 (PID: {pid})！", toast_type="success", duration=2500)
        else:
            show_toast(self, msg, toast_type="error", duration=3000)
        self.search_custom_port_action()
        self.refresh_ports_diagnostics_ui()

    def _build_toolbox_nav_view(self) -> QWidget:
        """子页面 3: 加速生态官方主站导航"""
        scroll = QScrollArea()
        scroll.setObjectName("MainScrollArea")
        scroll.setWidgetResizable(True)

        content = QWidget()
        content.setObjectName("ScrollContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 20, 20, 20)
        layout.setSpacing(18)

        # 顶部返回与搜索栏
        nav_header_row = QHBoxLayout()
        btn_back = QPushButton(" 返回工具箱")
        btn_back.setProperty("class", "MDBtnTonal")
        tm = ThemeManager.get_instance()
        primary_c = tm.get_palette().get("primary", "#7EB9F5")
        if SvgIconFactory:
            btn_back.setIcon(SvgIconFactory.get_icon("arrow_left", primary_c, 14))
            btn_back.setIconSize(QSize(14, 14))
        btn_back.clicked.connect(lambda: self.toolbox_stack.setCurrentIndex(0))
        nav_header_row.addWidget(btn_back)

        lbl_nav_sec = QLabel("官方主站直达")
        lbl_nav_sec.setObjectName("PageTitle")
        lbl_nav_sec.setStyleSheet("font-size: 18px;")
        nav_header_row.addWidget(lbl_nav_sec)
        nav_header_row.addStretch()

        self.txt_nav_search = QLineEdit()
        self.txt_nav_search.setPlaceholderText("搜索生态主站 (名称/域名/关键词)...")
        self.txt_nav_search.setFixedWidth(260)
        self.txt_nav_search.setProperty("class", "SearchInput")
        self.txt_nav_search.textChanged.connect(self._filter_navigator_cards)
        nav_header_row.addWidget(self.txt_nav_search)
        layout.addLayout(nav_header_row)

        self.nav_card_widgets.clear()
        self.nav_group_cards.clear()

        # 分组渲染
        for group_id, group_info in SERVICE_GROUPS.items():
            g_items = [s for s in NAVIGATOR_SERVICES if s.get("group") == group_id]
            if not g_items:
                continue

            grp_card = QFrame()
            grp_card.setProperty("class", "MDCard")
            g_card_layout = QVBoxLayout(grp_card)
            g_card_layout.setContentsMargins(18, 14, 18, 14)
            g_card_layout.setSpacing(10)

            # 分组标题
            gh_row = QHBoxLayout()
            gh_icon = QLabel()
            gh_icon.setPixmap(SvgIconFactory.get_pixmap(group_info.get("icon", "zap"), primary_c, 18))
            lbl_gh_title = QLabel(f"{group_info.get('name', '')} ({len(g_items)})")
            lbl_gh_title.setProperty("class", "GroupTitle")
            gh_row.addWidget(gh_icon)
            gh_row.addWidget(lbl_gh_title)
            gh_row.addStretch()
            g_card_layout.addLayout(gh_row)

            # 该分组下的服务卡片列表
            cards_grid = QVBoxLayout()
            cards_grid.setSpacing(8)

            for sdata in g_items:
                card = NavigatorCard(sdata, self)
                cards_grid.addWidget(card)
                self.nav_card_widgets.append((card, sdata))

            g_card_layout.addLayout(cards_grid)
            layout.addWidget(grp_card)
            self.nav_group_cards[group_id] = grp_card

        layout.addStretch()
        scroll.setWidget(content)
        return scroll

    def _filter_navigator_cards(self, query: str):
        q = query.strip().lower()
        visible_counts_by_group = {gid: 0 for gid in self.nav_group_cards}

        for card, data in self.nav_card_widgets:
            if not q:
                card.setVisible(True)
                gid = data.get("group")
                if gid in visible_counts_by_group:
                    visible_counts_by_group[gid] += 1
                continue

            matched = (
                q in data.get("name", "").lower()
                or q in data.get("domain", "").lower()
                or q in data.get("desc", "").lower()
                or any(q in tag.lower() for tag in data.get("tags", []))
            )
            card.setVisible(matched)
            if matched:
                gid = data.get("group")
                if gid in visible_counts_by_group:
                    visible_counts_by_group[gid] += 1

        for gid, grp_card in self.nav_group_cards.items():
            grp_card.setVisible(visible_counts_by_group.get(gid, 0) > 0)

    def _on_image_selected_for_search(self, path: str):
        pass

    def _paste_image_from_clipboard_action(self):
        img = get_image_from_clipboard()
        if img:
            tmp_p = save_image_to_temp(img)
            if self.drop_image_widget:
                self.drop_image_widget.set_image(tmp_p)
            show_toast(self, "已从剪贴板读取并加载图片！", toast_type="success", duration=2000)
        else:
            show_toast(self, "剪贴板中未检测到图片数据，请先复制/截取图片", toast_type="warning", duration=2500)

    def _browse_image_file_action(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择要检索的图片", "",
            "图片文件 (*.jpg *.jpeg *.png *.webp *.bmp *.gif);;所有文件 (*.*)"
        )
        if path and self.drop_image_widget:
            self.drop_image_widget.set_image(path)

    def start_reverse_image_search(self):
        path = getattr(self.drop_image_widget, "current_image_path", None)
        if not path or not os.path.exists(path):
            img = get_image_from_clipboard()
            if img:
                path = save_image_to_temp(img)
                if self.drop_image_widget:
                    self.drop_image_widget.set_image(path)
            else:
                show_toast(self, "请先拖入图片或点击从剪贴板粘贴图片", toast_type="warning", duration=2500)
                return

        engine_id = self.cmb_search_engine.currentData() if self.cmb_search_engine else "saucenao"
        engine_name = SEARCH_ENGINES.get(engine_id, {}).get("name", "以图搜图")
        show_toast(self, f"正在通过 {engine_name} 发起检索...", toast_type="info", duration=2000)

        self.search_worker = ImageSearchWorker(engine_id, path)
        self.search_worker.finished_signal.connect(self.on_search_finished)
        self.search_worker.start()

    def on_search_finished(self, ok: bool, msg: str):
        show_toast(self, msg, toast_type="success" if ok else "error", duration=3500)

    # ------------------ PAGE 3: Steam 账号管家 ------------------
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
        desc = QLabel("多线程并发探测全量服务的候选 IP 延迟，自动生成延迟最低的 upstream 并热重载 Nginx")
        desc.setObjectName("PageDesc")
        title_box.addWidget(title)
        title_box.addWidget(desc)
        header.addLayout(title_box)
        header.addStretch()

        self.btn_start_ping = QPushButton("开始全量测速")
        self.btn_start_ping.setProperty("class", "MDBtnPrimary")
        self.btn_start_ping.setCursor(Qt.PointingHandCursor)
        self.btn_start_ping.clicked.connect(self.start_cdn_ping)
        header.addWidget(self.btn_start_ping)

        self.btn_apply_cdn = QPushButton("应用测速结果")
        self.btn_apply_cdn.setProperty("class", "MDBtnTonal")
        self.btn_apply_cdn.setCursor(Qt.PointingHandCursor)
        self.btn_apply_cdn.setEnabled(False)
        self.btn_apply_cdn.clicked.connect(self.apply_optimal_cdn)
        header.addWidget(self.btn_apply_cdn)

        layout.addLayout(header)

        # 测速状态概览横幅
        is_dark = ThemeManager.get_instance().is_dark
        primary_c = "#7EB9F5" if is_dark else "#0284C7"
        self.cdn_status_banner = QFrame()
        self.cdn_status_banner.setProperty("class", "MDCard")
        banner_l = QHBoxLayout(self.cdn_status_banner)
        banner_l.setContentsMargins(18, 12, 18, 12)
        banner_l.setSpacing(12)

        icon_lbl = QLabel()
        icon_lbl.setFixedSize(22, 22)
        if SvgIconFactory:
            icon_lbl.setPixmap(SvgIconFactory.get_pixmap("zap", primary_c, 20))
        banner_l.addWidget(icon_lbl)

        banner_text_l = QVBoxLayout()
        banner_text_l.setSpacing(2)
        self.lbl_cdn_status_summary = QLabel("测速目标已就绪")
        self.lbl_cdn_status_summary.setProperty("class", "CategoryTitle")
        self.lbl_cdn_last_time = QLabel("默认加载所有测速目标及历史最优节点，支持一键全量测速或单项独立测速")
        self.lbl_cdn_last_time.setProperty("class", "CategoryDesc")
        banner_text_l.addWidget(self.lbl_cdn_status_summary)
        banner_text_l.addWidget(self.lbl_cdn_last_time)
        banner_l.addLayout(banner_text_l)
        banner_l.addStretch()

        layout.addWidget(self.cdn_status_banner)

        self.cdn_results_layout = QVBoxLayout()
        self.cdn_results_layout.setSpacing(14)
        layout.addLayout(self.cdn_results_layout)

        # 默认即刻呈现所有测速目标及上次测速结果
        initial_results = self.get_current_or_initial_cdn_results()
        self.render_cdn_results(initial_results)

        layout.addStretch()
        scroll.setWidget(content)
        return scroll

    def get_current_or_initial_cdn_results(self) -> Dict[str, List[Dict]]:
        """获取当前或历史持久化的测速结果；若无则为全量服务构建包含全部候选 IP 的初始目标结构"""
        if self.cached_cdn_results:
            return self.cached_cdn_results

        cfg = load_config()
        saved_full = cfg.get("cached_cdn_full_results")
        if isinstance(saved_full, dict) and saved_full:
            self.cached_cdn_results = saved_full
            return saved_full

        cached_lats = cfg.get("cached_latencies", {})
        results: Dict[str, List[Dict]] = {}

        for srv in SERVICES_LIST:
            sid = srv["id"]
            cand_ips = CANDIDATE_IPS.get(sid, [])
            c_info = cached_lats.get(sid)
            cached_lat = None
            cached_proxy = False
            if isinstance(c_info, dict):
                cached_lat = c_info.get("latency")
                cached_proxy = c_info.get("via_proxy", False)
            elif isinstance(c_info, (int, float)):
                cached_lat = int(c_info)

            items = []
            for idx, ip in enumerate(cand_ips):
                if idx == 0 and cached_lat is not None and cached_lat > 0:
                    items.append({
                        "ip": ip,
                        "latency": int(cached_lat),
                        "available": True,
                        "rank": 1,
                        "via_proxy": cached_proxy,
                        "status_text": f"{int(cached_lat)} ms"
                    })
                else:
                    items.append({
                        "ip": ip,
                        "latency": 9999,
                        "available": False,
                        "rank": 3,
                        "status_text": "待测速"
                    })
            results[sid] = items

        self.cached_cdn_results = results
        return results

    def start_cdn_ping(self):
        if self.cdn_worker and self.cdn_worker.isRunning():
            show_toast(self, "测速正在进行中，请稍候...", toast_type="info", duration=1500)
            return
        self.btn_start_ping.setEnabled(False)
        self.btn_start_ping.setText("测速探测中...")

        # 展示骨架屏卡片
        while self.cdn_results_layout.count():
            item = self.cdn_results_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for _ in range(4):
            self.cdn_results_layout.addWidget(SkeletonCard())

        show_toast(self, "正在并发探测全量服务的候选节点延迟...", toast_type="info", duration=2500)

        if getattr(self, "_startup_flow_in_progress", False):
            self._startup_flow_in_progress = False
            if self._startup_cdn_worker and self._startup_cdn_worker.isRunning():
                self._startup_cdn_worker.request_stop()

        # 公网探活挪进 worker: 它本身是一次带超时的真实网络请求 (0.6s), 放在按钮回调里
        # 会让"点击测速"这一下先卡住界面
        self.cdn_worker = CDNTestWorker()
        self.cdn_worker.finished.connect(self.on_cdn_ping_finished)
        self.cdn_worker.start()

        QTimer.singleShot(0, lambda: self._probe_internet_async(load_config().get(
            "network_probe_target", "www.baidu.com")))

    def _probe_internet_async(self, probe_target: str):
        """后台探活 (不阻塞 UI), 仅在不可达时给一条提示"""
        self._net_probe_worker = NetProbeWorker(probe_target)
        self._net_probe_worker.result.connect(self._on_net_probe_result)
        self._net_probe_worker.start()

    def _on_net_probe_result(self, ok: bool):
        if not ok:
            show_toast(self, "未检测到公网连通 (校园网未认证或断网)，测速可能全部超时",
                       toast_type="warning", duration=4000)

    def on_cdn_ping_finished(self, results: Dict):
        self.cached_cdn_results = results
        cfg = load_config()
        cfg["cached_cdn_full_results"] = results
        cfg["last_optimal_time"] = int(time.time())
        save_config(cfg)

        # 同步测速结果到健康巡检
        services = list(dict.fromkeys(cfg.get("enabled_services", DEFAULT_ENABLED_SERVICES)))
        health_monitor.update_services(services, results)
        self.btn_start_ping.setEnabled(True)
        self.btn_start_ping.setText("重新全量测速")
        self.btn_apply_cdn.setEnabled(True)

        self.render_cdn_results(results)
        show_toast(self, "全量 CDN 测速完成！点击右上角【应用测速结果】即可生效", toast_type="success", duration=3500)

    def _set_badge(self, sid: str, latency: int, is_star: bool = False, via_proxy: bool = False):
        """统一更新主控制台延迟徽章; ECH 服务渲染隧道状态(含其健康度, 不谎报可用)"""
        if sid not in self.service_badges:
            return
        if is_ech_service(sid):
            from ech_tunnel import ech_tunnel

            self.service_badges[sid].set_latency(0, ech=True, ech_ok=ech_tunnel.is_healthy())
        else:
            self.service_badges[sid].set_latency(latency, is_star=is_star, via_proxy=via_proxy)

    def _render_ech_service_card(self, sid: str, name: str):
        """渲染 ECH 隧道服务的状态卡片

        ECH 服务的上游是本地隧道端口, 与候选节点延迟不是同一维度; 逐个 IP
        展示"超时"既无信息量又误导。这里改为呈现隧道本身的状态。
        """
        from ech_tunnel import ech_tunnel

        is_dark = ThemeManager.get_instance().is_dark
        st = ech_tunnel.status()
        healthy = st["healthy"]

        card = QFrame()
        card.setProperty("class", "MDCard")
        self.cdn_card_widgets[sid] = card
        card_l = QVBoxLayout(card)
        card_l.setContentsMargins(16, 14, 16, 14)
        card_l.setSpacing(10)

        card_top = QHBoxLayout()
        # 标题跟随实际状态: 隧道未就绪时不能仍宣称"经 ECH 直连"
        suffix = "经 ECH 隧道直连" if healthy else "ECH 隧道未就绪"
        lbl_title = QLabel(f"{name} ({suffix})")
        lbl_title.setProperty("class", "CategoryTitle")
        lbl_title.setWordWrap(True)
        card_top.addWidget(lbl_title)
        card_top.addStretch()

        # 独立测速对 ECH 服务无意义: 探测发的是普通握手, 必然失败。
        # 保留按钮位避免布局错位, 但禁用并说明原因。
        btn_single = QPushButton("独立测速")
        btn_single.setProperty("class", "MDBtnTiny")
        btn_single.setEnabled(False)
        btn_single.setToolTip("该服务走 ECH 隧道, 探测层无法复现其链路, 无需单独测速")
        self.cdn_single_buttons[sid] = btn_single
        card_top.addWidget(btn_single)
        card_l.addLayout(card_top)

        # 状态行: 隧道健康度
        if healthy:
            dot, text_c = ("#10B981" if is_dark else "#059669"), ("#34D399" if is_dark else "#059669")
            status_txt = f"隧道运行中 · 127.0.0.1:{st['port']}"
        else:
            dot, text_c = ("#EF4444" if is_dark else "#DC2626"), ("#F87171" if is_dark else "#DC2626")
            status_txt = "隧道未就绪 · 已回退常规直连"

        row = QHBoxLayout()
        row.setSpacing(8)
        dot_lbl = QLabel()
        dot_lbl.setFixedSize(8, 8)
        dot_lbl.setStyleSheet(f"background-color: {dot}; border-radius: 4px;")
        row.addWidget(dot_lbl)
        lbl_status = QLabel(status_txt)
        lbl_status.setStyleSheet(f"font-family: monospace; font-size: 12px; font-weight: bold; color: {text_c};")
        row.addWidget(lbl_status)
        row.addStretch()
        card_l.addLayout(row)

        # 说明行: 解释为何不列节点延迟
        cand_n = len(CANDIDATE_IPS.get(sid, []))
        lbl_note = QLabel(
            f"加密 SNI 直连 Cloudflare, 不依赖候选节点探测"
            f"（候选 IP 池 {cand_n} 个, 由隧道内部解析使用）"
        )
        lbl_note.setWordWrap(True)
        note_c = "#75879E" if is_dark else "#64748B"
        lbl_note.setStyleSheet(f"font-size: 11px; color: {note_c};")
        card_l.addWidget(lbl_note)

        self.cdn_results_layout.addWidget(card)

    def render_cdn_results(self, results: Dict):
        """根据当前主题渲染涵盖全量测速目标与候选 IP 节点的列表"""
        while self.cdn_results_layout.count():
            item = self.cdn_results_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        is_dark = ThemeManager.get_instance().is_dark
        primary_c = "#7EB9F5" if is_dark else "#0284C7"
        star_color = "#FBBF24" if is_dark else "#D97706"
        new_cached_lats = {}
        has_any_available = False

        # 遍历全量服务列表，确保即使未单独测速的服务也展示测速目标
        for srv in SERVICES_LIST:
            sid = srv["id"]
            name = srv["name"]
            ip_list = results.get(sid)

            # ECH 服务: 探测发的是普通握手, 复现不了 ECH 路径 —— 空 SNI 会被
            # Cloudflare 拒绝, 明文 SNI 会被按关键字阻断, 因此节点必然全部
            # "不可用"。按常规渲染会满屏"超时", 与服务实际可用的事实相反。
            # 这里改呈现隧道状态。
            if is_ech_service(sid):
                has_any_available = True
                self._set_badge(sid, 0)
                new_cached_lats[sid] = {"latency": 0, "via_proxy": False, "ech": True}
                self._render_ech_service_card(sid, name)
                continue

            if not ip_list:
                cand_ips = CANDIDATE_IPS.get(sid, [])
                ip_list = [{"ip": ip, "latency": 9999, "available": False, "status_text": "待测速"} for ip in cand_ips]

            best_item = None
            for it in ip_list:
                if it.get("available") and it.get("latency", 9999) < 9999:
                    best_item = it
                    has_any_available = True
                    break

            if best_item and sid in self.service_badges:
                best_lat = best_item["latency"]
                is_proxy = (sid in cdn_opt.last_relay_services) or best_item.get("via_proxy", False)
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
                is_best = (idx == 0 and item.get("available") and item.get("latency", 9999) < 9999)
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

                if item.get("available") and item.get("latency", 9999) < 9999:
                    lat = int(item["latency"])
                    if is_dark:
                        color = "#34D399" if lat < 100 else ("#FBBF24" if lat < 250 else "#F87171")
                    else:
                        color = "#059669" if lat < 100 else ("#D97706" if lat < 250 else "#DC2626")
                    lbl_lat = QLabel(f"{lat} ms")
                    lbl_lat.setStyleSheet(f"font-family: monospace; font-size: 11px; font-weight: bold; color: {color};")
                elif item.get("status_text") == "待测速":
                    color = "#75879E" if is_dark else "#94A3B8"
                    lbl_lat = QLabel("待测速")
                    lbl_lat.setStyleSheet(f"font-family: monospace; font-size: 11px; color: {color};")
                else:
                    color = "#F87171" if is_dark else "#DC2626"
                    lbl_lat = QLabel("超时")
                    lbl_lat.setStyleSheet(f"font-family: monospace; font-size: 11px; font-weight: bold; color: {color};")
                il.addWidget(lbl_lat)

                # 显式 polish 确保动态添加时 QSS 属性选择器刷新
                ip_item.style().unpolish(ip_item)
                ip_item.style().polish(ip_item)

                grid.addWidget(ip_item)

            card_l.addLayout(grid)
            self.cdn_results_layout.addWidget(card)

        if hasattr(self, "btn_apply_cdn") and self.btn_apply_cdn:
            self.btn_apply_cdn.setEnabled(has_any_available)

        if hasattr(self, "lbl_cdn_status_summary") and self.lbl_cdn_status_summary:
            last_opt_time = load_config().get("last_optimal_time", 0)
            if last_opt_time > 0:
                ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_opt_time))
                self.lbl_cdn_status_summary.setText(f"已加载上次优选测速数据 (共 {len(SERVICES_LIST)} 项服务)")
                self.lbl_cdn_last_time.setText(f"上次全量优化时间: {ts_str} | 点击【重新全量测速】或各卡片【独立测速】可更新")
            else:
                self.lbl_cdn_status_summary.setText(f"测速目标已就绪 (共 {len(SERVICES_LIST)} 项服务)")
                self.lbl_cdn_last_time.setText("点击右上角【开始全量测速】或单项卡片【独立测速】探测实时网络延迟")

        if new_cached_lats:
            cfg = load_config()
            cfg["cached_latencies"] = {**cfg.get("cached_latencies", {}), **new_cached_lats}
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
            self.cached_cdn_results = self.get_current_or_initial_cdn_results()
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

        self._set_badge(sid, int(best_lat) if best_lat != 9999 else -1,
                        is_star=True, via_proxy=is_proxy)

        # 3. 持久化缓存延迟与完整测速数据
        cfg = load_config()
        cached_lats = cfg.get("cached_latencies", {})
        cached_lats[sid] = {"latency": max(1, int(best_lat)), "via_proxy": is_proxy}
        cfg["cached_latencies"] = cached_lats
        cfg["cached_cdn_full_results"] = self.cached_cdn_results
        save_config(cfg)

        # 4. 局部重绘 CDN 测速页面
        self.render_cdn_results(self.cached_cdn_results)

        if best_lat != 9999:
            show_toast(self, f"[{srv_name}] 节点优化完成！最低延迟: {int(best_lat)} ms (已热重载生效)", toast_type="success", duration=3000)
        else:
            show_toast(self, f"[{srv_name}] 节点探测超时，已回退默认候选池", toast_type="warning", duration=3500)

    def trigger_startup_auto_cdn(self):
        """启动后后台静默触发 CDN 自动测速与代理启动编排"""
        cfg = load_config()
        auto_proxy_enabled = cfg.get("auto_proxy", True)
        auto_cdn_enabled = cfg.get("auto_cdn_optimize_on_startup", True)
        defer_proxy = cfg.get("auto_proxy_after_cdn", True)

        if not auto_cdn_enabled and not (defer_proxy and auto_proxy_enabled):
            self._startup_flow_in_progress = False
            return

        # 检查最小防抖时间 (默认 30 分钟)
        last_time = cfg.get("last_optimal_time", 0)
        min_interval_sec = cfg.get("auto_cdn_min_interval_minutes", 30) * 60
        now = time.time()
        skip_cdn = False
        if auto_cdn_enabled and (now - last_time < min_interval_sec):
            print(f"[AutoCDN] 距离上次自动测速仅 {int((now - last_time)/60)} 分钟 (< {int(min_interval_sec/60)} 分钟)，跳过启动重复测速")
            skip_cdn = True

        if not auto_cdn_enabled:
            skip_cdn = True

        only_enabled = cfg.get("auto_cdn_only_enabled", True)
        target_services = cfg.get("enabled_services", DEFAULT_ENABLED_SERVICES) if only_enabled else None

        wait_net = cfg.get("auto_cdn_wait_network_ready", True)
        delay_sec = cfg.get("auto_cdn_network_stable_delay_seconds", 60)
        probe_tgt = cfg.get("network_probe_target", "www.baidu.com")

        print(f"[StartupFlow] 启动后台静默编排 (探网: {wait_net}, 缓冲: {delay_sec}s, 测速: {not skip_cdn})...")
        self._startup_cdn_worker = StartupAutoCDNWorker(
            filter_services=target_services,
            wait_network=wait_net,
            stable_delay_sec=delay_sec,
            probe_target=probe_tgt,
            skip_cdn_test=skip_cdn
        )
        self._startup_cdn_worker.finished.connect(self.on_startup_auto_cdn_finished)
        self._startup_cdn_worker.start()

    def on_startup_auto_cdn_finished(self, results: Dict):
        """启动后台静默测速完成回调 (自动应用并静默热重载，测速后正式启动加速)"""
        cfg = load_config()
        if results:
            self.cached_cdn_results = results
            ok, msg = cdn_opt.apply_optimal(results)
            cfg["last_optimal_time"] = int(time.time())
            cfg["cached_cdn_full_results"] = results

            new_cached_lats = {}
            for sid, ip_list in results.items():
                if ip_list and sid in self.service_badges:
                    best_lat = ip_list[0]["latency"] if ip_list[0]["available"] else 9999
                    is_proxy = (sid in cdn_opt.last_relay_services)
                    self._set_badge(sid, max(1, int(best_lat)), is_star=True, via_proxy=is_proxy)
                    # ECH 服务的节点延迟无意义(探测恒失败), 缓存隧道状态本身
                    new_cached_lats[sid] = (
                        {"latency": 0, "via_proxy": False, "ech": True}
                        if is_ech_service(sid)
                        else {"latency": max(1, int(best_lat)), "via_proxy": is_proxy}
                    )

            cfg["cached_latencies"] = new_cached_lats
            save_config(cfg)

        # GitHub 全段封锁提示: 直连多段候选全挂或可用节点不足时, 弹窗提醒启用上游代理 (relay 自动绕过)
        blocked, low_avail = [], []
        for block_sid in ("github_web", "github_raw", "github_release", "github_assets", "github_s3", "gitlab"):
            block_items = results.get(block_sid)
            if not block_items:
                continue
            if not any(it.get("available") for it in block_items):
                blocked.append(block_sid)
                print(f"[AutoCDN] {block_sid} 直连候选全挂 (GFW 逐段封锁), 启用上游代理后自动经 relay 绕过")
            elif sum(1 for it in block_items if it.get("rank", 3) == 0) < 2:
                low_avail.append(block_sid)  # rank0 不足 2 个 = 单点依赖, 随时可能全挂

        if blocked or low_avail:
            try:
                from win_utils import auto_detect_active_proxy
                proxy_online = is_proxy_available(auto_detect_active_proxy(timeout=0.2), timeout=0.3)
            except Exception:
                proxy_online = False
            proxy_enabled = bool(load_config().get("upstream_proxy", {}).get("enabled", False))
            warn_list = sorted(set(blocked) | set(low_avail))
            base_msg = (f"GitHub/GitLab 服务直连全挂({', '.join(sorted(blocked))}), "
                        if blocked else f"GitHub/GitLab 服务可用节点不足({', '.join(low_avail)}), ")
            if proxy_online and not proxy_enabled:
                show_toast(self, base_msg + "检测到本地代理在线, 建议在设置中开启上游代理以获得 relay 兜底",
                           toast_type="warning", duration=4500)
            elif proxy_enabled:
                show_toast(self, base_msg + "已启用代理兜底, 直连段封锁期间经 relay 转发",
                           toast_type="info", duration=3500)
            else:
                show_toast(self, base_msg + "建议检查网络直连状态",
                           toast_type="warning", duration=3500)
            print(f"[AutoCDN] Git 系服务稳定性告警: {warn_list}")

        if nginx_mgr.is_running():
            nginx_mgr.reload()

        health_monitor.update_services(
            list(dict.fromkeys(cfg.get("enabled_services", DEFAULT_ENABLED_SERVICES))),
            results
        )

        # 若当前在 CDN 测速页面，刷新列表
        if self.stack.currentIndex() == 2:
            self.render_cdn_results(results)

        success_count = sum(1 for items in results.values() if items and items[0].get("available"))
        show_toast(
            self, f"已自动优选并热重载 {success_count}/{len(results)} 项服务最佳 CDN 节点",
            toast_type="success", duration=3200
        )

        # 若处于开机/启动延迟启用流程中，测速/等待结束后正式启动加速服务并注入 Hosts
        if self._startup_flow_in_progress:
            self._startup_flow_in_progress = False
            cfg_now = load_config()
            if cfg_now.get("auto_proxy", True):
                print("[StartupFlow] 启动阶段网络准备就绪，正式启动加速服务并应用 Hosts 规则...")
                self.start_acceleration(show_toast_on_fail=False)

    def apply_optimal_cdn(self):
        if not self.cached_cdn_results:
            return
        ok, msg = cdn_opt.apply_optimal(self.cached_cdn_results)
        if ok:
            cfg = load_config()
            cfg["last_optimal_time"] = int(time.time())
            cfg["cached_cdn_full_results"] = self.cached_cdn_results
            # 同步更新主控制台全部服务延迟微徽章与持久化
            saved_lats = cfg.get("cached_latencies", {})
            for sid, ip_list in self.cached_cdn_results.items():
                if ip_list and sid in self.service_badges:
                    best_lat = ip_list[0]["latency"] if ip_list[0].get("available") else 9999
                    is_proxy = (sid in cdn_opt.last_relay_services)
                    if is_ech_service(sid):
                        # ECH 服务: 节点全部"不可用"是预期结果, 展示隧道状态
                        self._set_badge(sid, 0)
                        saved_lats[sid] = {"latency": 0, "via_proxy": False, "ech": True}
                    elif best_lat != 9999:
                        self._set_badge(sid, max(1, int(best_lat)), is_star=True, via_proxy=is_proxy)
                        saved_lats[sid] = {"latency": max(1, int(best_lat)), "via_proxy": is_proxy}

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
    def _build_settings_env_card(self, primary_icon_c: str) -> QFrame:
        """卡片 0: 网络环境与第三方代理共存诊断"""
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

        btn_open_ports = QPushButton("端口排障工具 →")
        btn_open_ports.setProperty("class", "MDBtnOutlined")
        btn_open_ports.clicked.connect(self._goto_toolbox_ports_action)
        e_title_box.addWidget(btn_open_ports)

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
        return env_card

    def _goto_toolbox_ports_action(self):
        """从设置页一键直达工具箱端口排查子页面"""
        if hasattr(self, 'btn_nav_toolbox') and self.btn_nav_toolbox:
            self.btn_nav_toolbox.setChecked(True)
        self.on_nav_clicked(1)
        self._enter_toolbox_ports_action()

    def _build_settings_general_card(self, primary_icon_c: str, cfg: dict) -> QFrame:
        """卡片 1: 常规偏好与系统外观"""
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
        return gen_card

    def _build_settings_hosts_card(self, primary_icon_c: str, cfg: dict) -> QFrame:
        """卡片 2: Hosts 托管与退出清理"""
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
        return hosts_card

    def _build_settings_speedtest_card(self, primary_icon_c: str, cfg: dict) -> QFrame:
        """卡片 3: IPv4/IPv6 协议偏好与 CDN 性能微调"""
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
        lbl_coe_desc = QLabel("开启时启动测速仅探测已启用的服务 (测速更快)；关闭时将探测全量服务")
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

        # 3.5 测速优选后再启用代理 (防校园网劫持)
        row_proxy_after_cdn = QHBoxLayout()
        r_pac_text = QVBoxLayout()
        r_pac_text.setSpacing(2)
        lbl_pac_title = QLabel("测速优选成功后再启用加速 (防校园网与网关劫持)")
        lbl_pac_title.setProperty("class", "ItemTitle")
        lbl_pac_title.setWordWrap(True)
        lbl_pac_desc = QLabel("启动时不立即写入 Hosts 劫持流量，等待外网连通并优选出真实可用节点后再激活代理")
        lbl_pac_desc.setProperty("class", "ItemDesc")
        lbl_pac_desc.setWordWrap(True)
        r_pac_text.addWidget(lbl_pac_title)
        r_pac_text.addWidget(lbl_pac_desc)
        row_proxy_after_cdn.addLayout(r_pac_text)
        row_proxy_after_cdn.addStretch()

        self.sw_proxy_after_cdn = MDSwitch(checked=cfg.get("auto_proxy_after_cdn", True))
        self.sw_proxy_after_cdn.toggled.connect(lambda c: update_config_key("auto_proxy_after_cdn", c))
        row_proxy_after_cdn.addWidget(self.sw_proxy_after_cdn)
        ct_layout.addLayout(row_proxy_after_cdn)

        # 3.6 外网连通缓冲等待时长
        row_delay = QHBoxLayout()
        row_delay.setSpacing(16)
        lbl_delay = QLabel("外网连通后稳定缓冲等待:")
        lbl_delay.setProperty("class", "ItemTitle")
        lbl_delay.setWordWrap(True)
        self.cmb_stable_delay = NoWheelComboBox()
        self.cmb_stable_delay.addItem("即时 (0秒)", 0)
        self.cmb_stable_delay.addItem("15 秒", 15)
        self.cmb_stable_delay.addItem("30 秒", 30)
        self.cmb_stable_delay.addItem("60 秒 (推荐)", 60)
        self.cmb_stable_delay.addItem("90 秒", 90)
        cur_delay = cfg.get("auto_cdn_network_stable_delay_seconds", 60)
        for idx in range(self.cmb_stable_delay.count()):
            if int(self.cmb_stable_delay.itemData(idx)) == int(cur_delay):
                self.cmb_stable_delay.setCurrentIndex(idx)
                break
        self.cmb_stable_delay.currentIndexChanged.connect(
            lambda idx: update_config_key("auto_cdn_network_stable_delay_seconds", self.cmb_stable_delay.itemData(idx))
        )
        row_delay.addWidget(lbl_delay)
        row_delay.addWidget(self.cmb_stable_delay)
        row_delay.addStretch()
        ct_layout.addLayout(row_delay)

        # 3.7 防抖周期与自愈频率
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
        return cdn_tune_card

    def _build_settings_proxy_card(self, primary_icon_c: str, cfg: dict) -> QFrame:
        """卡片 4: 测速代理设置"""
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
        return proxy_card

    def _build_settings_dns_card(self, primary_icon_c: str, cfg: dict) -> QFrame:
        """卡片 5: 本地 DNS 智能分流与上游解析"""
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
        lbl_dns_title = QLabel(f"启用本地 DNS 智能分流 (UDP {local_dns_server.port})")
        self.lbl_dns_title = lbl_dns_title
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

        # 5.1b 域名重定向后端: Hosts 注入 vs NRPT 策略表
        row_redir = QHBoxLayout()
        r_redir_text = QVBoxLayout()
        r_redir_text.setSpacing(2)
        lbl_redir_title = QLabel("使用 NRPT 策略表重定向 (替代 Hosts 注入)")
        lbl_redir_title.setProperty("class", "ItemTitle")
        lbl_redir_title.setWordWrap(True)
        lbl_redir_desc = QLabel(
            "把加速域名的解析劫持交给 Windows 名称解析策略表: 不改动系统 Hosts 文件, "
            "且后缀匹配天然覆盖整个子域。需管理员权限 + 本机 53/UDP 空闲, 不满足时自动回退 Hosts"
        )
        lbl_redir_desc.setProperty("class", "ItemDesc")
        lbl_redir_desc.setWordWrap(True)
        r_redir_text.addWidget(lbl_redir_title)
        r_redir_text.addWidget(lbl_redir_desc)
        row_redir.addLayout(r_redir_text)
        row_redir.addStretch()

        self.sw_redirect_nrpt = MDSwitch(checked=(normalize_redirect_mode(cfg) == MODE_NRPT))
        self.sw_redirect_nrpt.toggled.connect(self.on_redirect_mode_toggled)
        row_redir.addWidget(self.sw_redirect_nrpt)
        d_layout.addLayout(row_redir)

        self.lbl_nrpt_status = QLabel("")
        self.lbl_nrpt_status.setProperty("class", "ItemDesc")
        self.lbl_nrpt_status.setWordWrap(True)
        d_layout.addWidget(self.lbl_nrpt_status)
        self.refresh_nrpt_status_label()

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
        return dns_card

    def _build_settings_steam_card(self, primary_icon_c: str, cfg: dict) -> QFrame:
        """卡片 6: Steam 路径与游戏高级启动参数"""
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
        return steam_card

    def _build_settings_maintenance_card(self, primary_icon_c: str, cfg: dict) -> QFrame:
        """卡片 7: 系统根证书与本地存储管理"""
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
        return cert_card

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

        layout.addWidget(self._build_settings_env_card(primary_icon_c))
        layout.addWidget(self._build_settings_general_card(primary_icon_c, cfg))
        layout.addWidget(self._build_settings_hosts_card(primary_icon_c, cfg))
        layout.addWidget(self._build_settings_speedtest_card(primary_icon_c, cfg))
        layout.addWidget(self._build_settings_proxy_card(primary_icon_c, cfg))
        layout.addWidget(self._build_settings_dns_card(primary_icon_c, cfg))
        layout.addWidget(self._build_settings_steam_card(primary_icon_c, cfg))
        layout.addWidget(self._build_settings_maintenance_card(primary_icon_c, cfg))

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
            health_monitor.set_check_interval(int(val))  # 运行中即时生效, 无需重启

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
        start_min = cfg.get("start_minimized", False)
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

    def _run_in_background(self, fn, on_done, busy_attr: str = ""):
        """在后台线程执行重活, 完成后回 UI 线程回调

        :param on_done: 在主线程接收结果 (可能为 Exception 实例)
        :param busy_attr: 用于防重入的实例属性名 (同名 worker 运行期间忽略再次触发)
        """
        if busy_attr:
            running = getattr(self, busy_attr, None)
            if running is not None and running.isRunning():
                return
        worker = BackgroundTaskWorker(fn)

        def _deliver(result):
            # 投递后立即断开: 否则 worker → lambda → 窗口 形成循环引用, 解释器收尾时
            # Qt 对象析构顺序不确定 (实测表现为退出时的访问违例)
            try:
                worker.done.disconnect(_deliver)
            except Exception:
                pass
            on_done(result)

        worker.done.connect(_deliver)
        if busy_attr:
            setattr(self, busy_attr, worker)
        worker.start()

    def diagnose_hosts_action(self):
        """Hosts 体检: 文件读写 + flushdns 子进程, 放后台执行"""
        def _done(result):
            if isinstance(result, Exception):
                show_toast(self, f"Hosts 体检异常: {result}", toast_type="error", duration=4000)
                return
            diag = result or {}
            if diag.get("fixes"):
                fix_str = "；".join(diag["fixes"])
                show_toast(self, f"Hosts 修复成功: {fix_str}", toast_type="success", duration=4000)
            elif diag.get("is_healthy"):
                show_toast(self, "Hosts 文件状态健康，权限正常且无任何冲突残留！", toast_type="success", duration=3000)
            else:
                issue_str = "；".join(diag.get("issues", []))
                show_toast(self, f"Hosts 存在异常: {issue_str}", toast_type="warning", duration=4000)
            self._start_status_probe()

        self._run_in_background(lambda: hosts_mgr.diagnose_and_repair(auto_fix=True),
                                _done, busy_attr="_hosts_diag_worker")

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

        def _done(result):
            if isinstance(result, Exception):
                show_toast(self, f"测速代理检测异常: {result}", toast_type="error", duration=3000)
                return
            if result:
                show_toast(self, f"测速代理连通正常！({host}:{port} 响应活跃)", toast_type="success", duration=3000)
            else:
                show_toast(self, f"测速代理连接超时 ({host}:{port} 未处于监听状态)", toast_type="warning", duration=3500)

        # check_proxy_alive 是带超时的真实连接 (实测约 1s), 放后台避免点击即卡
        self._run_in_background(lambda: check_proxy_alive(host, port), _done,
                                busy_attr="_proxy_test_worker")

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
        """安装根证书: PowerShell/certutil 子进程 + 信任库清理, 放后台执行"""
        def _done(result):
            if isinstance(result, Exception):
                show_toast(self, f"证书安装异常: {result}", toast_type="error", duration=3500)
            else:
                ok, msg = result
                show_toast(self, msg, toast_type="success" if ok else "error", duration=3000)
            self._start_status_probe()

        self._run_in_background(lambda: cert_mgr.install_cert(), _done,
                                busy_attr="_cert_install_worker")

    def uninstall_cert_action(self):
        def _done(result):
            if isinstance(result, Exception):
                show_toast(self, f"证书卸载异常: {result}", toast_type="error", duration=3500)
            else:
                ok, msg = result
                show_toast(self, msg, toast_type="info", duration=3000)
            self._start_status_probe()

        self._run_in_background(lambda: cert_mgr.uninstall_cert(), _done,
                                busy_attr="_cert_uninstall_worker")

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
        """托盘「完全退出」: 必须**同步**完成清理后再退出

        清理绝不能依赖 atexit: 顺序不可控, 且 safe_shutdown 若抛异常会直接跳过清理 ——
        残留的 NRPT 规则会把数百个域名指向无人监听的 127.0.0.1:53, 造成整机解析失败
        (实测事故)。因此用 try/finally 确保清理一定执行, 并复查结果。
        """
        print("[GameArt Toolkit] 正在完全退出程序...")
        if hasattr(self, 'tray') and self.tray:
            self.tray.hide()
        cfg = load_config()
        if cfg.get("auto_clear_cache_on_exit", False):
            try:
                nginx_mgr.clear_cache()
            except Exception:
                pass
        result = {}
        try:
            self.safe_shutdown()
        except Exception as e:
            # 必须吞掉: 这是退出流程, 让异常传播会跳过下面的清理与 QApplication.quit(),
            # 用户点「完全退出」将毫无反应 (实测由单测发现)
            print(f"[GameArt Toolkit] 关闭定时器/线程时异常 (已忽略并继续退出): {e}")
        finally:
            # 无论 safe_shutdown 是否异常, 清理都必须执行
            result = emergency_fast_cleanup()

        if isinstance(result, dict) and not result.get("ok", True):
            detail = result.get("detail") or "退出清理未完全成功"
            print(f"[GameArt Toolkit] 退出清理告警: {detail}")
            try:
                self.notify_tray("清理未完全成功", f"{detail}；下次以管理员身份启动时会自动回收。",
                                 QSystemTrayIcon.Warning, 6000)
            except Exception:
                pass
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
        is_acc = nginx_mgr.is_running() and self._is_redirect_active()
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
        if getattr(self, "_startup_flow_in_progress", False):
            return

        # NRPT 存活兜底必须最先做: 规则生效而本机解析器已死时, 命中域名在整机范围内解析
        # 失败 (查询被导向无人监听的 127.0.0.1:53)。此时"重启 nginx"毫无用处, 必须先把
        # 解析器拉起来; 拉不起来就只能撤规则回退 Hosts, 绝不能把这个状态留着。
        if REDIRECT_STATE.get("backend") == MODE_NRPT:
            try:
                dns_alive = local_dns_server.is_running() and local_dns_server.port == NRPT_DNS_PORT
            except Exception:
                dns_alive = False
            if not dns_alive:
                ok, msg = local_dns_server.ensure_bind(NRPT_DNS_PORT)
                if ok:
                    print(f"[Watchdog] NRPT 解析器已恢复监听 53: {msg}")
                else:
                    print(f"[Watchdog] NRPT 解析器无法监听 53 ({msg}), 撤除规则回退 Hosts")
                    self._remove_redirect()
                    self.notify_tray("解析器异常", f"本机解析器无法监听 53 ({msg})，已撤除 NRPT 规则。",
                                     QSystemTrayIcon.Warning, 4000)
                    return

        # ECH 隧道存活兜底: 上游已指向隧道 (upstream-dynamic.conf 里写着 127.0.0.1:<隧道端口>)
        # 而隧道进程已死时, 每个请求都会得到 **502** —— 实测事故: 隧道进程退出后 discord 全站 502,
        # 而看门狗只查 nginx/hosts, 永远不会发现这个问题, 会一直坏到用户下次手动应用。
        try:
            from path_utils import NGINX_DIR as _NGINX_DIR
            from nginx_generator import NginxConfGenerator as _Gen
            ech_in_use = bool(_Gen._ech_services_from_upstream(
                _NGINX_DIR / "conf" / "upstream-dynamic.conf"))
        except Exception:
            ech_in_use = False
        if ech_in_use and not ech_tunnel.is_running():
            ok, msg = self._start_ech_tunnel()
            print(f"[Watchdog] ECH 隧道未运行, 已尝试重启: {ok} {msg}")
            if ok:
                try:
                    nginx_mgr.reload()
                except Exception:
                    pass
            return

        cfg = load_config()
        if not cfg.get("auto_proxy", True):
            return

        if self._is_manually_stopped:
            return

        if self._has_prompted_hosts_perm and not self._is_redirect_active():
            return

        is_nginx = nginx_mgr.is_running()
        is_hosts = self._is_redirect_active()

        if not is_nginx or not is_hosts:
            self.start_acceleration(show_toast_on_fail=False)

    # ------------------ 域名重定向后端 (Hosts / NRPT) 分派 ------------------

    def _is_redirect_active(self) -> bool:
        """加速劫持是否已生效 (Hosts 或 NRPT 任一后端生效即为真, 覆盖回退场景)

        性能注意: NRPT 后端的 is_applied 要走一次 PowerShell 查询 (进程启动开销 ~0.8s),
        而本方法会被每 8 秒的看门狗定时器与多处 UI 回调调用 —— 若每次都查, NRPT 模式下
        界面会周期性卡顿。因此优先信任本进程记录的后端状态 (配合"本机解析器是否已在 53
        端口服务"这一即时判据), 仅在状态未知时才回落到真实查询。
        """
        if REDIRECT_STATE.get("backend") == MODE_NRPT:
            try:
                if local_dns_server.is_running() and local_dns_server.port == NRPT_DNS_PORT:
                    return True
            except Exception:
                pass
        try:
            return is_redirect_applied(load_config(), hosts_mgr, nrpt_mgr)
        except Exception:
            try:
                return hosts_mgr.is_applied()
            except Exception:
                return False

    def _apply_redirect(self, services: List[str]) -> Tuple[bool, str]:
        """按 redirect_mode 应用域名重定向, 前置条件不足时自动回退 Hosts"""
        return apply_redirect(load_config(), services, hosts_mgr, nrpt_mgr,
                              local_dns_server, REDIRECT_STATE)

    def _remove_redirect(self) -> Tuple[bool, str]:
        """幂等清理两种后端的全部残留, 并恢复本机解析器默认端口"""
        return remove_redirect(load_config(), hosts_mgr, nrpt_mgr,
                               local_dns_server, REDIRECT_STATE)

    def toggle_acceleration(self):
        is_acc = nginx_mgr.is_running() and self._is_redirect_active()
        if is_acc:
            self.stop_acceleration()
        else:
            self.start_acceleration(show_toast_on_fail=True)

    def start_acceleration(self, show_toast_on_fail: bool = False, blocking: bool = False):
        """启动加速 (域名重定向 + ECH 隧道 + Nginx + L4 Relay + 健康巡检)

        为什么默认异步执行: 本流程包含证书安装 (子进程)、重定向写入 (NRPT 模式下含 PowerShell)、
        ECH 隧道拉起与健康等待、Nginx 启动与端口等待、relay 启动、git 配置子进程 —— 合计数秒。
        它既被【启动加速】按钮调用, 也被"测速完成后再启用代理"的完成回调调用, 同步执行就是
        一次明显的界面冻结 (实测 UI 线程重活 7 处)。
        blocking=True 仅供自动化测试与非 UI 线程调用方使用。
        """
        if getattr(self, "_startup_flow_in_progress", False):
            self._startup_flow_in_progress = False
            worker = self._startup_cdn_worker
            if worker is not None and worker.isRunning():
                worker.request_stop()

        self._is_manually_stopped = False

        if blocking or threading.current_thread() is not threading.main_thread():
            self._finish_start_acceleration(
                self._start_acceleration_heavy(show_toast_on_fail), show_toast_on_fail)
            return

        self._run_in_background(
            lambda: self._start_acceleration_heavy(show_toast_on_fail),
            lambda res: self._finish_start_acceleration(res, show_toast_on_fail),
            busy_attr="_accel_start_worker")

    def _start_acceleration_heavy(self, show_toast_on_fail: bool) -> Dict[str, Any]:
        """启动加速的重活部分 (后台线程执行, **不得触碰任何 Qt 对象**)"""
        result: Dict[str, Any] = {"stage": "ok", "msg": "", "services": [],
                                  "ech_ok": True, "ech_msg": "", "relay_ok": True, "relay_msg": "",
                                  "prompted": self._has_prompted_hosts_perm}
        try:
            if not cert_mgr.is_cert_installed(force_refresh=False):
                cert_mgr.install_cert()

            cfg = load_config()
            saved_services = cfg.get("enabled_services")
            services = list(saved_services) if saved_services is not None else list(DEFAULT_ENABLED_SERVICES)
            result["services"] = services

            h_ok, h_msg = self._apply_redirect(services)
            if not h_ok:
                result.update(stage="redirect_fail", msg=h_msg)
                if not self._has_prompted_hosts_perm:
                    self._has_prompted_hosts_perm = True
                    result["prompted"] = False
                else:
                    result["prompted"] = True
                return result
            self._has_prompted_hosts_perm = False

            # ECH 隧道必须先于 CDN 优化就绪: 生成 upstream 时会查询隧道健康状态来决定
            # 是否让 ech_enabled 服务走隧道, 隧道未起会退回常规分支
            ech_ok, ech_msg = self._start_ech_tunnel()
            result["ech_ok"], result["ech_msg"] = ech_ok, ech_msg

            n_ok, n_msg = nginx_mgr.start()
            if not n_ok:
                self._remove_redirect()
                result.update(stage="nginx_fail", msg=n_msg)
                return result

            relay_ok, relay_msg = self._start_relay()
            result["relay_ok"], result["relay_msg"] = relay_ok, relay_msg
            health_monitor.start(services)

            # 为 Git / 开发生态注入作用域证书 (3 次 git 子进程, 放后台执行)
            try:
                cert_mgr.inject_dev_environments()
            except Exception:
                pass
            return result
        except Exception as e:
            result.update(stage="error", msg=f"{type(e).__name__}: {e}")
            return result

    def _finish_start_acceleration(self, result: Dict[str, Any], show_toast_on_fail: bool):
        """启动加速的界面收尾 (仅在 UI 线程执行)"""
        stage = (result or {}).get("stage", "error")
        if stage == "redirect_fail":
            msg = result.get("msg", "")
            if not result.get("prompted"):
                if show_toast_on_fail:
                    show_toast(self, f"{msg} (需管理员权限修改 Hosts)", toast_type="warning",
                               duration=6000, action_text="提权", on_action=elevate_relaunch)
                else:
                    self.notify_tray("Hosts 权限提示", "未获取管理员权限修改 Hosts，可点击界面侧栏【提权】。",
                                     QSystemTrayIcon.Warning, 3000)
            elif show_toast_on_fail:
                show_toast(self, f"{msg} (需管理员权限修改 Hosts)", toast_type="warning",
                           duration=6000, action_text="提权", on_action=elevate_relaunch)
            return
        if stage == "nginx_fail":
            if show_toast_on_fail:
                show_toast(self, f"Nginx 启动失败: {result.get('msg', '')}", toast_type="error", duration=4000)
            else:
                self.notify_tray("Nginx 启动提示", result.get("msg", ""), QSystemTrayIcon.Warning, 2500)
            return
        if stage == "error":
            show_toast(self, f"启动加速失败: {result.get('msg', '')}", toast_type="error", duration=4000)
            return

        services = result.get("services") or []
        if show_toast_on_fail:
            extra = (f" | {result.get('relay_msg', '')}" if result.get("relay_ok")
                     else f" | ⚠ {result.get('relay_msg', '')}")
            if not result.get("ech_ok"):
                extra += f" | ⚠ ECH: {result.get('ech_msg', '')}"
            show_toast(self, f"加速服务已启动，{len(services)} 项服务规则已生效！{extra}",
                       toast_type="success", duration=2500)

        self._start_status_probe()
        self.refresh_tray_steam_menu()

    def _start_ech_tunnel(self) -> Tuple[bool, str]:
        """启动 ECH 隧道: 聚合所有 ech_enabled 服务的域名作为白名单

        域名白名单同时起到安全边界作用 —— 隧道只转发名单内的目标, 避免被当作
        通用代理滥用。IP 池取自各服务的 candidate_ips, 作为 DoH 被投毒时的兜底
        (实测境内 DoH 对受限域名的解析是间歇性污染的)。
        """
        from service_profile import PROFILES

        ech_services = [p for p in PROFILES if getattr(p, "ech_enabled", False)]
        if not ech_services:
            return True, "无服务启用 ECH 隧道"

        domains: List[str] = []
        ip_pool: List[str] = []
        for p in ech_services:
            domains.extend(p.domains)
            ip_pool.extend(p.candidate_ips)
        # 去重保序 (多个服务可能共享域名, 如 source.pixiv.net)
        domains = list(dict.fromkeys(domains))
        ip_pool = list(dict.fromkeys(ip_pool))

        return ech_tunnel.start(domains=domains, ip_pool=ip_pool)

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

    def stop_acceleration(self, blocking: bool = False):
        """停止加速 (停止数据平面 + 还原重定向与证书注入)

        与 start_acceleration 同理默认异步: 其中含 relay/ECH/Nginx 进程停止、重定向还原
        (hosts 写回 + flushdns, NRPT 模式还含 PowerShell 清理) 与证书注入还原。
        """
        self._is_manually_stopped = True
        if blocking or threading.current_thread() is not threading.main_thread():
            self._stop_acceleration_heavy()
            self._finish_stop_acceleration()
            return
        self._run_in_background(self._stop_acceleration_heavy,
                                lambda _r: self._finish_stop_acceleration(),
                                busy_attr="_accel_stop_worker")

    def _stop_acceleration_heavy(self):
        """停止加速的重活部分 (后台线程执行, 不得触碰 Qt 对象)"""
        health_monitor.stop()
        relay_server.stop()
        relay_server.clear_proxy_routes()
        ech_tunnel.stop()
        self._remove_redirect()
        try:
            cert_mgr.restore_dev_environments()
        except Exception:
            pass
        nginx_mgr.stop()

    def _finish_stop_acceleration(self):
        """停止加速的界面收尾 (仅在 UI 线程执行)"""
        backend = REDIRECT_STATE.get("backend")
        cleaned = "NRPT 与 Hosts 规则均已还原" if backend is None else "重定向规则已还原"
        show_toast(self, f"加速服务已停止，{cleaned}", toast_type="info", duration=2200)
        self._start_status_probe()

    def on_auto_proxy_toggled(self, checked: bool):
        update_config_key("auto_proxy", checked)
        state_str = "开启" if checked else "关闭"
        show_toast(self, f"自动托管代理已{state_str}", toast_type="info", duration=2000)

    def refresh_env_diagnostics_ui(self):
        """刷新系统网络环境与第三方代理诊断信息 (探测在后台线程, 不阻塞 UI)"""
        worker = getattr(self, "_env_diag_worker", None)
        if worker is not None and worker.isRunning():
            return
        try:
            self.lbl_env_summary.setText("诊断结论: 正在探测本地代理端口...")
        except Exception:
            pass
        self._env_diag_worker = EnvDiagnosticsWorker()
        self._env_diag_worker.ready.connect(self._apply_env_diagnostics)
        self._env_diag_worker.start()

    def _apply_env_diagnostics(self, diag: dict):
        """把后台诊断结果写进界面 (仅在 UI 线程执行)"""
        try:
            if diag.get("error"):
                self.lbl_env_summary.setText(f"诊断异常: {diag['error']}")
                return
            sys_p = diag.get("system_proxy", {}) or {}
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

    def refresh_nrpt_status_label(self):
        """刷新 NRPT 后端能力状态 (系统支持 / 管理员权限 / 53 端口占用者)"""
        if not hasattr(self, "lbl_nrpt_status"):
            return
        try:
            if hasattr(self, "lbl_dns_title"):
                self.lbl_dns_title.setText(f"启用本地 DNS 智能分流 (UDP {local_dns_server.port})")
            caps = nrpt_mgr.capabilities()
        except Exception as e:
            self.lbl_nrpt_status.setText(f"NRPT 状态检测异常: {e}")
            return

        if caps.get("ready"):
            port = caps.get("port53") or {}
            ns = caps.get("name_server") or "127.0.0.1"
            if port.get("family") == "ipv6":
                # 共存说明必须显示: 用户会疑惑"53 明明被代理占了为什么还能用"
                self.lbl_nrpt_status.setText(
                    f"NRPT 前置条件已满足 (管理员权限); IPv4 53 被 {caps.get('port53_owner') or '代理'} 占用, "
                    f"将改用 IPv6 回环 {ns}:53 共存")
            else:
                self.lbl_nrpt_status.setText(
                    f"NRPT 前置条件已满足: 管理员权限 + 本机 53/UDP 空闲 ({ns}:53), 可直接启用")
            self.lbl_nrpt_status.setStyleSheet("color: #34D399;")
        else:
            detail = caps.get("reason") or "前置条件不满足"
            owner = caps.get("port53_owner")
            if owner and owner not in detail:
                detail += f"；当前占用 53 的进程: {owner}"
            if not caps.get("admin"):
                detail += "；提权后若 IPv4 53 被代理占用, 会自动改用 IPv6 回环 ::1 共存"
            self.lbl_nrpt_status.setText(f"NRPT 暂不可用: {detail}")
            self.lbl_nrpt_status.setStyleSheet("color: #FBBF24;")

    def on_redirect_mode_toggled(self, checked: bool):
        """切换加速域名的重定向后端, 加速运行中即刻迁移, 未运行则随下次启动生效"""
        update_config_key("redirect_mode", "nrpt" if checked else "hosts")
        self.refresh_nrpt_status_label()

        if not (nginx_mgr.is_running() or self._is_redirect_active()):
            name = "NRPT 策略表" if checked else "Hosts 注入"
            show_toast(self, f"域名重定向后端已设为 {name}（加速启动时生效）", toast_type="info", duration=2200)
            return

        cfg = load_config()
        services = list(cfg.get("enabled_services") or DEFAULT_ENABLED_SERVICES)
        ok, msg = self._apply_redirect(services)
        self.refresh_nrpt_status_label()

        if not ok:
            show_toast(self, msg, toast_type="error", duration=4500)
        elif REDIRECT_STATE.get("backend") == MODE_NRPT:
            show_toast(self, f"已切换为 NRPT 重定向: {msg}", toast_type="success", duration=2800)
        else:
            note = REDIRECT_STATE.get("note") or ""
            show_toast(self, f"已回退 Hosts 重定向: {note or msg}", toast_type="warning", duration=3500)

    def on_dns_mode_toggled(self, checked: bool):
        """响应本地 DNS 模式切换"""
        cfg = load_config()

        # NRPT 模式依赖本机解析器常驻 53 端口 (NRPT 的 NameServers 只能填 IP, 端口固定 53),
        # 关掉它会让加速域名直接解析失败, 因此在 NRPT 生效期间强制保持开启
        if not checked and normalize_redirect_mode(cfg) == MODE_NRPT and self._is_redirect_active():
            update_config_key("dns_mode_enabled", True)
            if hasattr(self, "sw_dns_mode"):
                self.sw_dns_mode.blockSignals(True)
                self.sw_dns_mode.setCheckedNoAnim(True)
                self.sw_dns_mode.blockSignals(False)
            show_toast(self, "NRPT 模式依赖本地 DNS 常驻 53 端口，已保持开启", toast_type="warning", duration=2800)
            return

        update_config_key("dns_mode_enabled", checked)
        if checked:
            ok, msg = local_dns_server.start()
            show_toast(self, msg, toast_type="success" if ok else "error", duration=2500)
        else:
            local_dns_server.stop()
            show_toast(self, "本地 DNS 服务已停止", toast_type="info", duration=2000)
        self.refresh_nrpt_status_label()

    def on_health_heal_toggled(self, checked: bool):
        """响应持续健康巡检与故障自愈切换"""
        update_config_key("health_heal_enabled", checked)
        if checked:
            services = list(dict.fromkeys(load_config().get("enabled_services", DEFAULT_ENABLED_SERVICES)))
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
                proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                                      timeout=3, **get_silent_startup_kwargs())
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

    # 注册退出清理。必须放在上面那条纯命令行分支之后 (卸载器只期望清 hosts),
    # 且必须是主程序入口而非模块级 —— 见 _register_exit_cleanup 的说明。
    _register_exit_cleanup()

    # 0.5 清理上一会话遗留的重定向 (异常退出/被强杀时会残留)。
    # 必须在建窗口前做: NRPT 残留会把 ~数百个域名指向无人监听的 127.0.0.1:53, 在整机范围
    # 内造成解析失败, 而用户此时可能根本不打算启动加速 —— 实测事故见 redirect_manager
    # .cleanup_orphans 的说明。此处的判定口径是"数据平面未运行 = 上一会话的孤儿"。
    if "--clean-redirect-silent" in sys.argv:
        try:
            from redirect_manager import cleanup_orphans
            res = cleanup_orphans(load_config(), hosts_mgr, nrpt_mgr, local_dns_server,
                                  data_plane_alive=nginx_mgr.is_running())
            print(f"[CleanRedirect] {res.get('detail', '')}")
        except Exception as e:
            print(f"[CleanRedirect Error] {e}")
        sys.exit(0)

    try:
        from redirect_manager import cleanup_orphans
        _orphan = cleanup_orphans(load_config(), hosts_mgr, nrpt_mgr, local_dns_server,
                                  data_plane_alive=nginx_mgr.is_running())
        if _orphan.get("cleaned"):
            print(f"[Startup] {_orphan.get('detail')}")
    except Exception as e:
        print(f"[Startup] 重定向残留清理跳过: {e}")

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
