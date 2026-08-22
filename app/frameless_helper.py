# -*- coding: utf-8 -*-
"""
GameArt Toolkit - Win32 原生无边框窗口与 DWM 拦截器
提供:
1. 无外部依赖的原生无边框 (去掉系统白色边框与标题栏)
2. 保留 Windows 硬件阴影与 Windows 11 原生圆角
3. 8 方向边缘缩放 (Resize)
4. 映射最大化按钮为 HTMAXBUTTON，支持 Windows 11 Snap Layouts 贴靠菜单
5. 修复双击标题栏最大化、全屏状态下任务栏防遮挡与多显示器 DPI 自适应
"""

import sys
import ctypes
from ctypes import wintypes
from PySide6.QtCore import Qt, QPoint, QRect, QTimer
from PySide6.QtGui import QCursor
from PySide6.QtWidgets import QWidget, QPushButton

# Windows API 消息常量
WM_QUERYENDSESSION = 0x0011
WM_ENDSESSION = 0x0016
WM_NCCALCSIZE = 0x0083
WM_NCHITTEST = 0x0084
WM_GETMINMAXINFO = 0x0024
WM_DPICHANGED = 0x02E0

# 命中测试常量
HTERROR = -2
HTTRANSPARENT = -1
HTNOWHERE = 0
HTCLIENT = 1
HTCAPTION = 2
HTMINBUTTON = 8
HTMAXBUTTON = 9
HTLEFT = 10
HTRIGHT = 11
HTTOP = 12
HTTOPLEFT = 13
HTTOPRIGHT = 14
HTBOTTOM = 15
HTBOTTOMLEFT = 16
HTBOTTOMRIGHT = 17
HTCLOSE = 20

# 窗口样式常量
GWL_STYLE = -16
WS_CAPTION = 0x00C00000
WS_THICKFRAME = 0x00040000
WS_MINIMIZEBOX = 0x00020000
WS_MAXIMIZEBOX = 0x00010000
WS_SYSMENU = 0x00080000

# DWM 属性常量
DWMWA_USE_IMMERSIVE_DARK_MODE = 20
DWMWA_WINDOW_CORNER_PREFERENCE = 33
DWMWCP_ROUND = 2

# 结构体定义
class RECT(ctypes.Structure):
    _fields_ = [
        ("left", wintypes.LONG),
        ("top", wintypes.LONG),
        ("right", wintypes.LONG),
        ("bottom", wintypes.LONG),
    ]

class POINT(ctypes.Structure):
    _fields_ = [
        ("x", wintypes.LONG),
        ("y", wintypes.LONG),
    ]

class MINMAXINFO(ctypes.Structure):
    _fields_ = [
        ("ptReserved", POINT),
        ("ptMaxSize", POINT),
        ("ptMaxPosition", POINT),
        ("ptMinTrackSize", POINT),
        ("ptMaxTrackSize", POINT),
    ]

class PWINDOWPOS(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("hwndInsertAfter", wintypes.HWND),
        ("x", ctypes.c_int),
        ("y", ctypes.c_int),
        ("cx", ctypes.c_int),
        ("cy", ctypes.c_int),
        ("flags", wintypes.UINT),
    ]

class NCCALCSIZE_PARAMS(ctypes.Structure):
    _fields_ = [
        ("rgrc", RECT * 3),
        ("lppos", ctypes.POINTER(PWINDOWPOS)),
    ]


class NativeFramelessHelper:
    """
    原生 Windows 无边框辅助类
    挂载至 QMainWindow，通过重写 nativeEvent 实现 Windows 原生特性
    """
    def __init__(self, window: QWidget, border_width: int = 6):
        self.window = window
        self.border_width = border_width
        self.title_bar = None
        self.max_btn = None
        self.min_btn = None
        self.close_btn = None
        self.theme_btn = None
        self.draggable_widgets = []
        self.interactive_widgets = []
        self._ready = False  # 构造期间不处理 nativeEvent

        if sys.platform == "win32":
            # 延迟到事件循环空闲后再执行 DWM 初始化
            # 避免 SetWindowPos(SWP_FRAMECHANGED) 同步触发 WM_NCCALCSIZE 导致 nativeEvent 重入硬崩
            QTimer.singleShot(0, self._init_window)

    def set_title_bar(self, title_bar: QWidget):
        """设置标题栏组件"""
        self.title_bar = title_bar

    def set_window_controls(self, min_btn=None, max_btn=None, close_btn=None, theme_btn=None):
        """注册标题栏交互控制按钮"""
        self.min_btn = min_btn
        self.max_btn = max_btn
        self.close_btn = close_btn
        self.theme_btn = theme_btn

    def add_draggable_widget(self, widget: QWidget):
        """添加允许拖拽窗口的控件"""
        if widget and widget not in self.draggable_widgets:
            self.draggable_widgets.append(widget)

    def add_interactive_widget(self, widget: QWidget):
        """添加标题栏上可交互（不允许拖拽拦截）的控件，例如按钮、搜索框"""
        if widget and widget not in self.interactive_widgets:
            self.interactive_widgets.append(widget)

    def _init_window(self):
        """设置窗口样式与 DWM 属性"""
        hwnd = int(self.window.winId())

        # 保留必要样式位以支持 DWM 系统阴影与原生动画
        user32 = ctypes.windll.user32
        style = user32.GetWindowLongW(hwnd, GWL_STYLE)
        user32.SetWindowLongW(hwnd, GWL_STYLE, style | WS_CAPTION | WS_THICKFRAME | WS_MAXIMIZEBOX | WS_MINIMIZEBOX | WS_SYSMENU)

        # 启用 Win10/Win11 深色模式与 Win11 圆角
        try:
            dwmapi = ctypes.windll.dwmapi
            dark_mode = ctypes.c_int(1)
            dwmapi.DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                ctypes.byref(dark_mode),
                ctypes.sizeof(dark_mode)
            )
            round_pref = ctypes.c_int(DWMWCP_ROUND)
            dwmapi.DwmSetWindowAttribute(
                hwnd,
                DWMWA_WINDOW_CORNER_PREFERENCE,
                ctypes.byref(round_pref),
                ctypes.sizeof(round_pref)
            )
        except Exception:
            pass

        # 标记就绪 (必须在 SetWindowPos 之前设置，因为它会同步触发 nativeEvent)
        self._ready = True

        # 强制重算非客户区
        user32.SetWindowPos(
            hwnd, 0, 0, 0, 0, 0,
            0x0001 | 0x0002 | 0x0004 | 0x0020  # SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_FRAMECHANGED
        )

    def is_maximized(self) -> bool:
        """检查当前窗口是否最大化"""
        if sys.platform == "win32":
            user32 = ctypes.windll.user32
            return bool(user32.IsZoomed(int(self.window.winId())))
        return self.window.isMaximized()

    def handle_native_event(self, event_type, message):
        """
        在 QMainWindow.nativeEvent 中调用此方法处理 Windows 消息
        返回值: (handled: bool, result: int)
        """
        if sys.platform != "win32" or not self._ready:
            return False, 0

        try:
            # PySide6 不同版本 message 类型不同，兼容 int() 与 __int__() 两种
            addr = int(message)
            msg = wintypes.MSG.from_address(addr)
        except Exception:
            return False, 0

        # 0. 拦截 Windows 系统关机与会话结束消息 (响应后清理，防止异常断网)
        if msg.message == WM_QUERYENDSESSION:
            return True, 1  # 明确告知系统允许关机
        elif msg.message == WM_ENDSESSION:
            if msg.wParam != 0:  # 确认正在关机/注销
                if hasattr(self.window, "on_windows_shutdown"):
                    try:
                        self.window.on_windows_shutdown()
                    except Exception:
                        pass
                return True, 0

        # 1. 移除默认客户区边框但保留系统阴影
        if msg.message == WM_NCCALCSIZE:
            if msg.wParam:
                if self.is_maximized():
                    user32 = ctypes.windll.user32
                    hwnd = int(self.window.winId())
                    monitor = user32.MonitorFromWindow(hwnd, 2)  # MONITOR_DEFAULTTONEAREST
                    if monitor:
                        class MONITORINFO(ctypes.Structure):
                            _fields_ = [
                                ("cbSize", wintypes.DWORD),
                                ("rcMonitor", RECT),
                                ("rcWork", RECT),
                                ("dwFlags", wintypes.DWORD),
                            ]
                        mi = MONITORINFO()
                        mi.cbSize = ctypes.sizeof(MONITORINFO)
                        if user32.GetMonitorInfoW(monitor, ctypes.byref(mi)):
                            params = NCCALCSIZE_PARAMS.from_address(msg.lParam)
                            params.rgrc[0].left = mi.rcWork.left
                            params.rgrc[0].top = mi.rcWork.top
                            params.rgrc[0].right = mi.rcWork.right
                            params.rgrc[0].bottom = mi.rcWork.bottom
                return True, 0
            return True, 0

        # 1.5 拦截 WM_GETMINMAXINFO 保证系统级拖拽缩放不低于最小尺寸 (带 DPI 缩放换算)
        elif msg.message == WM_GETMINMAXINFO:
            if hasattr(self, "window") and self.window:
                min_size = self.window.minimumSize()
                if min_size.isValid() and (min_size.width() > 0 or min_size.height() > 0):
                    try:
                        info = MINMAXINFO.from_address(msg.lParam)
                        hwnd = int(self.window.winId())
                        dpi = ctypes.windll.user32.GetDpiForWindow(hwnd)
                        scale = dpi / 96.0 if dpi > 0 else 1.0
                        if min_size.width() > 0:
                            info.ptMinTrackSize.x = int(min_size.width() * scale)
                        if min_size.height() > 0:
                            info.ptMinTrackSize.y = int(min_size.height() * scale)
                        return True, 0
                    except Exception:
                        pass

        # 2. 命中测试 (NCHITTEST): 边缘拉伸、标题栏拖拽、Win11 最大化按钮贴靠菜单
        elif msg.message == WM_NCHITTEST:
            # 使用 Qt 校准后的标准全局逻辑坐标，消除 High-DPI 缩放下的像素错位
            global_pos = QCursor.pos()
            local_pos = self.window.mapFromGlobal(global_pos)

            w = self.window.width()
            h = self.window.height()
            bw = max(4, min(self.border_width, 8))
            is_max = self.is_maximized()

            # 优先级 1: 检查最大化按钮，返回 HTMAXBUTTON 触发 Windows 11 Snap Layouts 贴靠菜单
            if self.max_btn and self.max_btn.isVisible():
                btn_top_left = self.max_btn.mapToGlobal(QPoint(0, 0))
                btn_rect = QRect(btn_top_left, self.max_btn.size())
                if btn_rect.contains(global_pos):
                    return True, HTMAXBUTTON

            # 其他标题栏控制按钮（主题、最小化、关闭）与交互式控件返回 HTCLIENT 派发给 Qt
            control_buttons = [self.theme_btn, self.min_btn, self.close_btn]
            for btn in control_buttons:
                if btn and btn.isVisible():
                    btn_top_left = btn.mapToGlobal(QPoint(0, 0))
                    btn_rect = QRect(btn_top_left, btn.size())
                    if btn_rect.contains(global_pos):
                        return True, HTCLIENT

            for widget in self.interactive_widgets:
                if widget and widget.isVisible():
                    top_left = widget.mapToGlobal(QPoint(0, 0))
                    rect = QRect(top_left, widget.size())
                    if rect.contains(global_pos):
                        return True, HTCLIENT

            # 优先级 2: 非最大化状态下，仅在真实窗口边缘 bw 像素内触发 8 方向边缘拉伸
            if not is_max:
                on_left = -2 <= local_pos.x() <= bw
                on_right = w - bw <= local_pos.x() <= w + 2
                on_top = -2 <= local_pos.y() <= bw
                on_bottom = h - bw <= local_pos.y() <= h + 2

                if on_top and on_left:
                    return True, HTTOPLEFT
                if on_top and on_right:
                    return True, HTTOPRIGHT
                if on_bottom and on_left:
                    return True, HTBOTTOMLEFT
                if on_bottom and on_right:
                    return True, HTBOTTOMRIGHT
                if on_left:
                    return True, HTLEFT
                if on_right:
                    return True, HTRIGHT
                if on_top:
                    return True, HTTOP
                if on_bottom:
                    return True, HTBOTTOM

            # 优先级 3: 检查标题栏可拖拽区域
            if self.title_bar and self.title_bar.isVisible():
                top_left = self.title_bar.mapToGlobal(QPoint(0, 0))
                rect = QRect(top_left, self.title_bar.size())
                if rect.contains(global_pos):
                    return True, HTCAPTION

            for widget in self.draggable_widgets:
                if widget and widget.isVisible():
                    top_left = widget.mapToGlobal(QPoint(0, 0))
                    rect = QRect(top_left, widget.size())
                    if rect.contains(global_pos):
                        return True, HTCAPTION

            return True, HTCLIENT

        # 3. 非客户区鼠标点击联动 (响应 HTMAXBUTTON 触发的最大化切换)
        elif msg.message == 0x00A1:  # WM_NCLBUTTONDOWN
            if msg.wParam == HTMAXBUTTON:
                return True, 0
        elif msg.message == 0x00A2:  # WM_NCLBUTTONUP
            if msg.wParam == HTMAXBUTTON:
                if hasattr(self.window, "title_bar") and self.window.title_bar:
                    if hasattr(self.window.title_bar, "_on_toggle_maximize"):
                        self.window.title_bar._on_toggle_maximize()
                return True, 0

        # 4. DPI 变化处理 (交由 Qt 原生处理以保持设备像素比与自适应排版一致)
        elif msg.message == WM_DPICHANGED:
            return False, 0

        return False, 0

    def set_immersive_dark_mode(self, is_dark: bool):
        """动态切换窗口暗色模式 (兼容 Win11/Win10 1903+ 的 20 与 Win10 1809 的 19)"""
        if sys.platform != "win32":
            return
        try:
            hwnd = int(self.window.winId())
            dwmapi = ctypes.windll.dwmapi
            dark_mode = ctypes.c_int(1 if is_dark else 0)
            # 优先使用现代 DWMWA_USE_IMMERSIVE_DARK_MODE (20)
            hr = dwmapi.DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                ctypes.byref(dark_mode),
                ctypes.sizeof(dark_mode)
            )
            if hr != 0:
                # 兼容旧版 Win10 (1809 之前常量为 19)
                dwmapi.DwmSetWindowAttribute(
                    hwnd,
                    19,
                    ctypes.byref(dark_mode),
                    ctypes.sizeof(dark_mode)
                )
            self.window.update()
        except Exception:
            pass
