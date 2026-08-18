# -*- coding: utf-8 -*-
"""
PixivToolkit - Material Design 3 自绘控件库
包含:
1. TitleBar: 无边框标题栏组件 (Win11 Snap 联动、状态胶囊、三联窗口控制按钮)
2. ToastManager / ToastNotification: 全局悬浮非阻塞通知系统 (Success/Info/Warning/Error)
3. InlineEditableLabel: 原位内联编辑组件 (Steam 备注点击/双击原地编辑)
4. MDSwitch: 阻尼动效、按压缩放的 MD3 开关
5. TrafficMonitorChart: 单调三次样条平滑实时网络速率监控波形图 (抗过冲)
6. LatencyBadge: 动态延迟微徽章与优选星标
7. SkeletonCard: CDN 测速骨架屏占位卡片
"""

import time
import math
from typing import List, Optional, Callable
from PySide6.QtCore import (
    Qt, QRect, QRectF, QPoint, QPointF, QSize, Property, QPropertyAnimation,
    QEasingCurve, Signal, QTimer, QObject, QEvent, QParallelAnimationGroup
)
from PySide6.QtGui import (
    QPainter, QColor, QPen, QBrush, QFont, QPainterPath, QLinearGradient,
    QRadialGradient, QMouseEvent, QKeyEvent, QFocusEvent
)
from PySide6.QtWidgets import (
    QLayout, QStackedWidget, QLayoutItem,
    QWidget, QAbstractButton, QHBoxLayout, QVBoxLayout, QLabel, QFrame,
    QPushButton, QLineEdit, QGraphicsOpacityEffect, QSizePolicy
)

try:
    from svg_icons import SvgIconFactory
except ImportError:
    SvgIconFactory = None

try:
    from material_theme import ThemeManager
except ImportError:
    class _DummyThemeManager(QObject):
        theme_changed = Signal(str)
        _instance = None
        @classmethod
        def get_instance(cls):
            if cls._instance is None:
                cls._instance = _DummyThemeManager()
            return cls._instance
        def get_current_theme(self):
            return "dark"
        def get_palette(self):
            return {}
        def get_color(self, k):
            return QColor("#000000")
    ThemeManager = _DummyThemeManager

class FlowLayout(QLayout):
    def __init__(self, parent=None, margin=0, h_spacing=10, v_spacing=10):
        super().__init__(parent)
        self.setContentsMargins(margin, margin, margin, margin)
        self._h_spacing = h_spacing
        self._v_spacing = v_spacing
        self.itemList = []

    def addItem(self, item):
        self.itemList.append(item)

    def count(self):
        return len(self.itemList)

    def itemAt(self, index):
        if 0 <= index < len(self.itemList):
            return self.itemList[index]
        return None

    def takeAt(self, index):
        if 0 <= index < len(self.itemList):
            return self.itemList.pop(index)
        return None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self.do_layout(QRect(0, 0, width, 0), True)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self.do_layout(rect, False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self.itemList:
            size = size.expandedTo(item.minimumSize())
        m = self.contentsMargins()
        size += QSize(m.left() + m.right(), m.top() + m.bottom())
        return size

    def do_layout(self, rect, test_only):
        m = self.contentsMargins()
        effective_rect = rect.adjusted(m.left(), m.top(), -m.right(), -m.bottom())
        x = effective_rect.x()
        y = effective_rect.y()
        line_height = 0

        for item in self.itemList:
            item_width = item.sizeHint().width()
            item_height = item.sizeHint().height()

            next_x = x + item_width
            if next_x > effective_rect.right() and line_height > 0:
                x = effective_rect.x()
                y = y + line_height + self._v_spacing
                next_x = x + item_width
                line_height = 0

            if not test_only:
                item.setGeometry(QRect(QPoint(x, y), item.sizeHint()))

            x += item_width + self._h_spacing
            line_height = max(line_height, item_height)

        return y + line_height - rect.y() + m.bottom()

class AnimatedStackedWidget(QStackedWidget):
    """
    带 Material 3 平滑淡入淡出动画的堆叠页面容器
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.m_duration = 200
        self.m_easing_curve = QEasingCurve.OutCubic
        self._anim = None
        self._target_index = -1

    def setCurrentIndex(self, index):
        if index < 0 or index >= self.count():
            return
        if self.currentIndex() == index:
            return

        # 如果窗口尚未显示（例如启动阶段），直接即时切换
        if not self.isVisible():
            super().setCurrentIndex(index)
            return

        # 如果有正在进行的动画，先立即结束
        if self._anim and self._anim.state() == QPropertyAnimation.Running:
            self._anim.stop()

        current_widget = self.currentWidget()
        next_widget = self.widget(index)
        if not current_widget or not next_widget:
            super().setCurrentIndex(index)
            return

        self._target_index = index
        next_widget.setGeometry(self.contentsRect())
        next_widget.show()
        next_widget.raise_()

        effect = QGraphicsOpacityEffect(next_widget)
        next_widget.setGraphicsEffect(effect)

        self._anim = QPropertyAnimation(effect, b"opacity", self)
        self._anim.setDuration(self.m_duration)
        self._anim.setEasingCurve(self.m_easing_curve)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)

        def _on_finished():
            super(AnimatedStackedWidget, self).setCurrentIndex(index)
            next_widget.setGraphicsEffect(None)
            self._target_index = -1

        self._anim.finished.connect(_on_finished)
        super().setCurrentIndex(index)  # 立即更新 currentIndex 状态
        self._anim.start()


# 1. 自定义标题栏 (TitleBar)
# ==============================================================================
class TitleBar(QFrame):
    """
    MD3 无边框标题栏
    高度 38px，包含品牌 Logo、大标题、版本 Pill、状态胶囊与三联窗口按钮
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("TitleBar")
        self.setFixedHeight(38)
        self.window = parent

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 0, 0)
        layout.setSpacing(8)

        # 品牌图标与文字
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(20, 20)
        self._render_brand_icon()
        layout.addWidget(self.icon_label)

        self.title_label = QLabel("PixivToolkit")
        self.title_label.setObjectName("TitleBrand")
        layout.addWidget(self.title_label)

        self.badge_label = QLabel("MD3 Native")
        self.badge_label.setObjectName("TitleBadge")
        layout.addWidget(self.badge_label)

        # 运行状态胶囊指示器
        self.status_pill = QLabel("● 加速待命")
        self.status_pill.setObjectName("TitleStatusPill")
        layout.addWidget(self.status_pill)

        # 中间可拖拽空白扩展区
        layout.addStretch()

        # 窗口操作按钮组 (主题切换胶囊 + 最小化、最大化、关闭三联)
        self.btn_theme = QPushButton()
        self.btn_theme.setObjectName("BtnTitleTheme")
        self.btn_theme.setProperty("class", "ThemeToggleBtn")
        self.btn_theme.setFixedSize(36, 32)
        self.btn_theme.setCursor(Qt.PointingHandCursor)
        self.btn_theme.setToolTip("切换明暗主题 (Alt+T)")
        self.btn_theme.clicked.connect(self._on_theme_toggle)
        
        ThemeManager.get_instance().theme_changed.connect(self._on_theme_changed)

        self.btn_min = QPushButton()
        self.btn_min.setObjectName("BtnTitleMin")
        self.btn_min.setProperty("class", "WindowControlBtn")
        self.btn_min.setFixedSize(46, 38)
        self.btn_min.setToolTip("最小化")
        self.btn_min.clicked.connect(self._on_minimize)

        self.btn_max = QPushButton()
        self.btn_max.setObjectName("BtnTitleMax")
        self.btn_max.setProperty("class", "WindowControlBtn")
        self.btn_max.setFixedSize(46, 38)
        self.btn_max.setToolTip("最大化 / 还原")
        self.btn_max.clicked.connect(self._on_toggle_maximize)

        self.btn_close = QPushButton()
        self.btn_close.setObjectName("BtnTitleClose")
        self.btn_close.setProperty("class", "WindowCloseBtn")
        self.btn_close.setFixedSize(46, 38)
        self.btn_close.setToolTip("关闭 (最小化到托盘)")
        self.btn_close.clicked.connect(self._on_close)

        # 初始加载 Fluent 矢量图标
        self._refresh_window_control_icons()

        layout.addWidget(self.btn_theme)
        layout.addWidget(self.btn_min)
        layout.addWidget(self.btn_max)
        layout.addWidget(self.btn_close)

    def _render_brand_icon(self):
        """自绘 20x20 品牌 Pixiv 柔和蔚蓝微图标"""
        from PySide6.QtGui import QPixmap
        pixmap = QPixmap(20, 20)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)

        is_dark = ThemeManager.get_instance().is_dark
        # 圆角背景 (Pixiv 柔和蔚蓝高光渐变)
        painter.setPen(Qt.NoPen)
        grad = QLinearGradient(0, 0, 20, 20)
        if is_dark:
            grad.setColorAt(0, QColor("#7EB9F5"))
            grad.setColorAt(1, QColor("#1D8CF8"))
        else:
            grad.setColorAt(0, QColor("#38BDF8"))
            grad.setColorAt(1, QColor("#0284C7"))
        painter.setBrush(QBrush(grad))
        painter.drawRoundedRect(QRectF(1, 1, 18, 18), 5, 5)

        # 中心闪电/加速微图腾
        painter.setPen(QPen(QColor("#FFFFFF"), 1.8, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        path = QPainterPath()
        path.moveTo(11, 4)
        path.lineTo(6, 11)
        path.lineTo(10, 11)
        path.lineTo(9, 16)
        path.lineTo(14, 9)
        path.lineTo(10, 9)
        path.closeSubpath()
        painter.setBrush(QBrush(QColor("#FFFFFF")))
        painter.drawPath(path)
        painter.end()
        self.icon_label.setPixmap(pixmap)

    def update_status(self, is_running: bool, text: str = None):
        """更新标题栏状态胶囊"""
        is_dark = ThemeManager.get_instance().is_dark
        if is_running:
            msg = text if text else "● 代理加速中"
            self.status_pill.setText(msg)
            if is_dark:
                self.status_pill.setStyleSheet("""
                    background-color: rgba(52, 211, 153, 0.12);
                    color: #34D399;
                    border: none;
                    border-radius: 11px;
                    padding: 2px 10px;
                """)
            else:
                self.status_pill.setStyleSheet("""
                    background-color: rgba(16, 185, 129, 0.10);
                    color: #059669;
                    border: none;
                    border-radius: 11px;
                    padding: 2px 10px;
                """)
        else:
            msg = text if text else "○ 服务已停止"
            self.status_pill.setText(msg)
            if is_dark:
                self.status_pill.setStyleSheet("""
                    background-color: rgba(117, 135, 158, 0.12);
                    color: #75879E;
                    border: none;
                    border-radius: 11px;
                    padding: 2px 10px;
                """)
            else:
                self.status_pill.setStyleSheet("""
                    background-color: rgba(100, 116, 139, 0.08);
                    color: #64748B;
                    border: none;
                    border-radius: 11px;
                    padding: 2px 10px;
                """)

    def _refresh_window_control_icons(self):
        """批量渲染并设置标题栏控制按钮的 Fluent 矢量图标"""
        is_dark = ThemeManager.get_instance().is_dark
        ctrl_icon_color = "#CBD5E1" if is_dark else "#475569"
        
        # 1. 主题切换按钮
        theme_icon_name = "sun" if is_dark else "moon"
        theme_icon_color = "#CFE5FF" if is_dark else "#0284C7"
        if SvgIconFactory:
            self.btn_theme.setIcon(SvgIconFactory.get_icon(theme_icon_name, theme_icon_color, 16))
            self.btn_theme.setIconSize(QSize(16, 16))
            self.btn_theme.setText("")
        else:
            self.btn_theme.setText("☀️" if is_dark else "🌙")

        # 2. 最小化按钮
        if SvgIconFactory:
            self.btn_min.setIcon(SvgIconFactory.get_icon("window_min", ctrl_icon_color, 12))
            self.btn_min.setIconSize(QSize(12, 12))
            self.btn_min.setText("")

        # 3. 最大化/还原按钮
        is_max = self.window.isMaximized() if self.window else False
        self.update_max_icon(is_max)

        # 4. 关闭按钮
        if SvgIconFactory:
            self.btn_close.setIcon(SvgIconFactory.get_icon("window_close", ctrl_icon_color, 12))
            self.btn_close.setIconSize(QSize(12, 12))
            self.btn_close.setText("")

    def update_max_icon(self, is_maximized: bool):
        """根据最大化状态切换 Fluent SVG 矢量图标"""
        is_dark = ThemeManager.get_instance().is_dark
        ctrl_icon_color = "#CBD5E1" if is_dark else "#475569"
        icon_name = "window_restore" if is_maximized else "window_max"
        
        if SvgIconFactory:
            self.btn_max.setIcon(SvgIconFactory.get_icon(icon_name, ctrl_icon_color, 12))
            self.btn_max.setIconSize(QSize(12, 12))
            self.btn_max.setText("")
        else:
            self.btn_max.setText("❐" if is_maximized else "▢")
        self.btn_max.setToolTip("还原" if is_maximized else "最大化")

    def mouseDoubleClickEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            self._on_toggle_maximize()
            event.accept()
        else:
            super().mouseDoubleClickEvent(event)

    def _on_theme_toggle(self):
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance()
        new_theme = ThemeManager.get_instance().toggle_theme(app)
        if self.window and hasattr(self.window, "frameless_helper") and self.window.frameless_helper:
            self.window.frameless_helper.set_immersive_dark_mode(new_theme == "dark")

    def _on_theme_changed(self, theme_name: str = ""):
        self._refresh_window_control_icons()
        self._render_brand_icon()
        self.update_status(self.status_pill.text().startswith("●"), self.status_pill.text())

    def _on_minimize(self):
        if self.window:
            self.window.showMinimized()

    def _on_toggle_maximize(self):
        if not self.window:
            return
        if self.window.isMaximized():
            self.window.showNormal()
            self.update_max_icon(False)
        else:
            self.window.showMaximized()
            self.update_max_icon(True)

    def _on_close(self):
        if self.window:
            self.window.close()


# ==============================================================================
# 2. 悬浮非侵入式通知系统 (MD3 Toast / Snackbar Overlay)
# ==============================================================================
class ToastNotification(QFrame):
    """
    单个 MD3 悬浮通知卡片
    具备进场垂直位移 + 淡入淡出动画、微光晕边框与内联 Action 按钮
    """
    closed = Signal(object)

    def __init__(self, parent: QWidget, message: str, toast_type: str = "info",
                 duration: int = 3000, action_text: str = None, on_action: Callable = None):
        super().__init__(parent)
        self.toast_type = toast_type.lower()
        self.duration = duration
        self.on_action = on_action
        self.setProperty("class", "ToastFrame")
        self.setAttribute(Qt.WA_DeleteOnClose)

        # 视觉效果
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.opacity_effect.setOpacity(0.0)
        self.setGraphicsEffect(self.opacity_effect)

        # 布局
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 8, 10, 8)
        layout.setSpacing(10)

        # 状态图标
        icon_name, icon_color, border_color, bg_tint = self._get_style_params()
        self.icon_lbl = QLabel()
        if SvgIconFactory:
            self.icon_lbl.setPixmap(SvgIconFactory.get_pixmap(icon_name, icon_color, 18))
        else:
            self.icon_lbl.setText("●")
            self.icon_lbl.setStyleSheet(f"color: {icon_color}; font-size: 14px; font-weight: bold;")
        layout.addWidget(self.icon_lbl)

        # 消息文本
        self.msg_lbl = QLabel(message)
        self.msg_lbl.setProperty("class", "ToastMsg")
        self.msg_lbl.setWordWrap(True)
        layout.addWidget(self.msg_lbl)

        # 可选操作按钮
        if action_text and on_action:
            self.action_btn = QPushButton(action_text)
            self.action_btn.setProperty("class", "ToastActionBtn")
            self.action_btn.setCursor(Qt.PointingHandCursor)
            self.action_btn.clicked.connect(self._handle_action)
            layout.addWidget(self.action_btn)

        # 关闭按钮
        self.close_btn = QPushButton("✕")
        self.close_btn.setProperty("class", "ToastCloseBtn")
        self.close_btn.setCursor(Qt.PointingHandCursor)
        self.close_btn.clicked.connect(self.dismiss)
        layout.addWidget(self.close_btn)

        # 设置微光晕边框样式
        is_dark = ThemeManager.get_instance().is_dark
        toast_bg = "#182032" if is_dark else "#FFFFFF"
        self.setStyleSheet(f"""
            QFrame[class="ToastFrame"] {{
                background-color: {toast_bg};
                border: 1.2px solid {border_color};
                border-radius: 12px;
            }}
        """)

        # 定时器
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.dismiss)

        # 进场动画
        self.anim_opacity = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.anim_opacity.setDuration(220)
        self.anim_opacity.setEasingCurve(QEasingCurve.OutCubic)

    def _get_style_params(self):
        is_dark = ThemeManager.get_instance().is_dark
        if self.toast_type == "success":
            return "check", "#34D399" if is_dark else "#10B981", "#059669", "rgba(16, 185, 129, 0.15)"
        elif self.toast_type == "warning":
            return "warning", "#FBBF24" if is_dark else "#F59E0B", "#D97706", "rgba(245, 158, 11, 0.15)"
        elif self.toast_type == "error":
            return "error", "#F87171" if is_dark else "#EF4444", "#DC2626", "rgba(239, 68, 68, 0.15)"
        else:
            return "info", "#7EB9F5" if is_dark else "#0284C7", "#1D3B66" if is_dark else "#BAE6FD", "rgba(126, 185, 245, 0.15)"

    def show_animated(self, target_pos: QPoint):
        self.move(target_pos.x(), target_pos.y() + 15)
        self.show()
        self.raise_()

        # 位移动画
        self.anim_pos = QPropertyAnimation(self, b"pos")
        self.anim_pos.setDuration(220)
        self.anim_pos.setStartValue(self.pos())
        self.anim_pos.setEndValue(target_pos)
        self.anim_pos.setEasingCurve(QEasingCurve.OutCubic)

        self.anim_opacity.setStartValue(0.0)
        self.anim_opacity.setEndValue(1.0)

        self.anim_pos.start()
        self.anim_opacity.start()

        if self.duration > 0:
            self.timer.start(self.duration)

    def enterEvent(self, event):
        """鼠标悬停暂停自动关闭"""
        if self.timer.isActive():
            self.timer.stop()
        super().enterEvent(event)

    def leaveEvent(self, event):
        """鼠标离开恢复计时"""
        if self.duration > 0 and not self.timer.isActive():
            self.timer.start(1500)
        super().leaveEvent(event)

    def _handle_action(self):
        if self.on_action:
            try:
                self.on_action()
            except Exception as e:
                print(f"[Toast] Action callback error: {e}")
        self.dismiss()

    def dismiss(self):
        """淡出销毁"""
        self.timer.stop()
        self.anim_opacity.stop()
        self.anim_opacity.setStartValue(self.opacity_effect.opacity())
        self.anim_opacity.setEndValue(0.0)
        self.anim_opacity.setDuration(160)
        self.anim_opacity.finished.connect(self._on_dismiss_finished)
        self.anim_opacity.start()

    def _on_dismiss_finished(self):
        self.closed.emit(self)
        self.close()


class ToastManager(QObject):
    """
    全局非侵入式 Toast 通知总线单例
    自动管理悬浮通知的进出场、位置计算与竖向堆叠
    """
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = ToastManager()
        return cls._instance

    def __init__(self):
        super().__init__()
        self.active_toasts: List[ToastNotification] = []
        self._watched_parent = None

    def show(self, parent: QWidget, message: str, toast_type: str = "info",
             duration: int = 3000, action_text: str = None, on_action: Callable = None):
        """
        显示一条非侵入式通知
        :param parent: 主窗口容器
        :param message: 通知文本内容
        :param toast_type: 'success' | 'info' | 'warning' | 'error'
        :param duration: 自动消失毫秒数 (默认 3000ms)
        :param action_text: 内联动作按钮文字 (如 '[🛡️ 提权]')
        :param on_action: 动作回调函数
        """
        if not parent:
            return

        toast = ToastNotification(
            parent, message, toast_type, duration, action_text, on_action
        )
        toast.closed.connect(self._on_toast_closed)
        self.active_toasts.append(toast)

        # 调整尺寸并计算初始位置
        toast.adjustSize()
        self._reposition_toasts(parent)

        if parent and parent != self._watched_parent:
            if self._watched_parent:
                self._watched_parent.removeEventFilter(self)
            parent.installEventFilter(self)
            self._watched_parent = parent

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Resize and obj == self._watched_parent:
            self._reposition_toasts(obj)
        return False

    def _on_toast_closed(self, toast):
        if toast in self.active_toasts:
            self.active_toasts.remove(toast)
            if self.active_toasts:
                parent = self.active_toasts[0].parentWidget()
                self._reposition_toasts(parent)

    def _reposition_toasts(self, parent: QWidget):
        if not parent:
            return
        pw = parent.width()
        ph = parent.height()

        # 从底部往上堆叠，距底部 24px
        curr_y = ph - 24
        for toast in reversed(self.active_toasts):
            tw = toast.width()
            th = toast.height()
            target_x = max(16, (pw - tw) // 2)
            target_y = curr_y - th
            curr_y = target_y - 8

            if toast.isVisible():
                # 平滑平移
                anim = QPropertyAnimation(toast, b"pos", toast)
                anim.setDuration(180)
                anim.setEndValue(QPoint(target_x, target_y))
                anim.setEasingCurve(QEasingCurve.OutCubic)
                anim.start()
            else:
                toast.show_animated(QPoint(target_x, target_y))


# 全局快速调用方法
def show_toast(parent: QWidget, message: str, toast_type: str = "info",
               duration: int = 3000, action_text: str = None, on_action: Callable = None):
    ToastManager.get_instance().show(parent, message, toast_type, duration, action_text, on_action)


# ==============================================================================
# 3. 原位内联编辑组件 (InlineEditableLabel)
# ==============================================================================
class InlineEditableLabel(QWidget):
    """
    原位内联编辑组件
    常规态：显示当前别名徽章或 '+ 备注' (带微铅笔 ✏️)
    激活态：单击/双击原地切换为 QLineEdit，回车保存，Esc取消，失去焦点自动保存
    """
    text_changed = Signal(str)

    def __init__(self, initial_text: str = "", placeholder: str = "+ 备注", parent=None):
        super().__init__(parent)
        self.current_text = initial_text
        self.placeholder = placeholder

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 徽章展示态
        self.badge_label = QLabel()
        self.badge_label.setProperty("class", "InlineBadge")
        self.badge_label.setCursor(Qt.PointingHandCursor)
        self.badge_label.setToolTip("点击或双击修改备注 (回车即存)")
        self._update_badge_text()
        layout.addWidget(self.badge_label)

        # 编辑输入框
        self.edit_input = QLineEdit()
        self.edit_input.setProperty("class", "InlineEditInput")
        self.edit_input.setPlaceholderText("输入账号备注...")
        self.edit_input.setMaxLength(24)
        self.edit_input.hide()
        layout.addWidget(self.edit_input)

        # 事件监听
        self.badge_label.mousePressEvent = self._on_badge_clicked
        self.edit_input.returnPressed.connect(self._commit_edit)
        self.edit_input.installEventFilter(self)
        ThemeManager.get_instance().theme_changed.connect(self._on_theme_changed)

    def _on_theme_changed(self, theme: str = ""):
        try:
            self._update_badge_text()
        except (RuntimeError, Exception):
            pass

    def _update_badge_text(self):
        try:
            if not hasattr(self, 'badge_label') or not self.badge_label:
                return
            is_dark = ThemeManager.get_instance().is_dark
            if self.current_text:
                self.badge_label.setText(f"备注: {self.current_text}")
                if is_dark:
                    self.badge_label.setStyleSheet("""
                        background-color: #182032;
                        color: #7EB9F5;
                        border: 1px solid #273752;
                        border-radius: 6px;
                        padding: 2px 8px;
                        font-size: 11px;
                        font-weight: bold;
                    """)
                else:
                    self.badge_label.setStyleSheet("""
                        background-color: #E0F2FE;
                        color: #0284C7;
                        border: 1px solid #BAE6FD;
                        border-radius: 6px;
                        padding: 2px 8px;
                        font-size: 11px;
                        font-weight: bold;
                    """)
            else:
                self.badge_label.setText(f"{self.placeholder}")
                if is_dark:
                    self.badge_label.setStyleSheet("""
                        background-color: transparent;
                        color: #75879E;
                        border: 1px dashed #273752;
                        border-radius: 6px;
                        padding: 2px 8px;
                        font-size: 11px;
                    """)
                else:
                    self.badge_label.setStyleSheet("""
                        background-color: transparent;
                        color: #64748B;
                        border: 1px dashed #CBD5E1;
                        border-radius: 6px;
                        padding: 2px 8px;
                        font-size: 11px;
                    """)
        except (RuntimeError, Exception):
            pass

    def set_text(self, text: str):
        self.current_text = text.strip()
        self._update_badge_text()

    def get_text(self) -> str:
        return self.current_text

    def _on_badge_clicked(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            self.start_edit()

    def start_edit(self):
        """激活原位编辑输入态"""
        self.badge_label.hide()
        self.edit_input.setText(self.current_text)
        self.edit_input.show()
        self.edit_input.setFocus()
        self.edit_input.selectAll()

    def _commit_edit(self):
        """提交保存"""
        new_val = self.edit_input.text().strip()
        self.edit_input.hide()
        self.badge_label.show()
        if new_val != self.current_text:
            self.current_text = new_val
            self._update_badge_text()
            self.text_changed.emit(new_val)

    def _cancel_edit(self):
        """取消编辑"""
        self.edit_input.hide()
        self.badge_label.show()

    def eventFilter(self, obj, event):
        if obj == self.edit_input:
            if event.type() == QEvent.FocusOut:
                self._commit_edit()
                return True
            elif event.type() == QEvent.KeyPress:
                key_event = event
                if key_event.key() == Qt.Key_Escape:
                    self._cancel_edit()
                    return True
        return super().eventFilter(obj, event)


# ==============================================================================
# 4. Material 3 动画开关 (MDSwitch)
# ==============================================================================
class MDSwitch(QAbstractButton):
    """
    Material Design 3 标准动画开关
    具备阻尼微动效、状态色彩平滑插值、按压缩放
    """
    def __init__(self, parent=None, checked=False):
        super().__init__(parent)
        self.setCheckable(True)
        self.setChecked(checked)
        self.setFixedSize(52, 28)
        self.setCursor(Qt.PointingHandCursor)

        self._thumb_position = 1.0 if checked else 0.0
        self._press_scale = 0.0  # 按压拉伸动画
        self._hover_glow = 0.0

        self._anim = QPropertyAnimation(self, b"thumb_position", self)
        self._anim.setDuration(220)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

        self._hover_anim = QPropertyAnimation(self, b"hover_glow_prop", self)
        self._hover_anim.setDuration(150)
        self._hover_anim.setEasingCurve(QEasingCurve.OutCubic)

        self.toggled.connect(self._on_toggled)
        ThemeManager.get_instance().theme_changed.connect(self.update)

    def _get_thumb_position(self) -> float:
        return self._thumb_position

    def _set_thumb_position(self, pos: float):
        self._thumb_position = pos
        self.update()

    thumb_position = Property(float, _get_thumb_position, _set_thumb_position)

    def _get_hover_glow(self) -> float:
        return self._hover_glow

    def _set_hover_glow(self, val: float):
        self._hover_glow = val
        self.update()

    hover_glow_prop = Property(float, _get_hover_glow, _set_hover_glow)

    def _on_toggled(self, checked: bool):
        self._anim.stop()
        self._anim.setStartValue(self._thumb_position)
        self._anim.setEndValue(1.0 if checked else 0.0)
        self._anim.start()

    def setCheckedNoAnim(self, checked: bool):
        self.blockSignals(True)
        self.setChecked(checked)
        self._thumb_position = 1.0 if checked else 0.0
        self.blockSignals(False)
        self.update()

    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            self._press_scale = 1.0
            self.update()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            self._press_scale = 0.0
            self.update()
        super().mouseReleaseEvent(event)

    def enterEvent(self, event):
        self._hover_anim.stop()
        self._hover_anim.setStartValue(self._hover_glow)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._hover_anim.stop()
        self._hover_anim.setStartValue(self._hover_glow)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()
        self._press_scale = 0.0
        self.update()
        super().leaveEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = float(self.width())
        h = float(self.height())
        radius = h / 2.0
        pos = self._thumb_position

        # 1. 轨道色彩插值
        is_dark = ThemeManager.get_instance().is_dark
        track_off = QColor("#1E283E") if is_dark else QColor("#E2E8F0")
        track_on = QColor("#7EB9F5") if is_dark else QColor("#0284C7")
        track_color = QColor(
            int(track_off.red() + (track_on.red() - track_off.red()) * pos),
            int(track_off.green() + (track_on.green() - track_off.green()) * pos),
            int(track_off.blue() + (track_on.blue() - track_off.blue()) * pos)
        )

        border_off = QColor("#273752") if is_dark else QColor("#CBD5E1")
        border_on = QColor("#A6D1FF") if is_dark else QColor("#0369A1")
        border_color = QColor(
            int(border_off.red() + (border_on.red() - border_off.red()) * pos),
            int(border_off.green() + (border_on.green() - border_off.green()) * pos),
            int(border_off.blue() + (border_on.blue() - border_off.blue()) * pos)
        )

        # 绘制轨道
        track_rect = QRectF(1, 1, w - 2, h - 2)
        painter.setPen(QPen(border_color, 1.2))
        painter.setBrush(QBrush(track_color))
        painter.drawRoundedRect(track_rect, radius, radius)

        # 2. 滑块尺寸与位置计算
        # 未开启 14px，开启 20px，按下额外扩充 2px
        base_diameter = 14.0 + 6.0 * pos
        extra = 2.0 if self._press_scale > 0 else 0.0
        thumb_diameter = base_diameter + extra
        thumb_radius = thumb_diameter / 2.0

        thumb_x_min = 4.0 + (20.0 - thumb_diameter) / 2.0
        thumb_x_max = w - 4.0 - thumb_diameter - (20.0 - thumb_diameter) / 2.0
        thumb_x = thumb_x_min + (thumb_x_max - thumb_x_min) * pos
        thumb_y = (h - thumb_diameter) / 2.0

        # 3. 悬浮光晕绘制
        if self._hover_glow > 0:
            glow_color = QColor("rgba(126, 185, 245, 0.20)") if is_dark else QColor("rgba(2, 132, 199, 0.15)")
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(glow_color))
            painter.drawEllipse(QRectF(thumb_x - 4, thumb_y - 4, thumb_diameter + 8, thumb_diameter + 8))

        # 4. 绘制滑块
        thumb_off = QColor("#94A3B8") if is_dark else QColor("#64748B")
        thumb_on = QColor("#FFFFFF") if is_dark else QColor("#FFFFFF")
        thumb_color = QColor(
            int(thumb_off.red() + (thumb_on.red() - thumb_off.red()) * pos),
            int(thumb_off.green() + (thumb_on.green() - thumb_off.green()) * pos),
            int(thumb_off.blue() + (thumb_on.blue() - thumb_off.blue()) * pos)
        )

        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(thumb_color))
        painter.drawEllipse(QRectF(thumb_x, thumb_y, thumb_diameter, thumb_diameter))

        # 5. 开启时在滑块中心绘制精致钩标志
        if pos > 0.55:
            check_color = QColor("#002E5C") if is_dark else QColor("#0284C7")
            painter.setPen(QPen(check_color, 1.8, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            opacity = min(1.0, (pos - 0.55) / 0.45)
            painter.setOpacity(opacity)
            cx = thumb_x + thumb_radius
            cy = thumb_y + thumb_radius
            painter.drawLine(QPointF(cx - 3.5, cy), QPointF(cx - 1, cy + 2.5))
            painter.drawLine(QPointF(cx - 1, cy + 2.5), QPointF(cx + 4, cy - 2.5))
            painter.setOpacity(1.0)

        painter.end()


# ==============================================================================
# 5. 单调三次样条平滑网络波形图 (TrafficMonitorChart)
# ==============================================================================
class TrafficMonitorChart(QWidget):
    """
    实时网络监控波形图
    采用单调三次样条 (Monotone Spline) 平滑算法，消除折线突变与过冲
    """
    def __init__(self, parent=None, max_points: int = 30):
        super().__init__(parent)
        self.max_points = max_points
        self.down_speeds: List[float] = [0.0] * max_points
        self.up_speeds: List[float] = [0.0] * max_points
        self.total_requests = 0
        self.cache_hits = 0
        self._ema_max = 100.0

        self.setFixedHeight(140)
        ThemeManager.get_instance().theme_changed.connect(self.update)
        self.setMinimumWidth(320)

    def add_sample(self, down_kb: float, up_kb: float, req_delta: int = 0, hit_delta: int = 0):
        self.down_speeds.pop(0)
        self.down_speeds.append(max(0.0, down_kb))

        self.up_speeds.pop(0)
        self.up_speeds.append(max(0.0, up_kb))

        self.total_requests += req_delta
        self.cache_hits += hit_delta
        self.update()

    def _build_smooth_path(self, points: List[QPointF]) -> QPainterPath:
        """构建单调平滑三次贝塞尔样条路径，避免突变过冲"""
        path = QPainterPath()
        if not points:
            return path
        path.moveTo(points[0])
        n = len(points)
        if n < 2:
            return path
        if n == 2:
            path.lineTo(points[1])
            return path

        for i in range(n - 1):
            p0 = points[i]
            p1 = points[i + 1]
            # 计算平滑切线控制点
            p_prev = points[i - 1] if i > 0 else p0
            p_next = points[i + 2] if i < n - 2 else p1

            dx = p1.x() - p0.x()
            cp1_x = p0.x() + dx / 3.0
            cp1_y = p0.y() + (p1.y() - p_prev.y()) / 6.0

            cp2_x = p1.x() - dx / 3.0
            cp2_y = p1.y() - (p_next.y() - p0.y()) / 6.0

            path.cubicTo(QPointF(cp1_x, cp1_y), QPointF(cp2_x, cp2_y), p1)

        return path

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = float(self.width())
        h = float(self.height())

        # 1. 容器底色与圆角边框 (通透 Material 3 调色板，告别死黑)
        is_dark = ThemeManager.get_instance().is_dark
        bg_rect = QRectF(0, 0, w, h)
        bg_grad = QLinearGradient(0, 0, 0, h)
        if is_dark:
            bg_grad.setColorAt(0.0, QColor("#182234"))
            bg_grad.setColorAt(1.0, QColor("#121927"))
            painter.setPen(QPen(QColor("#223147"), 1.2))
        else:
            bg_grad.setColorAt(0.0, QColor("#FFFFFF"))
            bg_grad.setColorAt(1.0, QColor("#F8FAFC"))
            painter.setPen(QPen(QColor("#E2E8F0"), 1.2))
        painter.setBrush(QBrush(bg_grad))
        painter.drawRoundedRect(bg_rect, 14, 14)

        # 水平参考线与呼吸网格
        chart_top = 38.0
        chart_bottom = h - 14.0
        chart_h = chart_bottom - chart_top
        chart_left = 16.0
        chart_right = w - 16.0
        chart_w = chart_right - chart_left

        painter.setPen(QPen(QColor(255, 255, 255, 12) if is_dark else QColor(0, 0, 0, 12), 1, Qt.DashLine))
        for i in range(1, 4):
            y = chart_top + chart_h * (i / 4.0)
            painter.drawLine(QPointF(chart_left, y), QPointF(chart_right, y))

        # 2. 动态 Y 轴缩放
        raw_max = max(max(self.down_speeds), max(self.up_speeds), 100.0)
        alpha = 0.15  # EMA平滑系数，越小越平滑
        if raw_max > self._ema_max:
            self._ema_max = raw_max  # 上升时立即跟随
        else:
            self._ema_max = self._ema_max * (1.0 - alpha) + raw_max * alpha  # 下降时平滑衰减
        max_val = self._ema_max

        # 3. 构造点序列与局部极值计算
        n = len(self.down_speeds)
        dx = chart_w / float(n - 1) if n > 1 else chart_w

        points_up = []
        min_y_up = chart_bottom
        for i, val in enumerate(self.up_speeds):
            x = chart_left + i * dx
            norm = min(1.0, val / max_val)
            y = chart_bottom - norm * chart_h
            min_y_up = min(min_y_up, y)
            points_up.append(QPointF(x, y))

        points_down = []
        min_y_down = chart_bottom
        for i, val in enumerate(self.down_speeds):
            x = chart_left + i * dx
            norm = min(1.0, val / max_val)
            y = chart_bottom - norm * chart_h
            min_y_down = min(min_y_down, y)
            points_down.append(QPointF(x, y))

        # 4. 绘制上传曲线与渐变填充 (Pixiv 蓝)
        if len(points_up) >= 2:
            path_up = self._build_smooth_path(points_up)
            fill_up = QPainterPath(path_up)
            fill_up.lineTo(chart_right, chart_bottom)
            fill_up.lineTo(chart_left, chart_bottom)
            fill_up.closeSubpath()

            grad_up = QLinearGradient(0, min_y_up - 2, 0, chart_bottom)
            if is_dark:
                grad_up.setColorAt(0.0, QColor(126, 185, 245, 75))
                grad_up.setColorAt(0.4, QColor(126, 185, 245, 35))
                grad_up.setColorAt(1.0, QColor(126, 185, 245, 8))
            else:
                grad_up.setColorAt(0.0, QColor(2, 132, 199, 65))
                grad_up.setColorAt(0.4, QColor(2, 132, 199, 25))
                grad_up.setColorAt(1.0, QColor(2, 132, 199, 5))
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(grad_up))
            painter.drawPath(fill_up)

            painter.setPen(QPen(QColor("#7EB9F5") if is_dark else QColor("#0284C7"), 1.8, Qt.DashLine, Qt.RoundCap, Qt.RoundJoin))
            painter.setBrush(Qt.NoBrush)
            painter.drawPath(path_up)

        # 5. 绘制下载曲线与渐变填充 (绿色)
        if len(points_down) >= 2:
            path_down = self._build_smooth_path(points_down)
            fill_down = QPainterPath(path_down)
            fill_down.lineTo(chart_right, chart_bottom)
            fill_down.lineTo(chart_left, chart_bottom)
            fill_down.closeSubpath()

            grad_down = QLinearGradient(0, min_y_down - 2, 0, chart_bottom)
            if is_dark:
                grad_down.setColorAt(0.0, QColor(52, 211, 153, 95))
                grad_down.setColorAt(0.3, QColor(52, 211, 153, 50))
                grad_down.setColorAt(0.8, QColor(16, 185, 129, 20))
                grad_down.setColorAt(1.0, QColor(16, 185, 129, 6))
            else:
                grad_down.setColorAt(0.0, QColor(16, 185, 129, 85))
                grad_down.setColorAt(0.3, QColor(16, 185, 129, 40))
                grad_down.setColorAt(0.8, QColor(16, 185, 129, 15))
                grad_down.setColorAt(1.0, QColor(16, 185, 129, 4))
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(grad_down))
            painter.drawPath(fill_down)

            painter.setPen(QPen(QColor("#34D399") if is_dark else QColor("#10B981"), 2.2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            painter.setBrush(Qt.NoBrush)
            painter.drawPath(path_down)

        # 6. 顶部指标排版
        curr_down = self.down_speeds[-1]
        down_txt = f"↓ 下载: {curr_down:.1f} KB/s" if curr_down < 1024 else f"↓ 下载: {curr_down/1024.0:.2f} MB/s"
        painter.setPen(QColor("#34D399") if is_dark else QColor("#10B981"))
        painter.setFont(QFont("Segoe UI", 10, QFont.Bold))
        painter.drawText(QRectF(18, 10, 160, 20), Qt.AlignLeft | Qt.AlignVCenter, down_txt)

        curr_up = self.up_speeds[-1]
        up_txt = f"↑ 上传: {curr_up:.1f} KB/s"
        painter.setPen(QColor("#7EB9F5") if is_dark else QColor("#0284C7"))
        painter.drawText(QRectF(190, 10, 130, 20), Qt.AlignLeft | Qt.AlignVCenter, up_txt)

        req_txt = f"已加速请求: {self.total_requests} 次"
        painter.setPen(QColor("#75879E") if is_dark else QColor("#64748B"))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(QRectF(w - 240, 10, 222, 20), Qt.AlignRight | Qt.AlignVCenter, req_txt)

        painter.end()


# ==============================================================================
# 6. 延迟微徽章 (LatencyBadge)
# ==============================================================================
class LatencyBadge(QWidget):
    """动态延迟微徽章控件"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.latency_ms = -1
        self.is_star = False
        self.setFixedHeight(24)
        self.setMinimumWidth(70)
        ThemeManager.get_instance().theme_changed.connect(self.update)

    def set_latency(self, ms: int, is_star: bool = False):
        self.latency_ms = ms
        self.is_star = is_star
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = float(self.width())
        h = float(self.height())

        is_dark = ThemeManager.get_instance().is_dark
        if self.latency_ms < 0:
            bg_color = QColor("#182032") if is_dark else QColor("#F1F5F9")
            border_color = QColor("#273752") if is_dark else QColor("#CBD5E1")
            text_color = QColor("#75879E") if is_dark else QColor("#64748B")
            txt = "检测中"
            dot_color = QColor("#75879E") if is_dark else QColor("#94A3B8")
        elif self.latency_ms >= 9999:
            bg_color = QColor("rgba(239, 68, 68, 0.15)") if is_dark else QColor("rgba(239, 68, 68, 0.10)")
            border_color = QColor("#EF4444")
            text_color = QColor("#F87171") if is_dark else QColor("#DC2626")
            txt = "超时"
            dot_color = QColor("#EF4444")
        else:
            if self.latency_ms < 60:
                bg_color = QColor("rgba(52, 211, 153, 0.12)") if is_dark else QColor("rgba(16, 185, 129, 0.08)")
                border_color = QColor("transparent")
                text_color = QColor("#34D399") if is_dark else QColor("#059669")
                dot_color = QColor("#10B981")
            elif self.latency_ms < 150:
                bg_color = QColor("rgba(245, 158, 11, 0.15)") if is_dark else QColor("rgba(245, 158, 11, 0.10)")
                border_color = QColor("#D97706")
                text_color = QColor("#FBBF24") if is_dark else QColor("#D97706")
                dot_color = QColor("#F59E0B")
            else:
                bg_color = QColor("rgba(239, 68, 68, 0.15)") if is_dark else QColor("rgba(239, 68, 68, 0.10)")
                border_color = QColor("#EF4444")
                text_color = QColor("#F87171") if is_dark else QColor("#DC2626")
                dot_color = QColor("#EF4444")

            if self.is_star:
                txt = f"{int(self.latency_ms)} ms [优选]"
            else:
                txt = f"{int(self.latency_ms)} ms"

        # 胶囊外框
        rect = QRectF(1, 1, w - 2, h - 2)
        painter.setPen(QPen(border_color, 1))
        painter.setBrush(QBrush(bg_color))
        painter.drawRoundedRect(rect, h / 2.0, h / 2.0)

        # 状态小圆点
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(dot_color))
        painter.drawEllipse(QRectF(8, (h - 6) / 2.0, 6, 6))

        # 文字
        painter.setPen(text_color)
        font = QFont("Segoe UI", 9, QFont.Bold)
        painter.setFont(font)
        painter.drawText(QRectF(18, 0, w - 22, h), Qt.AlignCenter, txt)
        painter.end()


# ==============================================================================
# 7. CDN 测速骨架屏卡片 (SkeletonCard)
# ==============================================================================
class SkeletonCard(QFrame):
    """
    骨架屏占位卡片
    在测速或异步加载过程中提供渐变流动动效
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(64)
        self.setProperty("class", "MDCard")
        self._offset = 0.0

        self.timer = QTimer(self)
        ThemeManager.get_instance().theme_changed.connect(self.update)
        self.timer.timeout.connect(self._step_animation)
        self.timer.start(30)

    def showEvent(self, event):
        if not self.timer.isActive():
            self.timer.start(30)
        super().showEvent(event)

    def hideEvent(self, event):
        if self.timer.isActive():
            self.timer.stop()
        super().hideEvent(event)

    def _step_animation(self):
        self._offset = (self._offset + 0.03) % 2.0
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = float(self.width())
        h = float(self.height())

        # 卡片底色
        is_dark = ThemeManager.get_instance().is_dark
        painter.setPen(QPen(QColor("#1E283E") if is_dark else QColor("#E2E8F0"), 1))
        painter.setBrush(QBrush(QColor("#141A28") if is_dark else QColor("#F8FAFC")))
        painter.drawRoundedRect(QRectF(0, 0, w, h), 12, 12)

        # 扫掠渐变
        grad = QLinearGradient(0, 0, w, 0)
        p0 = max(0.0, min(1.0, self._offset - 0.4))
        p1 = max(0.0, min(1.0, self._offset))
        p2 = max(0.0, min(1.0, self._offset + 0.4))

        base_color = QColor("#141A28") if is_dark else QColor("#F1F5F9")
        highlight_color = QColor("#27344E") if is_dark else QColor("#FFFFFF")
        grad.setColorAt(0.0, base_color)
        if 0.0 <= p0 < 1.0:
            grad.setColorAt(p0, base_color)
        if 0.0 <= p1 <= 1.0:
            grad.setColorAt(p1, highlight_color)
        if 0.0 < p2 <= 1.0:
            grad.setColorAt(p2, base_color)
        grad.setColorAt(1.0, base_color)

        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(grad))
        # 骨架占位条
        painter.drawRoundedRect(QRectF(16, 16, w * 0.45, 14), 4, 4)
        painter.drawRoundedRect(QRectF(16, 38, w * 0.25, 10), 4, 4)
        painter.drawRoundedRect(QRectF(w - 120, 22, 100, 20), 10, 10)

        painter.end()
