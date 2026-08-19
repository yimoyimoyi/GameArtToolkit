# -*- coding: utf-8 -*-
"""
GameArt Toolkit - Material Design 3 调色板与桌面 QSS 样式系统
提供:
1. MD3 Tonal Elevation 层级色彩常量与语义定义
2. 无边框标题栏 (TitleBar) 与 Windows 窗口控制按钮规范
3. 悬浮非阻塞通知 (MD3 Toast / Snackbar) 视觉容器
4. 原位编辑 (Inline Edit) 与微徽章样式
5. 空态 (Empty State) 与骨架屏 (Skeleton Screen) 样式
6. 阶梯式 8dp 网格与圆角系统规范
"""

# Material Design 3 暗色调色板常量定义 (Pixiv Soft Blue & Obsidian Dark)
from PySide6.QtCore import QObject, Signal

MD3_SURFACE = "#0C101A"
MD3_SURFACE_DIM = "#080B12"
MD3_SURFACE_CONTAINER_LOWEST = "#0F1420"
MD3_SURFACE_CONTAINER_LOW = "#141A28"
MD3_SURFACE_CONTAINER = "#182032"
MD3_SURFACE_CONTAINER_HIGH = "#1E283E"
MD3_SURFACE_CONTAINER_HIGHEST = "#27344E"

MD3_PRIMARY = "#7EB9F5"               # 柔和清新电光蓝
MD3_ON_PRIMARY = "#002E5C"
MD3_PRIMARY_CONTAINER = "#1D3B66"
MD3_ON_PRIMARY_CONTAINER = "#CFE5FF"

MD3_SECONDARY = "#94A3B8"
MD3_SECONDARY_CONTAINER = "#1E293B"
MD3_ON_SECONDARY_CONTAINER = "#E2E8F0"

MD3_TERTIARY = "#56C2E6"              # 柔和数字青
MD3_TERTIARY_CONTAINER = "#0D5170"

MD3_SUCCESS = "#34D399"
MD3_SUCCESS_CONTAINER = "#059669"
MD3_SUCCESS_BG = "rgba(16, 185, 129, 0.15)"

MD3_WARNING = "#FBBF24"
MD3_WARNING_CONTAINER = "#D97706"
MD3_WARNING_BG = "rgba(245, 158, 11, 0.15)"

MD3_ERROR = "#F87171"
MD3_ERROR_CONTAINER = "#DC2626"
MD3_ERROR_BG = "rgba(239, 68, 68, 0.15)"

MD3_OUTLINE = "#273752"
MD3_OUTLINE_VARIANT = "#1A2538"
MD3_TEXT_PRIMARY = "#F1F5F9"
MD3_TEXT_SECONDARY = "#CBD5E1"
MD3_TEXT_MUTED = "#75879E"

MATERIAL_DARK_QSS = """
/* ==========================================================================
   全局基础重置与深色基底 (Surface - Obsidian Dark)
   ========================================================================== */
QWidget#CentralWidget, QWidget#ScrollContent, QWidget#AppRootWidget {
    background-color: #0C101A;
    color: #F1F5F9;
    font-family: "Segoe UI", "Microsoft YaHei", -apple-system, sans-serif;
    font-size: 13px;
}

QMainWindow {
    background-color: #0C101A;
}

/* 提示气泡 ToolTip */
QToolTip {
    background-color: #182032;
    color: #F1F5F9;
    border: 1px solid #273752;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
}

/* ==========================================================================
   无边框标题栏 (TitleBar)
   ========================================================================== */
QFrame#TitleBar {
    background-color: #0C101A;
    border-bottom: 1px solid #141A28;
    min-height: 38px;
    max-height: 38px;
}

QLabel#TitleBrand {
    color: #7EB9F5;
    font-size: 13px;
    font-weight: bold;
    letter-spacing: 0.5px;
}

QLabel#TitleBadge {
    background-color: #1E283E;
    color: #CFE5FF;
    font-size: 10px;
    font-weight: bold;
    border-radius: 6px;
    padding: 2px 6px;
}

QLabel#TitleStatusPill {
    background-color: rgba(52, 211, 153, 0.12);
    color: #34D399;
    border: none;
    border-radius: 11px;
    padding: 2px 10px;
    font-size: 11px;
    font-weight: 500;
}

/* 标题栏主题切换按钮 (ThemeToggleBtn) */
QPushButton[class="ThemeToggleBtn"] {
    background-color: transparent;
    border: none;
    border-radius: 8px;
    min-width: 36px;
    max-width: 36px;
    min-height: 32px;
    max-height: 32px;
    margin: 3px 2px;
}

QPushButton[class="ThemeToggleBtn"]:hover {
    background-color: rgba(126, 185, 245, 0.15);
}

QPushButton[class="ThemeToggleBtn"]:pressed {
    background-color: rgba(126, 185, 245, 0.25);
}

/* 窗口最小化、最大化按钮 (WindowControlBtn) - Fluent 46x38 规范 */
QPushButton[class="WindowControlBtn"] {
    background-color: transparent;
    border: none;
    min-width: 46px;
    max-width: 46px;
    min-height: 38px;
    max-height: 38px;
    padding: 0px;
    margin: 0px;
}

QPushButton[class="WindowControlBtn"]:hover {
    background-color: rgba(255, 255, 255, 0.08);
}

QPushButton[class="WindowControlBtn"]:pressed {
    background-color: rgba(255, 255, 255, 0.04);
}

/* 窗口关闭按钮 (WindowCloseBtn) - Fluent 46x38 红底过渡 */
QPushButton[class="WindowCloseBtn"] {
    background-color: transparent;
    border: none;
    min-width: 46px;
    max-width: 46px;
    min-height: 38px;
    max-height: 38px;
    padding: 0px;
    margin: 0px;
}

QPushButton[class="WindowCloseBtn"]:hover {
    background-color: #EF4444;
}

QPushButton[class="WindowCloseBtn"]:pressed {
    background-color: #DC2626;
}

/* ==========================================================================
   滚动区域与滚动条
   ========================================================================== */
QScrollArea#MainScrollArea {
    background: transparent;
    border: none;
}

QScrollBar:vertical {
    background: transparent;
    width: 8px;
    margin: 0px 2px 0px 0px;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background: #1E283E;
    min-height: 32px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background: #27344E;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar::handle:vertical:pressed {
    background: #7EB9F5;
}

QScrollBar:horizontal {
    background: transparent;
    height: 8px;
    margin: 0px 0px 2px 0px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal {
    background: #1E283E;
    min-width: 32px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal:hover {
    background: #27344E;
}

QScrollBar::handle:horizontal:pressed {
    background: #1D3B66;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* ==========================================================================
   侧边导航栏 (NavSidebar)
   ========================================================================== */
QFrame#NavSidebar {
    background-color: #0F1420;
    border-right: 1px solid #182032;
    min-width: 220px;
    max-width: 220px;
}

QLabel#BrandTitle {
    color: #7EB9F5;
    font-size: 18px;
    font-weight: bold;
    letter-spacing: 0.5px;
}

QLabel#BrandSubtitle {
    color: #75879E;
    font-size: 11px;
}

QPushButton[class="NavButton"] {
    background-color: transparent;
    color: #94A3B8;
    border: none;
    border-radius: 12px;
    padding: 10px 14px;
    text-align: left;
    font-size: 13px;
    font-weight: 500;
}

QPushButton[class="NavButton"]:hover {
    background-color: #182032;
    color: #F1F5F9;
}

QPushButton[class="NavButton"]:checked {
    background-color: #1E283E;
    color: #7EB9F5;
    font-weight: bold;
}

/* ==========================================================================
   页面标题与文本排版规范
   ========================================================================== */
QLabel#PageTitle {
    font-size: 22px;
    font-weight: bold;
    color: #F1F5F9;
    margin-bottom: 2px;
}

QLabel#PageDesc {
    font-size: 12px;
    color: #75879E;
    margin-bottom: 12px;
}

/* ==========================================================================
   Material 3 卡片容器体系
   ========================================================================== */
QFrame[class="MDCard"] {
    background-color: #141A28;
    border: 1px solid #1E283E;
    border-radius: 16px;
}

QFrame[class="MDCardHover"]:hover {
    border: 1px solid #273752;
    background-color: #182032;
}

QLabel[class="CategoryTitle"] {
    font-size: 15px;
    font-weight: bold;
    color: #F1F5F9;
}

QLabel[class="CategoryDesc"] {
    font-size: 11px;
    color: #75879E;
}

/* 服务项目单行卡片 */
QFrame[class="ServiceItem"] {
    background-color: #0F1420;
    border: 1px solid #182032;
    border-radius: 10px;
    padding: 8px 12px;
}

QFrame[class="ServiceItem"]:hover {
    border: 1px solid #273752;
    background-color: #182032;
}

/* 顶部指标卡片 */
QFrame[class="StatCard"] {
    background-color: #141A28;
    border: 1px solid #1E283E;
    border-radius: 12px;
}

QLabel[class="StatLabel"] {
    font-size: 11px;
    color: #75879E;
}

QLabel[class="StatValue"] {
    font-size: 16px;
    font-weight: bold;
    color: #F1F5F9;
}

QLabel[class="StatHint"] {
    font-size: 10px;
    color: #64748B;
}

/* ==========================================================================
   Steam 账号卡片体系 (支持双击直切与原位编辑)
   ========================================================================== */
QFrame[class="AccountCard"] {
    background-color: #141A28;
    border: 1px solid #1E283E;
    border-radius: 14px;
}

QFrame[class="AccountCard"]:hover {
    border: 1px solid #273752;
    background-color: #182032;
}

QFrame[class="AccountCardActive"] {
    background-color: rgba(126, 185, 245, 0.10);
    border: 1.5px solid #7EB9F5;
    border-radius: 14px;
}

QLabel[class="AccountName"] {
    font-size: 14px;
    font-weight: bold;
    color: #F1F5F9;
}

QLabel[class="AccountSteamId"] {
    font-size: 11px;
    color: #75879E;
    font-family: "JetBrains Mono", Consolas, monospace;
}

QLabel[class="AccountHint"] {
    font-size: 10px;
    color: #64748B;
}

/* 原位编辑输入框 (Inline Edit) */
QLineEdit[class="InlineEditInput"] {
    background-color: #0F1420;
    color: #F1F5F9;
    border: 1.5px solid #7EB9F5;
    border-radius: 6px;
    padding: 3px 8px;
    font-size: 12px;
    selection-background-color: #1D3B66;
}

QLabel[class="InlineBadge"] {
    background-color: #182032;
    color: #7EB9F5;
    border: 1px solid #273752;
    border-radius: 6px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 500;
}

QLabel[class="InlineBadge"]:hover {
    background-color: #1E283E;
    border-color: #7EB9F5;
    color: #FFFFFF;
}

/* ==========================================================================
   悬浮 Toast / Snackbar 通知系统
   ========================================================================== */
QFrame[class="ToastFrame"] {
    background-color: #182032;
    border: 1px solid #273752;
    border-radius: 12px;
    padding: 6px 14px;
}

QLabel[class="ToastMsg"] {
    color: #F1F5F9;
    font-size: 12px;
    font-weight: 500;
}

QPushButton[class="ToastActionBtn"] {
    background-color: #1E283E;
    color: #CFE5FF;
    border: none;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: bold;
}

QPushButton[class="ToastActionBtn"]:hover {
    background-color: #27344E;
    color: #FFFFFF;
}

QPushButton[class="ToastCloseBtn"] {
    background-color: transparent;
    color: #75879E;
    border: none;
    font-size: 13px;
    min-width: 20px;
    max-width: 20px;
}

QPushButton[class="ToastCloseBtn"]:hover {
    color: #F1F5F9;
}

/* ==========================================================================
   空态卡片 (Empty State) 与骨架屏
   ========================================================================== */
QFrame[class="EmptyStateCard"] {
    background-color: #141A28;
    border: 1px dashed #273752;
    border-radius: 16px;
    padding: 32px 24px;
}

QLabel[class="EmptyStateTitle"] {
    font-size: 16px;
    font-weight: bold;
    color: #F1F5F9;
}

QLabel[class="EmptyStateDesc"] {
    font-size: 12px;
    color: #75879E;
    line-height: 1.5;
}

/* ==========================================================================
   按钮体系 (Buttons)
   ========================================================================== */
QPushButton[class="MDBtnPrimary"] {
    background-color: #7EB9F5;
    color: #002E5C;
    border: none;
    border-radius: 10px;
    padding: 9px 18px;
    font-weight: bold;
    font-size: 13px;
}

QPushButton[class="MDBtnPrimary"]:hover {
    background-color: #A6D1FF;
}

QPushButton[class="MDBtnPrimary"]:pressed {
    background-color: #5BA2E6;
}

QPushButton[class="MDBtnStop"] {
    background-color: #EF4444;
    color: #FFFFFF;
    border: none;
    border-radius: 10px;
    padding: 9px 18px;
    font-weight: bold;
    font-size: 13px;
}

QPushButton[class="MDBtnStop"]:hover {
    background-color: #F87171;
}

QPushButton[class="MDBtnStop"]:pressed {
    background-color: #DC2626;
}

QPushButton[class="MDBtnTonal"] {
    background-color: #1E283E;
    color: #CFE5FF;
    border: none;
    border-radius: 8px;
    padding: 7px 14px;
    font-weight: bold;
    font-size: 12px;
}

QPushButton[class="MDBtnTonal"]:hover {
    background-color: #27344E;
}

QPushButton[class="MDBtnTonal"]:pressed {
    background-color: #141A28;
}

QPushButton[class="MDBtnOutlined"] {
    background-color: transparent;
    color: #CBD5E1;
    border: 1px solid #273752;
    border-radius: 8px;
    padding: 6px 12px;
    font-size: 12px;
}

QPushButton[class="MDBtnOutlined"]:hover {
    background-color: #182032;
    color: #FFFFFF;
    border-color: #7EB9F5;
}

QPushButton[class="MDBtnOutlined"]:pressed {
    background-color: #27344E;
}

/* ==========================================================================
   输入框与复选框与菜单
   ========================================================================== */
QLineEdit {
    background-color: #0F1420;
    color: #F1F5F9;
    border: 1px solid #273752;
    border-radius: 8px;
    padding: 7px 12px;
    font-size: 12px;
}

QLineEdit:focus {
    border: 1.5px solid #7EB9F5;
    background-color: #141A28;
}

QRadioButton {
    color: #F1F5F9;
    spacing: 8px;
    font-size: 12px;
}

QRadioButton::indicator {
    width: 16px;
    height: 16px;
    border-radius: 8px;
    border: 1px solid #75879E;
    background-color: transparent;
}

QRadioButton::indicator:checked {
    background-color: #7EB9F5;
    border: 3px solid #141A28;
}

QCheckBox {
    color: #F1F5F9;
    spacing: 8px;
    font-size: 12px;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 1px solid #75879E;
    background-color: transparent;
}

QCheckBox::indicator:checked {
    background-color: #7EB9F5;
    border-color: #7EB9F5;
}

QMenu {
    background-color: #182032;
    border: 1px solid #273752;
    border-radius: 10px;
    padding: 6px 0px;
    color: #F1F5F9;
}

QMenu::item {
    padding: 8px 24px 8px 16px;
    font-size: 12px;
}

QMenu::item:selected {
    background-color: #1E283E;
    color: #FFFFFF;
}

QMenu::separator {
    height: 1px;
    background: #27344E;
    margin: 4px 8px;
}

/* 通用排版与语义文本类 (MD3 规范) */
QLabel[class="MainStatusTitle"] {
    font-size: 17px;
    font-weight: bold;
    color: #F1F5F9;
}

QLabel[class="MainStatusSub"] {
    font-size: 12px;
    color: #75879E;
}

QLabel[class="ItemTitle"] {
    font-size: 13px;
    font-weight: bold;
    color: #F1F5F9;
}

QLabel[class="ItemDesc"] {
    font-size: 11px;
    color: #75879E;
}

QLabel[class="SectionHeaderTitle"] {
    font-size: 14px;
    font-weight: bold;
    color: #F1F5F9;
}

QLabel[class="SectionHeaderDesc"] {
    font-size: 12px;
    color: #75879E;
}

QLabel[class="CdnIpText"] {
    font-family: monospace;
    font-size: 11px;
    color: #F1F5F9;
}

QFrame[class="CdnIpCard"] {
    background-color: #0F1420;
    border: 1px solid #1E283E;
    border-radius: 6px;
    padding: 6px 10px;
}

QFrame[class="CdnIpCardBest"] {
    background-color: rgba(126, 185, 245, 0.12);
    border: 1px solid #7EB9F5;
    border-radius: 6px;
    padding: 6px 10px;
}
"""

# Material Design 3 浅色调色板常量定义
# ==============================================================================
# Material Design 3 浅色调色板常量定义 (Pixiv Soft Blue & Crisp White)
# ==============================================================================
MD3_LIGHT_SURFACE = "#F8FAFC"
MD3_LIGHT_SURFACE_CONTAINER_LOWEST = "#FFFFFF"
MD3_LIGHT_SURFACE_CONTAINER_LOW = "#F1F5F9"
MD3_LIGHT_SURFACE_CONTAINER = "#E2E8F0"
MD3_LIGHT_SURFACE_CONTAINER_HIGH = "#CBD5E1"
MD3_LIGHT_SURFACE_CONTAINER_HIGHEST = "#94A3B8"

MD3_LIGHT_PRIMARY = "#0284C7"         # 柔和清新 Pixiv 蔚蓝
MD3_LIGHT_ON_PRIMARY = "#FFFFFF"
MD3_LIGHT_PRIMARY_CONTAINER = "#E0F2FE"
MD3_LIGHT_ON_PRIMARY_CONTAINER = "#0369A1"

MD3_LIGHT_SECONDARY = "#475569"
MD3_LIGHT_SUCCESS = "#10B981"
MD3_LIGHT_ERROR = "#EF4444"
MD3_LIGHT_WARNING = "#F59E0B"

MD3_LIGHT_TEXT_PRIMARY = "#0F172A"
MD3_LIGHT_TEXT_SECONDARY = "#334155"
MD3_LIGHT_TEXT_MUTED = "#64748B"
MD3_LIGHT_OUTLINE = "#CBD5E1"
MD3_LIGHT_OUTLINE_VARIANT = "#E2E8F0"

MATERIAL_LIGHT_QSS = """
/* ==========================================================================
   全局基础重置与浅色基底 (Surface - Soft Ice Blue 淡冰蓝基调)
   ========================================================================== */
QWidget#CentralWidget, QWidget#ScrollContent, QWidget#AppRootWidget {
    background-color: #EEF5FD;
    color: #0F172A;
    font-family: "Segoe UI", "Microsoft YaHei", -apple-system, sans-serif;
    font-size: 13px;
}

QMainWindow {
    background-color: #EEF5FD;
}

/* 提示气泡 ToolTip */
QToolTip {
    background-color: #E4EFFB;
    color: #0F172A;
    border: 1px solid #BDD8F6;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
}

/* ==========================================================================
   无边框标题栏 (TitleBar)
   ========================================================================== */
QFrame#TitleBar {
    background-color: #EEF5FD;
    border-bottom: 1px solid #D8E8FA;
    min-height: 38px;
    max-height: 38px;
}

QLabel#TitleBrand {
    color: #0284C7;
    font-size: 13px;
    font-weight: bold;
    letter-spacing: 0.5px;
}

QLabel#TitleBadge {
    background-color: #E0F2FE;
    color: #0369A1;
    font-size: 10px;
    font-weight: bold;
    border-radius: 6px;
    padding: 2px 6px;
}

QLabel#TitleStatusPill {
    background-color: rgba(16, 185, 129, 0.12);
    color: #059669;
    border: 1px solid rgba(16, 185, 129, 0.3);
    border-radius: 11px;
    padding: 2px 10px;
    font-size: 11px;
    font-weight: bold;
}

/* 标题栏主题切换按钮 (ThemeToggleBtn) */
QPushButton[class="ThemeToggleBtn"] {
    background-color: transparent;
    border: none;
    border-radius: 8px;
    min-width: 36px;
    max-width: 36px;
    min-height: 32px;
    max-height: 32px;
    margin: 3px 2px;
}

QPushButton[class="ThemeToggleBtn"]:hover {
    background-color: rgba(2, 132, 199, 0.12);
}

QPushButton[class="ThemeToggleBtn"]:pressed {
    background-color: rgba(2, 132, 199, 0.20);
}

/* 窗口最小化、最大化按钮 (WindowControlBtn) - Fluent 46x38 规范 */
QPushButton[class="WindowControlBtn"] {
    background-color: transparent;
    border: none;
    min-width: 46px;
    max-width: 46px;
    min-height: 38px;
    max-height: 38px;
    padding: 0px;
    margin: 0px;
}

QPushButton[class="WindowControlBtn"]:hover {
    background-color: rgba(0, 0, 0, 0.06);
}

QPushButton[class="WindowControlBtn"]:pressed {
    background-color: rgba(0, 0, 0, 0.10);
}

/* 窗口关闭按钮 (WindowCloseBtn) - Fluent 46x38 红底过渡 */
QPushButton[class="WindowCloseBtn"] {
    background-color: transparent;
    border: none;
    min-width: 46px;
    max-width: 46px;
    min-height: 38px;
    max-height: 38px;
    padding: 0px;
    margin: 0px;
}

QPushButton[class="WindowCloseBtn"]:hover {
    background-color: #E81123;
}

QPushButton[class="WindowCloseBtn"]:pressed {
    background-color: #C4101E;
}

/* ==========================================================================
   滚动区域与滚动条
   ========================================================================== */
QScrollArea#MainScrollArea {
    background: transparent;
    border: none;
}

QScrollBar:vertical {
    background: transparent;
    width: 8px;
    margin: 0px 2px 0px 0px;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background: #B8D3F2;
    min-height: 32px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background: #92BDE8;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar::handle:vertical:pressed {
    background: #0284C7;
}

QScrollBar:horizontal {
    background: transparent;
    height: 8px;
    margin: 0px 0px 2px 0px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal {
    background: #B8D3F2;
    min-width: 32px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal:hover {
    background: #92BDE8;
}

QScrollBar::handle:horizontal:pressed {
    background: #0284C7;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* ==========================================================================
   侧边导航栏 (NavSidebar) - 高质感浅霜蓝
   ========================================================================== */
QFrame#NavSidebar {
    background-color: #E4EFFB;
    border-right: 1px solid #D0E2F5;
    min-width: 220px;
    max-width: 220px;
}

QLabel#BrandTitle {
    color: #0284C7;
    font-size: 17px;
    font-weight: bold;
    letter-spacing: 0.5px;
}

QLabel#BrandSubtitle {
    color: #64748B;
    font-size: 11px;
}

QPushButton[class="NavButton"] {
    background-color: transparent;
    color: #334155;
    border: none;
    border-radius: 12px;
    padding: 10px 14px;
    text-align: left;
    font-size: 13px;
    font-weight: 500;
}

QPushButton[class="NavButton"]:hover {
    background-color: #D4E6FA;
    color: #0F172A;
}

QPushButton[class="NavButton"]:checked {
    background-color: #BAE0FD;
    color: #0284C7;
    border: 1px solid #7DD3FC;
    font-weight: bold;
}

/* ==========================================================================
   页面标题与文本排版规范
   ========================================================================== */
QLabel#PageTitle {
    font-size: 22px;
    font-weight: bold;
    color: #0F172A;
    margin-bottom: 2px;
}

QLabel#PageDesc {
    font-size: 12px;
    color: #64748B;
    margin-bottom: 12px;
}

/* ==========================================================================
   Material 3 卡片容器体系
   ========================================================================== */
QFrame[class="MDCard"] {
    background-color: #FFFFFF;
    border: 1px solid #D8E7F8;
    border-radius: 16px;
}

QFrame[class="MDCardHover"]:hover {
    border: 1px solid #C4DCF7;
    background-color: #F9FBFE;
}

QLabel[class="CategoryTitle"] {
    font-size: 15px;
    font-weight: bold;
    color: #0F172A;
}

QLabel[class="CategoryDesc"] {
    font-size: 11px;
    color: #64748B;
}

/* 服务项目单行卡片 */
QFrame[class="ServiceItem"] {
    background-color: #F4F8FD;
    border: 1px solid #D8E7F8;
    border-radius: 10px;
    padding: 8px 12px;
}

QFrame[class="ServiceItem"]:hover {
    border: 1px solid #BDDAF8;
    background-color: #E8F2FD;
}

/* 顶部指标卡片 */
QFrame[class="StatCard"] {
    background-color: #FFFFFF;
    border: 1px solid #D8E7F8;
    border-radius: 12px;
}

QLabel[class="StatLabel"] {
    font-size: 11px;
    color: #64748B;
}

QLabel[class="StatValue"] {
    font-size: 16px;
    font-weight: bold;
    color: #0F172A;
}

QLabel[class="StatHint"] {
    font-size: 10px;
    color: #94A3B8;
}

/* ==========================================================================
   Steam 账号卡片体系 (支持双击直切与原位编辑)
   ========================================================================== */
QFrame[class="AccountCard"] {
    background-color: #FFFFFF;
    border: 1px solid #D8E7F8;
    border-radius: 14px;
}

QFrame[class="AccountCard"]:hover {
    border: 1px solid #BDDAF8;
    background-color: #EBF4FD;
}

QFrame[class="AccountCardActive"] {
    background-color: #D8EEFD;
    border: 1.5px solid #0284C7;
    border-radius: 14px;
}

QLabel[class="AccountName"] {
    font-size: 14px;
    font-weight: bold;
    color: #0F172A;
}

QLabel[class="AccountSteamId"] {
    font-size: 11px;
    color: #64748B;
    font-family: "JetBrains Mono", Consolas, monospace;
}

QLabel[class="AccountHint"] {
    font-size: 10px;
    color: #94A3B8;
}

/* 原位编辑输入框 (Inline Edit) */
QLineEdit[class="InlineEditInput"] {
    background-color: #FFFFFF;
    color: #0F172A;
    border: 1.5px solid #0284C7;
    border-radius: 6px;
    padding: 3px 8px;
    font-size: 12px;
    selection-background-color: #BAE0FD;
}

QLabel[class="InlineBadge"] {
    background-color: #E0F2FE;
    color: #0284C7;
    border: 1px solid #BAE6FD;
    border-radius: 6px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 500;
}

QLabel[class="InlineBadge"]:hover {
    background-color: #BAE6FD;
    border-color: #0284C7;
    color: #0369A1;
}

/* ==========================================================================
   悬浮 Toast / Snackbar 通知系统
   ========================================================================== */
QFrame[class="ToastFrame"] {
    background-color: #FFFFFF;
    border: 1px solid #D8E7F8;
    border-radius: 12px;
    padding: 6px 14px;
}

QLabel[class="ToastMsg"] {
    color: #0F172A;
    font-size: 12px;
    font-weight: 500;
}

QPushButton[class="ToastActionBtn"] {
    background-color: #E0F2FE;
    color: #0284C7;
    border: none;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: bold;
}

QPushButton[class="ToastActionBtn"]:hover {
    background-color: #BAE6FD;
    color: #0369A1;
}

QPushButton[class="ToastCloseBtn"] {
    background-color: transparent;
    color: #64748B;
    border: none;
    font-size: 13px;
    min-width: 20px;
    max-width: 20px;
}

QPushButton[class="ToastCloseBtn"]:hover {
    color: #0F172A;
}

/* ==========================================================================
   空态卡片 (Empty State) 与骨架屏
   ========================================================================== */
QFrame[class="EmptyStateCard"] {
    background-color: #FFFFFF;
    border: 1px dashed #BDD8F6;
    border-radius: 16px;
    padding: 32px 24px;
}

QLabel[class="EmptyStateTitle"] {
    font-size: 16px;
    font-weight: bold;
    color: #0F172A;
}

QLabel[class="EmptyStateDesc"] {
    font-size: 12px;
    color: #64748B;
    line-height: 1.5;
}

/* ==========================================================================
   按钮体系 (Buttons)
   ========================================================================== */
QPushButton[class="MDBtnPrimary"] {
    background-color: #0284C7;
    color: #FFFFFF;
    border: none;
    border-radius: 10px;
    padding: 9px 18px;
    font-weight: bold;
    font-size: 13px;
}

QPushButton[class="MDBtnPrimary"]:hover {
    background-color: #0369A1;
}

QPushButton[class="MDBtnPrimary"]:pressed {
    background-color: #075985;
}

QPushButton[class="MDBtnStop"] {
    background-color: #EF4444;
    color: #FFFFFF;
    border: none;
    border-radius: 10px;
    padding: 9px 18px;
    font-weight: bold;
    font-size: 13px;
}

QPushButton[class="MDBtnStop"]:hover {
    background-color: #F87171;
}

QPushButton[class="MDBtnStop"]:pressed {
    background-color: #DC2626;
}

QPushButton[class="MDBtnTonal"] {
    background-color: #E0F2FE;
    color: #0284C7;
    border: none;
    border-radius: 8px;
    padding: 7px 14px;
    font-weight: bold;
    font-size: 12px;
}

QPushButton[class="MDBtnTonal"]:hover {
    background-color: #BAE6FD;
}

QPushButton[class="MDBtnTonal"]:pressed {
    background-color: #B9E6FE;
}

QPushButton[class="MDBtnOutlined"] {
    background-color: transparent;
    color: #334155;
    border: 1px solid #BDD8F6;
    border-radius: 8px;
    padding: 6px 12px;
    font-size: 12px;
}

QPushButton[class="MDBtnOutlined"]:hover {
    background-color: #E0F0FE;
    color: #0F172A;
    border-color: #0284C7;
}

QPushButton[class="MDBtnOutlined"]:pressed {
    background-color: #BAE0FD;
}

/* ==========================================================================
   输入框与复选框与菜单
   ========================================================================== */
QLineEdit {
    background-color: #FFFFFF;
    color: #0F172A;
    border: 1px solid #BDD8F6;
    border-radius: 8px;
    padding: 7px 12px;
    font-size: 12px;
}

QLineEdit:focus {
    border: 1.5px solid #0284C7;
    background-color: #F8FAFD;
}

QRadioButton {
    color: #0F172A;
    spacing: 8px;
    font-size: 12px;
}

QRadioButton::indicator {
    width: 16px;
    height: 16px;
    border-radius: 8px;
    border: 1px solid #94A3B8;
    background-color: transparent;
}

QRadioButton::indicator:checked {
    background-color: #0284C7;
    border: 3px solid #EEF5FD;
}

QCheckBox {
    color: #0F172A;
    spacing: 8px;
    font-size: 12px;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 1px solid #94A3B8;
    background-color: transparent;
}

QCheckBox::indicator:checked {
    background-color: #0284C7;
    border-color: #0284C7;
}

QMenu {
    background-color: #FFFFFF;
    border: 1px solid #D8E7F8;
    border-radius: 10px;
    padding: 6px 0px;
    color: #0F172A;
}

QMenu::item {
    padding: 8px 24px 8px 16px;
    font-size: 12px;
}

QMenu::item:selected {
    background-color: #E0F2FE;
    color: #0284C7;
}

QMenu::separator {
    height: 1px;
    background: #D8E7F8;
    margin: 4px 8px;
}

/* 通用排版与语义文本类 (MD3 规范) */
QLabel[class="MainStatusTitle"] {
    font-size: 17px;
    font-weight: bold;
    color: #0F172A;
}

QLabel[class="MainStatusSub"] {
    font-size: 12px;
    color: #64748B;
}

QLabel[class="ItemTitle"] {
    font-size: 13px;
    font-weight: bold;
    color: #0F172A;
}

QLabel[class="ItemDesc"] {
    font-size: 11px;
    color: #64748B;
}

QLabel[class="SectionHeaderTitle"] {
    font-size: 14px;
    font-weight: bold;
    color: #0F172A;
}

QLabel[class="SectionHeaderDesc"] {
    font-size: 12px;
    color: #64748B;
}

QLabel[class="CdnIpText"] {
    font-family: monospace;
    font-size: 11px;
    color: #0F172A;
}

QFrame[class="CdnIpCard"] {
    background-color: #F4F8FD;
    border: 1px solid #D8E7F8;
    border-radius: 6px;
    padding: 6px 10px;
}

QFrame[class="CdnIpCardBest"] {
    background-color: #E0F2FE;
    border: 1px solid #0284C7;
    border-radius: 6px;
    padding: 6px 10px;
}
"""

class ThemeManager(QObject):
    theme_changed = Signal(str)

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        super().__init__()
        try:
            from config_store import load_config
            config = load_config()
            self._current_theme = config.get("theme", "dark")
        except Exception:
            self._current_theme = "dark"

    def get_current_theme(self) -> str:
        return self._current_theme

    @property
    def is_dark(self) -> bool:
        return self._current_theme == "dark"

    @property
    def is_light(self) -> bool:
        return self._current_theme == "light"

    def set_theme(self, theme_name: str, app=None) -> bool:
        if theme_name not in ("dark", "light"):
            return False
        
        self._current_theme = theme_name
        
        try:
            from config_store import update_config_key
            update_config_key("theme", theme_name)
        except Exception:
            pass
        
        if app:
            qss = MATERIAL_DARK_QSS if theme_name == "dark" else MATERIAL_LIGHT_QSS
            app.setStyleSheet(qss)
            
        self.theme_changed.emit(theme_name)
        return True

    def toggle_theme(self, app=None) -> str:
        new_theme = "light" if self._current_theme == "dark" else "dark"
        self.set_theme(new_theme, app)
        return new_theme

    def get_palette(self) -> dict:
        if self._current_theme == "dark":
            return {
                "surface": MD3_SURFACE,
                "container": MD3_SURFACE_CONTAINER,
                "primary": MD3_PRIMARY,
                "text": MD3_TEXT_PRIMARY,
                "text_muted": MD3_TEXT_MUTED,
                "outline": MD3_OUTLINE,
                "success": MD3_SUCCESS,
                "error": MD3_ERROR
            }
        else:
            return {
                "surface": MD3_LIGHT_SURFACE,
                "container": MD3_LIGHT_SURFACE_CONTAINER,
                "primary": MD3_LIGHT_PRIMARY,
                "text": MD3_LIGHT_TEXT_PRIMARY,
                "text_muted": MD3_LIGHT_TEXT_MUTED,
                "outline": MD3_LIGHT_OUTLINE,
                "success": MD3_LIGHT_SUCCESS,
                "error": MD3_LIGHT_ERROR
            }

    def get_color(self, color_key: str):
        from PySide6.QtGui import QColor
        palette = self.get_palette()
        color_str = palette.get(color_key, "#000000")
        return QColor(color_str)
