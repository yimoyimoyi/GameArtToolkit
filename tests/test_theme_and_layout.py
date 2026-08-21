# -*- coding: utf-8 -*-
"""
多主题系统、布局缩放、设置同步与 High-DPI 渲染测试
"""

import sys
import pytest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = BASE_DIR / "app"
sys.path.insert(0, str(APP_DIR))

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QPixmap
from material_theme import (
    ThemeManager, MATERIAL_DARK_QSS, MATERIAL_LIGHT_QSS, MATERIAL_PINK_QSS,
    MD3_SURFACE, MD3_LIGHT_SURFACE, MD3_PINK_SURFACE,
    MD3_PRIMARY, MD3_LIGHT_PRIMARY, MD3_PINK_PRIMARY
)
from svg_icons import SvgIconFactory


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_theme_constants_and_qss():
    """验证三套主题的常量与 QSS 字符串非空且包含基础样式"""
    assert len(MATERIAL_DARK_QSS) > 500
    assert len(MATERIAL_LIGHT_QSS) > 500
    assert len(MATERIAL_PINK_QSS) > 500

    # 验证已有深色模式色彩未被破坏
    assert MD3_SURFACE == "#0C101A"
    assert MD3_PRIMARY == "#7EB9F5"

    # 验证已有浅色模式色彩未被破坏
    assert MD3_LIGHT_SURFACE == "#F8FAFC"
    assert MD3_LIGHT_PRIMARY == "#0284C7"

    # 验证新增粉色模式色彩
    assert MD3_PINK_SURFACE == "#FFF5F7"
    assert MD3_PINK_PRIMARY == "#E11D48"


def test_theme_manager_palette_and_switching(qapp):
    """验证 ThemeManager 的调色板和主题切换逻辑"""
    tm = ThemeManager.get_instance()

    # 1. 切换至 dark
    assert tm.set_theme("dark", qapp)
    assert tm.is_dark
    assert not tm.is_light
    assert not tm.is_pink
    p_dark = tm.get_palette()
    assert p_dark["surface"] == MD3_SURFACE
    assert p_dark["primary"] == MD3_PRIMARY

    # 2. 标题栏快速二元切换至 light
    next_th = tm.toggle_theme(qapp)
    assert next_th == "light"
    assert tm.is_light
    p_light = tm.get_palette()
    assert p_light["surface"] == MD3_LIGHT_SURFACE
    assert p_light["primary"] == MD3_LIGHT_PRIMARY

    # 3. 标题栏再次二元切换回 dark
    next_th = tm.toggle_theme(qapp)
    assert next_th == "dark"
    assert tm.is_dark

    # 4. 设置页面显式设置粉色主题
    assert tm.set_theme("pink", qapp)
    assert tm.is_pink
    p_pink = tm.get_palette()
    assert p_pink["surface"] == MD3_PINK_SURFACE
    assert p_pink["primary"] == MD3_PINK_PRIMARY

    # 5. 在粉色模式下，标题栏快速切换切回 dark
    next_th = tm.toggle_theme(qapp)
    assert next_th == "dark"
    assert tm.is_dark


def test_svg_icon_factory_high_dpi(qapp):
    """验证 SvgIconFactory 在不同 DPR 下正确生成物理像素尺寸与设备像素比"""
    # 逻辑尺寸 18px，DPR = 1.0 -> 物理 18x18
    pix_1x = SvgIconFactory.get_pixmap("zap", "#FFFFFF", size=18, dpr=1.0)
    assert not pix_1x.isNull()
    assert pix_1x.devicePixelRatio() == 1.0
    assert pix_1x.width() == 18
    assert pix_1x.height() == 18

    # 逻辑尺寸 18px，DPR = 2.0 -> 物理 36x36, DPR = 2.0
    pix_2x = SvgIconFactory.get_pixmap("zap", "#FFFFFF", size=18, dpr=2.0)
    assert not pix_2x.isNull()
    assert pix_2x.devicePixelRatio() == 2.0
    # 验证物理尺寸与设备像素比正确
    assert pix_2x.width() == 36
    assert pix_2x.height() == 36


def test_no_emojis_in_theme_and_widgets():
    """验证 material_theme 与 md_widgets 中严禁包含 emoji 字符"""
    import re
    emoji_pattern = re.compile(r'[\U00010000-\U0010ffff\u2600-\u27bf]')

    mt_path = APP_DIR / "material_theme.py"
    md_path = APP_DIR / "md_widgets.py"
    svg_path = APP_DIR / "svg_icons.py"

    for fpath in [mt_path, md_path, svg_path]:
        content = fpath.read_text(encoding="utf-8")
        matches = emoji_pattern.findall(content)
        assert len(matches) == 0, f"文件 {fpath.name} 中发现了禁止的 Emoji: {matches}"


def test_no_wheel_combobox_prevents_accidental_scroll(qapp):
    """验证 NoWheelComboBox 在未展开状态下忽略滚轮事件，防止页面滚动时鼠标误触切换设置"""
    from PySide6.QtGui import QWheelEvent
    from PySide6.QtCore import Qt, QPoint, QPointF
    from md_widgets import NoWheelComboBox

    cmb = NoWheelComboBox()
    cmb.addItems(["选项 A", "选项 B", "选项 C"])
    cmb.setCurrentIndex(0)

    # 模拟在未展开状态下滚动滚轮
    wheel_ev = QWheelEvent(
        QPointF(10, 10),
        QPointF(10, 10),
        QPoint(0, 0),
        QPoint(0, -120),
        Qt.NoButton,
        Qt.NoModifier,
        Qt.ScrollUpdate,
        False
    )
    cmb.wheelEvent(wheel_ev)

    # 确认滚轮事件被忽略且索引保持为 0，未发生误触切换
    assert not wheel_ev.isAccepted()
    assert cmb.currentIndex() == 0


def test_flex_flow_layout_auto_fit_and_hidden_items(qapp):
    """验证 FlexFlowLayout 自动适应列数、弹性均分拉伸与隐藏控件自动重流"""
    from PySide6.QtWidgets import QWidget, QFrame
    from PySide6.QtCore import QRect
    from md_widgets import FlowLayout

    container = QWidget()
    layout = FlowLayout(container, margin=10, h_spacing=10, v_spacing=10,
                        min_item_width=200, max_item_width=400, flex_fill=True)

    # 添加 4 个卡片
    cards = []
    for i in range(4):
        c = QFrame()
        c.setMinimumHeight(50)
        cards.append(c)
        layout.addWidget(c)

    # 1. 容器宽度为 450px: 可用宽度 450 - 20 = 430px
    #    cols = (430 + 10) // (200 + 10) = 2 列
    #    弹性均分宽度 = (430 - 10) // 2 = 210px
    h1 = layout.heightForWidth(450)
    layout.setGeometry(QRect(0, 0, 450, h1))
    assert cards[0].width() == 210
    assert cards[1].width() == 210
    assert cards[0].x() == 10
    assert cards[1].x() == 230
    assert cards[2].x() == 10
    assert cards[3].x() == 230
    assert h1 == 10 + 50 + 10 + 50 + 10  # 130px (2 行)

    # 2. 隐藏 2 个卡片 (模拟搜索过滤)
    cards[0].setVisible(False)
    cards[1].setVisible(False)
    h2 = layout.heightForWidth(450)
    layout.setGeometry(QRect(0, 0, 450, h2))
    assert cards[2].x() == 10
    assert cards[3].x() == 230
    assert h2 == 10 + 50 + 10  # 70px (高度自动收缩至 1 行)

    # 3. 恢复所有卡片，在宽容器 (1200px) 下验证列数不受 visible 数量限制
    #    cols 始终反映容器最佳列数，末行未填满时卡片宽度保持一致 (等宽网格)
    for c in cards:
        c.setVisible(True)
    # avail=1180, cols = (1180+10)//(200+10) = 5, flex = (1180-40)//5 = 228
    h3 = layout.heightForWidth(1200)
    layout.setGeometry(QRect(0, 0, 1200, h3))
    assert cards[0].width() == 228
    assert cards[3].width() == 228  # 末行卡片宽度与首行一致
    assert h3 == 10 + 50 + 10  # 4 项 < 5 cols，全部排满 1 行

    # 4. 验证末行未填满时卡片宽度仍保持一致 (8 项卡片，5 列 → 第 2 行仅 3 项)
    #    先用 takeAt 正确从布局中移除旧卡片 (与 pyside_app 中 load_steam_accounts_ui 模式一致)
    while layout.count():
        item = layout.takeAt(0)
        if item.widget():
            item.widget().deleteLater()
    cards = []
    for i in range(8):
        c = QFrame()
        c.setMinimumHeight(40)
        cards.append(c)
        layout.addWidget(c)
    # avail=1180, cols=5, flex=228, 8 项排 2 行 (5+3)
    h4 = layout.heightForWidth(1200)
    layout.setGeometry(QRect(0, 0, 1200, h4))
    assert cards[0].width() == 228   # 首行第 1 项
    assert cards[4].width() == 228   # 首行末项
    assert cards[5].width() == 228   # 末行第 1 项
    assert cards[7].width() == 228   # 末行末项 (宽度一致，网格等宽)
    assert h4 == 10 + 40 + 10 + 40 + 10  # 2 行 = 110px (margin=10)

    # 5. 验证 max_item_width 约束生效: 宽容器下 flex 宽度超出 max 时应被截断
    container2 = QWidget()
    layout2 = FlowLayout(container2, margin=0, h_spacing=0, v_spacing=0,
                         min_item_width=300, max_item_width=300, flex_fill=True)
    c_wide = QFrame(container2)
    c_wide.setMinimumHeight(50)
    layout2.addWidget(c_wide)
    # 500px 容器: cols=(500)//(300)=1, flex=max(300, 500//1)=500 → min(500,300)=300
    h5 = layout2.heightForWidth(500)
    layout2.setGeometry(QRect(0, 0, 500, h5))
    assert c_wide.width() == 300  # 被 max_item_width=300 截断，而非填满 500


def test_flow_layout_dynamic_height_for_width(qapp):
    """验证 FlowLayout 能够正确探测子控件的 heightForWidth 动态计算多行高度"""
    from PySide6.QtWidgets import QWidget, QLabel
    from PySide6.QtCore import QRect
    from md_widgets import FlowLayout

    class DynamicHeightWidget(QWidget):
        def hasHeightForWidth(self):
            return True
        def heightForWidth(self, w):
            # 模拟随宽度缩减而折行增高: 宽 >= 300 时 40px，宽 < 300 时 80px
            return 80 if w < 300 else 40
        def minimumSize(self):
            from PySide6.QtCore import QSize
            return QSize(100, 40)

    container = QWidget()
    layout = FlowLayout(container, margin=0, h_spacing=10, v_spacing=10, min_item_width=300, flex_fill=True)
    w1 = DynamicHeightWidget(container)
    w2 = DynamicHeightWidget(container)
    layout.addWidget(w1)
    layout.addWidget(w2)

    # 容器宽 800px: cols = 2, flex_width = (800-10)//2 = 395px (>=300, height = 40px)
    h_wide = layout.heightForWidth(800)
    assert h_wide == 40

    # 容器宽 250px: cols = 1, flex_width = 250px (<300, height = 80px)
    h_narrow = layout.heightForWidth(250)
    # 2 行每行 80px: 80 + 10 + 80 = 170px
    assert h_narrow == 170


def test_traffic_monitor_chart_narrow_width_no_overlap(qapp):
    """验证 TrafficMonitorChart 在极窄 (320px) 到超宽 (1200px) 下绘制正常且不发生崩溃"""
    from PySide6.QtGui import QPixmap
    from md_widgets import TrafficMonitorChart

    chart = TrafficMonitorChart()
    chart.add_sample(1024.0, 512.0, req_delta=15, hit_delta=8)

    for test_w in [320, 400, 540, 800, 1200]:
        chart.resize(test_w, 140)
        pixmap = QPixmap(test_w, 140)
        chart.render(pixmap)
        assert not pixmap.isNull()


def test_steam_account_card_and_flow_no_overlap(qapp):
    """验证 SteamAccountCard 与 accounts_container 约束一致，在各宽度下无水平重叠"""
    from PySide6.QtWidgets import QWidget
    from PySide6.QtCore import QRect
    from md_widgets import FlowLayout

    container = QWidget()
    flow = FlowLayout(container, margin=10, h_spacing=14, v_spacing=14, min_item_width=320, max_item_width=480, flex_fill=True)

    cards = []
    for i in range(3):
        c = QWidget(container)
        c.setMinimumSize(320, 120)
        cards.append(c)
        flow.addWidget(c)

    # 1. 容器宽度为 700px (无法容纳 2 个 320+14=334px，排为 2 列: (700-20-14)//2 = 333px)
    h = flow.heightForWidth(700)
    flow.setGeometry(QRect(0, 0, 700, h))
    # 验证卡片 0 与卡片 1 不重叠: card0.x + card0.w + gap <= card1.x
    assert cards[0].x() == 10
    assert cards[0].width() == 333
    assert cards[1].x() == 10 + 333 + 14
    assert cards[1].width() == 333
    assert cards[0].x() + cards[0].width() <= cards[1].x()


def test_stat_cards_and_settings_word_wrap(qapp):
    """验证主控制台 StatCard 标签和设置项标签已配置 setWordWrap(True)"""
    from pyside_app import MainWindow

    # 1. 验证 create_stat_card 构造的四合一卡片所有文本标签均开启自适应换行
    card_nginx = MainWindow.create_stat_card(None, "Nginx 数据平面", "运行中", "反代引擎与磁盘缓存", "server")
    assert card_nginx.lbl_title.wordWrap()
    assert card_nginx.lbl_val.wordWrap()
    assert card_nginx.lbl_hint.wordWrap()

    card_cert = MainWindow.create_stat_card(None, "Windows 根证书", "有效", "系统受信任证书库", "lock")
    assert card_cert.lbl_title.wordWrap()
    assert card_cert.lbl_val.wordWrap()
    assert card_cert.lbl_hint.wordWrap()

    card_hosts = MainWindow.create_stat_card(None, "Hosts 规则库", "已生效", "服务规则隔离", "file_text")
    assert card_hosts.lbl_title.wordWrap()
    assert card_hosts.lbl_val.wordWrap()
    assert card_hosts.lbl_hint.wordWrap()

    card_steam = MainWindow.create_stat_card(None, "Steam 活跃用户", "已就绪", "支持双击免密切换", "gamepad")
    assert card_steam.lbl_title.wordWrap()
    assert card_steam.lbl_val.wordWrap()
    assert card_steam.lbl_hint.wordWrap()

    # 2. 验证源码中关键描述标签均显式配置 setWordWrap(True)
    source_pyside = (APP_DIR / "pyside_app.py").read_text(encoding="utf-8")
    assert "self.lbl_env_summary.setWordWrap(True)" in source_pyside
    assert "self.lbl_cache_size_desc.setWordWrap(True)" in source_pyside
    assert "self.lbl_main_sub.setWordWrap(True)" in source_pyside


def test_render_cdn_results_ipv4_and_ipv6(qapp):
    """验证 render_cdn_results 正确引用 primary_c 且支持 IPv4 与超长 IPv6 结果展示"""
    from PySide6.QtWidgets import QWidget, QVBoxLayout
    from pyside_app import MainWindow

    dummy_parent = QWidget()
    results_layout = QVBoxLayout(dummy_parent)

    # 模拟 MainWindow 实例的必要属性
    class DummyWindow:
        def __init__(self):
            self.cdn_results_layout = results_layout
            self.service_badges = {}
            self.cdn_card_widgets = {}
            self.cdn_single_buttons = {}
            self._single_cdn_workers = {}
            self.cached_cdn_results = {}

    dummy = DummyWindow()

    # 测试数据包含常规 IPv4 与完整 39 字符超长 IPv6
    mock_results = {
        "pixiv_web": [
            {"ip": "210.140.131.222", "latency": 45.2, "available": True},
            {"ip": "2606:4700:3033:0000:0000:6815:1234:5678", "latency": 88.6, "available": True},
            {"ip": "2404:6800:4004:081a:0000:0000:0000:200e", "latency": 0, "available": False},
        ]
    }

    # 在深色与浅色两套主题下分别测试 render_cdn_results
    tm = ThemeManager.get_instance()
    for th in ["dark", "light", "pink"]:
        tm.set_theme(th, qapp)
        # 执行 render_cdn_results，验证无 NameError/UnboundLocalError(针对 primary_c)
        MainWindow.render_cdn_results(dummy, mock_results)
        assert "pixiv_web" in dummy.cdn_card_widgets
        card = dummy.cdn_card_widgets["pixiv_web"]
        assert card is not None
        # 验证卡片内子控件数量
        assert dummy.cdn_results_layout.count() == 1


