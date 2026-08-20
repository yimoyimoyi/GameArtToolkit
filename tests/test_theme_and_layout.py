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
