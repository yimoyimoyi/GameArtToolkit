# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 现代矢量应用与任务栏图标生成器
支持导出 16x16 至 256x256 全尺寸 Windows ICO 与 512x512 高清 PNG
"""

import sys
from pathlib import Path
from PySide6.QtGui import (
    QGuiApplication, QImage, QPainter, QColor, QFont,
    QLinearGradient, QRadialGradient, QPen, QBrush, QPainterPath
)
from PySide6.QtCore import Qt, QRectF, QPointF
from PIL import Image

BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = BASE_DIR / "app"

def generate_gameart_icon(size: int = 512) -> Image.Image:
    """生成 GameArt Toolkit 现代应用主图标 (极光蓝渐变底座 + 游戏艺术双翼矢量徽章)"""
    _app = QGuiApplication.instance() or QGuiApplication(sys.argv)

    image = QImage(size, size, QImage.Format_ARGB32_Premultiplied)
    image.fill(Qt.transparent)

    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setRenderHint(QPainter.SmoothPixmapTransform)
    painter.setRenderHint(QPainter.TextAntialiasing)

    margin = size * 0.05
    rect = QRectF(margin, margin, size - 2 * margin, size - 2 * margin)
    radius = size * 0.22

    # 1. 极光深蓝紫到天蓝多重平滑渐变底座
    grad = QLinearGradient(0, 0, size, size)
    grad.setColorAt(0.0, QColor("#0B132B"))
    grad.setColorAt(0.4, QColor("#1C2541"))
    grad.setColorAt(0.85, QColor("#0284C7"))
    grad.setColorAt(1.0, QColor("#38BDF8"))

    painter.setBrush(QBrush(grad))
    painter.setPen(QPen(QColor(255, 255, 255, 45), size * 0.015))
    painter.drawRoundedRect(rect, radius, radius)

    # 2. 内部顶部光晕
    glow_grad = QRadialGradient(size * 0.5, size * 0.25, size * 0.5)
    glow_grad.setColorAt(0.0, QColor(255, 255, 255, 55))
    glow_grad.setColorAt(1.0, QColor(255, 255, 255, 0))
    painter.setBrush(QBrush(glow_grad))
    painter.setPen(Qt.NoPen)
    painter.drawRoundedRect(rect, radius, radius)

    # 3. 绘制精致 GameArt 科技徽标 (游戏手柄核心 + 极速火箭流线)
    scale = size / 24.0

    # 绘制火箭与流线翼
    rocket_path = QPainterPath()
    # 顶部火箭箭身
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

    # 底部推进动力发光粒子
    fire_path = QPainterPath()
    fire_path.moveTo(10.5 * scale, 18.5 * scale)
    fire_path.lineTo(12.0 * scale, 21.0 * scale)
    fire_path.lineTo(13.5 * scale, 18.5 * scale)
    fire_path.closeSubpath()
    painter.setBrush(QBrush(QColor("#38BDF8")))
    painter.drawPath(fire_path)

    # 绘制游戏手柄按键与十字星光
    painter.setBrush(QBrush(QColor("#0284C7")))
    painter.drawEllipse(QRectF(10.5 * scale, 9.0 * scale, 3.0 * scale, 3.0 * scale))

    # 左右双翼科技流线
    wing_pen = QPen(QColor("#FFFFFF"), size * 0.024, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    painter.setPen(wing_pen)
    painter.setBrush(Qt.NoBrush)
    painter.drawLine(QPointF(5.0 * scale, 11.5 * scale), QPointF(7.0 * scale, 14.5 * scale))
    painter.drawLine(QPointF(19.0 * scale, 11.5 * scale), QPointF(17.0 * scale, 14.5 * scale))

    painter.end()

    ptr = image.bits()
    pil_img = Image.frombuffer("RGBA", (size, size), ptr, "raw", "BGRA", 0, 1)
    return pil_img

def ensure_icons():
    """生成并保存图标到 app 目录与根目录"""
    APP_DIR.mkdir(parents=True, exist_ok=True)
    
    png_path = APP_DIR / "icon.png"
    ico_path = APP_DIR / "icon.ico"
    
    img = generate_gameart_icon(512)
    img.save(str(png_path), format="PNG")
    
    # 导出包含 Windows 各级分辨率的标准 ICO
    ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(str(ico_path), format="ICO", sizes=ico_sizes)
    print(f"[Icon] GameArt Toolkit 应用图标已生成: {ico_path}")
    return ico_path, png_path

if __name__ == "__main__":
    ensure_icons()
