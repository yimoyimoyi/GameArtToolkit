# -*- coding: utf-8 -*-
"""
PixivToolkit - 平面化风格应用图标生成器
生成与内置托盘保持一致的平面化 (Flat) 图标，支持导出 16x16 至 256x256 全尺寸 Windows ICO 与 PNG
"""

import sys
from pathlib import Path
from PySide6.QtGui import QGuiApplication, QImage, QPainter, QColor, QFont
from PySide6.QtCore import Qt, QRectF
from PIL import Image

BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = BASE_DIR / "app"

def generate_flat_icon(size: int = 512, bg_hex: str = "#0284C7") -> Image.Image:
    """生成平面化风格应用图标 (圆角矩形纯色底座 + 白色大写 P)"""
    _app = QGuiApplication.instance() or QGuiApplication(sys.argv)

    image = QImage(size, size, QImage.Format_ARGB32_Premultiplied)
    image.fill(Qt.transparent)

    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setRenderHint(QPainter.SmoothPixmapTransform)
    painter.setRenderHint(QPainter.TextAntialiasing)

    # 平面化圆角矩形底座
    margin = size * 0.06
    rect = QRectF(margin, margin, size - 2 * margin, size - 2 * margin)
    radius = size * 0.22

    painter.setBrush(QColor(bg_hex))
    painter.setPen(Qt.NoPen)
    painter.drawRoundedRect(rect, radius, radius)

    # 居中纯白大写字母 P
    painter.setPen(QColor("#FFFFFF"))
    font_size = int(size * 0.58)
    font = QFont("Segoe UI", font_size, QFont.Bold)
    font.setStyleStrategy(QFont.PreferAntialias)
    painter.setFont(font)

    text_rect = rect.adjusted(0, -size * 0.02, 0, 0)
    painter.drawText(text_rect, Qt.AlignCenter, "P")
    painter.end()

    ptr = image.bits()
    pil_img = Image.frombuffer("RGBA", (size, size), ptr, "raw", "BGRA", 0, 1)
    return pil_img

def ensure_icons():
    """生成并保存图标到 app 目录与根目录"""
    APP_DIR.mkdir(parents=True, exist_ok=True)
    
    png_path = APP_DIR / "icon.png"
    ico_path = APP_DIR / "icon.ico"
    
    img = generate_flat_icon(512, "#0284C7")
    img.save(str(png_path), format="PNG")
    
    # 导出包含 Windows 各级分辨率的标准 ICO
    ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(str(ico_path), format="ICO", sizes=ico_sizes)
    print(f"[Icon] 平面化应用图标已生成: {ico_path}")
    return ico_path, png_path

if __name__ == "__main__":
    ensure_icons()
