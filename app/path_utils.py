# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 路径解析与运行环境工具模块 (统一适配源码与 PyInstaller 打包目录)
"""

import sys
from pathlib import Path

def get_base_dir() -> Path:
    """获取程序根运行目录（兼容源码开发与 PyInstaller 打包环境）"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent

BASE_DIR = get_base_dir()
APP_DIR = Path(__file__).resolve().parent
NGINX_DIR = BASE_DIR / "nginx"
CONFIG_PATH = BASE_DIR / "config.json"
BACKUP_DIR = BASE_DIR / "backups"
HOSTS_BACKUP_DIR = BACKUP_DIR / "hosts"
