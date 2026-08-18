# -*- coding: utf-8 -*-
"""
生成带有 UTF-8 BOM 编码与 cmd.exe 兼容前缀的批处理脚本 (桌面客户端版)
"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# 1. 桌面客户端双击运行脚本 (无黑框静默拉起)
start_gui_bat = """
@echo off
chcp 65001 >nul
title PixivToolkit 桌面客户端
cd /d "%~dp0"

:: 优先使用无黑框控制台的 pythonw 静默启动应用程序
where pythonw >nul 2>&1
if %errorLevel% equ 0 (
    start "" pythonw app\\pyside_app.py %*
    exit /b 0
)

:: 兜底使用标准 python (自动隐藏控制台)
where python >nul 2>&1
if %errorLevel% equ 0 (
    start "" python app\\pyside_app.py %*
    exit /b 0
)

echo ========================================================
echo   [错误] 未检测到 Python 运行环境！
echo   请确保已安装 Python 3.10+ 并将其勾选添加到系统 PATH 环境变量。
echo ========================================================
echo.
pause
exit /b 1
"""

# 2. 打包为 EXE
build_exe_bat = """
@echo off
chcp 65001 >nul
title PixivToolkit - 打包为 EXE
cd /d "%~dp0"

echo ========================================================
echo   正在打包编译 PySide6 桌面应用 (内置 UAC 管理员清单)...
echo ========================================================
python build.py
echo.
echo 打包结束，按任意键打开发布目录...
pause >nul
if exist "%~dp0dist\\PixivToolkit" (
    start explorer "%~dp0dist\\PixivToolkit"
)
"""

# 3. 辅助清理与安装脚本
clean_hosts_bat = """
@echo off
chcp 65001 >nul
title PixivToolkit - 安全清理 Hosts
cd /d "%~dp0.."

echo ========================================================
echo   正在从系统 Hosts 中清理 PixivToolkit 加速规则...
echo ========================================================
python -c "import sys; sys.path.insert(0, 'app'); from hosts_manager import HostsManager; ok, msg = HostsManager().remove_rules(); print(msg)"
pause
"""

install_cert_bat = """
@echo off
chcp 65001 >nul
title PixivToolkit - 安装根证书
cd /d "%~dp0.."

echo ========================================================
echo   正在向系统导入受信任根证书...
echo ========================================================
python -c "import sys; sys.path.insert(0, 'app'); from cert_manager import CertManager; ok, msg = CertManager().install_cert(); print(msg)"
pause
"""

files = {
    BASE_DIR / "启动桌面客户端(双击运行).bat": start_gui_bat,
    BASE_DIR / "一键打包为EXE(双击运行).bat": build_exe_bat,
    BASE_DIR / "scripts" / "clean_hosts.bat": clean_hosts_bat,
    BASE_DIR / "scripts" / "install_cert.bat": install_cert_bat,
}

for path, content in files.items():
    with open(path, "w", encoding="utf-8-sig") as f:
        f.write(content)

print("所有批处理文件已成功以 UTF-8 with BOM 编码保存并完成 cmd.exe 解析兼容！")
