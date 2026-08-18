
@echo off
chcp 65001 >nul
title PixivToolkit 桌面客户端
cd /d "%~dp0"

:: 优先使用无黑框控制台的 pythonw 静默启动应用程序
where pythonw >nul 2>&1
if %errorLevel% equ 0 (
    start "" pythonw app\pyside_app.py %*
    exit /b 0
)

:: 兜底使用标准 python (自动隐藏控制台)
where python >nul 2>&1
if %errorLevel% equ 0 (
    start "" python app\pyside_app.py %*
    exit /b 0
)

echo ========================================================
echo   [错误] 未检测到 Python 运行环境！
echo   请确保已安装 Python 3.10+ 并将其勾选添加到系统 PATH 环境变量。
echo ========================================================
echo.
pause
exit /b 1
