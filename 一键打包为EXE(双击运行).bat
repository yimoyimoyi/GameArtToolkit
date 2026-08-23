@echo off
:: 指定控制台与语言环境编码，避免在多语言或不同 Windows 环境下报错
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
set LANG=zh_CN.UTF-8
set LC_ALL=zh_CN.UTF-8

title GameArt Toolkit - 打包为 EXE
cd /d "%~dp0"

echo ========================================================
echo   正在打包编译 PySide6 桌面应用 (内置 UAC 管理员清单)...
echo ========================================================
python build.py
echo.
echo 打包结束，按任意键打开发布目录...
pause >nul
if exist "%~dp0dist\GameArtToolkit" (
    start explorer "%~dp0dist\GameArtToolkit"
)
