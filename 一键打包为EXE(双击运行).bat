@echo off
chcp 65001 >nul
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
