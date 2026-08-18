
@echo off
chcp 65001 >nul
title PixivToolkit Web 控制台
cd /d "%~dp0"

echo ========================================================
echo   正在启动 PixivToolkit 服务控制台...
echo ========================================================
python app\main.py
if %errorLevel% neq 0 (
    echo.
    pause
)
