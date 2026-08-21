@echo off
chcp 65001 >nul
title GameArt Toolkit - Windows Release 一键打包
cd /d "%~dp0"

echo ========================================================
echo   正在执行 GameArt Toolkit Windows Release 完整打包...
echo ========================================================
python build.py

echo.
echo 打包流程结束，按任意键打开发布目录...
pause >nul
if exist "%~dp0dist" (
    start explorer "%~dp0dist"
)
