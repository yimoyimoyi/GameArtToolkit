@echo off
:: 指定控制台与语言环境编码，避免在多语言或不同 Windows 环境下报错
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
set LANG=zh_CN.UTF-8
set LC_ALL=zh_CN.UTF-8

title GameArt Toolkit - 安装根证书
cd /d "%~dp0.."

:: 检查并自动请求管理员权限
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [提示] 正在请求管理员权限以导入根证书...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ========================================================
echo   正在向系统导入受信任根证书...
echo ========================================================
python -c "import sys; sys.path.insert(0, 'app'); from cert_manager import CertManager; ok, msg = CertManager().install_cert(); print(msg)"
pause
