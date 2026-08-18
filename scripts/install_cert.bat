
@echo off
chcp 65001 >nul
title PixivToolkit - 一键安装根证书
cd /d "%~dp0.."

echo ========================================================
echo   正在向系统导入受信任根证书...
echo ========================================================
python -c "import sys; sys.path.insert(0, 'app'); from cert_manager import CertManager; ok, msg = CertManager().install_cert(); print(msg)"
pause
