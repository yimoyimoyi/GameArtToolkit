
@echo off
chcp 65001 >nul
title PixivToolkit - 安全清理 Hosts
cd /d "%~dp0.."

echo ========================================================
echo   正在从系统 Hosts 中清理 PixivToolkit 加速规则...
echo ========================================================
python -c "import sys; sys.path.insert(0, 'app'); from hosts_manager import HostsManager; ok, msg = HostsManager().remove_rules(); print(msg)"
pause
