# -*- coding: utf-8 -*-
"""
PixivToolkit - PySide6 Material 客户端 PyInstaller 一键编译与打包脚本 (防占用与环境自愈版)
"""

import os
import sys
import time
import shutil
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def build_exe():
    print("========================================================")
    print("   PixivToolkit (PySide6 Material) 开始编译打包为 EXE")
    print("========================================================")

    dist_dir = BASE_DIR / "dist"
    build_dir = BASE_DIR / "build"
    app_entry = BASE_DIR / "app" / "pyside_app.py"

    # 1. 终止可能正在运行的 Nginx 或 PixivToolkit 进程，防止文件锁定
    print("\n[1/4] 清理正在运行的后台进程与锁文件...")
    subprocess.run("taskkill /F /IM nginx.exe /IM PixivToolkit.exe", shell=True, capture_output=True)
    ps_kill = "Start-Process taskkill -ArgumentList '/F /IM nginx.exe /IM PixivToolkit.exe' -Verb RunAs -Wait"
    try:
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_kill], capture_output=True, timeout=5)
    except Exception:
        pass
    time.sleep(0.5)

    # 2. 清理旧构建目录
    print("[2/4] 清理旧构建目录 (dist/build)...")
    for d in [dist_dir, build_dir]:
        if d.exists():
            for retry in range(3):
                try:
                    shutil.rmtree(d, ignore_errors=False)
                    break
                except Exception as e:
                    time.sleep(0.5)
                    subprocess.run("taskkill /F /IM nginx.exe /IM PixivToolkit.exe", shell=True, capture_output=True)

    # 3. 构造 PyInstaller 指令与图标配置
    icon_file = BASE_DIR / "app" / "icon.ico"
    if not icon_file.exists():
        try:
            sys.path.insert(0, str(BASE_DIR / "scripts"))
            from generate_icon import ensure_icons
            ensure_icons()
        except Exception as e:
            print(f"[WARN] 自动生成图标异常: {e}")

    print("\n[3/4] 调用 PyInstaller 编译 PySide6 应用程序 (集成专属图标与 UAC 管理员清单)...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onedir",
        "--windowed",
        "--uac-admin",
        "--name", "PixivToolkit",
    ]

    if icon_file.exists():
        cmd.append(f"--icon={icon_file}")

    cmd.extend([
        f"--add-data={BASE_DIR / 'app'};app",
        "--clean",
        str(app_entry)
    ])

    print(f"执行命令: {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=str(BASE_DIR))

    if proc.returncode != 0:
        print("\n[ERROR] PyInstaller 编译失败！")
        return False

    # 4. 复制 Nginx 运行时、SSL 证书与默认配置到发布目录
    print("\n[4/4] 部署便携式 Nginx 数据平面与依赖文件...")
    target_out_dir = dist_dir / "PixivToolkit"
    target_nginx_dir = target_out_dir / "_internal" / "nginx"
    target_nginx_root = target_out_dir / "nginx"

    shutil.copytree(BASE_DIR / "nginx", target_nginx_dir, dirs_exist_ok=True)
    shutil.copytree(BASE_DIR / "nginx", target_nginx_root, dirs_exist_ok=True)

    # 复制根目录 ca.cer 到发布根目录以供快捷手动导入
    if (BASE_DIR / "nginx" / "ca.cer").exists():
        shutil.copyfile(BASE_DIR / "nginx" / "ca.cer", target_out_dir / "ca.cer")

    # 复制应用专属图标到发布根目录
    if (BASE_DIR / "app" / "icon.ico").exists():
        shutil.copyfile(BASE_DIR / "app" / "icon.ico", target_out_dir / "icon.ico")
    if (BASE_DIR / "app" / "icon.png").exists():
        shutil.copyfile(BASE_DIR / "app" / "icon.png", target_out_dir / "icon.png")

    print("\n========================================================")
    print("  [SUCCESS] 打包完成！发布目录:")
    print(f"  {target_out_dir}")
    print("  可执行文件: PixivToolkit.exe (自带 UAC 管理员盾牌清单，原生启动无需 Python 环境)")
    print("========================================================")
    return True

if __name__ == "__main__":
    build_exe()
