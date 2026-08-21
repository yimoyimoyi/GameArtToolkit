# -*- coding: utf-8 -*-
"""
GameArt Toolkit - Windows Release 统一编译、打包与发布资产生成引擎
支持:
1. PyInstaller 一键编译 PySide6 应用程序 (集成管理员清单与图标)
2. Nginx 数据平面与纯净目录树装配 (零私钥分发)
3. 自动生成绿色便携版压缩包 (.zip)
4. 自动检测 Inno Setup 编译器生成单文件安装包 (Setup.exe)
5. 自动计算 SHA-256 校验和文件
"""

import os
import sys
import time
import shutil
import hashlib
import zipfile
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def get_app_version() -> str:
    """从 app/version.py 中读取统一版本号"""
    version_file = BASE_DIR / "app" / "version.py"
    if version_file.exists():
        try:
            with open(version_file, "r", encoding="utf-8") as f:
                for line in f:
                    if "__version__" in line or "VERSION" in line:
                        parts = line.split("=")
                        if len(parts) == 2:
                            return parts[1].strip().strip("'\"")
        except Exception:
            pass
    return "1.0.0"

def find_iscc() -> str:
    """寻找系统安装的 Inno Setup 编译器 ISCC.exe"""
    # 1. 检查环境变量 PATH
    cmd = shutil.which("iscc") or shutil.which("ISCC")
    if cmd:
        return cmd
    
    # 2. 检查常见安装路径
    candidates = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Inno Setup 6" / "ISCC.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Inno Setup 6" / "ISCC.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Inno Setup 6" / "ISCC.exe",
        Path(os.environ.get("USERPROFILE", "")) / "scoop" / "shims" / "iscc.exe",
        Path(os.environ.get("USERPROFILE", "")) / "scoop" / "apps" / "inno-setup" / "current" / "ISCC.exe",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return ""

def calculate_sha256(file_path: Path) -> str:
    """计算文件的 SHA-256 校验和"""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def make_portable_zip(source_dir: Path, output_zip: Path):
    """将绿色发布目录打包为 Portable.zip 压缩包 (优先 7z 高压)"""
    seven_zip = shutil.which("7z") or shutil.which("7za")
    if not seven_zip:
        scoop_7z = Path(os.environ.get("USERPROFILE", "")) / "scoop" / "shims" / "7z.exe"
        if scoop_7z.exists():
            seven_zip = str(scoop_7z)

    if output_zip.exists():
        output_zip.unlink()

    if seven_zip:
        print(f"  [7z] 正在使用 7-Zip 高压打包便携包: {output_zip.name} ...")
        cmd = [
            seven_zip, "a", "-tzip", "-mx=9",
            str(output_zip),
            f"{source_dir}\\*"
        ]
        subprocess.run(cmd, capture_output=True, text=True)
    else:
        print(f"  [Zip] 正在打包便携包: {output_zip.name} ...")
        with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for root, dirs, files in os.walk(source_dir):
                for file in files:
                    abs_p = Path(root) / file
                    rel_p = abs_p.relative_to(source_dir)
                    zf.write(abs_p, arcname=str(rel_p))

def build_all():
    version = get_app_version()
    print("========================================================")
    print(f"   GameArt Toolkit v{version} Windows Release 打包流水线")
    print("========================================================")

    dist_dir = BASE_DIR / "dist"
    build_dir = BASE_DIR / "build"
    app_entry = BASE_DIR / "app" / "pyside_app.py"
    target_out_dir = dist_dir / "GameArtToolkit"

    # 1. 终止可能正在运行的 Nginx 或 GameArtToolkit 进程
    print("\n[1/5] 清理后台运行进程与锁文件...")
    subprocess.run("taskkill /F /IM nginx.exe /IM GameArtToolkit.exe /IM PixivToolkit.exe", shell=True, capture_output=True)
    ps_kill = "Start-Process taskkill -ArgumentList '/F /IM nginx.exe /IM GameArtToolkit.exe /IM PixivToolkit.exe' -Verb RunAs -Wait"
    try:
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_kill], capture_output=True, timeout=5)
    except Exception:
        pass
    time.sleep(0.5)

    # 2. 清理旧构建目录
    print("[2/5] 准备纯净输出目录...")
    if target_out_dir.exists():
        for retry in range(3):
            try:
                shutil.rmtree(target_out_dir, ignore_errors=False)
                break
            except Exception:
                time.sleep(0.5)
                subprocess.run("taskkill /F /IM nginx.exe /IM GameArtToolkit.exe /IM PixivToolkit.exe", shell=True, capture_output=True)

    if build_dir.exists():
        try:
            shutil.rmtree(build_dir, ignore_errors=True)
        except Exception:
            pass

    dist_dir.mkdir(parents=True, exist_ok=True)

    # 3. 生成图标与 Nginx 配置模板
    print("\n[3/5] 编译前置准备 (图标校验与 Nginx 配置模板全量生成)...")
    icon_file = BASE_DIR / "app" / "icon.ico"
    if not icon_file.exists():
        try:
            sys.path.insert(0, str(BASE_DIR / "scripts"))
            from generate_icon import ensure_icons
            ensure_icons()
        except Exception as e:
            print(f"[WARN] 自动生成图标异常: {e}")

    try:
        sys.path.insert(0, str(BASE_DIR / "app"))
        from nginx_generator import NginxConfGenerator
        NginxConfGenerator.generate_all(BASE_DIR / "nginx" / "conf")
    except Exception as e:
        print(f"[WARN] Nginx 模板前置生成异常: {e}")

    # 4. 调用 PyInstaller 编译 PySide6 应用程序
    print("\n[4/5] 调用 PyInstaller 编译 PySide6 (集成管理员清单与图标)...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onedir",
        "--windowed",
        "--uac-admin",
        "--name", "GameArtToolkit",
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

    # 部署 Nginx 运行时与静态资源
    print("\n- 部署便携式 Nginx 数据平面与依赖文件...")
    target_nginx_root = target_out_dir / "nginx"
    ignore_patterns = shutil.ignore_patterns(
        "*.log", "*.pid", "cache", "temp",
        "*.key", "*.crt", "*.cer", "*.pem", "*.pfx", "*.p12"
    )
    shutil.copytree(BASE_DIR / "nginx", target_nginx_root, dirs_exist_ok=True, ignore=ignore_patterns)

    (target_nginx_root / "ca").mkdir(parents=True, exist_ok=True)
    (target_nginx_root / "conf" / "ca").mkdir(parents=True, exist_ok=True)
    (target_nginx_root / "cache").mkdir(parents=True, exist_ok=True)
    (target_nginx_root / "logs").mkdir(parents=True, exist_ok=True)
    for temp_sub in ["client_body_temp", "proxy_temp", "fastcgi_temp", "scgi_temp", "uwsgi_temp"]:
        (target_nginx_root / "temp" / temp_sub).mkdir(parents=True, exist_ok=True)

    if (BASE_DIR / "app" / "icon.ico").exists():
        shutil.copyfile(BASE_DIR / "app" / "icon.ico", target_out_dir / "icon.ico")
    if (BASE_DIR / "app" / "icon.png").exists():
        shutil.copyfile(BASE_DIR / "app" / "icon.png", target_out_dir / "icon.png")

    # 5. 生成 Release 发布资产 (便携包 + 安装包 + SHA256)
    print("\n[5/5] 生成 Release 发布资产包...")
    
    # 5.1 生成 Portable Zip 便携包
    portable_zip = dist_dir / f"GameArtToolkit_v{version}_Portable.zip"
    make_portable_zip(target_out_dir, portable_zip)

    # 5.2 寻找 Inno Setup 并生成 Setup.exe
    iscc_path = find_iscc()
    iss_file = BASE_DIR / "installer.iss"
    setup_exe = dist_dir / f"GameArtToolkit_Setup_v{version}.exe"

    if iscc_path and iss_file.exists():
        print(f"\n  [InnoSetup] 找到 Inno Setup 编译器: {iscc_path}")
        print(f"  正在编译安装包: {setup_exe.name} ...")
        iss_cmd = [iscc_path, f"/DMyAppVersion={version}", str(iss_file)]
        iss_proc = subprocess.run(iss_cmd, cwd=str(BASE_DIR), capture_output=True, text=True)
        if iss_proc.returncode == 0:
            print(f"  [SUCCESS] 单文件安装包生成成功: {setup_exe}")
        else:
            print(f"  [WARN] Inno Setup 编译警告/异常: {iss_proc.stderr or iss_proc.stdout}")
    else:
        print("\n  [INFO] 未检测到 Inno Setup (ISCC.exe)，跳过生成 Setup.exe 单文件安装包。")
        print("         (如需生成 Setup 安装包，可下载安装 Inno Setup 6 或使用 scoop/winget install inno-setup)")

    # 5.3 计算 SHA-256 校验和
    print("\n- 正在计算发布文件 SHA-256 哈希值...")
    checksum_file = dist_dir / "checksums.sha256"
    checksum_lines = []
    
    release_files = [portable_zip]
    if setup_exe.exists():
        release_files.append(setup_exe)

    for f in release_files:
        if f.exists():
            h = calculate_sha256(f)
            checksum_lines.append(f"{h}  {f.name}")
            print(f"  {f.name} => {h}")

    with open(checksum_file, "w", encoding="utf-8") as f:
        f.write("\n".join(checksum_lines) + "\n")

    print("\n========================================================")
    print(f"  [SUCCESS] GameArt Toolkit v{version} 发布资产打包完成！")
    print(f"  发布输出目录: {dist_dir}")
    print("========================================================")
    return True

if __name__ == "__main__":
    build_all()
