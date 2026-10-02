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

# 强制设置环境语言与标准 I/O 编码，避免 Windows 多语言环境或非 UTF-8 控制台下报错
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
os.environ.setdefault("LANG", "zh_CN.UTF-8")
os.environ.setdefault("LC_ALL", "zh_CN.UTF-8")

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
    return "1.1.0"

def build_ech_tunnel() -> bool:
    """构建 ECH 隧道可执行文件 (需要 Go 工具链)

    隧道源码在 tools/ech_tunnel/, 通过 build.ps1 编译成静态单文件。
    Go 工具链缺失时返回 False —— 调用方应降级为警告而非中断打包:
    缺少隧道只会让标记 ech_enabled 的服务退回常规分支, 不影响其余功能。
    """
    script = BASE_DIR / "tools" / "ech_tunnel" / "build.ps1"
    if not script.exists():
        print(f"  [WARN] 未找到构建脚本: {script}")
        return False
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
            capture_output=True, text=True, timeout=300,
            encoding="utf-8", errors="replace",
        )
        if result.returncode == 0:
            print("  " + (result.stdout or "").strip().replace("\n", "\n  "))
            return True
        print(f"  [WARN] ECH 隧道构建失败: {(result.stderr or '').strip()[:300]}")
    except FileNotFoundError:
        print("  [WARN] 未找到 PowerShell, 跳过 ECH 隧道构建")
    except subprocess.TimeoutExpired:
        print("  [WARN] ECH 隧道构建超时")
    except Exception as e:
        print(f"  [WARN] 调用 ECH 隧道构建脚本异常: {e}")
    return False


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

    # 3. 生成图标与 Nginx 配置模板及 Windows PE 版本信息
    print("\n[3/5] 编译前置准备 (版本信息同步、图标校验与 Nginx 配置模板全量生成)...")
    ver_info_file = BASE_DIR / "file_version_info.txt"
    try:
        parts = [int(p) if p.isdigit() else 0 for p in version.split(".")]
        while len(parts) < 4:
            parts.append(0)
        v_tuple = tuple(parts[:4])
        v_str = ".".join(str(x) for x in v_tuple)
        ver_content = f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={v_tuple},
    prodvers={v_tuple},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          '080404b0',
          [
            StringStruct('CompanyName', 'GameArt Project'),
            StringStruct('FileDescription', 'GameArt Toolkit 桌面客户端'),
            StringStruct('FileVersion', '{v_str}'),
            StringStruct('InternalName', 'GameArtToolkit.exe'),
            StringStruct('LegalCopyright', 'Copyright (C) 2026 GameArt Project'),
            StringStruct('OriginalFilename', 'GameArtToolkit.exe'),
            StringStruct('ProductName', 'GameArt Toolkit'),
            StringStruct('ProductVersion', '{v_str}'),
            StringStruct('Comments', 'Pixiv / Steam / Game Art Acceleration Toolkit')
          ]
        ),
        StringTable(
          '040904b0',
          [
            StringStruct('CompanyName', 'GameArt Project'),
            StringStruct('FileDescription', 'GameArt Toolkit Desktop Client'),
            StringStruct('FileVersion', '{v_str}'),
            StringStruct('InternalName', 'GameArtToolkit.exe'),
            StringStruct('LegalCopyright', 'Copyright (C) 2026 GameArt Project'),
            StringStruct('OriginalFilename', 'GameArtToolkit.exe'),
            StringStruct('ProductName', 'GameArt Toolkit'),
            StringStruct('ProductVersion', '{v_str}')
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct('Translation', [2052, 1200, 1033, 1200])])
  ]
)
"""
        ver_info_file.write_text(ver_content, encoding="utf-8")
        print(f"  [Version] 已同步 PE 版本信息定义: v{v_str}")
    except Exception as e:
        print(f"[WARN] 同步版本信息异常: {e}")

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
    print("\n[4/5] 调用 PyInstaller 编译 PySide6 (集成管理员清单、PE版本与图标)...")
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

    if ver_info_file.exists():
        cmd.append(f"--version-file={ver_info_file}")

    cmd.extend([
        f"--add-data={BASE_DIR / 'app'};app",
        "--exclude-module=tkinter",
        "--exclude-module=matplotlib",
        "--exclude-module=scipy",
        "--exclude-module=unittest",
        "--exclude-module=test",
        "--exclude-module=pydoc",
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

    # ------------------------------------------------------------------
    # 发布包密钥泄漏硬校验 (2026-10-02 新增)
    #
    # 为什么必须有: 上面的 ignore_patterns 是**按扩展名排除的黑名单** —— 一旦模式被改动、
    # 或将来出现别的密钥扩展名, CA 私钥就会被静默放进发布包。实测本机 dist 里就残留过
    # 一整套 `nginx/ca/ca.key` + `nginx/ca/ca.cer` (旧版 build.py 拷进去的),
    # 而**那个根证书当时仍在本机受信任存储里** —— 等于把一个可用的中间人私钥, 连同
    # "它已被信任"这个前提一起发了出去。
    # 本项目是"零私钥分发"(每个安装在首次运行时自生成唯一 CA), 故这里对拷贝结果做硬校验:
    # 发现证书/私钥一律删除并使构建失败 —— 用结果校验补黑名单的不可靠。
    # 注意只用 target_nginx_root 递归: 依赖里 certifi 的 cacert.pem 是公开 CA 包, 不能误伤。
    # ------------------------------------------------------------------
    leaked = []
    for _pat in ("*.key", "*.crt", "*.cer", "*.pem", "*.pfx", "*.p12"):
        leaked.extend(target_nginx_root.rglob(_pat))
    if leaked:
        for _f in leaked:
            try:
                _f.unlink()
            except Exception:
                pass
        print("\n[ERROR] 发布包的 nginx 目录里出现了证书/私钥文件 —— 已删除并中止构建:")
        for _f in leaked:
            print(f"    {_f}")
        print("        CA 私钥绝不能进发布包 (每个安装应首次运行时自生成);"
              " 请检查上面的 ignore_patterns 是否被改动。")
        return False
    print("  ✓ 发布包密钥校验通过: nginx 目录内无证书/私钥文件")

    if (BASE_DIR / "app" / "icon.ico").exists():
        shutil.copyfile(BASE_DIR / "app" / "icon.ico", target_out_dir / "icon.ico")
    if (BASE_DIR / "app" / "icon.png").exists():
        shutil.copyfile(BASE_DIR / "app" / "icon.png", target_out_dir / "icon.png")

    # 部署 ECH 隧道可执行文件 (Go 静态二进制, 无运行时依赖)
    # 只复制 exe: 源码与构建脚本留在仓库, 不进发布包
    print("\n- 部署 ECH 隧道可执行文件...")
    tunnel_exe = BASE_DIR / "tools" / "ech_tunnel" / "ech-tunnel.exe"
    if not tunnel_exe.exists():
        print("  未找到已编译的隧道, 尝试现场构建...")
        build_ech_tunnel()
    if tunnel_exe.exists():
        tunnel_dst = target_out_dir / "tools" / "ech_tunnel"
        tunnel_dst.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(tunnel_exe, tunnel_dst / "ech-tunnel.exe")
        size_mb = tunnel_exe.stat().st_size / (1024 * 1024)
        print(f"  已部署 ECH 隧道: {tunnel_dst / 'ech-tunnel.exe'} ({size_mb:.1f} MB)")
    else:
        # 不中断打包: 缺少隧道时, 标记 ech_enabled 的服务会退回常规分支
        print("  [WARN] ECH 隧道不可用, 本次发布将不含 ECH 直连能力")
        print("         标记 ech_enabled 的服务会自动退回常规分支")

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
