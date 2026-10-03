# -*- coding: utf-8 -*-
"""
GameArt Toolkit - Windows 原生 API 工具集 (进程与端口探测)
"""

import os
import socket
import ctypes
from ctypes import wintypes
from typing import List, Optional, Tuple, Dict, Any

TH32CS_SNAPPROCESS = 0x00000002

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.c_void_p),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', ctypes.c_char * 260)
    ]

def is_process_running(proc_name: str) -> bool:
    """使用 Windows 原生 Toolhelp32 API 快速判断进程是否存在 (耗时 < 0.5ms)"""
    h_snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if h_snapshot == -1:
        return False

    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    has_next = ctypes.windll.kernel32.Process32First(h_snapshot, ctypes.byref(pe))
    target = proc_name.lower().encode('utf-8')

    found = False
    try:
        while has_next:
            if target == pe.szExeFile.lower() or target in pe.szExeFile.lower():
                found = True
                break
            has_next = ctypes.windll.kernel32.Process32Next(h_snapshot, ctypes.byref(pe))
    finally:
        ctypes.windll.kernel32.CloseHandle(h_snapshot)

    return found

def get_pids_by_name(proc_name: str) -> List[int]:
    """返回指定进程名的全部 PID 列表 (Toolhelp32, 与 is_process_running 同源)"""
    pids: List[int] = []
    h_snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if h_snapshot == -1:
        return pids
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    has_next = ctypes.windll.kernel32.Process32First(h_snapshot, ctypes.byref(pe))
    target = proc_name.lower().encode('utf-8')
    try:
        while has_next:
            if target == pe.szExeFile.lower() or target in pe.szExeFile.lower():
                pids.append(int(pe.th32ProcessID))
            has_next = ctypes.windll.kernel32.Process32Next(h_snapshot, ctypes.byref(pe))
    finally:
        ctypes.windll.kernel32.CloseHandle(h_snapshot)
    return pids

def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """使用 Socket 探测端口是否被监听

    优先快速 connect 判定; 连接超时(部分安全软件/防火墙对回环 SYN 静默丢弃)
    时改用 bind 探测确认, 避免误判为"空闲"且白等超时。
    """
    import errno
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.05)
        rc = s.connect_ex((host, port))
        if rc == 0:
            return True  # 能建立连接 = 端口有监听
        if rc != errno.ETIMEDOUT:  # 立即拒绝 = 端口空闲
            return False
    # 回环 SYN 被静默丢弃: bind 探测确认端口真实占用状态
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return False  # bind 成功 = 端口空闲
        except OSError:
            return True  # bind 失败 = 端口被占用

def is_admin() -> bool:
    """检查当前进程是否具有 Windows 管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def elevate_relaunch(*args, **kwargs) -> bool:
    """唤起 Windows UAC 提示框并以管理员权限重新启动自身 (兼容 PyInstaller 打包与 Python 脚本环境)"""
    import os
    import sys
    from pathlib import Path

    is_frozen = getattr(sys, 'frozen', False)
    if is_frozen:
        exe_path = sys.executable
        work_dir = str(Path(sys.executable).parent)
        param_str = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    else:
        base_dir = Path(__file__).resolve().parent.parent
        bat_file = base_dir / "启动桌面客户端(双击运行).bat"
        if bat_file.exists():
            # 优先通过启动批处理以管理员权限拉起
            exe_path = "cmd.exe"
            param_str = f'/c ""{bat_file}""'
            work_dir = str(base_dir)
        else:
            exe_path = sys.executable
            script_abs = str((base_dir / "app" / "pyside_app.py").resolve())
            work_dir = str(base_dir)
            extra_args = [f'"{a}"' for a in sys.argv[1:]]
            param_str = f'"{script_abs}"' + (" " + " ".join(extra_args) if extra_args else "")

    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", exe_path, param_str, work_dir, 1
    )
    if ret > 32:
        try:
            from PySide6.QtWidgets import QApplication
            app = QApplication.instance()
            if app:
                app.quit()
        except Exception:
            pass
        os._exit(0)
    return False

def get_silent_startup_kwargs() -> dict:
    """获取 Windows 下静默无控制台窗口启动子进程的标准参数字典"""
    import sys
    import subprocess
    if sys.platform == "win32":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        return {
            "creationflags": subprocess.CREATE_NO_WINDOW,
            "startupinfo": si
        }
    return {}

def hide_console_window():
    """如果在 Windows 控制台下被拉起，静默隐藏控制台窗口"""
    import sys
    if sys.platform == "win32":
        try:
            import ctypes
            h_console = ctypes.windll.kernel32.GetConsoleWindow()
            if h_console:
                ctypes.windll.user32.ShowWindow(h_console, 0)  # 0 = SW_HIDE
        except Exception:
            pass

def flush_dns_native() -> bool:
    """调用 Windows 原生 DnsFlushResolverCache 刷新 DNS 缓存 (不启动子进程)"""
    try:
        dnsapi = ctypes.windll.dnsapi
        return dnsapi.DnsFlushResolverCache() != 0
    except Exception:
        try:
            import subprocess
            subprocess.run("ipconfig /flushdns", shell=True, capture_output=True, timeout=2, **get_silent_startup_kwargs())
            return True
        except Exception:
            return False

# ==================== Windows 开机自启管理 (计划任务免 UAC 提权 + 快捷方式双轨制) ====================
REG_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
DEFAULT_APP_NAME = "GameArtToolkit"
AUTOSTART_TASK_NAME = "GameArtToolkit_AutoStart"
AUTOSTART_SHORTCUT_NAME = "GameArt Toolkit.lnk"

def _get_startup_shortcut_path() -> "Path":
    import os
    from pathlib import Path
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup" / AUTOSTART_SHORTCUT_NAME
    return Path.home() / r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" / AUTOSTART_SHORTCUT_NAME

def _is_task_scheduler_autostart_enabled() -> bool:
    """查询 Windows 计划任务中是否存在自启项"""
    import subprocess
    try:
        cmd = ["schtasks", "/query", "/tn", AUTOSTART_TASK_NAME, "/fo", "LIST"]
        # errors="replace": 中文 Windows 子进程输出为 GBK, UTF-8 模式(PYTHONUTF8=1)
        # 下解码失败会崩溃 subprocess 读取线程并导致 stdout 管道无人读取
        res = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                             timeout=3, **get_silent_startup_kwargs())
        return res.returncode == 0
    except Exception:
        return False

def _create_task_scheduler_xml(exe_path: str, arguments: str, work_dir: str) -> str:
    """生成符合 Windows 计划任务标准的 XML 定义 (支持电池运行、免 UAC 最高权限与指定工作目录)"""
    import xml.sax.saxutils as saxutils
    safe_exe = saxutils.escape(exe_path)
    safe_args = saxutils.escape(arguments)
    safe_work_dir = saxutils.escape(work_dir)

    xml_content = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>GameArt Toolkit 开机自启动任务（免 UAC 提权）</Description>
    <Author>GameArt Project</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT1S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{safe_exe}</Command>
      <Arguments>{safe_args}</Arguments>
      <WorkingDirectory>{safe_work_dir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""
    return xml_content

def is_autostart_enabled(app_name: str = DEFAULT_APP_NAME) -> bool:
    """查询系统是否已配置开机自启动（优先检测计划任务，兼容快捷方式与注册表）"""
    import winreg

    # 1. 优先检查计划任务
    if _is_task_scheduler_autostart_enabled():
        return True

    # 2. 检查启动文件夹快捷方式
    shortcut = _get_startup_shortcut_path()
    if shortcut.exists():
        return True

    # 3. 兼容检查注册表
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, app_name)
            return bool(val)
    except Exception:
        pass

    return False

def set_autostart(enable: bool, start_minimized: bool = False, app_name: str = DEFAULT_APP_NAME) -> tuple[bool, str]:
    """设置或取消 Windows 开机自启动 (优先采用计划任务免 UAC 弹窗提权，同步清理注册表残留)"""
    import sys
    import tempfile
    import subprocess
    import winreg
    from pathlib import Path

    shortcut_path = _get_startup_shortcut_path()

    if enable:
        is_frozen = getattr(sys, 'frozen', False)
        if is_frozen:
            target_exe = sys.executable
            arguments = "--minimized" if start_minimized else ""
            work_dir = str(Path(sys.executable).parent)
            icon_path = sys.executable
        else:
            # 源码环境优先使用 pythonw.exe 实现无黑框后台运行
            py_exe = Path(sys.executable)
            pyw_candidate = py_exe.parent / "pythonw.exe"
            target_exe = str(pyw_candidate if pyw_candidate.exists() else py_exe)
            script_path = str(Path(__file__).resolve().parent / "pyside_app.py")
            arguments = f'"{script_path}"' + (" --minimized" if start_minimized else "")
            work_dir = str(Path(__file__).resolve().parent.parent)
            icon_file = Path(__file__).resolve().parent / "icon.ico"
            icon_path = str(icon_file) if icon_file.exists() else target_exe

        # 尝试通过 Task Scheduler 注册
        xml_str = _create_task_scheduler_xml(target_exe, arguments, work_dir)
        temp_xml = None
        task_success = False
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-16", suffix=".xml", delete=False) as f:
                f.write(xml_str)
                temp_xml = f.name

            cmd = ["schtasks", "/create", "/tn", AUTOSTART_TASK_NAME, "/xml", temp_xml, "/f"]
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                                 timeout=5, **get_silent_startup_kwargs())
            if res.returncode == 0:
                task_success = True
        except Exception:
            task_success = False
        finally:
            if temp_xml and Path(temp_xml).exists():
                try:
                    Path(temp_xml).unlink(missing_ok=True)
                except Exception:
                    pass

        # 同步创建启动文件夹快捷方式（确保 Windows 任务管理器启动选项卡完美显示名称与图标）
        try:
            shortcut_path.parent.mkdir(parents=True, exist_ok=True)
            ps_cmd = (
                f"$WshShell = New-Object -ComObject WScript.Shell; "
                f"$Shortcut = $WshShell.CreateShortcut('{shortcut_path}'); "
                f"$Shortcut.TargetPath = '{target_exe}'; "
                f"$Shortcut.Arguments = '{arguments}'; "
                f"$Shortcut.WorkingDirectory = '{work_dir}'; "
                f"$Shortcut.IconLocation = '{icon_path},0'; "
                f"$Shortcut.Description = 'GameArt Toolkit 桌面客户端'; "
                f"$Shortcut.Save()"
            )
            subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd],
                           capture_output=True, text=True, errors="replace",
                           timeout=5, **get_silent_startup_kwargs())
        except Exception:
            pass

        # 清理旧的 Run 注册表项（避免冲突或无特权被拦截）
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, app_name)
        except Exception:
            pass

        if task_success or shortcut_path.exists():
            return True, "已成功开启开机自启动 (最高权限免弹窗)"
        return False, "开启开机自启动失败，请检查系统安全策略"

    else:
        # 1. 删除计划任务
        try:
            subprocess.run(["schtasks", "/delete", "/tn", AUTOSTART_TASK_NAME, "/f"],
                           capture_output=True, text=True, errors="replace",
                           timeout=4, **get_silent_startup_kwargs())
        except Exception:
            pass

        # 2. 删除启动快捷方式
        try:
            if shortcut_path.exists():
                shortcut_path.unlink(missing_ok=True)
        except Exception:
            pass

        # 3. 清理注册表项
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, app_name)
        except Exception:
            pass

        return True, "已成功关闭开机自启动"

# ==================== Windows 原生关机与控制台事件拦截 ====================
PHANDLER_ROUTINE = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
_SHUTDOWN_CALLBACKS = []
_GLOBAL_CTRL_HANDLER_REF = None

def _win32_ctrl_handler(dw_ctrl_type: int) -> bool:
    # 捕获 CTRL_CLOSE_EVENT(2), CTRL_LOGOFF_EVENT(5), CTRL_SHUTDOWN_EVENT(6)
    if dw_ctrl_type in (2, 5, 6):
        for cb in list(_SHUTDOWN_CALLBACKS):
            try:
                cb()
            except Exception:
                pass
        return True
    return False

def register_shutdown_handler(callback) -> bool:
    """注册底层 Win32 控制台与系统关机/注销回调 (SetConsoleCtrlHandler)"""
    global _GLOBAL_CTRL_HANDLER_REF
    if callback not in _SHUTDOWN_CALLBACKS:
        _SHUTDOWN_CALLBACKS.append(callback)

    if _GLOBAL_CTRL_HANDLER_REF is None:
        try:
            _GLOBAL_CTRL_HANDLER_REF = PHANDLER_ROUTINE(_win32_ctrl_handler)
            return ctypes.windll.kernel32.SetConsoleCtrlHandler(_GLOBAL_CTRL_HANDLER_REF, True) != 0
        except Exception:
            return False
    return True

# ==================== 原生进程终止与代理探测 ====================
PROCESS_TERMINATE = 0x0001

def fast_terminate_pid(pid: int) -> bool:
    """使用 Win32 OpenProcess + TerminateProcess 直接终止进程 (不启动子进程)"""
    if pid <= 0:
        return False
    try:
        h_proc = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if h_proc:
            try:
                ctypes.windll.kernel32.TerminateProcess(h_proc, 0)
                return True
            finally:
                ctypes.windll.kernel32.CloseHandle(h_proc)
    except Exception:
        pass
    return False


# ==================== 进程镜像路径识别 (2026-10-04) ====================
# 为什么需要: 退出清理原先按**进程名**枚举并终止全部 `nginx.exe`, 会连带杀掉用户
# 自己另装的 nginx (开发/测试用)。改为按**完整镜像路径**判定, 两头都要:
#   · 路径 == 我们的 nginx.exe       -> 杀 (含无法识别 pid 的孤儿 worker)
#   · 路径取得到但不等于我们的        -> 跳过 (保护用户自己的程序)
#   · 路径取不到 (权限不足 / 已退出)  -> **照杀**
# 最后一条是刻意的取舍: 宁可放过一个无关进程, 也不能漏掉一个孤儿 worker ——
# 后者会占着 80/443、能服务请求却永远无法 reload/stop, 并阻塞下次启动, 是更坏的结局。
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_IMAGE_PATH_BUF_CHARS = 32768


def query_process_image_path(pid: int) -> str:
    """取进程完整镜像路径 (宽字符, 不受非 ASCII 安装路径影响); 失败返回空串

    用 `QueryFullProcessImageNameW` + `PROCESS_QUERY_LIMITED_INFORMATION` —— 后者是
    能取到路径的**最小权限**, 无需 PROCESS_QUERY_INFORMATION (那要求更高完整性级别,
    对部分进程会直接拒绝)。本函数**绝不抛异常**: 取不到就返回空串, 由调用方按上面的
    策略决定杀还是跳过。
    """
    if pid <= 0:
        return ""
    try:
        kernel32 = ctypes.windll.kernel32
        h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not h_proc:
            return ""
        try:
            size = wintypes.DWORD(_IMAGE_PATH_BUF_CHARS)
            buf = ctypes.create_unicode_buffer(size.value)
            if not kernel32.QueryFullProcessImageNameW(h_proc, 0, buf, ctypes.byref(size)):
                return ""
            return buf.value or ""
        finally:
            kernel32.CloseHandle(h_proc)
    except Exception:
        return ""


def _normalize_image_path(path: str) -> str:
    """镜像路径归一化: 去引号 / 去 `\\\\?\\` 长路径前缀 / 统一分隔符与大小写"""
    s = (path or "").strip().strip('"')
    if s.startswith("\\\\?\\"):
        s = s[4:]
        if s.upper().startswith("UNC\\"):
            s = "\\\\" + s[4:]
    try:
        return os.path.normcase(os.path.normpath(s))
    except Exception:
        return s.lower()


def is_same_image(path: str, expected_exe) -> bool:
    """两个路径是否指向**同一个可执行文件**

    优先 `os.path.samefile` (按卷+文件索引比较, 天然免疫大小写与 8.3 短路径差异);
    任一路径不可达时退回归一化字符串比较 (此时仍可能因短路径形式不同而误判, 故
    调用方在"路径取不到"时选择保守照杀, 见文件顶部说明)。
    """
    try:
        if path and os.path.exists(path) and os.path.exists(str(expected_exe)):
            return os.path.samefile(path, str(expected_exe))
    except OSError:
        pass
    return _normalize_image_path(path) == _normalize_image_path(str(expected_exe))


def select_own_image_pids(pids: List[int], expected_exe) -> Tuple[List[int], List[int]]:
    """按镜像路径把候选 pid 分成 (属于本程序的, 属于他人的)

    返回 (ours, foreign): `ours` 含"路径取不到"的 pid (保守照杀), 理由见文件顶部说明。
    """
    ours: List[int] = []
    foreign: List[int] = []
    for pid in pids or []:
        path = query_process_image_path(pid)
        if not path or is_same_image(path, expected_exe):
            ours.append(pid)
        else:
            foreign.append(pid)
    return ours, foreign


def is_windows_dark_mode() -> bool:
    """读取 Windows 10/11 注册表 AppsUseLightTheme，判断系统当前是否为深色模式"""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as key:
            val, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            return val == 0
    except Exception:
        return True


def check_proxy_alive(host: str = "127.0.0.1", port: int = 7897, timeout: float = 1.0) -> bool:
    """测试上游测速代理是否可用: TCP 端口探活 + HTTP CONNECT 隧道握手双重验证

    仅 TCP 探活会将任意占用端口的服务误判为代理, 增加 CONNECT 握手
    保证返回 True 时该端口确实是可用的 HTTP 代理 (与测速链路的 CONNECT 行为一致)
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) != 0:
                return False
            # CONNECT 到测试地址 (1.2.3.4:443), 真实代理会返回 200 Connection established
            s.sendall(b"CONNECT 1.2.3.4:443 HTTP/1.1\r\nHost: 1.2.3.4:443\r\n\r\n")
            hdr = b""
            while b"\r\n\r\n" not in hdr:
                chunk = s.recv(4096)
                if not chunk:
                    break
                hdr += chunk
            line = hdr.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
            return " 200 " in line
    except Exception:
        return False


# ==================== WinINet 系统代理例外列表 (ProxyOverride) 管理 ====================
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37
REG_PROXY_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


class ProxyBypassManager:
    """WinINet 系统代理例外列表 (ProxyOverride) 动态接管与还原管理器
    
    让浏览器在 Clash 等开启系统代理时，针对指定加速域名自动绕过代理，
    直连 127.0.0.1 享受本地 Nginx 0ms 磁盘缓存与协议加速。
    """
    TAG_START = "<-GameArtStart->"
    TAG_END = "<-GameArtEnd->"
    LEGACY_TAG_START = "<-PixivToolkitStart->"
    LEGACY_TAG_END = "<-PixivToolkitEnd->"

    @classmethod
    def apply_bypass(cls, domains: List[str]) -> bool:
        """将加速域名追加至 ProxyOverride 例外列表并通知 WinINet 立即生效"""
        if not domains:
            return False
        import winreg
        import re
        try:
            current_override = ""
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PROXY_SETTINGS, 0, winreg.KEY_READ) as key:
                    current_override, _ = winreg.QueryValueEx(key, "ProxyOverride")
            except FileNotFoundError:
                current_override = "<local>"

            clean_override = cls._strip_tags(current_override)
            
            # 为每个域名生成通配符规则 (*.domain 与 domain)
            rules = []
            for d in domains:
                d_clean = d.strip()
                if not d_clean:
                    continue
                if d_clean.startswith("*."):
                    rules.append(d_clean)
                else:
                    rules.append(f"*.{d_clean}")
                    rules.append(d_clean)
            
            rules_str = ";".join(dict.fromkeys(rules))
            tagged_block = f"{cls.TAG_START}{rules_str}{cls.TAG_END}"
            
            # 合并并确保 <local> 存在
            parts = [p for p in clean_override.split(";") if p and p != "<local>"]
            parts.append(tagged_block)
            parts.append("<local>")
            new_override = ";".join(parts)

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PROXY_SETTINGS, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, new_override)

            cls._notify_wininet()
            return True
        except Exception:
            return False

    @classmethod
    def restore_bypass(cls) -> bool:
        """从 ProxyOverride 中安全剥离本项目的标签块并通知 WinINet 立即还原"""
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PROXY_SETTINGS, 0, winreg.KEY_READ) as key:
                current_override, _ = winreg.QueryValueEx(key, "ProxyOverride")
        except Exception:
            return False

        clean_override = cls._strip_tags(current_override)
        if clean_override == current_override:
            return True  # 无需更改

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PROXY_SETTINGS, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, clean_override)
            cls._notify_wininet()
            return True
        except Exception:
            return False

    @classmethod
    def _strip_tags(cls, text: str) -> str:
        """剥离当前版本与历史版本的标签块"""
        import re
        if not text:
            return "<local>"
        pattern = re.compile(rf"{re.escape(cls.TAG_START)}.*?{re.escape(cls.TAG_END)};?", re.DOTALL)
        text = pattern.sub("", text)
        legacy_pattern = re.compile(rf"{re.escape(cls.LEGACY_TAG_START)}.*?{re.escape(cls.LEGACY_TAG_END)};?", re.DOTALL)
        text = legacy_pattern.sub("", text)
        # 清理多余的分号
        clean_parts = [p.strip() for p in text.split(";") if p.strip()]
        return ";".join(clean_parts) if clean_parts else "<local>"

    @classmethod
    def _notify_wininet(cls):
        """通知 Windows WinINet 系统代理配置已更新 (即时生效)"""
        try:
            ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
        except Exception:
            pass


# ==================== 物理网卡与本地代理自适应探测 ====================

COMMON_PROXY_PORTS = [
    ("127.0.0.1", 7897),   # Clash Verge / Mihomo Mixed Port
    ("127.0.0.1", 7890),   # Clash for Windows / Classical Clash
    ("127.0.0.1", 10809),  # v2rayN / Xray HTTP
    ("127.0.0.1", 2080),   # Sing-box HTTP / Mixed
    ("127.0.0.1", 10808),  # SOCKS5 fallback
]


def get_physical_adapter_ip() -> Optional[str]:
    """获取本机默认物理网卡 (Ethernet/Wi-Fi) 的局域网 IPv4 地址，避开 TUN 虚拟网卡 (如 198.18.x.x)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # 排除 TUN 虚拟网卡常见的 198.18.x.x, 198.19.x.x, 127.x.x.x
        if not local_ip.startswith(("198.18.", "198.19.", "127.")):
            return local_ip
    except Exception:
        pass
    return None


def auto_detect_active_proxy(timeout: float = 0.2) -> Optional[Tuple[str, int]]:
    """后台自适应嗅探当前活跃的本地代理端口 (优先读取注册表 ProxyServer，次选常见客户端端口)"""
    # 1. 优先读取系统注册表中的 ProxyServer 配置
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PROXY_SETTINGS, 0, winreg.KEY_READ) as key:
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
            if server:
                # 兼容 "127.0.0.1:7890" 或 "http=127.0.0.1:7890;https=..."
                for part in server.split(";"):
                    hp = part.split("=")[-1].strip()
                    if ":" in hp:
                        host, port_str = hp.split(":", 1)
                        if port_str.isdigit():
                            port = int(port_str)
                            if is_port_in_use(port, host):
                                return (host, port)
    except Exception:
        pass

    # 2. 依次探测常用客户端端口
    for host, port in COMMON_PROXY_PORTS:
        if is_port_in_use(port, host):
            return (host, port)
    return None


def get_port_process_info(port: int) -> List[Dict[str, Any]]:
    """
    查询指定端口的占用详情 (支持 TCP / UDP 监听与连接)，获取占用进程的 PID、名称、绝对路径
    优先使用 psutil，自动兜底使用 Windows 原生 netstat + tasklist
    """
    results: List[Dict[str, Any]] = []
    seen_pids = set()

    # 1. 尝试使用 psutil 高速获取
    try:
        import psutil
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.laddr.port == port:
                pid = conn.pid
                if pid and pid not in seen_pids and pid > 0:
                    seen_pids.add(pid)
                    proc_name = "未知进程"
                    exe_path = ""
                    status = conn.status or "LISTEN"
                    try:
                        p = psutil.Process(pid)
                        proc_name = p.name()
                        exe_path = p.exe()
                    except Exception:
                        pass
                    results.append({
                        "port": port,
                        "pid": pid,
                        "name": proc_name,
                        "exe": exe_path,
                        "status": status,
                        "proto": "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    })
        if results:
            return results
    except Exception:
        pass

    # 2. 兜底方案：使用 Windows 原生 netstat -ano
    try:
        import subprocess
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        cmd = f"netstat -ano -p tcp"
        out = subprocess.check_output(cmd, startupinfo=si, text=True, errors="ignore")
        
        # 解析 netstat 输出
        target_str = f":{port}"
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("TCP") and not line.startswith("UDP"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                local_addr = parts[1]
                if local_addr.endswith(target_str):
                    try:
                        pid = int(parts[-1])
                        if pid > 0 and pid not in seen_pids:
                            seen_pids.add(pid)
                            proc_name = "未知进程"
                            exe_path = ""
                            # 使用 tasklist 或 wmic 查名称
                            try:
                                t_out = subprocess.check_output(
                                    f'tasklist /fi "PID eq {pid}" /fo csv /nh',
                                    startupinfo=si, text=True, errors="ignore"
                                )
                                if t_out and '"' in t_out:
                                    proc_name = t_out.split('","')[0].replace('"', '').strip()
                            except Exception:
                                pass
                            results.append({
                                "port": port,
                                "pid": pid,
                                "name": proc_name,
                                "exe": exe_path,
                                "status": parts[3] if len(parts) >= 5 else "LISTEN",
                                "proto": parts[0]
                            })
                    except ValueError:
                        continue
    except Exception:
        pass

    return results


def get_critical_ports_status(ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    """批量获取核心端口 (默认 80, 443, 53) 的占用诊断状态"""
    if ports is None:
        ports = [80, 443, 53]

    statuses = []
    for port in ports:
        in_use = is_port_in_use(port)
        proc_info = get_port_process_info(port) if in_use else []
        statuses.append({
            "port": port,
            "in_use": in_use,
            "processes": proc_info
        })
    return statuses


def kill_process_by_pid_safe(pid: int) -> Tuple[bool, str]:
    """安全终止指定 PID 进程，返回 (是否成功, 说明文字)"""
    import os
    if pid <= 0:
        return False, "无效的进程 PID"
    if pid == os.getpid():
        return False, "无法终止当前客户端自身进程"

    try:
        # 1. 尝试快速终止
        fast_terminate_pid(pid)
        # 等待 150ms 确认
        time.sleep(0.15)
        if not is_process_running(pid):
            return True, f"已成功释放进程 (PID: {pid})"
    except Exception as e:
        pass

    # 2. 尝试使用 taskkill /F /T
    try:
        import subprocess
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], startupinfo=si, capture_output=True)
        time.sleep(0.15)
        if not is_process_running(pid):
            return True, f"已成功结束进程 (PID: {pid})"
        else:
            return False, f"结束进程失败，可能需要管理员权限或系统核心保护 (PID: {pid})"
    except Exception as e:
        return False, f"操作异常: {e}"



