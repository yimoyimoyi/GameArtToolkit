# -*- coding: utf-8 -*-
"""
GameArt Toolkit - Windows 原生 API 工具集 (进程与端口探测)
"""

import socket
import ctypes
from ctypes import wintypes
from typing import List, Optional, Tuple

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
    """使用 Socket 探测端口是否被监听"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.05)
        return s.connect_ex((host, port)) == 0

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
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=3, **get_silent_startup_kwargs())
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
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, **get_silent_startup_kwargs())
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
                           capture_output=True, text=True, timeout=5, **get_silent_startup_kwargs())
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
                           capture_output=True, text=True, timeout=4, **get_silent_startup_kwargs())
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


