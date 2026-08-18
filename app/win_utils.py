# -*- coding: utf-8 -*-
"""
PixivToolkit - Windows 原生 API 工具集 (进程与端口探测)
"""

import socket
import ctypes
from ctypes import wintypes

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

# ==================== Windows 开机自启管理 (HKCU 注册表免管理员权限) ====================
REG_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
DEFAULT_APP_NAME = "PixivToolkit"

def is_autostart_enabled(app_name: str = DEFAULT_APP_NAME) -> bool:
    """查询当前用户注册表是否已配置开机自启动"""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, app_name)
            return bool(val)
    except FileNotFoundError:
        return False
    except Exception:
        return False

def set_autostart(enable: bool, start_minimized: bool = True, app_name: str = DEFAULT_APP_NAME) -> tuple[bool, str]:
    """设置或取消 Windows 开机自启动 (写入 HKCU 免 UAC 弹窗)"""
    import sys
    import winreg
    from pathlib import Path

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if enable:
                is_frozen = getattr(sys, 'frozen', False)
                if is_frozen:
                    exe_path = f'"{sys.executable}"'
                else:
                    script_path = Path(__file__).resolve().parent / "pyside_app.py"
                    exe_path = f'"{sys.executable}" "{script_path}"'

                cmd_str = f"{exe_path} --minimized" if start_minimized else exe_path
                winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, cmd_str)
                return True, "已成功开启开机自启动"
            else:
                try:
                    winreg.DeleteValue(key, app_name)
                except FileNotFoundError:
                    pass
                return True, "已成功关闭开机自启动"
    except Exception as e:
        return False, f"配置开机自启失败: {e}"

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

