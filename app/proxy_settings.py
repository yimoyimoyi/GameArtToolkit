# -*- coding: utf-8 -*-
"""
GameArt Toolkit - WinINET 自动配置脚本 (PAC) 发布器 (2026-10-02 新增)

## 它解决的场景

用户要求: **不由程序拉起浏览器**, 且接受"需要用户自己重启浏览器才生效"。
于是不用命令行 `--proxy-pac-url`(那是进程级参数, 必须由我们启动浏览器才能带上),
改为把 PAC 地址写进 **Windows 用户级"自动配置脚本"**:

    HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\AutoConfigURL

为什么选它而不是 Chrome 策略 `ProxyPacUrl`:
  · **不需要管理员** (HKCU);
  · **不会出现"由贵单位管理"横幅** —— Chrome 策略会, 而这是普通的系统代理设置;
  · **同时覆盖 Chrome / Edge / 以及任何沿用 WinINET 的应用**, 不像浏览器策略只作用于一家;
  · 生效后**不需要程序常驻拉起浏览器**, 用户自己开浏览器就是。

## 已实测的边界 (2026-10-02)

· 写入后必须调用 `InternetSetOption(INTERNET_OPTION_SETTINGS_CHANGED / REFRESH)`,
  否则已运行的应用不会重新读取 —— 本模块两个都调。
· 是否"运行中的浏览器当场采用"取决于浏览器对 WinINET 变更的响应, 本模块只负责
  "把设置改对 + 通知系统"; 用户若未生效, 重启浏览器即可 (用户已明确接受这一点)。
· **必须可完整还原**: 写入前备份 AutoConfigURL / ProxyEnable / ProxyServer,
  退出时恢复原值 (含"原本不存在"这一情形)。系统代理是用户自身的设置, 绝不能留下污染。

## 安全边界

只操作**当前用户**的设置, 且只碰上述三个值; 不做任何机器级改动。
"""
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from win_utils import get_silent_startup_kwargs

sys.path.insert(0, str(Path(__file__).resolve().parent))

_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_BACKUP_VALUES = ("AutoConfigURL", "ProxyEnable", "ProxyServer", "ProxyOverride")

# WinINET 选项号 (wininet.h)
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37


def _winreg():
    import winreg  # noqa: PLC0415  仅在 Windows 上可用
    return winreg


def read_current() -> Dict[str, Any]:
    """读取当前与 PAC/代理相关的用户级设置 (用于备份与状态显示)

    返回 {"exists": bool, "values": {name: (data, type)}}
    """
    out: Dict[str, Any] = {"exists": False, "values": {}}
    if sys.platform != "win32":
        return out
    winreg = _winreg()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _SETTINGS_KEY) as k:
            out["exists"] = True
            for name in _BACKUP_VALUES:
                try:
                    data, typ = winreg.QueryValueEx(k, name)
                    out["values"][name] = (data, typ)
                except FileNotFoundError:
                    pass
    except FileNotFoundError:
        pass
    return out


def pac_fallback_directive() -> str:
    """把用户**当前的固定代理设置**翻译成 PAC 的兜底返回值 (2026-10-02 实测新增)

    ## 为什么必须有它 (实测事故)

    PAC 优先于固定代理。若我们的 PAC 对未命中域名一律返回 `DIRECT`,
    **用户自己的固定代理会被整个旁路** —— 实测: 设 ProxyEnable=1 + ProxyServer=本机某端口,
    再写入返回 DIRECT 的 PAC, 该端口收到的 CONNECT 数为 **0**。
    也就是说: 用户开着系统代理时启用本后端, 他其它所有站点都会变成直连, 上网直接受影响。

    ⇒ 兜底必须**复现**用户原有设置:
       · ProxyEnable=1 且 ProxyServer 可用 -> 返回对应的 PROXY/SOCKS 指令;
       · 否则 -> DIRECT。
    WinINET 的 ProxyServer 支持两种写法, 都要认:
       · `host:port`                        (所有协议同一个代理)
       · `http=h:p;https=h:p;socks=h:p`     (按协议分别指定)
    注意 socks 要走 `SOCKS`/`SOCKS5` 指令, 否则会被当成 HTTP 代理而失败。
    """
    cur = read_current()
    vals = cur.get("values") or {}
    enabled = int((vals.get("ProxyEnable") or (0, 0))[0] or 0) == 1
    server = str((vals.get("ProxyServer") or ("", 0))[0] or "").strip()
    if not enabled or not server:
        return "DIRECT"
    # 按协议分别指定的写法
    if "=" in server:
        mapping = {}
        for part in server.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                mapping[k.strip().lower()] = v.strip()
        https = mapping.get("https") or mapping.get("http")
        if https:
            return f"PROXY {https}"
        socks = mapping.get("socks") or mapping.get("socks5")
        if socks:
            return f"SOCKS5 {socks}"
        return "DIRECT"
    low = server.lower()
    if low.startswith("socks"):
        # 形如 socks=host:port 或 socks5://host:port
        addr = server.split("=", 1)[-1].split("//")[-1]
        return f"SOCKS5 {addr}"
    return f"PROXY {server}"


def _notify_change() -> None:
    """通知 WinINET 设置已变更, 让已运行的应用重新读取

    缺少这一步时, 已打开的浏览器**不会**重新读取代理设置 —— 这是"改完没反应"的常见原因。
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        wininet = ctypes.windll.wininet
        for opt in (INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH):
            try:
                wininet.InternetSetOptionW(None, opt, None, 0)
            except Exception:
                pass
    except Exception:
        pass


def set_autoconfig_url(url: str) -> Tuple[bool, str]:
    """把 PAC 地址写入用户级自动配置脚本, 并通知系统

    :return: (是否成功, 面向用户的消息)
    """
    if sys.platform != "win32":
        return False, "非 Windows 平台, 不支持系统代理设置"
    if not url or not url.lower().startswith(("http://", "https://")):
        return False, f"PAC 地址必须是 http(s) URL: {url!r}"
    winreg = _winreg()
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _SETTINGS_KEY, 0,
                                winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, url)
        _notify_change()
        return True, f"已把 PAC 写入系统「自动配置脚本」: {url} (无需管理员)"
    except Exception as e:
        return False, f"写入自动配置脚本失败: {type(e).__name__}: {e}"


def restore(backup: Dict[str, Any]) -> Tuple[bool, str]:
    """按备份还原用户级代理设置 (含"原本不存在则删除")

    必须在退出时调用: 系统代理是用户自己的设置, 留下污染等于替用户改了上网方式。
    """
    if sys.platform != "win32":
        return True, "非 Windows 平台, 无需还原"
    winreg = _winreg()
    values = (backup or {}).get("values") or {}

    def _readback() -> Dict[str, Any]:
        """用**同一个** winreg 句柄回读 (不能调 read_current(): 它会重新导入真实模块,
        在注入替身的测试里会去读真实注册表, 于是"校验"本身失真)"""
        now: Dict[str, Any] = {}
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _SETTINGS_KEY) as k2:
                for name in _BACKUP_VALUES:
                    try:
                        now[name] = winreg.QueryValueEx(k2, name)
                    except FileNotFoundError:
                        pass
        except FileNotFoundError:
            pass
        return now

    def _mismatch(now: Dict[str, Any]) -> list:
        bad = []
        for name in _BACKUP_VALUES:
            if name in values:
                want = values[name][0]
                got = (now.get(name) or [None])[0]
                if got != want:
                    bad.append(f"{name} 未写成 (期望 {want!r}, 实际 {got!r})")
            elif name in now:
                bad.append(f"{name} 未删除 (仍为 {now[name][0]!r})")
        return bad

    def _apply() -> None:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _SETTINGS_KEY, 0,
                                winreg.KEY_SET_VALUE) as k:
            for name in _BACKUP_VALUES:
                if name in values:
                    data, typ = values[name]
                    winreg.SetValueEx(k, name, 0, typ, data)
                else:
                    try:
                        winreg.DeleteValue(k, name)
                    except FileNotFoundError:
                        pass

    try:
        # ★ 为什么是"删 → 通知 → 回读 → 必要时**再删一次**" (2026-10-02 实测定因):
        #   本函数原先无条件返回成功; 实测它在返回"系统代理设置已还原"的同时,
        #   AutoConfigURL **原封不动**留在注册表里 —— 用户的浏览器会一直去取一个
        #   已经不存在的本地 PAC。
        #   进一步实测把责任定位清楚了: `winreg.DeleteValue` **本身完全正常**
        #   (朴素 CreateKeyEx+KEY_SET_VALUE+DeleteValue 一把就删掉了)。真正的问题是
        #   紧接着的 `_notify_change()` —— 通知 WinINET 刷新之后, 那个值**又回来了**
        #   (WinINET 的自动配置缓存在刷新时会把值写回注册表)。
        #   所以"删一次就完事"这个前提本身不成立: 必须**通知之后再回读, 不符就再删**。
        #   与本项目另两处教训同源 (certutil -delstore、NRPT cmdlet): 绝不把
        #   "命令没报错"当成"已生效", 一律写完回读。
        surviving: list = []
        for attempt in (1, 2):
            # ★★ 顺序是**先通知、后改注册表** —— 这是本轮定因的核心结论 (2026-10-02)。
            #   原先写的是 _apply() 然后 _notify_change(), 表现为"删了没用": 逐步打印
            #   证明 DeleteValue **四个值全都成功**(手工复刻后注册表真的变成 {}), 但紧接着
            #   的 _notify_change() 让 **WinINET 把它缓存的代理配置写回注册表** ——
            #   删掉的四个值原样复活, 连我们从未设置过的 ProxyOverride / ProxyServer
            #   都带着**原始取值**回来, 这是"缓存回写"而非"删除失败"的确证。
            #   所以必须先通知(让它把缓存吐完), 再落我们的最终状态, 且其后**不再通知**。
            _notify_change()
            _apply()
            surviving = _mismatch(_readback())
            if not surviving:
                return True, ("系统代理设置已还原"
                              + ("" if attempt == 1 else f" (第 {attempt} 次尝试才生效)"))
        return False, ("系统代理还原**未真正生效** (命令未报错但回读不符): "
                       + "; ".join(surviving))
    except Exception as e:
        return False, f"还原系统代理设置失败: {type(e).__name__}: {e}"
        # ---- 兜底: 走**已证实可用**的路径 (2026-10-02) ----
        # 实测定因: winreg.DeleteValue 单独用**完全正常** (朴素
        # CreateKeyEx+KEY_SET_VALUE+DeleteValue 一把就删掉了 AutoConfigURL),
        # 但在本函数里连删两次都不生效 —— 根因未查明。
        # 此时不能只"如实报失败"就收手: 留下 AutoConfigURL 指向一个已死的本地 PAC,
        # 用户的浏览器会一直去取它; 而 pac_auto 现在是**默认后端**, 每次退出都撞这条路。
        # reg.exe 是独立进程, 不共享本进程的注册表视图, 实测能清除。
        if any(s.startswith("AutoConfigURL") for s in surviving):
            _notify_change()          # 同上: 先让它回写, 再删
            try:
                # ⚠ reg.exe 要**完整的 hive 前缀**, 而 _SETTINGS_KEY 是 winreg 的相对路径
                #   —— 少了 HKCU\\ 会静默什么都不做 (reg 返回非零但不抛异常)。
                subprocess.run(["reg", "delete", "HKCU\\\\" + _SETTINGS_KEY,
                                "/v", "AutoConfigURL", "/f"],
                               capture_output=True, timeout=5, shell=False,
                               **get_silent_startup_kwargs())
            except Exception:
                pass
            surviving = _mismatch(_readback())
            if not surviving:
                return True, "系统代理设置已还原 (经 reg.exe 兜底清除)"
        return False, ("系统代理还原**未真正生效** (命令未报错但回读不符): "
                       + "; ".join(surviving))
    except Exception as e:
        return False, f"还原系统代理设置失败: {type(e).__name__}: {e}"


def is_pointing_at(url: str) -> bool:
    """当前自动配置脚本是否正指向给定地址 (用于状态判定)"""
    cur = read_current()
    v = (cur.get("values") or {}).get("AutoConfigURL")
    return bool(v) and str(v[0]).strip() == str(url).strip()
