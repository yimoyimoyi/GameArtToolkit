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
    user_pac = str((vals.get("AutoConfigURL") or ("", 0))[0] or "").strip()

    # ★ M15 (2026-10-03): 用户自己的 **PAC** 也必须在兜底里被复现, 不能只看 ProxyServer。
    #   原实现只看 ProxyEnable + ProxyServer ⇒ 对"靠自己 PAC 上网"的用户,
    #   我们的 PAC 一旦未命中就返回 DIRECT, **把他整条 PAC 出口旁路掉** ——
    #   与本函数要修的 b1693ed 事故是同一个形态, 只是那次是固定代理、这次是 PAC。
    #   实测依据: 本机用户正是这种状态 —— `upstream_proxy.enabled=False` 且
    #   ProxyEnable=0, 固定代理端口无人监听, 说明他不是靠固定代理出网的。
    #   只认**别人的** PAC (我们自己写的 proxy.pac 不算用户设置, 否则会自我循环)。
    if user_pac and not is_our_pac_url(user_pac):
        return f"PAC {user_pac}"

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


def _readback_with(winreg) -> Dict[str, Any]:
    r"""用**调用方注入的** winreg 句柄回读 (与 restore() 的 _readback 同款)

    为什么必须接受 winreg 参数而不是调 read_current(): read_current() 会重新导入
    **真实** winreg —— 在注入替身的测试里它读的是真实注册表, 于是"校验"本身失真。
    """
    now: Dict[str, Any] = {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _SETTINGS_KEY) as k:
            for name in _BACKUP_VALUES:
                try:
                    now[name] = winreg.QueryValueEx(k, name)
                except FileNotFoundError:
                    pass
    except FileNotFoundError:
        pass
    return now


def set_autoconfig_url(url: str) -> Tuple[bool, str]:
    """把 PAC 地址写入用户级自动配置脚本, 并通知系统

    ## ★ 顺序与读回 (2026-10-03 定因, 与 restore() 的结论对齐)

    `restore()` 的根因结论是 "**WinINET writes its cached proxy config back;
    notify BEFORE apply**" —— 即必须先通知(让它把缓存吐干净)再落我们的最终状态,
    否则缓存回写会冲掉刚写的值。而本函数此前恰好相反:
        先 `SetValueEx` 再 `_notify_change()`, 且**零读回**, 写成功即报成功。
    于是同一个风险在"每次点击开启加速"的路径上完全没有防护 —— 若缓存回写冲掉新值,
    程序仍报"已把 PAC 写入系统自动配置脚本", 而系统代理实际没变, 用户只会看到"没反应"。

    现在改为: 通知 → 写 → **同一句柄回读** → 不符则重试一次 → 仍不符**如实返回失败**。
    与本项目另两处教训同源 (certutil -delstore、NRPT cmdlet): 绝不把"命令没报错"当成"已生效"。

    :return: (是否成功, 面向用户的消息)
    """
    if sys.platform != "win32":
        return False, "非 Windows 平台, 不支持系统代理设置"
    if not url or not url.lower().startswith(("http://", "https://")):
        return False, f"PAC 地址必须是 http(s) URL: {url!r}"
    winreg = _winreg()
    try:
        bad = ""
        for attempt in (1, 2):
            # ⚠ 先通知、后写 (见 docstring)。重试时会再通知一次, 这是刻意的:
            #   重试的前提正是"上一次的写入被缓存回写冲掉了", 需要它再吐一次。
            _notify_change()
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _SETTINGS_KEY, 0,
                                    winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, url)
            cur = _readback_with(winreg).get("AutoConfigURL")
            got = cur[0] if cur else None
            if got == url:
                return True, (f"已把 PAC 写入系统「自动配置脚本」: {url} (无需管理员)"
                              + ("" if attempt == 1 else f" (第 {attempt} 次尝试才生效)"))
            # 文案与 restore() 的 _mismatch 同款: 指明是哪个值、期望什么、实际什么
            bad = f"AutoConfigURL 未写成 (期望 {url!r}, 实际 {got!r})"
        return False, (f"写入自动配置脚本**未真正生效** (命令未报错但回读不符): {bad}")
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

    def _failure(surviving: list) -> Tuple[bool, str]:
        return False, ("系统代理还原**未真正生效** (命令未报错但回读不符): "
                       + "; ".join(surviving))

    def _reg_delete_fallback() -> Tuple[bool, str]:
        r"""兜底: 用**独立进程** reg.exe 清除 AutoConfigURL

        ## ★ 为什么这段此前是死代码, 以及它此前为什么即使被跑到也没用 (2026-10-03 定因)

        ① **不可达**: 它原先写在 `except Exception` 的 `return` 之后, 属于同一个 try 的
           handler 体内 —— 前面已经 return, 这段永远不执行; 而紧随其后的第二个
           `except Exception` 也永不匹配 (前一个已吃掉 Exception)。
           提交 `c6d80ab`/`a2fbf9f` 把它称作"**已证实可用的最终保险**", 实际上从未跑过。
        ② **即使跑到也无效**: key 字面量原先写成 HKCU 前缀再加两个反斜杠, 而 Python
           里那两个反斜杠求值为**两个**反斜杠, 拼出的 key 是 `HKCU\\Software\...` ——
           实测 `reg query` 直接回 `ERROR: Invalid key name.`。而那时又用
           `except Exception: pass` 吞掉一切且**不看返回码** ⇒ 静默什么都没删。
           一个失效的保险被当成有效保险, 比"没有保险"更危险。

        现在: 正确的单反斜杠前缀 + 检查 returncode + 回读确认。
        ⚠ 测试必须 patch `subprocess.run`, 否则这条路径会真的改开发者自己的注册表。
        """
        _notify_change()          # 同上: 先让它回写, 再删
        try:
            # ⚠ reg.exe 要**完整的 hive 前缀**, 而 _SETTINGS_KEY 是 winreg 的相对路径
            #   —— 少了 HKCU\ 会静默什么都不做 (reg 返回非零但不抛异常)。
            proc = subprocess.run(["reg", "delete", "HKCU\\" + _SETTINGS_KEY,
                                   "/v", "AutoConfigURL", "/f"],
                                  capture_output=True, timeout=5, shell=False,
                                  **get_silent_startup_kwargs())
        except Exception as e:
            return False, f"reg.exe 兜底清除失败: {type(e).__name__}: {e}"
        # 删除"值不存在"时 reg 也返回非零, 那种情况不是错误 —— 由回读定论。
        falling = _mismatch(_readback())
        if not falling:
            return True, "系统代理设置已还原 (经 reg.exe 兜底清除)"
        detail = getattr(proc, "returncode", None)
        return False, (f"reg.exe 兜底清除后回读仍不符 (reg 退出码 {detail}): "
                       + "; ".join(falling))

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
    except Exception as e:
        return False, f"还原系统代理设置失败: {type(e).__name__}: {e}"

    # ★ 兜底在正常路径之外 —— 只有"两轮回读仍不符"才走到这里 (原先它被 return 挡住)。
    #   reg.exe 是独立进程, 不共享本进程的注册表视图, 实测能清除; 但只在
    #   AutoConfigURL 仍残留时才值得走 (其它值它清不了)。
    if any(str(s).startswith("AutoConfigURL") for s in surviving):
        ok_fb, msg_fb = _reg_delete_fallback()
        if ok_fb:
            return True, msg_fb
        return False, msg_fb
    return _failure(surviving)


def is_pointing_at(url: str) -> bool:
    """当前自动配置脚本是否正指向给定地址 (用于状态判定)"""
    cur = read_current()
    v = (cur.get("values") or {}).get("AutoConfigURL")
    return bool(v) and str(v[0]).strip() == str(url).strip()


def is_our_pac_url(url: Any) -> bool:
    """该 AutoConfigURL 是否**看起来是我们写的** (回环地址 + proxy.pac)

    ★ 抽出来是为了让"清理遗留"这条路径也能用**同一条判据** (见 clear_autoconfig_url 的说明)。
    为什么不用精确比对 `pac.pac_url()`: PAC 服务端口可能变 (测试/回退/端口冲突),
    而"回环 + proxy.pac"这组特征足以识别"这是我们这一族的产物" —— 与本项目
    `restore_system_proxy_if_needed` 里既有的判断逐字一致 (不引入第二套标准)。
    """
    s = str(url or "").strip()
    return bool(s) and "127.0.0.1" in s and "proxy.pac" in s


def clear_autoconfig_url() -> Tuple[bool, str]:
    """**只**清除 `AutoConfigURL` 这一个值 (绝不碰用户另外三个值)

    ## ★★ 为什么必须有这个函数 (2026-10-03 实机踩到, 属"补充修复")

    实机测试里出现了这样一幕: 打包程序崩溃/被强杀后, 注册表里只剩下
    `AutoConfigURL` 指向我们**已死**的本地 PAC, 而落盘备份也丢了。
    应用自己的恢复入口 `redirect_manager.restore_system_proxy_if_needed()` 走到
    "没有备份, 但值仍在" 那条分支 —— 它调的是

        proxy_settings.restore({"values": {}})

    而 `restore()` 的语义是"把系统代理**整体**还原成 `values` 描述的状态":
    传空集 ⇒ 把 `_BACKUP_VALUES`(**四个**值: AutoConfigURL / ProxyEnable /
    ProxyServer / ProxyOverride) **全部删除**。

    实测后果: 用户原本设着 `ProxyServer=127.0.0.1:7897` (他唯一的代理出口)
    与 `ProxyEnable`, 只因为"我们没有他的备份", 就被连同 AutoConfigURL 一起删掉了 ——
    而函数**返回成功**, 文案还是"系统代理设置已还原"。
    `ProxyServer` 与我们的 PAC 毫无关系, 删它属于**超出授权范围**。

    正确口径: "清理我们自己留下的东西" 这条路径**只能删 AutoConfigURL**;
    要动另外三个值, 唯一正当依据是**用户原值的备份** (那才走 `restore(backup)`)。

    实现上有意复用 `restore()` 的定因结论 (先 notify 后写、写完回读、不符则 reg 兜底),
    但作用域收敛到单个值。
    """
    if sys.platform != "win32":
        return True, "非 Windows 平台, 无需清理"
    winreg = _winreg()
    try:
        surviving: list = []
        for attempt in (1, 2):
            # 与 restore() 同因: WinINET 的自动配置缓存会在**刷新时把值写回注册表**,
            # 所以必须先通知 (让它把缓存吐完) 再删, 且删完要回读。
            _notify_change()
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _SETTINGS_KEY, 0,
                                    winreg.KEY_SET_VALUE) as k:
                try:
                    winreg.DeleteValue(k, "AutoConfigURL")
                except FileNotFoundError:
                    pass
            now = _readback_with(winreg)
            surviving = [] if "AutoConfigURL" not in now else [
                f"AutoConfigURL 未删除 (仍为 {now['AutoConfigURL'][0]!r})"]
            if not surviving:
                return True, ("已清除本程序写入的系统「自动配置脚本」"
                              + ("" if attempt == 1 else f" (第 {attempt} 次尝试才生效)"))
        # 兜底: 独立进程 reg.exe (不共享本进程的注册表视图)
        _notify_change()
        try:
            proc = subprocess.run(["reg", "delete", "HKCU\\" + _SETTINGS_KEY,
                                   "/v", "AutoConfigURL", "/f"],
                                  capture_output=True, timeout=5, shell=False,
                                  **get_silent_startup_kwargs())
        except Exception as e:
            return False, f"清除自动配置脚本失败: {type(e).__name__}: {e}"
        now = _readback_with(winreg)
        if "AutoConfigURL" not in now:
            return True, "已清除系统「自动配置脚本」(经 reg.exe 兜底)"
        return False, (f"清除自动配置脚本**未真正生效** (reg 退出码 "
                       f"{getattr(proc, 'returncode', None)}): "
                       f"AutoConfigURL 仍为 {now['AutoConfigURL'][0]!r}")
    except Exception as e:
        return False, f"清除自动配置脚本失败: {type(e).__name__}: {e}"
