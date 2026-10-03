# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 域名重定向后端分派层 (Hosts / NRPT)

设计目标: 让"加速域名的解析劫持"成为可切换的后端, 而上层 (GUI / 看门狗 / 生命周期)
只面向统一语义, 不必关心底层是写 Hosts 文件还是写 NRPT 策略表。

后端语义对比:
  hosts 后端: 逐域名写 "127.0.0.1 域名" 到系统 Hosts, 精确匹配, 无需额外端口;
              但会改动系统文件, 且 Windows 新版对 Hosts 的权限与杀软拦截较敏感。
  nrpt  后端: 写 Windows NRPT 命名空间规则, 把命中域名的 DNS 查询导向本机解析器
              (127.0.0.1:53), 不碰 Hosts 文件, 且后缀匹配天然覆盖整个子域;
              代价是必须提权 + 独占 53/UDP + 要求本机解析器常驻。

任何一步失败都可回退 Hosts (由 nrpt_auto_fallback 控制), 保证"加速可用"永远优先于
"后端新潮" —— 回退原因会写入 state["note"] 供界面与日志展示, 不做静默降级。
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hosts_manager import build_domain_targets
from service_profile import ServiceMode, get_profile_by_domain
from nrpt_manager import NRPT_DNS_PORT, NRPT_NAME_SERVER, NrptManager
from pac_redirect import PacRedirectManager
import proxy_settings
from win_utils import ProxyBypassManager

MODE_HOSTS = "hosts"
MODE_NRPT = "nrpt"
# PAC + 本地 CONNECT 转发: 把通配表达在 PAC 的 JS 里, 由本机转发器把隧道对到 nginx。
# 免管理员 / 不写注册表 / 不占 53 / 不改系统 DNS (见 app/pac_redirect.py)。
# 定位: 面向用户的**正式无管理员方案**; nrpt 保留为测试/高级手段。
MODE_PAC = "pac"
# pac_auto: 同样用 PAC 表达通配, 但**不由程序拉起浏览器**, 而是把 PAC 地址写进
# Windows 用户级「自动配置脚本」(WinINET AutoConfigURL): 不需要管理员、
# 不出现"由贵单位管理"横幅、覆盖所有沿用系统代理的应用, 且实测**运行中的浏览器
# 会当场采用**(写入后调用 InternetSetOption 通知系统)。见 app/proxy_settings.py。
MODE_PAC_AUTO = "pac_auto"

# 持久化备份用的配置键。**为什么必须落盘而不是只放内存** (2026-10-02):
# pac_auto 会改用户的**系统代理设置**。若只把原值放在内存里, 进程一旦被强杀/崩溃,
# 备份随之丢失, 用户的系统代理就被永久改成了我们的 PAC —— 那等于替用户改掉了上网方式,
# 且他本人无从恢复。落盘后, 下次启动的 cleanup_orphans 能把它还原回去。
_CFG_PROXY_BACKUP = "proxy_settings_backup"


def _persist_proxy_backup(backup: dict) -> bool:
    """把用户原有代理设置落盘; 返回**是否真的写进去了**

    ★ 必须返回 bool (2026-10-03 定因): 原实现整体 `except: pass` 而调用方无条件
    `state["proxy_backup_saved"] = True` 并对外宣称"已自动备份并还原原有代理设置" ——
    备份没落盘也报成功, 等于把"可恢复"这个承诺建立在一次静默失败的写入上。
    """
    try:
        from config_store import load_config, save_config
        cfg = load_config() or {}
        cfg[_CFG_PROXY_BACKUP] = backup
        return bool(save_config(cfg))
    except Exception:
        return False


def _load_proxy_backup():
    try:
        from config_store import load_config
        return (load_config() or {}).get(_CFG_PROXY_BACKUP)
    except Exception:
        return None


def _clear_proxy_backup() -> None:
    try:
        from config_store import load_config, save_config
        cfg = load_config() or {}
        if _CFG_PROXY_BACKUP in cfg:
            cfg.pop(_CFG_PROXY_BACKUP, None)
            save_config(cfg)
    except Exception:
        pass


def restore_system_proxy_if_needed() -> Tuple[bool, str]:
    """若系统代理仍指向我们的 PAC, 按落盘备份还原 (启动时与清理时都调用)

    三种情况都要处理, 且都要**幂等**:
      1. 正常退出: 有备份 -> 还原并清除备份;
      2. 上次被强杀: 有备份 -> 还原 (这正是落盘的意义);
      3. 备份也丢了但 AutoConfigURL 仍指向本机 PAC 端口 -> 至少把它删掉,
         否则用户的浏览器会把所有流量送进一个可能已不存在的本地代理。
    """
    try:
        cur = proxy_settings.read_current()
    except Exception as e:
        return False, f"读取系统代理失败: {e}"
    auto = ((cur.get("values") or {}).get("AutoConfigURL") or [None])[0]
    backup = _load_proxy_backup()
    if not auto and not backup:
        return True, "系统代理无需还原"

    # ★ 有备份时也必须有"现值是否仍是我们写的"这道判据 (2026-10-03 定因)。
    #   原实现: `if backup:` 就无条件 restore —— 而下面"没有备份"的分支反而有守卫
    #   ("只清理指向本机 PAC 的那种, 绝不乱动用户自设的其它 PAC")。
    #   同一个函数里两种标准, 后果是: 用户在我们运行期间**自己改过**代理设置(或换了网络、
    #   被别的工具改过)之后, 我们一退出就照旧按旧备份**覆盖回去**, 把用户的新设置抹掉 ——
    #   等于替用户改上网方式, 与"系统代理是用户自己的设置"这条自我约束直接冲突。
    #   判据用 proxy_settings.is_pointing_at() (此前定义了却无人调用的死代码, 见 M11)。
    still_ours = False
    try:
        if auto:
            still_ours = ("127.0.0.1" in str(auto) and "proxy.pac" in str(auto))
    except Exception:
        still_ours = False

    if backup:
        if not still_ours:
            # 现值已不是我们的 PAC: 用户(或其他程序)改过。清掉过期备份, 不动注册表。
            _clear_proxy_backup()
            return True, f"系统代理已被改动 (现为 {auto or '空'}), 不是本项目的 PAC, 不动它"
        ok, msg = proxy_settings.restore(backup)
        if ok:
            _clear_proxy_backup()
        return ok, msg
    # ★★ 这条分支**只能清 AutoConfigURL 一个值** (2026-10-03 实机踩到, 属"补充修复")
    #
    # 原先这里调的是 `proxy_settings.restore({"values": {}})` —— 而 restore() 的语义是
    # "把系统代理**整体**还原成 values 描述的状态", 传空集就等于把**四个值全删**
    # (AutoConfigURL / ProxyEnable / ProxyServer / ProxyOverride)。
    #
    # 实机后果 (我本人复现): 用户原本设着 ProxyServer=127.0.0.1:7897 (他唯一的代理出口)
    # 与 ProxyEnable, 只因为"我们没有他的备份", 就被连同 AutoConfigURL 一起删掉,
    # 而函数**返回成功**、文案还写"系统代理设置已还原"。
    # ProxyServer 跟我们的 PAC 毫无关系 ⇒ 这是**超出授权范围地改用户的联网方式**。
    #
    # 现在: 清理路径只删自己的那一个值; 要动另外三个, 唯一正当依据是**用户原值的备份**
    # (那条走上方的 restore(backup))。
    if still_ours:
        ok, msg = proxy_settings.clear_autoconfig_url()
        return ok, f"检测到上次遗留的本地 PAC 设置, 已清除 ({auto})" + ("" if ok else f" — {msg}")
    return True, "系统代理指向的不是本项目的 PAC, 不动它"

DEFAULT_DNS_PORT = 5353

# 不经本机代理的画像模式 (与 nginx_generator.NGINX_BYPASS_MODES 同源判据):
# DIRECT 由 hosts/DNS 直接钉真实 CDN IP; QUIC_DIRECT 由 DNS 下发 HTTPS RR 让浏览器自走 QUIC。
# 两者在 nginx 侧都没有 server 块 ⇒ 交给 PAC 只会落到默认 server 拿到不相干的内容。
_PAC_BYPASS_MODES = (ServiceMode.DIRECT, ServiceMode.QUIC_DIRECT)

_NRPT = NrptManager()
_PAC = PacRedirectManager()


def normalize_mode(cfg: Optional[Dict[str, Any]]) -> str:
    """归一化重定向后端配置, 非法值一律视作 Hosts (保持历史行为)"""
    raw = str((cfg or {}).get("redirect_mode", MODE_HOSTS) or MODE_HOSTS).strip().lower()
    if raw == MODE_NRPT:
        return MODE_NRPT
    if raw == MODE_PAC:
        return MODE_PAC
    if raw == MODE_PAC_AUTO:
        return MODE_PAC_AUTO
    return MODE_HOSTS


def default_dns_port(cfg: Optional[Dict[str, Any]] = None) -> int:
    """本机解析器的默认监听端口 (NRPT 模式以外的场景)"""
    try:
        return int((cfg or {}).get("dns_listen_port", DEFAULT_DNS_PORT) or DEFAULT_DNS_PORT)
    except Exception:
        return DEFAULT_DNS_PORT


def _restore_bypass(domains: List[str]):
    """回环劫持的域名不应再走系统代理, 保持 WinINet 例外列表同步"""
    try:
        ProxyBypassManager.apply_bypass(domains)
    except Exception:
        pass


def _clear_bypass():
    try:
        ProxyBypassManager.restore_bypass()
    except Exception:
        pass


def pac_redirectable_domains(services: List[str]) -> List[str]:
    """由启用服务推导**该交给 PAC/代理处理**的域名 (原缺陷 H6)

    ## 为什么不能直接用 `build_domain_targets(...).keys()`

    `build_domain_targets` 对 `DIRECT` / `QUIC_DIRECT` 画像会算出"**钉真实 CDN IP**"
    的决策 (见 hosts_manager 的推导), 而那两个模式在 nginx 侧被 `NGINX_BYPASS_MODES`
    排除 —— **没有 server 块**。原实现把 `.keys()` 直接交给 PAC, 于是这些域名被
    送进本地代理, 却又没有站点承载它们 ⇒ 落到默认 server (H5/H5′), 得到**不相干的内容**。

    对照: DNS 后端 (`dns_server._resolve_local_entry`) 是**尊重** `profile.mode` 的
    (`QUIC_DIRECT` 走向上游解析、`DIRECT` 返回真实 CDN IP), PAC 分支原先不尊重。
    这里补齐这条对称性 —— 判据取自画像本身, 与 DNS 层同源。

    `reddit_static` 就是活例子: `mode=ServiceMode.DIRECT`(注释写"只钉真实 IP, 不经本机
    反代")且**默认启用**, 所以这条路径在日常使用里必然被走到。
    """
    out: List[str] = []
    for d in sorted(build_domain_targets(services).keys()):
        try:
            profile = get_profile_by_domain(d)
        except Exception:
            profile = None
        if profile is not None and getattr(profile, "mode", None) in _PAC_BYPASS_MODES:
            continue
        out.append(d)
    return out


def _pac_fallback_directive_safe() -> str:
    """取用户既有代理设置的 PAC 兜底指令; 任何异常都退化为 DIRECT

    为什么单独抽出来: `pac.start(..., fallback=...)` 有**两个**调用方
    (apply_redirect 与 GUI 的"以 PAC 启动浏览器"), 原实现只有前者传了 fallback,
    后者用默认值 DIRECT ⇒ 点那个按钮会把**系统级生效的 PAC** 悄悄换成 DIRECT 兜底版,
    把用户自己的固定代理旁路掉 (实测事故 b1693ed: 用户代理收到的 CONNECT 数为 0)。
    """
    try:
        return proxy_settings.pac_fallback_directive() or "DIRECT"
    except Exception:
        return "DIRECT"


def apply_redirect(cfg: Dict[str, Any], services: List[str], hosts, nrpt=None,
                   dns=None, state: Optional[Dict[str, Any]] = None,
                   pac_mgr=None) -> Tuple[bool, str]:
    """
    按配置应用域名重定向

    :param hosts: HostsManager 实例 (由调用方传入, 保留测试注入点)
    :param nrpt:  NrptManager 实例, 缺省用模块级单例
    :param dns:   LocalDnsServer 实例, NRPT 后端需要它接管 53 端口
    :param state: 输出字典, 记录实际生效的后端 / 是否回退 / 回退原因
    :return: (是否成功, 面向用户的消息)
    """
    state = state if state is not None else {}
    nrpt = nrpt or _NRPT
    mode = normalize_mode(cfg)
    domains = sorted(build_domain_targets(services).keys())
    state["mode"] = mode
    state["domain_count"] = len(domains)

    if is_pac_mode(mode):   # 族查询, 不写死成员 (见 is_pac_mode docstring)
        # PAC 分支: 域名表交给 PAC 后端 (它把通配表达在 PAC 的 JS 里)。
        # 与 NRPT 分支一样, **同时清掉 Hosts 规则** —— Hosts 优先级高于代理之前的解析,
        # 残留会让部分域名绕过本后端, 造成"有的能开有的不能"的错乱。
        #
        # ★ 域名表必须先按 `profile.mode` 过滤 (2026-10-03 定因, 原缺陷 H6):
        #   DIRECT / QUIC_DIRECT 的画像在 nginx 侧**没有 server 块**, 交给 PAC 只会把它们
        #   送进本地代理再落到默认 server —— 那正是"静默错内容"。见 pac_redirectable_domains。
        pac_domains = pac_redirectable_domains(services)
        state["pac_domain_count"] = len(pac_domains)
        pac = pac_mgr or _PAC
        # 兜底必须复现用户既有代理设置: PAC 优先于固定代理, 一律返回 DIRECT 会把
        # 用户自己的代理整个旁路掉 (实测其 CONNECT 数为 0)。
        _fb = _pac_fallback_directive_safe()
        ok, msg = pac.start(pac_domains, fallback=_fb)
        if not ok:
            # ★ 这里**刻意不回退 Hosts**: Hosts 表达不了通配, 回退后动态节点名依然不被劫持
            # —— 那正是本项目一直在消除的"假可用"(界面显示已加速, 实际视频永远转圈)。
            # NRPT 分支可以回退, 是因为 Hosts 至少能覆盖那批**精确**域名; PAC 失败则说明
            # 本地端口不可用, 此时任何"看起来成功"的兜底都是误导。
            state.update({"backend": None, "fell_back": False, "note": msg})
            return False, f"PAC 后端不可用: {msg}"
        try:
            hosts.remove_rules()
        except Exception:
            pass
        _restore_bypass(domains)
        state.update({"backend": mode, "fell_back": False, "note": "",
                      "pac_url": pac.pac_url()})

        if mode == MODE_PAC_AUTO:
            # 把 PAC 写进系统「自动配置脚本」: 不需管理员、不需程序拉起浏览器,
            # 且实测运行中的浏览器会当场采用 (写入后已通知系统)。
            # ⚠ 写入前**必须备份**用户原有代理设置, 并持久化 —— 否则进程被强杀后
            #    备份随内存丢失, 用户的系统代理就被我们永久改掉了。
            #
            # ★★ "已备份过就不再备份" 这道守卫是必须的 (2026-10-03 定因) ——
            #    `_apply_redirect` 在**每次**服务开关/后端切换时都会被调用, 而第一次
            #    apply 之后 AutoConfigURL 已经指向**我们自己的** PAC。若第二次 apply
            #    无条件 read_current(), 它读到的"用户原值"其实就是我们自己写的值 ——
            #    于是落盘备份被污染成"用户的 PAC = 我们的 PAC"; 退出时把它写回注册表,
            #    用户**原有的 AutoConfigURL 永久丢失** (随后 _clear_proxy_backup 还会
            #    删掉唯一的证据)。更糟的是若回读恰好"成功", 这个坏状态会被固化, 下次
            #    启动又用同一份污染备份再写一遍。
            #    这正是 proxy_settings.py 注释写明要避免的事, 所以守卫必须在这里。
            backup = _load_proxy_backup()
            if backup is None:
                cur = proxy_settings.read_current()
                # 备份丢失但注册表已指着我们 (上次被强杀) 时, 不能把"我们自己的值"
                # 当用户原值 —— 记成空集, 让还原走"删除"这条路 (用户原本没有 PAC 时
                # 正确; 他原本有 PAC 时那份原值早在第一次 apply 时就被备份了, 且因
                # 上面的守卫从未被覆盖过)。
                try:
                    if proxy_settings.is_pointing_at(pac.pac_url()):
                        cur = {"exists": bool(cur.get("exists")), "values": {}}
                except Exception:
                    pass
                backup = cur
            ok2, msg2 = proxy_settings.set_autoconfig_url(pac.pac_url())
            if not ok2:
                pac.stop()
                state.update({"backend": None, "fell_back": False, "note": msg2})
                return False, f"无法写入系统自动配置脚本: {msg2}"
            saved = _persist_proxy_backup(backup)
            state["proxy_backup_saved"] = saved
            if not saved:
                # 备份没落盘 ⇒ 不得宣称"已自动备份": 强杀后就无法还原用户的代理设置了。
                return True, (f"{msg}; {msg2}; ⚠ **原有代理设置未能落盘备份**"
                              f"(配置文件写入失败) —— 退出时仍会尝试还原, 但若进程被强杀"
                              f"则无法恢复, 建议尽快正常退出。")
            return True, (f"{msg}; {msg2}; 已自动备份并还原原有代理设置。"
                          f"用浏览器直接打开即可 (若个别浏览器未生效, 重启该浏览器)。")

        return True, (f"{msg}; 请以 `--proxy-pac-url={pac.pac_url()}` 启动浏览器"
                      f" (界面上的『以 PAC 启动浏览器』已代为处理)")

    if mode != MODE_NRPT:
        ok, msg = hosts.apply_rules(services)
        state.update({"backend": MODE_HOSTS, "fell_back": False, "note": ""})
        return ok, msg

    caps = nrpt.capabilities()
    state["capabilities"] = caps

    def _fallback(reason: str) -> Tuple[bool, str]:
        if not cfg.get("nrpt_auto_fallback", True):
            state.update({"backend": None, "fell_back": False, "note": reason})
            return False, f"NRPT 模式不可用: {reason}"
        ok_h, msg_h = hosts.apply_rules(services)
        state.update({"backend": MODE_HOSTS, "fell_back": True, "note": reason})
        if not ok_h:
            return False, msg_h
        return True, f"{msg_h} [NRPT 不可用已回退 Hosts: {reason}]"

    # 前置条件不满足 (非管理员 / 53 被占用 / 系统不支持) → 直接回退
    if not caps.get("ready"):
        return _fallback(caps.get("reason", "前置条件不满足"))

    # 1) 本机解析器接管 53 端口 (按探测结果选择地址族: IPv4 被占时改绑 ::1 共存)
    name_server = (caps.get("port53") or {}).get("name_server") or NRPT_NAME_SERVER
    if dns is not None:
        ok, msg = dns.ensure_bind(NRPT_DNS_PORT, host=name_server)
        if not ok:
            return _fallback(f"本机解析器无法监听 {name_server}:{NRPT_DNS_PORT} ({msg})")

    # 2) 写入 NRPT 规则 (NameServers 与解析器实际监听地址保持一致)
    ok, msg = nrpt.apply(domains, name_server=name_server)
    if not ok:
        if dns is not None:
            try:
                dns.stop()
                dns.set_port(None)
            except Exception:
                pass
        return _fallback(msg)

    # 3) 清除 Hosts 规则: Hosts 优先级高于 DNS, 残留会静默掩盖 NRPT 并造成双份残留
    try:
        hosts.remove_rules()
    except Exception:
        pass
    # 4) 保留系统代理例外
    _restore_bypass(domains)

    _family_note = ""
    if (caps.get("port53") or {}).get("family") == "ipv6":
        _family_note = " (IPv4 53 被代理占用, 已改用 IPv6 回环共存)"
    state.update({"backend": MODE_NRPT, "fell_back": False, "note": "",
                  "name_server": name_server})
    return True, f"{msg}, 已接管 {len(domains)} 个加速域名{_family_note}"


def remove_redirect(cfg: Dict[str, Any], hosts, nrpt=None, dns=None,
                    state: Optional[Dict[str, Any]] = None,
                    pac_mgr=None) -> Tuple[bool, str]:
    """幂等清理两种后端的全部残留, 并恢复本机解析器的默认端口。

    两个后端都清理而非只清当前模式: 用户切换后端、异常退出、旧版本残留等场景下,
    只清其一会留下"域名指向 127.0.0.1 但没有服务应答"的死解析。
    """
    state = state if state is not None else {}
    nrpt = nrpt or _NRPT
    pac = pac_mgr or _PAC
    ok_all = True
    messages: List[str] = []

    # PAC 后端必须先停: 它持有两个监听端口 (隧道 + PAC 服务), 残留端口会让下次启动
    # 撞上"端口被占用", 而且旧 PAC 可能仍在把浏览器流量导向本机。
    try:
        _r_ok, _r_msg = restore_system_proxy_if_needed()
        if _r_msg and "无需" not in _r_msg and "不动它" not in _r_msg:
            messages.append(_r_msg)
    except Exception as e:
        ok_all = False
        messages.append(f"系统代理还原异常: {e}")

    try:
        if pac.running:
            ok, msg = pac.stop()
            ok_all = ok_all and ok
            messages.append(msg)
    except Exception as e:
        ok_all = False
        messages.append(f"PAC 后端清理异常: {e}")

    try:
        ok, msg = hosts.remove_rules()
        ok_all = ok_all and ok
        if msg:
            messages.append(msg)
    except Exception as e:
        ok_all = False
        messages.append(f"Hosts 清理异常: {e}")

    try:
        if nrpt.is_supported() and nrpt.is_applied():
            ok, msg = nrpt.remove_all()
            ok_all = ok_all and ok
            messages.append(msg)
    except Exception as e:
        ok_all = False
        messages.append(f"NRPT 清理异常: {e}")

    if dns is not None:
        try:
            if dns.port == NRPT_DNS_PORT:
                dns.stop()
                dns.set_port(None)
                if cfg.get("dns_mode_enabled", True):
                    dns.start()
                messages.append("本机解析器已恢复默认监听端口")
        except Exception as e:
            messages.append(f"解析器端口恢复异常: {e}")

    if not messages:
        messages.append("无残留重定向规则")

    state.update({"backend": None, "fell_back": False, "note": ""})
    return ok_all, "; ".join(messages)


def fast_remove_redirect(cfg: Dict[str, Any], hosts, nrpt=None, dns=None,
                         pac_mgr=None) -> bool:
    """退出/关机通道的快速清理。

    NRPT 规则必须在此清理: 规则残留而本机解析器已退出时, 命中域名的 DNS 查询会被
    定向到一个无人监听的 127.0.0.1:53, 表现为这些域名彻底无法解析 (比 Hosts 残留更
    严重)。因此即使多花一次 PowerShell 调用也必须清掉。
    """
    nrpt = nrpt or _NRPT
    pac = pac_mgr or _PAC
    ok = True
    # PAC 后端同样必须在退出通道停掉: 它持有两个本地监听端口。
    # (它不涉及整机解析, 所以危害不如 NRPT 残留, 但端口残留会让下次启动直接失败。)
    try:
        restore_system_proxy_if_needed()
    except Exception:
        ok = False

    try:
        if pac.running:
            pac.stop()
    except Exception:
        ok = False

    try:
        ok = hosts.fast_remove_rules() and ok
    except Exception:
        ok = False

    try:
        if nrpt.is_supported() and nrpt.is_applied():
            ok_n, _ = nrpt.remove_all(fast=True)
            ok = ok and ok_n
    except Exception:
        ok = False

    if dns is not None:
        try:
            if dns.port == NRPT_DNS_PORT:
                dns.stop()
                dns.set_port(None)
        except Exception:
            pass
    return ok


def _our_redirect_backend_running(cfg: Dict[str, Any], nrpt=None,
                                  pac_mgr=None) -> bool:
    """我们自己的重定向后端是否正在运行 (= 它正持有系统代理设置)

    用途 (缺陷 W1, 2026-10-04): `cleanup_orphans` 的语义是"清理**上一会话**的残留"。
    但 `restore_system_proxy_if_needed()` 原先被放在最前面、且**不看 data_plane_alive**,
    于是**第二份副本启动时会替第一份把系统代理还原掉并清空落盘备份** ——
    而那个设置正是第一份正在使用的。第一份的 `REDIRECT_STATE` 仍报"已生效",
    且备份已删 ⇒ 它之后再也无法正确还原。这就是"两个实例互相拆台"里最直接的一条。

    与 `is_redirect_applied` 用同一组判据, 避免两处各算一套:
      · PAC 家族: 后端实例的 `running` (它不写系统状态, 只能看进程内状态)
      · NRPT:     规则仍装着
    """
    try:
        if is_pac_mode(normalize_mode(cfg)) and (pac_mgr or _PAC).running:
            return True
    except Exception:
        pass
    try:
        if normalize_mode(cfg) == MODE_NRPT:
            _n = nrpt or _NRPT
            return bool(_n.is_supported() and _n.is_applied())
    except Exception:
        pass
    return False


def cleanup_orphans(cfg: Dict[str, Any], hosts, nrpt=None, dns=None,
                    data_plane_alive: bool = False, pac_mgr=None) -> Dict[str, Any]:
    """启动时清理**上一会话遗留**的重定向 (异常退出/被强杀时会残留)

    为什么必须在启动时清 (实测事故): 上一会话在 NRPT 模式下被强杀, 规则残留下来, 而
    本机解析器随进程一起退出 —— 于是规则里那 ~280 个域名在**整机范围**内全部解析失败
    (查询被导向无人监听的 127.0.0.1:53), 且此时用户根本没打算启动加速。Hosts 残留同理
    (指向 127.0.0.1 而 nginx 未运行)。判定口径: 数据平面不存活 + 重定向仍生效 = 孤儿。

    返回 {"cleaned": bool, "detail": str}
    """
    nrpt = nrpt or _NRPT

    # ⚠ `detail` 必须**先**初始化 (2026-10-02 单测抓到): 下面 try/except 的两条分支都写成
    #   `f"{detail}; ..." if detail else ...`, 而 detail 只在**这两行**里被赋值 ——
    #   于是 restore_system_proxy_if_needed() 一旦抛异常, 走 except 分支时 detail 尚未绑定
    #   ⇒ UnboundLocalError。而这是**启动路径**(孤儿残留清理), 一炸就整段清理中断,
    #   用户看到的是"上一会话残留没清掉"而不是真正的异常原因。
    detail = ""
    proxy_msg = ""
    _p_ok = True

    applied_hosts = False
    try:
        applied_hosts = bool(hosts.is_applied())
    except Exception:
        pass

    applied_nrpt = False
    try:
        applied_nrpt = bool(nrpt.is_supported() and nrpt.is_applied())
    except Exception:
        pass

    # ══════════════════════════════════════════════════════════════════════════
    # ★★ 系统代理的还原: 两个条件都必须满足 (2026-10-03 定因 + 2026-10-04 收敛)
    #
    # 条件一 (2026-10-03, 原缺陷 S3): **不能**被"无残留就提前 return"挡住。
    #   原顺序是 `if not (applied_hosts or applied_nrpt): return "无残留"` 之后才还原,
    #   而 pac_auto 分支**故意会删掉 hosts 规则** ⇒ 进程被强杀后的残留恰好是
    #   hosts=False、nrpt=False、而系统代理仍指着我们的 PAC, 命中的正是那个提前 return
    #   ⇒ "上次被强杀 → 按落盘备份还原"这条设计在最典型的中止场景下**从未生效过**。
    #   所以它必须在"无残留"这条 return 之前跑。
    #
    # 条件二 (2026-10-04, 缺陷 W1): **不能**在"另一个实例正持有它"时跑。
    #   原实现只看 `data_plane_alive`, 而 `restore_system_proxy_if_needed()` 在它之前
    #   ⇒ 第二份副本启动时会替第一份还原掉系统代理**并清空落盘备份**(还原成功即
    #   `_clear_proxy_backup()`), 而第一份仍以为自己在生效、且再也无法正确还原。
    #   判据用"我们自己的重定向后端是否在跑"而不是 nginx: PAC 后端不写任何系统状态,
    #   它是否活着只能看进程内状态 —— 而系统代理恰恰是它写的。
    #   (注意: 数据平面存活 ≠ 我们的 PAC 活着。窗口未关而本程序被关掉时, nginx 会按
    #    设计存活, 此时 PAC 已死、系统代理正指着死端口 ⇒ 那正是要还原的场景, 所以
    #    这里**不能**用 data_plane_alive 当判据。)
    # ══════════════════════════════════════════════════════════════════════════
    if _our_redirect_backend_running(cfg, nrpt=nrpt, pac_mgr=pac_mgr):
        proxy_msg = ""
    else:
        try:
            _p_ok, _p_msg = restore_system_proxy_if_needed()
            if _p_msg and "无需" not in _p_msg and "不动它" not in _p_msg:
                proxy_msg = _p_msg
        except Exception as e:
            _p_ok = False
            proxy_msg = f"系统代理还原异常: {e}"

    if not (applied_hosts or applied_nrpt):
        # ⚠ 无残留时 `detail` 必须保持逐字 "无残留" (tests/test_nrpt_manager.py 断言依赖它),
        #   所以系统代理的还原文案走**独立字段** proxy_detail, 不并进 detail。
        return {"cleaned": False, "detail": "无残留", "proxy_detail": proxy_msg,
                "proxy_ok": _p_ok}

    # 走到这里说明**确实看到残留**, 才轮到"数据平面存活 ⇒ 视为本会话状态不动它"这条守卫。
    # 它守的是残留删除 (hosts/NRPT 规则), 而不是系统代理还原 —— 后者已经在上一步按
    # "我们的后端是否正持有它"独立判过了 (缺陷 W1)。两者判据不同、归属不同, 不能混用。
    if data_plane_alive:
        return {"cleaned": False, "detail": "数据平面存活, 视为本会话状态, 不做清理",
                "proxy_detail": proxy_msg, "proxy_ok": _p_ok}

    ok = fast_remove_redirect(cfg, hosts, nrpt, dns)
    parts = []
    if applied_hosts:
        parts.append("Hosts")
    if applied_nrpt:
        parts.append("NRPT")
    detail = (f"已清理上一会话遗留的 {'/'.join(parts)} 重定向残留"
              if ok else f"{'/'.join(parts)} 残留清理未完全成功 (删除 NRPT 规则需管理员权限)")
    # ★ 系统代理还原的结果**不得**被上面的赋值吞掉 (2026-10-03 定因): 原实现里
    #   `detail` 在这两行被**无条件覆盖**, 于是"系统代理还原失败"的文案被丢弃,
    #   随后 `ok=True` 还会清掉 last_cleanup_warning —— 用户永远不会知道
    #   他的系统代理没被还原回来。
    if proxy_msg:
        detail = f"{detail}; {proxy_msg}"

    # 结果落盘: 下次启动要在界面上明确告知用户, 而不是让他自己去猜为什么上不了网
    try:
        from config_store import load_config as _load, save_config as _save
        _cfg = _load()
        if ok and not proxy_msg:
            _cfg.pop("last_cleanup_warning", None)
        else:
            import time as _time
            _cfg["last_cleanup_warning"] = {"ts": int(_time.time()), "detail": detail}
        _save(_cfg)
    except Exception:
        pass

    return {"cleaned": True, "ok": ok, "detail": detail,
            "proxy_detail": proxy_msg, "proxy_ok": _p_ok,
            "had_hosts": applied_hosts, "had_nrpt": applied_nrpt}


def is_pac_mode(mode: str) -> bool:
    """该后端是否属于 **PAC 家族** (pac / pac_auto) —— 请一律用它, 不要写 `== MODE_PAC`

    为什么必须抽出来 (2026-10-02 用户实测, 一次真实回归):
      `is_redirect_applied()` 原先写的是 `normalize_mode(cfg) == MODE_PAC`, **漏了
      pac_auto**。而 pac_auto 分支会**故意清掉 hosts 规则**(Hosts 优先于 PAC, 残留会造成
      "有的能开有的不能"), 于是:
        · `hosts.is_applied()` → False
        · `normalize_mode(cfg) != MODE_NRPT` → 直接 return False
      ⇒ 判定为"未生效", 尽管 PAC 后端在跑、AutoConfigURL 也已写入。
      后果就是用户在界面上看到的:**点"开启加速"永远只能再开一次**, 按钮与状态条不变化
      —— 因为 `toggle_acceleration()` 每次都认为"当前没开"。
      与 `wildcard_capable()` 同一手法: 判据写成**能力/族查询**, 新增同族后端时
      不必回头改每一处比较点。
    """
    return str(mode or "").strip().lower() in (MODE_PAC, MODE_PAC_AUTO)


def is_redirect_applied(cfg: Dict[str, Any], hosts, nrpt=None,
                        pac_mgr=None) -> bool:
    """判定重定向是否处于生效状态 (任一后端生效即为真, 兼容 NRPT 回退 Hosts 的场景)

    `pac_mgr` 与 `apply_redirect` 的注入点对称: 测试或调用方若使用了自定义实例,
    此处也必须查同一个实例, 否则会报"未生效"而实际后端在跑 (两边各查各的 = 假状态)。
    """
    # PAC 后端以"两个监听端口都在"为准 (它不写任何系统状态, 所以只能看进程内状态)
    # ⚠ 必须用 is_pac_mode(): 只写 == MODE_PAC 会把 pac_auto 漏掉 —— 见其 docstring。
    if is_pac_mode(normalize_mode(cfg)) and (pac_mgr or _PAC).running:
        return True

    try:
        if hosts.is_applied():
            return True
    except Exception:
        pass

    if normalize_mode(cfg) != MODE_NRPT:
        return False

    nrpt = nrpt or _NRPT
    try:
        return bool(nrpt.is_applied())
    except Exception:
        return False


def _cli():
    """清理 CLI: 供异常退出后手动回收残留 (删 NRPT 规则需管理员权限)

    用法:
        python -m app.redirect_manager --status    # 只读查看当前重定向状态
        python -m app.redirect_manager --remove    # 清理 Hosts + NRPT 残留并释放 53
    """
    import argparse
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent))

    ap = argparse.ArgumentParser(description="域名重定向 (Hosts / NRPT) 状态与残留清理")
    ap.add_argument("--status", action="store_true", help="只读查看当前重定向状态")
    ap.add_argument("--remove", action="store_true", help="清理全部重定向残留并释放 53 端口")
    args = ap.parse_args()

    from config_store import load_config
    from hosts_manager import HostsManager
    from dns_server import local_dns_server
    try:
        from nrpt_manager import NrptManager
        nrpt_mgr = NrptManager()
    except Exception as e:
        print(f"  (NRPT 后端不可用: {e})")
        nrpt_mgr = None
    hosts_mgr = HostsManager()

    cfg = load_config()
    if args.status or not args.remove:
        print(f"重定向模式      : {normalize_mode(cfg)}")
        print(f"Hosts 是否生效  : {hosts_mgr.is_applied()}")
        if nrpt_mgr is not None:
            caps = nrpt_mgr.capabilities()
            rules = nrpt_mgr.list_own_rules() if caps.get("supported") else []
            print(f"NRPT 支持/管理员: {caps.get('supported')} / {caps.get('admin')}")
            port = caps.get("port53", {}) or {}
            print(f"NRPT 自有规则数 : {len(rules)}")
            fam = port.get("family") or "-"
            if port.get("available"):
                print(f"53 端口         : 可用 (推荐 NameServer {port.get('name_server')} / {fam})")
                if fam == "ipv6":
                    print(f"                  说明: {port.get('note')}")
            else:
                print(f"53 端口         : IPv4 与 IPv6 均被占用: {port.get('owner')}")
                print("                  说明: NRPT 目标端口固定为 53; 请先关闭代理的 DNS 接管")
            if rules:
                print("  提示: 规则存在而本机解析器未监听 53 时, 命中域名将无法解析, 请执行 --remove")
        if not args.remove:
            return 0

    res = fast_remove_redirect(cfg, hosts_mgr, nrpt_mgr, local_dns_server)
    port = nrpt_mgr.port53_status(force=True) if nrpt_mgr is not None else {}
    print(f"清理结果: {'成功' if res else '未完全成功 (NRPT 删除需管理员权限)'}")
    print(f"Hosts 残留: {hosts_mgr.is_applied()} | 53 端口: "
          f"{'可用' if port.get('available') else '仍被占用: ' + str(port.get('owner'))}")
    return 0 if res else 1


if __name__ == "__main__":
    import sys as _sys
    if _sys.version_info < (3, 10):
        _sys.stderr.write(f"\n[错误] 需要 Python 3.10 及以上, 当前为 {_sys.version.split()[0]}\n\n")
        raise SystemExit(2)
    raise SystemExit(_cli())
