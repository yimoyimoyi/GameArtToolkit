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
from nrpt_manager import NRPT_DNS_PORT, NRPT_NAME_SERVER, NrptManager
from win_utils import ProxyBypassManager

MODE_HOSTS = "hosts"
MODE_NRPT = "nrpt"

DEFAULT_DNS_PORT = 5353

_NRPT = NrptManager()


def normalize_mode(cfg: Optional[Dict[str, Any]]) -> str:
    """归一化重定向后端配置, 非法值一律视作 Hosts (保持历史行为)"""
    raw = str((cfg or {}).get("redirect_mode", MODE_HOSTS) or MODE_HOSTS).strip().lower()
    return MODE_NRPT if raw == MODE_NRPT else MODE_HOSTS


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


def apply_redirect(cfg: Dict[str, Any], services: List[str], hosts, nrpt=None,
                   dns=None, state: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
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
                    state: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
    """幂等清理两种后端的全部残留, 并恢复本机解析器的默认端口。

    两个后端都清理而非只清当前模式: 用户切换后端、异常退出、旧版本残留等场景下,
    只清其一会留下"域名指向 127.0.0.1 但没有服务应答"的死解析。
    """
    state = state if state is not None else {}
    nrpt = nrpt or _NRPT
    ok_all = True
    messages: List[str] = []

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


def fast_remove_redirect(cfg: Dict[str, Any], hosts, nrpt=None, dns=None) -> bool:
    """退出/关机通道的快速清理。

    NRPT 规则必须在此清理: 规则残留而本机解析器已退出时, 命中域名的 DNS 查询会被
    定向到一个无人监听的 127.0.0.1:53, 表现为这些域名彻底无法解析 (比 Hosts 残留更
    严重)。因此即使多花一次 PowerShell 调用也必须清掉。
    """
    nrpt = nrpt or _NRPT
    ok = True
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


def cleanup_orphans(cfg: Dict[str, Any], hosts, nrpt=None, dns=None,
                    data_plane_alive: bool = False) -> Dict[str, Any]:
    """启动时清理**上一会话遗留**的重定向 (异常退出/被强杀时会残留)

    为什么必须在启动时清 (实测事故): 上一会话在 NRPT 模式下被强杀, 规则残留下来, 而
    本机解析器随进程一起退出 —— 于是规则里那 ~280 个域名在**整机范围**内全部解析失败
    (查询被导向无人监听的 127.0.0.1:53), 且此时用户根本没打算启动加速。Hosts 残留同理
    (指向 127.0.0.1 而 nginx 未运行)。判定口径: 数据平面不存活 + 重定向仍生效 = 孤儿。

    返回 {"cleaned": bool, "detail": str}
    """
    nrpt = nrpt or _NRPT
    try:
        if data_plane_alive:
            return {"cleaned": False, "detail": "数据平面存活, 视为本会话状态, 不做清理"}
    except Exception:
        pass

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

    if not (applied_hosts or applied_nrpt):
        return {"cleaned": False, "detail": "无残留"}

    ok = fast_remove_redirect(cfg, hosts, nrpt, dns)
    parts = []
    if applied_hosts:
        parts.append("Hosts")
    if applied_nrpt:
        parts.append("NRPT")
    detail = (f"已清理上一会话遗留的 {'/'.join(parts)} 重定向残留"
              if ok else f"{'/'.join(parts)} 残留清理未完全成功 (删除 NRPT 规则需管理员权限)")

    # 结果落盘: 下次启动要在界面上明确告知用户, 而不是让他自己去猜为什么上不了网
    try:
        from config_store import load_config as _load, save_config as _save
        _cfg = _load()
        if ok:
            _cfg.pop("last_cleanup_warning", None)
        else:
            import time as _time
            _cfg["last_cleanup_warning"] = {"ts": int(_time.time()), "detail": detail}
        _save(_cfg)
    except Exception:
        pass

    return {"cleaned": True, "ok": ok, "detail": detail,
            "had_hosts": applied_hosts, "had_nrpt": applied_nrpt}


def is_redirect_applied(cfg: Dict[str, Any], hosts, nrpt=None) -> bool:
    """判定重定向是否处于生效状态 (任一后端生效即为真, 兼容 NRPT 回退 Hosts 的场景)"""
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
