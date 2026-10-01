# -*- coding: utf-8 -*-
"""
GameArt Toolkit - QUIC(HTTP/3) 直连启动器

适用场景 (2026-10-01 无代理国内直连出口实测):
  部分站点的 **TCP+TLS 标准 SNI 会被 GFW 立即 RST**, 但 **UDP/443 的 QUIC 通路放行**。
  对这类站点, 任何"本机终止 TLS"的方案 (Nginx L7 反代 / L4 中继) 都必然失败, 唯一可行的
  是让**浏览器自己**用 HTTP/3 直连 —— 而浏览器默认会先试 TCP (被 RST) 才谈 QUIC, 因此
  必须由外部把"该源支持 h3"这件事告诉它。

两条告知途径:
  1. DNS 侧 (正解, 见 app/dns_server.py 的 HTTPS RR 应答): 需本机解析器对外服务 53 端口,
     配合 NRPT 或手动指定 DNS —— 需要管理员权限且 53 空闲。
  2. 启动器 (本模块): 以命令行开关直接把映射与 h3 强制声明注入浏览器进程, **无需管理员权限、
     无需占用 53 端口**, 代价是该窗口使用独立浏览器配置目录 (Chrome/Edge 在已有实例运行时
     会忽略新开关, 必须用独立 user-data-dir 才能保证生效)。

实测依据 (scripts/probe_h3_sni.py + 浏览器 A/B):
  - 强制 QUIC 打开 www.reddit.com: 页面加载成功, netlog 出现 QUIC_SESSION ×124 / HTTP3 ×24
  - 同 IP 映射但不强制 QUIC: ERR_TIMED_OUT
"""

import sys as _sys

# 版本前置检查: 本项目使用 PEP 585/604 类型标注, 需 Python 3.10+。旧解释器下会抛出
# 难以理解的 TypeError, 这里改为给出可操作的提示。
if _sys.version_info < (3, 10):
    _sys.stderr.write(
        f"\n[错误] 需要 Python 3.10 及以上, 当前为 {_sys.version.split()[0]}。\n"
        f"       请使用运行客户端的同一解释器, 例如: py -3.13 -m app.quic_launcher\n"
        f"       当前解释器: {_sys.executable}\n\n")
    raise SystemExit(2)

import sys as _sys

# 版本前置检查: 本项目使用 PEP 585/604 类型标注, 需 Python 3.10+。旧解释器下会抛出
# 难以理解的 TypeError, 这里改为给出可操作的提示。
if _sys.version_info < (3, 10):
    _sys.stderr.write(
        f"\n[错误] 需要 Python 3.10 及以上, 当前为 {_sys.version.split()[0]}。\n"
        f"       请使用运行客户端的同一解释器, 例如: py -3.13 -m app.quic_launcher\n"
        f"       当前解释器: {_sys.executable}\n\n")
    raise SystemExit(2)

import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from path_utils import BASE_DIR
from win_utils import get_silent_startup_kwargs, is_process_running

QUIC_PROFILE_DIR = BASE_DIR / "browser_profiles" / "quic"

# 支持的浏览器 (按优先级): Chrome 优先, Edge 作为系统自带兜底
BROWSER_CANDIDATES: List[Tuple[str, str]] = [
    ("chrome", r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
    ("chrome", r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
    ("chrome", r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
    ("edge", r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
    ("edge", r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
]

_BROWSER_PROCESS_NAMES = {"chrome": "chrome.exe", "edge": "msedge.exe"}


def _expand(path_tpl: str) -> Optional[Path]:
    """展开 %VAR% 形式的路径模板 (不依赖 os.path.expandvars 对 ProgramFiles(x86) 的支持)"""
    import os
    import re

    def repl(m):
        return os.environ.get(m.group(1), m.group(0))

    expanded = re.sub(r"%([^%]+)%", repl, path_tpl)
    p = Path(expanded)
    return p if p.exists() else None


def find_browsers() -> List[Tuple[str, Path]]:
    """探测本机可用的 Chromium 系浏览器 (返回 [(名称, 路径)])"""
    found: List[Tuple[str, Path]] = []
    seen = set()
    for name, tpl in BROWSER_CANDIDATES:
        p = _expand(tpl)
        if p and str(p).lower() not in seen:
            seen.add(str(p).lower())
            found.append((name, p))
    return found


def is_browser_running() -> bool:
    """本机是否已有 Chromium 实例在运行 (决定能否复用默认配置目录)"""
    for proc in _BROWSER_PROCESS_NAMES.values():
        try:
            if is_process_running(proc):
                return True
        except Exception:
            continue
    return False


def build_command(browser_path, domain: str, ip: str, url: Optional[str] = None,
                  profile_dir: Optional[Path] = None,
                  extra_domains: Sequence[str] = (),
                  extra_targets: Sequence[Tuple[str, str]] = ()) -> List[str]:
    """构造 QUIC 直连启动命令行

    :param domain: 目标域名 (同时用作 SNI 与 Host)
    :param ip: 该域名的真实 CDN IP (由 DoH 实测得到, 见 probe_h3_sni.py)
    :param profile_dir: 独立配置目录; 已有浏览器实例在运行时必须提供, 否则开关会被忽略
    :param extra_domains: 需要一并映射到同一 IP 的同站域名 (如 www 前缀)
    :param extra_targets: 需要**各自映射到不同 IP** 的子资源域 (域名, IP) 对。

    为什么必须支持子资源域: 只映射主域时, 页面引用的 CDN 子域 (实测 discord 需要
    cdn.discordapp.com, 其 TCP 侧被 RST) 仍会走系统解析 + TCP → 图片/脚本加载失败。
    这些域必须同时满足两件事: ① 解析到可用 IP (host-resolver-rules); ② 允许走 h3
    (origin-to-force-quic-on), 否则 Chrome 仍会用那条被 RST 的 TCP 通道。
    """
    targets: List[Tuple[str, str]] = [(domain, ip)]
    targets += [(d, ip) for d in extra_domains if d and d != domain]
    for host, host_ip in extra_targets or ():
        if host and host_ip and all(host != h for h, _ in targets):
            targets.append((host, host_ip))

    rules = ",".join(f"MAP {h} {i}" for h, i in targets)

    cmd: List[str] = [str(browser_path)]
    if profile_dir is not None:
        cmd.append(f"--user-data-dir={Path(profile_dir)}")
    # 绝不让系统代理介入: 本路线的意义就是"不经代理直连", 走代理会让结论失真且绕路
    cmd.append("--no-proxy-server")
    cmd.append(f"--host-resolver-rules={rules}")
    # 直接把"该源支持 h3"灌给浏览器, 等价于它自己查到了 HTTPS RR 的 alpn=h3。
    # **必须写成一条逗号分隔的参数**: 实测重复传入同名开关时 Chrome 只取最后一个
    # (对照实验: 重复 4 次 -> 只剩最后那个域被强制, 主域反而走 TCP 得到 ERR_CONNECTION_RESET;
    #  写成逗号列表 -> 页面正常加载)。字符串列表型开关的写法差异会直接决定成败。
    cmd.append("--origin-to-force-quic-on=" + ",".join(f"{h}:443" for h, _ip in targets))
    cmd.append("--no-first-run")
    cmd.append("--no-default-browser-check")
    cmd.append(url or f"https://{domain}/")
    return cmd


def resolve_service_ip(domain: str) -> Optional[str]:
    """从服务画像里取该域名的实测候选 IP (QUIC 直连服务由静态实测数据维护)"""
    try:
        from service_profile import get_profile_by_domain
        profile = get_profile_by_domain(domain)
        if profile and profile.candidate_ips:
            return profile.candidate_ips[0]
    except Exception:
        pass
    return None


def _profile_extra_targets(domain: str) -> List[Tuple[str, str]]:
    """取该域名所属画像里**其余子资源域**及其优选 IP

    为什么需要: 页面内容来自 CDN 子域 (实测 discord 需 cdn.discordapp.com, 其 TCP 侧被 RST)。
    只映射主域时这些子域仍走系统解析 + TCP, 结果就是"框架能开、图片全挂"。这里把画像登记的
    每个域名都映射到其优选 IP, 并逐一强制 h3。
    """
    out: List[Tuple[str, str]] = []
    try:
        from service_profile import get_profile_by_domain
        profile = get_profile_by_domain(domain)
        if not profile:
            return out
        try:
            from quic_probe import current_best_ip
            best = current_best_ip(profile.id)
        except Exception:
            best = ""
        fallback = best or (profile.candidate_ips[0] if profile.candidate_ips else "")
        for d in profile.domains:
            if not d or d.startswith("*") or "." not in d or d == domain:
                continue
            out.append((d, fallback))
    except Exception:
        pass
    return out


def verify_quic(domain: str, ip: str, timeout: float = 8.0) -> Tuple[Optional[bool], str]:
    """用 aioquic 真实发起一次 HTTP/3 请求, 确认该 IP 对该域名可用 (只读, 不启动浏览器)

    返回 (结果, 说明): True=可用, False=不可用, None=无法判定 (缺依赖)
    """
    try:
        import asyncio
        import ssl
        from aioquic.asyncio.client import connect
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.h3.connection import H3_ALPN, H3Connection
        from aioquic.h3.events import HeadersReceived
        from aioquic.quic.configuration import QuicConfiguration
    except Exception as e:
        return None, f"缺少 aioquic, 无法预检: {e}"

    class _Probe(QuicConnectionProtocol):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self._http = H3Connection(self._quic)
            self.status = None

        def quic_event_received(self, event):
            for ev in self._http.handle_event(event):
                if isinstance(ev, HeadersReceived):
                    for k, v in ev.headers:
                        if k == b":status":
                            try:
                                self.status = int(v)
                            except Exception:
                                pass

    async def _run():
        cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE)
        cfg.server_name = domain
        async with connect(ip, 443, configuration=cfg, create_protocol=_Probe,
                           wait_connected=True) as client:
            sid = client._quic.get_next_available_stream_id()
            client._http.send_headers(sid, [
                (b":method", b"HEAD"), (b":scheme", b"https"),
                (b":authority", domain.encode()), (b":path", b"/"),
            ], end_stream=True)
            client.transmit()
            deadline = timeout
            while client.status is None and deadline > 0:
                await asyncio.sleep(0.2)
                deadline -= 0.2
            return client.status

    try:
        status = asyncio.run(asyncio.wait_for(_run(), timeout=timeout + 4))
    except Exception as e:
        return False, f"QUIC 握手/请求失败: {type(e).__name__}"
    if status:
        return True, f"QUIC 通道可用 (HTTP {status})"
    return False, "QUIC 握手成功但未收到 HTTP 响应"


def launch(domain: str, ip: Optional[str] = None, url: Optional[str] = None,
           browser: Optional[str] = None, extra_domains: Sequence[str] = (),
           dry_run: bool = False, verify: bool = False) -> Tuple[bool, str, List[str]]:
    """启动浏览器以 QUIC 直连方式打开目标站点

    返回 (是否成功, 面向用户的消息, 实际命令行)

    总开关 (quic_probe.QUIC_ENABLED) 停用时直接拒绝: 该启动器是 QUIC 通道的入口,
    停用期间不应被误触发 (代码与验证能力保留, 改回开关即可恢复)。
    """
    try:
        from quic_probe import is_enabled as _quic_enabled
        if not _quic_enabled():
            return False, "QUIC 通道已暂时停用 (见 app/quic_probe.py 的 QUIC_ENABLED)", []
    except Exception:
        pass

    browsers = find_browsers()
    if not browsers:
        return False, "未找到 Chrome / Edge, 无法使用 QUIC 直连启动器", []

    chosen = None
    if browser:
        for name, path in browsers:
            if name == browser:
                chosen = (name, path)
                break
    if chosen is None:
        chosen = browsers[0]

    if not ip:
        ip = resolve_service_ip(domain)
    if not ip:
        return False, f"没有 {domain} 的可用 IP (请先用探测脚本测速或手动指定 --ip)", []
    if ":" in ip:
        return False, f"暂不支持 IPv6 目标: {ip}", []

    if verify:
        ok, detail = verify_quic(domain, ip)
        if ok is False:
            return False, f"{domain}@{ip} 预检未通过: {detail}", []

    # 已有实例在运行时新开关会被忽略, 必须落到独立配置目录才能保证生效
    profile_dir = None
    note = ""
    if is_browser_running():
        profile_dir = QUIC_PROFILE_DIR
        note = "（检测到浏览器已在运行, 已启用独立配置目录以确保开关生效）"

    cmd = build_command(chosen[1], domain, ip, url=url,
                        profile_dir=profile_dir, extra_domains=extra_domains,
                        extra_targets=_profile_extra_targets(domain))
    if dry_run:
        return True, f"预览命令{note}", cmd

    try:
        QUIC_PROFILE_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         **get_silent_startup_kwargs())
    except Exception as e:
        return False, f"启动浏览器失败: {e}", cmd

    return True, f"已用 {chosen[0]} 以 QUIC(HTTP/3) 直连打开 {domain} (IP {ip}){note}", cmd


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(description="QUIC(HTTP/3) 直连启动器")
    ap.add_argument("--domain", required=True, help="目标域名, 如 www.reddit.com")
    ap.add_argument("--ip", help="目标真实 CDN IP (缺省取服务画像里的候选)")
    ap.add_argument("--url", help="要打开的完整 URL")
    ap.add_argument("--browser", choices=["chrome", "edge"], help="指定浏览器")
    ap.add_argument("--extra-domain", action="append", default=[], help="一并映射的同站域名")
    ap.add_argument("--dry-run", action="store_true", help="只打印命令不启动")
    ap.add_argument("--verify", action="store_true", help="启动前用 aioquic 预检 QUIC 可达性")
    ap.add_argument("--list-browsers", action="store_true", help="列出探测到的浏览器")
    args = ap.parse_args(argv)

    if args.list_browsers:
        for name, path in find_browsers():
            print(f"{name}: {path}")
        return 0

    if args.verify and args.ip:
        ok, detail = verify_quic(args.domain, args.ip)
        print(f"[预检] {args.domain}@{args.ip}: {detail}")

    ok, msg, cmd = launch(args.domain, ip=args.ip, url=args.url, browser=args.browser,
                          extra_domains=args.extra_domain, dry_run=args.dry_run,
                          verify=args.verify)
    print(msg)
    if cmd:
        print(json.dumps(cmd, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())


