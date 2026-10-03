# -*- coding: utf-8 -*-
"""
GameArt Toolkit - ECH 隧道进程管理引擎 (Encrypted Client Hello Tunnel Manager)

ECH 隧道在本地回环上提供一个 HTTP 入口, 把收到的请求以带 ECH 的 TLS 连接转发
到 Cloudflare 边缘, 用于绕过针对明文 SNI 的关键字阻断。设计与验证详见
docs/ech-tunnel-proposal.md。

端口规划 (重要):
    44301  L4 Relay SNI 主端口
    44311-44374  L4 Relay 代理转发端口段 (RELAY_PORT_BASE + crc32 % 64)
    44401  ← ECH 隧道, 本模块

必须避开 relay 段: 实测占用该段会导致 relay 端口 bind 失败
(PermissionError WinError 10013), 表现为 relay 服务静默不可用。
"""

import ipaddress
import json
import re
import sys
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from path_utils import BASE_DIR, NGINX_DIR
from win_utils import (
    get_pids_by_name,
    get_silent_startup_kwargs,
    is_port_in_use,
    is_process_running,
)

# 隧道可执行文件与运行产物
TUNNEL_DIR = BASE_DIR / "tools" / "ech_tunnel"
TUNNEL_EXE = TUNNEL_DIR / "ech-tunnel.exe"
LOG_FILE = NGINX_DIR / "logs" / "ech-tunnel.log"

ECH_PORT_BASE = 44401
PROCESS_NAME = "ech-tunnel.exe"

# 上次启动隧道时使用的域名白名单与**每主机 IP 池**。隧道只在启动时读取这些参数,
# 复用一个参数已过期的进程会让新增域名静默不通 (升级后 profile 的 domains 变化即触发,
# 表现为部分站点无响应且无任何报错, 极难排查), 故落盘以便比对是否需要重启。
# 格式 = JSON ({"domains": [...], "host_ip_pool": {...}}); 旧格式(纯行文本)解析失败
# ⇒ 保守判定"需要重启", 与原先的保守取向一致。
DOMAINS_STATE_FILE = NGINX_DIR / "logs" / "ech-tunnel.domains"

# Cloudflare 官方 IPv4 网段 (与 tools/ech_tunnel/resolver.go 的 cloudflareV4 必须一致;
# tests/test_ech_tunnel_targets.py 会**读 Go 源码逐条比对**, 防止两处漂移)。
#
# 为什么 Python 侧也要这张表: 交给隧道的 IP 池必须只含 Cloudflare 地址 —— 池里混进
# 非 CF 地址(实测 pixiv_web 的候选池含源站 210.140.139.x)时, 它们**能建 TCP 但必然
# ECH 握手失败**, 而隧道的拨号逻辑只在 TCP 失败时换下一个地址 ⇒ 第一个地址就把整条
# 链路打死 (实测表现为 502, 换地址后恢复)。
CLOUDFLARE_V4_CIDRS: Tuple[str, ...] = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)
_CLOUDFLARE_NETS = tuple(ipaddress.ip_network(c) for c in CLOUDFLARE_V4_CIDRS)


def is_cloudflare_ip(ip: str) -> bool:
    """该地址是否落在 Cloudflare 网段内 (ECH 隧道只应拿到这类地址)"""
    try:
        obj = ipaddress.ip_address(str(ip).strip().strip("[]"))
    except ValueError:
        return False
    return any(obj in net for net in _CLOUDFLARE_NETS)

# DoH 端点: 仅作 ECHConfig 自举与域名解析的补充路径。实测境内 DoH 对受限
# 域名会间歇性返回污染结果, 真正可靠的是域名自带的静态 IP 池, 因此这里的
# 端点失败不影响可用性 (隧道内部有网段过滤与池回退)。
DEFAULT_DOH_ENDPOINTS = [
    "https://223.5.5.5/resolve",
    "https://dns.alidns.com/resolve",
]


class EchTunnelManager:
    """ECH 隧道进程生命周期管理 (启动 / 停止 / 健康检查)"""

    def __init__(self, exe_path: Path = TUNNEL_EXE, port: int = ECH_PORT_BASE):
        self.exe_path = exe_path
        self.port = port

    # ------------------------------------------------------------------
    # 状态查询
    # ------------------------------------------------------------------
    def is_running(self) -> bool:
        """隧道进程是否存活"""
        return is_process_running(PROCESS_NAME)

    def get_pids(self) -> List[int]:
        return get_pids_by_name(PROCESS_NAME)

    def is_listening(self) -> bool:
        """端口是否处于监听状态 (进程存活但监听未就绪时返回 False)"""
        return is_port_in_use(self.port)

    def is_healthy(self) -> bool:
        """进程存活且端口已监听"""
        return self.is_running() and self.is_listening()

    # ── ECHConfig 新鲜度 (2026-10-03) ────────────────────────────────────
    # 为什么必须补这一层: 隧道进程活着 + 端口在听 **不等于** ECHConfig 仍可靠。
    # Go 侧 `ECHConfigManager.Get()` 只返回配置字节, 没有对外的状态面; 刷新全线失败时它
    # **继续沿用旧配置**, 只写一行日志 (tools/ech_tunnel/echconfig.go:126)。
    # 于是"DoH 被阻断 + 内置兜底过期"会表现为 **隧道报告健康而每个请求都失败** ——
    # 正是本项目反复吃亏的"真因被表象掩盖"。
    # 判据: 自本进程启动以来**从未**出现"已更新 ECHConfig" ⇒ 大概率仍在用内置兜底
    # (那份的来源日期是 2026-09-23, 见 echconfig.go:22-26)。
    LOG_MARK_UPDATED = "已更新 ECHConfig"
    LOG_MARK_DOH_ALL_FAILED = "全部 DoH 端点查询失败"

    def config_freshness(self, tail_lines: int = 500) -> Dict:
        """从隧道日志派生 ECHConfig 新鲜度 (只读; 日志缺失/不可读时如实返回 unknown)"""
        out: Dict = {"known": False, "last_update": None, "last_doh_failure": None,
                     "using_builtin_guess": None, "note": ""}
        try:
            if not LOG_FILE.exists():
                out["note"] = f"日志不存在: {LOG_FILE}"
                return out
            lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as e:
            out["note"] = f"日志读取失败: {type(e).__name__}"
            return out

        stamp = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
        for ln in lines[-max(1, int(tail_lines)):]:
            if self.LOG_MARK_UPDATED in ln:
                m = stamp.match(ln)
                out["last_update"] = m.group(1) if m else "(有更新, 无时间戳)"
            elif self.LOG_MARK_DOH_ALL_FAILED in ln:
                m = stamp.match(ln)
                out["last_doh_failure"] = m.group(1) if m else "(有失败, 无时间戳)"
        out["known"] = True
        # 从未刷新成功 = 大概率还在用内置兜底
        out["using_builtin_guess"] = out["last_update"] is None
        if out["using_builtin_guess"]:
            out["note"] = ("自启动以来未见成功刷新, 大概率仍在使用**内置兜底配置**"
                           + ("; 且出现过 DoH 全线失败" if out["last_doh_failure"] else ""))
        elif out["last_doh_failure"] and (out["last_update"] or "") < (out["last_doh_failure"] or ""):
            out["note"] = "最近一次 DoH 全线失败发生在最近一次成功刷新之后"
        else:
            out["note"] = "配置有过成功刷新"
        return out

    def is_functionally_healthy(self) -> bool:
        """**功能性**健康: 进程/端口健康 **且** ECHConfig 不像是在吃内置兜底

        与 `is_healthy()` 刻意分开: 后者是既有的"进程+端口"语义, 有调用方依赖它,
        不能改语义。本方法供"要不要告警/降级"的判断使用。
        """
        if not self.is_healthy():
            return False
        f = self.config_freshness()
        return not f.get("using_builtin_guess", False)

    def status(self) -> Dict:
        return {
            "running": self.is_running(),
            "listening": self.is_listening(),
            "healthy": self.is_healthy(),
            "ech_config": self.config_freshness(),
            "functionally_healthy": self.is_functionally_healthy(),
            "port": self.port,
            "pids": self.get_pids(),
        }

    # ------------------------------------------------------------------
    # 域名白名单状态 (决定能否复用已在运行的隧道进程)
    # ------------------------------------------------------------------
    def _save_domains(self, domains: List[str],
                      host_ip_pool: Optional[Dict[str, List[str]]] = None) -> None:
        try:
            DOMAINS_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            DOMAINS_STATE_FILE.write_text(_state_signature(domains, host_ip_pool), encoding="utf-8")
        except Exception:
            pass

    def _domains_unchanged(self, domains: List[str],
                           host_ip_pool: Optional[Dict[str, List[str]]] = None) -> bool:
        """在运行的隧道其白名单与**每主机 IP 池**是否与本请求一致

        读不到/解析不了状态文件时保守返回 False —— 宁可重启一次, 也不要沿用参数未知的
        进程。误判代价不对称: 多重启一次的代价是启动慢几百毫秒, 而沿用过期参数的代价是
        部分域名静默不通 (白名单) 或**地址池错配导致的截断/502** (per-host 池)。
        """
        try:
            if not DOMAINS_STATE_FILE.exists():
                return False
            saved = DOMAINS_STATE_FILE.read_text(encoding="utf-8", errors="ignore")
            return saved == _state_signature(domains, host_ip_pool)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def build_command(
        self,
        domains: List[str],
        ip_pool: Optional[List[str]] = None,
        host_ip_pool: Optional[Dict[str, List[str]]] = None,
        doh_endpoints: Optional[List[str]] = None,
        ech_refresh_minutes: int = 30,
    ) -> List[str]:
        """组装启动参数。域名白名单为空时隧道不限制目标, 故调用方应始终传入。"""
        cmd = [
            str(self.exe_path),
            "-listen", f"127.0.0.1:{self.port}",
            "-domains", ",".join(d for d in domains if d),
            "-doh", ",".join(doh_endpoints or DEFAULT_DOH_ENDPOINTS),
            "-ech-refresh", f"{ech_refresh_minutes}m",
        ]
        if ip_pool:
            cmd += ["-ip-pool", ",".join(ip for ip in ip_pool if ip)]
        # 每主机专属池: 对"权威解析不是 Cloudflare"的主机 (n2.pawchive.pw 的 DoH 答案
        # 落在 DDoS-Guard), 这是唯一能拿到**本 zone 真实边缘**的路; 否则只能退到全局池,
        # 实测会把 1.8MB 原图打成截断(439KB/903KB) 或 502。
        hp = format_host_ip_pool(host_ip_pool)
        if hp:
            cmd += ["-host-ip-pool", hp]
        return cmd

    def start(
        self,
        domains: List[str],
        ip_pool: Optional[List[str]] = None,
        host_ip_pool: Optional[Dict[str, List[str]]] = None,
        doh_endpoints: Optional[List[str]] = None,
        force_restart: bool = False,
    ) -> Tuple[bool, str]:
        """启动隧道。已在运行且参数一致时直接返回成功。

        复用判据是"进程在 + 参数一致", 不能只看进程: 隧道只在启动时读取域名
        白名单, 复用一个白名单已过期的进程会让新增域名静默不通。
        """
        if not self.exe_path.exists():
            return False, (
                f"未找到隧道可执行文件: {self.exe_path}\n"
                f"请先执行 tools/ech_tunnel/build.ps1 构建"
            )

        if not domains:
            return False, "未指定任何域名白名单, 拒绝启动 (隧道将不限制目标域名)"

        if self.is_running():
            if not force_restart and self._domains_unchanged(domains, host_ip_pool):
                return True, f"ECH 隧道已在运行 ({self.get_pids()})"
            self.stop()
            time.sleep(0.3)

        # 端口被非本程序占用: 明确报错而不是静默失败
        if is_port_in_use(self.port):
            return False, f"端口 {self.port} 已被其他程序占用, 无法启动 ECH 隧道"

        cmd = self.build_command(domains, ip_pool, host_ip_pool, doh_endpoints)

        try:
            LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            # 日志追加写入; Popen 会复制句柄, with 退出后子进程仍可写
            with open(LOG_FILE, "ab") as log:
                subprocess.Popen(
                    cmd,
                    cwd=str(TUNNEL_DIR),
                    shell=False,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    **get_silent_startup_kwargs(),
                )
            # 等待监听就绪: 隧道启动需完成一次 ECHConfig 的 DoH 查询,
            # 但内置配置可立即兜底, 正常情况下百毫秒内即可监听
            for _ in range(20):
                time.sleep(0.1)
                if self.is_healthy():
                    self._save_domains(domains, host_ip_pool)  # 记录本次参数, 供下次比对
                    return True, f"ECH 隧道启动成功 (127.0.0.1:{self.port}, {len(domains)} 个域名)"
            if self.is_running():
                return False, f"ECH 隧道进程已起但端口 {self.port} 未监听, 详见 {LOG_FILE}"
            return False, f"ECH 隧道启动失败, 详见 {LOG_FILE}"
        except Exception as e:
            return False, f"启动 ECH 隧道异常: {e}"

    def stop(self) -> Tuple[bool, str]:
        """按 PID 精准终止隧道进程"""
        if not self.is_running():
            return True, "ECH 隧道未在运行"

        for pid in self.get_pids():
            try:
                subprocess.run(
                    f"taskkill /F /T /PID {pid}",
                    shell=True, capture_output=True, timeout=3,
                    **get_silent_startup_kwargs(),
                )
            except Exception:
                pass

        time.sleep(0.2)
        if self.is_running():
            return False, "停止 ECH 隧道超时"
        return True, "ECH 隧道已停止"

    def restart(
        self,
        domains: List[str],
        ip_pool: Optional[List[str]] = None,
        host_ip_pool: Optional[Dict[str, List[str]]] = None,
        doh_endpoints: Optional[List[str]] = None,
    ) -> Tuple[bool, str]:
        """重启隧道 (域名白名单或地址池变化时使用)"""
        self.stop()
        return self.start(domains, ip_pool, host_ip_pool, doh_endpoints, force_restart=True)

    def tail_log(self, lines: int = 30) -> str:
        """读取日志尾部, 供界面诊断使用"""
        if not LOG_FILE.exists():
            return "(尚无日志)"
        try:
            content = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
            return "\n".join(content[-lines:])
        except Exception as e:
            return f"(读取日志失败: {e})"


# 全局单例
ech_tunnel = EchTunnelManager()


def format_host_ip_pool(host_ip_pool: Optional[Dict[str, List[str]]]) -> str:
    """把 {host: [ip, ...]} 拼成隧道的 `-host-ip-pool` 取值: `host=ip1,ip2;host2=ip3`

    排序后再拼, 保证同一份输入产生**逐字相同**的字符串 —— 状态文件比对依赖这一点
    (否则字典顺序抖动会导致每次启动都判"参数变了"而无谓重启)。
    """
    if not host_ip_pool:
        return ""
    parts = []
    for host in sorted(host_ip_pool):
        ips = [ip for ip in (host_ip_pool.get(host) or []) if ip]
        if host and ips:
            parts.append(f"{host}={','.join(ips)}")
    return ";".join(parts)


def _state_signature(domains: List[str],
                     host_ip_pool: Optional[Dict[str, List[str]]] = None) -> str:
    """隧道启动参数的可比对签名 (白名单 + 每主机池), 落盘供"是否需要重启"判定"""
    return json.dumps({
        "domains": list(domains),
        "host_ip_pool": {k: list(v) for k, v in sorted((host_ip_pool or {}).items())},
    }, ensure_ascii=False, sort_keys=True)


def build_ech_targets(profiles, allow_fn=None) -> Tuple[List[str], List[str], Dict[str, List[str]]]:
    """聚合 ECH 隧道的 (域名白名单, 全局 IP 池, 每主机 IP 池) —— **纯函数**, 便于单测

    规则 (2026-10-03 明确化):
      · 只取 `ech_enabled=True` 的画像;
      · 受控分组 (如 adult) 未被放开时, 该分组的画像**不进白名单** ——
        总闸的语义是"这些服务不许生效", 而白名单是"允许隧道转发到哪些目标"的前置面,
        把默认关闭的成人域名预先放进去与闸门语义矛盾;
      · 两个 IP 列表都**只保留 Cloudflare 网段内的地址** (见 CLOUDFLARE_V4_CIDRS 注释:
        非 CF 地址能建 TCP 但必然 ECH 握手失败, 而隧道只在 TCP 失败时换 IP ⇒ 直接 502);
      · **每主机池**取该画像 domains -> candidate_ips 的映射: 对权威解析不是 CF 的主机
        (实测 n2.pawchive.pw) 这是唯一能拿到本 zone 真实边缘的路, 否则会退到混着其它
        zone 边缘的全局池并出现截断/502;
      · 三个结果都**去重保序** (多个画像可能共享域名/边缘 IP)。
    """
    domains: List[str] = []
    ip_pool: List[str] = []
    host_ip_pool: Dict[str, List[str]] = {}
    for p in profiles:
        if not getattr(p, "ech_enabled", False):
            continue
        if allow_fn is not None:
            try:
                if not allow_fn(p):
                    continue
            except Exception:
                continue
        p_domains = list(getattr(p, "domains", ()) or ())
        # 只收 CF 网段内的候选: 非 CF 地址进池等于"第一个地址打死整条链路" (见上)
        p_ips = [ip for ip in (getattr(p, "candidate_ips", ()) or ()) if is_cloudflare_ip(ip)]
        domains.extend(p_domains)
        ip_pool.extend(p_ips)
        for d in p_domains:
            if p_ips:
                host_ip_pool.setdefault(str(d).lower(), [])
                for ip in p_ips:
                    if ip not in host_ip_pool[str(d).lower()]:
                        host_ip_pool[str(d).lower()].append(ip)
    return (list(dict.fromkeys(domains)), list(dict.fromkeys(ip_pool)), host_ip_pool)
