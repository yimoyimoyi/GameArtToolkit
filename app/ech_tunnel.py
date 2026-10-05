# -*- coding: utf-8 -*-
"""
GameArt Toolkit - ECH 隧道进程管理引擎 (Encrypted Client Hello Tunnel Manager)

ECH 隧道在本地回环上提供一个 HTTP 入口, 把收到的请求以带 ECH 的 TLS 连接转发
到 Cloudflare 边缘, 用于绕过针对明文 SNI 的关键字阻断。设计与验证详见
docs/ech-tunnel-proposal.md。

端口规划 (重要):
    44301  L4 Relay SNI 主端口
    44311-44438  L4 Relay 代理转发端口段 (RELAY_PORT_BASE + crc32 % RELAY_PORT_SPAN)
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
#
# ★ 2026-10-04 顺序修正 (用户"civitai/discord 时好时坏"的真根因之一):
#   原先是**阿里优先**, 而实测阿里对**几乎所有受限域名**都在返回 Meta/垃圾段:
#       civitai.com            doh.pub=172.66.152.186/104.20.38.219  ali=173.252.88.133
#       blobs-b2.civitai.com   doh.pub=172.66.152.186/…             ali=103.252.114.61(死)
#       gateway.discord.gg     doh.pub=162.159.133.234/…            ali=31.13.82.33
#       www.youtube.com        doh.pub=142.251.156.4/…              ali=31.13.92.37
#   而 `doh.pub` 连测 6/6 一致给出正确结果。把阿里放第一位 ⇒ 隧道自举与解析会**优先
#   采纳污染答案**。这与 `cdn_optimizer.DOH_ENDPOINTS` 的口径也对齐了 —— 那边早已写成
#   "阿里…可能继承 GFW 注入结果, 仅作容灾"并把 doh.pub 放第一; 本处与 h3_upstream 是
#   漏改的两处 (同一教训, 三张表只改对了一张)。
#   ⚠ 不要把阿里挪回第一位: 那是本次缺陷的成因。保留它是为了"doh.pub 也不可达"时的兜底。
DEFAULT_DOH_ENDPOINTS = [
    "https://doh.pub/dns-query",
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
    # 进程边界标记 (Go 侧 main.go:"[boot] ECH 隧道启动"). 新鲜度**必须**以最后一次
    # 进程启动为水位线, 否则会把"上一个进程"的成功刷新算到当前进程头上 —— 见下面注释。
    LOG_MARK_BOOT = "[boot]"

    def config_freshness(self, tail_lines: int = 500) -> Dict:
        """从隧道日志派生 ECHConfig 新鲜度 (只读; 日志缺失/不可读时如实返回 unknown)

        ★ 只读文件尾部, 不整读 (2026-10-04): 这份日志是**追加写、不轮转**的,
        而这个函数会被 UI 渲染与状态刷新反复调用。整读一个无限增长的日志, 代价
        会随运行时长线性上升 —— 属于"越跑越慢"的缺陷形态。按字节从尾部取一段
        再切行, 代价就有界了。

        ★★ 2026-10-04 修**假健康**: 原先在整段尾部里找 `已更新 ECHConfig`, 于是
        "**当前**进程启动时 DoH 全失败、只能吃内置兜底", 却因为**上一个**进程留下过
        一条成功刷新 (实测同一份日志里有 39 次启动、45 次刷新) 而被判为"配置新鲜" ——
        隧道明明在用 2026-09-23 的内置兜底逐请求失败, 界面却报健康。这正是本项目
        反复吃亏的"真因被表象掩盖"。
        现在先把日志**切到最后一个 `[boot]` 之后**, 只在**当前进程**的日志段内判定:
          · 段内出现"已更新"            -> 新鲜 (using_builtin_guess=False)
          · 段内只有"全部 DoH 失败"      -> 正在吃内置兜底 (True, 且报出 DoH 失败时间)
          · 段内两者都没有              -> 尚不确定 (True + 明确说明, 宁可warning不谎报健康)
        """
        out: Dict = {"known": False, "last_update": None, "last_doh_failure": None,
                     "using_builtin_guess": None, "run_started": None,
                     "scoped_to_current_run": False, "note": ""}
        try:
            if not LOG_FILE.exists():
                out["note"] = f"日志不存在: {LOG_FILE}"
                return out
            tail_lines = max(1, int(tail_lines))
            # 每行约 100~200 字节; 取 tail_lines 的若干倍足够覆盖, 且设 1MB 上限。
            want_bytes = min(1_048_576, max(64_1024, tail_lines * 512))
            with open(LOG_FILE, "rb") as fh:
                fh.seek(0, 2)
                size = fh.tell()
                start = max(0, size - want_bytes)
                fh.seek(start)
                blob = fh.read()
            if start > 0:
                # 我们是从中间切进去的, 第一行几乎肯定是半行 —— 丢掉它。
                blob = blob.split(b"\n", 1)[-1]
            lines = blob.decode("utf-8", "replace").splitlines()[-tail_lines:]
        except Exception as e:
            out["note"] = f"日志读取失败: {type(e).__name__}"
            return out

        stamp = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
        # ── 切到最后一次进程启动之后 (水位线) ──────────────────────────────
        boot_idx = -1
        for i, ln in enumerate(lines):
            if self.LOG_MARK_BOOT in ln:
                boot_idx = i
        # ⚠ 尾部窗口内**没有** [boot] 时有两种可能: ① 本进程启动得很早, 启动行已被
        #   窗口挤出; ② 进程根本没起过。此时若直接把 boot_idx 当 0, 就会把窗口里
        #   任何一条历史成功刷新当成本次 —— 正是要修的假健康。故保守：不裁剪,
        #   但把结论降级为"不确定" (宁可告警, 不谎报健康)。
        if boot_idx >= 0:
            scoped = lines[boot_idx:]
            out["scoped_to_current_run"] = True
        else:
            scoped = lines
        if scoped and stamp.match(scoped[0]):
            out["run_started"] = stamp.match(scoped[0]).group(1)
        # 若启动行本身就是第一行, run_started 取它的时间戳更准
        if boot_idx >= 0 and boot_idx < len(lines):
            m0 = stamp.match(lines[boot_idx])
            if m0:
                out["run_started"] = m0.group(1)

        for ln in scoped:
            if self.LOG_MARK_UPDATED in ln:
                m = stamp.match(ln)
                out["last_update"] = m.group(1) if m else "(有更新, 无时间戳)"
            elif self.LOG_MARK_DOH_ALL_FAILED in ln:
                m = stamp.match(ln)
                out["last_doh_failure"] = m.group(1) if m else "(有失败, 无时间戳)"
        out["known"] = True

        # ⚠ 关键: 窗口内**看不到进程启动标记**时, 绝不能按"段内有没有成功刷新"下结论 ——
        #   那正是假健康的来源 (上一条成功刷新可能属于上一个已死的进程)。这里显式
        #   **保守判不可信**, 并且**不采信** last_update (否则又会把它当成本次的新鲜证据)。
        if not out["scoped_to_current_run"]:
            out["using_builtin_guess"] = True
            out["last_update"] = None
            out["note"] = ("日志尾部窗口内未见进程启动标记, 无法确认配置是否属于本次运行"
                           " —— 保守判为配置不可信 (可重启隧道以重新自举 ECHConfig)")
            return out

        # 本次进程内从未刷新成功 = 大概率还在用内置兜底
        out["using_builtin_guess"] = out["last_update"] is None
        if out["using_builtin_guess"]:
            out["note"] = ("本次启动以来未见成功刷新, 大概率仍在使用**内置兜底配置**"
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


def normalize_ech_allow_entry(entry) -> str:
    """把一个白名单条目规范化为 Go 侧能真正匹配到的形式 (缺陷 W3, 2026-10-04)

    Go 侧的匹配 (`main.go` 的 `Tunnel.allowed`) 是::

        host == suffix || strings.HasSuffix(host, "." + suffix)

    因此 `suffix` 只能是**裸主机名**:
      · `booth.pm`    -> 匹配 `booth.pm` 与 `<任意>.booth.pm`  ✅ 这就是"子树"
      · `*.booth.pm`  -> 两者都不成立(既不相等, 也不以 `.*.booth.pm` 结尾)  ❌ 永远不匹配

    所以 `*.x` 必须转成裸 `x`。这是**语义等价**变换而非放宽: 前缀 `*.` 想表达的
    "整棵子树"正是裸后缀在后缀匹配下已经具有的含义。

    与 `nrpt_manager.build_namespace_entries` 剥 `*.` 是同一个修法、同一个理由 ——
    NRPT 的 `.x` 后缀语义同理。两处都必须保持"校验/匹配对象是剥离后的裸域名"。

    非字符串、空串一律返回空串(由调用方丢弃), 避免把一个畸形条目送进白名单,
    因为白名单是**逐字节**比较的, 一个畸形条目只会静默地永不匹配。
    """
    if not isinstance(entry, str):
        return ""
    s = entry.strip().lower().rstrip(".")
    if s.startswith("*."):
        s = s[2:]
    elif s == "*":
        # 裸 `*` 没有可用的后缀语义; 放行它等于把隧道变成开放代理, 直接丢弃。
        return ""
    # NRPT 风格的前导点 (`.x`) 同样是"整棵子树"的意思 —— 与 runner 侧
    # normalizeAllowEntry 保持同一口径, 否则两个入口会对同一个写法给出不同结果。
    s = s.lstrip(".")
    return s


def build_ech_targets(profiles, allow_fn=None) -> Tuple[List[str], List[str], Dict[str, List[str]]]:
    """聚合 ECH 隧道的 (域名白名单, 全局 IP 池, 每主机 IP 池) —— **纯函数**, 便于单测

    规则 (2026-10-03 明确化):
      · 只取 `ech_enabled=True` 的画像;
      · 受控分组 (如 adult) 未被放开时, 该分组的画像**不进白名单** ——
        总闸的语义是"这些服务不许生效", 而白名单是"允许隧道转发到哪些目标"的前置面,
        把默认关闭的成人域名预先放进去与闸门语义矛盾;
      · **通配必须转成裸后缀** (2026-10-04 定因, 缺陷 W3): 画像里写的是 `*.booth.pm`,
        而 Go 侧的匹配是 `host == suffix || HasSuffix(host, "."+suffix)` ——
        字面 `*.booth.pm` **永远匹配不到** `accounts.booth.pm`(既不相等, 也不以
        `.*.booth.pm` 结尾) ⇒ 隧道对任意 booth 子域回 403。
        而 `*.x` 与裸 `x` 在 Go 的后缀语义下**本来就是同一件事**, 故剥离是语义等价
        变换, 不是放宽: 裸 `booth.pm` 同时覆盖 apex 与所有子域。
        这正是"声明覆盖了但实际必然失败"的形态, 与 nrpt_manager 的
        `build_namespace_entries` 剥 `*.` 是同一个修法、同一个理由;
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
        # ★ 剥掉 `*.`: Go 侧的后缀匹配已覆盖整个子树, 字面通配反而一条都匹配不上。
        #   顺手小写 —— 白名单是逐字节比较的, 大小写不一致同样等于不匹配。
        p_domains = [normalize_ech_allow_entry(d)
                     for d in (getattr(p, "domains", ()) or ())]
        p_domains = [d for d in p_domains if d]
        # 只收 CF 网段内的候选: 非 CF 地址进池等于"第一个地址打死整条链路" (见上)
        p_ips = [ip for ip in (getattr(p, "candidate_ips", ()) or ()) if is_cloudflare_ip(ip)]
        domains.extend(p_domains)
        ip_pool.extend(p_ips)
        for d in p_domains:
            if p_ips:
                host_ip_pool.setdefault(d, [])
                for ip in p_ips:
                    if ip not in host_ip_pool[d]:
                        host_ip_pool[d].append(ip)
    return (list(dict.fromkeys(domains)), list(dict.fromkeys(ip_pool)), host_ip_pool)
