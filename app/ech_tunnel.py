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

    def status(self) -> Dict:
        return {
            "running": self.is_running(),
            "listening": self.is_listening(),
            "healthy": self.is_healthy(),
            "port": self.port,
            "pids": self.get_pids(),
        }

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def build_command(
        self,
        domains: List[str],
        ip_pool: Optional[List[str]] = None,
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
        return cmd

    def start(
        self,
        domains: List[str],
        ip_pool: Optional[List[str]] = None,
        doh_endpoints: Optional[List[str]] = None,
        force_restart: bool = False,
    ) -> Tuple[bool, str]:
        """启动隧道。已在运行且 force_restart=False 时直接返回成功。"""
        if not self.exe_path.exists():
            return False, (
                f"未找到隧道可执行文件: {self.exe_path}\n"
                f"请先执行 tools/ech_tunnel/build.ps1 构建"
            )

        if not domains:
            return False, "未指定任何域名白名单, 拒绝启动 (隧道将不限制目标域名)"

        if self.is_running():
            if not force_restart:
                return True, f"ECH 隧道已在运行 ({self.get_pids()})"
            self.stop()
            time.sleep(0.3)

        # 端口被非本程序占用: 明确报错而不是静默失败
        if is_port_in_use(self.port):
            return False, f"端口 {self.port} 已被其他程序占用, 无法启动 ECH 隧道"

        cmd = self.build_command(domains, ip_pool, doh_endpoints)

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
        doh_endpoints: Optional[List[str]] = None,
    ) -> Tuple[bool, str]:
        """重启隧道 (域名白名单变化时使用)"""
        self.stop()
        return self.start(domains, ip_pool, doh_endpoints, force_restart=True)

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
