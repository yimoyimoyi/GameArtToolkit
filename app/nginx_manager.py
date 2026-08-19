# -*- coding: utf-8 -*-
"""
PixivToolkit - Nginx 进程与端口生命周期管理引擎 (配置预检与精准 PID 版)
"""

import sys
import time
import shutil
import subprocess
from pathlib import Path
from typing import Tuple, Dict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from path_utils import NGINX_DIR
from win_utils import is_process_running, is_port_in_use, get_pids_by_name, get_silent_startup_kwargs
from nginx_generator import NginxConfGenerator
from cert_manager import CertManager

NGINX_EXE = NGINX_DIR / "nginx.exe"
CACHE_DIR = NGINX_DIR / "cache"
PID_FILE = NGINX_DIR / "logs" / "nginx.pid"

class NginxManager:
    def __init__(self, nginx_dir: Path = NGINX_DIR):
        self.nginx_dir = nginx_dir
        self.nginx_exe = self.nginx_dir / "nginx.exe"
        self.cache_dir = self.nginx_dir / "cache"
        self.pid_file = self.nginx_dir / "logs" / "nginx.pid"

    def is_running(self) -> bool:
        """检查 Nginx 进程是否正在运行"""
        return is_process_running("nginx.exe")

    def get_pid(self) -> int:
        """从 logs/nginx.pid 读取当前主进程 PID"""
        if self.pid_file.exists():
            try:
                with open(self.pid_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content.isdigit():
                        return int(content)
            except Exception:
                pass
        return 0

    def _repair_pid_file(self) -> int:
        """校验 PID 文件与实际 nginx 进程一致性, 不一致时自动修复

        nginx 进程异常重启后 PID 文件会过期, 导致 -s reload/-s stop 信号失效
        (OpenEvent ngx_reload_<过期PID> failed)。此方法在 reload/stop 前调用,
        用实际进程 PID 覆盖过期文件, 恢复信号通道。
        """
        real_pids = get_pids_by_name("nginx.exe")
        if not real_pids:
            return 0
        pid = self.get_pid()
        if pid in real_pids:
            return pid  # 一致, 无需修复
        # PID 文件过期: 优先取监听 80/443 的 nginx 实例 (数据平面), 否则取第一个
        actual = 0
        try:
            proc = subprocess.run(
                'netstat -ano | findstr "LISTENING"',
                shell=True, capture_output=True, text=True, timeout=2
            )
            for line in (proc.stdout or "").splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[4].isdigit():
                    cand = int(parts[4])
                    if cand in real_pids and (":80 " in line or ":443 " in line):
                        actual = cand
                        break
        except Exception:
            pass
        if not actual:
            actual = real_pids[0]
        try:
            with open(self.pid_file, "w", encoding="utf-8") as f:
                f.write(str(actual))
        except Exception:
            pass
        return actual

    def test_config(self) -> Tuple[bool, str]:
        """执行 nginx -t 进行语法与 upstream 预检 (包含前置模板渲染)"""
        if not self.nginx_exe.exists():
            return False, "未找到 nginx.exe"
        try:
            # 1. 自动从 ServiceProfile 单源渲染三大站点配置
            NginxConfGenerator.generate_all(self.nginx_dir / "conf")

            # 2. 自动确保证书与私钥在本地按需自生成就绪 (零分发与自愈)
            CertManager(cer_path=self.nginx_dir / "ca.cer", nginx_dir=self.nginx_dir).ensure_certificates()

            # 3. 仅当 upstream-dynamic.conf 缺失时生成兜底配置 (避免覆盖已优选的节点)
            upstream_conf = self.nginx_dir / "conf" / "upstream-dynamic.conf"
            if not upstream_conf.exists():
                from cdn_optimizer import CDNOptimizer
                CDNOptimizer(upstream_conf).apply_optimal({})

            # 3. 执行 Nginx 语法预检
            cmd = [str(self.nginx_exe), "-p", str(self.nginx_dir), "-c", "conf/nginx.conf", "-t"]
            proc = subprocess.run(
                cmd, cwd=str(self.nginx_dir), capture_output=True,
                text=True, errors="ignore", timeout=4, **get_silent_startup_kwargs()
            )
            if proc.returncode == 0 or "syntax is ok" in proc.stderr.lower() or "syntax is ok" in proc.stdout.lower():
                return True, "Nginx 配置语法预检通过"
            err_msg = (proc.stderr or proc.stdout).strip()
            return False, f"Nginx 配置语法错误: {err_msg}"
        except Exception as e:
            return False, f"预检 Nginx 配置异常: {e}"

    def check_port_occupancy(self, port: int) -> Dict:
        """诊断指定端口是否被占用"""
        occupied = is_port_in_use(port)
        return {
            "occupied": occupied,
            "pid": self.get_pid() if (occupied and self.is_running()) else None,
            "process_name": "nginx.exe" if (occupied and self.is_running()) else ("Occupied" if occupied else "None")
        }

    def start(self, force_restart: bool = False) -> Tuple[bool, str]:
        """启动 Nginx 进程 (支持自动刷新配置与防陈旧进程，全静默无窗)"""
        if not self.nginx_exe.exists():
            return False, f"未找到 nginx.exe: {self.nginx_exe}"

        # 配置预检
        ok, test_msg = self.test_config()
        if not ok:
            return False, test_msg

        if self.is_running():
            if force_restart:
                self.stop()
                time.sleep(0.3)
            else:
                self.reload()
                return True, "Nginx 配置已刷新并处于运行状态"

        # 检查 443 端口
        if is_port_in_use(443):
            return False, "443 端口已被其他程序占用，请先关闭占用程序！"

        try:
            for sub in ["logs", "temp", "cache"]:
                (self.nginx_dir / sub).mkdir(parents=True, exist_ok=True)

            cmd = [str(self.nginx_exe), "-p", str(self.nginx_dir), "-c", "conf/nginx.conf"]
            subprocess.Popen(
                cmd, cwd=str(self.nginx_dir), shell=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                **get_silent_startup_kwargs()
            )
            time.sleep(0.4)

            if self.is_running():
                return True, "Nginx 加速引擎启动成功！"
            else:
                return False, "Nginx 启动失败，请检查端口冲突或 logs/error.log。"
        except Exception as e:
            return False, f"启动 Nginx 异常: {e}"

    def stop(self) -> Tuple[bool, str]:
        """停止 Nginx 进程（基于 PID 精准终止，全静默无窗）"""
        if not self.is_running():
            return True, "Nginx 未在运行"

        # PID 文件一致性校验: 防止 nginx 重启后信号失效导致无法停止
        self._repair_pid_file()

        pid = self.get_pid()

        # 1. 优先优雅停止
        try:
            subprocess.run(
                [str(self.nginx_exe), "-p", str(self.nginx_dir), "-s", "stop"],
                cwd=str(self.nginx_dir), capture_output=True, timeout=2,
                **get_silent_startup_kwargs()
            )
            time.sleep(0.2)
        except Exception:
            pass

        # 2. 若依然存活，根据 PID 树强制终止本实例
        if self.is_running():
            if pid > 0:
                try:
                    subprocess.run(
                        f"taskkill /F /T /PID {pid}", shell=True,
                        capture_output=True, timeout=2, **get_silent_startup_kwargs()
                    )
                    time.sleep(0.2)
                except Exception:
                    pass

        # 3. 兜底尝试停止
        if self.is_running():
            try:
                subprocess.run(
                    [str(self.nginx_exe), "-p", str(self.nginx_dir), "-s", "quit"],
                    cwd=str(self.nginx_dir), capture_output=True, timeout=2,
                    **get_silent_startup_kwargs()
                )
                time.sleep(0.2)
            except Exception:
                pass

        if not self.is_running():
            if self.pid_file.exists():
                try:
                    self.pid_file.unlink(missing_ok=True)
                except Exception:
                    pass
            return True, "Nginx 加速引擎已安全停止。"
        return False, "停止 Nginx 超时。"

    def reload(self) -> Tuple[bool, str]:
        """热重载 Nginx 配置（零中断，前置语法预检，全静默无窗）"""
        if not self.is_running():
            return self.start()

        # PID 文件一致性校验: 防止 nginx 重启后信号失效
        self._repair_pid_file()

        # 前置语法自检，防止破损配置打崩服务
        ok, test_msg = self.test_config()
        if not ok:
            return False, test_msg

        try:
            cmd = [str(self.nginx_exe), "-p", str(self.nginx_dir), "-s", "reload"]
            proc = subprocess.run(
                cmd, cwd=str(self.nginx_dir), capture_output=True,
                text=True, errors="ignore", timeout=3, **get_silent_startup_kwargs()
            )
            if proc.returncode == 0:
                return True, "Nginx 热重载成功！"
            return False, f"热重载失败: {proc.stderr or proc.stdout}"
        except Exception as e:
            return False, f"热重载异常: {e}"

    def clear_cache(self) -> Tuple[bool, str]:
        """安全清理 Pixiv 图片本地磁盘缓存"""
        deleted = 0
        try:
            if self.cache_dir.exists():
                for item in self.cache_dir.iterdir():
                    try:
                        if item.is_dir():
                            shutil.rmtree(item, ignore_errors=True)
                        else:
                            item.unlink(missing_ok=True)
                        deleted += 1
                    except Exception:
                        continue
            return True, f"本地图片缓存已清理完成！(清理了 {deleted} 个缓存分片)"
        except Exception as e:
            return False, f"清空缓存异常: {e}"
