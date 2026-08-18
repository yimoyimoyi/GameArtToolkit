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
from win_utils import is_process_running, is_port_in_use, get_silent_startup_kwargs

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
        """检查 Nginx 进程是否正在运行 (毫秒级)"""
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

    def test_config(self) -> Tuple[bool, str]:
        """执行 nginx -t 进行语法与 upstream 预检"""
        if not self.nginx_exe.exists():
            return False, "未找到 nginx.exe"
        try:
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
        """极速诊断指定端口是否被占用"""
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
