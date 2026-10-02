# -*- coding: utf-8 -*-
"""
GameArt Toolkit - Nginx 进程与端口生命周期管理引擎 (配置预检与精准 PID 版)
"""

import sys
import re
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

    def is_master_alive(self) -> bool:
        """pid 文件记录的 master 是否仍然存活

        为什么不能只看 is_running(): 后者按进程名判断, 孤儿 worker 同样为真。
        而 nginx 的 reload/stop 信号通道 (Global\\ngx_reload_<master_pid>) 以
        master 为基准 —— master 一旦消失, 只剩 worker 时任何热重载都注定失败,
        且 _repair_pid_file 会把 worker 的 PID 写进 pid 文件, 让状态进一步污染
        (worker 监听 80/443, 正是它被误判为 master 的原因)。据此可识别该状态。
        """
        pid = self.get_pid()
        return pid > 0 and pid in get_pids_by_name("nginx.exe")

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
                shell=True, capture_output=True, text=True, errors="replace", timeout=2
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

    def prepare_certificates(self) -> Tuple[bool, str]:
        """确保证书与私钥就绪 (幂等; 按需自签发/重签发以覆盖新增域名)

        ★ 这是**唯一**会改动证书的入口 (2026-10-02 从 test_config() 里挪出来)。
        为什么必须显式成一个方法而不是留在"语法预检"里:
          `test_config()` 的语义是 `nginx -t` 预检 —— 一个**看起来只读**的动作。
          而它原先内含 `ensure_certificates()`, 也就是"测一下配置就可能铸造新根证书并
          改写全机受信任存储"。这与"预检不得有副作用"直接冲突, 也是 4 次"在用根被删"
          事故里那一步的触发面。现在把它显式化: 预检只读, 证书准备由 start() 调用一次。

        注意与"信任库"的分工: 本方法只负责**本目录**的证书文件 (叶证书按 SAN 重签),
        不动受信任存储 —— 装机/清理那条路径在 app/cert_manager.py 的 install_cert /
        prune_stale_trust_roots, 两者刻意分开。
        """
        try:
            return CertManager(cer_path=self.nginx_dir / "ca.cer",
                               nginx_dir=self.nginx_dir).ensure_certificates()
        except Exception as e:
            return False, f"本地证书自检失败: {type(e).__name__}: {e}"

    def test_config(self) -> Tuple[bool, str]:
        """执行 nginx -t 进行语法与 upstream 预检 (包含前置模板渲染)"""
        if not self.nginx_exe.exists():
            return False, "未找到 nginx.exe"
        try:
            from cdn_optimizer import CDNOptimizer
            upstream_conf = self.nginx_dir / "conf" / "upstream-dynamic.conf"

            # 1. 先确保 upstream-dynamic.conf 就绪 —— site 配置里 proxy_pass 的协议
            #    以该文件实际写入的后端为准 (走 ECH 隧道是回环明文 HTTP 入口, 退化
            #    到候选池则是 https), 故它必须先于站点配置存在, 否则首轮渲染会按
            #    "隧道不可用" 输出 https:// 而 upstream 实际写的是隧道地址。
            if not upstream_conf.exists():
                ok_apply, _ = CDNOptimizer(upstream_conf).apply_optimal({})
                if not ok_apply:
                    return False, "自动补全 upstream 配置失败 (缺失: 文件缺失)"

            # 2. 自动从 ServiceProfile 单源渲染三大站点配置
            NginxConfGenerator.generate_all(self.nginx_dir / "conf")

            # ⚠ 证书生成**已从这里移走** (2026-10-02 定因):
            #   `test_config()` 的语义是"`nginx -t` 语法预检" —— 一个**看起来只读**的动作。
            #   而它原先会在里面调用 `CertManager(...).ensure_certificates()`, 也就是
            #   **测一下配置就可能铸造一个新的根证书并改写全机受信任存储**。
            #   这与"审计/预检不得有副作用"直接冲突, 也正是 4 次"在用根被删"事故里
            #   那一步的触发面 (生成发生在非预期目录时, 旧根会被当陈旧清除)。
            #   现在改由启动流程在调用 test_config() **之前**显式确保一次, 见 start()。

            # 4. site 引用的 upstream 未定义时自动补全
            #    (新增 ServiceProfile 后 site 配置会引用新 upstream, 若未重新测速则 nginx 无法启动;
            #    增量合并保留既有已优选节点, 仅补充缺失服务块)
            missing_refs = []
            try:
                text = upstream_conf.read_text(encoding="utf-8", errors="ignore")
                defined = set(re.findall(r"upstream (upstream_[a-z0-9_]+)", text))
                refs = CDNOptimizer(upstream_conf)._scan_site_upstream_refs()
                missing_refs = sorted(refs - defined)
            except Exception:
                pass
            if missing_refs:
                ok_apply, _ = CDNOptimizer(upstream_conf).apply_optimal({})
                if not ok_apply:
                    return False, f"自动补全 upstream 配置失败 (缺失: {missing_refs})"
                # upstream 内容已变: 重新渲染一次, 让 proxy_pass 的协议跟上
                NginxConfGenerator.generate_all(self.nginx_dir / "conf")

            # 3. 执行 Nginx 语法预检 (不传 -p 以避免 Windows 下中文路径 ANSI 转换 1113 错误，以 cwd 为 prefix)
            cmd = [str(self.nginx_exe), "-c", "conf/nginx.conf", "-t"]
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
        # 证书必须先于预检就绪 —— 它原先藏在 test_config() 里面 (见那里的注释),
        # 使"语法预检"带上"铸造根证书并改全机信任"的副作用。挪到启动流程显式调用:
        # 预检保持只读, 而"确保证书"这件事仍然在启动时完成一次 (自愈能力不变)。
        ok_c, msg_c = self.prepare_certificates()
        if not ok_c:
            return False, msg_c
        ok, test_msg = self.test_config()
        if not ok:
            return False, test_msg

        if self.is_running():
            # 孤儿 worker 状态 (进程在但 master 已消失) 必须强制重启而非热重载:
            # reload 的信号通道以 master 为基准, 此时必然 OpenEvent failed, 而
            # _repair_pid_file 还会把 worker 的 PID 写进 pid 文件让状态更脏。
            # stop() 走 taskkill /F /T 杀进程树, 能把 master+worker 一并清掉。
            if force_restart or not self.is_master_alive():
                self.stop()
                time.sleep(0.3)
            else:
                ok, reload_msg = self.reload()
                if ok:
                    return True, "Nginx 配置已刷新并处于运行状态"
                # 热重载失败不再静默吞掉 (原先无条件 return True, 导致配置更新
                # 实际未生效却报成功)。降级为强制重启, 重启也失败才向上报错。
                self.stop()
                time.sleep(0.3)

        # 检查 80 与 443 端口
        if is_port_in_use(80):
            return False, "80 端口已被其他程序(如 IIS/Skype/World Wide Web Publishing)占用，请先关闭占用程序！"
        if is_port_in_use(443):
            return False, "443 端口已被其他程序占用，请先关闭占用程序！"

        try:
            for sub in ["logs", "temp", "cache"]:
                (self.nginx_dir / sub).mkdir(parents=True, exist_ok=True)

            # 必须显式指定 -p 前缀。缺省时 nginx 使用编译期默认 prefix, 而 pid 文件
            # (logs/nginx.pid) 与 reload/stop 依赖的 Global\ngx_reload_<master_pid>
            # 事件对象都以 prefix 为基准, 于是全部与项目目录错位 —— 实测表现为
            # master 启动后随即退出、只剩一个孤儿 worker 占着 80/443 (能服务请求但
            # 永远无法 reload/stop, OpenEvent 恒报错), 且该状态会长期残留。
            cmd = [str(self.nginx_exe), "-p", str(self.nginx_dir), "-c", "conf/nginx.conf"]
            # CREATE_BREAKAWAY_FROM_JOB: 让 nginx master 脱离本进程的 Job Object。
            # Windows 下 subprocess 创建的子进程默认继承调用方的 Job, 一旦本进程退出、
            # Job 关闭, master 会被连带终止 (worker 反而存活), 结果只剩一个孤儿 worker
            # 占着 80/443 —— 它能服务请求却永远无法 reload/stop (OpenEvent 恒报错),
            # 并且阻塞下次启动。宿主 Job 不允许 breakaway 时 CreateProcess 会直接失败,
            # 故回退常规启动以兼容受限环境。
            flags = get_silent_startup_kwargs()
            flags["creationflags"] = flags.get("creationflags", 0) | subprocess.CREATE_BREAKAWAY_FROM_JOB
            try:
                subprocess.Popen(cmd, cwd=str(self.nginx_dir), shell=False,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **flags)
            except OSError:
                flags["creationflags"] &= ~subprocess.CREATE_BREAKAWAY_FROM_JOB
                subprocess.Popen(cmd, cwd=str(self.nginx_dir), shell=False,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **flags)
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

        # 1. 优先优雅停止 (-p 同 start/reload: 信号通道以 prefix 为基准)
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
            # -p 必须与 start() 一致, 否则 nginx 会去默认 prefix 下找 pid 文件,
            # 找不到 master 就报 OpenEvent failed, 热重载永远失败
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
