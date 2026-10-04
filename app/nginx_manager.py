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
from nginx_generator import NginxConfGenerator, _atomic_write_text
import cert_manager
from cert_manager import CertManager

NGINX_EXE = NGINX_DIR / "nginx.exe"
CACHE_DIR = NGINX_DIR / "cache"
PID_FILE = NGINX_DIR / "logs" / "nginx.pid"

# nginx `stub_status` 端点端口 (2026-10-04 新增)。
# ⚠ 单一真源: nginx.conf 里那个 `listen 127.0.0.1:<此端口>` 必须与本值一致。
#   为什么单列一个端口而不是复用 80/443: 那两处已被 default_server 与全部 site-*.conf
#   占用 (host 路由), 再塞一个状态 location 会与"未登记域名一律 444"的语义纠缠。
#   该端口与既有段无冲突: relay 44311-44374 / ECH 44401 / h3 腿 44411 / PAC 44500-44501。
NGINX_STATUS_PORT = 44421


def parse_stub_status(text: str) -> Dict:
    """解析 nginx `stub_status` 的回应体 (纯函数, 便于单测)

    实测原始回应体形如 (2026-10-04, 本机临时 nginx 验证)::

        Active connections: 1
        server accepts handled requests
         1 1 1
        Reading: 0 Writing: 1 Waiting: 0

    解析不出任何字段时返回 {} —— 表示"没拿到", 而不是"取到了 0"。
    """
    out: Dict = {}
    if not text:
        return out
    m = re.search(r"Active connections:\s*(\d+)", text)
    if m:
        out["active"] = int(m.group(1))
    m = re.search(r"server accepts handled requests\s*\n\s*(\d+)\s+(\d+)\s+(\d+)", text)
    if m:
        out["accepts"] = int(m.group(1))
        out["handled"] = int(m.group(2))
        out["requests"] = int(m.group(3))
    m = re.search(r"Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)", text)
    if m:
        out["reading"] = int(m.group(1))
        out["writing"] = int(m.group(2))
        out["waiting"] = int(m.group(3))
    return out

class NginxManager:
    def __init__(self, nginx_dir: Path = NGINX_DIR):
        self.nginx_dir = nginx_dir
        self.nginx_exe = self.nginx_dir / "nginx.exe"
        self.cache_dir = self.nginx_dir / "cache"
        self.pid_file = self.nginx_dir / "logs" / "nginx.pid"

    def fetch_status(self) -> Dict:
        """读取 nginx `stub_status` 快照 (只读; 失败/未运行一律返回 {})

        ## 为什么是 stub_status (2026-10-04)

        控制台原有一个"实时网络流量监控"面板, 但它**从未接过数据源** —— 每秒被灌入
        `0.0/0.0/0/0`, 因此永远是平线。要真字节数有两条路, 都被有意堵死:
          · nginx access_log **被刻意全局关闭** (见 nginx.conf 的说明: 该文件实测
            183.9 MB, 且记录解密后的完整请求行含 token ⇒ 占空间 + 留存凭据);
          · 数据面在 127.0.0.1 上, 而 loopback 计数器**不计数** (实测 recv/sent 均为 0),
            物理网卡则是整机流量且回源字节被算两次。
        ⇒ 改用 stub_status: 零磁盘开销、无字节、不碰凭据, 给的是"有多少连接 / 服务了
          多少请求"这个真实口径。端点由 nginx.conf 的 `listen 127.0.0.1:44421` 承载
          (仅回环可达, 实测从网卡地址连接被拒)。

        返回值键: active / accepts / handled / requests / reading / writing / waiting。
        **不可用时不编造 0** —— 返回 {} 让调用方区分"nginx 没在跑"与"此刻没有连接"。
        """
        try:
            import urllib.request
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{NGINX_STATUS_PORT}/nginx_status", timeout=2.0) as r:
                text = r.read().decode("utf-8", "replace")
        except Exception:
            return {}
        return parse_stub_status(text)

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

        ★ 分工已变更 (2026-10-03, 按用户定的不变式): 本方法现在**也负责收敛信任库** ——
        调用 `cert_manager.ensure_single_usable_ca()`, 使状态满足"任一刻恰好有一个可用的根":
          叶子由当前 ca.cer 签发 + 当前根已装机 + 其它自有根已清理 (三者皆幂等)。
        为什么必须放在启动路径上: `nginx -t` 与 `curl -k` **都测不出**断链, 而断链的表现是
          "所有本地域名不受信"; 实测本机出现过"源码树 ca.cer 不在信任库"的状态。
        为什么仍与 test_config() 分开: 那是**只读预检**, 不得有副作用 —— 这条分界没变。
        信任库操作需要管理员; 无权限时**不阻断**(如实报告), 以免把程序锁死在起不来的状态。
        """
        try:
            _cm = CertManager(cer_path=self.nginx_dir / "ca.cer", nginx_dir=self.nginx_dir)
            ok, msg = cert_manager.ensure_single_usable_ca(_cm)
        except Exception as e:
            return False, f"本地证书自检失败: {type(e).__name__}: {e}"

        # ★ 运行清单校验 (2026-10-03): 证书文件齐了**不等于链是通的**。
        #   分两类, 因为它们的"能不能立刻修"完全不同:
        #     · **本地不变量** (文件齐全 / ca.key 与 ca.cer 配套 / 叶子由本目录的 CA 签发)
        #       —— 任何环境下都必须成立 ⇒ **阻断**;
        #     · **信任库** (签发叶子的根是否已装进系统信任库) —— 依赖环境 (是否装过机、
        #       打包版是否换过根) ⇒ **告警**, 不阻断。沙箱测试里 CA 是现生成的、并未装机,
        #       把它也当阻断会让测试无辜变红。
        #   ⚠ 验签本身曾经写错并**恒返回 False**, 导致我据此虚报过一次"证书事故";
        #     修正后的 _is_signed_by 用 verify_directly_issued_by, 详见其 docstring。
        try:
            import runtime_manifest
            local = list(runtime_manifest.check(self.nginx_dir, include_trust=False))
            trust = [p for p in runtime_manifest.check(self.nginx_dir) if p not in local]
        except Exception as e:                  # 校验本身绝不该把启动带崩
            local, trust = [], [f"运行清单校验本身失败: {type(e).__name__}: {e}"]
        self.runtime_problems = local + trust
        if local and ok:
            return False, "运行清单校验未通过: " + "; ".join(local)
        if trust:
            msg = f"{msg} | ⚠ 运行清单(信任库): " + "; ".join(trust)
        return ok, msg

    def test_config(self) -> Tuple[bool, str]:
        """执行 nginx -t 预检: **渲染 → 语法预检 → 通过才提交** (原缺陷 M1)

        ## 原实现的两个问题 (2026-10-03 定因)

        ① **自称只读却会改被跟踪文件**: 它内部直接调
           `NginxConfGenerator.generate_all(self.nginx_dir / "conf")`,
           于是每次启动、每次 `reload()` 都重写 `nginx/conf/site-*.conf` 三个**被 git 跟踪**
           的文件 —— 而 `generate_all` 旧实现又是三次裸 `write_text`(非原子)。
           这把"看一眼配置对不对"变成了"改动工作树"。
        ② **先落盘再预检**: 万一新增画像渲染出的配置非法, 磁盘上已经是被改坏的版本,
           nginx 下次 reload 会直接拒载 (而 site 与 upstream 是一对, 混合状态尤其危险)。

        ## 现在的流程

          1. 备齐 `upstream-dynamic.conf` 与缺失的 upstream 块 (这一步本来就必要);
          2. 把**正式 conf 目录**整体复制到 `<cache>/precheck/<pid>/conf`, 在那里渲染;
          3. 用该临时 prefix 跑 `nginx -t`;
          4. **只有预检通过**才把渲染结果 `os.replace` 提交回正式目录 (单文件原子)。

        ⚠ 写在 `cache/` 下、且每次调用带 PID 后缀, 是为了不进入被跟踪路径、
          也不与并发的另一次预检互相踩 (本函数可能被 UI 线程与看门狗同时调用)。
        """
        if not self.nginx_exe.exists():
            return False, "未找到 nginx.exe"
        try:
            from cdn_optimizer import CDNOptimizer
            conf_dir = self.nginx_dir / "conf"
            upstream_conf = conf_dir / "upstream-dynamic.conf"

            # 1. 先确保 upstream-dynamic.conf 就绪 —— site 配置里 proxy_pass 的协议
            #    以该文件实际写入的后端为准 (走 ECH 隧道是回环明文 HTTP 入口, 退化
            #    到候选池则是 https), 故它必须先于站点配置存在, 否则首轮渲染会按
            #    "隧道不可用" 输出 https:// 而 upstream 实际写的是隧道地址。
            if not upstream_conf.exists():
                ok_apply, _ = CDNOptimizer(upstream_conf).apply_optimal({})
                if not ok_apply:
                    return False, "自动补全 upstream 配置失败 (缺失: 文件缺失)"

            # ⚠ 证书生成**已从这里移走** (2026-10-02 定因):
            #   `test_config()` 的语义是"`nginx -t` 语法预检" —— 一个**看起来只读**的动作。
            #   而它原先会在里面调用 `CertManager(...).ensure_certificates()`, 也就是
            #   **测一下配置就可能铸造一个新的根证书并改写全机受信任存储**。
            #   这与"审计/预检不得有副作用"直接冲突, 也正是 4 次"在用根被删"事故里
            #   那一步的触发面 (生成发生在非预期目录时, 旧根会被当陈旧清除)。
            #   现在改由启动流程在调用 test_config() **之前**显式确保一次, 见 start()。

            # 2. site 引用的 upstream 未定义时自动补全
            #    (新增 ServiceProfile 后 site 配置会引用新 upstream, 若未重新测速则 nginx 无法启动;
            #    增量合并保留既有已优选节点, 仅补充缺失服务块)
            try:
                text = upstream_conf.read_text(encoding="utf-8", errors="ignore")
                defined = set(re.findall(r"upstream (upstream_[a-z0-9_]+)", text))
                refs = CDNOptimizer(upstream_conf)._scan_site_upstream_refs()
                missing_refs = sorted(refs - defined)
            except Exception:
                missing_refs = []
            if missing_refs:
                ok_apply, _ = CDNOptimizer(upstream_conf).apply_optimal({})
                if not ok_apply:
                    return False, f"自动补全 upstream 配置失败 (缺失: {missing_refs})"

            # 3. 渲染 + 预检 + 提交
            return self._render_precheck_and_commit(conf_dir)
        except Exception as e:
            return False, f"预检 Nginx 配置异常: {e}"

    def _stage_conf_dir(self, src_conf: Path) -> Path:
        """把正式 conf 目录复制到一个**临时 prefix** 下, 返回该 prefix 的 conf 路径

        为什么不就地渲染再预检: 见 test_config() 的说明 —— 就地渲染等于
        "先改被跟踪文件、再检查改得对不对"。
        为什么整个复制而不是只复制 .conf: nginx 的 `-c` 是相对 prefix 的路径,
        且 conf 里含 `ca/` 证书 (预检需要能读到它们)。conf 只有 ~0.1MB, 复制很便宜。

        ⚠ **必须补齐 prefix 的骨架目录** (logs / cache / temp / html)。实测教训:
          nginx 启动时会先去开 `logs/error.log`, 目录不存在就直接
          `[alert] could not open error log file ... (3: The system cannot find the path specified)`
          并**预检失败** —— 而我最初的实现把它当成"配置语法错", 于是预检永不通过,
          修正后的配置再也提交不出去 (磁盘上留下的是更早那次坏渲染)。
          这个坑的形态值得记住: **"预检环境的缺陷"会伪装成"被测对象的缺陷"**。
        """
        import os as _os
        import shutil as _shutil
        import tempfile as _tempfile
        base = self.nginx_dir / "cache" / "precheck"
        base.mkdir(parents=True, exist_ok=True)
        tmp = Path(_tempfile.mkdtemp(prefix=f"t{_os.getpid()}_", dir=str(base)))
        _shutil.copytree(src_conf, tmp / "conf")
        # 骨架目录: 只要存在即可, nginx 会自己往里写 / 自己建需要的子目录
        for sub in ("logs", "cache", "temp", "html"):
            (tmp / sub).mkdir(parents=True, exist_ok=True)
        self._precheck_tmp = tmp
        return tmp / "conf"

    def _cleanup_precheck(self) -> None:
        tmp = getattr(self, "_precheck_tmp", None)
        if tmp is not None:
            try:
                shutil.rmtree(tmp, ignore_errors=True)
            except Exception:
                pass
            self._precheck_tmp = None

    def _render_precheck_and_commit(self, conf_dir: Path) -> Tuple[bool, str]:
        """在临时 prefix 里渲染并 `nginx -t`; 通过才把渲染结果提交回正式目录

        ⚠ **关键顺序**: 必须先把渲染结果**写进临时目录**, 再跑 `nginx -t`。
          实测踩到过反过来的写法: 只拿到渲染出的文本、没写进临时 conf, 于是
          `nginx -t` 校验的是**临时目录里从正式目录复制过来的旧内容** ——
          预检"通过", 然后坏内容被提交到正式目录。
          这个坑的形态很值得记住: **预检对象与提交对象不是同一份**时,
          预检通过与否与"要提交的东西合不合法"毫无关系。
        """
        staged_conf = self._stage_conf_dir(conf_dir)
        try:
            # 1) 在临时目录里渲染并**落盘到临时目录** (正式目录此刻一个字节都没动)
            try:
                rendered = NginxConfGenerator.render_all(staged_conf)
            except Exception as e:
                return False, f"站点配置渲染失败: {e}"
            for name, content in rendered.items():
                try:
                    _atomic_write_text(staged_conf / name, content)
                except Exception as e:
                    return False, f"临时站点配置写入失败 ({name}): {e}"

            # 2) 用临时 prefix 预检 —— 此刻校验的正是**将要提交的那份内容**。
            #    cwd 即 prefix (不传 -p, 以避免 Windows 下中文路径 ANSI 转换 1113 错误,
            #    与旧实现同一口径)。
            prefix = staged_conf.parent
            proc = subprocess.run(
                [str(self.nginx_exe), "-c", "conf/nginx.conf", "-t"],
                cwd=str(prefix), capture_output=True,
                text=True, errors="ignore", timeout=8, **get_silent_startup_kwargs()
            )
            ok = (proc.returncode == 0
                  or "syntax is ok" in (proc.stderr or "").lower()
                  or "syntax is ok" in (proc.stdout or "").lower())
            if not ok:
                err_msg = (proc.stderr or proc.stdout or "").strip()
                return False, f"Nginx 配置语法错误: {err_msg}"

            # 3) 预检通过 ⇒ 提交 (每个文件 tmp + os.replace, 不会出现半截内容)
            dirty = []
            for name, content in rendered.items():
                target = conf_dir / name
                try:
                    if target.exists() and target.read_text(
                            encoding="utf-8", errors="ignore") == content:
                        continue          # 内容没变就不动文件 (避免无意义的 mtime 抖动)
                except Exception:
                    pass
                _atomic_write_text(target, content)
                dirty.append(name)
            if dirty:
                return True, f"Nginx 配置语法预检通过 (已更新: {', '.join(sorted(dirty))})"
            return True, "Nginx 配置语法预检通过 (无变更)"
        finally:
            self._cleanup_precheck()

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

            # prefix 必须等于项目目录 (pid 文件 logs/nginx.pid 与 reload/stop 依赖的
            # 信号通道都以它为基准), 但**不能用 `-p <绝对路径>` 来表达** —— nginx 的
            # Windows 入口是 ANSI 的 main(argc, argv), 带非 ASCII 的 `-p` 会在
            # UTF-16→ANSI 往返中失真。实测 (2026-10-04, 临时中文目录 + 全量 conf):
            #   · `-p <中文绝对路径>`   → exit 1: CreateFile(.../logs/error.log) failed
            #                             (1113: No mapping for the Unicode character
            #                             exists in the target multi-byte code page)
            #                             —— 连 error log 都开不了, 配置更读不到
            #   · cwd=中文目录 + `-p .` → exit 0
            #   · cwd=中文目录 + 不给 -p → exit 0, pid 解析为完整中文绝对路径
            #   · cwd=C:\ + 不给 -p     → 去找 `C:\/conf/nginx.conf`
            #     ⇒ **prefix 实测取自 cwd** (不是 exe 所在目录), 即 cwd 本身就是前缀。
            # 因此这里只传 `-c` 并把 cwd 设为 nginx_dir —— 与 `nginx -t` 预检路径
            # (_stage_conf_dir 同样是"cwd 即 prefix") 口径统一。
            # ⚠ start / reload / stop / quit 四处必须一致: 前缀不同则 nginx 会去别的
            #   目录找 pid 文件, 报 OpenEvent failed, 表现为"能服务但永远无法 reload/stop"。
            cmd = [str(self.nginx_exe), "-c", "conf/nginx.conf"]
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

        # 1. 优先优雅停止 (cwd 即 prefix, 与 start/reload 一致 —— 见 start() 里的实测说明;
        #    绝不能传非 ASCII 的 `-p`)
        try:
            subprocess.run(
                [str(self.nginx_exe), "-s", "stop"],
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
                    [str(self.nginx_exe), "-s", "quit"],
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
            # cwd 必须与 start() 一致 (cwd 即 prefix, 见 start() 的实测说明): 前缀不同
            # 时 nginx 会去别的目录找 pid 文件, 找不到 master 就报 OpenEvent failed,
            # 热重载永远失败。同样**不得**传非 ASCII 的 `-p`。
            cmd = [str(self.nginx_exe), "-s", "reload"]
            proc = subprocess.run(
                cmd, cwd=str(self.nginx_dir), capture_output=True,
                text=True, errors="ignore", timeout=3, **get_silent_startup_kwargs()
            )
            if proc.returncode == 0:
                return True, "Nginx 热重载成功！"
            return False, f"热重载失败: {proc.stderr or proc.stdout}"
        except Exception as e:
            return False, f"热重载异常: {e}"

    # 自写日志文件的大小上限 (缺陷 D5, 2026-10-04)。单项超过即截断到尾部这段长度。
    LOG_TRUNCATE_BYTES = 2 * 1024 * 1024   # 2 MB

    def _trim_logs(self) -> Tuple[int, int]:
        """按大小截断自写日志, 返回 (处理文件数, 释放字节数)

        为什么需要: 这些日志由 nginx / 隧道**追加写、不轮转**, 而没有任何东西会缩小
        它们 —— 实测旧实例的 `access.log` 曾长到 **183.9 MB**。`access_log off` 已经
        止住了新增 (见 nginx.conf), 但**既有文件与隧道日志仍在增长**, 且原先的
        `clear_cache()` 只清 `cache/img`, 完全覆盖不到 logs 目录。

        做法是"截断保留尾部"而不是删除: 排障时最近的行才有用, 而直接删文件会让
        nginx 继续往一个已 unlink 的句柄写 (Windows 上多半直接失败),
        也会让用户/支持人员丢掉刚发生的那次故障现场。
        """
        handled = freed = 0
        logs_dir = self.nginx_dir / "logs"
        if not logs_dir.exists():
            return 0, 0
        for f in logs_dir.glob("*"):
            try:
                if not f.is_file():
                    continue
                size = f.stat().st_size
                if size <= self.LOG_TRUNCATE_BYTES:
                    continue
                with open(f, "rb") as fh:
                    fh.seek(size - self.LOG_TRUNCATE_BYTES)
                    tail = fh.read()
                # 从行边界开始, 避免留下半行 (半行会让解析日志的代码读到残缺记录)
                nl = tail.find(b"\n")
                if nl >= 0:
                    tail = tail[nl + 1:]
                with open(f, "wb") as fh:
                    fh.write(tail)
                try:
                    freed += max(0, size - f.stat().st_size)
                except Exception:
                    pass
                handled += 1
            except Exception:
                continue
        return handled, freed

    def clear_cache(self) -> Tuple[bool, str]:
        """安全清理本地磁盘缓存**与自写日志** (缺陷 D5: 日志原先不在清理范围内)"""
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
            # 日志一并按大小收敛 —— 用户点"清理"时的预期是"把占地方的东西收掉",
            # 而 183.9 MB 的 access.log 显然属于"占地方的东西"。
            logs_handled, logs_freed = self._trim_logs()
            tail = ""
            if logs_handled:
                tail = f", 另有 {logs_handled} 个日志文件超限已截断 (释放 {logs_freed / 1048576:.1f} MB)"
            return True, f"本地图片缓存已清理完成！(清理了 {deleted} 个缓存分片{tail})"
        except Exception as e:
            return False, f"清空缓存异常: {e}"
