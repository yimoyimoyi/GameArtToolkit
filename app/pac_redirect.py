# -*- coding: utf-8 -*-
"""
GameArt Toolkit - PAC + 本地 CONNECT 转发 域名重定向后端 (2026-10-02 新增)

## 为什么需要这个后端 (它解决的是什么问题)

googlevideo 的节点名是**动态且海量**的 (rr1---sn-xxxx.googlevideo.com), 而:
  · Windows hosts **不支持通配** → 只能逐个登记, 不现实;
  · NRPT 支持后缀匹配, 但**需要管理员权限**并**独占 53/UDP**。

于是在 hosts 与 NRPT 之外需要第三条路。本后端把"通配"从 **DNS 层**挪到 **线路层**:

    浏览器 --CONNECT(带主机名)--> 本转发器 --TCP--> 127.0.0.1:443 (nginx)
                                                └ 用现有本地 CA 终止 TLS, 按 SNI 路由 -> h3 腿

关键机制: **HTTPS 经代理时浏览器根本不做 DNS**, 它发出 `CONNECT host:443`, 而代理只开一条
原始 TCP 隧道, TLS 由浏览器与隧道**另一端**端到端协商。因此:
  · 通配表达在 **PAC 的 JS** 里 (`host.endsWith('.googlevideo.com')`),
    **完全不需要 DNS 具备任何通配能力**;
  · nginx 与 h3 腿**一行都不用改** —— 它们仍然只在 443 上做原来的事;
  · 不需要管理员、不写注册表、不占 53、不动系统 DNS。

## 与另外两个后端的分工 (实测结论)

| 后端   | 通配表达        | 管理员 | 系统影响            | 实测             |
|--------|-----------------|--------|---------------------|------------------|
| hosts  | ✗ 不支持        | 不要   | 改 hosts            | ✗ 通配服务不适用 |
| nrpt   | DNS 后缀规则    | **要** | 整机 DNS + 占 53    | ✓ 劫持已验证     |
| **pac**| **PAC 里的 JS** | 不要   | **仅该浏览器进程**  | ✓ **播放成功**   |

**定位**: `pac` 是面向用户的**正式无管理员方案**; `nrpt` 保留作为**测试/高级**手段
(整机生效、可覆盖非浏览器应用), 二者共存, 由 `redirect_mode` 选择。

## 已实测的边界 (不要在这里"想当然")

1. `--proxy-pac-url=file:///…` **未生效** (转发器收不到任何 CONNECT, 页面走直连);
   而 `--proxy-server` 与 **data: 形式**、**http:// 形式**的 PAC 都生效。
   ⇒ 故本模块**由本机 HTTP 提供 PAC**: 无 file:// 兼容问题, 也无 data: URL 的长度限制
   (实测完整域名表 553 条 / 11300 字节, 内联成 data: 会远超 Windows 命令行上限)。
2. PAC 必须 **DIRECT 兜底**: 未命中的流量一律直连, 绝不把无关流量卷进本机代理。
3. 转发器**总是**把隧道对到本机 nginx —— 选哪些域名走它由 PAC 决定, 保持单一职责。

复现与证据: docs/googlevideo-sabr-analysis.md §13.3.6 起, 以及本次会话的
scripts/probe_pac_playback.py --full-domains (553 域名 / HTTP PAC / 播放成功)。
"""

import socket
import socketserver
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

# 本地转发器与 PAC 服务的默认端口。取高位空闲段, 避免与项目既有端口冲突:
# 443=nginx, 44411=h3 腿, 44401=ECH, 44301/44311+=relay, 53=NRPT 解析器。
PAC_PROXY_PORT = 44500
PAC_HTTP_PORT = 44501
PAC_UPSTREAM_HOST = "127.0.0.1"
PAC_UPSTREAM_PORT = 443          # 本机 nginx
_BUFSIZE = 65536
_HANDSHAKE_TIMEOUT = 30.0
_TUNNEL_TIMEOUT = 300.0


def build_pac(proxy_port: int, exact_hosts: Sequence[str],
              wildcard_suffixes: Sequence[str], fallback: str = "DIRECT") -> bytes:
    """生成 PAC 脚本 (纯函数, 可离线单测)

    :param exact_hosts: 精确主机名 (来自已启用服务的域名表)
    :param wildcard_suffixes: 通配后缀, 形如 `.googlevideo.com` (注意带前导点)
        —— 与 registered 域名的 `*.x` 形式差一个点, 由调用方转换。
    :param fallback: **未命中域名时返回什么**。默认 `DIRECT`; 但**用户已配置固定代理时
        必须传入其代理指令** (见 proxy_settings.pac_fallback_directive) ——
        否则会把用户自己的代理整个旁路掉。实测: PAC 优先于固定代理, 返回 DIRECT 时
        用户代理收到的 CONNECT 数为 **0**, 他其它所有站点都会变成直连。
    """
    import json as _json
    fb = (fallback or "DIRECT").strip() or "DIRECT"
    # 只接受合法的 PAC 返回形式, 避免把注册表里的任意字符串拼进脚本 (注入面)
    if not (fb == "DIRECT" or fb.startswith(("PROXY ", "SOCKS ", "SOCKS5 ", "HTTP "))):
        fb = "DIRECT"
    return (
        "// GameArt Toolkit - PAC: 命中域名经本机隧道交给 nginx\n"
        "function FindProxyForURL(url, host) {\n"
        "  host = host.toLowerCase();\n"
        f"  var exact = {_json.dumps(sorted(exact_hosts))};\n"
        f"  var suffix = {_json.dumps(sorted(wildcard_suffixes))};\n"
        "  for (var i = 0; i < suffix.length; i++) {\n"
        "    if (host === suffix[i].substring(1) || host.endsWith(suffix[i])) {\n"
        f"      return 'PROXY 127.0.0.1:{int(proxy_port)}';\n"
        "    }\n"
        "  }\n"
        "  if (exact.indexOf(host) >= 0) {\n"
        f"    return 'PROXY 127.0.0.1:{int(proxy_port)}';\n"
        "  }\n"
        f"  return {_json.dumps(fb)};\n"
        "}\n").encode("utf-8")


def split_domains(domains: Sequence[str]) -> Tuple[List[str], List[str]]:
    """把重定向域名表拆成 (精确主机, 通配后缀)

    `*.googlevideo.com` → 通配后缀 `.googlevideo.com` (PAC 里用 endsWith 匹配)
    这样通配在 DNS 层**不存在**, 只在 PAC 的 JS 里存在。
    """
    exact, wild = [], []
    for d in domains or []:
        s = str(d).strip().lower()
        if not s:
            continue
        if s.startswith("*."):
            wild.append(s[1:])              # "*.x" -> ".x"
        else:
            exact.append(s)
    return sorted(set(exact)), sorted(set(wild))


class _ConnectHandler(socketserver.BaseRequestHandler):
    """把 CONNECT 隧道对到本机 nginx"""

    def handle(self):
        cli = self.request
        cli.settimeout(_HANDSHAKE_TIMEOUT)
        head = b""
        try:
            while b"\r\n\r\n" not in head and len(head) < 16384:
                chunk = cli.recv(4096)
                if not chunk:
                    return
                head += chunk
        except Exception:
            return

        first = head.split(b"\r\n", 1)[0].decode("latin-1", "ignore")
        if not first.upper().startswith("CONNECT"):
            try:
                cli.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n"
                            b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            except Exception:
                pass
            return
        try:
            target = first.split()[1]
        except IndexError:
            return
        host = target.rsplit(":", 1)[0]
        mgr = self.server.manager           # type: ignore[attr-defined]
        with mgr._lock:
            mgr.tunnels.append(host)
            if len(mgr.tunnels) > 200:
                del mgr.tunnels[:-200]

        try:
            up = socket.create_connection(
                (PAC_UPSTREAM_HOST, PAC_UPSTREAM_PORT), timeout=10)
        except Exception as e:
            try:
                cli.sendall(f"HTTP/1.1 502 Bad Gateway\r\n"
                            f"X-H3-Connect-Error: {type(e).__name__}\r\n"
                            f"Content-Length: 0\r\n\r\n".encode())
            except Exception:
                pass
            return

        try:
            cli.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except Exception:
            up.close()
            return

        up.settimeout(_TUNNEL_TIMEOUT)
        cli.settimeout(_TUNNEL_TIMEOUT)
        done = threading.Event()

        def pump(src, dst):
            try:
                while not done.is_set():
                    b = src.recv(_BUFSIZE)
                    if not b:
                        break
                    dst.sendall(b)
            except Exception:
                pass
            finally:
                done.set()
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass

        t = threading.Thread(target=pump, args=(cli, up), daemon=True)
        t.start()
        pump(up, cli)
        t.join(timeout=5)


class _PacHttpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(10)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            first = data.split(b"\r\n", 1)[0].decode("latin-1", "ignore")
            parts = first.split()
            path = parts[1] if len(parts) > 1 else "/"
            mgr = self.server.manager       # type: ignore[attr-defined]
            if path.startswith("/proxy.pac"):
                body = mgr.pac_bytes() or b""
                head = ("HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/x-ns-proxy-autoconfig\r\n"
                        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
            else:
                body = b"not found"
                head = (f"HTTP/1.1 404 Not Found\r\nContent-Length: {len(body)}\r\n"
                        f"Connection: close\r\n\r\n")
            self.request.sendall(head.encode() + body)
        except Exception:
            pass


class _Server(socketserver.ThreadingTCPServer):
    # ⚠ **不能**开 SO_REUSEADDR (2026-10-02 实测): 在 Windows 上它允许绑定到**已被监听**的
    # 端口 —— 于是端口冲突不会报错, 本后端会与既有监听者争抢流量 (实测: 先占住端口再 start,
    # 竟然返回成功)。本项目其余服务也都选择"端口被占就如实失败"。
    # 代价是 TIME_WAIT 期间可能短暂无法重绑, 但这远比静默抢端口可接受。
    allow_reuse_address = False
    daemon_threads = True

    def handle_error(self, request, client_address):
        # 浏览器会频繁提前关闭隧道 —— 默认实现会为每次断连打一段回溯, 淹没诊断输出
        pass


class PacRedirectManager:
    """PAC + CONNECT 转发后端的生命周期管理"""

    def __init__(self, proxy_port: int = PAC_PROXY_PORT,
                 http_port: int = PAC_HTTP_PORT):
        self.proxy_port = proxy_port
        self.http_port = http_port
        self._proxy: Optional[_Server] = None
        self._http: Optional[_Server] = None
        self._exact: List[str] = []
        self._wild: List[str] = []
        self._pac: Optional[bytes] = None
        self._fallback = 'DIRECT'
        self._lock = threading.Lock()
        self.tunnels: List[str] = []
        self.last_error = ""

    # ------------------------------------------------------------------ 查询
    @property
    def running(self) -> bool:
        return self._proxy is not None and self._http is not None

    def pac_url(self) -> str:
        """浏览器要用 `--proxy-pac-url` 指定的地址"""
        return f"http://127.0.0.1:{self.http_port}/proxy.pac"

    def pac_bytes(self) -> Optional[bytes]:
        return self._pac

    def browser_args(self) -> List[str]:
        """把本后端接入浏览器所需的启动参数

        项目已有"由本程序启动浏览器"的先例 (app/quic_launcher.py), 这里给出对应参数。
        **必须用 http:// 形式**: 实测 file:/// 不生效; data: 装不下完整域名表。
        """
        return [f"--proxy-pac-url={self.pac_url()}"]

    def status(self) -> Dict[str, Any]:
        with self._lock:
            tunnels = sorted(set(self.tunnels))
        return {
            "running": self.running,
            "proxy_port": self.proxy_port,
            "http_port": self.http_port,
            "pac_url": self.pac_url(),
            "exact_hosts": len(self._exact),
            "wildcard_suffixes": len(self._wild),
            "pac_bytes": len(self._pac or b""),
            "fallback": self._fallback,
            "tunnels": len(tunnels),
            "tunnel_sample": tunnels[:12],
            "last_error": self.last_error,
        }

    # ---------------------------------------------------------------- 生命周期
    def start(self, domains: Sequence[str],
              fallback: str = "DIRECT") -> Tuple[bool, str]:
        """按域名表启动转发器与 PAC 服务 (幂等: 已运行则只更新 PAC 内容)

        `fallback` 是**未命中域名**时的 PAC 返回值。若用户已配置固定代理, 必须传入
        其代理指令 —— 否则会把用户自己的代理整个旁路 (实测: 用户代理收到 0 个 CONNECT)。
        """
        exact, wild = split_domains(domains)
        if not exact and not wild:
            return False, "无域名需要重定向"
        self._exact, self._wild = exact, wild
        self._pac = build_pac(self.proxy_port, exact, wild, fallback=fallback)
        self._fallback = (fallback or 'DIRECT').strip() or 'DIRECT'
        if self.running:
            return True, (f"PAC 后端已在运行, 已更新域名表 "
                          f"({len(exact)} 精确 + {len(wild)} 通配)")

        try:
            proxy = _Server(("127.0.0.1", self.proxy_port), _ConnectHandler)
            proxy.manager = self            # type: ignore[attr-defined]
        except OSError as e:
            self.last_error = f"隧道端口 {self.proxy_port} 不可用: {e}"
            return False, (f"PAC 后端启动失败: 隧道端口 {self.proxy_port} 被占用 ({e})")
        try:
            http = _Server(("127.0.0.1", self.http_port), _PacHttpHandler)
            http.manager = self             # type: ignore[attr-defined]
        except OSError as e:
            # 半启动状态必须回滚, 否则会留下一个没人管的监听端口
            try:
                proxy.server_close()
            except Exception:
                pass
            self.last_error = f"PAC 端口 {self.http_port} 不可用: {e}"
            return False, (f"PAC 后端启动失败: PAC 端口 {self.http_port} 被占用 ({e})")

        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        threading.Thread(target=http.serve_forever, daemon=True).start()
        self._proxy, self._http = proxy, http
        self.last_error = ""
        return True, (f"PAC 后端已启动: 隧道 {self.proxy_port} -> 本机 nginx:443, "
                      f"PAC 由 {self.pac_url()} 提供 "
                      f"({len(exact)} 精确 + {len(wild)} 通配域名)")

    def stop(self) -> Tuple[bool, str]:
        ok = True
        for srv in (self._http, self._proxy):
            if srv is None:
                continue
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                ok = False
        self._http = self._proxy = None
        self._pac = None
        self._exact, self._wild = [], []
        with self._lock:
            self.tunnels.clear()
        return ok, "PAC 后端已停止" if ok else "PAC 后端停止时出现异常"


# ===========================================================================
# 浏览器启动 (PAC 后端的"最后一公里")
# ===========================================================================
def launch_browser(mgr: "PacRedirectManager", url: Optional[str] = None,
                   browser: Optional[str] = None,
                   profile_dir: Optional[str] = None,
                   extra_args: Sequence[str] = (),
                   dry_run: bool = False) -> Tuple[bool, str, List[str]]:
    """以本后端的 PAC 启动浏览器 (返回 (是否成功, 消息, 实际命令行))

    为什么要由程序启动浏览器: `--proxy-pac-url` 是**进程级**参数, 无法只靠写配置让
    已在运行的浏览器生效。项目已有同类先例 (app/quic_launcher.py 的 QUIC 启动器),
    这里复用它的 `find_browsers()` 做浏览器发现。

    **必须用 http:// 形式的 PAC**: 实测 file:/// 不生效 (转发器收不到任何 CONNECT,
    页面走直连), 而 data: 装不下完整域名表。
    """
    if not mgr.running:
        return False, "PAC 后端未运行 —— 请先应用重定向 (或先启用需要它的服务)", []

    try:
        from quic_launcher import find_browsers
        browsers = find_browsers()
    except Exception as e:
        return False, f"无法枚举浏览器: {type(e).__name__}: {e}", []
    if not browsers:
        return False, "未找到 Chrome / Edge, 无法以 PAC 方式启动浏览器", []

    chosen = None
    if browser:
        chosen = next(((n, p) for n, p in browsers if n == browser), None)
    if chosen is None:
        chosen = browsers[0]

    cmd = [str(chosen[1])] + list(mgr.browser_args())
    if profile_dir:
        # 独立配置目录可避免与用户正在使用的浏览器实例互相干扰 (参数只在"冷启动"生效)
        cmd.append(f"--user-data-dir={profile_dir}")
    cmd += [a for a in extra_args if a]
    if url:
        cmd.append(url)

    if dry_run:
        return True, f"将启动 {chosen[0]}: {' '.join(cmd)}", cmd
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         close_fds=True)
    except Exception as e:
        return False, f"启动 {chosen[0]} 失败: {type(e).__name__}: {e}", cmd
    return True, (f"已用 {chosen[0]} 启动 (PAC: {mgr.pac_url()})。"
                  f"注意: 若该浏览器已有实例在运行, 新参数可能不生效 —— "
                  f"请先完全退出浏览器再试。"), cmd
