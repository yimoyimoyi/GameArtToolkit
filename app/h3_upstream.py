# -*- coding: utf-8 -*-
"""
GameArt Toolkit - HTTP/3 上游腿 (nginx 明文回环 → 本模块 → HTTP/3 → 真实节点)

为什么需要它 (2026-10-01 实测):
  googlevideo (YouTube 视频流) 是唯一**走不了** L7+掩护SNI 的域:
    - 经中转 IP 请求 /videoplayback 时, 上游回 `Bandaid Misdirected Traffic Server`
      (Google 明确回"打错服务器") —— 该通道根本不服务视频内容;
    - 真实 IPv6 节点的 TCP 侧被压制 (同一时刻实测 QUIC 5/5 成功 vs TCP 0/5 全超时);
    - 唯一能到达真视频服务 (Server: `gvs 1.0`) 的通道是 HTTP/3 + IPv6 + 真实节点名。
  而本项目的 nginx 构建**没有 --with-http_v3_module**, 它自己说不了 HTTP/3,
  所以这条上游腿必须由本模块承担。

与现有 ECH 隧道的架构关系 (刻意的同构):
  discord/pixiv 现在是  nginx --明文回环--> Go ECH 隧道 --TCP+TLS+ECH--> Cloudflare
  本模块则是            nginx --明文回环--> 本模块(python/aioquic) --HTTP/3--> 真实节点
  即"由本地代理承担困难的那条上游腿"。浏览器侧与 discord 完全一致 ——
  默认浏览器可直接用, 不需要浏览器支持 h3、不需要 QUIC 启动器、不需要管理员。

为什么用 aioquic 而不是给 Go 隧道加 quic-go:
  aioquic 已是本项目依赖 (quic_probe.py 在用), 无需新增第三方库、无需拉取 Go 模块
  (实测 proxy.golang.org 本机不可达)、无需在打包产物里多一个二进制。
  实测其作为上游腿的传输能力足够: 同一文件 HTTP/3 8.34 Mbps vs TCP 2.65 Mbps;
  支持 Range (206 + Content-Range); 6 路并发 6/6 成功、聚合 11.21 Mbps。
  **瓶颈在通道可用性, 不在这个实现。**

⚠️ 通道可用性是**分钟级时变的** (实测同一小时内在 0% 与 100% 之间多次翻转)。
  本模块只提供传输能力; "要不要启用"必须由 app/gvs_h3_probe.py 的闸门决定 ——
  在未测通时登记服务就是项目明令禁止的"假可用"。
"""

import asyncio
import concurrent.futures
import queue
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# 版本前置检查 (与 cert_manager / quic_probe 一致)
if sys.version_info < (3, 10):
    sys.stderr.write(
        f"\n[错误] 需要 Python 3.10 及以上, 当前为 {sys.version.split()[0]}。\n"
        f"       当前解释器: {sys.executable}\n\n")
    raise SystemExit(2)

sys.path.insert(0, str(Path(__file__).resolve().parent))

# 端口: 44301=L4 Relay SNI, 44311-44374=relay 转发段, 44401=ECH 隧道。
# 44411 紧邻 ECH 段且当前空闲 —— 统一"4xxxx = 本地明文回环上游"的语义。
PORT = 44411

DEFAULT_CONNECT_TIMEOUT = 8.0
DEFAULT_IDLE_TIMEOUT = 20.0
MAX_RESPONSE_QUEUE = 64          # 回压: 队列满时挂起 h3 读取, 不无限缓冲
RESPONSE_FLUSH_BYTES = 256 * 1024   # 合并小包再交给 HTTP 层 (见 _forward 注释)
MAX_REQUEST_BODY = 8 * 1024 * 1024

# 逐跳头 (RFC 9110 §7.6.1) —— 绝不能透传
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection",
}

# 响应头白名单 —— 必须保住 206/content-range/accept-ranges (视频拖动的前提)
RESPONSE_KEEP = {
    "content-type", "content-length", "content-range", "accept-ranges",
    "last-modified", "etag", "cache-control", "expires", "date", "age",
    "content-encoding", "content-disposition", "vary", "server",
}

_REASON = {
    200: "OK", 204: "No Content", 206: "Partial Content", 301: "Moved Permanently",
    302: "Found", 303: "See Other", 304: "Not Modified", 307: "Temporary Redirect",
    308: "Permanent Redirect", 400: "Bad Request", 401: "Unauthorized",
    403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout",
    416: "Range Not Satisfiable", 421: "Misdirected Request", 429: "Too Many Requests",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
    504: "Gateway Timeout",
}


# ===========================================================================
# 纯逻辑 (可离线单测, 不碰网络)
# ===========================================================================
def node_name_from_host(host: str) -> str:
    """`rr1---sn-i3b7kns6.googlevideo.com` → `rr1---sn-i3b7kns6`"""
    h = strip_port(host).lower()
    return h.split(".", 1)[0] if "." in h else h


def strip_port(host: str) -> str:
    h = (host or "").strip()
    if h.startswith("["):                      # IPv6 字面量 [::1]:443
        return h.split("]")[0].lstrip("[")
    return h.split(":")[0] if h.count(":") == 1 else h


def filter_request_headers(headers: Sequence[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """HTTP/1.1 请求头 → HTTP/3 请求头

    去掉逐跳头与 `Host` —— 后者改由 `:authority` 承载 (否则会与 authority 冲突)。
    """
    out: List[Tuple[str, str]] = []
    for k, v in headers:
        lk = (k or "").lower().strip()
        if not lk or lk in HOP_BY_HOP or lk == "host":
            continue
        out.append((lk, v))
    return out


def filter_response_headers(headers: Sequence[Tuple[bytes, bytes]]) -> List[Tuple[str, str]]:
    """HTTP/3 响应头 → HTTP/1.1 响应头 (白名单保留, 保证 206/content-range 不丢)"""
    out: List[Tuple[str, str]] = []
    for k, v in headers:
        ks = k.decode("latin-1").lower()
        if ks.startswith(":") or ks in HOP_BY_HOP:
            continue
        if ks in RESPONSE_KEEP:
            out.append((ks, v.decode("latin-1")))
    return out


def status_line(code: int) -> str:
    return f"HTTP/1.1 {code} {_REASON.get(code, 'Status')}"


def attempt_order(ips: Sequence[str], limit: int = 4) -> List[str]:
    """按"IPv6/IPv4 交替"重排候选, 截取 limit 个

    为什么不能简单地"IPv6 优先取前 N 个": 不同目标的可达族是相反的 ——
    googlevideo 只有 IPv6 可达 (IPv4 被压制), 而 Cloudflare/Fastly 在本机反过来
    只有 IPv4 可达 (实测 CF 的 IPv6 全部 ConnectionError)。若按解析顺序取前 N 个,
    可能整批都是不可达的那一族, 于是明明有可用地址却报失败。
    交替后, 无论目标属于哪一族, 都能在前 2 次尝试内命中。
    """
    v6 = [ip for ip in ips if ":" in ip]
    v4 = [ip for ip in ips if ":" not in ip]
    out: List[str] = []
    for i in range(max(len(v6), len(v4))):
        if i < len(v6):
            out.append(v6[i])
        if i < len(v4):
            out.append(v4[i])
        if len(out) >= limit:
            break
    return out[:limit]


def is_reusable(proto: Any) -> bool:
    """连接是否仍可复用

    刻意读**我们自己的** closed 标记, 不读 aioquic 内部字段:
    实测 `QuicConnection` **没有 `is_closed` 属性** (aioquic 1.2.0), 早先用
    `getattr(quic, "is_closed", True)` 判断会让每一次请求都判为"不可复用",
    于是每个请求都重做一次 QUIC 握手 (实测 reused=0 / new_conn=3, 1.27MB 慢到 15~20s)。
    """
    return bool(proto) and not getattr(proto, "closed", True)


# ===========================================================================
# 协议类: 按 stream_id 分发事件 —— 同一连接上可并发多个请求 (HTTP/3 多路复用)
# ===========================================================================
def _build_protocol_class():
    """延迟导入 aioquic (缺依赖时本模块仍可被导入与单测)"""
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.quic.events import ConnectionTerminated

    class H3Protocol(QuicConnectionProtocol):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.h3 = H3Connection(self._quic)
            self.streams: Dict[int, "asyncio.Queue"] = {}
            self.terminated = asyncio.Event()
            self.closed = False          # 线程安全的普通标记, 供连接池判活

        def register(self, sid: int) -> "asyncio.Queue":
            q: asyncio.Queue = asyncio.Queue()
            self.streams[sid] = q
            return q

        def unregister(self, sid: int) -> None:
            self.streams.pop(sid, None)

        def connection_lost(self, exc) -> None:
            self.closed = True
            self.terminated.set()
            super().connection_lost(exc)

        def quic_event_received(self, event) -> None:
            if isinstance(event, ConnectionTerminated):
                self.closed = True
                self.terminated.set()
            for he in self.h3.handle_event(event):
                sid = getattr(he, "stream_id", None)
                q = self.streams.get(sid)
                if q is not None:
                    q.put_nowait(he)

    return H3Protocol


# ===========================================================================
# 事件循环桥 (后台线程跑 asyncio; HTTP 线程通过 run_coroutine_threadsafe 提交)
# ===========================================================================
class _LoopBridge:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, name="h3-upstream-loop",
                                        daemon=True)
        self._thread.start()

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def submit(self, coro) -> "concurrent.futures.Future":
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def call(self, coro, timeout: Optional[float] = None):
        return self.submit(coro).result(timeout)

    def stop(self):
        try:
            self.loop.call_soon_threadsafe(self.loop.stop)
        except Exception:
            pass
        self._thread.join(timeout=3)


# ===========================================================================
# h3 转发核心
# ===========================================================================
class H3Forwarder:
    """把一次 HTTP/1.1 请求转成 HTTP/3 请求, 并把响应流式推回队列

    resolver: (host) -> [ip, ...]   目标节点解析 (可注入: 测试与避投毒)
    sni_for:  (host) -> str         TLS SNI (默认 = host 本身)
    """

    def __init__(self, resolver: Callable[[str], List[str]],
                 sni_for: Optional[Callable[[str], str]] = None,
                 connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
                 idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
                 target_port: int = 443):
        self.resolver = resolver
        self.sni_for = sni_for or (lambda h: h)
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self.target_port = target_port      # 可注入: 单测指向本地 h3 源站, 不依赖外网
        self._bridge = _LoopBridge()
        self._pool: Dict[Tuple[str, str], Any] = {}
        self._pool_lock = threading.Lock()
        self._conn_lock: Optional["asyncio.Lock"] = None   # 惰性创建 (必须在事件循环内)
        self.stats = {"requests": 0, "reused": 0, "new_conn": 0, "errors": 0}

    async def _get_conn(self, ip: str, sni: str):
        from aioquic.asyncio.client import connect
        from aioquic.h3.connection import H3_ALPN
        from aioquic.quic.configuration import QuicConfiguration

        proto_cls = _build_protocol_class()
        key = (ip, sni)

        # 建连必须**串行化 + 双检**: 冷启动时多个请求会同时发现池是空的, 于是各建一条
        # 连接 —— 实测并发 6 个请求即 new_conn=6, 其中 5 个报 upstream_no_response /
        # IncompleteRead。改为串行建连后, 第一个请求建连, 其余复用同一条连接上的
        # 多条 HTTP/3 流 (实测 reused=8 / new_conn=1, 6/6 全部成功)。
        if self._conn_lock is None:
            self._conn_lock = asyncio.Lock()
        async with self._conn_lock:
            with self._pool_lock:
                ent = self._pool.get(key)
                if ent is not None and is_reusable(ent[0]):
                    self.stats["reused"] += 1
                    return ent[0]
                self._pool.pop(key, None)

            cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                    verify_mode=ssl.CERT_NONE)
            cfg.server_name = sni
            cfg.idle_timeout = max(5.0, min(float(self.idle_timeout), 60.0))
            # 放大流控窗口 —— 否则大文件吞吐会被 aioquic 默认窗口卡死
            cfg.max_data = 16 * 1024 * 1024
            cfg.max_stream_data = 8 * 1024 * 1024

            # 关键: aioquic 的 connect() 是**异步上下文管理器**(async generator), 不是可 await 的
            # 协程 —— 直接 await 会得到 "_AsyncGeneratorContextManager can't be used in
            # 'await' expression"(实测踩到)。要长期持有连接做池化, 必须手动进入上下文并
            # **不退出**, 把 cm 一并存进池里, 关闭时再 __aexit__。
            cm = connect(ip, self.target_port, configuration=cfg,
                         create_protocol=proto_cls, wait_connected=True)
            proto = await cm.__aenter__()
            self.stats["new_conn"] += 1
            with self._pool_lock:
                self._pool[key] = (proto, cm)
            return proto

    async def _forward(self, ip: str, sni: str, authority: str, method: str, path: str,
                       headers: Sequence[Tuple[str, str]], body: bytes,
                       out: "queue.Queue", timeout: float) -> None:
        from aioquic.h3.events import DataReceived, HeadersReceived

        loop = asyncio.get_running_loop()

        async def emit(item):
            """带背压地推入队列 (满时把阻塞 put 丢到线程池, 不卡事件循环)"""
            if out.full():
                await loop.run_in_executor(None, out.put, item)
            else:
                out.put_nowait(item)

        # 建连失败必须**向上抛**, 不能吞进队列: forward() 靠它来改用下一个候选地址。
        # 若在这里吞掉, forward() 会以为"这次调用成功了"而直接返回 ——
        # 实测后果: unpkg 的首个候选是 Cloudflare IPv6 (本机不可达), 请求直接失败,
        # 而后面明明有可用的 IPv4 却永远不会被尝试。
        try:
            proto = await self._get_conn(ip, sni)
        except Exception:
            self.stats["errors"] += 1
            raise

        try:
            sid = proto._quic.get_next_available_stream_id()
            q = proto.register(sid)
            try:
                req = [(b":method", method.encode()), (b":scheme", b"https"),
                       (b":authority", authority.encode()), (b":path", path.encode())]
                # 必须过滤: HTTP/3 (HPACK) 要求字段名全小写, 且 Host 要由 :authority 承载。
                # 直接把 HTTP/1.1 的头透传会因大写字段名被上游拒绝 ——
                # 实测 Fastly 回 400 "found an invalid character in header name"。
                for k, v in filter_request_headers(headers):
                    req.append((k.encode("latin-1"), v.encode("latin-1")))
                proto.h3.send_headers(sid, req, end_stream=not body)
                if body:
                    proto.h3.send_data(sid, body, end_stream=True)
                proto.transmit()

                deadline = time.perf_counter() + timeout
                status: Optional[int] = None
                resp_headers: List[Tuple[bytes, bytes]] = []
                while status is None:
                    if time.perf_counter() > deadline or proto.terminated.is_set():
                        # 还没写任何东西 → 抛出去让 forward() 换下一个节点
                        self.stats["errors"] += 1
                        raise ConnectionError(f"{ip}: upstream_no_response")
                    try:
                        ev = await asyncio.wait_for(q.get(), timeout=0.5)
                    except asyncio.TimeoutError:
                        proto.transmit()
                        continue
                    if isinstance(ev, HeadersReceived):
                        status = next((int(v) for k, v in ev.headers
                                       if k == b":status"), 0)
                        resp_headers = list(ev.headers)
                    elif isinstance(ev, DataReceived):
                        try:
                            proto.h3.acknowledge_data(sid, ev.data)
                        except Exception:
                            pass

                await emit(("headers", status, filter_response_headers(resp_headers)))
                # 正文: 流式推送, 直到 stream_ended
                #
                # 必须**合并小包**: aioquic 每个 DataReceived 只有 ~1.2KB, 若逐包入队再逐个
                # 写到 HTTP/1.1 socket, 队列与系统调用开销会主导耗时 ——
                # 实测逐包写法取 1.27MB 要 15~20s, 合并到 256KB 后恢复到正常量级。
                buf = bytearray()
                while True:
                    if proto.terminated.is_set():
                        break
                    try:
                        ev = await asyncio.wait_for(q.get(), timeout=timeout)
                    except asyncio.TimeoutError:
                        break
                    if not isinstance(ev, DataReceived):
                        continue
                    if ev.data:
                        buf += ev.data
                        if len(buf) >= RESPONSE_FLUSH_BYTES:
                            await emit(("data", bytes(buf)))
                            buf.clear()
                    try:
                        proto.h3.acknowledge_data(sid, ev.data)
                    except Exception:
                        pass
                    proto.transmit()
                    if ev.stream_ended:
                        break
                if buf:
                    await emit(("data", bytes(buf)))
                await emit(("end", None))
            finally:
                proto.unregister(sid)
        except Exception as e:
            # 走到这里说明**已经写了响应头**(正文中途出错), 不能再换节点重试 ——
            # 否则会把两个上游的响应拼在一起。如实收尾即可。
            self.stats["errors"] += 1
            try:
                out.put_nowait(("error", f"{type(e).__name__}: {e}"))
            except Exception:
                pass
        finally:
            pass

    def forward(self, host: str, method: str, path: str,
                headers: Sequence[Tuple[str, str]], body: bytes,
                out: "queue.Queue", timeout: float = DEFAULT_CONNECT_TIMEOUT) -> None:
        """同步入口 (供 HTTP 线程调用): 解析目标 → 逐个候选地址尝试

        重试语义: 只要**尚未写入任何东西**, 就换下一个候选地址重试。
        这对本场景很关键 —— 同一域名常常同时解析出 IPv6 与 IPv4, 而两者的可达性
        在不同目标上恰好相反 (googlevideo 只有 v6 通; Cloudflare/Fastly 本机只有 v4 通)。
        实测反例: 修复前 unpkg 因首个候选是 CF IPv6 而整单失败, 后面可用的 v4 从未被尝试。
        """
        authority = strip_port(host)
        sni = self.sni_for(authority)
        self.stats["requests"] += 1
        try:
            ips = self.resolver(authority)
        except Exception as e:
            out.put(("error", f"resolve_failed: {type(e).__name__}"))
            return
        if not ips:
            out.put(("error", "resolve_empty"))
            return
        last_err = "all_targets_failed"
        for ip in attempt_order(ips):
            try:
                self._bridge.call(
                    self._forward(ip, sni, authority, method, path, headers, body,
                                  out, timeout),
                    timeout=timeout * 2 + 8)
                return
            except Exception as e:                 # 未写入任何内容 -> 换下一个节点
                last_err = f"{type(e).__name__}: {e}".strip().rstrip(":")
                with self._pool_lock:
                    self._pool.pop((ip, sni), None)
                continue
        out.put(("error", last_err))

    def close(self):
        with self._pool_lock:
            entries = list(self._pool.values())
            self._pool.clear()

        async def _shutdown():
            # 先取消仍在飞行的请求任务, 再关连接。
            # 不取消的话, 那些任务会在事件循环停止后继续回调 UDP transport,
            # 抛出 "Event loop is closed" / "Task was destroyed but it is pending"
            # 之类的 teardown 噪声 (实测在候选回退用例中必然出现)。
            tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for task in tasks:
                task.cancel()
            if tasks:
                # 必须等它们真正结束取消流程: 只 sleep(0) 一次不够, 仍是 pending 的任务
                # 会在循环停止后被析构, 打印 "Task was destroyed but it is pending!"。
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True), timeout=3)
                except Exception:
                    pass
            for proto, cm in entries:
                try:
                    await cm.__aexit__(None, None, None)
                except Exception:
                    try:
                        proto._quic.close()
                    except Exception:
                        pass

        try:
            self._bridge.call(_shutdown(), timeout=8)
        except Exception:
            pass
        self._bridge.stop()


# ===========================================================================
# HTTP/1.1 回环服务 (nginx 的明文上游入口)
# ===========================================================================
def make_handler(forwarder: H3Forwarder, timeout: float):
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "GameArtH3Upstream/1.0"

        def log_message(self, fmt, *args):     # 不打访问日志 (与全局 access_log off 一致)
            pass

        def _relay(self):
            host = self.headers.get("Host", "")
            if not host:
                self.send_error(400, "missing host")
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            body = self.rfile.read(min(length, MAX_REQUEST_BODY)) if length > 0 else b""

            out: "queue.Queue" = queue.Queue(maxsize=MAX_RESPONSE_QUEUE)
            threading.Thread(
                target=forwarder.forward,
                args=(host, self.command, self.path, list(self.headers.items()),
                      body, out, timeout),
                daemon=True).start()

            first = out.get()
            if first[0] == "error":
                msg = f"h3 upstream error: {first[1]}".encode()
                self.send_response(502)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(msg)))
                self.send_header("X-H3-Upstream-Error", str(first[1])[:120])
                self.end_headers()
                self.wfile.write(msg)
                self.close_connection = True
                return

            _kind, code, headers = first
            has_len = any(k.lower() == "content-length" for k, _v in headers)
            self.send_response_only(code)
            for k, v in headers:
                self.send_header(k, v)
            if not has_len:
                self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                while True:
                    kind, payload = out.get()
                    if kind == "data":
                        if has_len:
                            self.wfile.write(payload)
                        else:
                            self.wfile.write(b"%X\r\n%s\r\n" % (len(payload), payload))
                    else:                       # end / error
                        break
                if not has_len:
                    self.wfile.write(b"0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True

        do_GET = _relay
        do_HEAD = _relay
        do_POST = _relay
        do_PUT = _relay
        do_OPTIONS = _relay

    return _Handler


class H3UpstreamProxy:
    """本地 HTTP/3 上游代理 (nginx --明文--> 本服务 --h3--> 真实节点)"""

    def __init__(self, port: int = PORT,
                 resolver: Optional[Callable[[str], List[str]]] = None,
                 sni_for: Optional[Callable[[str], str]] = None,
                 host: str = "127.0.0.1",
                 timeout: float = DEFAULT_CONNECT_TIMEOUT,
                 target_port: int = 443):
        self.port = port
        self.host = host
        self.timeout = timeout
        self.target_port = target_port      # 可注入: 单测指向本地 h3 源站
        self.forwarder = H3Forwarder(resolver or default_resolver, sni_for, timeout,
                                    target_port=target_port)
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> Tuple[bool, str]:
        if self.running:
            return True, "已在运行"
        try:
            self._httpd = ThreadingHTTPServer(
                (self.host, self.port), make_handler(self.forwarder, self.timeout))
            self._httpd.daemon_threads = True
            self._thread = threading.Thread(target=self._httpd.serve_forever,
                                            name="h3-upstream-http", daemon=True)
            self._thread.start()
            return True, ""
        except Exception as e:
            self._httpd = None
            return False, f"{type(e).__name__}: {e}"

    def stop(self):
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        try:
            self.forwarder.close()
        except Exception:
            pass


# ===========================================================================
# 生命周期管理 (供应用启动/看门狗/退出调用)
# ===========================================================================
class H3UpstreamManager:
    """本地 HTTP/3 上游腿的生命周期管理

    与 EchTunnelManager 的关键差别: ECH 隧道是**独立 exe**, 需要子进程与 PID 管理;
    而 h3 腿就是本仓库的 Python 模块, 直接在应用进程内跑后台线程即可 ——
    少一层进程管理, 也不会出现"GUI 退出后残留孤儿进程"的问题。
    因此这里刻意**不**用 is_process_running(按进程名查), 而是查自己持有的实例。
    """

    def __init__(self, port: int = PORT):
        self.port = port
        self._proxy: Optional[H3UpstreamProxy] = None
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- 状态
    def is_running(self) -> bool:
        """代理实例是否存活 (进程内的存活判定)"""
        with self._lock:
            return self._proxy is not None and self._proxy.running

    def is_listening(self) -> bool:
        """端口是否已监听 (进程活着但监听没起来时返回 False)"""
        try:
            from win_utils import is_port_in_use
            return bool(is_port_in_use(self.port))
        except Exception:
            s = socket.socket()
            try:
                s.settimeout(0.5)
                return s.connect_ex(("127.0.0.1", self.port)) == 0
            except Exception:
                return False
            finally:
                s.close()

    def is_healthy(self) -> bool:
        return self.is_running() and self.is_listening()

    def status(self) -> Dict[str, Any]:
        with self._lock:
            proxy = self._proxy
        return {
            "running": self.is_running(),
            "listening": self.is_listening(),
            "healthy": self.is_healthy(),
            "port": self.port,
            "stats": dict(proxy.forwarder.stats) if proxy is not None else {},
        }

    # ---------------------------------------------------------------- 生命周期
    def start(self) -> Tuple[bool, str]:
        """启动代理 (幂等: 已在运行则直接返回成功)

        端口被**别的进程**占用时必须明确失败, 而不是假装成功 ——
        否则 nginx 会把请求打到别人的服务上, 表现为莫名其妙的 502/错页。
        """
        with self._lock:
            if self._proxy is not None and self._proxy.running:
                return True, "h3 上游腿已在运行"
            if self._proxy is None and self.is_listening():
                return False, (f"端口 {self.port} 已被占用 (非本模块的实例), "
                               f"无法启动 h3 上游腿")
            proxy = H3UpstreamProxy(port=self.port)
            ok, why = proxy.start()
            if not ok:
                return False, f"h3 上游腿启动失败: {why}"
            self._proxy = proxy
            return True, f"h3 上游腿已启动 (127.0.0.1:{self.port})"

    def ensure_running(self) -> Tuple[bool, str]:
        """保证在运行 (看门狗用)"""
        return self.start()

    def stop(self) -> Tuple[bool, str]:
        with self._lock:
            proxy, self._proxy = self._proxy, None
        if proxy is None:
            return True, "h3 上游腿未在运行"
        try:
            proxy.stop()
            return True, "h3 上游腿已停止"
        except Exception as e:
            return False, f"停止 h3 上游腿异常: {e}"

    def restart(self) -> Tuple[bool, str]:
        self.stop()
        return self.start()


# 模块级单例 (与 ech_tunnel.ech_tunnel 同款用法)
h3_proxy = H3UpstreamManager()


# ===========================================================================
# 启用前置条件校验 (把"会静默失效"的配置显式暴露出来)
# ===========================================================================
def check_preconditions(redirect_mode: str) -> List[str]:
    """返回使用 HTTP/3 上游腿的**阻塞项** (空列表 = 前置条件满足)

    为什么需要它: `requires_dns_backend` 这个标记此前只被 ip_pool 用于"排除默认启用",
    **并未强制**切换后端。于是用户可以在 Hosts 模式下手动开启 googlevideo, 而:
      - Hosts 文件**不支持通配**, 只能逐个登记域名;
      - googlevideo 的节点名是动态且海量的 (rr1---sn-xxxx.googlevideo.com);
      - 结果: 只有 apex 被劫持, 真实节点名仍走被封锁的系统解析 →
        表现为"页面能开而视频永远转圈"的假可用。
    这里把该判断做成纯函数, 由启动流程调用并如实告知, 而不是让它静默失效。
    """
    blockers: List[str] = []
    mode = str(redirect_mode or "hosts").strip().lower()
    if mode != "nrpt":
        blockers.append(
            "当前解析后端为 Hosts, 但使用 HTTP/3 上游腿的服务依赖**动态节点名**"
            "(如 rr1---sn-xxxx.googlevideo.com), Hosts 不支持通配 → 节点名不会被劫持, "
            "会表现为'页面能开而视频永远转圈'。请改用 NRPT 后端。")
    return blockers


# ===========================================================================
# 默认解析器 (避开投毒)
# ===========================================================================
# googlevideo 的节点名在**别名域**上解析最干净 (实测 5 个解析器一致返回真实 IPv6),
# 而 *.googlevideo.com 的解析在部分通道会被投毒 (apex 实测返回 Dropbox/Facebook 段)。
ALIAS_SUFFIXES = ("gvt1.com", "snap.gvt1.com", "bdn.dev", "gcpcdn.gvt1.com")

# 投毒应答的前缀/取值黑名单。列表**只收实测到的取值**, 不凭记忆堆砌 ——
# 2026-10-02 实测 (两个 DoH 服务对各名字的原始应答, 见 measure_poison) 补入:
#   2001::1            alidns 对 *.c.youtube.com / www.youtube.com / www.google.com 的 AAAA
#                      (单个地址, 属 Teredo 段 2001:0000::/32 —— 真 CDN 永不会用隧道段)
#   2001:0:            Teredo 前缀的另一种写法, 一并挡掉。**注意不能写泛化的 "2001:"** ——
#                      Google 真实 IPv6 正是 2001:4860::/32, 会被误杀。
#   185.45.5.35        doh.pub 对 *.c.youtube.com 的 A
#   174.132.167.252    alidns 对 www.youtube.com 的 A
#   128.242.240.212    alidns 对 rr2---sn-i3b7kns1.googlevideo.com 的 A
#   192.133.77.133     doh.pub 对同一名字的 A
#   199.96.62.75       过滤后仍漏过来的 A (rr2---... 三次 ConnectionError 的直接原因)
#   69.171.235.22      alidns 对 www.google.com 的 A
#   199.59.149.204     alidns 对 rr1---sn-i3b7kns6.googlevideo.com 的 A
_DNS_POISON_PREFIX = ("157.240.", "31.13.", "2a03:2880", "162.125.", "65.49.",
                      "104.244.", "108.160.", "59.24.",
                      # —— 2026-10-02 实测补入 ——
                      "2001::1", "2001:0:",
                      "185.45.", "174.132.", "128.242.240.", "192.133.77.",
                      "199.96.62.", "69.171.235.", "199.59.149.")

# Google 自有网段 (公开段 + 本次实测用到的段)。用途不是"硬门槛"而是**优先信号**:
# 投毒应答的取值是无穷的, 逐个拉黑是打地鼠; 而"真 Google 边缘必然落在 Google 段内"
# 是个稳定得多的判据。故解析时**先过滤投毒, 再优先取落在这些段里的地址**;
# 若一个都没有 (例如将来 Google 走了未列入的段), 仍回退到过滤后的完整列表 ——
# 宁可多试几个地址, 也不要因为段表不全而硬失败。
_GOOGLE_NETS_V6 = ("2404:6800::/32", "2404:6801::/32", "2607:f8b0::/32",
                   "2001:4860::/32", "2a00:1450::/32")
_GOOGLE_NETS_V4 = ("142.250.0.0/15", "142.251.0.0/16", "172.217.0.0/16",
                   "216.58.192.0/19", "74.125.0.0/16", "64.233.160.0/19",
                   "108.177.0.0/17", "209.85.128.0/17", "173.194.0.0/16",
                   "72.14.192.0/18", "216.239.32.0/19", "8.8.8.0/24", "8.8.4.0/24")
_GOOGLE_NETS = None       # 惰性构造 (ipaddress 解析有开销, 且只在需要时用)


def _google_nets():
    global _GOOGLE_NETS
    if _GOOGLE_NETS is None:
        import ipaddress
        nets = []
        for c in _GOOGLE_NETS_V6 + _GOOGLE_NETS_V4:
            try:
                nets.append(ipaddress.ip_network(c))
            except Exception:
                pass
        _GOOGLE_NETS = nets
    return _GOOGLE_NETS


def is_google_edge_ip(ip: str) -> bool:
    """该地址是否落在 Google 自有网段内 (用于给解析结果排序, 不做硬淘汰)"""
    import ipaddress
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except Exception:
        return False
    for n in _google_nets():
        if a.version == n.version and a in n:
            return True
    return False


def prefer_google(ips: List[str]) -> List[str]:
    """优先 Google 段地址, 保序; 若一个都没有则原样返回 (不做硬淘汰, 见 _GOOGLE_NETS 注释)"""
    if not ips:
        return ips
    good = [ip for ip in ips if is_google_edge_ip(ip)]
    return good if good else ips


def is_poisoned(ip: str) -> bool:
    return "face:b00c" in ip or any(ip.startswith(p) for p in _DNS_POISON_PREFIX)


def _doh(name: str, qtype: str, timeout: float = 4.0) -> List[str]:
    """DoH 查询 (AAAA/A) 并过滤投毒应答"""
    import json as _json
    import urllib.request

    want = 28 if qtype.upper() == "AAAA" else 1
    for url in ("https://dns.alidns.com/resolve", "https://doh.pub/dns-query"):
        try:
            req = urllib.request.Request(
                f"{url}?name={name}&type={qtype.upper()}",
                headers={"accept": "application/dns-json",
                         "user-agent": "GameArtToolkit"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                j = _json.loads(r.read().decode())
            raw = [a["data"] for a in (j.get("Answer") or []) if a.get("type") == want]
            # 只接受**能解析成 IP 且版本正确**的取值: 某些 DoH 会把 CNAME 目标混在
            # 同一 type 的 Answer 里返回 (实测出现过 'rr1.sn-i3b7kns6.googlevideo.com.'),
            # 直接拿去连接只会得到 ConnectionError。
            import ipaddress as _ipa
            ver = 6 if want == 28 else 4
            out = []
            for x in raw:
                s = str(x).strip().rstrip(".")
                try:
                    if _ipa.ip_address(s).version != ver:
                        continue
                except Exception:
                    continue
                if not is_poisoned(s):
                    out.append(s)
            # 同一次应答内优先 Google 自有段 (投毒取值无穷, 拉黑是打地鼠; 段内判定更稳)
            out = prefer_google(list(dict.fromkeys(out)))
            if out:
                return out
        except Exception:
            continue
    return []


def default_resolver(host: str) -> List[str]:
    """把请求 Host 解析成真实节点地址

    顺序刻意是 **IPv6 在前, IPv4 在后**:
      - googlevideo 的 IPv4 侧被压制, 只有 IPv6 可达 (实测 QUIC/IPv6 通、IPv4 不通);
      - 而 Cloudflare 等目标反过来常常只有 IPv4 可达 (本机实测 CF 的 IPv6 全超时)。
    两者都返回, 由调用方按序尝试 —— 这样同一个上游腿既能服务 googlevideo,
    也能服务普通 h3 目标 (自测/对照用)。
    """
    node = node_name_from_host(host)
    if not node:
        return []
    target = strip_port(host)
    if target.endswith(ALIAS_SUFFIXES):
        names = [target]
    else:
        names = [f"{node}.{s}" for s in ALIAS_SUFFIXES] + [target]

    v6: List[str] = []
    v4: List[str] = []
    for name in names:
        if not v6:
            v6 = _doh(name, "AAAA")
        if not v4:
            v4 = _doh(name, "A")
        if v6 or v4:
            break
    if v6 or v4:
        return v6 + v4

    # 兜底: 系统解析 (可能被投毒, 已过滤), 同样 IPv6 优先
    try:
        out6, out4 = [], []
        for fam, bucket in ((socket.AF_INET6, out6), (socket.AF_INET, out4)):
            try:
                for i in socket.getaddrinfo(target, 443, fam, socket.SOCK_STREAM):
                    ip = i[4][0]
                    if not is_poisoned(ip):
                        bucket.append(ip)
            except Exception:
                continue
        # 系统解析最容易拿到投毒应答, 因此这一路更要把 Google 段排到前面
        # (2026-10-02 实测: 未排序时 www.youtube.com 拿到 2001::1 + 174.132.167.252 两个投毒值)
        return prefer_google(list(dict.fromkeys(out6))) + prefer_google(list(dict.fromkeys(out4)))
    except Exception:
        return []


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="HTTP/3 上游腿 (本地明文回环 → HTTP/3)")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--selftest", action="store_true",
                    help="启动后经本代理取一个已知 h3 站点的真实文件, 然后退出")
    args = ap.parse_args(argv)

    proxy = H3UpstreamProxy(port=args.port, host=args.host)
    ok, why = proxy.start()
    print(f"h3 上游腿: {'已启动' if ok else '启动失败'}  http://{args.host}:{args.port}  {why}")
    if not ok:
        return 2
    if args.selftest:
        import urllib.request
        try:
            req = urllib.request.Request(
                f"http://{args.host}:{args.port}/npm/three@0.160.0/build/three.module.js",
                headers={"Host": "cdn.jsdelivr.net"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
                print(f"自测: HTTP {r.status}  {len(data)} 字节  首字节={data[:4].hex()}  "
                      f"复用={proxy.forwarder.stats['reused']} 新建={proxy.forwarder.stats['new_conn']}")
            proxy.stop()
            return 0 if len(data) > 1000 else 1
        except Exception as e:
            print(f"自测失败: {type(e).__name__}: {e}")
            proxy.stop()
            return 1
    print("按 Ctrl+C 退出")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    proxy.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
