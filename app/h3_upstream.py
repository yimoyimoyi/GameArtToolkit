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
import collections
import concurrent.futures
import queue
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

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

DEFAULT_CONNECT_TIMEOUT = 4.0
# 等**首个响应头**的预算 (握手已完成的阶段) —— 必须与 connect 档分开。
#
# 为什么从 8s 降到 4s (B3, 2026-10-02 节点测量定因, n=69 次定 IP 探测):
#   成功者的**握手**极快: 中位 253ms / p90 320ms; 失败者**从不回应** (20s 大预算下
#   仍无响应, 其中 5 次是"握手很快成功但服务端不答首头")。也就是说
#   包内**不存在"握手慢但最终成功"的连续带** —— 8s 预算里有 7.x 秒纯粹是在等一个
#   不会来的包。按 _forward 的真实模型 (hs<=cap 且 hdr<=cap) 反推, cap 3s→20s 的
#   成功率是 19%→23%, 即放大预算只能多救 1/69。
#   握手降到 4s 后: 失败路径的花费**减半**, 且 12s 的重试预算才容得下 2~3 次尝试
#   (8s 档只容得下 1 次 —— 这正是"v6 抖一次就硬失败"的机制之一)。
#   ⚠ 适用范围: 这个数值是按 **googlevideo** 实测定的, 而当前 `h3_upstream=True` 的画像
#     **只有 googlevideo 一个** (见 service_profile), 所以腿的实际负载就是它。
#     将来若有别的服务挂到这条腿上, 必须**重新实测**它的握手分布再决定是否共用这个值。
DEFAULT_FIRST_BYTE_TIMEOUT = 8.0
# 为什么首头仍留 8s 而**不**跟着降到 4s: 同一批实测里有**两个真实成功**的首头耗时
# 达 5531ms 与 7162ms (rr4---sn-oji3bc-5n r1 / rr4---sn-4g5e6nzl r1) —— 那是 gvs
# 服务端自己的慢, 不是建连问题。把这一档一起砍到 4s 会**丢掉这两次成功**;
# 拆开两档就能只砍"等死地址"的成本, 不砍"等服务端"的耐心。
DEFAULT_IDLE_TIMEOUT = 20.0
# 流式目标 (SABR / 大文件) 的逐读静默上限。为什么必须显著大于 20s:
# SABR 服务端在"播放器缓冲已满"时**合法地长时间不发数据**, 这正是它节流的实现方式。
# 按旧的 20s 逐读超时, 这种合法静默会被当成"流已结束", 响应以 200/206 **静默截断** ——
# 与"通道被掐"完全无法区分。300s 覆盖实测可观测到的静默长度, 且仍能兜住真正卡死的连接。
DEFAULT_STREAM_IDLE_READ = 300.0
MAX_RESPONSE_QUEUE = 64          # 回压: 队列满时挂起 h3 读取, 不无限缓冲
RESPONSE_FLUSH_BYTES = 256 * 1024   # 合并小包再交给 HTTP 层 (见 _forward 注释)
MAX_REQUEST_BODY = 8 * 1024 * 1024
EVENT_RING_MAX = 32              # 事件环长度 (有界, 见 _EventRing)
TAP_RING_MAX = 64                # 请求级诊断 tap 长度 (有界, 见 _RequestTap)
# 每个候选地址的额外重试次数。
#
# ⚠ 默认 **0 (关闭)**, 这是**实测**结论而非保守取值 (2026-10-02):
#   E2 用同一实验对比过 retries=0 与 retries=1 (connect 档同为 8s):
#     retries=0 → SABR POST 成功 7/10 = 70%
#     retries=1 → SABR POST 成功 6/19 = 32%   (target_failed 事件 3 → 20)
#   通道是**分钟级时变**的, 所以这个对比**不能**证明"重试让它变差";
#   但同样**没有任何证据**说明重试有用, 而存在一条可信的反向机制:
#   每次失败都要等满 connect 档 (8s), retries=1 + 重解析轮会让一个注定失败的请求
#   最坏耗到 6×8=48s 才回 502 —— 对 **有状态、且播放器自带分段重试** 的 SABR,
#   "快速失败让播放器自己重试" 优于 "在网关里盲等"。
#   因此: 默认关闭, 并保留开关与 MAX_TOTAL_ATTEMPTS / RETRY_TIME_BUDGET 两道闸门,
#   供将来在有**同刻交错对照**的条件下重新评估。
DEFAULT_RETRY_SAME_NODE = 0
# 单次请求允许的总尝试次数上限 —— 防止"重试 × 候选 × 两轮"叠加出不可控的长尾
MAX_TOTAL_ATTEMPTS = 6
# 额外尝试的**墙钟预算** (秒)。超过即不再重试, 直接 502。
# 为什么必须有它: 仅靠"次数上限"挡不住长尾 —— 6 次 × 8s = 48s 仍然太久。
# 流式/有状态协议需要的是"要么成功, 要么尽快失败"。
RETRY_TIME_BUDGET = 12.0

# 不允许携带消息体的状态码 (RFC 9110 §6.4.1 / §15.3.5 / §15.4.5):
# 204 与 304 的头部之后就结束, **既不得带 Content-Length 也不得带 Transfer-Encoding**。
BODYLESS_STATUSES = frozenset({204, 304})

# 逐跳头 (RFC 9110 §7.6.1) —— 绝不能透传
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection",
}

# 响应头白名单 —— 必须保住 206/content-range/accept-ranges (视频拖动的前提)
#
# ⚠ 2026-10-02 实测教训: **白名单本身就是个陷阱**。
#   YouTube 播放器是用 `fetch()` **跨源**取 SABR 的 (origin=https://www.youtube.com,
#   target=rr*.googlevideo.com)。白名单里原本一个 `access-control-*` 都没有, 于是
#   gvs 回的 CORS 头被**悄悄丢掉** ⇒ 浏览器判 CORS 失败 ⇒ `net::ERR_FAILED` ⇒
#   播放器永远停在 `player_state=3 / readyState=0`。
#   当时的证据是浏览器控制台的原话 (CDP Log):
#     "Access to fetch at 'https://rr1---sn-….googlevideo.com/videoplayback…'
#      from origin 'https://www.youtube.com' has been blocked by CORS policy:
#      No 'Access-Control-Allow-Origin' header is present on the …"
#   **现象上它和"通道不通"几乎一样 (媒体永不就绪), 但根因在我们自己的转发层。**
#   这就是"静默丢弃"的代价: 传输层明明成功 (tap 记录 200 + 1000+B), 却因为少了一个
#   响应头而整体失败, 且失败现场完全不在我们的日志里。
#   ⇒ 凡是被代理方可能用于**跨源读取**的头, 都必须显式列入白名单。
RESPONSE_KEEP = {
    "content-type", "content-length", "content-range", "accept-ranges",
    "last-modified", "etag", "cache-control", "expires", "date", "age",
    "content-encoding", "content-disposition", "vary", "server",
    # --- 跨源 (CORS) 族: 缺一个就可能让 fetch/MSE 整体失败 ---
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-expose-headers", "access-control-allow-methods",
    "access-control-allow-headers", "access-control-max-age",
    "timing-allow-origin", "cross-origin-resource-policy",
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
@dataclass(frozen=True)
class TimeoutBudget:
    """一次请求-响应周期的超时预算 —— **四档拆开, 不再让一个数值身兼数职**

    为什么必须拆 (2026-10-02 代码审阅定因): 原先 `DEFAULT_CONNECT_TIMEOUT = 8.0` 同时充当
      (a) 建连超时、(b) 逐读空闲超时、(c) 外层 Future 上限 (`timeout×2+8` = 24 s)。
    三者耦合的后果是**整条周期硬上限 24 秒** —— 而视频流必然是分钟级, 因此任何 SABR 实验
    都会在 24 s 处抛 TimeoutError, 得到的是这个魔数的行为, 不是 SABR 的结论。
    (既有的"5/5 通过"之所以没暴露它: 端到端用例是 200 KB 文件与 206 切片, 全在 24 s 内完成。)

    四档语义 (与项目已有的"服务级覆盖全局"先例同形, 见 `ServiceProfile.probe_timeout`):
      connect      仅**建连 (QUIC 握手)** 的预算 —— 保持很小, 让失活地址快速交棒
      first_byte   握手完成后**等首个响应头**的预算 (与 connect 分开, 见常量注释:
                   死地址卡在 connect 档, 而 gvs 服务端自己的慢需要更长的耐心)
      idle_read    两次数据之间允许的最大静默 (流式必须显著放大, 见 DEFAULT_STREAM_IDLE_READ)
      max_duration 整个周期上限; **None = 不设上限** (流式服务的正确取值)

    ⚠ `first_byte` 必须是**最后一个**字段: 既有调用方按位置写
    `TimeoutBudget(1.0, 300.0, None)`, 加在中间会静默改掉它们的语义。
    """
    connect: float = DEFAULT_CONNECT_TIMEOUT
    idle_read: float = DEFAULT_IDLE_TIMEOUT
    max_duration: Optional[float] = None
    first_byte: float = DEFAULT_FIRST_BYTE_TIMEOUT

    def as_dict(self) -> Dict[str, Any]:
        return {"connect": self.connect, "first_byte": self.first_byte,
                "idle_read": self.idle_read, "max_duration": self.max_duration}


def as_budget(value: "Optional[Union[float, TimeoutBudget]]",
              idle_read: Optional[float] = None,
              max_duration: Optional[float] = None,
              first_byte: Optional[float] = None) -> TimeoutBudget:
    """把旧的 `timeout: float` 形式兼容成 TimeoutBudget

    关键: 裸 float 只填 connect 与 idle_read, **max_duration 一律为 None** ——
    这正是移除"24 秒硬天花板"的那一步。传 float 的既有调用者不会再有总时长上限。

    `first_byte` 的兼容规则 (2026-10-02 拆档时定):
      · 显式传 float 的旧调用方 → `first_byte = connect`, 语义与拆档前**逐字一致**
        (拆档前等首头用的正是 `budget.connect`), 不会有静默漂移;
      · 未传 (value 为 None) → 两档各取模块默认 (connect=4s / first_byte=8s);
      · 生产路径 (`H3UpstreamProxy`) 显式传一个 TimeoutBudget, 从而拿到同样的
        connect=4s / first_byte=8s —— 新语义只进入**经过实测论证的那条路径**。
    """
    if isinstance(value, TimeoutBudget):
        return value
    if value is None:
        connect = DEFAULT_CONNECT_TIMEOUT
        fb = DEFAULT_FIRST_BYTE_TIMEOUT if first_byte is None else float(first_byte)
    else:
        connect = float(value)
        # 旧调用方传的 float 只表达"建连超时"; 拆档前它兼任首头档, 这里保持等价。
        fb = connect if first_byte is None else float(first_byte)
    return TimeoutBudget(connect=connect,
                         idle_read=float(idle_read) if idle_read else connect,
                         max_duration=max_duration,
                         first_byte=fb)


def ip_family(ip: str) -> str:
    """地址族标记: `"v6"` / `"v4"` —— 与 attempt_order 划分族的口径保持一致"""
    return "v6" if ":" in str(ip) else "v4"


def _describe_exc(exc: BaseException) -> str:
    """异常 → 简短可读描述 (与拆档前日志格式 `类型: 消息` 保持一致)

    `asyncio.TimeoutError` 的 str 是空串, 直接拼会得到 "TimeoutError: " 这种带尾冒号的
    噪音, 这里统一收尾。
    """
    s = f"{type(exc).__name__}: {exc}".strip()
    return s.rstrip(":") or type(exc).__name__


class UpstreamStageError(Exception):
    """带上失败**阶段**的上游错误 —— B1 需要它来区分"握手失败"与"首头失败"

    为什么这个区分是必须的 (2026-10-02 节点测量, n=69):
      · **握手阶段**失败 ⇒ 该地址**整个不可达** (UDP 没有 RST, 打到死地址只会静默
        丢包)。实测这种失败是**按地址族整体成立**的: 42 个 v4 样本只成功 2 个,
        且 9 个节点里 7 个的 v4 候选是 3/3 全失败 ⇒ 可以据此跳过同族其余地址。
      · **首头阶段**失败 ⇒ **不能**据此推断整个族: 实测同一 (IP, SNI) 在 ~30s 内
        既成又败 (rr5---sn-ajaig5-5h 直探 0/9, 生产路径同一 IP 2/3 成功),
        属分钟级抖动。
    """

    STAGE_HANDSHAKE = "handshake"
    STAGE_HEADERS = "headers"

    def __init__(self, stage: str, detail: str):
        super().__init__(detail)
        self.stage = stage
        self.detail = detail


def read_request_body(headers_get, rfile, max_bytes: int = MAX_REQUEST_BODY,
                      max_chunks: int = 1_000_000) -> Tuple[bytes, Optional[str]]:
    """按 RFC 9112 读取请求体, 返回 (body, error)

    为什么不能只看 Content-Length (2026-10-02 审阅定因, 两条静默失效路径):
      1. `Transfer-Encoding: chunked` 的体**完全不被读取** → 向上游发出**空体 POST**,
         上游回 400/403, 现象酷似"通道不通"。nginx 的 `proxy_request_buffering off`
         会让分块体原样转发过来, 所以这不是理论情形。
      2. 超过 max_bytes 时 `min(length, max_bytes)` **静默截断且不报错** → 上游收到错体;
         若走 keep-alive, 残留字节还会让后续请求错位。
    正确处理: chunked 自行解码; 超限返回错误(**由调用方回 413**), 绝不静默截断。
    """
    te = (headers_get("Transfer-Encoding") or "").lower()
    if "chunked" in te:
        body = bytearray()
        for _ in range(max_chunks):
            line = rfile.readline(64)
            if not line:
                return bytes(body), "chunked_body_truncated"
            try:
                size = int(line.split(b";", 1)[0].strip() or b"0", 16)
            except ValueError:
                return bytes(body), "chunked_bad_size"
            if size == 0:
                # 吃掉 trailer 直到空行
                while True:
                    t = rfile.readline(256)
                    if not t or t in (b"\r\n", b"\n"):
                        break
                return bytes(body), None
            if len(body) + size > max_bytes:
                return bytes(body), "body_too_large"
            chunk = rfile.read(size)
            if len(chunk) < size:
                return bytes(body), "chunked_body_truncated"
            body += chunk
            rfile.readline(2)                      # CRLF
        return bytes(body), "chunked_too_many_chunks"

    try:
        length = int(headers_get("Content-Length") or 0)
    except ValueError:
        return b"", "bad_content_length"
    if length <= 0:
        return b"", None
    if length > max_bytes:
        # 不读体, 直接报错 —— 由调用方回 413 并关闭连接
        return b"", "body_too_large"
    return rfile.read(length), None


def plan_http1_response(status: Optional[int],
                        headers: Sequence[Tuple[str, str]],
                        method: str = "GET") -> Dict[str, Any]:
    """决定回给 nginx 的 HTTP/1.1 响应如何封装 (RFC 9110) —— 纯函数, 可离线单测

    为什么需要它 (2026-10-02 审阅定因): 原实现"没有 Content-Length 就一律补
    `Transfer-Encoding: chunked`", 于是 204/304 会发出

        HTTP/1.1 204 No Content
        Transfer-Encoding: chunked

    —— 而 RFC 9110 规定 204/304 **既不得带 Content-Length 也不得带 Transfer-Encoding**。
    这解释了一个此前被记为"未解释的互操作现象"的差异: **curl 宽容** (拿到干净的 204),
    **Chrome 不宽容** (报 ERR_ABORTED)。同类问题还有 `do_HEAD` 会带上正文。
    意义: 该现象很可能不是独立谜题, 而与 SABR 阻塞共享根因 —— gvs 在 SABR 会话中**确实会回 204**
    (UMP 的握手/确认), 届时这条违规会直接打断会话。

    注: "Chrome 因此 abort" 属**高置信推测**, 需 E0-1 之后一次最小实验确认。
    """
    code = int(status or 0)
    method = (method or "GET").upper()
    has_cl = any(str(k).lower() == "content-length" for k, _v in headers or [])
    bodyless = code in BODYLESS_STATUSES or 100 <= code < 200
    if bodyless:
        # 头部之后即结束: 不带 CL、不带 TE、不写正文
        return {"allow_body": False, "use_content_length": False, "chunked": False,
                "strip_length_headers": True}
    if method == "HEAD":
        # HEAD 可带 Content-Length (描述实体长度) 但**不得有正文**
        return {"allow_body": False, "use_content_length": has_cl, "chunked": False,
                "strip_length_headers": False}
    if has_cl:
        return {"allow_body": True, "use_content_length": True, "chunked": False,
                "strip_length_headers": False}
    return {"allow_body": True, "use_content_length": False, "chunked": True,
            "strip_length_headers": False}


class _RequestTap:
    """请求级诊断 tap —— 回答"浏览器到底发了什么、gvs 怎么回的"

    为什么需要 (2026-10-02, E2 的前提): 在此之前每一轮 googlevideo 实验都只能看到
    "客户端拿到了什么", 看不到**浏览器实际发出的请求形态**。而 SABR 的判定恰恰在形态上
    (POST + `application/vnd.yt-ump` + protobuf 体), 不在响应上。
    有了它, "浏览器不播" 才能被拆成"根本没发 SABR 请求" / "发了但被拒" / "被拒的原因"。

    记录字段 (文档规定的七项):
      method, path_prefix (去掉查询串), body_len, status, first_byte_ms, total_ms, bytes
    另附 SABR 线索: 请求头/响应头里是否出现 ump / sabr 关键字 (只看关键字, 不落全文)。
    有界 (deque maxlen) —— 诊断数据不该无界增长, 也不该留存任何查询串内容 (含签名参数)。
    """

    def __init__(self, maxlen: int = TAP_RING_MAX):
        self._dq: "collections.deque" = collections.deque(maxlen=maxlen)

    def record(self, **kw) -> None:
        kw.setdefault("t", round(time.time(), 2))
        self._dq.append(kw)

    def snapshot(self) -> List[Dict[str, Any]]:
        return list(self._dq)

    def reset(self) -> None:
        self._dq.clear()


def _path_prefix(path: str, limit: int = 48) -> str:
    """只保留路径前缀 (丢掉查询串) —— 诊断不需要、也不该留存签名参数"""
    return str(path or "").split("?", 1)[0][:limit]


def _has_marker(text: str, *needles: str) -> bool:
    t = str(text or "").lower()
    return any(n in t for n in needles)


class _EventRing:
    """有界事件环 —— 腿的"盲区自陈" (P4 等价物)

    为什么必须有: 腿的 `log_message` 是空实现, 对外**零可观测性**, 于是"视频转圈"无法归因。
    而 `forwarder.stats` 只是单调计数器, 无法回答"刚刚发生了什么"。
    这里记录**最后 N 条异常事件** (种类 + 摘要 + 时间), 经 `status()` 暴露,
    零新增流量, 同时服务"诊断"与"健康信号"两个需求。

    种类: resolve_failed / resolve_empty / upstream_no_response / body_too_large /
          bad_content_length / chunked_body_truncated / target_failed / stream_cut /
          invalid_status
    """

    def __init__(self, maxlen: int = EVENT_RING_MAX):
        self._dq: "collections.deque" = collections.deque(maxlen=maxlen)

    def add(self, kind: str, detail: str = "") -> None:
        self._dq.append({"t": round(time.time(), 3), "kind": str(kind)[:40],
                         "detail": str(detail)[:160]})

    def snapshot(self) -> List[Dict[str, Any]]:
        return list(self._dq)

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for e in self._dq:
            out[e["kind"]] = out.get(e["kind"], 0) + 1
        return out


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


def cors_headers_present(headers: Sequence[Tuple[bytes, bytes]]) -> bool:
    """上游响应里是否**真的**带了跨源头 (用于区分"被我们丢了"与"上游本就没发")

    为什么要单独判一次: 实测 CORS 缺失导致的失败现象与"通道不通"几乎一样,
    所以必须能回答"是白名单丢的, 还是 gvs 压根没发" —— 这决定了修法是
    "补白名单" 还是 "兜底注入"。
    """
    return any(k.decode("latin-1").lower().startswith("access-control-")
               for k, _v in headers or [])


def filter_response_headers(headers: Sequence[Tuple[bytes, bytes]]) -> List[Tuple[str, str]]:
    """HTTP/3 响应头 → HTTP/1.1 响应头 (白名单保留, 保证 206/content-range/CORS 不丢)

    ⚠ 白名单的教训见 RESPONSE_KEEP 上方注释: 曾因缺 `access-control-*` 而让
    SABR 传输明明成功、播放器却永远就绪不了。
    """
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
                 target_port: int = 443,
                 retries: int = DEFAULT_RETRY_SAME_NODE):
        self.resolver = resolver
        self.sni_for = sni_for or (lambda h: h)
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self.target_port = target_port      # 可注入: 单测指向本地 h3 源站, 不依赖外网
        self.retries = int(retries)         # 同节点重试次数 (见 DEFAULT_RETRY_SAME_NODE)
        self._bridge = _LoopBridge()
        self._pool: Dict[Tuple[str, str], Any] = {}
        self._pool_lock = threading.Lock()
        self._conn_lock: Optional["asyncio.Lock"] = None   # 惰性创建 (必须在事件循环内)
        self.stats = {"requests": 0, "reused": 0, "new_conn": 0, "errors": 0}
        self.events = _EventRing()          # 有界事件环 (盲区自陈, 见 _EventRing)
        self.tap = _RequestTap()            # 请求级诊断 tap (见 _RequestTap)

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
            # QUIC 层的空闲超时也由 idle_timeout 驱动。上限从 60s 放宽到 600s:
            # 流式目标 (SABR) 的服务端静默**可以超过 60s** (服务端节流的实现方式),
            # 若仍卡在 60s, 上层把逐读预算放大到 300s 也没用 —— 连接会先被 QUIC 关掉。
            cfg.idle_timeout = max(5.0, min(float(self.idle_timeout), 600.0))
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
                       out: "queue.Queue", budget: TimeoutBudget) -> None:
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
        #
        # ⚠ 建连必须**用自己的 connect 档**设上限, 不能依赖 QUIC 的 idle_timeout:
        #   UDP 没有 "connection refused", 打到死端口只会静默丢包; 若把 idle_timeout 放大到
        #   流式所需的 300s (见 _get_conn), 建连就会等满 300s —— 实测这正是让
        #   "候选不可达 → 换下一个" 那三条回归用例挂住的原因。
        #   两件事必须分开: **握手**用 connect 档限时, **已建连后的静默**用 idle_read 档。
        try:
            proto = await asyncio.wait_for(self._get_conn(ip, sni), timeout=budget.connect)
        except Exception as e:
            self.stats["errors"] += 1
            # 打上"握手阶段"标记: forward() 据此判定**该地址族**在本轮不可达并跳过同族
            # 其余地址 (见 UpstreamStageError)。消息保持与拆档前逐字一致, 便于比对日志。
            raise UpstreamStageError(UpstreamStageError.STAGE_HANDSHAKE,
                                     _describe_exc(e)) from e

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

                # 等首个响应头: 用 **first_byte 档**(握手已单独限时)。
                # 拆档理由见 DEFAULT_FIRST_BYTE_TIMEOUT: 死地址卡在握手, 而 gvs 服务端
                # 自己的慢 (实测两次真实成功要 5.5s / 7.2s) 需要更长的耐心。
                deadline = time.perf_counter() + budget.first_byte
                status: Optional[int] = None
                resp_headers: List[Tuple[bytes, bytes]] = []
                while status is None:
                    if time.perf_counter() > deadline or proto.terminated.is_set():
                        # 还没写任何东西 → 抛出去让 forward() 换下一个节点。
                        # ⚠ 标记为**首头阶段**: 这**不能**用来推断整个地址族不可达。
                        self.stats["errors"] += 1
                        self.events.add("upstream_no_response", f"{ip} {path.split('?')[0][:40]}")
                        raise UpstreamStageError(
                            UpstreamStageError.STAGE_HEADERS,
                            f"{ip}: upstream_no_response")
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
                # CORS 归因探针: 记下上游**原始**头里有没有跨源头。
                # 这决定修法是"补白名单"(上游有、我们丢了) 还是"兜底注入"(上游没发)。
                if cors_headers_present(resp_headers):
                    self.stats["cors_upstream"] = self.stats.get("cors_upstream", 0) + 1
                else:
                    self.stats["cors_missing_upstream"] = \
                        self.stats.get("cors_missing_upstream", 0) + 1
                    self.events.add("no_cors_upstream",
                                    f"{ip} {path.split('?')[0][:28]} 上游未带 access-control-*")
                # 正文: 流式推送, 直到 stream_ended
                #
                # 必须**合并小包**: aioquic 每个 DataReceived 只有 ~1.2KB, 若逐包入队再逐个
                # 写到 HTTP/1.1 socket, 队列与系统调用开销会主导耗时 ——
                # 实测逐包写法取 1.27MB 要 15~20s, 合并到 256KB 后恢复到正常量级。
                #
                # 逐读超时用 **idle_read 档**(默认对流式目标已放大到 300s):
                # 服务端"缓冲已满"时的合法静默不得被当成流结束 —— 否则响应会以 200/206
                # **静默截断**, 且与"通道被掐"无法区分。截断时记事件环, 不再无声无息。
                buf = bytearray()
                while True:
                    if proto.terminated.is_set():
                        self.events.add("stream_cut", f"{ip} connection_terminated")
                        break
                    try:
                        ev = await asyncio.wait_for(q.get(), timeout=budget.idle_read)
                    except asyncio.TimeoutError:
                        self.events.add("stream_cut",
                                        f"{ip} idle>{budget.idle_read:g}s 静默超限 (已发 {len(buf)}B 未刷)")
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
                out: "queue.Queue",
                timeout: "Optional[Union[float, TimeoutBudget]]" = None,
                idle_read: Optional[float] = None,
                max_duration: Optional[float] = None,
                retries: Optional[int] = None) -> None:
        """同步入口 (供 HTTP 线程调用): 解析目标 → 逐个候选地址尝试 → (必要时)重解析再试

        重试语义: 只要**尚未写入任何东西**, 就可以再试。
        这对本场景很关键 —— 同一域名常常同时解析出 IPv6 与 IPv4, 而两者的可达性
        在不同目标上恰好相反 (googlevideo 只有 v6 通; Cloudflare/Fastly 本机只有 v4 通)。
        实测反例: 修复前 unpkg 因首个候选是 CF IPv6 而整单失败, 后面可用的 v4 从未被尝试。

        **2026-10-02 E2 实测新增的两条重试 (为什么必须有)**:
        E2 用 CDP 驱动真实浏览器时, 10 个真实 SABR POST 里 7 个成功、**3 个失败**,
        且失败全是同一个 IPv6 节点在 connect 档(8s)内 `upstream_no_response`。
        事后核对发现两件事, 各自对应一条修复:
          ① **同一个节点名在别的请求里是成功的** (rr…1486 一次 200、一次失败)
             ⇒ 这是**抖动**, 不是"该节点坏" ⇒ 值得**对同一节点重试**(原先只换候选, 见 retries);
          ② 失败时事件环记的 IP 与事后解析出的答案**不是同一个**
             ⇒ 候选集**时变**, 某些时刻只落到单个候选, 此时没有 v4 兜底、也没有第二次机会
             ⇒ 需要**重解析再试一遍**(见下方第二轮)。
        这两条都不依赖 DNS 稳定, 因此对"通道分钟级时变"是正向收益。

        超时: `timeout` 兼容旧的裸 float; 四档预算见 TimeoutBudget。
        **裸 float 不再产生"整周期硬上限"** —— max_duration 默认 None。

        **B1 (2026-10-02 节点测量): 某族首个地址在握手阶段失败后, 本轮跳过该族其余地址。**
        为什么: 实测 42 个 v4 样本只成功 2 个, 且 9 个节点里 7 个的 v4 候选是 3/3 全失败,
        即"族级不可达"是**整体成立**的; 而候选集里常见 2~4 个同族地址, 逐个等满
        connect 档纯属重复付账 (`attempt_order` 的 limit 就是 4)。
        ⚠ 跳过**按轮**生效, 不跨轮继承: 一轮 = 一份 DNS 快照, 重解析是"再问一次世界变了没",
        拿到新快照就该重新给该族机会 (实测 v6 会在 ~30s 内又从死转活)。
        ⚠ 只跳过**同族**, 绝不跳过别的族 —— googlevideo 只有 v6 通、Cloudflare 只有 v4 通,
        把"首族失败"推广成"全都别试"会把可用目标整个弄坏。
        """
        budget = as_budget(timeout, idle_read=idle_read, max_duration=max_duration)
        retries = self.retries if retries is None else int(retries)
        authority = strip_port(host)
        sni = self.sni_for(authority)
        self.stats["requests"] += 1
        try:
            ips = self.resolver(authority)
        except Exception as e:
            self.events.add("resolve_failed", f"{authority}: {type(e).__name__}")
            out.put(("error", f"resolve_failed: {type(e).__name__}"))
            return
        if not ips:
            self.events.add("resolve_empty", authority)
            out.put(("error", "resolve_empty"))
            return

        last_err = "all_targets_failed"
        tried: List[str] = []
        attempts = 0
        t_start = time.perf_counter()
        # 两轮: 第 0 轮用初始候选, 第 1 轮**重解析**(DoH 答案时变, 单候选时尤其需要)
        for rnd in range(2):
            # B1 的族级失效集合 —— **每轮重置** (见 docstring: 一轮 = 一份 DNS 快照)
            dead_families: set = set()
            if rnd == 0:
                cands = [ip for ip in attempt_order(ips) if ip not in tried]
            else:
                # 重解析本身也要受预算约束: DoH 最坏可能串行花掉几十秒, 若在失败路径上
                # 无约束地再来一次, 502 会被推得比不重试还晚 —— 与设 RETRY_TIME_BUDGET 的
                # 理由完全相同。
                if (time.perf_counter() - t_start) > RETRY_TIME_BUDGET:
                    self.events.add("retry_budget_exhausted",
                                    f"{authority} 预算用尽, 跳过重解析")
                    break
                cands = [ip for ip in attempt_order(self._reresolve(authority))
                         if ip not in tried]
                if not cands:
                    break
            for ip in cands:
                if ip_family(ip) in dead_families:
                    self.events.add(
                        "family_skipped",
                        f"{ip} 同族 ({ip_family(ip)}) 本轮已有地址握手失败, 跳过")
                    continue
                for attempt in range(retries + 1):
                    # 两道闸门 (见 RETRY_TIME_BUDGET 注释): 次数上限 + 墙钟预算。
                    # 只靠次数挡不住长尾 —— 6×8s=48s 仍太久; 流式协议要的是
                    # "要么成功, 要么尽快失败", 让播放器用**它自己的**分段重试去补。
                    if attempts >= MAX_TOTAL_ATTEMPTS:
                        self.events.add(
                            "attempts_exhausted",
                            f"{authority} 已尝试 {attempts} 次 (上限 {MAX_TOTAL_ATTEMPTS})")
                        out.put(("error", last_err))
                        return
                    if attempts and (time.perf_counter() - t_start) > RETRY_TIME_BUDGET:
                        self.events.add(
                            "retry_budget_exhausted",
                            f"{authority} 重试预算 {RETRY_TIME_BUDGET:g}s 用尽 (已试 {attempts} 次)")
                        out.put(("error", last_err))
                        return
                    attempts += 1
                    tried.append(ip)
                    # 用 submit 拿 Future 而不是 call(): 超时/失败时必须能**取消协程**。
                    # 为什么关键 (2026-10-02 审阅定因): 原先 `call(..., timeout×2+8)` 超时后
                    # 直接 continue, 而 _forward 协程**没有被取消** —— 它继续向**同一个** out
                    # 推事件: ① HTTP 线程正在 out.get(), 拿到第二个 ("headers", …) 会因
                    # "不是 data"而 break ⇒ 流被提前掐断; ② 被遗弃的协程在队列满 64 后, 经
                    # run_in_executor(None, out.put, item) **永久阻塞** ⇒ 吃掉线程池线程。
                    fut = self._bridge.submit(self._forward(
                        ip, sni, authority, method, path, headers, body, out, budget))
                    try:
                        fut.result(budget.max_duration)
                        if attempts > 1:
                            self.events.add("recovered",
                                            f"{authority} 第 {attempts} 次尝试成功 ({ip})")
                        return
                    except Exception as e:         # 未写入任何内容 -> 可以再试
                        # 阶段标记优先: 拆档后 _forward 会抛 UpstreamStageError, 它的
                        # detail 已是"类型: 消息"形式, 再加一层类型前缀只会变成噪音。
                        last_err = (e.detail if isinstance(e, UpstreamStageError)
                                    else _describe_exc(e))
                        self.events.add(
                            "target_failed",
                            f"{ip} try{attempt + 1}/{retries + 1} rnd{rnd} {last_err}")
                        # B1: 只有**握手阶段**失败才说明该地址族整体不可达 (见
                        # UpstreamStageError 注释); 首头阶段失败在**可用**地址上也会发生,
                        # 拿它推断整个族会把抖动误判成死族。
                        if getattr(e, "stage", None) == UpstreamStageError.STAGE_HANDSHAKE:
                            fam = ip_family(ip)
                            if fam not in dead_families:
                                dead_families.add(fam)
                                self.events.add(
                                    "family_unreachable",
                                    f"{authority} {fam} 首个地址 {ip} 握手失败, "
                                    f"本轮跳过同族其余地址")
                        try:
                            fut.cancel()           # 让 _forward 在 await 点收到 CancelledError
                        except Exception:
                            pass
                        self._drain(out)           # 丢弃半成品, 避免污染下一次
                        with self._pool_lock:
                            self._pool.pop((ip, sni), None)
        out.put(("error", last_err))

    def _reresolve(self, authority: str) -> List[str]:
        """重解析一次 (返回空列表表示拿不到新答案)

        为什么要单独一步: 实测候选集**时变** —— 同一次实验里失败请求记下的 IP
        与事后解析出的答案不是同一个, 且某些时刻只落到**单个**不可响应的 IPv6。
        全失败后立刻重解析, 往往能得到另一个节点或 v4 兜底。
        """
        try:
            fresh = list(self.resolver(authority) or [])
        except Exception as e:
            self.events.add("reresolve_failed", f"{authority}: {type(e).__name__}")
            return []
        fresh = [ip for ip in fresh if ip]
        if fresh:
            self.events.add("reresolve", f"{authority} 得到 {len(fresh)} 个候选")
        return fresh

    @staticmethod
    def _drain(q: "queue.Queue") -> None:
        """清空队列 (被取消的协程可能已推入 headers/半截 data)"""
        while True:
            try:
                q.get_nowait()
            except queue.Empty:
                return

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
def make_handler(forwarder: H3Forwarder,
                 timeout: "Union[float, TimeoutBudget]"):
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "GameArtH3Upstream/1.0"

        def log_message(self, fmt, *args):     # 不打访问日志 (与全局 access_log off 一致)
            pass

        def _cors_for_error(self):
            """错误响应也必须带 CORS 头

            为什么: 播放器用 fetch() **跨源**取 SABR。腿因上游不可达而回 502 时,
            若该响应没有 CORS 头, 浏览器报的是 "blocked by CORS policy" 而**不是** 502
            —— 真实原因(节点可用性)被掩盖, 播放器也无法按状态码退避重试。
            实测: 正式方案的一次验收里 32 条 CORS 错误, 逐条追下去全是 502 的次生症状。
            """
            origin = self.headers.get("Origin")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Expose-Headers",
                                 "X-H3-Upstream-Error, Content-Length, Content-Range")
                self.send_header("Vary", "Origin")

        def _relay(self):
            host = self.headers.get("Host", "")
            if not host:
                self.send_error(400, "missing host")
                return
            t_req = time.perf_counter()
            # 请求体: 支持 chunked, 且超限时报错而**不静默截断** (见 read_request_body)
            body, berr = read_request_body(self.headers.get, self.rfile)
            if berr:
                forwarder.events.add(berr, f"{self.command} {_path_prefix(self.path)}")
                forwarder.tap.record(method=self.command, path_prefix=_path_prefix(self.path),
                                     host=host, body_len=len(body), status=None,
                                     first_byte_ms=None,
                                     total_ms=round((time.perf_counter() - t_req) * 1000, 1),
                                     bytes=0, err=berr)
                code = 413 if berr == "body_too_large" else 400
                msg = f"h3 upstream: {berr}".encode()
                self.send_response(code)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(msg)))
                self.send_header("X-H3-Upstream-Error", berr)
                self._cors_for_error()
                self.end_headers()
                # ⚠ 这段回写也必须容错: 实测 (播放诊断) 浏览器会**在 502 返回前就取消**请求
                # (播放器放弃该分段时会 abort), 于是这里抛 ConnectionAbortedError
                # (WinError 10053) 并打出一整段回溯。502 分支与正文分支是**两处**独立的
                # 写入点, 之前只给正文分支加了容错, 漏了这里 —— 又一次"只修了看得到的那处"。
                try:
                    if self.command != "HEAD":
                        self.wfile.write(msg)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError,
                        TimeoutError, OSError):
                    pass
                self.close_connection = True
                return

            # SABR 线索: 请求侧 (Content-Type / 体长) —— 只看关键字, 不落全文
            req_ctype = self.headers.get("Content-Type", "")
            req_sabr = _has_marker(req_ctype, "yt-ump", "ump", "sabr")

            out: "queue.Queue" = queue.Queue(maxsize=MAX_RESPONSE_QUEUE)
            threading.Thread(
                target=forwarder.forward,
                # 逐读静默与整周期上限从 forwarder 读 (生产路径按流式配置, 见 proxy.__init__):
                # 不再把一个 timeout 同时当建连/逐读/整周期三种角色用。
                args=(host, self.command, self.path, list(self.headers.items()),
                      body, out, timeout,
                      getattr(forwarder, "idle_timeout", None),
                      getattr(forwarder, "max_duration", None)),
                daemon=True).start()

            first = out.get()
            t_first = time.perf_counter()
            if first[0] == "error":
                forwarder.tap.record(method=self.command, path_prefix=_path_prefix(self.path),
                                     host=host, body_len=len(body), status=None,
                                     first_byte_ms=round((t_first - t_req) * 1000, 1),
                                     total_ms=round((t_first - t_req) * 1000, 1),
                                     bytes=0, req_ctype=req_ctype, err=str(first[1])[:80])
                msg = f"h3 upstream error: {first[1]}".encode()
                self.send_response(502)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(msg)))
                self.send_header("X-H3-Upstream-Error", str(first[1])[:120])
                self._cors_for_error()
                self.end_headers()
                # ⚠ 本回写也必须容错。实测(播放诊断)浏览器会在 502 返回前就取消请求,
                # 这里抛 ConnectionAbortedError (WinError 10053) 并打出整段回溯。
                # 注意: 这是**第三处**写入点 —— 此前给"正文循环"与"body-error 分支"都加了
                # 容错, 却**漏了这一处**, 而且我还一度以为已经修过它 (实际改的是相邻分支)。
                # 教训: 多处同类写入点不能靠"看到哪修哪", 应逐点列清 (见审计脚本)。
                try:
                    if self.command != "HEAD":
                        self.wfile.write(msg)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError,
                        TimeoutError, OSError):
                    pass
                self.close_connection = True
                return

            _kind, code, headers = first
            resp_ctype = next((v for k, v in headers if str(k).lower() == "content-type"), "")
            resp_sabr = _has_marker(resp_ctype, "yt-ump", "ump", "sabr")
            # 封装规划是纯函数 (可离线单测), 见 plan_http1_response 的注释:
            # 204/304 既不得带 Content-Length 也不得带 Transfer-Encoding; HEAD 不得有正文。
            plan = plan_http1_response(code, headers, self.command)
            if not code:
                forwarder.events.add("invalid_status", self.path.split("?")[0][:60])
            self.send_response_only(code)
            for k, v in headers:
                if plan["strip_length_headers"] and str(k).lower() in (
                        "content-length", "transfer-encoding"):
                    continue
                self.send_header(k, v)
            if plan["chunked"]:
                self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            bytes_out = [0]
            try:
                if not plan["allow_body"]:
                    # 无正文响应: 不写任何字节, 但要把队列读干净, 避免遗弃协程继续往里推
                    while True:
                        kind, _payload = out.get()
                        if kind != "data":
                            break
                    return
                while True:
                    kind, payload = out.get()
                    if kind == "data":
                        bytes_out[0] += len(payload)
                        if plan["chunked"]:
                            self.wfile.write(b"%X\r\n%s\r\n" % (len(payload), payload))
                        else:
                            self.wfile.write(payload)
                    else:                       # end / error
                        break
                if plan["chunked"]:
                    self.wfile.write(b"0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError,
                    TimeoutError, OSError):
                # Windows 上客户端中断常抛 ConnectionAbortedError (WinError 10053) 或裸
                # OSError, 都不在 BrokenPipe/ConnectionReset 里 —— 实测漏网时会在 stderr
                # 打一整段回溯 (E2 的 CDP 运行里就出现过), 把真正的诊断输出淹没。
                # 这类中断是**正常事件** (浏览器取消分段请求), 静默收尾即可。
                pass
            finally:
                # 诊断 tap: 文档规定的七项字段 (见 _RequestTap)。放 finally 里, 保证
                # "无正文提前 return" 与异常路径同样留下记录 —— 否则最需要看的那几类
                # (204/304、断流) 恰恰不会出现在诊断数据里。
                forwarder.tap.record(
                    method=self.command, path_prefix=_path_prefix(self.path), host=host,
                    body_len=len(body), status=code,
                    first_byte_ms=round((t_first - t_req) * 1000, 1),
                    total_ms=round((time.perf_counter() - t_req) * 1000, 1),
                    bytes=bytes_out[0], req_ctype=req_ctype[:48],
                    req_sabr=req_sabr, resp_ctype=resp_ctype[:48], resp_sabr=resp_sabr,
                    err="")
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
                 target_port: int = 443,
                 idle_read: float = DEFAULT_STREAM_IDLE_READ,
                 max_duration: Optional[float] = None,
                 retries: int = DEFAULT_RETRY_SAME_NODE,
                 first_byte: Optional[float] = None):
        self.port = port
        self.host = host
        self.timeout = timeout
        self.target_port = target_port      # 可注入: 单测指向本地 h3 源站
        # 生产路径按**流式**配置: 逐读静默放宽到 300s、整周期不设上限。
        # 这是移除"24 秒硬天花板"的那一步 —— 视频流必然分钟级, 有上限就必然失败。
        self.idle_read = idle_read
        self.max_duration = max_duration
        self.retries = int(retries)
        # 生产路径显式给出**拆档**后的预算 (connect=握手 / first_byte=等首头)。
        # 为什么在这里构造而不是让 as_budget 从裸 float 推: 见 as_budget 的兼容规则 ——
        # 旧调用方传 float 时必须保持"first_byte == connect"的逐字语义, 而新语义
        # (握手 4s / 首头 8s) 只应进入**经过实测论证的这条生产路径**。
        self.budget = TimeoutBudget(
            connect=float(timeout), idle_read=float(idle_read),
            max_duration=max_duration,
            first_byte=(DEFAULT_FIRST_BYTE_TIMEOUT if first_byte is None
                        else float(first_byte)))
        self.forwarder = H3Forwarder(resolver or default_resolver, sni_for, timeout,
                                     idle_timeout=idle_read,
                                     target_port=target_port, retries=retries)
        # QUIC 自身的 idle_timeout 也必须跟上逐读预算, 否则连接会先被 QUIC 关掉
        self.forwarder.max_duration = max_duration
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
                (self.host, self.port), make_handler(self.forwarder, self.budget))
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
        fwd = proxy.forwarder if proxy is not None else None
        return {
            "running": self.is_running(),
            "listening": self.is_listening(),
            "healthy": self.is_healthy(),
            "port": self.port,
            "stats": dict(fwd.stats) if fwd is not None else {},
            # 盲区自陈 (P4 等价物): 最近 N 条异常事件 + 分类计数。
            # 没有它, "视频转圈"无从归因 —— 腿的 log_message 是空实现, 对外零可观测性。
            "events": fwd.events.snapshot() if fwd is not None else [],
            "event_counts": fwd.events.counts() if fwd is not None else {},
            # 请求级诊断 tap (E2 的观测面): 浏览器实际发了什么、gvs 怎么回的
            "tap": fwd.tap.snapshot() if fwd is not None else [],
            "timeouts": {"idle_read": getattr(fwd, "idle_timeout", None),
                         "max_duration": getattr(fwd, "max_duration", None)}
            if fwd is not None else {},
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
def wildcard_capable(redirect_mode: str) -> bool:
    """该解析后端能否下发**通配**域名 (纯函数, 可离线单测)

    为什么要抽象成"通配能力"而不是写死"必须是 NRPT":
      - Hosts 文件**不支持通配**, 只能逐个登记;
      - NRPT 命名空间**支持后缀匹配** (见 nrpt_manager) —— 但它**需要管理员 + 独占 53**;
      - **PAC + 本地 CONNECT 转发** 把通配表达在 PAC 的 JS 里 (`host.endsWith('.x')`),
        因此**不需要 DNS 具备任何通配能力**, 也不需要管理员
        (见 app/pac_redirect.py; 实测完整域名表 553 条, 播放成功)。
    判据写成能力查询, 新增后端时这里只需加一条, 不必改调用方。
    """
    return str(redirect_mode or "").strip().lower() in ("nrpt", "pac", "pac_auto")


def needs_wildcard_resolution(profile) -> bool:
    """该画像是否**依赖通配解析下发**

    判据: 需要本机 DNS 下发 (requires_dns_backend) **且** 域名里含 `*.` 通配。
    googlevideo 正是如此 (domains=["*.googlevideo.com"]): 它的节点名是动态且海量的
    (rr1---sn-xxxx.googlevideo.com), 逐个登记既不可能也不该做。
    """
    if not getattr(profile, "requires_dns_backend", False):
        return False
    return any(str(d).startswith("*.") for d in (getattr(profile, "domains", None) or []))


def blocked_services(services, redirect_mode: str, profiles_by_id=None) -> Dict[str, str]:
    """在给定解析后端下**无法生效**的服务 → 原因

    用途 (与 check_preconditions 的分工):
      - check_preconditions: 面向"腿"的整体前置条件, 用于启动时的告警;
      - 本函数: 面向"具体服务", 用于**启用边界硬门槛**与**应用重定向前剔除**。
    为什么两处都要: 只在启动时告警 = 门装错了位置。用户在 Hosts 模式下开启 googlevideo
    会得到一个"页面能开而视频永远转圈"的假可用, 而那一刻他就在界面上, 正是该拦住他的时候。
    另外, 若用户手改配置文件绕过界面, 应用重定向前也必须剔除, 不能让它静默失效。
    """
    if profiles_by_id is None:
        from service_profile import PROFILES_BY_ID as profiles_by_id  # 延迟导入避免环
    out: Dict[str, str] = {}
    if wildcard_capable(redirect_mode):
        return out
    for sid in services or []:
        p = profiles_by_id.get(sid)
        if p is not None and needs_wildcard_resolution(p):
            out[sid] = (
                f"[{getattr(p, 'name', sid)}] 依赖动态节点名的**通配**解析下发 "
                f"({'/'.join(getattr(p, 'domains', None) or [])})，"
                f"而当前解析后端 (Hosts) 不支持通配 —— 节点名不会被劫持，"
                f"会表现为「页面能开而视频永远转圈」。请改用 NRPT 后端。")
    return out


def check_preconditions(redirect_mode: str) -> List[str]:
    """返回使用 HTTP/3 上游腿的**阻塞项** (空列表 = 前置条件满足)

    为什么需要它: `requires_dns_backend` 这个标记此前只被 ip_pool 用于"排除默认启用",
    **并未强制**切换后端。于是用户可以在 Hosts 模式下手动开启 googlevideo, 而:
      - Hosts 文件**不支持通配**, 只能逐个登记域名;
      - googlevideo 的节点名是动态且海量的 (rr1---sn-xxxx.googlevideo.com);
      - 结果: 只有 apex 被劫持, 真实节点名仍走被封锁的系统解析 →
        表现为"页面能开而视频永远转圈"的假可用。
    这里把该判断做成纯函数, 由**启用边界**与启动流程共同调用, 而不是让它静默失效。
    """
    blockers: List[str] = []
    if not wildcard_capable(redirect_mode):
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
                      # ⚠ 下面四条刻意写成**整个 /16**, 而不是实测到的那个 /24。
                      # 第二次实测 (node_reach_measure.py, 同一批节点名重查) 拿到的是
                      # **同段内的另一个取值**: 128.242.245.157 / 199.96.63.177 /
                      # 199.59.148.247 / 185.60.216.169 —— 而当时表里写的是
                      # 128.242.240. / 199.96.62. / 199.59.149. / (无), 于是**四条全部漏过**,
                      # 其中 rr2---sn-i3b7kns1 因此被解析到 Facebook 地址并白烧 71.9s。
                      # 投毒取值在段内轮换, 按 /24 精确拉黑等于每轮换一次就漏一次。
                      # 与 cdn_optimizer.POLLUTED_IP_PREFIXES 的粒度保持一致 (那边本来就是 /16)。
                      "128.242.", "199.96.", "199.59.", "185.60.216.",
                      "2001::1", "2001:0:",
                      "185.45.", "174.132.", "192.133.77.",
                      "69.171.235.")

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


# 只能整段拉黑的投毒取值所在网段 (与具体取值无关)
_POISON_NET_CIDRS = ("2001::/32",)      # Teredo: 真 CDN 永远不会用隧道段
_POISON_NETS = None


def _poison_nets():
    global _POISON_NETS
    if _POISON_NETS is None:
        import ipaddress
        nets = []
        for c in _POISON_NET_CIDRS:
            try:
                nets.append(ipaddress.ip_network(c))
            except Exception:
                pass
        _POISON_NETS = nets
    return _POISON_NETS


# googlevideo 节点家族的名字域 (含实测用到的**别名域** —— 节点名在别名域上解析最干净)
_GVS_FAMILY_SUFFIXES = (".googlevideo.com", ".gvt1.com", ".bdn.dev",
                        ".c.youtube.com")
# 节点名形态: rr1---sn-i3b7kns6 / rr5---sn-ajaig5-5h (也接受 rr1.sn-… 这类写法)
_GVS_NODE_RE = None


def is_gvs_family_host(host: str) -> bool:
    """该请求目标是否属于 googlevideo 节点家族 —— 是则解析结果**必须**落在 Google 段

    为什么必须与普通 h3 目标分开处理 (2026-10-02 节点测量定因):
      对普通 h3 目标 (Cloudflare / Fastly / unpkg 自测) 非 Google 地址是**正常**的,
      套上"必须 Google 段"会把它整个弄坏;
      而 GVS 节点是 Google **自建**边缘, 不存在第三方承载 —— 因此对这类名字,
      任何非 Google 段的应答都**必然**是投毒注入, 可以放心硬淘汰。
    实测依据: 9 个节点名 × 5 个来源, 4 个别名域对 8/9 个节点一致返回 Google 段地址,
    唯一例外 (rr2---sn-i3b7kns1) 是别名域全部为空、只剩被投毒的 apex 应答。
    """
    global _GVS_NODE_RE
    import re
    h = strip_port(host).lower().rstrip(".")
    if h.endswith(_GVS_FAMILY_SUFFIXES):
        return True
    if _GVS_NODE_RE is None:
        _GVS_NODE_RE = re.compile(r"^rr\d+[.-]+sn-[a-z0-9-]+$")
    return bool(_GVS_NODE_RE.match(h.split(".", 1)[0]))


def is_poisoned(ip: str) -> bool:
    if "face:b00c" in ip or any(ip.startswith(p) for p in _DNS_POISON_PREFIX):
        return True
    # Teredo 隧道段 2001::/32: 实测两个投毒取值 2001::1 与 2001::67d6:a86a 都落在段内。
    # 必须按**段**判定, 不能用字面前缀: 写 "2001::1" 挡不住同段其他取值 (实测漏掉
    # 2001::67d6:a86a), 而写泛化的 "2001:" 又会误杀 Google 真实的 2001:4860::/32。
    try:
        import ipaddress
        a = ipaddress.ip_address(str(ip).strip())
        return any(a.version == n.version and a in n for n in _poison_nets())
    except Exception:
        return False


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

    **GVS 节点家族走"必须 Google 段"的硬判据** (见 is_gvs_family_host):
    这类名字的非 Google 应答必然是投毒, 留着它只会让腿把 connect 预算烧在一个
    永远不答的地址上 (实测 rr2---sn-i3b7kns1 拿到 Facebook 地址 → 3/3 失败,
    71.9s 纯白烧)。宁可返回空、让上层**快速如实失败**, 也不要拿投毒地址去试。
    """
    node = node_name_from_host(host)
    if not node:
        return []
    target = strip_port(host)
    strict = is_gvs_family_host(target)
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
        if strict:
            # 只有**真的**拿到 Google 段地址才收工。否则继续换下一个名字 ——
            # 若在这里按"有应答就 break", 一个投毒应答就会把后面的别名域/apex 全部截断。
            if any(is_google_edge_ip(ip) for ip in v6 + v4):
                break
        elif v6 or v4:
            break
    if v6 or v4:
        cand = v6 + v4
        if strict:
            cand = [ip for ip in cand if is_google_edge_ip(ip)]
        return cand

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
        out = (prefer_google(list(dict.fromkeys(out6)))
               + prefer_google(list(dict.fromkeys(out4))))
        if strict:
            out = [ip for ip in out if is_google_edge_ip(ip)]
        return out
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
