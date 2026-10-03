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
import functools
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


# ── pre-emit 单次上限 (2026-10-03) ──────────────────────────────────────────────
# 实测症状: 一次挂住的尝试吃满**整个**请求预算 (失败耗时精确等于 12.0s = 客户端上限),
#   于是候选里的好地址轮不到。
# 为什么 A/B 两条路线都失败 (各自实测 20 个用例红):
#   它们只改了"档用在哪", 而问题在于**时间截断会丢掉阶段信息** —— 超时只说"超时",
#   而族跳过要的是"握手失败"。阶段一丢, 同族地址全被尝试 (2→4 次), 越改越慢。
# 本实现补上两件缺的东西:
#   1. **只截断"输出开始之前"那一段** —— 一旦 emitted 就换成完整预算等完,
#      否则会把成功但较大的传输一起砍掉 (4MB 分段必然超过该上限), 那是灾难性的;
#   2. **把阶段补回来** —— 被截断时按当时阶段归类 (握手/首头), 于是族跳过照常生效。
#
# ⚠⚠ 结论: 该机制**当前不启用** (2026-10-03 真机实测, 四方对照)
#   技术上可行 —— 测试全绿 (10 个新用例 + h3 全部 124 个, 含 A/B 打破的那 20 个族跳过用例),
#   因为"被截断时按当时阶段归类"确实补回了 A/B 丢掉的信息。
#   但它在**真实链路上有害**, 且任何"有用的取值"都有害:
#     同一节点名、同一批候选地址 (2607:f8b0:4007:4::6 / 74.125.157.70), 各 24 次交错:
#       启用本上限 (2.5s)   →  成功  0/24 (0%)    失败耗时 p50=p95=max=5.1s (=2×2.5s)
#       回退(单次用满预算)  →  成功 22/24 (92%)   失败耗时 p50=9.2s
#   原因就在 DEFAULT_FIRST_BYTE_TIMEOUT 的注释里: **gvs 服务端自己就慢** —— 实测两次
#   真实成功要 5.5s / 7.2s, 那正是 first_byte 档设为 8s 的理由。
#   ⇒ 能把 12s 停顿压下去的档 (2~3s) 必然短于合法的首字节耗时, 于是**杀掉本来会成功的请求**;
#     而不会误杀的那些档 (≥8s) 相对 12s 预算几乎没有收益。
#   ⇒ 四种方案里最好的是**现状** (单次尝试用满预算)。保留本段仅为记录结论:
#     调用点已回退, 机制不生效; 若要重新评估, 必须先有"成功请求的首字节耗时分布"。
ATTEMPT_PRE_EMIT_CAP = 2.5

# 往响应队列里推一项时的**单次有界等待** (秒)。队列满就等这么久, 然后回到循环顶部
# 重新检查"客户端是否已走" —— 见 _forward.emit 的 H4 注释。
# 取值理由: 够长以免在高吞吐下空转; 够短以免客户端消失后白等 (它只影响放弃的延迟)。
_EMIT_PUT_TIMEOUT = 0.5

# 成绩单健康分档阈值 —— **从 gvs_h3_probe 取**, 不在这里各写一份 (原缺陷 M10)。
# 为什么用 try/except 而不是无条件 import: gvs_h3_probe 是带 CLI 的诊断模块,
# 让"腿能否加载"依赖它、并因此把失败级联到整个加速器, 代价不对等。
# 因此取不到常量时退回**字面量相同的默认值**, 但把那件事记进事件环 (见 _health_constants_ok),
# 而不是静默漂移 —— 判据可以退回, 但"我退回了"必须可见。
try:
    from gvs_h3_probe import FLAKY_THRESHOLD as _PROBE_FLAKY_THRESHOLD
    from gvs_h3_probe import OK_THRESHOLD as _PROBE_OK_THRESHOLD
    _PROBE_THRESHOLDS_FROM_MODULE = True
except Exception:                                   # pragma: no cover - 依赖缺失时的退路
    _PROBE_OK_THRESHOLD = 0.8
    _PROBE_FLAKY_THRESHOLD = 0.3
    _PROBE_THRESHOLDS_FROM_MODULE = False


class ClientGone(Exception):
    """客户端已放弃该请求 (连接中断 / 队列无人消费) —— 用于让 _forward 协程立刻解栈

    为什么必须是**独立异常类型**而不是复用 OSError: forward() 需要区分
    "上游失败(可以换候选重试)" 与 "客户端没了(重试毫无意义, 而且会污染成绩单)"。
    把它混进普通 Exception 会让腿在客户端已经取消之后继续烧候选与预算。
    """

# ---------------------------------------------------------------------------
# 地址级失败记忆 (跨请求) —— 2026-10-02 节点实测逼出来的
#
# `scripts/probe_gvs_nodes.py` 经**生产腿**对 12 个真实节点 × 4 轮交错采样:
#   · 失败是**按 (节点, 地址) 粘滞**的, 不是随机的:
#       rr5---sn-ajaig5-5h → 每轮都失败在 2a00:1450:4009...  (3/3)
#       rr1---sn-5hne6nzk  → 每轮都失败在 2a00:1450:400e...  (3/3)
#       rr1---sn-p5qddn7k / rr1---sn-p5qlsn6s → 每轮都失败在 2607:f8b0:4004... (3/3)
#     而同族里另一些节点在**同一时刻** 0.4~2.0s 就拿到真 gvs 响应 (403 + server: gvs)。
#   · 一次首头失败要烧掉 **8.3s** (首头预算 DEFAULT_FIRST_BYTE_TIMEOUT=8s),
#     而一次请求的重试墙钟预算只有 RETRY_TIME_BUDGET=12s ⇒ 连续两个死地址就会把预算耗尽。
#   · 同一个节点在不同轮次给出**相反结论** (rr1---sn-p5qs7nd7: 502 → 403 → 502) ——
#     这正是"卡顿/降码率"的机理: 解析出的候选里既有死地址也有活地址, 每次请求**掷硬币**
#     决定先试哪个; 掷到死地址就白等 8s 再可能被预算掐断。
#
# 对策 = 给每个**地址**记一笔失败账 (带冷却与衰减), 排序时把冷却中的地址往后放:
#   · 首头阶段失败 (STAGE_HEADERS) 才记账 —— 握手失败已由 B1 的族级逻辑处理, 重复记账
#     会让"整族抖动"被放大成"地址全黑"。
#   · **只降权, 不禁用**: 冷却地址仍然在候选里 (排后), 且当全部候选都在冷却时按原顺序试 ——
#     绝不允许"记忆"造出永久盲区 (本项目对"假可用"的红线同样适用于"假不可用")。
#   · 一成功即清零 (reward), 因此它是**近期可用性**而非终身判决。
ADDR_COOLDOWN_SECONDS = 90.0        # 首次首头失败后的冷却时长
ADDR_COOLDOWN_MAX_SECONDS = 600.0   # 连续失败时的冷却上限 (指数增长到此封顶)

# ⚠ 默认 **关闭** —— 这是同刻交错 A/B 的结论, 不是保守取值 (2026-10-02):
#   `python scripts/probe_gvs_nodes.py --ab --rounds 4` (每个 (轮, 节点) 先发一条启用记忆的
#   请求, 紧接着发一条关闭记忆的请求, 8 节点 × 4 轮 × 2 臂 = 64 条):
#       记忆 ON : 成功 13/32 (40.6%), 成功样本中位延迟 464ms
#       记忆 OFF: 成功 17/32 (53.1%), 成功样本中位延迟 377ms
#   即**没有观察到收益**。机理也解释了为什么不该有收益 —— 同一时刻对 5 个节点各解析 4 次,
#   每个节点**只有一种答案** `(1 个 v6, 1 个 v4)`, 且 v6 就是那个时好时坏的地址:
#       rr5---sn-ajaig5-5h → 恒定 2a00:1450:4009:1e::5 + 173.194.129.85
#     于是"族内把失败地址后移"在这套拓扑下是**空操作** (族内只有一个地址, 无处可移)。
#   保留代码而不删除的理由: 它的收益条件是"同一族内 ≥2 个地址且其中一个是坏的" ——
#   本轮 12 个节点都不是这种形态, 但换 IP 段/换节点名后可能出现; 届时应**先用 --ab 复测**
#   再打开, 与本项目对 DEFAULT_RETRY_SAME_NODE 的处置口径一致 (无证据不默认开启)。
ADDR_HEALTH_ENABLED_DEFAULT = False

# ---------------------------------------------------------------------------
# 节点成绩单 (跨会话) —— 见 _NodeScoreboard docstring
NODE_SCORE_KEY = "gvs_node_scores"      # config.json 键 (沿用 quic_optimal_ips 的存储模式)
NODE_SCORE_MAX = 60                     # 有界: 只保留最近见过的 60 个节点
NODE_SCORE_MIN_SAMPLES = 6              # 低于该样本数不下"可用率"结论 (只报 NO_DATA)
NODE_SCORE_HEALTHY_RATE = 0.5           # 单节点"健康"的可用率门槛
NODE_SCORE_FLUSH_SECONDS = 120.0        # 落盘节流: 不在请求路径上频繁写配置


# 慢 / 活 / 死 **三态** (2026-10-03)
#   为什么必须是三态: 二值判据(健康与否)会把"慢但能通"的节点算成不健康而**永久跳过** ——
#   这恰好是"快速失败"的单点失效模式 (短档判死 -> 慢节点被拉黑 -> 候选越用越少)。
#   与腿里 rank 3 把"可疑"和"没数据"混成一个值, 是同一类错误: **用二值去表达三态事实**。
#   各态都有明确的可操作含义:
#     healthy    快档即通             -> 优先
#     slow_alive 能通但首字节很慢      -> 可用, 排后面(最后手段), **不该被拉黑**
#     dead       多数失败             -> 跳过 + 退避
#     no_data    样本不足             -> **必须单独一态**, 不能并进 dead
#                                        (否则新节点一上来就被当死节点跳过)
#   好消息: **无需新增埋点** —— ok/fail 计数与成功时的首字节耗时 fb_ms 都已采集。
NODE_SLOW_FIRST_BYTE_MS = 2500.0


def node_state(entry: Dict[str, Any],
               min_samples: int = NODE_SCORE_MIN_SAMPLES,
               healthy_rate: float = NODE_SCORE_HEALTHY_RATE,
               slow_ms: float = NODE_SLOW_FIRST_BYTE_MS) -> str:
    """由成绩单记录推导节点状态 (纯函数: 便于单测, 也便于别处复用同一判据)

    数据全部来自已有采集, 不引入新字段。坏数据(手改坏的 fb_ms)按"不慢"处理, 不让
    一个坏值把判据打崩 —— 成绩单是落盘数据, 必须假设它可能被改坏。
    """
    try:
        ok = int(entry.get("ok", 0) or 0)
        fail = int(entry.get("fail", 0) or 0)
    except (TypeError, ValueError):
        return "no_data"
    total = ok + fail
    if total < min_samples:
        return "no_data"
    if ok <= 0:
        return "dead"
    if ok / total < healthy_rate:
        return "dead"
    fb = entry.get("fb_ms")
    try:
        if fb is not None and float(fb) >= slow_ms:
            return "slow_alive"
    except (TypeError, ValueError):
        pass
    return "healthy"

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


class _NodeScoreboard:
    """节点级成绩单 (跨会话) —— 从**浏览器真实流量**零成本采集

    ## 为什么是它 (2026-10-03 节点探查方案的 L1)

    实测把"地址多样性"两条路都否掉了:
      · 4 个别名域 (gvt1/snap.gvt1/bdn.dev/gcpcdn.gvt1) 对同一节点名**答案逐字相同**;
      · 多解析器里只有 `doh.pub` 给 Google 段答案 (alidns/360 回投毒地址, 其余不可达)。
    ⇒ **每个节点只有一个可用地址**, 所以"哪个节点此刻能用"是唯一可探查的维度,
      而探查它的最佳数据源不是合成探测 (受 `n=`/UMP 体限制, 上轮 failover 实验已栽),
      而是**浏览器自己的播放请求** —— 腿的 `_RequestTap` 三个记录点已经在记录
      `host`(节点名) / `status` / `first_byte_ms` / `bytes` / `err`, 成功失败都记。

    本类只做一件事: 把这些**已经存在**的记录按节点名累加, 并落盘跨会话保留。

    ## 口径 (必须与"播放可用"对齐, 否则又是一次自欺)

    · 只要**拿到了 HTTP 响应**就算该节点活着 —— 包括 gvs 对普通 GET 回的 403/400
      (`server: gvs 1.0` 说明确实打到了真视频服务)。按状态码<500 判定即可。
    · 失败按**原因分类**, 因为三类对应完全不同的处置:
        resolve_empty -> 该节点名从本机拿不到 Google 段答案 (strict 解析的正确答案, 换名才有用)
        handshake     -> 地址族整体不可达 (已有 B1 族级跳过)
        headers       -> 连上了但等不到首头 (`upstream_no_response`, 本篇的主角: 时变)
    · **客户端自己的错不算节点头上** (body_too_large / bad_content_length / 断流) ——
      否则会把"我们读体失败"记成"节点坏"。
    · 有界: 只保留最近见过的 N 个节点; 落盘节流 (见 NODE_SCORE_FLUSH_SECONDS),
      避免每个请求都写配置文件。
    """

    def __init__(self, max_nodes: int = NODE_SCORE_MAX, autoload: bool = True,
                 persist: bool = True):
        self.max_nodes = int(max_nodes)
        # persist=False 供**命令行探测工具**用: 它们会造大量合成请求 (403/502),
        # 若写进同一份 config 键, 会污染"浏览器真实播放统计"这个口径 —— 而健康门正是读它的。
        self.persist = bool(persist)
        self._lock = threading.Lock()
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._dirty = False
        self._last_flush = 0.0
        if autoload:
            self.load()

    # ---------------------------------------------------------------- 采集
    @staticmethod
    def _classify(status: Optional[int], err: str) -> Optional[str]:
        """-> "ok" / "resolve_empty" / "handshake" / "headers" / "other" / None(不记账)"""
        e = str(err or "").lower()
        # 客户端侧错误: 不是节点的错, 不记账
        if any(k in e for k in ("body_too_large", "bad_content_length",
                                "chunked_body_truncated", "client")):
            return None
        if isinstance(status, int) and status < 500:
            return "ok"
        if "resolve_empty" in e:
            return "resolve_empty"
        if "resolve_failed" in e:
            return "resolve_empty"
        if "handshake" in e:
            return "handshake"
        if "no_response" in e:
            return "headers"
        return "other" if status is None else "ok"

    def record(self, host: str, status: Optional[int] = None, err: str = "",
               first_byte_ms: Optional[float] = None, bytes_: int = 0) -> None:
        """记一条真实请求结果 (节点名须属 GVS 家族; 其余忽略)"""
        node = node_name_from_host(host or "")
        if not node or not is_gvs_family_host(host or ""):
            return
        kind = self._classify(status, err)
        if kind is None:
            return
        now = time.time()
        with self._lock:
            e = self._nodes.get(node)
            if e is None:
                if len(self._nodes) >= self.max_nodes:
                    # 淘汰最久未见的节点 (有界: 成绩单不该无界增长)
                    worst = min(self._nodes, key=lambda k: self._nodes[k].get("last_seen", 0))
                    self._nodes.pop(worst, None)
                e = {"ok": 0, "fail": 0, "classes": {}, "bytes": 0,
                     "first_seen": now, "last_seen": now,
                     "last_ok": 0.0, "last_fail": 0.0}
                self._nodes[node] = e
            e["last_seen"] = now
            if kind == "ok":
                e["ok"] += 1
                e["last_ok"] = now
                e["bytes"] = int(e.get("bytes", 0)) + int(bytes_ or 0)
                if first_byte_ms:
                    e["fb_ms"] = round(float(first_byte_ms), 1)
            else:
                e["fail"] += 1
                e["last_fail"] = now
                e["classes"][kind] = e["classes"].get(kind, 0) + 1
            self._dirty = True
        self.save()          # 内部按 NODE_SCORE_FLUSH_SECONDS 节流; 失败静默

    # ---------------------------------------------------------------- 读出
    def ranked(self, min_samples: int = 1) -> List[Dict[str, Any]]:
        """按可用率排序 (样本不足的排在后面, 但**不隐藏** —— 它们正是"待观察"名单)"""
        with self._lock:
            rows = []
            for node, e in self._nodes.items():
                total = e["ok"] + e["fail"]
                if total < min_samples:
                    continue
                rows.append({"node": node, "ok": e["ok"], "fail": e["fail"],
                             "total": total, "rate": round(e["ok"] / total, 3),
                             # 三态随行给出 (见 node_state): 调用方不必再自写一份判据
                             "state": node_state(e),
                             "classes": dict(e["classes"]),
                             "last_ok": round(e.get("last_ok", 0.0), 1),
                             "last_fail": round(e.get("last_fail", 0.0), 1),
                             "fb_ms": e.get("fb_ms")})
            rows.sort(key=lambda r: (-r["rate"], -r["ok"], r["node"]))
            return rows

    def summary(self, min_samples: int = NODE_SCORE_MIN_SAMPLES) -> Dict[str, Any]:
        """给健康门/UI 用的一句话结论 (样本不足时如实说"样本不足", 不猜)"""
        with self._lock:
            nodes = list(self._nodes.items())
        total = sum(e["ok"] + e["fail"] for _n, e in nodes)
        ok = sum(e["ok"] for _n, e in nodes)
        healthy = [n for n, e in nodes
                   if (e["ok"] + e["fail"]) >= min_samples and e["ok"] > 0
                   and e["ok"] / max(1, e["ok"] + e["fail"]) >= NODE_SCORE_HEALTHY_RATE]
        return {"nodes": len(nodes), "samples": total, "ok": ok,
                "rate": round(ok / total, 3) if total else None,
                "healthy_nodes": len(healthy), "enough_samples": total >= min_samples,
                "state": self.state(min_samples=min_samples)}

    def state(self, min_samples: int = NODE_SCORE_MIN_SAMPLES) -> str:
        """OK / FLAKY / UNSTABLE / NO_DATA —— 阈值**从 gvs_h3_probe 导入**, 不再各写一份

        ★ M10 (2026-10-03): 原实现这里硬编码 `0.8` / `0.3`, 而 docstring 却声称
        "阈值与 app/gvs_h3_probe 对齐" —— 注释是唯一的规格说明, 于是两边会静默漂移
        (改了一处忘了另一处, 界面显示的门槛与探针闸门的门槛就不是一回事)。
        现在直接从 gvs_h3_probe 取常量: 单一来源, 改了必然一起改。
        """
        with self._lock:
            total = sum(e["ok"] + e["fail"] for e in self._nodes.values())
            ok = sum(e["ok"] for e in self._nodes.values())
        if total < min_samples:
            return "NO_DATA"
        rate = ok / total
        if rate >= _PROBE_OK_THRESHOLD:
            return "OK"
        if rate >= _PROBE_FLAKY_THRESHOLD:
            return "FLAKY"
        return "UNSTABLE"

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {k: dict(v) for k, v in self._nodes.items()}

    def clear(self) -> None:
        with self._lock:
            self._nodes.clear()
            self._dirty = True

    # ---------------------------------------------------------------- 落盘
    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {k: dict(v) for k, v in self._nodes.items()}

    def load(self) -> None:
        """从配置读回 (失败一律静默: 成绩单是"锦上添花", 绝不能因此挡住腿启动)"""
        try:
            from config_store import load_config
            data = (load_config() or {}).get(NODE_SCORE_KEY) or {}
            if not isinstance(data, dict):
                return
            with self._lock:
                for k, v in list(data.items())[:self.max_nodes]:
                    if isinstance(v, dict):
                        self._nodes[str(k)] = {
                            "ok": int(v.get("ok", 0) or 0), "fail": int(v.get("fail", 0) or 0),
                            "classes": dict(v.get("classes") or {}),
                            "bytes": int(v.get("bytes", 0) or 0),
                            "first_seen": float(v.get("first_seen", 0) or 0),
                            "last_seen": float(v.get("last_seen", 0) or 0),
                            "last_ok": float(v.get("last_ok", 0) or 0),
                            "last_fail": float(v.get("last_fail", 0) or 0),
                            "fb_ms": v.get("fb_ms")}
        except Exception:
            pass

    def save(self, force: bool = False) -> bool:
        """节流落盘 (force=True 用于退出/停止时) —— 任何异常都不得影响请求路径"""
        if not self.persist:
            return False
        now = time.time()
        with self._lock:
            if not self._dirty:
                return False
            if not force and (now - self._last_flush) < NODE_SCORE_FLUSH_SECONDS:
                return False
            payload = {k: dict(v) for k, v in self._nodes.items()}
            self._dirty = False
            self._last_flush = now
        try:
            from config_store import update_config_key
            update_config_key(NODE_SCORE_KEY, payload)
            return True
        except Exception:
            return False


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

    ⚠ 2026-10-03: 同时把每条记录喂给 `_NodeScoreboard` (见其 docstring) —— 这样
    "节点成绩单"不需要任何新代码路径去采集, 用**同一份**已经存在的诊断数据即可。
    """

    def __init__(self, maxlen: int = TAP_RING_MAX, scores: Optional["_NodeScoreboard"] = None):
        self._dq: "collections.deque" = collections.deque(maxlen=maxlen)
        self._scores = scores

    def record(self, **kw) -> None:
        kw.setdefault("t", round(time.time(), 2))
        self._dq.append(kw)
        # 同一份记录顺带喂给节点成绩单 (零额外采集成本, 见 _NodeScoreboard docstring)。
        # 任何异常都吞掉: 诊断/统计绝不能影响请求路径。
        if self._scores is not None:
            try:
                self._scores.record(host=str(kw.get("host") or ""),
                                    status=kw.get("status"),
                                    err=str(kw.get("err") or ""),
                                    first_byte_ms=kw.get("first_byte_ms"),
                                    bytes_=int(kw.get("bytes") or 0))
            except Exception:
                pass

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


def order_candidates(ips: Sequence[str], cooling: Optional[Callable[[str], bool]] = None,
                     limit: int = 4) -> List[str]:
    """在 `attempt_order` 的族交替基础上, 把"冷却中"的地址在**本族内**后移

    为什么是"本族内后移"而不是整体重排: `attempt_order` 的族交替是 B1 的实测成果
    (googlevideo 只有 v6 通、Cloudflare 只有 v4 通)。若把冷却地址整体挪到队尾, 就可能
    出现 [v4_死族, v6_冷却, v6_活] —— 反而先撞整个不可达的族。族内后移两头的性质都保住:
     每个族仍有代表靠前, 而"刚失败过的地址"不会被优先重试。

    cooling(ip) 为 None 或全部候选都在冷却时, 行为与 `attempt_order` 逐字一致 (不留盲区)。
    """
    ordered = attempt_order(ips, limit=len(ips) or limit)
    if cooling is None or not ordered:
        return ordered[:limit]
    v6 = [ip for ip in ordered if ":" in ip]
    v4 = [ip for ip in ordered if ":" not in ip]
    if not any(cooling(ip) for ip in ordered):
        return ordered[:limit]
    v6 = [ip for ip in v6 if not cooling(ip)] + [ip for ip in v6 if cooling(ip)]
    v4 = [ip for ip in v4 if not cooling(ip)] + [ip for ip in v4 if cooling(ip)]
    out: List[str] = []
    for i in range(max(len(v6), len(v4))):
        if i < len(v6):
            out.append(v6[i])
        if i < len(v4):
            out.append(v4[i])
        if len(out) >= limit:
            break
    return out[:limit]


class _AddrHealth:
    """地址级失败记忆 (跨请求, 线程安全) —— 见 ADDR_COOLDOWN_SECONDS 上方的实测依据

    只降权不禁用: 冷却中的地址仍会排在候选里 (族内靠后), 且一成功即清零。
    """

    def __init__(self, base: float = ADDR_COOLDOWN_SECONDS,
                 cap: float = ADDR_COOLDOWN_MAX_SECONDS,
                 enabled: bool = ADDR_HEALTH_ENABLED_DEFAULT):
        self.base = float(base)
        self.cap = float(cap)
        self.enabled = bool(enabled)
        self._lock = threading.Lock()
        self._fails: Dict[str, int] = {}
        self._until: Dict[str, float] = {}
        self._last_ok: Dict[str, float] = {}

    def cooling(self, ip: str, now: Optional[float] = None) -> bool:
        if not self.enabled:
            return False
        now = time.time() if now is None else now
        with self._lock:
            return self._until.get(ip, 0.0) > now

    def penalty(self, ip: str) -> float:
        """记一次首头失败, 返回本次冷却时长 (指数增长, 封顶 cap)"""
        if not self.enabled:
            return 0.0
        with self._lock:
            n = self._fails.get(ip, 0) + 1
            self._fails[ip] = n
            secs = min(self.cap, self.base * (2 ** (n - 1)))
            self._until[ip] = time.time() + secs
            return secs

    def reward(self, ip: str) -> bool:
        """记一次成功; 返回是否**之前处于冷却/失败态** (用于产出"已恢复"事件)"""
        with self._lock:
            was = bool(self._fails.get(ip))
            self._fails.pop(ip, None)
            self._until.pop(ip, None)
            self._last_ok[ip] = time.time()
            return was

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        now = time.time()
        with self._lock:
            return {ip: {"fails": self._fails.get(ip, 0),
                         "cooling_for_s": round(max(0.0, self._until.get(ip, 0.0) - now), 1),
                         "last_ok_s_ago": (round(now - self._last_ok[ip], 1)
                                           if ip in self._last_ok else None)}
                    for ip in set(self._fails) | set(self._until) | set(self._last_ok)}


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
                 retries: int = DEFAULT_RETRY_SAME_NODE,
                 persist_scores: bool = True):
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
        # 节点成绩单 (跨会话, 见 _NodeScoreboard): 由 tap 的同一份记录喂数据。
        # 位置在 tap 之前 —— tap 需要持有它, 才能做到"零额外采集路径"。
        self.node_scores = _NodeScoreboard(persist=persist_scores)
        self.tap = _RequestTap(scores=self.node_scores)   # 请求级诊断 tap (见 _RequestTap)
        # 地址级失败记忆 (见 ADDR_HEALTH_ENABLED_DEFAULT 上方的同刻 A/B 实测): 默认**关闭**,
        # 因此生产行为与引入前逐字一致; 打开后才让"最近失败过的地址"在本族内后移。
        self.addr_health = _AddrHealth(enabled=ADDR_HEALTH_ENABLED_DEFAULT)

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
            stale = None
            with self._pool_lock:
                ent = self._pool.get(key)
                if ent is not None and is_reusable(ent[0]):
                    self.stats["reused"] += 1
                    return ent[0]
                # 不可复用/不存在的条目必须**取出并关闭**, 不能只 pop (见 _discard_conn)。
                # 注意这里不能直接调 self._discard_conn(): 它内部会再取一次 _pool_lock,
                # 而我们已经持有它 (threading.Lock 不可重入) ⇒ 会死锁。
                stale = self._pool.pop(key, None)
            if stale is not None:
                await self._aclose_conn(stale)

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

    def _await_attempt(self, fut, phase, budget) -> None:
        """等到本次尝试结束; **单次上限只作用于"输出开始之前"那一段**

        为什么上限只覆盖 pre-emit (2026-10-03 实测定因):
          · 实测一次挂住的尝试吃满整个请求预算 (失败耗时精确等于 12.0s = 客户端上限),
            于是候选里的好地址轮不到 —— 而"挂住"发生在**首头之前**;
          · 但若把上限作用于**整个**尝试, 会连"成功但较大"的传输一起截断
            (4MB 分段必然超过 2.5s) —— 那是灾难性的;
          · 所以一旦 phase 里出现 emitted, 就改用完整预算等完。
        为什么必须把阶段补回来 (A/B 两条路线各自实测 20 个用例红, 就死在这里):
          时间截断本身只给出"超时", 而族跳过要的是"握手失败";
          不按当时阶段归类, 同族地址就会全被尝试 (实测 2→4 次), **越改越慢**。
        """
        deadline = time.perf_counter() + ATTEMPT_PRE_EMIT_CAP
        while True:
            try:
                fut.result(timeout=0.05)
                return
            except TimeoutError:
                if phase.get("emitted"):
                    # 已开始输出: 不得再截断, 用完整预算等完 (行为与改动前一致)
                    fut.result(budget.max_duration)
                    return
                if time.perf_counter() >= deadline:
                    raise UpstreamStageError(
                        phase.get("stage") or UpstreamStageError.STAGE_HANDSHAKE,
                        f"attempt_pre_emit_cap({ATTEMPT_PRE_EMIT_CAP:g}s)")

    async def _forward(self, ip: str, sni: str, authority: str, method: str, path: str,
                       headers: Sequence[Tuple[str, str]], body: bytes,
                       out: "queue.Queue", budget: TimeoutBudget,
                       abandoned: "Optional[threading.Event]" = None,
                       phase: "Optional[Dict[str, Any]]" = None) -> None:
        # phase: 供**调用侧**读取本次尝试当时的阶段/是否已开始输出 (跨线程可见的 dict)。
        # 它是"被上限放弃时还能正确归类"的唯一依据 —— 见 ATTEMPT_PRE_EMIT_CAP。
        from aioquic.h3.events import DataReceived, HeadersReceived

        loop = asyncio.get_running_loop()

        async def emit(item):
            """带背压地推入队列, 且**永不无限期阻塞** (2026-10-03 定因, 原缺陷 H4)

            ## 为什么原实现会永久泄漏

            原实现只有一句 `if out.full(): await loop.run_in_executor(None, out.put, item)` ——
            无界阻塞。而客户端中途取消请求时, 消费端(HTTP 线程)**直接从异常分支 return 走了**,
            ⇒ 队列从此没有读者 ⇒ 一旦队列满 64, `_forward` 就永久卡在默认线程池里。
            泄漏的是 {1 个 HTTP 线程 + 1 个协程 + 1 个默认线程池工作线程 + 1 条永不 ack 的
            HTTP/3 流}。线程池默认 `min(32, cpu+4)`, 泄漏满即整条腿对**所有**并发请求
            停止推进; 被遗弃的流不再 acknowledge_data, 还占着同一条 QUIC 连接的
            `max_stream_data` 窗口, 可饿死同连接上的其他视频分段。

            ## 修法: 有界尝试 + 放弃信号

              · `put_nowait` 成功即返回 (快路径, 不涉线程池);
              · 队列满时用**有界** `out.put(timeout=0.5)` 跑在线程池里 —— 关键区别是
                它会**返回**, 不会永久占住工作线程;
              · 每轮先查 `abandoned` (客户端已走 ⇒ 抛 ClientGone, 协程立刻解栈);
              · 没有放弃信号时 (旧调用方/单测) 退化为原来的阻塞语义, 保持兼容。
            """
            while True:
                if abandoned is not None and abandoned.is_set():
                    raise ClientGone()
                try:
                    out.put_nowait(item)
                    return
                except queue.Full:
                    pass
                # 队列满: 用**有界** put 让出一段时间。关键区别在于它会返回 —— 原先的
                # `out.put` 没有超时, 一旦队列没有读者就永久占住一个线程池工作线程。
                try:
                    await loop.run_in_executor(
                        None, functools.partial(out.put, item, True, _EMIT_PUT_TIMEOUT))
                    return
                except queue.Full:
                    # 这半秒内没排上: 回到循环顶部重新检查放弃信号
                    continue
                except Exception:
                    # 队列本身出问题 (不该发生): 不要因为它把整条腿拖死
                    raise ClientGone()

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
        if phase is not None:
            phase["stage"] = UpstreamStageError.STAGE_HANDSHAKE
        try:
            proto = await asyncio.wait_for(self._get_conn(ip, sni), timeout=budget.connect)
        except Exception as e:
            self.stats["errors"] += 1
            # 打上"握手阶段"标记: forward() 据此判定**该地址族**在本轮不可达并跳过同族
            # 其余地址 (见 UpstreamStageError)。消息保持与拆档前逐字一致, 便于比对日志。
            raise UpstreamStageError(UpstreamStageError.STAGE_HANDSHAKE,
                                     _describe_exc(e)) from e

        # ★★ `headers_sent` 是"能否重试"的**唯一**判据 (2026-10-03 定因, 原缺陷 H1)。
        #   原先靠 `except` 的**位置**来推断, 而注释写着"走到这里说明已经写了响应头" ——
        #   那个前提不成立: `STAGE_HEADERS` 的异常(首头超时, 即 E2 实测的**主失败模式**
        #   `upstream_no_response`)必然发生在首次 emit 头部**之前**。
        #   而下面的 except 既入队错误、又**不重新抛出**, 于是调用侧 `fut.result()` 认为
        #   这次调用**成功**并直接 return —— 换候选/重解析那整条容错链对主失败模式
        #   **从未执行过**(腿还会把这次记成 recovered/addr_recovered)。
        #   ⇒ 必须用显式标志, 而不是靠位置推断。
        if phase is not None:
            # 握手已成功 -> 之后的失败属于**首头阶段**, 不能用来推断整族不可达
            phase["stage"] = UpstreamStageError.STAGE_HEADERS
        headers_sent = False
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
                # ★ 头部一旦入队, 就**再也没有"换下一个候选"这个选项**了 —— 否则会把两个
                #   上游的响应拼在一起。这一行是 H1 的分界线。
                headers_sent = True
                if phase is not None:
                    phase["emitted"] = True  # 之后不得再截断 (见 ATTEMPT_PRE_EMIT_CAP)
                # CORS 归因探针: 记下上游**原始**头里有没有跨源头。
                # 这决定修法是"补白名单"(上游有、我们丢了) 还是"兜底注入"(上游没发)。
                if cors_headers_present(resp_headers):
                    self.stats["cors_upstream"] = self.stats.get("cors_upstream", 0) + 1
                else:
                    self.stats["cors_missing_upstream"] = \
                        self.stats.get("cors_missing_upstream", 0) + 1
                    self.events.add("no_cors_upstream",
                                    f"{ip} {path.split('?')[0][:28]} 上游未带 access-control-*")

                # ★ 无体状态码 (204/304/1xx): **头部即结束**, 立即收尾, 绝不进入正文循环。
                #
                # 为什么必须在这里收 (2026-10-03, 由 Go 黑盒测试台实测抓出):
                #   旧实现的收尾在**调用侧**, 而调用侧只能"等队列出现非 data 事件" ——
                #   上游 204 的流不会自己关, 于是每条 204/304 都要一直等到**逐读静默预算**
                #   耗尽才结束: 实测在 --idle-read=4 下是 4.0s, 而**生产预算是 300s**。
                #   而 SABR 会话里 gvs 恰恰用 204 当 ack (见 plan_http1_response 注释) ⇒
                #   每条 ack 占住一个 HTTP 线程 + 一条上游流, 最长 5 分钟 —— 与"卡顿/降码率"
                #   的症状完全一致, 且会随播放时长累积。
                if status in BODYLESS_STATUSES or 100 <= status < 200:
                    await emit(("end", None))
                    return
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
                # ★ `cut` 区分"正常结束"与"通道被掐" (2026-10-03 定因, 原缺陷 H2)。
                #   原实现两种收尾都以 `("end", None)` 结束 ⇒ 调用侧无法区分, 于是:
                #     · 给**截断**的响应补上了合法的 chunked 终止符 `0\r\n\r\n`,
                #       断流产生的响应在语法上**完全合法** —— nginx 与浏览器都无法区分
                #       "截断"与"完整", 播放器把半截分段当成功;
                #     · tap 仍记 `status=200, err=""`, 成绩单 `_classify` 记为 `ok`,
                #       把"通道被掐"统计成"节点健康"。
                #   上游不给 Content-Length 时 (SABR / 大文件最可能走的路) 后果最重。
                cut = ""
                while True:
                    if proto.terminated.is_set():
                        cut = f"connection_terminated ({len(buf)}B 未刷)"
                        self.events.add("stream_cut", f"{ip} {cut}")
                        break
                    try:
                        ev = await asyncio.wait_for(q.get(), timeout=budget.idle_read)
                    except asyncio.TimeoutError:
                        cut = f"idle>{budget.idle_read:g}s 静默超限 ({len(buf)}B 未刷)"
                        self.events.add("stream_cut", f"{ip} {cut}")
                        break
                    if not isinstance(ev, DataReceived):
                        # ⚠ trailers (HeadersReceived) 可能携带 stream_ended:
                        #   原先 `continue` 直接丢掉, 于是**正常结束被记成 stream_cut**,
                        #   客户端还要白等一整个逐读预算 (生产 300s)。见 M9。
                        if getattr(ev, "stream_ended", False):
                            break
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
                # ★ 把"是否被截断"如实告诉调用侧: 它据此决定**不补** chunked 终止符
                #   并记下真实错误。这是 H2 与 M9 的共同出口。
                await emit(("error", f"stream_cut: {cut}") if cut else ("end", None))
            finally:
                proto.unregister(sid)
        except ClientGone:
            # 客户端已放弃该请求: 不该计入 "errors"(那是上游的错), 队列也没有读者。
            self.events.add("client_gone", f"{ip} 客户端中断, 已取消该流")
            raise
        except Exception as e:
            self.stats["errors"] += 1
            if not headers_sent:
                # ★★ 头部还没写入 ⇒ **必须向上抛**, 让 forward() 换下一个候选/重解析。
                #   这是 H1 的核心修复: 原实现无条件吞进队列且不重抛, 于是首头失败
                #   (主失败模式) 永远走不到换候选那条路, 而腿还把它记成 recovered。
                try:
                    proto.unregister(sid)
                except Exception:
                    pass
                raise
            # 已经写了响应头: 不能再换节点重试 —— 否则会把两个上游的响应拼在一起。
            # 如实收尾即可。
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
                retries: Optional[int] = None,
                abandoned: "Optional[threading.Event]" = None) -> None:
        """同步入口 (供 HTTP 线程调用): 解析目标 → 逐个候选地址尝试 → (必要时)重解析再试

        :param abandoned: 客户端放弃信号。消费端 (HTTP 线程) 在连接中断时 set 它,
            本方法据此**停止烧候选/预算**并让 _forward 协程立刻解栈 (原缺陷 H4)。

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

        # ★★ 非幂等方法**不得跨地址重放** (2026-10-03 定因, 原缺陷 H7)
        #
        # 原实现里候选遍历与重试**完全不看 method**, 每次尝试都
        # `send_data(sid, body, end_stream=True)` 发给**另一个地址** (round0 ≤4 候选 +
        # 重解析 round ≤4, 受 MAX_TOTAL_ATTEMPTS=6 约束); nginx 侧同一个 POST 也会被
        # 再次投给腿 (`non_idempotent` + `tries 4`)。三方独立指向同一条链 ⇒
        # **最坏 24 次投递**。
        #
        # 后果: SABR/UMP 是**有状态**协议 (项目自己这么定性),
        # `generativelanguage.googleapis.com/...:streamGenerateContent` 这类端点是
        # **按 token 计费**的生成调用 ⇒ 一次操作可能在上游产生两次生成。
        # 这是本项目唯一一条可能造成**用户直接经济损失**的缺陷。
        #
        # 口径: 幂等方法 (GET/HEAD/OPTIONS/TRACE) 照旧换候选重试 —— 那是本腿的核心容错。
        # 非幂等**只禁"换地址"**, 不禁"同地址重试" (2026-10-03 收窄后的口径):
        #   · SABR POST 的**同节点重试**是 2026-10-02 E2 实测的成果, 且实测显示默认
        #     retries=0, 该路径本就没开; 但**不能**用"非幂等"去关掉它 —— 那会把一条
        #     经过实测论证的容错与一条未经验证的策略混为一谈。
        #   · 真正会造成重复副作用的是**把同一个体投给另一个上游**: 那才是"一次操作
        #     产生两次生成"。所以只砍掉"轮 1 重解析换一批地址"与"多候选逐个试"。
        non_idem = str(method or "GET").upper() not in ("GET", "HEAD", "OPTIONS", "TRACE")
        if non_idem:
            self.events.add("non_idempotent_method",
                            f"{authority} {method} 非幂等: 不换地址(不重解析/不多候选)")

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
            if non_idem and rnd > 0:
                # 非幂等请求**不允许**跨地址重放 (见 non_idem 的推导), 所以第二轮
                # (重解析 = 再换一批地址) 直接不做。
                self.events.add("non_idempotent_no_addr_change",
                                f"{authority} {method} 非幂等, 跳过重解析换地址")
                break
            if rnd == 0:
                cands = [ip for ip in order_candidates(ips, self.addr_health.cooling)
                         if ip not in tried]
                if non_idem:
                    # 只留**第一个**候选: 换地址 = 把同一个 POST 投给另一个上游,
                    # 可能在上游产生第二次副作用 (按 token 计费的生成调用会真花钱)。
                    if len(cands) > 1:
                        self.events.add("non_idempotent_single_candidate",
                                        f"{authority} {method} 非幂等, 候选 "
                                        f"{len(cands)} 个只用首个 ({cands[0]})")
                    cands = cands[:1]
            else:
                # 重解析本身也要受预算约束: DoH 最坏可能串行花掉几十秒, 若在失败路径上
                # 无约束地再来一次, 502 会被推得比不重试还晚 —— 与设 RETRY_TIME_BUDGET 的
                # 理由完全相同。
                if (time.perf_counter() - t_start) > RETRY_TIME_BUDGET:
                    self.events.add("retry_budget_exhausted",
                                    f"{authority} 预算用尽, 跳过重解析")
                    break
                cands = [ip for ip in order_candidates(self._reresolve(authority),
                                                       self.addr_health.cooling)
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
                    phase: Dict[str, Any] = {}
                    fut = self._bridge.submit(self._forward(
                        ip, sni, authority, method, path, headers, body, out, budget,
                        abandoned, phase))
                    try:
                        # ⚠ 已回退单次上限 (2026-10-03 真机实测): 见 ATTEMPT_PRE_EMIT_CAP
                        #   上方记录 —— 任何"有用的短档"都会杀掉**本来会成功**的尝试。
                        #   此处保持原语义: 单次尝试用满整体预算。
                        fut.result(budget.max_duration)
                        if self.addr_health.enabled and self.addr_health.reward(ip):
                            self.events.add("addr_recovered", f"{authority} 地址 {ip} 已恢复")
                        if attempts > 1:
                            self.events.add("recovered",
                                            f"{authority} 第 {attempts} 次尝试成功 ({ip})")
                        return
                    except ClientGone:
                        # ★ 客户端已放弃: 换候选/重试**毫无意义** (没有读者), 而且会污染
                        #   成绩单(把客户端取消记成节点失败)并继续烧预算。直接收尾。
                        self.events.add("client_gone", f"{authority} 客户端中断, 停止重试")
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
                        stage = getattr(e, "stage", None)
                        if stage == UpstreamStageError.STAGE_HANDSHAKE:
                            fam = ip_family(ip)
                            if fam not in dead_families:
                                dead_families.add(fam)
                                self.events.add(
                                    "family_unreachable",
                                    f"{authority} {fam} 首个地址 {ip} 握手失败, "
                                    f"本轮跳过同族其余地址")
                        elif (stage == UpstreamStageError.STAGE_HEADERS
                              and self.addr_health.enabled):
                            # 地址级记账 (跨请求): 实测首头失败是**按地址粘滞**的,
                            # 而每次要烧 8s 首头预算 (见 ADDR_COOLDOWN_SECONDS 上方依据)。
                            # 只降权不禁用 —— 冷却地址仍在本族内排在后面。
                            secs = self.addr_health.penalty(ip)
                            self.stats["addr_cooled"] = self.stats.get("addr_cooled", 0) + 1
                            self.events.add(
                                "addr_cooled",
                                f"{authority} 地址 {ip} 首头失败, 冷却 {secs:.0f}s "
                                f"(后续请求把它在本族内后移; 仍会尝试, 不拉黑)")
                        try:
                            fut.cancel()           # 让 _forward 在 await 点收到 CancelledError
                        except Exception:
                            pass
                        self._drain(out)           # 丢弃半成品, 避免污染下一次
                        # ★ H9: pop 出来的连接必须**真的关掉** (见 _discard_conn)。
                        #   原实现只 pop 不 __aexit__ ⇒ 每次可恢复的失败永久丢一条已建立的
                        #   QUIC 连接 + 一个已 bind 的 UDP 套接字 (回收延迟是 aioquic 空闲
                        #   计时器量级, 最长 600s)。close() 只遍历**仍在池里**的条目, 救不回它。
                        self._discard_conn((ip, sni))
        # 走到这里说明所有候选都失败了。但若客户端已经走了, 入队错误没有意义 ——
        # 队列没有读者, 而且 put 在满队列上会阻塞(即使有超时, 也是白等一轮)。
        if abandoned is not None and abandoned.is_set():
            self.events.add("client_gone", f"{authority} 全部候选失败时客户端已中断")
            return
        out.put(("error", last_err))

    def _discard_conn(self, key) -> None:
        """把池里的连接**取出并真正关闭** (原缺陷 H9)

        为什么不能只 `pop`: `_get_conn` 刻意用 `cm.__aenter__()` 进入 aioquic 的 connect()
        上下文并**不退出** (那是池化手段, 见其注释)。因此一旦只把它从池里 pop 掉,
        `__aexit__` 就永远不会被调用 ⇒ `transport.close()` 永不执行 ⇒ 每次可恢复的失败
        都泄漏一条已建立的 QUIC 连接与一个已 bind 的 UDP 套接字。
        (aioquic 自己的 idle 计时器最终会关掉它, 但那是 600s 量级的延迟回收。)
        """
        if key is None:
            return
        with self._pool_lock:
            ent = self._pool.pop(key, None)
        if ent is None:
            return
        self._bridge.submit(self._aclose_conn(ent))

    @staticmethod
    async def _aclose_conn(ent) -> None:
        """在事件循环里关闭一个 (proto, cm) 池条目 —— best-effort, 绝不抛出"""
        proto, cm = ent
        try:
            await cm.__aexit__(None, None, None)
            return
        except Exception:
            pass
        try:
            proto._quic.close()
        except Exception:
            pass

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
                # ★ `Access-Control-Allow-Credentials: true` **必须**一并带上
                #   (2026-10-02 真机日志定因): YouTube 的播放器用
                #   `credentials: 'include'` 取 /videoplayback。当我们的腿返回 502 时,
                #   错误响应只有 Allow-Origin、没有 Allow-Credentials, 于是 Chrome 报的是
                #     "The value of the 'Access-Control-Allow-Credentials' header in the
                #      response is '' which must be 'true' when the request's credentials
                #      mode is 'include'"
                #   —— **真实原因是 502, 却被说成 CORS 头缺失**, 播放器也无法按状态码退避重试。
                #   这正是本项目记录过的同一类掩盖 ("32 条 CORS 错误, 逐条追下去全是 502 的
                #   次生症状")。带上它, 真因(状态码)才看得见。
                self.send_header("Access-Control-Allow-Credentials", "true")
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
            # ★ 客户端放弃信号 (2026-10-03, 原缺陷 H4): 连接中断时消费端**不再有读者**,
            #   必须把这个事实告诉生产者, 否则 _forward 会在满队列上白白占住线程池线程,
            #   同时泄漏协程与一条永不 acknowledge 的 HTTP/3 流。
            abandoned = threading.Event()
            threading.Thread(
                target=forwarder.forward,
                # ⚠ `abandoned` 必须用**关键字**传: 它是 2026-10-03 新增的参数, 而
                #   测试里的 forwarder 替身只接受 (host, method, path, headers, body,
                #   out, timeout, idle_read, max_duration) —— 位置参数会把它打成
                #   TypeError 并让整条请求挂住 (实测: 该线程一炸, out 永远为空,
                #   客户端等到超时)。关键字形式让新旧替身都能工作。
                kwargs=dict(
                    idle_read=getattr(forwarder, "idle_timeout", None),
                    max_duration=getattr(forwarder, "max_duration", None),
                    abandoned=abandoned),
                # 逐读静默与整周期上限从 forwarder 读 (生产路径按流式配置, 见 proxy.__init__):
                # 不再把一个 timeout 同时当建连/逐读/整周期三种角色用。
                args=(host, self.command, self.path, list(self.headers.items()),
                      body, out, timeout),
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
            bytes_out = [0]
            end_kind = "end"           # "end" = 正常收尾; "error" = 上游断流/异常
            end_err = ""
            # ══════════════════════════════════════════════════════════════════════════
            # ★★ H3: 整个响应回写必须在**同一个 try 之内** (2026-10-03 定因)
            #
            # 原实现的 try 从 `bytes_out = [0]` 之后才开始, 而真正写 socket 的那一步是
            # `end_headers()` → `flush_headers()` → `wfile.write()` —— **它在任何 try 之外**
            # (502 分支 :1480 与 body-error 分支 :1437 同样如此)。
            # 后果: 浏览器在 502 返回前取消请求时抛的 ConnectionAbortedError 会一路穿到
            # `socketserver.process_request_thread` → `handle_error()`, 打印整段回溯,
            # 并且 `finally` 里的 `tap.record` **被跳过** —— 丢掉的正是最该看的诊断。
            # 作者当时记录的触发场景("浏览器会在 502 返回前取消请求")恰好先撞上这第一次写。
            # ══════════════════════════════════════════════════════════════════════════
            try:
                self.send_response_only(code)
                for k, v in headers:
                    if plan["strip_length_headers"] and str(k).lower() in (
                            "content-length", "transfer-encoding"):
                        continue
                    self.send_header(k, v)
                if plan["chunked"]:
                    self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                if not plan["allow_body"]:
                    # 无正文响应: 不写任何字节。终止事件由 forwarder 在**头部之后立即**推入
                    # (见 _forward 的无体分支) —— 这里再加一道**有界**兜底: 即使将来回归,
                    # 也绝不允许把客户端挂住。旧行为是无限等 `out.get()`, 而 204 的上游流
                    # 不会自己关 ⇒ 实测每条要等满逐读预算 (生产 300s)。
                    deadline = time.perf_counter() + 2.0
                    while True:
                        remain = deadline - time.perf_counter()
                        if remain <= 0:
                            forwarder.events.add("bodyless_wait_timeout",
                                                 self.path.split("?")[0][:48])
                            break
                        try:
                            kind, _payload = out.get(timeout=remain)
                        except queue.Empty:
                            forwarder.events.add("bodyless_wait_timeout",
                                                 self.path.split("?")[0][:48])
                            break
                        if kind != "data":
                            break
                    # ★ M8 (2026-10-03): 无体分支也必须**关闭连接**。
                    #   原先这里是裸 `return`, 于是跳过了函数末尾的
                    #   `self.close_connection = True` —— 而 `upstream-dynamic.conf` 的注释
                    #   明确写着"本腿每条响应后关闭连接 (close_connection=True), 故不声明
                    #   keepalive"。两者矛盾: 一旦我们声明关连接却又不关, 该连接会带着
                    #   未消费的字节被复用。204 是 SABR 的 ack 路径 (热的), 所以这条不是理论问题。
                    self.close_connection = True
                    return
                while True:
                    kind, payload = out.get()
                    if kind == "data":
                        bytes_out[0] += len(payload)
                        if plan["chunked"]:
                            self.wfile.write(b"%X\r\n%s\r\n" % (len(payload), payload))
                        else:
                            self.wfile.write(payload)
                    else:
                        # ★ H2: 必须区分"上游正常结束"与"上游断流/出错"。
                        #   原实现把两者写成同一分支 (`else: # end / error`), 于是给**截断**
                        #   的响应补上了合法的 chunked 终止符 `0\r\n\r\n` —— 断流产生的响应在
                        #   语法上完全合法, nginx 与浏览器都无法区分"截断"与"完整",
                        #   播放器把半截分段当成功; 而 tap 仍记 err=""、成绩单记为 ok,
                        #   把"通道被掐"统计成"节点健康"。
                        end_kind = kind
                        if kind != "data":
                            end_err = str(payload or "")
                        break
                # 只在**正常结束**时补终止符。截断时故意不补: 让 nginx/浏览器看到一个
                # 不完整的 chunked 体(响亮失败), 而不是一个语法合法的半截响应。
                if plan["chunked"] and end_kind == "end":
                    self.wfile.write(b"0\r\n\r\n")
                elif end_kind != "end":
                    # 已声明 chunked 却不补终止符 ⇒ 必须关闭连接, 不能让它继续复用
                    # (否则下一个请求会读到残留字节)。
                    self.close_connection = True
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError,
                    TimeoutError, OSError):
                # Windows 上客户端中断常抛 ConnectionAbortedError (WinError 10053) 或裸
                # OSError, 都不在 BrokenPipe/ConnectionReset 里 —— 实测漏网时会在 stderr
                # 打一整段回溯 (E2 的 CDP 运行里就出现过), 把真正的诊断输出淹没。
                # 这类中断是**正常事件** (浏览器取消分段请求), 静默收尾即可。
                #
                # ★ 但"静默"不等于"不管": 必须告诉生产者客户端已经走了 (H4), 否则
                #   _forward 会继续往一个没有读者的队列里推, 满 64 后永久占住线程池线程。
                abandoned.set()
                self._drain_queue(out)
            finally:
                # 诊断 tap: 文档规定的七项字段 (见 _RequestTap)。放 finally 里, 保证
                # "无正文提前 return" 与异常路径同样留下记录 —— 否则最需要看的那几类
                # (204/304、断流) 恰恰不会出现在诊断数据里。
                #
                # ★ H2: err 不再恒为空 —— 断流/异常必须记下真实原因, 否则成绩单会把
                #   "通道被掐"统计成"节点健康"。
                forwarder.tap.record(
                    method=self.command, path_prefix=_path_prefix(self.path), host=host,
                    body_len=len(body), status=code,
                    first_byte_ms=round((t_first - t_req) * 1000, 1),
                    total_ms=round((time.perf_counter() - t_req) * 1000, 1),
                    bytes=bytes_out[0], req_ctype=req_ctype[:48],
                    req_sabr=req_sabr, resp_ctype=resp_ctype[:48], resp_sabr=resp_sabr,
                    err=(end_err[:80] if end_kind != "end" else ""))
            self.close_connection = True

        def _drain_queue(q: "queue.Queue") -> None:
            """排空响应队列, 让可能还阻塞在 put 上的生产者立刻返回 (H4)

            为什么必须有: 客户端中断后队列没有读者, 生产者即使有超时也会反复回来;
            排空后它下一次 put_nowait 就能成功退出, 于是协程与线程都能及时回收。
            """
            while True:
                try:
                    q.get_nowait()
                except queue.Empty:
                    return

        def handle_error(self, request, client_address):
            """覆盖 socketserver 的默认实现: **不打整段回溯** (H3)

            默认实现会把完整 traceback 打到 stderr。而本腿面对的多是"浏览器取消分段请求"
            这类**正常事件**, 一条回溯就会把真正的诊断输出淹没 (这正是 E2 运行里发生过的)。
            这里只留一行有界日志, 并通过事件环暴露给 status()。
            """
            try:
                forwarder.events.add("handler_error",
                                     f"{client_address} {type(sys.exc_info()[1]).__name__}")
            except Exception:
                pass

        do_GET = _relay
        do_HEAD = _relay
        do_POST = _relay
        do_PUT = _relay
        do_OPTIONS = _relay

    return _Handler


class _LegHTTPServer(ThreadingHTTPServer):
    """腿的回环 HTTP 服务器 —— 关键是**抬高 accept backlog**

    为什么必须覆盖默认值 (2026-10-03, 由 Go 黑盒测试台 `tools/h3_legtest` 实测抓出):
      `socketserver.TCPServer.request_queue_size` 默认只有 **5**。16 并发请求实测
      **6/16 直接被 connection refused** —— Windows 对溢出 backlog 的处理是 RST 而非排队。
      生产含义: nginx 侧 upstream 带 `keepalive 32`, 视频播放又天然并发多分段,
      突发一旦超过排队深度就会被打回 502; 而 `upstream_googlevideo` 只声明了一个 server
      且 `max_fails=0 fail_timeout=0s` (刻意关熔断), 重试**无处可去** —— 表现为随机卡顿/失败。
      128 = nginx keepalive 池 32 + 浏览器分段并发 + 突发余量; accept 本身是毫秒级,
      所以队列深度只是削峰, 不是延迟来源。
    """

    request_queue_size = 128
    # ⚠ 必须 False (2026-10-04 统一, 缺陷 D1): Windows 上 SO_REUSEADDR 允许绑定
    #   一个**已被监听**的端口 —— 于是"端口被占"不会报错, 两个进程同时绑 44411,
    #   流量落到谁那里不确定。本项目在 pac_redirect.py 里已为这个语义定过案
    #   (注释写着"不能开"), 但这里与 l4_relay / dns_server / is_port_in_use 没跟上;
    #   现在四处统一为"独占语义, 冲突如实失败"。后果是 TIME_WAIT 期间短时无法重绑
    #   —— 与 pac_redirect 已接受的同一代价, 且 is_listening() 会如实报告未就绪。
    allow_reuse_address = False
    daemon_threads = True


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
                 first_byte: Optional[float] = None,
                 persist_scores: bool = True):
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
                                     target_port=target_port, retries=retries,
                                     persist_scores=persist_scores)
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
            self._httpd = _LegHTTPServer(
                (self.host, self.port), make_handler(self.forwarder, self.budget))
            self._thread = threading.Thread(target=self._httpd.serve_forever,
                                            name="h3-upstream-http", daemon=True)
            self._thread.start()
            return True, ""
        except Exception as e:
            self._httpd = None
            return False, f"{type(e).__name__}: {e}"

    def stop(self):
        try:
            # 退出前把成绩单落盘 (force: 绕过节流) —— 否则跨会话累积就断了
            self.forwarder.node_scores.save(force=True)
        except Exception:
            pass
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
            # 地址级失败记忆 (2026-10-02 节点实测的落地): 哪些地址刚失败过、冷却多久、
            # 哪些已恢复。没有它, "为什么这个节点时通时不通"在界面上无从解释。
            "addr_health": fwd.addr_health.snapshot() if fwd is not None else {},
            # 节点成绩单 (2026-10-03): 跨会话的真实流量统计 + 排名 —— 让"当前窗口能不能播"
            # 变成可读状态, 而不是靠人跑命令。
            "node_scores": fwd.node_scores.summary() if fwd is not None else {},
            "node_rank": fwd.node_scores.ranked()[:12] if fwd is not None else [],
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
    """该画像是否**依赖通配解析下发** (动态子域必须靠后缀通配覆盖)

    ## ★ 为什么不再做二次推导 (2026-10-03 定因, 原缺陷 M13)

    旧实现是 `requires_dns_backend and any(d.startswith("*."))` —— 把"需要 DNS 后端"
    与"域名里有通配"**合取**起来推导。而 `requires_dns_backend` 的真实语义是
    "需要 DNS 下发 HTTPS RR (QUIC 直连)", 与通配毫无关系; 它之所以对 googlevideo 为真,
    只是因为那个画像当时**借这个字段兼职"不默认启用"**。

    这个合取式的害处不只是"词不达意": 它把 S1 的缺陷藏住了 ——
    NRPT 后端把 `*.` 条目整条丢空时, 这里的推导仍然回答"需要通配",
    于是上层以为能力齐备。现在直接读**为这件事专门声明的字段**。

    googlevideo 正是如此 (domains 全是 `*.googlevideo.com` 这类通配): 它的节点名是动态
    且海量的 (rr1---sn-xxxx.googlevideo.com), 逐个登记既不可能也不该做。
    """
    return bool(getattr(profile, "needs_wildcard_resolution", False))


def wildcard_domains(profile) -> List[str]:
    """画像里以 `*.` 开头的域名 (通配项), 保序"""
    return [str(d) for d in (getattr(profile, "domains", None) or [])
            if str(d).startswith("*.")]


def wildcard_gap_warnings(services, redirect_mode: str, profiles_by_id=None
                          ) -> Dict[str, List[str]]:
    """当前解析后端**表达不了**的通配域 → 受影响的服务 (软告警, 不拦截)

    与 blocked_services 的分工 (两者判据不同, 别混用):
      · blocked_services: 服务**整体**依赖通配 (googlevideo 的域名全是 `*.`) ⇒ **硬拦**,
        因为在 Hosts 下它 100% 不能用;
      · 本函数: 服务里**只有部分**域名是通配 (gemini 的 `*.clients6.google.com`) ⇒ 只能**软告警**
        —— 拦掉它比现在的半可用状态**更糟** (那个画像其余 17 个具体域在 Hosts 下是好的)。

    为什么必须有这个软告警 (2026-10-02 用户控制台实测):
      Hosts 文件不支持通配, 但 `build_domain_targets` 会把 `*.clients6.google.com`
      **原样**写进 Hosts (`127.0.0.1 *.clients6.google.com`) —— 那一行匹配不到任何真实主机名。
      于是该通配覆盖的主机照旧走真实解析 (被墙), 而**启用边界对它毫无提示**:
      实测 `geminiweb-pa.clients6.google.com/v1/processSession` (WebChannel 会话端点) 与
      `waa-pa.clients6.google.com/$rpc/...` 双双 ERR_CONNECTION_TIMED_OUT,
      表现为"页面外壳能开、对话完全不通"。
      这正是本项目反复强调的"假可用"—— 所以哪怕不拦, 也必须**说出来**。
    """
    if profiles_by_id is None:
        from service_profile import PROFILES_BY_ID as profiles_by_id  # 延迟导入避免环
    out: Dict[str, List[str]] = {}
    if wildcard_capable(redirect_mode):
        return out
    for sid in services or []:
        p = profiles_by_id.get(sid)
        if p is None:
            continue
        wild = wildcard_domains(p)
        # 已经被硬拦的服务不再重复软告警 —— 两者结果集刻意保持**不相交**,
        # 调用方可以放心把两类消息拼在一起展示。
        if wild and not needs_wildcard_resolution(p):
            out[sid] = wild
    return out


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
                f"会表现为「页面能开而视频永远转圈」。请改用 PAC 后端 "
                f"(免管理员, 且 PAC 能在 JS 里表达通配 —— 见 app/pac_redirect.py)。")
    return out


def gvs_health(scoreboard: Optional["_NodeScoreboard"] = None) -> Dict[str, Any]:
    """googlevideo 通道健康度 (**离线读取**, 不发起任何探测)

    供"启用边界软告警"与启动流程使用 —— 它的数据来自 `_NodeScoreboard`:
    浏览器真实播放留下的节点成绩单 (跨会话持久化)。**刻意不做实时探测**:
      · 实时探测要几十秒 (整池 × 多轮), 挂在开关回调上会冻结界面;
      · 更重要的是, 合成探测本身读不出"能不能播" (受 `n=` 与 UMP 体限制, 见
        docs/googlevideo-node-availability.md §5), 而成绩单是真实播放的直接统计。

    返回 state 与阈值同 `app/gvs_h3_probe` (OK/FLAKY/UNSTABLE/NO_DATA), 便于两处结论互相对照。
    """
    sb = scoreboard
    if sb is None:
        sb = _NodeScoreboard()          # 仅读配置, 不启动腿
    try:
        return sb.summary()
    except Exception as e:
        return {"nodes": 0, "samples": 0, "ok": 0, "rate": None, "healthy_nodes": 0,
                "enough_samples": False, "state": "NO_DATA", "error": str(e)[:120]}


def gvs_health_hint(services=None, scoreboard: Optional["_NodeScoreboard"] = None) -> str:
    """给 UI 的一句话告警 (稳定/样本不足时返回空串 —— 不打扰)

    口径: 只在**确实不稳定**时提示, 与既有的软告警 (blocked/gaps) 同一形态。
    scoreboard 可注入 (单测用); 省略时读已落盘的成绩单。
    """
    try:
        h = gvs_health(scoreboard)
    except Exception:
        return ""
    state = str(h.get("state") or "NO_DATA")
    if state in ("OK", "NO_DATA"):
        return ""
    total = int(h.get("samples") or 0)
    ok = int(h.get("ok") or 0)
    rate = h.get("rate")
    pct = f"{round(float(rate) * 100)}%" if rate is not None else "-"
    tail = ("视频可能卡顿/降码率或需要反复重试; 这是**节点级**的分钟级时变问题 "
            "(各节点只有一个可用地址, 详见 docs/googlevideo-node-availability.md)。")
    if state == "UNSTABLE":
        return f"最近 {total} 次视频请求里节点可用率仅 {pct} ({ok}/{total}) —— {tail}"
    return (f"最近 {total} 次视频请求里节点可用率偏低 {pct} ({ok}/{total}) —— {tail}")


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
            "会表现为'页面能开而视频永远转圈'。请改用 PAC 后端 "
            "(免管理员; PAC 用 host.endsWith() 表达通配, 无需 DNS 具备任何通配能力)。")
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
    # ---- 测试/调试注入面 (2026-10-03) --------------------------------------
    # 为什么要开这几个口子: 黑盒测试 (tools/h3_legtest, Go) 必须能把腿指向**本地源站**,
    # 并**缩短预算**才能在秒级内验证"静默不等于流结束""首头超时""中途掐断"这些语义。
    # 它们只影响 CLI 启动方式, 默认值与生产逐字一致 —— 应用内的启动路径不经过这里。
    ap.add_argument("--target-port", type=int, default=443,
                    help="上游 HTTP/3 端口 (默认 443; 测试用: 指向本地源站)")
    ap.add_argument("--resolve", action="append", default=[], metavar="HOST=IP[,IP...]",
                    help="静态解析覆盖 (可重复; 测试用: 把节点名指到本地源站)。"
                         "未命中的名字仍走生产解析链 (别名域 → DoH → 投毒过滤 → Google 段 strict)")
    ap.add_argument("--connect", type=float, default=None, help="握手预算秒 (默认 4)")
    ap.add_argument("--first-byte", type=float, default=None, help="首头预算秒 (默认 8)")
    ap.add_argument("--idle-read", type=float, default=None, help="逐读静默预算秒 (默认 300)")
    args = ap.parse_args(argv)

    static: Dict[str, List[str]] = {}
    for item in (args.resolve or []):
        if "=" not in item:
            continue
        _name, _ips = item.split("=", 1)
        static[_name.strip().lower().rstrip(".")] = [x.strip() for x in _ips.split(",") if x.strip()]

    def _resolver(host: str) -> List[str]:
        """命中 --resolve 就用静态答案, 否则回落到生产解析链"""
        key = str(host or "").strip().lower().rstrip(".")
        if key in static:
            return list(static[key])
        return default_resolver(host)

    proxy = H3UpstreamProxy(
        port=args.port, host=args.host,
        resolver=_resolver if static else None,
        target_port=args.target_port,
        timeout=float(args.connect) if args.connect else DEFAULT_CONNECT_TIMEOUT,
        first_byte=args.first_byte,
        idle_read=float(args.idle_read) if args.idle_read else DEFAULT_STREAM_IDLE_READ)
    ok, why = proxy.start()
    print(f"h3 上游腿: {'已启动' if ok else '启动失败'}  http://{args.host}:{args.port}  {why}")
    if ok and (static or args.target_port != 443):
        print(f"  注入面: 目标端口={args.target_port} 静态解析={static or '(无)'} "
              f"预算 connect={proxy.budget.connect:g}s first_byte={proxy.budget.first_byte:g}s "
              f"idle_read={proxy.budget.idle_read:g}s")
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
