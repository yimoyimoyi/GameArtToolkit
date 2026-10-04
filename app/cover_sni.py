# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 掩护 SNI 候选池 / 自动回归 / 降级链

## 为什么需要这个模块

方案 §5.1 把 `g.cn` 能否前置称为"整套方案里最脆的一环"(Google 2018 年曾关闭一批
域名前置), §6.4 要求把它做成**运行时状态**而不是一次性结论, §8 要求有一条**无人干预**
的降级链, §10 验收标准第 6 条要求"掩护 SNI 失效时能自动降级, 且 UI 状态可见"。

本模块就是这条链的实现: 候选池 → 逐候选实测 → 选第一个可用的 → 缓存为运行时状态 →
供 nginx 生成器 (降级) 与 UI (状态可见 / 显式失败) 读取。

## 候选池从哪来 (2026-10-01 实测, 不是猜的)

对 8 个国内云中转 IP 逐个做**四关验证**(§6.2): ① TCP → ② TLS → ③ 证书名覆盖真实 Host
→ ④ 真实 Host 请求 `/generate_204`。结果:

| 策略 | TLS | 证书名覆盖真实 Host | 链受系统信任 | HTTP |
|---|---|---|---|---|
| 真实域名 (ssl_sni_mode="host")      | 8/8 | **8/8** | **8/8** | 204 |
| g.cn / www.g.cn / google.cn / www.google.cn | 8/8 | 0/8 | 8/8 | 204 |
| gstatic.com / www.gstatic.com       | 8/8 | 0/8 | 8/8 | 204 |
| 空 SNI                              | 8/8 | 0/8 | **0/8** (`invalid2.invalid` 占位证书) | 204 |
| goo.gl                              | 7/8 | 7/8 | 7/8 | 204 |

两个必须记住的结论:

1. **中转节点是按 SNI 选证书的** —— 同一 IP 发不同 SNI 会拿到**不同**证书
   (发 g.cn 拿到 `*.google.cn` 那张, 发 www.google.com 拿到 `www.google.com` 那张,
   发空 SNI 拿到 `invalid2.invalid`)。所以"证书名覆盖真实 Host"这道门槛是真门槛,
   不是形同虚设 —— 它正是 §6.2 第 ③ 关。
2. **伪 SNI 是 `proxy_ssl_verify off` 的唯一原因**, 不是 Google 的固有属性:
   用真实域名当 SNI 时证书名 8/8 匹配、链 8/8 受信。因此当 Google 真的关掉域名前置时,
   `host` 策略是一条**可完整校验**的退路 —— 它排在候选池第一顺位之外的第二位, 正是为此。

## 为什么不把首选直接改成"真实域名"

伪 SNI 的价值是**不把真实域名明文写进 ClientHello**(客户端→中转节点这一段是明文 SNI),
按 §5.1 的抗封杀意图, 首选仍是掩护域。真实域名作为**退路**保留 —— 它不是"更安全的默认",
而是"掩护失效时唯一还能开证书校验的路"。

## 与既有 `VENDOR_COVER_SNI` 的关系

`service_profile.VENDOR_COVER_SNI` 是**静态单值**(画像里的 ssl_sni_mode 默认值);
本模块是它的**运行时超集**: 无新鲜探测结果时一律回落到画像配置值, 因此不改变既有行为,
只在探测明确说"首选已失效"时才降级。

## 为什么要从 vendor 泛化成 channel (2026-10-02, reddit 实测逼出来的)

本条通道最早只服务 Google, 状态键就是 `cdn_vendor`。把 reddit 也做成运行时状态时,
"照 google 的样子加一个 `fastly` 键"是**错的**, 实测与代码两侧都证实:

1. **`cdn_vendor=="fastly"` 的画像有 4 个**: `github_raw`(掩护域是 `objects.githubusercontent.com`)、
   `imgur`、`reddit`、`reddit_static`(DIRECT + 自身 SNI)。vendor 级状态会把
   github_raw/reddit_static 一起卷进来, 让它们的探测 SNI 被改成 `www.fastly.com`。
2. **登记 `VENDOR_CERT_SUFFIXES["fastly"]` 会让 `cdn_optimizer` 的证书硬门槛(704-718)
   淘汰整池** —— github_raw 的 `*.githubusercontent.com`、reddit_static 自身 SNI 的证书
   都不"属于 fastly 证书族"。那正是 service_profile 记录过的"测速总失败"同类事故。
3. **`PROBE_PATH="/search?q=test"` 是 Google 专用探活路径**: Fastly 通道上根路径本就
   403/404, 用它会让 `http_ok` 恒为 0 → 假 UNAVAILABLE + UI 假警报。

因此状态键改为 **channel**(本模块 `CHANNELS`), 每个 channel 自带 **真实 Host / 探活路径 /
可放行状态码 / 证书期望 / 节点池来源 / 通过判据**; `cdn_vendor` 退回纯元数据。
画像**显式声明**自己走哪条 channel(`ServiceProfile.cover_sni_channel`), 没声明的画像
行为与改造前完全一致 (拿静态 `ssl_sni_mode`) —— github_raw / reddit_static 因此不受影响。

### Fastly 与 Google 的关键行为差异 (2026-10-02 实测, 决定了证书期望怎么写)

对 6 个 Fastly 段 IP × 9 个 SNI 实测 (`scripts/probe_fastly_cover_pool.py`):

| 观测 | Google 中转 | Fastly 共享 IP |
|---|---|---|
| 证书由什么决定 | **按 SNI 选证书**(发 `g.cn` 拿 `*.google.cn`) | **按 IP 决定**(`199.232.161.140` 发任何 SNI 都回 `*.reddit.com`; `199.232.19x/146.75.x` 一律回 `*.imgur.com`) |
| 掩护 SNI 下证书名覆盖真实 Host | 否 (0/8) | 否 —— 但证书**属于真实目标的域族**, 因为 IP 就是该客户的边缘 |
| 空 SNI | 占位证书 `invalid2.invalid` (链必不受信) | 仍回该 IP 客户的真证书(实测 `*.reddit.com`) —— 空 SNI 在 Fastly 上**不是**占位证书 |
| 被 RST 的 SNI | 真实域名 (Google 关闭了域名前置) | **按域名**: `www.reddit.com` / `www.redditstatic.com` / `www.imgur.com` 一律 RST; `www.fastly.com` / `fastly.com` / `developer.fastly.com` / `docs.fastly.com` / `status.fastly.com` 可握手 |

⇒ Fastly 通道的证书门槛**不能**是"厂商自有证书族"(google 那套), 而必须是
**"证书落在本 channel 目标的域族内"**: 发 `www.fastly.com` 拿到 `*.reddit.com` 才算"这条路
真的打到了 reddit 的边缘"; 若在 imgur 的 IP 上拿回 `*.imgur.com`, 说明该组合**跨租户错配**,
必须淘汰 (实测: 把 reddit 的 Host 打到 imgur 专属 IP 上就是这种情形)。

### 这条通道是**分钟级时变**的 (同一组合 40 分钟内实测 200 → 504 → 502 → TLS 超时 → RST)

所以 `any_node` 判据(`pass_rule`)、按命中率而非单次成败下结论、以及 UI 显式可见
三者缺一不可 —— 单次采样只能得到"某时刻的快照"。
"""

import json
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

try:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover - 项目 cert_manager 已强依赖 cryptography
    _HAS_CRYPTO = False

# ---------------------------------------------------------------------------
# 策略常量
# ---------------------------------------------------------------------------
STRATEGY_HOST = "host"      # SNI = 真实请求域名 (映射到 ssl_sni_mode="host")
STRATEGY_EMPTY = "empty"    # 不发 SNI        (映射到 ssl_sni_mode="empty")

# 降级链层级 (对应方案 §8 的表格)
LEVEL_HOST = "L7_HOST"          # 层 2 变体: L7 + 真实 SNI (可开证书校验)
LEVEL_COVER = "L7_COVER"        # 层 2: L7 + 伪 SNI (掩护)
LEVEL_EMPTY = "L7_EMPTY"        # 层 3: L7 + 空 SNI
LEVEL_UNAVAILABLE = "UNAVAILABLE"   # 层 —: 显式不可用 (UI 必须可见)

LEVEL_LABELS = {
    LEVEL_HOST: "L7 + 真实 SNI",
    LEVEL_COVER: "L7 + 掩护 SNI",
    LEVEL_EMPTY: "L7 + 空 SNI",
    LEVEL_UNAVAILABLE: "不可用",
}

# 厂商自有证书族后缀 —— §6.2 第 ③ 关「这个节点是不是真的该厂商边缘」的判据。
#
# 为什么不能拿"证书名是否覆盖真实 Host"当掩护策略的门槛:
#   掩护 SNI 的定义就是"证书名**必然不覆盖**真实 Host"(否则不需要掩护), 拿它当门槛
#   等于把全部掩护策略判死 —— 这正是本模块第一版犯的错 (实测输出: g.cn 名字匹配 0/8
#   => 被淘汰 => 错误地降级到真实 SNI)。
# 为什么不能只看"握手没报错":
#   发空 SNI 时对端回的是**占位证书** `invalid2.invalid`, 握手照样成功。
# 正确判据 = 「对端证书的 SAN 里至少有一条落在**该厂商自己的证书族**内」:
#   - g.cn 那张: `*.google.cn` / `google.cn` / `*.googleapis.cn` / `*.gstatic.cn` ... => 命中 google.cn ✓
#   - 空 SNI   : 只有 `invalid2.invalid`                                      => 不命中 ✓(判失败)
#   - 打错服务器: 证书是别人家的                                                 => 不命中 ✓
# 这比"证书名覆盖真实 Host"更贴近 §6.2 的原话 (「证书 SAN 是否为 *.google.cn」)。
#
# 厂商"品牌标签": SAN 中**任一标签**等于该标签即认定属于该厂商证书族。
# 为什么需要它 (2026-10-02): Google 的国家域名证书是 *.google.com.sg / *.google.co.jp
# 这类形式, 它们**不以任何固定后缀结尾** (后缀有 130+ 种), 枚举后缀覆盖不了 ——
# 实测把 `www.google.com.sg` 交给只认 "google.com" 后缀的表会判失败, 从而误杀真实节点。
# 判据取"标签相等"而非"子串包含": `notgoogle.com` 的标签是 ["notgoogle","com"], 不含
# "google"; 而 `google.com.sg` / `www.google.com` / `google.co.jp` 都含 "google"。
# 已知残余风险: 形如 `google.evil.com` 的证书也会被接受 —— 但那种 SAN 不会出现在
# Google 的中转边缘上, 而该门槛的职责是挡掉占位证书/Bandaid 类错误 vhost,
# 不是做完整的所有权证明。
VENDOR_BRAND_LABELS: Dict[str, Tuple[str, ...]] = {
    "google": ("google",),
}

# 只登记**已实测过**的厂商; 未登记厂商退回"非占位证书 + 链受信"这两条弱门槛 (见 gate_ok)。
VENDOR_CERT_SUFFIXES: Dict[str, Tuple[str, ...]] = {
    "google": (
        "google.cn", "googleapis.cn", "gstatic.cn", "googlecnapps.cn",
        "googleapps-cn.com", "gkecnapps.cn", "googledownloads.cn",
        "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
        "youtube.com", "ytimg.com", "ggpht.com", "googlevideo.com",
        "android.com", "withgoogle.com", "appspot.com", "bdn.dev", "goo.gl",
    ),
}

# 候选池: vendor -> 有序策略元组。**只登记实测过的候选** —— 没有证据的候选宁可不放,
# 否则"自动降级"会降到一个没人验证过的策略上, 比不降级更糟。
COVER_POOLS: Dict[str, Tuple[str, ...]] = {
    "google": (
        "g.cn",             # 当前首选 (画像 ssl_sni_mode 用的就是它), 8/8 四关全过
        "www.g.cn",         # 同一张证书 (*.google.cn + google.cn), 冗余用
        "google.cn",
        "www.google.cn",
        "gstatic.com",      # 换一张 Google 自有证书, 抗"整域名单点被墙"
        "www.gstatic.com",
        STRATEGY_HOST,      # 真实域名: 8/8 名字匹配 + 8/8 链受信, 可开 proxy_ssl_verify
        STRATEGY_EMPTY,     # 最后手段: 证书必为 invalid2.invalid, 只能牺牲上游校验
    ),
}

# 探测结果缓存时长 (秒)。掩护 SNI 的有效性是分钟级时变的 (§6.4), 但也没必要每次渲染
# nginx 配置都重探一遍; 5 分钟是本项目其它健康检查同一量级。
STATE_TTL_SECONDS = 300.0

PROBE_TIMEOUT = 4.0

# 探活路径必须是**对 Host 敏感**的 —— 这一点是用对照实验定下来的 (2026-10-02):
#   原先用 `/generate_204` (Google 的通用探活端点), 但对照显示它对 Host 完全不敏感:
#   `www.baidu.com` / `www.google.com.zz`(不存在的 TLD) / 随机标签 **全部同样回 204**。
#   于是"真实 Host 探活通过"这条判据形同虚设 —— 任何策略、任何域名都会通过。
#   改用 `/search?q=test`: 真实 Google web vhost 回 200/301(->www.google.com) 且带
#   `server: gws`; 不存在的域名回 **404** 且无 server 头。对照 5/5 负样本被正确判否。
#   该结论同时更正了画像注释里"用 /generate_204 判真伪"的旧说法。
PROBE_PATH = "/search?q=test"
OK_STATUSES = {200, 204, 301, 302, 303, 307, 308}

# Fastly 通道的掩护候选 —— **每一个都有实测证据** (2026-10-03, 三窗口 × 6 节点 × 11 域 = 198 条 HTTP 实测,
# scripts/probe_fastly_cover_pool.py --http-only-tls-ok, 见 docs/archive/reddit-cover-sni-channel.md §2.5):
#
#   掩护域 @ 节点                窗口1/2/3 可用域数        结论
#   www.fastly.com @199.232.161.140   11/11, 11/11, 11/11  ★ 首选: 三窗口全绿, 状态与画像记载逐字一致
#   fastly.com     @199.232.161.140   11/11, 11/11, 11/11  ★ 备选: 同上 (同一 IP、同一证书)
#   developer.fastly.com @199.232.161.140  8/11, 4/11, 0/11  △ 弱候选 (窗口1 可用, 后两窗口退化) —— 保留但排在末位
#   docs.fastly.com @ 任意            0/11, 0/11, 0/11      ✗ 已移除: 能握手但 HTTP 一律 504
#   status.fastly.com @ 任意          0/11, 0/11, 0/11      ✗ 已移除: 同上
#   empty (不发 SNI) @ 任意           0/11, 0/11, 0/11      ✗ 已移除: 能握手但 HTTP 一律 504
#   www.redditstatic.com / www.reddit.com 作 SNI  一律 RST/0  ✗ 自身域不可作掩护
#
# ⚠ 被移除的三个候选为什么**不能**留在池里: 它们都能完成 TLS 握手 (掩护照"握手成功"判会全部放行),
#   但真实 Host 的 HTTP 一律超时。留在池里只会让降级链在失败窗口里多花两轮探测 (每轮 ~2s)
#   才落到 UNAVAILABLE —— 与本项目"宁可尽快如实报错"的口径相反。
#   注: `empty` 因此不再出现在本通道的池里, 配置开关 cover_sni_allow_empty 对本通道成为空操作
#   (它仍然作用于 Google 池 —— 那里的空 SNI 是"占位证书"那一级)。
#
# 为什么要显式写出 (掩护域, 节点) 的配对证据: 池是按**掩护域**排序的, 而实测里同一个掩护域
# 在不同节点上结论相反 (www.fastly.com 在 .161 上 11/11, 在 .113 上 0/11 全 502) ——
# 可用组合是"配对"属性。节点侧由画像的 candidate_ips 提供, 因此改动节点池时必须回头看这张表。
FASTLY_COVER_POOL: Tuple[str, ...] = (
    "www.fastly.com",
    "fastly.com",
    "developer.fastly.com",
    STRATEGY_HOST,      # 真实域名: reddit 主域实测一律 RST, 但这是**唯一可完整校验**的退路
)


@dataclass(frozen=True)
class ChannelSpec:
    """一条掩护 SNI 通道的完整声明 (状态键 = name)

    为什么要显式声明而不是从 `cdn_vendor` 推: 见模块头部"为什么要从 vendor 泛化成
    channel" —— 同一个 vendor 下既有"必须走掩护"的画像, 也有"只钉 IP、走自身 SNI"的画像,
    凭 vendor 猜必然把它们卷到一起。
    """
    name: str
    pool: Tuple[str, ...]
    host: str                                  # 探活用的真实 Host (必须是该通道的**主域**)
    path: str = PROBE_PATH
    ok_statuses: Tuple[int, ...] = tuple(sorted(OK_STATUSES))
    # 证书期望:
    #   cert_vendor   非空 -> 掩护照 old 判据 (证书须属该厂商自有证书族; google 用)
    #   cert_families 非空 -> 证书须落在这些**域族**内 (Fastly 用: 按 IP 选证书, 证书属于目标)
    cert_vendor: str = ""
    cert_families: Tuple[str, ...] = ()
    # 节点池来源画像 (取它的 candidate_ips; 单一真源, 不在这里另抄一份 IP)
    ip_source: str = ""
    # 通过判据:
    #   "all_nodes" = 整池节点全部过证书门槛 (google 的既有语义, 逐字保留)
    #   "any_node"  = 至少一个节点过全部四关 (Fastly 用: 候选池里本就存在长期不通的节点,
    #                 要求整池全绿等于永远判不可用 —— 实测 199.232.113.140 在首个窗口起
    #                 40 分钟内始终 RST/502 (末次回归才 2/2 通过, 见 docs/archive/reddit-cover-sni-channel.md))
    pass_rule: str = "all_nodes"
    # 该通道是否属"跨租户掩护"(证书按 IP 而非 SNI 选) —— 仅用于 UI 文案/诊断
    cross_tenant: bool = False


# 已登记的通道。**只放实测过的**。
CHANNELS: Dict[str, ChannelSpec] = {
    "google": ChannelSpec(
        name="google",
        pool=COVER_POOLS["google"],
        host="www.google.com",
        path="/search?q=test",
        cert_vendor="google",
        ip_source="google_web",
        pass_rule="all_nodes",
    ),
    "reddit": ChannelSpec(
        name="reddit",
        pool=FASTLY_COVER_POOL,
        host="www.reddit.com",
        # 根路径对 www.reddit.com 实测 200; 媒体域根路径 403/404 属"Fastly 已服务该域"。
        # 因此放行 <500 的全部状态码 —— 与 reddit 画像的 probe_ok_statuses 同口径。
        path="/",
        ok_statuses=(200, 204, 301, 302, 303, 307, 308, 403, 404),
        cert_families=("reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"),
        ip_source="reddit",
        pass_rule="any_node",
        cross_tenant=True,
    ),
}


_lock = threading.RLock()
_states: Dict[str, "VendorState"] = {}


# ---------------------------------------------------------------------------
# 证书工具
# ---------------------------------------------------------------------------
def cert_sans(der: bytes) -> List[str]:
    """从对端证书 DER 读 SAN 列表"""
    if not der or not _HAS_CRYPTO:
        return []
    try:
        cert = x509.load_der_x509_certificate(der)
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return [str(s) for s in ext.value.get_values_for_type(x509.DNSName)]
    except Exception:
        return []


def name_covered(sans: List[str], host: str) -> bool:
    """证书 SAN 是否覆盖 host (含 RFC 6125 单级通配)。

    这是 §6.2 第 ③ 关的判据 —— 等价于 nginx 的 `proxy_ssl_name $host` 校验语义,
    而不是"握手没报错就算过"。
    """
    if not host:
        return False
    host = host.lower().lstrip(".")
    for s in sans:
        s = str(s).lower()
        if s == host:
            return True
        if s.startswith("*."):
            rest = s[2:]
            if host.endswith("." + rest) and host.count(".") == rest.count(".") + 1:
                return True
    return False


def sni_mode_for(strategy: str) -> str:
    """策略 -> 画像 ssl_sni_mode 取值 (供 nginx_generator 直接使用)"""
    return strategy if strategy in (STRATEGY_HOST, STRATEGY_EMPTY) else str(strategy)


def cert_belongs_to_vendor(sans: List[str], vendor: str) -> Optional[bool]:
    """对端证书是否属于该厂商自有证书族 (§6.2 第 ③ 关)

    返回 None 表示该厂商未登记证书族 => 该关不适用 (调用方改用弱门槛)。
    命中条件: SAN 落在已登记后缀内, **或** SAN 的任一标签等于该厂商品牌标签
    (后者用于覆盖 *.google.com.sg / *.google.co.jp 这类国家域名证书, 见上方注释)。
    """
    vendor = str(vendor or "").strip().lower()
    suffixes = VENDOR_CERT_SUFFIXES.get(vendor)
    labels = VENDOR_BRAND_LABELS.get(vendor, ())
    if not suffixes or not sans:
        return None
    for s in sans:
        s = str(s).lower().lstrip("*.")
        for suf in suffixes:
            if s == suf or s.endswith("." + suf):
                return True
        if labels and any(part in labels for part in s.split(".")):
            return True
    return False


def cert_matches_family(sans: List[str], families: Tuple[str, ...]) -> Optional[bool]:
    """对端证书是否落在给定**域族**内 (Fastly 通道的证书判据)

    为什么 Fastly 不能用 `cert_belongs_to_vendor`: 实测该厂商的共享 IP **按 IP 决定证书**,
    掩护 SNI 取什么都不改变拿到的证书 —— 证书是**目标客户自己的**(在 reddit 的边缘 IP 上
    拿 `*.reddit.com`, 在 imgur 的 IP 上拿 `*.imgur.com`)。于是正确的门槛是:

        "证书必须属于**本通道目标的域族**" —— 即"这条路真的打到了目标的边缘";

    它同时挡住了跨租户错配: 把 reddit 的 Host 打到 imgur 专属 IP 上会拿回 `*.imgur.com`,
    此时 `families=("reddit.com", ...)` 判否 —— 这正是必须淘汰的组合。

    返回 None 表示未声明域族 => 该关不适用 (调用方退回弱门槛)。
    """
    if not families or not sans:
        return None
    for s in sans:
        if _cert_family(s) in families:
            return True
    return False


def _cert_family(san: str) -> str:
    """SAN -> 域族 (末两段标签): `*.reddit.com` -> reddit.com; `a.b.redd.it` -> redd.it"""
    s = str(san or "").lower().lstrip("*.").strip(".")
    parts = [p for p in s.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else s


def _placeholder_only(sans: List[str]) -> bool:
    """是否只有占位证书 (invalid2.invalid) —— 即"根本没落到真边缘"的确定性特征"""
    if not sans:
        return True
    return all("invalid" in str(s).lower() for s in sans)


def level_for(strategy: str) -> str:
    """策略 -> 降级链层级

    注意: 空策略 (strategy="") 表示"候选池内全部失败" —— 必须是 UNAVAILABLE。
    曾把空串落进 cover 分支, 于是 `available` 恒为真, UI 会把"全挂"显示成正常运行;
    本项目的红线是"宁可报错也不静默假可用", 故此处显式判空。
    """
    if not strategy:
        return LEVEL_UNAVAILABLE
    if strategy == STRATEGY_HOST:
        return LEVEL_HOST
    if strategy == STRATEGY_EMPTY:
        return LEVEL_EMPTY
    return LEVEL_COVER


def pool_for(vendor: str, allow_empty: Optional[bool] = None) -> Tuple[str, ...]:
    """取该厂商的候选池; 未登记厂商返回空元组 (调用方应回落到静态配置, 不做降级)

    allow_empty 由配置项 cover_sni_allow_empty 驱动 (见 config_store): 关掉它就从池里
    摘掉最后一级"空 SNI", 于是"掩护域 + 真实域名全失效"会直接落到 UNAVAILABLE —— 这是
    刻意的取舍: 空 SNI 下上游证书必为占位证书, 宁可显式报不可用, 也不静默降级。
    """
    pool = COVER_POOLS.get(str(vendor or "").strip().lower(), ())
    if not pool:
        return ()
    if allow_empty is None:
        allow_empty = allow_empty_from_config()
    if allow_empty:
        return pool
    return tuple(s for s in pool if s != STRATEGY_EMPTY)


def _config_flag(key: str, default: bool) -> bool:
    """读配置开关 (惰性导入, 避免模块级循环依赖; 任何异常都退回默认值)"""
    try:
        from config_store import load_config
        v = load_config().get(key, default)
        return bool(default if v is None else v)
    except Exception:
        return default


def allow_empty_from_config() -> bool:
    return _config_flag("cover_sni_allow_empty", True)


def auto_regress_enabled() -> bool:
    """是否启用掩护 SNI 自动回归 + 自动降级 (关闭时一律沿用画像写死的 SNI)"""
    return _config_flag("cover_sni_auto_regress", True)


# ---------------------------------------------------------------------------
# 单节点 / 单策略探测
# ---------------------------------------------------------------------------
def probe_node(ip: str, strategy: str, host: str, vendor: str = "",
               timeout: float = PROBE_TIMEOUT, path: Optional[str] = None,
               ok_statuses: Optional[Sequence[int]] = None,
               cert_families: Tuple[str, ...] = ()) -> Dict:
    """对单个中转节点验证一个 SNI 策略的四关

    strategy="host" 时 SNI 用 host 本身; "empty" 时不发 SNI; 其余按字面量当掩护域。
    两个证书判据要分清 (这是本模块最容易写错的地方):
      host_covered —— 证书名是否覆盖**真实 Host**。掩护策略上它**必然为假**, 只用于判断
                      "这个策略能否开 upstream 证书校验", **不能**当淘汰门槛。
      gate_ok      —— §6.2 第 ③ 关: 证书是否**说明这条路真的打到了目标的边缘**。
                      三种口径 (按优先级):
                        · cert_families 非空 -> 证书须落在该通道目标的域族内 (Fastly:
                          按 IP 选证书, 证书是目标客户自己的)
                        · 否则 vendor 已登记证书族 -> 须属该厂商自有证书族 (Google)
                        · 否则 -> 弱门槛: 至少不能是占位证书
                      host 策略用 host_covered; 空 SNI 记 None (该关不适用)。
    path / ok_statuses / cert_families 由 channel 传入; 不传时退回本模块的 Google 默认值,
    因此既有调用方与测试的行为逐字不变。
    """
    path = path or PROBE_PATH
    ok_set = set(ok_statuses) if ok_statuses else set(OK_STATUSES)
    out = {"ip": ip, "strategy": strategy, "tcp_ok": False, "tls_ok": False,
           "sans": [], "host_covered": None, "gate_ok": None, "chain_ok": False,
           "status": None, "http_ok": False, "error": ""}
    if strategy == STRATEGY_HOST:
        sni: Optional[str] = host
    elif strategy == STRATEGY_EMPTY:
        sni = None
    else:
        sni = strategy

    sock = ssock = None
    try:
        sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 443))
        out["tcp_ok"] = True

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
        ssock = ctx.wrap_socket(sock, server_hostname=sni)
        sock = None
        out["tls_ok"] = True

        der = ssock.getpeercert(binary_form=True)
        out["sans"] = cert_sans(der)
        out["host_covered"] = name_covered(out["sans"], host)
        if strategy == STRATEGY_EMPTY:
            out["gate_ok"] = None
        elif strategy == STRATEGY_HOST:
            out["gate_ok"] = out["host_covered"]
        else:
            belongs = cert_matches_family(out["sans"], cert_families)
            if belongs is None:
                belongs = cert_belongs_to_vendor(out["sans"], vendor)
            if belongs is None:
                # 既未声明域族、厂商也未登记证书族 => 退回弱门槛: 至少不能是占位证书
                belongs = not _placeholder_only(out["sans"])
            out["gate_ok"] = bool(belongs)

        ssock.settimeout(timeout)
        ssock.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                       f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) GameArtToolkit/2.0\r\n"
                       f"Connection: close\r\n\r\n").encode())
        hdr = b""
        while b"\r\n\r\n" not in hdr:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            hdr += chunk
        line = hdr.split(b"\r\n", 1)[0].decode("utf-8", "replace")
        if line.startswith("HTTP/") and len(line.split()) >= 2 and line.split()[1].isdigit():
            out["status"] = int(line.split()[1])
            out["http_ok"] = out["status"] in ok_set
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    finally:
        for s in (ssock, sock):
            try:
                if s:
                    s.close()
            except Exception:
                pass

    # 链可信度: 独立连接, 用系统信任库校链 (与名字无关)。
    # 空 SNI 必失败 (invalid2.invalid), 这正是"空 SNI 只能作为最后手段"的量化依据。
    sock = ssock = None
    try:
        sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 443))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
        ssock = ctx.wrap_socket(sock, server_hostname=sni)
        sock = None
        out["chain_ok"] = True
    except Exception:
        out["chain_ok"] = False
    finally:
        for s in (ssock, sock):
            try:
                if s:
                    s.close()
            except Exception:
                pass
    return out


@dataclass
class StrategyResult:
    """一个 SNI 策略在整池节点上的汇总"""
    strategy: str
    total: int = 0
    tls_ok: int = 0
    gate_ok: int = 0
    chain_ok: int = 0
    http_ok: int = 0
    host_covered: int = 0
    nodes: List[Dict] = field(default_factory=list)
    # 通过判据 (由 channel 决定): "all_nodes"(默认, Google 语义) / "any_node"(Fastly)
    pass_rule: str = "all_nodes"
    # 证书期望的域族 (Fastly 通道; 仅用于自陈, 判定已在 probe_node 完成)
    cert_families: Tuple[str, ...] = ()

    @property
    def level(self) -> str:
        return level_for(self.strategy)

    @property
    def passed(self) -> bool:
        """是否可用作当前通道

        判据 (宁可判失败也不假可用):
        - 至少一个节点 TCP+TLS 成功;
        - 非空 SNI 策略: 证书门槛是硬门槛, 不降权 —— 但**按节点粒度**:
            · pass_rule="all_nodes"(Google 既有语义): 整池节点**全部**通过该门槛
              (§6.2 第 ③ 关; 逐字保留, 不改既有行为);
            · pass_rule="any_node"(Fastly): **至少一个节点**同时通过"证书门槛 + 真实 Host
              探活"。为什么必须放松: Fastly 候选池里本就存在长期不通的节点
              (实测 199.232.113.140 在首个窗口起 40 分钟内始终 RST/502, 末次回归才通过),
              要求整池全绿等于"**任一节点抖动就判整条通道不可用**" ——
              而"不可用"会让生成器回落到画像静态值 (仍是同一个掩护域), 白白丢掉可用性。
              放松的是**节点集合**, 不是判据强度: 该节点仍然四关全过才算数。
        - 真实 Host 的 HTTP 探活: all_nodes 要求过半节点; any_node 与证书门槛同一节点上判定。
        空 SNI 不适用证书门槛 (Google 上是占位证书), 只要求 HTTP 过半。
        """
        if self.tls_ok == 0:
            return False
        if self.strategy == STRATEGY_EMPTY:
            return self.http_ok >= max(1, (self.total + 1) // 2)
        if self.pass_rule == "any_node":
            return any(n.get("tls_ok") and n.get("gate_ok") is True and n.get("http_ok")
                       for n in self.nodes)
        if self.gate_ok < self.tls_ok:
            return False
        return self.http_ok >= max(1, (self.total + 1) // 2)

    @property
    def passing_ips(self) -> List[str]:
        """同时通过证书门槛与真实 Host 探活的节点 (Fastly 通道的"可用组合"自陈)

        它就是"掩护域 + 节点 IP"这对组合里真正可用的那一半 —— 实测同一个掩护域在不同
        节点上结论相反 (www.fastly.com 在 .161 上通、在 .113 上 RST), 所以必须能报出
        "是哪个节点通的", 而不是只给一个布尔。
        """
        if self.strategy == STRATEGY_EMPTY:
            return [n["ip"] for n in self.nodes if n.get("tls_ok") and n.get("http_ok")]
        return [n["ip"] for n in self.nodes
                if n.get("tls_ok") and n.get("gate_ok") is True and n.get("http_ok")]

    @property
    def verify_possible(self) -> bool:
        """该策略下上游证书名是否覆盖真实 Host => 能否开 proxy_ssl_verify"""
        return self.tls_ok > 0 and self.host_covered >= self.tls_ok

    def as_dict(self) -> Dict:
        return {"strategy": self.strategy, "level": self.level, "passed": self.passed,
                "total": self.total, "tls_ok": self.tls_ok, "gate_ok": self.gate_ok,
                "chain_ok": self.chain_ok, "http_ok": self.http_ok,
                "host_covered": self.host_covered, "verify_possible": self.verify_possible,
                "pass_rule": self.pass_rule, "passing_ips": self.passing_ips}


@dataclass
class VendorState:
    """某条通道当前生效的 SNI 策略与降级层级 (字段名保留 vendor 以兼容既有调用方)"""
    vendor: str
    host: str
    strategy: str
    results: List[StrategyResult] = field(default_factory=list)
    checked_at: float = 0.0
    from_cache: bool = False
    notes: str = ""
    # 通道名 (= vendor, 对 fastly 类通道才是真正的抽象单位); 新增字段带默认值以兼容既有构造
    channel: str = ""

    @property
    def level(self) -> str:
        return level_for(self.strategy)

    @property
    def level_label(self) -> str:
        return LEVEL_LABELS.get(self.level, self.level)

    @property
    def available(self) -> bool:
        return self.level != LEVEL_UNAVAILABLE

    @property
    def sni_mode(self) -> str:
        """供 nginx_generator 使用的 ssl_sni_mode 取值"""
        return sni_mode_for(self.strategy)

    @property
    def upstream_verify_possible(self) -> bool:
        """该策略下上游证书名是否匹配真实 Host (决定能否开 proxy_ssl_verify)"""
        for r in self.results:
            if r.strategy == self.strategy:
                return r.verify_possible
        return False

    def age(self) -> float:
        return max(0.0, time.time() - self.checked_at)

    def summary(self) -> str:
        if not self.available:
            tried = ", ".join(r.strategy for r in self.results) or "(无)"
            return f"{self.vendor}: 全部候选失效 -> 不可用 (已试: {tried})"
        cur = next((r for r in self.results if r.strategy == self.strategy), None)
        detail = f"{cur.tls_ok}/{cur.total} 节点 TLS 通过" if cur else ""
        if cur is not None and cur.passing_ips:
            detail += f", 可用节点 {','.join(cur.passing_ips)}"
        return (f"{self.vendor}: {self.level_label} (策略={self.strategy}) {detail}")

    def as_dict(self) -> Dict:
        return {"vendor": self.vendor, "channel": self.channel or self.vendor,
                "host": self.host, "strategy": self.strategy,
                "level": self.level, "level_label": self.level_label,
                "available": self.available, "sni_mode": self.sni_mode,
                "verify_possible": self.upstream_verify_possible,
                "checked_at": self.checked_at, "age_seconds": round(self.age(), 1),
                "summary": self.summary(), "notes": self.notes,
                "results": [r.as_dict() for r in self.results]}


# ---------------------------------------------------------------------------
# 通道解析 (channel <=> 画像)
# ---------------------------------------------------------------------------
def _profiles() -> List:
    """取画像列表 (惰性导入; 任何异常都返回空 —— 本模块不得因画像问题阻断生成)"""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from service_profile import PROFILES
        return list(PROFILES)
    except Exception:
        return []


def spec_for(key: str) -> Optional[ChannelSpec]:
    """按通道名 (或与通道同名的 vendor) 解析通道声明; 未登记返回 None"""
    k = str(key or "").strip()
    if k in CHANNELS:
        return CHANNELS[k]
    for spec in CHANNELS.values():
        if spec.name.lower() == k.lower():
            return spec
    return None


def channel_for_profile(profile) -> Optional[ChannelSpec]:
    """画像 -> 通道声明 (未声明的画像返回 None => 行为与改造前完全一致)

    两种命中方式:
      ① 画像**显式声明** `cover_sni_channel` (reddit 用这条);
      ② 兼容旧路径: 画像的 `cdn_vendor` 本身就是一个通道名、且该通道的证书判据也是
         按 vendor 写的 (google 用这条) —— 保证既有 Google 行为逐字不变。

    为什么不直接"vendor 有池就进通道": `cdn_vendor=="fastly"` 的画像有 4 个, 其中
    github_raw(掩护域 objects.githubusercontent.com) 与 reddit_static(DIRECT+自身 SNI)
    根本不走这条通道, 被卷进来会让它们的探测 SNI 被改写成 www.fastly.com (实测过的错配)。
    """
    name = getattr(profile, "cover_sni_channel", "") or ""
    if isinstance(name, str) and name.strip() in CHANNELS:
        return CHANNELS[name.strip()]
    vendor = str(getattr(profile, "cdn_vendor", "") or "").strip().lower()
    spec = CHANNELS.get(vendor)
    if spec is not None and spec.cert_vendor == vendor:
        return spec
    return None


def channel_probe_ips(channel: str) -> List[str]:
    """通道的候选节点池 (取自通道声明的画像 candidate_ips —— 单一真源, 不另抄一份 IP)"""
    spec = spec_for(channel)
    if spec is None or not spec.ip_source:
        return []
    prof = next((p for p in _profiles() if getattr(p, "id", "") == spec.ip_source), None)
    return list(getattr(prof, "candidate_ips", []) or []) if prof else []


def channel_host(channel: str) -> str:
    spec = spec_for(channel)
    return spec.host if spec is not None else ""


def channel_profile_ids(channel: str) -> List[str]:
    """该通道覆盖哪些画像 (UI 用它决定"要不要建状态卡")"""
    spec = spec_for(channel)
    if spec is None:
        return []
    return [p.id for p in _profiles() if channel_for_profile(p) is spec]


def pool_for_channel(channel: str, allow_empty: Optional[bool] = None) -> Tuple[str, ...]:
    spec = spec_for(channel)
    if spec is None:
        return ()
    return _filter_empty(spec.pool, allow_empty)


def _filter_empty(pool: Tuple[str, ...], allow_empty: Optional[bool] = None) -> Tuple[str, ...]:
    if not pool:
        return ()
    if allow_empty is None:
        allow_empty = allow_empty_from_config()
    if allow_empty:
        return tuple(pool)
    return tuple(s for s in pool if s != STRATEGY_EMPTY)


def _probe_call(spec: ChannelSpec, ip: str, strategy: str, host: str, timeout: float) -> Dict:
    """发起一次节点探测 —— **只在该通道与默认口径不同时**才追加关键字参数

    为什么要这么写: 既有测试把 `probe_node` 换成了 5 参数的位置签名 (fake(ip, strategy,
    host, vendor, timeout)); 无条件追加 path/ok_statuses/cert_families 会让它们 TypeError。
    Google 通道与默认口径完全一致, 因此它的调用形态与改造前逐字相同。
    """
    extra: Dict = {}
    if spec.path != PROBE_PATH:
        extra["path"] = spec.path
    if tuple(sorted(spec.ok_statuses)) != tuple(sorted(OK_STATUSES)):
        extra["ok_statuses"] = spec.ok_statuses
    if spec.cert_families:
        extra["cert_families"] = spec.cert_families
    return probe_node(ip, strategy, host, spec.cert_vendor, timeout, **extra)


# ---------------------------------------------------------------------------
# 候选池评估
# ---------------------------------------------------------------------------
def evaluate(vendor: str, ips: List[str], host: str,
             timeout: float = PROBE_TIMEOUT,
             max_workers: int = 8,
             allow_empty: Optional[bool] = None) -> VendorState:
    """按候选池顺序逐个实测, 取**第一个通过**的策略; 全失败则标记不可用

    顺序即优先级: 首选掩护域 → 其它掩护域 → 真实 SNI → 空 SNI。
    每个策略都要整池节点过一遍才下结论 —— 只看单节点会把"个别节点抖动"误判成
    "策略失效", 这正是本项目在 steam_community 上踩过的坑 (单次探测假阴性)。

    `vendor` 既可以是通道名 (google / reddit), 也可以是同名 vendor (兼容旧调用方)。
    """
    spec = spec_for(vendor)
    if spec is None:
        return VendorState(vendor=vendor, host=host, strategy="", checked_at=time.time(),
                           notes="该厂商未登记候选池或候选池为空, 回落到静态配置")
    return evaluate_channel(spec.name, ips, host, timeout=timeout,
                            max_workers=max_workers, allow_empty=allow_empty)


def evaluate_channel(channel: str, ips: List[str], host: str = "",
                     timeout: float = PROBE_TIMEOUT,
                     max_workers: int = 8,
                     allow_empty: Optional[bool] = None) -> VendorState:
    """按通道实测 (host 省略时取通道自身的主域)"""
    spec = spec_for(channel)
    if spec is None:
        return VendorState(vendor=str(channel), host=host, strategy="",
                           checked_at=time.time(),
                           notes="该厂商未登记候选池或候选池为空, 回落到静态配置")
    host = host or spec.host
    ips = list(ips or [])

    pool = _filter_empty(spec.pool, allow_empty)
    if not pool or not ips:
        return VendorState(vendor=spec.name, channel=spec.name, host=host, strategy="",
                           checked_at=time.time(),
                           notes="该厂商未登记候选池或候选池为空, 回落到静态配置")

    from concurrent.futures import ThreadPoolExecutor

    results: List[StrategyResult] = []
    state = VendorState(vendor=spec.name, channel=spec.name, host=host, strategy="",
                        checked_at=time.time())
    for strategy in pool:
        jobs = [(ip, strategy, host, timeout) for ip in ips]
        with ThreadPoolExecutor(max_workers=min(max_workers, len(jobs))) as ex:
            nodes = list(ex.map(lambda a: _probe_call(spec, a[0], a[1], a[2], a[3]), jobs))
        sr = StrategyResult(strategy=strategy, total=len(nodes), nodes=nodes,
                            pass_rule=spec.pass_rule, cert_families=spec.cert_families)
        for n in nodes:
            sr.tls_ok += int(n["tls_ok"])
            sr.gate_ok += int(n["gate_ok"] is True)
            sr.chain_ok += int(n["chain_ok"])
            sr.http_ok += int(n["http_ok"])
            sr.host_covered += int(n["host_covered"] is True)
        results.append(sr)
        if sr.passed:
            state.strategy = strategy
            break

    state.results = results
    if not state.strategy:
        state.strategy = ""
        state.notes = "候选池内全部策略均未通过; 按方案 §8 该通道应显式标记不可用"
    else:
        failed = [r.strategy for r in results if not r.passed and r is not results[-1]]
        if failed:
            state.notes = f"已从 {'/'.join(failed)} 降级"
        passing = next((r.passing_ips for r in results if r.strategy == state.strategy), [])
        if passing:
            state.notes = (state.notes + "; " if state.notes else "") + \
                f"可用节点: {','.join(passing)}"
    return state


def refresh(vendor: str, ips: List[str], host: str, force: bool = False,
            timeout: float = PROBE_TIMEOUT,
            allow_empty: Optional[bool] = None) -> VendorState:
    """带 TTL 缓存的探测 (线程安全)

    状态键 = 通道名 (未登记时退回传入的键) —— 因此 get_state("google") / get_state("reddit")
    与 UI、生成器读到的是同一份状态。
    """
    spec = spec_for(vendor)
    key = spec.name if spec is not None else str(vendor)
    with _lock:
        cur = _states.get(key)
        if cur and not force and cur.age() < STATE_TTL_SECONDS:
            cur.from_cache = True
            return cur
    st = evaluate(vendor, ips, host, timeout=timeout, allow_empty=allow_empty)
    with _lock:
        _states[key] = st
    return st


def get_state(vendor: str) -> Optional[VendorState]:
    """只读取已有状态, 不触发探测 (UI/生成器用; 无状态时调用方应回落静态配置)"""
    spec = spec_for(vendor)
    with _lock:
        return _states.get(spec.name if spec is not None else str(vendor))


def all_states() -> Dict[str, VendorState]:
    with _lock:
        return dict(_states)


def clear_states() -> None:
    with _lock:
        _states.clear()


def effective_sni_mode(profile) -> Optional[str]:
    """给定画像, 返回**当前应使用**的 ssl_sni_mode

    设计原则: 没有新鲜探测结果时**一律回落到画像自身的配置值** —— 保证本模块纯粹是
    "运行时超集", 不会在没有证据的情况下改变任何既有行为 (测试也因此是确定性的)。
    配置项 cover_sni_auto_regress 关闭时同样直接返回画像值 (不自动降级)。

    通道解析见 `channel_for_profile`: 只有**显式声明**了通道、或 vendor 本身登记成通道
    (google) 的画像才会被接管; 其余画像 (github_raw / reddit_static / 一切非掩护画像)
    逐字返回静态值。
    """
    spec = channel_for_profile(profile)
    static = getattr(profile, "ssl_sni_mode", None)
    if spec is None or not _filter_empty(spec.pool):
        return static
    if not auto_regress_enabled():
        return static
    st = get_state(spec.name)
    if st is None or not st.available:
        # 不可用时不能返回空串(会被当成字面量 SNI), 交回调用方按自身策略处理
        return static
    return st.sni_mode


# ---------------------------------------------------------------------------
# 便捷入口: 通道状态 (UI / 启动回归用)
# ---------------------------------------------------------------------------
GOOGLE_VENDOR = "google"
GOOGLE_STATE_HOST = CHANNELS["google"].host


def google_probe_ips() -> List[str]:
    """从画像里取 Google 通道的候选节点池 (单一真源, 不在这里另抄一份 IP)"""
    return channel_probe_ips(GOOGLE_VENDOR)


def google_profile_ids() -> List[str]:
    return channel_profile_ids(GOOGLE_VENDOR)


def check_google_channel(force: bool = False) -> VendorState:
    """回归探针: 检查 Google 掩护 SNI 是否仍然有效, 失效时自动降级"""
    return check_channel(GOOGLE_VENDOR, force=force)


def check_channel(channel: str, force: bool = False) -> VendorState:
    """回归探针 (任意通道): 实测该通道的候选池, 失效时按池降级

    节点池与真实 Host 都由通道声明提供 —— 这是"每个通道用自己的 Host 验证"的落地:
    reddit 的 421 反例证明跨租户掩护是**逐域成立**的, 拿别的通道的 Host 测会得到假结论。
    """
    spec = spec_for(channel)
    if spec is None:
        return VendorState(vendor=str(channel), host="", strategy="",
                           checked_at=time.time(),
                           notes="该厂商未登记候选池或候选池为空, 回落到静态配置")
    return refresh(spec.name, channel_probe_ips(spec.name), spec.host, force=force)


def enabled_channels(service_ids) -> List[str]:
    """已启用服务真正会用到哪几条通道 (UI 建卡 / 启动回归用)"""
    ids = set(service_ids or ())
    return [name for name in CHANNELS if ids & set(channel_profile_ids(name))]


def check_enabled_channels(service_ids, force: bool = False) -> Dict[str, VendorState]:
    """对**已启用服务所涉及的**通道逐个回归 (启动流程用)

    为什么要按"已启用"过滤而不是无条件探全部: 每条通道都是一次真实网络探测
    (整池 × 候选数), 与用户实际开启的服务无关的通道没必要探。
    """
    ids = set(service_ids or ())
    out: Dict[str, VendorState] = {}
    for name in enabled_channels(ids):
        try:
            out[name] = check_channel(name, force=force)
        except Exception:
            continue
    return out


def channel_label(channel: str) -> str:
    """通道的中文名 (UI 文案用; 未登记通道退回原名)"""
    return CHANNEL_LABELS.get(str(channel), str(channel))


CHANNEL_LABELS: Dict[str, str] = {
    "google": "Google / YouTube",
    "reddit": "Reddit (Fastly)",
}


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    ap = argparse.ArgumentParser(description="掩护 SNI 候选池 / 自动回归 / 降级链")
    ap.add_argument("--check", action="store_true", help="立即跑一次回归探测")
    ap.add_argument("--vendor", "--channel", dest="vendor", default=GOOGLE_VENDOR,
                    help=f"通道 (默认 google; 已登记: {', '.join(CHANNELS)})")
    ap.add_argument("--host", default=None, help="真实 Host (默认取该通道声明的主域)")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--timeout", type=float, default=PROBE_TIMEOUT)
    args = ap.parse_args(argv)

    spec = spec_for(args.vendor)
    if spec is None:
        print(f"[{args.vendor}] 未登记的通道; 已登记: {', '.join(CHANNELS)}")
        return 2

    ips = channel_probe_ips(spec.name)
    host = args.host or spec.host
    if not ips:
        print(f"[{spec.name}] 找不到候选节点池, 无法探测")
        return 2

    st = evaluate(spec.name, ips, host, timeout=args.timeout)
    if args.json:
        print(json.dumps(st.as_dict(), ensure_ascii=False, indent=2))
    else:
        print(f"通道: {spec.name} ({channel_label(spec.name)})   真实 Host: {host}   "
              f"探活路径: {spec.path}   节点池: {len(ips)} 个\n")
        if spec.cert_families:
            print("证书门槛 = 对端证书必须落在本通道目标的域族内: "
                  f"{', '.join(spec.cert_families)}")
            print("           (Fastly 按 **IP** 决定证书: 掩护域取什么都不改变拿到的那张 —— "
                  "故判据是\"证书属于目标\"而不是\"证书属于厂商\")")
        else:
            print("证书门槛 = §6.2 第③关: 对端证书是否属于该厂商自有证书族 (空 SNI 不适用)")
        print("链可信   = 链是否受系统信任库认可; 名字匹配真实 Host 的只有 host 策略 (可开校验)")
        print(f"通过判据 = {spec.pass_rule} "
              f"({'整池节点全过' if spec.pass_rule == 'all_nodes' else '至少一个节点四关全过'})\n")
        print(f"{'策略':<18}{'层级':<16}{'TLS':>6}{'证书门槛':>10}{'链可信':>8}{'HTTP过':>8}  结论")
        print("-" * 92)
        for r in st.results:
            gate = "不适用" if r.strategy == STRATEGY_EMPTY else f"{r.gate_ok}/{r.total}"
            mark = "  <- 证书名覆盖真实 Host, 可开 proxy_ssl_verify" if r.verify_possible else ""
            if not mark and r.passing_ips:
                mark = f"  <- 可用节点: {','.join(r.passing_ips)}"
            print(f"{r.strategy:<18}{LEVEL_LABELS.get(r.level, r.level):<16}"
                  f"{r.tls_ok:>4}/{r.total}{gate:>10}{r.chain_ok:>6}/{r.total}"
                  f"{r.http_ok:>6}/{r.total}  {'✅ 通过' if r.passed else '❌ 淘汰'}{mark}")
        print()
        print(f"当前生效: {st.summary()}")
        if st.notes:
            print(f"说明: {st.notes}")
        if not st.available:
            print("\n⚠ 该通道不可用 —— 按方案 §10 验收标准 6 与 §8 末行, 必须在 UI 显式报错, "
                  "不得静默白屏。")
    return 0 if st.available else 1


if __name__ == "__main__":
    sys.exit(main())
