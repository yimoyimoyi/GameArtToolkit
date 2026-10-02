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
"""

import json
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
               timeout: float = PROBE_TIMEOUT) -> Dict:
    """对单个中转节点验证一个 SNI 策略的四关

    strategy="host" 时 SNI 用 host 本身; "empty" 时不发 SNI; 其余按字面量当掩护域。
    两个证书判据要分清 (这是本模块最容易写错的地方):
      host_covered —— 证书名是否覆盖**真实 Host**。掩护策略上它**必然为假**, 只用于判断
                      "这个策略能否开 upstream 证书校验", **不能**当淘汰门槛。
      gate_ok      —— §6.2 第 ③ 关: 证书是否属于**该厂商自有证书族**(掩护策略), 或覆盖
                      真实 Host(host 策略)。空 SNI 记 None (对端必为占位证书, 该关不适用)。
    """
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
            belongs = cert_belongs_to_vendor(out["sans"], vendor)
            if belongs is None:
                # 该厂商未登记证书族 => 退回弱门槛: 至少不能是占位证书
                belongs = not _placeholder_only(out["sans"])
            out["gate_ok"] = bool(belongs)

        ssock.settimeout(timeout)
        ssock.sendall((f"GET {PROBE_PATH} HTTP/1.1\r\nHost: {host}\r\n"
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
            out["http_ok"] = out["status"] in OK_STATUSES
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

    @property
    def level(self) -> str:
        return level_for(self.strategy)

    @property
    def passed(self) -> bool:
        """是否可用作当前通道

        判据 (宁可判失败也不假可用):
        - 至少一个节点 TCP+TLS 成功;
        - 非空 SNI 策略: **该策略的证书门槛必须全部节点通过** (§6.2 第 ③ 关是硬门槛,
          不降权、不按多数放行);
        - 真实 Host 的 HTTP 探活至少过半节点正常 (证明 Host 路由成立)。
        空 SNI 不适用证书门槛 (对端必为占位证书), 只要求 HTTP 过半。
        """
        if self.tls_ok == 0:
            return False
        if self.strategy != STRATEGY_EMPTY and self.gate_ok < self.tls_ok:
            return False
        return self.http_ok >= max(1, (self.total + 1) // 2)

    @property
    def verify_possible(self) -> bool:
        """该策略下上游证书名是否覆盖真实 Host => 能否开 proxy_ssl_verify"""
        return self.tls_ok > 0 and self.host_covered >= self.tls_ok

    def as_dict(self) -> Dict:
        return {"strategy": self.strategy, "level": self.level, "passed": self.passed,
                "total": self.total, "tls_ok": self.tls_ok, "gate_ok": self.gate_ok,
                "chain_ok": self.chain_ok, "http_ok": self.http_ok,
                "host_covered": self.host_covered, "verify_possible": self.verify_possible}


@dataclass
class VendorState:
    """某厂商当前生效的 SNI 策略与降级层级"""
    vendor: str
    host: str
    strategy: str
    results: List[StrategyResult] = field(default_factory=list)
    checked_at: float = 0.0
    from_cache: bool = False
    notes: str = ""

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
        return (f"{self.vendor}: {self.level_label} (策略={self.strategy}) {detail}")

    def as_dict(self) -> Dict:
        return {"vendor": self.vendor, "host": self.host, "strategy": self.strategy,
                "level": self.level, "level_label": self.level_label,
                "available": self.available, "sni_mode": self.sni_mode,
                "verify_possible": self.upstream_verify_possible,
                "checked_at": self.checked_at, "age_seconds": round(self.age(), 1),
                "summary": self.summary(), "notes": self.notes,
                "results": [r.as_dict() for r in self.results]}


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
    """
    pool = pool_for(vendor, allow_empty=allow_empty)
    if not pool or not ips:
        return VendorState(vendor=vendor, host=host, strategy="", checked_at=time.time(),
                           notes="该厂商未登记候选池或候选池为空, 回落到静态配置")

    from concurrent.futures import ThreadPoolExecutor

    results: List[StrategyResult] = []
    state = VendorState(vendor=vendor, host=host, strategy="", checked_at=time.time())
    for strategy in pool:
        jobs = [(ip, strategy, host, vendor, timeout) for ip in ips]
        with ThreadPoolExecutor(max_workers=min(max_workers, len(jobs))) as ex:
            nodes = list(ex.map(lambda a: probe_node(*a), jobs))
        sr = StrategyResult(strategy=strategy, total=len(nodes), nodes=nodes)
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
    return state


def refresh(vendor: str, ips: List[str], host: str, force: bool = False,
            timeout: float = PROBE_TIMEOUT,
            allow_empty: Optional[bool] = None) -> VendorState:
    """带 TTL 缓存的探测 (线程安全)"""
    with _lock:
        cur = _states.get(vendor)
        if cur and not force and cur.age() < STATE_TTL_SECONDS:
            cur.from_cache = True
            return cur
    st = evaluate(vendor, ips, host, timeout=timeout, allow_empty=allow_empty)
    with _lock:
        _states[vendor] = st
    return st


def get_state(vendor: str) -> Optional[VendorState]:
    """只读取已有状态, 不触发探测 (UI/生成器用; 无状态时调用方应回落静态配置)"""
    with _lock:
        return _states.get(vendor)


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
    """
    vendor = str(getattr(profile, "cdn_vendor", "") or "").strip().lower()
    if not vendor or not pool_for(vendor):
        return getattr(profile, "ssl_sni_mode", None)
    if not auto_regress_enabled():
        return getattr(profile, "ssl_sni_mode", None)
    st = get_state(vendor)
    if st is None or not st.available:
        # 不可用时不能返回空串(会被当成字面量 SNI), 交回调用方按自身策略处理
        return getattr(profile, "ssl_sni_mode", None)
    return st.sni_mode


# ---------------------------------------------------------------------------
# 便捷入口: Google / YouTube 通道状态 (UI 用)
# ---------------------------------------------------------------------------
GOOGLE_VENDOR = "google"
GOOGLE_STATE_HOST = "www.google.com"


def google_probe_ips() -> List[str]:
    """从画像里取 Google 通道的候选节点池 (单一真源, 不在这里另抄一份 IP)"""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from service_profile import PROFILES
    except Exception:
        return []
    prof = next((p for p in PROFILES if getattr(p, "cdn_vendor", "") == GOOGLE_VENDOR), None)
    return list(getattr(prof, "candidate_ips", []) or []) if prof else []


def google_profile_ids() -> List[str]:
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from service_profile import PROFILES
    except Exception:
        return []
    return [p.id for p in PROFILES if getattr(p, "cdn_vendor", "") == GOOGLE_VENDOR]


def check_google_channel(force: bool = False) -> VendorState:
    """回归探针: 检查 Google 掩护 SNI 是否仍然有效, 失效时自动降级"""
    return refresh(GOOGLE_VENDOR, google_probe_ips(), GOOGLE_STATE_HOST, force=force)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    ap = argparse.ArgumentParser(description="掩护 SNI 候选池 / 自动回归 / 降级链")
    ap.add_argument("--check", action="store_true", help="立即跑一次回归探测")
    ap.add_argument("--vendor", default=GOOGLE_VENDOR, help="厂商 (默认 google)")
    ap.add_argument("--host", default=None, help="真实 Host (默认取该厂商首个画像主域)")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--timeout", type=float, default=PROBE_TIMEOUT)
    args = ap.parse_args(argv)

    vendor = args.vendor
    ips = google_probe_ips() if vendor == GOOGLE_VENDOR else []
    host = args.host or (GOOGLE_STATE_HOST if vendor == GOOGLE_VENDOR else "")
    if not ips:
        print(f"[{vendor}] 找不到候选节点池, 无法探测")
        return 2

    st = evaluate(vendor, ips, host, timeout=args.timeout)
    if args.json:
        print(json.dumps(st.as_dict(), ensure_ascii=False, indent=2))
    else:
        print(f"厂商: {vendor}   真实 Host: {host}   节点池: {len(ips)} 个\n")
        print("证书门槛 = §6.2 第③关: 对端证书是否属于该厂商自有证书族 (空 SNI 不适用)")
        print("链可信   = 链是否受系统信任库认可; 名字匹配真实 Host 的只有 host 策略 (可开校验)\n")
        print(f"{'策略':<18}{'层级':<16}{'TLS':>6}{'证书门槛':>10}{'链可信':>8}{'HTTP过':>8}  结论")
        print("-" * 92)
        for r in st.results:
            gate = "不适用" if r.strategy == STRATEGY_EMPTY else f"{r.gate_ok}/{r.total}"
            mark = "  <- 证书名覆盖真实 Host, 可开 proxy_ssl_verify" if r.verify_possible else ""
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
