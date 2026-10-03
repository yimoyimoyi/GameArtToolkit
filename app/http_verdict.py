# -*- coding: utf-8 -*-
"""HTTP 重定向判据的**单一真源**（2026-10-03）

为什么单独成模块（这是一次真实的误判事故收口）：

同一条判据此前散在三处，而**只有探测脚本里的那份是对的**：

| 位置 | 当时的实现 | 后果 |
|---|---|---|
| `scripts/probe_yande_channels.py` | 去掉 scheme/参数后比较路径（正确） | 只有它能看出 yande.re 的自跳 |
| `app/cdn_optimizer.py` | 只比 `path == "/"` | 抓不到 `/post → https://yande.re/post` 形态 |
| `scripts/probe_onboard.py` / `probe_ech_candidates.py` | **完全不看 Location** | 实测把 yande.re 经 CF 的自跳 301 判成"ECH 可用 3/3 次" |

最后一行是最危险的：一个**已经坏掉**的通道拿到了绿色验收结论（见
`docs/service-expansion-review-2026-10-03.md` §P0-2）。判据重复实现/缺失正是本项目
反复吃亏的地方，所以这里收敛成**纯函数**，生产探测与两个验收工具共用同一份。

纯函数、无 I/O、无全局状态 —— 便于单测，也便于被工具直接 import。
"""

from __future__ import annotations

from typing import Optional, Tuple

# 一次跳转的定性取值
SELF = "self"            # Location 指回**同一个 URL** (A → A)：死循环的最短形态
LOOP = "loop"            # 第二跳又跳回第一跳的来源 (A → B → A)：经 CDN 的典型形态
NORMALIZE = "normalize"  # 同 host 换到别的路径 (区域/语言跳转、canonical 补全) —— **正常**
EXTERNAL = "external"    # 换 host (是否正常由调用方判断，不在本模块下结论)
INVALID = "invalid"      # 没有可用的 Location

# 视为"通道已坏"的定性
BROKEN = (SELF, LOOP)


def location_target(loc: str, domain: str) -> Tuple[str, str]:
    """把 `Location` 解析成 (host, path) —— **相对 Location 必须按相对路径处理**

    为什么按相对路径解析而不是"不打补丁就排除某些路径"（2026-10-02 定因）:
      原先在探测里内联解析，对不带 `://` 的 Location 直接把 path 当成 "/" ——
      于是"同 host + 同路径"的自我重定向判据**退化成"同 host"**，任何相对重定向都被
      误判成死循环。实测 `www.xbox.com/` 回 `307 Location: /zh-CN/`（正常的区域跳转），
      **6 个候选全部**因此拿不到主力位。区域/语言跳转是 CDN 最常见的根路径行为。

    返回值已剥掉 query/fragment —— 路径比较不该被它们影响。
    """
    loc = (loc or "").strip()
    if "://" in loc:
        rest = loc.split("://", 1)[1]
        host = rest.split("/", 1)[0].lower()
        path = ("/" + rest.split("/", 1)[1]) if "/" in rest else "/"
    else:
        host = (domain or "").lower()           # 相对 Location 沿用本 host
        path = loc if loc.startswith("/") else "/" + loc
    path = path.split("?", 1)[0].split("#", 1)[0]
    return host, path


def is_self_redirect(location: str, request_host: str, request_path: str = "/") -> bool:
    """`Location` 是否指回**同一个 host + 同一个路径**（A → A）"""
    host, path = location_target(location, request_host)
    return host == (request_host or "").lower() and path == (request_path or "/")


def classify_redirect(location: str, request_host: str, request_path: str = "/",
                      second_location: str = "") -> str:
    """一次（或两次）跳转的定性，见模块头的 SELF/LOOP/NORMALIZE/EXTERNAL/INVALID

    `second_location` 传入时表示"已经把第一跳的目标又请求了一次，拿到的新 Location"：
    此时若新 Location 指回**原始请求路径**，就是 A → B → A 的死循环（LOOP）。

    为什么要支持第二跳：单纯比较一次 Location 抓不到 yande.re 的形态 ——
    经 CF 时 `/` 可能先 301 到 `/post`（看着像正常规范化），而 `/post` 又 301 回 `/post`。
    只判一跳会把这种通道判成"可用"。
    """
    if not (location or "").strip():
        return INVALID
    host, path = location_target(location, request_host)
    req_host = (request_host or "").lower()
    req_path = request_path or "/"
    if host != req_host:
        return EXTERNAL
    if path == req_path:
        return SELF
    if (second_location or "").strip():
        h2, p2 = location_target(second_location, req_host)
        if h2 == req_host and p2 == path:
            # 第二跳的目标与第一跳的**目标**相同 ⇒ 客户端会一直停在这一跳 ⇒ 死循环
            return LOOP
    return NORMALIZE


def is_broken(location: str, request_host: str, request_path: str = "/",
              second_location: str = "") -> bool:
    """该重定向是否意味着"这条通道已经坏了"（自跳或两跳死循环）"""
    return classify_redirect(location, request_host, request_path,
                             second_location) in BROKEN


def describe(verdict: str, location: str = "") -> str:
    """给人看的一句话（工具输出用，避免三处各写一种措辞）"""
    return {
        SELF: f"自跳循环 (Location 指回同一 URL: {location or '-'}) ⇒ 通道不可用",
        LOOP: f"两跳死循环 (A → B → A: {location or '-'}) ⇒ 通道不可用",
        NORMALIZE: f"正常规范化 → {location or '-'}",
        EXTERNAL: f"跳到其它 host → {location or '-'}",
        INVALID: "无 Location",
    }.get(verdict, verdict)


def self_redirect_flag(raw_headers: bytes, request_host: str,
                       request_path: str = "/") -> Optional[str]:
    """从**原始响应头**里取 Location 并定性（供只拿到 bytes 的探测代码使用）

    返回 None 表示响应头里没有 Location。
    """
    try:
        head = raw_headers.decode("latin-1", errors="replace")
    except Exception:
        return None
    for line in head.split("\r\n"):
        if line.lower().startswith("location:"):
            loc = line.split(":", 1)[1].strip()
            return classify_redirect(loc, request_host, request_path)
    return None
