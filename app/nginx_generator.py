# -*- coding: utf-8 -*-
"""
GameArt Toolkit - Nginx 站点配置声明式模板生成器 (Nginx Configuration Generator)

核心功能:
- 基于 ServiceProfile 单源注册表，自动生成 site-gaming.conf / site-acg.conf / site-dev.conf
- 彻底消除手写 Nginx 配置文件的重复维护风险，实现代码与配置 100% 自动同步
- 精准映射 WebSocket、Range 206、图片磁盘缓存、Steam 302 重定向与伪装 SNI
"""

import os
import re
import sys
import threading
from pathlib import Path
from typing import Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ech_tunnel import ech_tunnel
import h3_upstream
from path_utils import NGINX_DIR
from service_profile import (
    PROFILES,
    PROFILES_BY_ID,
    ServiceProfile,
    ServiceMode,
    SERVICE_GROUPS,
    SITE_FILE_FOR_GROUP,
)

CONF_DIR = NGINX_DIR / "conf"

# 站点配置文件的标题文案 (只影响注释头; 分组与文件的对应关系在 service_profile 里)
SITE_GROUP_TITLES = {
    "gaming": "游戏生态全平台加速规则",
    "acg": "二次元与创作者生态加速规则",
    "dev": "开发者与 AI 平台加速规则",
    "adult": "成人内容加速规则",
}

# ==============================================================================
# 上游**快速失败**策略 (2026-10-03) —— 与 cdn_optimizer 的 upstream 熔断参数配套
# ==============================================================================
#
# 三个参数必须**一起**看, 少任何一个都会让"单请求最坏等待时间"失去上界:
#   · connect_timeout      单次建连 (+ https 上游的 TLS 握手) 的预算;
#   · next_upstream_tries  单请求最多换几个节点;
#   · next_upstream_timeout 换节点的**总预算** —— 这才是真正的上界, 因为前两者相乘
#                          才是最坏值, 而池子大小是会变的 (4~8 个)。
#
# ★ 为什么把 connect 从 3s 压到 1s (换网后实测, 2026-10-03):
#   健康边缘的建连实测落在 29~350ms (Google 中国系 29~95ms / pixiv CDN 135~187ms /
#   Cloudflare 150~250ms / Fastly 104~150ms); 而"活着但病态"的是另一档:
#   1.1s / 1.3s / 2.3s / 3.3s (CloudFront 与个别 Fastly 地址)。
#   1s 干净地把两档分开: 全部健康节点照收, 病态节点判死并**立刻交棒**给同池里
#   100ms 级的兄弟节点。这不是"更激进", 而是"别再为一条注定更慢的路径付费"。
#   实测代价(旧值 3s): pypi 池 4 个里 2 个 TCP 超时 ⇒ 3s × 最多 4 次 = 单请求最坏 12s,
#   实测 TTFB 1.8~4.8s 且 8s 预算内没下完; 而**直连同一个 URL 只要 0.47s**。
#
# ★ 为什么总预算是 4s —— 以及它**实际**覆盖了几个死节点 (2026-10-04 实测校正):
#
# `proxy_next_upstream_timeout` 只在"要不要再换一个节点"这个**决策点**被检查,
# **不能中断进行中的那条腿**。所以真实上界是:
#       实际耗时 ≈ (被试掉的腿数) × (单腿最坏耗时)
# 而不是预算本身。原注释写的"4s 预算 + 1s 单次 ≈ 允许先试掉 2 个死节点"只在
# "每条腿都 ≤ 1.5s"时成立, 属于把**下限当成了上界**。
#
# 本机实测 (nginx 1.31.4, 见 docs/design-principles-...md 的 W6):
#   · 对**已关闭的回环端口**建连要约 **2.0s** 才返回 WSAECONNREFUSED
#     (.NET TcpClient 裸测 5 次: 2014.8–2062.7 ms) —— 即单腿 2s 量级;
#   · 两节点池 {不可用节点, 健康节点} 给 1s 预算 ⇒ 3 次里 **2 次返回 502,
#     健康节点根本没被试到**; 给 4s ⇒ 3/3 成功;
#   · 反向边界同样实测到: 预算 300ms 时实际 515–521ms (超 72%);
#     单腿 3.0s + 预算 1s 时实际 3012–3016ms (**超 3 倍**)。
#
# ⇒ 按实测的 2s 单腿成本, **4s 预算只够试掉 1 个死节点再连健康节点**, 不是 2 个。
#   这是"预算 ≥ 2 × 单腿最坏耗时"这条不变量在 2s 单腿下的**必然结果**:
#   4s < 2 × 2s = 4s 的边界上, 第二个死节点就会吃掉全部余额。
#   `_assert_budget_reaches_health_after_one_dead_leg()` (测试) 锁住这个关系,
#   所以将来改预算或改单腿成本时会被立刻发现, 而不是继续留一句错的口径。
#
# 为什么**不**在这一批里直接调大预算: 调大是行为变更, 需要先实测"2 个死节点 +
# 健康节点"下目标服务是否真的变好 (本项目已多次因未实测的配置改动翻车);
# 而且探测层 (cdn_optimizer._suspect_status) 本来就负责把高失败节点提前剔除,
# nginx 很少真的看到死节点 —— 先把这个口径改对, 再据实测定是否调值。
#
# ⚠ 为什么不顺手把 upstream 的 `fail_timeout` 从 5s 调大: 那是**另一笔权衡**
#   (记忆时长 vs 重新学习的时效), 且 cdn_optimizer 里的 5s 有实测依据
#   (见 UPSTREAM_FAIL_TIMEOUT 注释: GFW 逐段分钟级轮换)。本函数不碰它。
UPSTREAM_CONNECT_TIMEOUT = "1s"
UPSTREAM_NEXT_TRIES = 4
UPSTREAM_NEXT_TIMEOUT = "4s"

# 单腿最坏耗时 (秒) —— 实测值, 不是猜的。
# 本机对已关闭的回环端口建连约 2.0s 才返回失败; 真实公网死节点多为 SYN 超时,
# 量级相近或更大。它是"预算能覆盖几个节点"这条推理的输入, 因此必须是个具名常量,
# 而不是散在注释里的一个数字。
UPSTREAM_SINGLE_LEG_WORST_SECONDS = 2.0

# 预算至少要是单腿最坏耗时的这个倍数, 否则"重试"在数学上救不了任何东西
# (第一条腿就把余额吃光, 健康兄弟节点根本没机会被访问)。
UPSTREAM_BUDGET_MIN_LEG_MULTIPLE = 2


def _parse_nginx_duration_seconds(s: str) -> float:
    """把 nginx 时长字面量 (如 '1s' / '300ms' / '4s') 解析成秒

    只支持本文件实际会写出的单位; 遇到不认识的写法返回 -1, 由调用方决定怎么处理
    (不抛异常: 这个函数服务于"把配置口径核对正确", 不该在核对失败时把生成流程带崩)。
    """
    t = (s or "").strip().lower()
    try:
        if t.endswith("ms"):
            return float(t[:-2]) / 1000.0
        if t.endswith("s"):
            return float(t[:-1])
        if t.endswith("m"):
            return float(t[:-1]) * 60.0
    except ValueError:
        return -1.0
    return -1.0


def upstream_budget_reaches_health_after(dead_legs: int) -> bool:
    """在"先试掉 `dead_legs` 条死腿再连健康节点"的场景下, 预算是否还够用

    这是把注释里的那套推理变成**可执行**的判据: 预算 >= (dead_legs + 1) × 单腿最坏耗时,
    其中最后一项是健康节点的建连 (健康边缘实测 29~350ms, 但这里按单腿最坏算, 保守)。
    """
    budget = _parse_nginx_duration_seconds(UPSTREAM_NEXT_TIMEOUT)
    if budget < 0:
        return False
    return budget >= (dead_legs + 1) * UPSTREAM_SINGLE_LEG_WORST_SECONDS


def _assert_budget_reaches_health_after_one_dead_leg() -> None:
    """把"4s 预算到底覆盖几个死节点"这个事实钉住 (2026-10-04)

    实测口径见 UPSTREAM_NEXT_TIMEOUT 上方注释。这里**断言当前设计意图**:
    至少要在"1 个死节点 + 健康节点"下仍然够用 —— 低于这一条, 重试机制等于没有。
    若将来把预算调小或把单腿成本实测改大, 这里会明确失败并指向原因, 而不是
    让配置悄悄退化成"第一条腿吃光预算 ⇒ 502"。

    用显式 `raise` 而不是 `assert`: `python -O` 会**剥掉** assert 语句,
    而这条校验的意义正是"不允许被静默跳过"。
    """
    if not upstream_budget_reaches_health_after(1):
        raise ValueError(
            f"预算 {UPSTREAM_NEXT_TIMEOUT} 连'1 个死节点 + 1 个健康节点'都覆盖不了 "
            f"(单腿最坏按 {UPSTREAM_SINGLE_LEG_WORST_SECONDS}s 计): 重试在数学上救不了任何东西, "
            f"失败会以 502 形式出现, 用户看到的是'服务坏了'而不是'这个节点不行'")


# 导入期即校验: 配置口径错了就不该继续生成配置
_assert_budget_reaches_health_after_one_dead_leg()


def upstream_failover_lines(indent: str = "        ") -> List[str]:
    """渲染"上游快速失败"三件套 —— **所有 location 模板都必须用它**

    为什么抽成函数而不是散在各模板里: 本文件原有 6 处 location 模板各自手写这些参数,
    实测生成的 `site-acg.conf` 里因此出现三种口径 —— 5 个 location **完全没有**
    tries 限制 (继承默认 = 不限次数)、1 个写着 `proxy_next_upstream_timeout 60`
    (无单位, 60 秒, 形同虚设)、其余没有 connect 超时 (只继承全局 5s)。
    同一份配置里三种口径, 正是"最坏等待时间无界"的直接来源。
    """
    return [
        f"{indent}proxy_connect_timeout {UPSTREAM_CONNECT_TIMEOUT};",
        f"{indent}proxy_next_upstream_tries {UPSTREAM_NEXT_TRIES};",
        f"{indent}proxy_next_upstream_timeout {UPSTREAM_NEXT_TIMEOUT};",
    ]

# 不经 Nginx 的模式: Direct (Hosts/DNS 直指真实 CDN IP) 与 QUIC 直连 (浏览器自行走
# HTTP/3) 都由解析层直接引导, 本地 Nginx 既不该也无法承载它们 —— 若仍渲染 server 块,
# 会生成空上游池并导致 nginx -t 直接报 "no host in upstream" 启动失败。
NGINX_BYPASS_MODES = (ServiceMode.DIRECT, ServiceMode.QUIC_DIRECT)


class NginxConfGenerator:
    """Nginx 站点配置文件生成引擎"""

    # ------------------------------------------------------------------
    # ECH 隧道上游判定
    # ------------------------------------------------------------------
    @classmethod
    def _upstream_names_in_file(cls, upstream_conf: Path) -> Set[str]:
        """解析 upstream-dynamic.conf 里已定义的 upstream 名

        为什么要单独有它 (2026-10-02 实测事故): L7 画像的 upstream 由 CDNOptimizer
        **实测后**写入该文件; 若某个画像还没被测过 (例如刚新增), 生成器会照旧输出
        `proxy_pass {scheme}://{profile.upstream_name}` —— 而 upstream_name 为空时
        就得到 `proxy_pass https://;`。这不是"该服务不可用", 而是**整个 nginx 拒绝加载**
        (`nginx -t` 直接报 "no host in upstream \"\"") ⇒ 全部服务一起挂。
        实测就是这样把一次新增画像变成了全量故障, 故这里提供回落所需的名单。
        """
        if not upstream_conf.exists():
            return set()
        try:
            text = upstream_conf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return set()
        return set(re.findall(r"upstream\s+(upstream_[a-z0-9_]+)\s*\{", text))

    @classmethod
    def _static_fallback_upstream(cls, profile) -> str:
        """为"动态 upstream 尚未测出"的画像生成内联 upstream 块 (可能是空串)

        为什么用静态 candidate_ips 回落, 而不是干脆跳过该站点:
          · 跳过 = 域名被劫持到本机却**没有站点** ⇒ 落到默认 server, 浏览器拿到
            不匹配的证书或不相干的响应 —— 正是本轮反复出现的"假覆盖";
          · 用内联 upstream 至少能走 profile 里已实测过的静态 IP, 与"动态优选"相比
            只是不最优, 但**是通的**。
        仅当 candidate_ips 为空时返回空串 (此时调用方必须报错, 不能静默输出空 upstream)。
        """
        ips = [ip for ip in (getattr(profile, "candidate_ips", None) or []) if ip]
        if not ips:
            return ""
        # 惰性导入: 熔断参数由 cdn_optimizer 统一管理, 此处不得再造一套 (否则两边会漂移)
        try:
            from cdn_optimizer import _upstream_server_opts as _opts_fn
            opts = _opts_fn()
        except Exception:
            opts = "max_fails=1 fail_timeout=5s"
        name = getattr(profile, "upstream_name", "") or f"upstream_{profile.id}"
        lines = [
            f"# [回落] {profile.id} 的动态优选尚未测出, 使用画像自带的静态 IP",
            f"upstream {name} {{",
        ]
        for ip in ips:
            # ⚠ 必须带端口。实测教训: 写成裸 IP 时 nginx 会**默认用 80 端口**, 而中继听的是
            # 443 ⇒ 全部候选连不上, 站点返回 502。项目里动态写出的 upstream 都是
            # `ip:443` 形式 (见 upstream-dynamic.conf), 这里必须与之一致。
            # 若 candidate_ips 里已自带端口则原样保留。
            addr = ip if ":" in ip and not ip.count(":") > 1 else f"{ip}:443"
            lines.append(f"    server {addr} {opts};")
        lines.append("}")
        return "\n".join(lines) + "\n"

    @classmethod
    def _ech_services_from_upstream(cls, upstream_conf: Path) -> Optional[Set[str]]:
        """从 upstream-dynamic.conf 解析实际走 ECH 隧道的服务 id 集合

        返回 None 表示文件不存在 (调用方回退到实时健康检查)。

        为什么以文件内容为准、而不是 profile.ech_enabled: 后者是静态标记, 而
        CDNOptimizer 是否真的写入隧道地址是动态的 (隧道健康才写)。两者不一致时,
        site 配置若仍按静态标记输出 http://, 就会把明文 HTTP 打到候选池的 :443
        (HTTPS 端口), 上游直接回 400 "The plain HTTP request was sent to HTTPS
        port" —— 已实测复现 (curl http://210.140.139.158:443/ -H "Host: www.pixiv.net")。

        必须匹配 ECH 的精确端口而非笼统的 127.0.0.1: relay 分支同样写回环地址
        (127.0.0.1:443xx), 但它承载的是 TLS, 需要 https:// —— 混为一谈会反向错配。
        """
        if not upstream_conf.exists():
            return None
        try:
            text = upstream_conf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

        marker = f"127.0.0.1:{ech_tunnel.port}"
        found: Set[str] = set()
        for m in re.finditer(r"upstream\s+(upstream_[a-z0-9_]+)\s*\{(.*?)\}", text, re.S):
            if marker in m.group(2):
                found.add(m.group(1)[len("upstream_"):])
        return found

    @classmethod
    def _h3_services_from_upstream(cls, upstream_conf: Path) -> Optional[Set[str]]:
        """从 upstream-dynamic.conf 解析"上游走本地 HTTP/3 腿"的服务 id 集合

        与 ECH 分支同源: 判据必须取自**文件实际内容**(CDNOptimizer 真写了回环地址),
        而不是 profile 的静态标记 —— 两者脱钩会产出"明文 HTTP 打向真实 :443",
        上游直接回 400 (该错配已实测复现, 见 _ech_services_from_upstream 注释)。

        同样必须匹配**精确端口**: relay 分支也写 127.0.0.1:443xx, 但它承载 TLS, 需 https://。
        """
        if not upstream_conf.exists():
            return None
        try:
            text = upstream_conf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None
        marker = f"127.0.0.1:{h3_upstream.PORT}"
        found: Set[str] = set()
        for m in re.finditer(r"upstream\s+(upstream_[a-z0-9_]+)\s*\{(.*?)\}", text, re.S):
            if marker in m.group(2):
                found.add(m.group(1)[len("upstream_"):])
        return found

    @classmethod
    def _use_ech(cls, profile: ServiceProfile, ech_services: Optional[Set[str]]) -> bool:
        """该服务本次是否走 ECH 隧道 (必须与 CDNOptimizer 写入的 upstream 一致)"""
        if not getattr(profile, "ech_enabled", False):
            return False
        if ech_services is None:
            # 无 upstream 快照可用 (首次生成/文件缺失): 以隧道实时健康为准,
            # 与 CDNOptimizer 的 ECH 分支判据保持一致
            return ech_tunnel.is_healthy()
        return profile.id in ech_services

    @classmethod
    def _use_h3(cls, profile: ServiceProfile, h3_services: Optional[Set[str]]) -> bool:
        """该服务本次是否走本地 HTTP/3 上游腿 (与 CDNOptimizer 写入的 upstream 保持一致)"""
        if not getattr(profile, "h3_upstream", False):
            return False
        if h3_services is None:
            # 无 upstream 快照 (首次生成/文件缺失): 以静态标记为准 ——
            # h3 腿是本地常驻进程, 没有 ECH 那种"隧道健康"外部状态需要复核
            return True
        return profile.id in h3_services

    @classmethod
    def render_server_block(cls, profile: ServiceProfile,
                           ech_services: Optional[Set[str]] = None,
                           h3_services: Optional[Set[str]] = None) -> str:
        """为单个 ServiceProfile 渲染标准 Nginx Server 块

        ## ★ 通配来源 (2026-10-03 定案, 原缺陷 M6)

        以前这里有一张**按 `profile.id` 硬编码**的通配补表
        (steam_* / booth_pm / pixiv_fanbox / github_assets / gitlab / dlsite /
         battle_net / patreon)。它与其它三个后端各算一套:

          · nginx   —— 这张硬编码表
          · PAC     —— `pac_redirect.split_domains()`, 只认画像里显式写的 `*.`
          · NRPT    —— `nrpt_manager.build_namespace_entries()`, 按正则判
          · Hosts   —— 完全不支持通配

        于是**同一个画像在四个后端覆盖面不同, 且没有任何提示** —— 根因二。
        M3 已把证书 SAN 统一到"只取声明域名", 并且把那 9 条只存在于本表的通配
        **显式声明进了各自画像**。因此本表现在是纯冗余: 直接消费 `profile.domains`
        即可, 四个后端从此同源。
        """
        domains_list = list(profile.domains)

        # 保序去重 (通配已在画像里显式声明 —— 见本函数 docstring 的 M6 说明)
        domains_list = list(dict.fromkeys(domains_list))
        domains_str = " ".join(domains_list)

        # SNI 与 Host 头部策略
        #
        # 掩护 SNI 不是常量 (方案 §5.1 / §6.4): 这里不再直接读 profile.ssl_sni_mode,
        # 而是问 cover_sni 模块"当前该用哪个策略"。该模块按候选池实测, 掩护域失效时
        # 自动降级 (g.cn → 其它 Google 自有域 → 真实 SNI → 空 SNI); **没有新鲜探测结果时
        # 原样返回画像配置值**, 因此本处不改变任何既有行为, 只在探测明确说"首选已失效"
        # 时才换 SNI。降级结果同时由 UI 显示 (方案 §10 验收标准 6)。
        sni_mode = profile.ssl_sni_mode
        try:
            import cover_sni as _cover_sni
            sni_mode = _cover_sni.effective_sni_mode(profile) or profile.ssl_sni_mode
        except Exception:      # pragma: no cover - 探测模块不可用时绝不阻断生成
            sni_mode = profile.ssl_sni_mode
        if sni_mode != profile.ssl_sni_mode:
            lines_note_downgrade = (
                f"    # [降级] 掩护 SNI 回归探测判定 {profile.ssl_sni_mode} 失效, "
                f"本块实际使用 {sni_mode} (见 app/cover_sni.py)"
            )
        else:
            lines_note_downgrade = ""

        if sni_mode == "empty":
            sni_str = '""'
        elif sni_mode == "host":
            sni_str = "$host"
        else:
            sni_str = f'"{sni_mode}"'

        if profile.id == "steam_community":
            # Host 分流: api.steampowered.com 必须保持原 Host 才能命中 API 网关 vhost
            # (Host 被改写为 steamcommunity.com 时 API 路径会被上游 302 重定向到社区首页),
            # 其余域名 (steamcommunity.com 及子域) 归一化到主域防 118
            # 对应文件顶部 map $host $steam_upstream_host
            host_header = "$steam_upstream_host"
        else:
            host_header = profile.custom_headers.get("Host", "$host")

        # ECH 隧道分支: 上游指向本地回环上的明文 HTTP 入口, 真正的 TLS 与 ECH
        # 握手由隧道自己发起。此时必须完全不输出 proxy_ssl_* —— 否则形成
        # TLS-in-TLS, 隧道无法在中间注入 ECH 扩展。
        # 协议必须与 upstream 实际写入的后端一致 (隧道=明文回环, 退化候选池=https),
        # 判据取自 upstream-dynamic.conf 而非静态标记, 详见 _ech_services_from_upstream。
        ech = cls._use_ech(profile, ech_services)
        # HTTP/3 上游腿与 ECH 同款: 后端是本地回环上的**明文** HTTP 入口, 真正的 TLS/QUIC
        # 由本地代理自己发起。此时同样必须完全不输出 proxy_ssl_*。
        h3 = cls._use_h3(profile, h3_services)
        plaintext_local = bool(ech or h3)
        scheme = "http" if plaintext_local else "https"
        ssl_lines = [] if plaintext_local else [
            f"        proxy_ssl_name {sni_str};",
            "        proxy_ssl_server_name on;",
            "        proxy_ssl_verify off;",
            "        proxy_ssl_session_reuse on;",
        ]
        title = f"{profile.name} (经本地 ECH 隧道直连 Cloudflare)" if ech else (
            f"{profile.name} (经本地 HTTP/3 上游腿)" if h3 else profile.name)

        # ----------------------------------------------------------------------
        # 1. Pixiv 主站特殊处理 (包含 /ajax/ CORS 与 /ws/ WebSocket)
        # ----------------------------------------------------------------------
        if profile.id == "pixiv_web":
            return cls._render_pixiv_web_server(profile, ech_services)

        # ----------------------------------------------------------------------
        # 2. Pixiv 图片 CDN 特殊处理 (包含 pximg 缓存与 Sketch 直播流)
        # ----------------------------------------------------------------------
        if profile.id == "pixiv_img":
            return cls._render_pixiv_img_server(profile)

        # ----------------------------------------------------------------------
        # 3. 标准通用 Server 块渲染
        # ----------------------------------------------------------------------
        lines = [
            f"# {title}",
            "server {",
            "    listen 80;",
            "    listen 443 ssl;",
            "    http2 on;",
            f"    server_name {domains_str};",
            ""
        ]
        if lines_note_downgrade:
            lines.append(lines_note_downgrade)

        if profile.group == "dev":
            lines.append("    client_max_body_size 0;  # 支持任意体积大文件与 Git packfile")
        elif profile.id in ("pixiv_fanbox", "booth_pm"):
            lines.append("    client_max_body_size 50M;")

        # WebSocket 升级头的取舍 (项目实测, 见下方注释):
        #   普通服务用编译期字面量空串 "" -> upstream keepalive 生效 (TTFB 0.22~0.24s);
        #   但**真正需要 WebSocket 的服务** (如 Discord 网关 gateway.discord.gg, 路径是 /
        #   而非 /ws/) 必须发 "upgrade", 否则浏览器 WS 握手被清掉、客户端持续
        #   "[WS CLOSED] An error with the websocket occurred" (实测事故)。
        # 两者都是**生成期就写死的字面量**, 因此 keepalive 语义不受影响。
        conn_header = '"upgrade"' if getattr(profile, "websocket", False) else '""'

        # ★ 路径专属 location 排在 `location /` **之前** (2026-10-04 实现 path_rules)。
        #   语义上 nginx 按最长前缀优先, 顺序无关; 但读配置的人从上往下看, 把特例放在
        #   通配之前才不会有"为什么这条被吃掉了"的错觉。
        lines.extend(cls._render_path_rule_locations(profile, ssl_lines, host_header, scheme))

        # 通用 `location /` —— 管线与 path_rules **共用同一实现**, 不复制模板
        lines.append("    location / {")
        lines.extend(cls._render_location_body(
            profile, upstream=profile.upstream_name, scheme=scheme,
            host_header=host_header, conn_header=conn_header, ssl_lines=ssl_lines))
        lines.extend([
            "    }",
            "}\n"
        ])
        return "\n".join(lines)

    # ----------------------------------------------------------------------
    # location 体渲染 (通用 `location /` 与 path_rules 共用的**单一真源**)
    # ----------------------------------------------------------------------
    @classmethod
    def _render_location_body(cls, profile: ServiceProfile, upstream: str, scheme: str,
                              host_header: str, conn_header: str, ssl_lines: list,
                              rule=None, cache_suffix: str = "",
                              extra_headers: Optional[Dict[str, str]] = None) -> list:
        """产出一个 location 块的完整行 (不含 `location x {` 与 `}` 本身)

        为什么要抽出来 (2026-10-04, 实现 path_rules 时): 路径专属 location 必须与通用
        location **同款**代理管线 —— 缺 `proxy_http_version 1.1` 就没有 keepalive,
        缺 `Connection ""` 字面量就每次新建连接。复制一份的下场是本项目反复踩过的
        "两处模板漂移", 故收敛为唯一实现。

        缓冲/超时的判据 (与原实现逐字等价, 只是可被 rule 覆盖):
          · 零缓冲的条件 = 未开缓存 且 (dev 组 ‖ 该 rule 显式 buffering=False);
          · 超时默认 dev 组 3600s、其余 60s, rule.read_timeout / send_timeout 可覆盖。
        """
        # 零缓冲判定: 未开缓存且 (dev 组或该路径显式关缓冲)
        no_buf = False
        if not profile.enable_cache:
            if profile.group == "dev" or (rule is not None and rule.buffering is False):
                no_buf = True

        default_to = 3600 if profile.group == "dev" else 60
        read_to, send_to = default_to, default_to
        if rule is not None:
            if rule.read_timeout is not None:
                read_to = int(rule.read_timeout)
            if rule.send_timeout is not None:
                send_to = int(rule.send_timeout)

        out = [
            f"        proxy_pass {scheme}://{upstream};",
            "        proxy_http_version 1.1;",
            "        proxy_set_header Upgrade $http_upgrade;",
            # 必须是字面量空串, 不能写 $connection_upgrade —— 实测两者的行为并不等价:
            # nginx 只在值是编译期字面量空串时才真正"删除该头"; 变量求值得到的空串
            # 仍会发出空的 Connection 头, upstream 因此不进入 keepalive 复用。
            # 实测同一服务: 用 map 变量时 TTFB 恒为 0.55~0.71s 且上游 ESTABLISHED=0;
            # 改成 "" 后第 3 个请求起稳定降到 0.22~0.24s, 上游保留 3 条长连接。
            f"        proxy_set_header Connection {conn_header};",
            f"        proxy_set_header Host {host_header};",
            "        proxy_set_header User-Agent $http_user_agent;",
            "        proxy_set_header Accept-Encoding $http_accept_encoding;",
            "        proxy_set_header Accept-Language $http_accept_language;",
            *ssl_lines,
        ]

        # 本地静态资源/图片磁盘缓存挂载
        if profile.enable_cache:
            out.extend([
                "        # 开启本地磁盘缓存 (消除频次冲击与 0ms 秒开)" + cache_suffix,
                "        proxy_cache pixiv_img_cache;",
                "        proxy_cache_valid 200 304 7d;",
                "        proxy_cache_valid 404 1m;",
                "        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;",
                "        proxy_cache_revalidate on;",
                "        proxy_cache_lock on;",
                "        add_header X-Cache-Status $upstream_cache_status;",
            ])

        # Steam 商店与社区防网关 Portal 劫持重定向 (阻断深澜 srun 等局域网认证页面渗透到客户端)
        if profile.id in ("steam_store", "steam_community"):
            out.append("        # 防网关 Portal 劫持重定向，阻断局域网登录地址下发给客户端")
            out.append("        proxy_redirect ~*^https?://(?:172\\.|192\\.168\\.|10\\.|.*srun.*|.*portal.*)(.*)$ /;")

        # Steam 社区重定向防死循环自适应
        if profile.id == "steam_community":
            out.extend([
                "        proxy_redirect default;",
                "        proxy_redirect http:// https://;",
            ])
            if profile.group != "dev":
                out.append("        proxy_force_ranges on;")

        # 针对开发生态 (Git/GitHub/GitLab/大文件) 开启全链路流式零缓冲、Range 穿透与超长超时
        #
        # ⚠ 逐字等价于重构前的实现, 别"顺手化简" (2026-10-04 曾在重构中漏掉这一段,
        #   由"渲染结果与磁盘既有配置逐字节对比"当场抓到):
        #   dev 组**无条件**带 Range 透传 + request 零缓冲 + force_ranges, 与是否开缓存无关;
        #   只有 **response** buffering 由 enable_cache 决定 (开缓存必须保留缓冲, 否则缓存空转)。
        _dev_block = (profile.group == "dev" and rule is None)
        if _dev_block:
            if profile.enable_cache:
                out.append("        # 大文件与 Git Smart HTTP 极速流式透传配置 (彻底消灭磁盘 I/O 缓冲假死)")
                # ⚠ proxy_buffering off 与 proxy_cache **互斥** —— 二者不可同时出现在一个 location。
                # 实测依据 (2026-10-01, 本地 nginx 最小复现, 见 cache_probe 实验): 同一 location
                # 同时写 `proxy_cache` 与 `proxy_buffering off` + `proxy_max_temp_file_size 0` 时,
                # 第二次请求 `$upstream_cache_status` 仍是 MISS、源站被重新命中 (seq 4→5);
                # 仅把缓冲改回 on, 第二次即 HIT。原因: nginx 需要缓冲响应体才能落盘缓存。
                # 影响面 (修复前): 所有 group=dev 且 enable_cache=True 的画像缓存**全是空转**
                # (google_fonts / jsdelivr / npm / pypi / crates 等), 白白多打一次回源。
                # 故: 开了缓存的画像保留缓冲 (缓存优先), 未开缓存的才走零缓冲流式透传。
                out.append("        proxy_buffering on;   # 本画像开了磁盘缓存, 必须保留缓冲否则缓存不生效 (见上)")
                out.extend([
                    "        proxy_request_buffering off;",
                    "        proxy_force_ranges on;",
                    "        proxy_set_header Range $http_range;",
                    "        proxy_set_header If-Range $http_if_range;",
                ])
            else:
                out.append("        # 大文件与 Git Smart HTTP 极速流式透传配置 (彻底消灭磁盘 I/O 缓冲假死)")
                out.extend([
                    "        proxy_buffering off;",
                    "        proxy_max_temp_file_size 0;",
                    "        proxy_request_buffering off;",
                    "        proxy_force_ranges on;",
                    "        proxy_set_header Range $http_range;",
                    "        proxy_set_header If-Range $http_if_range;",
                ])
        elif no_buf:
            # 路径规则显式关缓冲 (dev 组未开缓存的情形已由上面的 no_buf 覆盖)
            out.extend([
                "        proxy_buffering off;",
                "        proxy_max_temp_file_size 0;",
                "        proxy_request_buffering off;",
                "        proxy_force_ranges on;",
                "        proxy_set_header Range $http_range;",
                "        proxy_set_header If-Range $http_if_range;",
            ])

        # 路径规则自己的头 (追加/覆盖; 空值表示删除该头, 与 nginx 语义一致)
        for _k, _v in (extra_headers or {}).items():
            out.append(f"        proxy_set_header {_k} {_v};")

        # 连接超时不再在这里写死 —— 见文件头的"上游快速失败策略"。
        # 原注释曾写"持续失败的节点由 max_fails=3/fail_timeout=30s 熔断",
        # 那句话**与代码不符** (cdn_optimizer 早已改成 max_fails=1/fail_timeout=5s),
        # 属于典型的"注释描述了一个不存在的实现", 已随本次收口删除。
        out.extend([
            f"        proxy_read_timeout {read_to}s;",
            f"        proxy_send_timeout {send_to}s;",
        ])

        # 状态码白名单仅限 nginx 编译期支持的这几个 (403/404/429/500/502/503/504),
        # 写 http_400 会导致 nginx 直接 [emerg] invalid value 起不来 —— 已实测验证。
        # 因此"上游返回 400"无法靠重试规避, 只能靠清理候选池中恒 400 的节点解决。
        #
        # http_404 默认【不】加入: githubassets / crates.io / google_fonts 等服务的
        # 根路径 404 属正常响应, 一律重试纯属浪费。仅当 profile 标记了 retry_on_404
        # (即已确认 upstream 内混有"错误 vhost"节点) 时才附带 —— nginx 的 max_fails
        # 熔断只对连接失败/超时生效, 对"成功返回 404"完全无感, 不重试就等于把错误
        # vhost 的 404 原样透传给用户 (minecraft "频繁 Page not found" 的直接成因)。
        retry_codes = _strip_retry_403(
            "http_403 http_429 http_404 http_500 http_502 http_503 http_504"
            if getattr(profile, "retry_on_404", False)
            else "http_403 http_429 http_500 http_502 http_503 http_504"
        )
        out.append(f"        proxy_next_upstream error timeout {retry_codes} non_idempotent;")
        # 三件套 (connect / tries / 总预算) 统一由 upstream_failover_lines 产出 ——
        # 不再在这里手写, 否则又会和别的模板漂移 (原先就是那样)。
        out.extend(upstream_failover_lines("        "))
        return out

    @classmethod
    def _render_path_rule_locations(cls, profile: ServiceProfile, ssl_lines: list,
                                    host_header: str, scheme: str) -> list:
        """把 `profile.path_rules` 渲染成**额外的 location 块** (2026-10-04 新增)

        在此之前 `path_rules` 是**只声明不渲染**的死字段 (见 service_profile.PathRule 注释),
        于是"某路径关缓冲 / 改超时"根本无法表达 —— civitai 草案的 `/api/download/` 关缓冲
        要求正是卡在这里。

        两条硬约束在生成期**响亮报错** (而不是静默降级):
          ① `buffering=False` 与 `enable_cache=True` 互斥 —— nginx 需要缓冲才能落盘缓存,
             同时写会让缓存**永远 MISS** (实测过), 属"看起来生效其实空转";
          ② 同路径重复声明 ⇒ location 重名 ⇒ nginx [emerg] 拒载整个配置。
        """
        rules = list(getattr(profile, "path_rules", ()) or ())
        if not rules:
            return []
        seen = set()
        out: list = []
        for rule in rules:
            path = str(getattr(rule, "path", "") or "").strip()
            if not path:
                raise ValueError(f"画像 {profile.id}: path_rule 缺少 path")
            if path in seen:
                raise ValueError(
                    f"画像 {profile.id} 重复声明了同一路径 {path!r} —— "
                    f"nginx 会因 location 重名而 [emerg] 拒载")
            seen.add(path)
            if rule.buffering is False and profile.enable_cache:
                raise ValueError(
                    f"画像 {profile.id} 的路径 {path!r} 声明了 buffering=False, 但该画像 "
                    f"enable_cache=True —— 二者互斥 (nginx 需要缓冲才能落盘缓存, 同时写会让"
                    f"缓存永远 MISS)。请二选一。")
            upstream = rule.proxy_pass or profile.upstream_name
            if not upstream:
                raise ValueError(f"画像 {profile.id} 的路径 {path!r} 无法确定上游")
            conn = '"upgrade"' if getattr(rule, "websocket", False) else '""'
            out.append(f"    location {path} {{")
            out.append(f"        # [path_rule] buffering={rule.buffering}")
            out.extend(cls._render_location_body(
                profile, upstream=upstream, scheme=scheme, host_header=host_header,
                conn_header=conn, ssl_lines=ssl_lines, rule=rule,
                cache_suffix=" (path_rule)", extra_headers=rule.custom_headers))
            out.append("    }")
            out.append("")
        return out

    @classmethod
    def _render_pixiv_web_server(cls, profile: ServiceProfile,
                                 ech_services: Optional[Set[str]] = None) -> str:
        """渲染 Pixiv 主站专用规则 (包含 /ajax/ CORS 与 /ws/ WebSocket)

        ECH 分支: 当该服务本次确实走隧道时, 上游指向本地回环上的明文 HTTP
        入口 (ECH 隧道), 真正的 TLS 与 ECH 握手由隧道自己发起。此时必须完全
        不输出 proxy_ssl_* —— 否则形成 TLS-in-TLS, 隧道无法在中间注入 ECH 扩展。
        """
        main_domains = [d for d in profile.domains if d != "lc-event.pixiv.net"]
        domains_str = " ".join(main_domains)
        # ★ 摘掉 http_403 (见 _strip_retry_403): 403 是重试改变不了的结果,
        #   而 nginx 侧带 non_idempotent ⇒ 留在列表里会让同一个 POST 被重放。
        retry_codes = _strip_retry_403(
            "http_403 http_429 http_404 http_500 http_502 http_503 http_504")

        ech = cls._use_ech(profile, ech_services)
        scheme = "http" if ech else "https"
        if ech:
            banner = f"# {profile.name} (经本地 ECH 隧道直连 Cloudflare)"
            ssl_opts = ""
        else:
            banner = f"# {profile.name} (采用空 SNI 策略，绕过 GFW SNI 阻断)"
            ssl_opts = """        proxy_ssl_name "";
        proxy_ssl_server_name on;
        proxy_ssl_verify off;
        proxy_ssl_session_reuse on;
"""
        # 快速失败三件套 (connect / tries / 总预算) —— 本模板的 4 个 location 原先
        # **一个都没写**, 于是全部继承 nginx.conf 的全局值: connect 5s 且 **tries 不限**,
        # 池里 5 个候选全死时要串行等 5×5=25s。见文件头"上游快速失败策略"。
        failover = "\n".join(upstream_failover_lines("        "))

        return f"""{banner}
server {{
    listen 80;
    listen 443 ssl;
    http2 on;
    server_name {domains_str};

    client_max_body_size 50M;

    location / {{
        proxy_pass {scheme}://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "";   # 字面量空串才能让 upstream keepalive 生效, 见 _render_generic 注释
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_max_temp_file_size 0;
        proxy_buffering off;
{ssl_opts}        proxy_next_upstream error timeout {retry_codes} non_idempotent;
{failover}
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }}

    location /ajax/ {{
        proxy_pass {scheme}://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "";   # 字面量空串才能让 upstream keepalive 生效, 见 _render_generic 注释
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_max_temp_file_size 0;
        proxy_buffering off;
{ssl_opts}{_CORS_ADD_HEADERS}
        proxy_next_upstream error timeout {retry_codes} non_idempotent;
{failover}
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }}

    location /ws/ {{
        proxy_pass {scheme}://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Connection "upgrade";
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_max_temp_file_size 0;
        proxy_buffering off;
{ssl_opts}{_CORS_ADD_HEADERS}
{failover}
        proxy_read_timeout 7200s;
        proxy_send_timeout 7200s;
    }}
}}

# Pixiv lc-event 专属流
server {{
    listen 80;
    listen 443 ssl;
    http2 on;
    server_name lc-event.pixiv.net;

    location / {{
        proxy_pass {scheme}://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "";   # 字面量空串才能让 upstream keepalive 生效, 见 _render_generic 注释
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_max_temp_file_size 0;
        proxy_buffering off;
{ssl_opts}        proxy_next_upstream error timeout {retry_codes} non_idempotent;
{failover}
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }}
}}
"""
    @classmethod
    def _render_pixiv_img_server(cls, profile: ServiceProfile) -> str:
        """渲染 Pixiv pximg 插画 CDN 专用规则 (带磁盘缓存与 Range 续传)

        server_name 由 *.pximg.net 通配 + profile.domains 组成 (原先硬编码,
        导致改 domains 后此处静默失配 —— 例如已迁走的 source.pixiv.net 仍被
        列在此处, 而新纳入的 booth.pximg.net 反而漏掉)。
        """
        names = list(dict.fromkeys(["*.pximg.net"] + list(profile.domains)))
        domains_str = " ".join(names)
        # ★ M17: 必须**尊重声明式字段 enable_cache**, 不能无条件写 proxy_cache
        #   (通用渲染器是会查的: 见 render_server_block 里的 `if profile.enable_cache:`)。
        #   原实现对这个特例渲染器硬写缓存指令 —— 于是"画像说不要缓存, 生成物却缓存"。
        #   当前 `pixiv_img` 恰好 enable_cache=True, 所以行为没变; 但这是**声明被忽略**的
        #   潜伏缺陷: 一旦按需关掉缓存, 生成物会与声明不符而不报错。
        cache_block = ""
        if getattr(profile, "enable_cache", False):
            cache_block = (
                "        proxy_cache pixiv_img_cache;\n"
                "        proxy_cache_valid 200 304 30d;\n"
                "        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;\n"
                "        add_header X-Cache-Status $upstream_cache_status;\n"
            )
        # 快速失败三件套。★ 这里原来是 `proxy_next_upstream_timeout 60;` —— **没有单位**,
        # nginx 按秒解释 = 60 秒, 等于没设上界; 而且它是本块唯一的超时相关指令
        # (connect 继承全局 5s、tries 完全不限)。这是"同一份配置三种口径"的又一例。
        failover = "\n".join(upstream_failover_lines("        "))
        return f"""# {profile.name} (带本地图片磁盘缓存与 Range 断点续传)
server {{
    listen 80;
    listen 443 ssl;
    http2 on;
    server_name {domains_str};

    location / {{
        proxy_pass https://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "";   # 字面量空串才能让 upstream keepalive 生效, 见 _render_generic 注释
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_set_header Referer "https://www.pixiv.net/";
        proxy_set_header Sec-Fetch-Site "cross-site";
        proxy_ssl_name "";
        proxy_ssl_server_name on;
        proxy_ssl_verify off;
        proxy_ssl_session_reuse on;
{cache_block}        proxy_force_ranges on;
        proxy_next_upstream error timeout {_strip_retry_403("http_403 http_429 http_404 http_500 http_502 http_503 http_504")} non_idempotent;
{failover}
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }}
}}
"""

    @classmethod
    def generate_all(cls, target_dir: Path = CONF_DIR,
                     ech_services: Optional[Set[str]] = None,
                     h3_services: Optional[Set[str]] = None) -> Dict[str, str]:
        """全量渲染并**原子写入**三大站点配置文件

        ★ 与旧实现的差别 (2026-10-03, 原缺陷 M1): 这里现在**真的**是原子写。
          旧实现在本函数里对三个文件各做一次裸 `write_text`, 而 docstring 却写着
          "原子写入" —— 注释与代码相反。裸写在 nginx reload/崩溃窗口里会被读到半截内容,
          而 site-*.conf 与 upstream-dynamic.conf 是**一对**(引用与定义),
          混合状态会让 nginx **整体拒载**(见 tests/test_config_pair.py)。
          现在: 渲染与落盘分离, 落盘走 `_atomic_write_text` (tmp + os.replace)。

        ⚠ 本函数**只保证单文件原子**。跨三个文件的事务由 `NginxManager.test_config()`
          的"预检通过才提交"负责 (那一步也保证预检本身不改动被跟踪文件)。

        ech_services 为走 ECH 隧道的服务 id 集合 (决定 proxy_pass 用 http 还是
        https)。缺省时从 target_dir 下已生成的 upstream-dynamic.conf 反推 —— 即
        以实际写进上游的后端为准, 保证两者不会脱钩; 该文件尚不存在时回退到隧道
        实时健康检查。
        """
        results = cls.render_all(target_dir, ech_services, h3_services)
        for name, content in results.items():
            _atomic_write_text(target_dir / name, content)
        return results

    @classmethod
    def render_all(cls, target_dir: Path = CONF_DIR,
                   ech_services: Optional[Set[str]] = None,
                   h3_services: Optional[Set[str]] = None) -> Dict[str, str]:
        """渲染三大站点配置并返回 {文件名: 内容}, **不落盘**

        拆出来的理由: `NginxManager.test_config()` 需要"先在临时目录里渲染 + 预检,
        通过了才提交", 而那个流程绝不能顺手改动正式文件 (那正是 M1 的另一半:
        `test_config()` 自称只读却每次重写被跟踪的 `site-*.conf`)。
        """
        target_dir.mkdir(parents=True, exist_ok=True)
        results = {}
        upstream_conf = target_dir / "upstream-dynamic.conf"
        if ech_services is None:
            ech_services = cls._ech_services_from_upstream(upstream_conf)
        if h3_services is None:
            h3_services = cls._h3_services_from_upstream(upstream_conf)

        # 动态 upstream 名单 (用于回落判定, 见 _static_fallback_upstream 注释)
        defined = cls._upstream_names_in_file(upstream_conf)

        def _fallback_for(profiles):
            """为缺动态 upstream 的 L7 画像生成内联 upstream 块

            为什么必须做: 缺了它, 生成物里会出现 `proxy_pass https://;` —— nginx **整体拒载**
            (实测 `nginx -t` 报 "no host in upstream \"\""), 于是**全部服务一起挂**, 而现场
            看起来只是"刚加了一个画像"。这种"局部问题导致全局故障"必须在生成期就挡住。
            若画像连静态 candidate_ips 都没有, 只能**明确报错**而不是输出空 upstream。
            """
            blocks, broken = [], []
            for p in profiles:
                # 只对**普通 L7 画像**做回落判定:
                #   · h3_upstream 画像的 upstream 由 cdn_optimizer 无条件写成
                #     `server 127.0.0.1:44411` (指向本机腿), 不依赖候选池;
                #   · ech_enabled 画像的 upstream 由隧道写入, 同理;
                #   · 二者在此之前就可能"没被写进动态文件", 若一并判为缺配就会误报
                #     (实测: 加了本检查后 googlevideo 被误判为"无动态 upstream")。
                if getattr(p, "h3_upstream", False) or getattr(p, "ech_enabled", False):
                    continue
                name = getattr(p, "upstream_name", "") or ""
                if not name:
                    broken.append(f"{p.id} (未设置 upstream_name)")
                    continue
                if name in defined:
                    continue
                blk = cls._static_fallback_upstream(p)
                if blk:
                    blocks.append(blk)
                else:
                    broken.append(f"{p.id} (无动态 upstream 且无 candidate_ips)")
            if broken:
                raise ValueError(
                    "以下服务无法生成有效的 upstream, 会产出非法配置并导致 nginx 整体拒载: "
                    + "; ".join(broken))
            return blocks

        # ★ 按分组表遍历 (2026-10-03) —— 原先只渲染 gaming/acg/dev 三个硬编码分组,
        #   于是新增分组 (adult) 的画像会**静默进不了任何站点配置**: 实测把 adult 画像挂进
        #   PROFILES 后 render_all 的任何输出里都找不到它, 浏览器只能打到 default_server(444)
        #   ⇒ "服务等于没加"且无报错。现在遍历 SITE_FILE_FOR_GROUP, 并保证四点:
        #     ① 每个分组一个文件 (新增分组只需在 service_profile 里加一行映射);
        #     ② 每组的注释头/CORS map/Steam 分流 map 与改造前**逐字一致** (既有测试在守);
        #     ③ 缺映射的分组**当场报错**, 而不是静默丢弃 (见下面的兜底检查);
        #     ④ 产物顺序与文件名保持稳定 (gaming → acg → dev → adult)。
        for group, filename in SITE_FILE_FOR_GROUP.items():
            group_profiles = [p for p in PROFILES
                              if p.group == group and p.mode not in NGINX_BYPASS_MODES]
            title = SITE_GROUP_TITLES.get(group, f"{group} 加速规则")
            if group == "acg":
                blocks = [
                    "# ==============================================================================",
                    f"# GameArt Toolkit - {title} (由 ServiceProfile 模板自动生成)",
                    "# ==============================================================================",
                    # CORS 来源白名单必须在 http 层声明 (nginx 的 map 只能出现在 http 上下文)
                    _CORS_MAP.rstrip("\n"),
                    "",
                ]
            else:
                blocks = [
                    "# ==============================================================================",
                    f"# GameArt Toolkit - {title} (由 ServiceProfile 模板自动生成)",
                    "# ==============================================================================\n",
                ]
            # Steam 社区 Host 分流 map: api.steampowered.com 保持原 Host 路由 API 网关,
            # 其余域名 (steamcommunity.com 及子域) 归一化到主域防 118 (由 steam_community 渲染引用)
            if group == "gaming" and any(p.id == "steam_community" for p in group_profiles):
                blocks.append(
                    "map $host $steam_upstream_host {\n"
                    "    hostnames;\n"
                    "    api.steampowered.com api.steampowered.com;\n"
                    "    default steamcommunity.com;\n"
                    "}\n"
                )
            blocks.extend(_fallback_for(group_profiles))
            for p in group_profiles:
                blocks.append(cls.render_server_block(p, ech_services, h3_services))
            results[filename] = "\n".join(blocks)

        # 兜底: 画像的 group 若没有对应站点文件, 就是"静默丢弃" —— 必须响亮地失败
        _unmapped = sorted({p.group for p in PROFILES if p.mode not in NGINX_BYPASS_MODES}
                           - set(SITE_FILE_FOR_GROUP))
        if _unmapped:
            raise ValueError(
                "这些分组没有对应的站点配置文件, 其中的画像会被静默丢弃 (既不生效也不报错): "
                f"{_unmapped} —— 请在 service_profile.SITE_FILE_FOR_GROUP 里登记, "
                "并在 nginx/conf/nginx.conf 里 include 对应文件")

        return results


# ==============================================================================
# 模块级辅助 (必须在 class 之后定义: 见下方 _CORS_* 与 _strip_retry_403 的说明)
# ==============================================================================

# 临时文件序号 (进程内自增): 与 pid/线程 id 一起保证**并发写同一目标时 tmp 不重名**。
# 见 _atomic_write_text 的说明 —— 写死 `.tmp` 会被并发调用互相移走, 报 FileNotFoundError。
_TMP_SEQ = 0
_TMP_SEQ_LOCK = threading.Lock()


def _next_tmp_seq() -> int:
    global _TMP_SEQ
    with _TMP_SEQ_LOCK:
        _TMP_SEQ += 1
        return _TMP_SEQ


def _atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    """把 text **原子地**写到 path (临时文件 + os.replace) —— 原缺陷 M1

    ## 为什么必须有

    原实现在 `generate_all()` 里对三个站点配置各写一次裸 `write_text`
    (`:652/:667/:682`), 而函数 docstring 却写着"**全量渲染并原子写入**三大站点配置文件"。
    注释与代码相反 ⇒
      · nginx 可能在**写了一半**的时候读到配置 (reload / 崩溃窗口);
      · 任一次写失败会留下"部分新 + 部分旧"的**混合状态**, 而 upstream 与 site 是**一对**
        (见 tests/test_config_pair.py 的说明: 引用不到定义的 upstream 会让 nginx **整体拒载**);
      · 没有临时文件就没有回滚点。

    本函数只保证"单个文件要么全是新内容、要么全是旧内容"(os.replace 在同一卷上是原子的),
    跨文件的事务由 `test_config()` 的"预检通过才提交"负责。

    ★ 临时文件名必须**唯一** (2026-10-03 实测事故): 原先写死 `path + ".tmp"`, 于是两个
    并发调用 (UI 生成 + 健康巡检重生成 / pytest-xdist 两个 worker 同时收集
    `tests/test_regression.py` 的模块级 generate_all) 会互相踩:
      A 建 tmp → B 覆盖同一 tmp → A `os.replace` **把 tmp 移走** → B `os.replace` 报
      `FileNotFoundError: site-gaming.conf.tmp -> site-gaming.conf`。
    这不只是测试问题 —— 生产里两个线程同时生成配置就会抛异常, 而下面的重试只覆盖
    `PermissionError` (共享冲突), 覆盖不到"tmp 已被别人移走"。故按 pid+线程+序号命名。
    """
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}."
                         f"{_next_tmp_seq()}.tmp")
    try:
        import time as _time
        # ⚠ 不传 newline="": 与原先的 `Path.write_text(text, encoding="utf-8")` 保持
        #   **逐字一致**的行尾行为 (文本模式下 \n 会按平台转成 os.linesep)。
        #   传了 newline="" 会让同样内容写出不同的行尾 ⇒ 每次预检都判定"内容变了"
        #   而重写三个文件, 制造无意义的 diff 与 mtime 抖动 (实测踩到)。
        with open(tmp, "w", encoding=encoding) as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        # ★ Windows 上 `os.replace` 会因**瞬时共享冲突**失败 (实测 WinError 5 拒绝访问,
        #   当时是另一个进程/线程正读同一个 site-*.conf)。这不是逻辑错误而是竞态窗口,
        #   重试几次即可越过; 但**绝不能静默放弃** —— 最后仍失败就抛出, 让调用方看到
        #   "这次写入没成功", 而不是留下一个陈旧的配置当成功。
        last = None
        for attempt in range(5):
            try:
                os.replace(tmp, path)
                return
            except PermissionError as e:      # WinError 5 / 32 都属于这一类
                last = e
                _time.sleep(0.05 * (attempt + 1))
        raise last if last else PermissionError(f"无法替换 {path}")
    except Exception:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass
        raise


def _render_all(target_dir: Path,
                ech_services: Optional[Set[str]] = None,
                h3_services: Optional[Set[str]] = None) -> Dict[str, str]:
    """兼容别名: 渲染三大站点配置, 只返回文本、不落盘

    与 `NginxConfGenerator.render_all` 等价; 保留模块级别名是为了让
    `NginxManager.test_config()` 能用一个**明显的只读名字**调用它 ——
    那个函数曾经因为顺手调用 `generate_all()` 而每次启动都重写被跟踪的
    `site-*.conf` (原缺陷 M1)。
    """
    return NginxConfGenerator.render_all(target_dir, ech_services, h3_services)



#
# 原实现是 `proxy_hide_header Access-Control-Allow-Origin;` +
# `add_header Access-Control-Allow-Origin $http_origin always;` —— 把**任意**
# Origin 原样反射回去, 等于**拆掉上游自己的来源限制**:
# 任意站点页面做 `fetch("https://www.pixiv.net/ajax/...", {credentials:'include'})`
# 都会拿到 `ACAO: https://evil.com`; 若上游带 `ACAC: true`, 浏览器即放行跨源读取
# 已登录数据。而且原实现**没有一并隐藏** `Access-Control-Allow-Credentials`,
# 也不发 `Vary: Origin` (后者会让共享缓存把一个来源的响应发给另一个来源)。
#
# 现在: 只有名单内的来源才回填 ACAO (名单外得到空值 = 相当于不发该头);
# 同时隐藏上游的 ACAC 并显式补 `Vary: Origin`。
# ⚠ 为什么放在类定义**之后**: 这些名字必须与 NginxConfGenerator 处于同一模块作用域,
#    而类方法体内的引用是运行时解析的 —— 因此位置只需在**调用时**已定义即可。
_CORS_MAP = """    # CORS 来源白名单 (不反射任意 Origin) —— 见 app/nginx_generator.py 的注释
    map $http_origin $cors_pixiv_origin {
        default "";
        "~^https://(www\\.)?pixiv\\.net$" $http_origin;
    }
"""

_CORS_ADD_HEADERS = """        proxy_hide_header Access-Control-Allow-Origin;
        proxy_hide_header Access-Control-Allow-Credentials;
        add_header Access-Control-Allow-Origin $cors_pixiv_origin always;
        add_header Vary Origin always;"""


def _strip_retry_403(codes: str) -> str:
    """从 proxy_next_upstream 的状态码列表里摘掉 `http_403` (2026-10-03, 原缺陷 H7)

    为什么必须摘: 本腿会把 gvs 的**正常** 403 原样透传 (非 Google 段/签名无效时的标准应答)。
    把 403 放进重试列表 ⇒ 每次 403 都要再投一遍上游, 而 nginx 侧本来就带
    `non_idempotent`, 于是同一个 POST 会被**重放**。对按 token 计费的生成端点,
    重放等于让用户多付一次钱; 而 403 是重试**改变不了**的结果 (它不是瞬时故障)。
    """
    return " ".join(c for c in str(codes).split() if c != "http_403")

