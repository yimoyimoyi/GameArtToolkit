# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 统一声明式服务元数据模型与配置体系 (Service Profile)

核心功能:
- 声明式定义各加速服务的元数据、域名、路径规则、加速模式 (L7 Nginx / L4 Relay / Direct)
- 集中管理 SNI 策略 (host / empty / 伪 SNI) 与 CDN 候选 IP 池
- 提供统一的数据源，消除跨模块配置漂移 (Single Source of Truth)
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple


class ServiceMode(str, Enum):
    """服务加速模式"""
    L7_NGINX = "l7_nginx"     # L7 HTTP/HTTPS 反向代理与缓存 (Nginx)
    L4_RELAY = "l4_relay"     # L4 TCP 隧道转发 + SNI 嗅探路由 (轻量 Relay)
    DIRECT = "direct"         # 纯 DNS / Hosts 优选直连 (无 MITM, 直接与 CDN TLS 握手)
    QUIC_DIRECT = "quic_direct"  # 纯 DNS 引导 HTTP/3 (QUIC) 直连: 不应答 127.0.0.1, 且
                                 # 由本机解析器额外下发 HTTPS RR(alpn=h3) 让浏览器自行走 QUIC
                                 # —— TCP 侧 SNI 被 RST 但 UDP/443 放行的站点靠它可直连


class SniMode(str, Enum):
    """TLS SNI 模式"""
    HOST = "host"             # 使用客户端请求的原始 Host 域名作为 SNI
    EMPTY = "empty"           # 空 SNI (不发送 server_name 扩展，绕过 SNI 审查)
    CUSTOM = "custom"         # 使用指定伪装域名 (如 CloudFront 分发域名 / Akamai 状态页)


# ------------------------------------------------------------------------------
# 伪 SNI / 域名前置 (Domain Fronting) 的 CDN 厂商能力表
#
# 2026-10-01 无代理国内直连出口实测 (scripts/probe_uplift_routes.py):
#   同 IP 上「掩护 SNI + 真实 Host」的结果 ——
#     Fastly      : imgur 302 (证书 CN=*.imgur.com) / twitch 200 (证书 CN=twitch.tv)  => 放行
#     Akamai      : myanimelist 200 (掩护 steambroadcast.akamaized.net)                => 放行
#     Cloudflare  : patreon / nhentai / discord / fandom 全部 403                       => 要求 SNI=Host
#     CloudFront  : deviantart 421 Misdirected Request                                  => 要求 SNI=Host
# 因此「伪 SNI 一律无效」是过度概括: 该路线只对 Fastly / Akamai 系站点成立。
# ------------------------------------------------------------------------------
VENDOR_COVER_SNI = {
    "fastly": "www.fastly.com",
    "akamai": "steambroadcast.akamaized.net",
    # Google 属**同租户掩护**: g.cn 是 Google 自家的未被封锁短域名, 其边缘按 HTTP Host
    # 路由到真实站点。2026-10-01 P0 实测: 8/8 中转 IP × SNI=g.cn × 真实 Host 全部
    # 200/302, 上游证书 SAN 含 *.google.cn (Google Trust Services WR2/WE2)。
    # 注意: 这与 Fastly/Akamai 的跨租户掩护不同 —— Google 是自己掩护自己, 所以
    # 绝不能套用"CF/CloudFront 拒绝跨租户"的判断, 也不要反过来推广到其它厂商。
    "google": "g.cn",
}

# 逐服务验证过的额外掩护域名 (同 CDN、同段、且自身 SNI 未被封锁)。
# 与 VENDOR_COVER_SNI 的区别: 后者是"该厂商通用掩护", 这里是"某个具体服务的对症掩护"。
EXTRA_VERIFIED_COVERS = {
    "objects.githubusercontent.com": (
        "GitHub raw 家族对症掩护: 与 raw 同处 185.199.x 同段、自身 SNI 未被封锁。"
        "2026-10-01 实测 32 个 GitHub 域名中仅 raw.githubusercontent.com 被 SNI 硬阻断"
        "(4 IP × 3 轮 TCP 全通但 TLS 全 RST, IPv6 路径同样 RST), 而用本域名作掩护 SNI、"
        "Host 保持 raw.githubusercontent.com 时返回 200 与真实文件内容。"
    ),
}

VENDOR_COVER_UNSUPPORTED = {
    "cloudflare": "Cloudflare 要求 SNI 与 Host 一致, 掩护 SNI 实测返回 403",
    "cloudfront": "CloudFront 拒绝跨分发掩护 SNI (实测 421 Misdirected Request)",
}

# 「自分发掩护」例外: CloudFront 不接受**别的分发/别的租户**的域名作 SNI, 但允许用
# **同一个分发**的其他别名 (含其 *.cloudfront.net 默认域名) —— 这类用法不是域名前置,
# 而是该分发自身的合法入口。huggingface 即长期使用该分发的默认域名作 SNI。
VENDOR_SELF_DISTRIBUTION_SUFFIX = {
    "cloudfront": (".cloudfront.net",),
}


def is_self_distribution_cover(vendor: str, cover: str) -> bool:
    """判断掩护 SNI 是否属于该厂商的"同分发自有域名"例外"""
    suffixes = VENDOR_SELF_DISTRIBUTION_SUFFIX.get(str(vendor or "").strip().lower(), ())
    cover = str(cover or "").strip().lower()
    return bool(cover) and any(cover.endswith(s) for s in suffixes)


def suggest_cover_sni(vendor: str) -> Optional[str]:
    """按 CDN 厂商给出可用的掩护 SNI; 该厂商不支持时返回 None (调用方须放弃伪 SNI 路线)"""
    return VENDOR_COVER_SNI.get(str(vendor or "").strip().lower())



@dataclass
class PathRule:
    """特定路径的路由与转发规则

    ⚠ 2026-10-04 之前本类**只是声明, 从未被渲染** —— `nginx_generator` 里没有任何地方
    读过 `path_rules`, 测试也从未覆盖。也就是说 "改这个字段" 曾经**完全没有效果**, 而
    画像作者会以为它生效了 (civitai 草案正是栽在这里: 它要求 `/api/download/` 关缓冲,
    而那条要求当时无法表达)。现在由 `NginxConfGenerator._render_path_rule_locations`
    真正渲染; `tests/test_nginx_path_rules.py` 守住"字段真的会出现在配置里"。

    字段语义:
      · `path`            : location 前缀。nginx 按**最长前缀优先**匹配, 故更具体的路径
                            天然压过 `location /`, 与书写顺序无关。
      · `proxy_pass`      : 覆盖上游; 省略则沿用画像的 `upstream_name`。
      · `buffering`       : False ⇒ 关缓冲 (大文件直通, 不落磁盘临时文件)。
                            ⚠ 与 `enable_cache=True` **互斥** (nginx 需要缓冲才能落盘缓存),
                            同时声明会在生成期**响亮报错**, 而不是静默让缓存空转。
      · `websocket`       : True ⇒ 写 `Connection "upgrade"` (否则该路径的 WS 升级头会被清掉)。
      · `custom_headers`  : 追加/覆盖 `proxy_set_header`。
      · `read_timeout` / `send_timeout` : 该路径自己的超时 (秒)。省略则用画像默认值
                            (dev 组 3600s, 其余 60s)。大文件下载必须有它 —— 否则模型
                            动辄 2–7 GB, 60s 的读超时会在回源停顿处直接掐断。
    """
    path: str
    proxy_pass: Optional[str] = None
    buffering: bool = True
    websocket: bool = False
    custom_headers: Dict[str, str] = field(default_factory=dict)
    read_timeout: Optional[int] = None
    send_timeout: Optional[int] = None


@dataclass
class ServiceProfile:
    """声明式加速服务元数据定义"""
    id: str                                  # 唯一服务标识符 (如 pixiv_web, steam_community)
    group: str                               # 所属分类 (gaming / acg / dev)
    name: str                                # 友好中文名称
    desc: str                                # 服务描述说明
    domains: List[str]                       # 关联的域名列表
    icon: str = "zap"                        # MD3 矢量图标标识
    mode: ServiceMode = ServiceMode.L7_NGINX # 默认处理模式
    upstream_name: str = ""                  # Nginx upstream 标识符 (如 upstream_pixiv_web)
    ssl_sni_mode: str = "host"               # SNI 模式: 'host', 'empty', 或自定义伪装域名
    candidate_ips: List[str] = field(default_factory=list) # CDN 优质候选 IP 池
    enable_cache: bool = False               # 是否启用本地磁盘缓存
    path_rules: List[PathRule] = field(default_factory=list) # 特殊路径规则列表
    custom_headers: Dict[str, str] = field(default_factory=dict) # 自定义 HTTP 头部
    probe_timeout: Optional[float] = None    # 服务级探测档位 (秒), 覆盖全局 cdn_timeout_seconds
    stable_ips: List[str] = field(default_factory=list) # 已知稳定段 IP, 测速排序"稳优先"信号
    measure_throughput: bool = False          # 是否在测速时实测下行吞吐 (B/s), 用于大文件/git pack 排序
    probe_ok_statuses: Optional[Tuple[int, ...]] = None  # 额外放行的 HTTP 状态码 (默认 {2xx,3xx}+500; 用于根路径无文档/无权限的虚拟主机如 S3 403 / githubassets 404)
    probe_domains: Tuple[str, ...] = ()       # 探测验证的域名列表 (空 = 仅 domains[0]; 多域全部非可疑才算干净, 防 GFW 按子域特判封锁)
    # ★ 探测用的**真实内容链接** `(host, path)` (空 = 沿用旧的 `GET /`)。
    #   为什么需要它 (2026-10-04 实测, nhentai_img 案例):
    #     有一类服务**对根路径不应答** —— 实测:
    #       213.152.165.53  i.nhentai.net  /                  -> 连接 200 但 **0 字节**
    #       213.152.165.53  i.nhentai.net  /galleries/9/1.jpg -> 200 + **256054B**
    #     而 `probe_ip_endpoint_v2` 硬编码请求 `GET /` ⇒ 该画像**永远 0 个 rank0**
    #     (实测 4 个 probe_timeout 档位 1.5/3/5/8 全是 0/5), 于是 `apply_optimal`
    #     永远回退候选池兜底 —— 表现为"检测不可用、实际可用"。
    #   实测判别力对照 (好候选 vs 已知坏候选):
    #     · github_web —— 根路径已能判别 (坏候选稳定回 400) ⇒ 真实链接**无增益**, 故不设;
    #     · nhentai_img —— 根路径 0 字节(判不了), 真实图片路径给 200+256KB ⇒ **决定性**。
    #   ⇒ 只在"根路径确实判不了"的画像上设它, 不搞一刀切 (见下方取舍说明)。
    # ⚠ 三条实测约束, 设错会把好候选全判死:
    #   ① 必须是**(host, path)** 而不是裸 path —— 同一 IP 对不同 host 行为不同
    #      (t3.nhentai.net 只在 /galleries/9/1t.jpg 上回 200, i.nhentai.net 只在 1.jpg 上);
    #   ② 必须与 `ssl_sni_mode` 协同 —— nhentai_img 只有**空 SNI** 能取到图,
    #      真实/apex SNI 都 RST; 用真实链接但错 SNI 一样失败;
    #   ③ 必须选**不带鉴权**且**不随内容变更**的 URL —— 链接一失效, 全部候选被判死。
    probe_path: Optional[Tuple[str, str]] = None
    cdn_vendor: str = ""                      # 上游 CDN 厂商 (fastly/akamai/cloudflare/cloudfront), 决定伪 SNI 是否可行
    # 探测阶段的**证书域族硬门槛** (空 = 不检查)。2026-10-03 新增。
    #
    # 为什么需要它 (这是 `cdn_vendor` 覆盖不到的一类): "源站忽略 SNI、按 Host 路由"
    # 的站点 (如 play.dlsite.com / chan.sankakucomplex.com) 用无害 SNI 就能握手成功,
    # 且**证书仍是目标域自己的** —— 这类站点没有 CDN 厂商证书族可查
    # (VENDOR_CERT_SUFFIXES 只登记了 google), 于是 `cdn_vendor=""` 的画像**完全没有证书门槛**,
    # 而候选池探测只能看到状态码 ⇒ 别家 vhost / 链路侧劫持页的 2xx 会被当成"可用"收进池
    # (实测假可用形态: 证书 CN=fallback.wgcz.net / flirtify.com, 见
    #  docs/archive/service-expansion-feasibility-2026-10-03.md §7.1)。
    #
    # 语义: 对端证书的 SAN 必须落在这些**域族**内 (判据 = cover_sni.cert_matches_family,
    # 域族 = SAN 末两段标签)。于是:
    #   · "L7 + 空 SNI" 通道 (证书应仍是目标域的): cert_families=("ehgt.org",)
    #   · "源站忽略 SNI" 通道 (证书 CN=play.dlsite.com): cert_families=("dlsite.com",)
    # 与 `cdn_vendor` 的分工: 厂商证书族用于**共享 CDN 按 IP 选证书**的场景, 域族门槛用于
    # **证书必须属于目标自己**的场景; 两者可同时声明, 任一不过即硬淘汰该候选。
    cert_families: Tuple[str, ...] = ()
    skip_cdn_probe: bool = False              # 跳过 TCP/TLS 测速 (QUIC_DIRECT 服务 TCP 侧本就被 RST, 探测只会得到假阴性)
    requires_dns_backend: bool = False         # 必须由本机 DNS 下发解析结果才能生效 (QUIC 直连类)
                                               # —— 默认的 Hosts 模式无法传递 HTTPS RR, 这类服务在
                                               # Hosts 模式下"启用了也不可用", 因此不纳入默认启用
    # ★ 2026-10-03 (原缺陷 M13): 原先只有一个 `requires_dns_backend` 字段, 而它身上压着
    #   **两种完全不同的语义**, 于是每个消费方各自推导, 得出不同结论:
    #     · QUIC 直连类: 需要 DNS 下发 **HTTPS RR (alpn=h3)** —— Hosts 传不了这种记录类型;
    #     · googlevideo: 节点名是 `rr1---sn-xxxx.googlevideo.com` 这种**海量动态子域**,
    #       必须靠**后缀通配**覆盖 —— 与 HTTPS RR 毫无关系。
    #   旧代码把后者写成 `requires_dns_backend=True`, 而 `needs_wildcard_resolution()`
    #   又用 `requires_dns_backend and any(d.startswith("*."))` 二次推导 ——
    #   那个合取式正好把 S1 的缺陷藏住了 (通配被 NRPT 丢空时, 这个推导仍然说"需要通配")。
    #   现在拆成两个明确字段, 每个消费方读它真正需要的那个。
    needs_wildcard_resolution: bool = False     # 该画像依赖**后缀通配**覆盖动态子域 (与 HTTPS RR 无关)
    experimental_default_off: bool = False      # 标记为实验/通道性服务 ⇒ 不纳入默认启用
                                                # (原先借 `requires_dns_backend` 兼职这件事)
    proxy_connect_by_domain: bool = False     # 代理通道探测时 CONNECT 域名而非候选 IP (适配 Clash 按 IP 段 DIRECT 规则直连、CDN geo 限制中国 IP 的场景)
    ech_enabled: bool = False                 # 经本地 ECH 隧道直连 (要求目标托管在 Cloudflare; 见 docs/ech-tunnel-proposal.md)
    h3_upstream: bool = False                 # 上游腿改走本地 HTTP/3 代理 (app/h3_upstream.py):
                                              # 用于 TCP 被压制、只有 HTTP/3 可达的目标 (googlevideo)。
                                              # nginx 侧与 ECH 同款 —— 明文回环 + 不输出 proxy_ssl_*。
                                              # ⚠ 该通道可用性是分钟级时变的, 启用前必须先过
                                              #   `python -m app.gvs_h3_probe` 闸门
                                              #   (见 docs/googlevideo-quic-channel.md)
    websocket: bool = False                   # 该服务的 location / 需要透传 WebSocket 升级头 (Connection "upgrade")
    # 让 nginx 对上游 404 也执行换节点重试。
    # 通用模板默认【不】重试 404 —— 因为 githubassets / crates.io / google_fonts 等服务的
    # 根路径 404 属正常响应, 重试纯属浪费。但当 upstream 内混有"错误 vhost"节点时
    # (该节点对该域名返回 404 而非超时), 不重试就意味着 404 被原样透传给用户 ——
    # nginx 的 max_fails 熔断只对连接失败/超时生效, 对"成功返回 404"完全无感。
    # 故仅对已确认存在此类节点的服务开启 (minecraft / xbox, 详见各自 candidate_ips 注释)。
    retry_on_404: bool = False
    # 掩护 SNI 运行时通道 (app/cover_sni.py 的 CHANNELS 键)。
    # 为什么要**显式**声明, 而不是让 cover_sni 凭 cdn_vendor 猜: 同一个 cdn_vendor 下既有
    # "必须走掩护 SNI"的画像 (reddit/imgur), 也有"只钉真实 IP、浏览器用自身 SNI"的画像
    # (reddit_static) 与"掩护域是别人家"的画像 (github_raw 的 objects.githubusercontent.com)。
    # 凭 vendor 猜会把它们卷进同一条通道 —— 它们的探测 SNI 会被改写成掩护域, 且一旦该 vendor
    # 登记了证书族, cdn_optimizer 的证书硬门槛会淘汰它们整池 ("测速总失败"同类事故)。
    # 留空 = 完全不参与运行时回归, 行为与改造前一致。
    cover_sni_channel: str = ""

    def get_effective_sni(self, domain: str = "") -> Optional[str]:
        """获取实际用于 TLS 握手的 SNI 域名"""
        if self.ssl_sni_mode == "empty":
            return None
        elif self.ssl_sni_mode == "host":
            return domain or (self.domains[0] if self.domains else None)
        else:
            return self.ssl_sni_mode


# ==============================================================================
# 服务分组定义
# ==============================================================================
SERVICE_GROUPS = {
    "gaming": {
        "id": "gaming",
        "name": "游戏生态",
        "icon": "gamepad",
        "desc": "Steam 全生态、Battle.net、GOG、Xbox、Minecraft、Ubisoft"
    },
    "acg": {
        "id": "acg",
        "name": "二次元与创作者",
        "icon": "palette",
        "desc": "Pixiv全生态、Fanbox、BOOTH、VNDB、Fantia、Pixivision"
    },
    "dev": {
        "id": "dev",
        "name": "开发者与 AI",
        "icon": "terminal",
        "desc": "GitHub (Web/Raw/Releases/S3)、HuggingFace、GitLab、PyPI、npm、crates.io"
    },
    # --------------------------------------------------------------------------
    # 受控分组 (gated): **默认不显示、也不可启用**, 由设置页开关显式放开
    #   (2026-10-03 按用户决策新增; 开关键 = config.json 的 "gated_groups_enabled")
    #
    # 为什么把"成人内容"单列一组而不是塞进 acg (产品决策, 见复核报告 §六.1):
    #   · 与 Pixiv/Fanbox 混进同一张卡片会让该组 11 → 29 个服务, 且两类内容的
    #     使用场景与默认启用意愿完全不同;
    #   · 需要一道**默认关闭**的总闸: 关闭时该分组在控制台不出现, 且其中任何服务
    #     都无法启用 (三层拦截: 界面 → 配置加载清洗 → 默认启用清单, 见 ip_pool.config_store)。
    #
    # 本组已按批次落地画像 (2026-10-04 账目): 15 个 —— pawchive / pawchive_img /
    #   pawchive_dl / ehentai / nhentai / furaffinity / dlsite / cara / artstation_cdn /
    #   hitomi / pinimg / ehentai_img / nhentai_img / dlsite_play / sankaku。
    #   ⚠ 这里原先写的是"本组目前**没有任何画像**(18 个候选画像仍待按批次落地)" ——
    #     那是分批落地**之前**的说明, 早已过期且会造成错账目 (把"18 个候选"当成待办数)。
    #   `pyside_app` 的"暂未接入任何服务"是**按键为空**动态判断的, 不依赖本注释, 故此
    #   注释过期不会导致界面出错 —— 但它会误导下一个读者, 故一并更正。
    # --------------------------------------------------------------------------
    "adult": {
        "id": "adult",
        "name": "成人内容",
        "icon": "lock",
        "desc": "E-Hentai / nhentai / DLsite / JavDB 等成人平台（默认隐藏；需在设置中显式开启后才显示并允许启用）",
        "gated": True,
        "gate_note": "该分组默认隐藏且不可启用：其中的服务面向成人内容，且部分站点存在身份/合规与账号风险。"
                     "开启后才在控制台显示并允许启用。",
    }
}

# 分组 -> 站点配置文件 (单一真源)
#
# 为什么把这张表放在这里而不是散在生成器与 cdn_optimizer 各写一份 (2026-10-03 实测事故):
#   两边原先各自写死 `site-gaming/acg/dev` 三个文件, 于是新增分组 (adult) 时画像是
#   **静默进不了任何配置**的 —— render_all 只按三个 group 过滤, 结果 adult 画像在
#   所有 site-*.conf 里都找不到, 浏览器打到 default_server(444), 表现为"加了等于没加",
#   而且没有任何报错。新增这张表后: 生成器遍历它产出文件、cdn_optimizer 用它做
#   "upstream 引用是否都有定义"的校验清单, 两处不会再漂移。
# ⚠ 新增分组必须同时: ① 在这里加一行; ② 在 nginx/conf/nginx.conf 里加 include。
#   生成器会在 render 时**当场报错**提醒漏了 ①(见 NginxConfGenerator.render_all 的兜底)。
SITE_FILE_FOR_GROUP = {
    "gaming": "site-gaming.conf",
    "acg": "site-acg.conf",
    "dev": "site-dev.conf",
    "adult": "site-adult.conf",
}


# ==============================================================================
# 核心加速服务 Profile 注册表 (声明式单源定义, 支持运行时动态扩展)
# ==============================================================================
PROFILES: List[ServiceProfile] = [
    # --------------------------------------------------------------------------
    # 游戏生态
    # --------------------------------------------------------------------------
    ServiceProfile(
        id="steam_store",
        group="gaming",
        name="Steam 商店与结账",
        desc="解决 Steam 商店首页白屏、愿望单与购物车结账卡死",
        domains=["store.steampowered.com", "checkout.steampowered.com", "help.steampowered.com", "login.steampowered.com",
                    "*.steampowered.com"],   # ★ 显式通配 (原缺陷 M3, 同上)
        icon="shopping_bag",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_steam_store",
        cdn_vendor="akamai",
        ssl_sni_mode="steambroadcast.akamaized.net",  # 统一伪 SNI
        candidate_ips=["23.1.179.144", "23.46.229.9", "104.91.87.202", "96.7.99.225"]
    ),
    ServiceProfile(
        id="steam_community",
        group="gaming",
        name="Steam 社区与个人资料",
        desc="解决 118 错误代码、玩家动态、讨论区与徽章展示",
        domains=["steamcommunity.com", "api.steampowered.com",
                    "*.steamcommunity.com"],   # ★ 显式通配 (原缺陷 M3, 同上)
        icon="gamepad",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_steam_community",
        cdn_vendor="akamai",
        ssl_sni_mode="steambroadcast.akamaized.net",  # 实测最佳伪 SNI 绕过 GFW 且 Akamai 响应 200 OK
        candidate_ips=["23.1.179.144", "23.46.229.9", "104.91.87.202", "96.7.99.225"],
        # Host 分流 (由 nginx_generator 特判渲染 map 实现): api.steampowered.com 保持原 Host
        # 命中 API 网关 vhost (硬编码主域会导致 API 路径被上游 302 到社区首页),
        # steamcommunity.com 及子域才归一化到主域防 118
        custom_headers={"Host": "steamcommunity.com"}
    ),
    ServiceProfile(
        id="steam_akamai",
        group="gaming",
        name="Steam 静态图片 CDN",
        desc="解决好友头像加载失败、创意工坊 Mod 预览图破图",
        domains=["community.akamai.steamstatic.com", "avatars.akamai.steamstatic.com", "clan.akamai.steamstatic.com",
                 "steamcommunity-a.akamaihd.net", "steamuserimages-a.akamaihd.net",  # 创意工坊封面/用户上传图
                 "cdn.akamai.steamstatic.com", "community.cloudflare.steamstatic.com",
                    "*.steamstatic.com"],  # 静态资源 CDN + ★显式通配 (原缺陷 M3)
        icon="zap",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_steam_akamai",
        cdn_vendor="akamai",
        ssl_sni_mode="steambroadcast.akamaized.net",  # 统一伪 SNI
        enable_cache=True,  # 开启本地磁盘缓存，防击穿并消除频次冲击
        # 403/404 放行: Akamai 对 steamstatic 根路径返回 403 (无根文档, 实测确定性响应,
        # 真实图片路径 /user/xxx.jpg 正常 200), 与 githubassets 404 同类的"根路径探测误杀"
        probe_ok_statuses=(403, 404),
        candidate_ips=["23.1.179.144", "23.46.229.9", "23.32.91.49", "184.27.185.73"]
    ),
    ServiceProfile(
        id="ubisoft",
        group="gaming",
        name="Ubisoft 育碧商城",
        desc="解决育碧“无法建立连接”、Club 奖励加载超时",
        domains=["store.ubi.com", "ubisoftconnect.com", "api-ubiservices.ubi.com"],
        icon="rocket",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_ubisoft",
        ssl_sni_mode="host",
        candidate_ips=["23.41.142.46", "104.91.87.202"]
    ),
    # ea_app 已移除 (2026-08): Akamai 对 api.origin.com SNI 确定性返回 TLS HANDSHAKE_FAILURE
    # (服务端主动拒绝, 友好网络下实测同样全挂 = 明确封锁/服务端停用), 加速不可行
    ServiceProfile(
        id="battle_net",
        group="gaming",
        name="Battle.net 战网国际服",
        desc="战网国际服账号、商店与补丁 CDN 加速 (Akamai + CloudFront)",
        domains=["battle.net", "www.battle.net", "us.battle.net", "eu.battle.net",
                 "kr.battle.net", "account.battle.net", "shop.battle.net",
                 "blizzard.com", "www.blizzard.com", "us.cdn.blizzard.com",
                 "level3.blizzard.com", "blznav.akamaized.net",
                    # ★ 显式通配 (2026-10-03, 原缺陷 M3): 这两条以前只存在于
                    #   nginx_generator 的硬编码补表里, 而证书 SAN 靠"后两段派生"
                    #   恰好也补上了。现在 SAN 只取声明域名 ⇒ 必须在此声明,
                    #   否则 nginx 会服务 *.battle.net 而证书不覆盖它。
                    "*.battle.net", "*.blizzard.com"],
        icon="rocket",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_battle_net",
        ssl_sni_mode="host",
        candidate_ips=["99.83.192.184", "166.117.48.155", "166.117.103.183", "166.117.198.189"]  # 实测 Akamai 节点
    ),

    ServiceProfile(
        id="gog",
        group="gaming",
        name="GOG 游戏商城",
        desc="CD Projekt 旗下游戏商城与客户端分发 (Fastly Anycast)",
        domains=["gog.com", "www.gog.com", "api.gog.com", "login.gog.com", "images.gog.com"],
        icon="shopping_bag",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_gog",
        ssl_sni_mode="host",
        candidate_ips=["151.101.129.241", "151.101.1.241", "151.101.65.241", "151.101.193.241", "146.75.45.241"]
    ),
    ServiceProfile(
        id="xbox",
        group="gaming",
        name="Xbox 微软游戏生态",
        desc="Xbox 商店、支持与游戏生态 (Akamai)",
        # 2026-09-29 修复: 移除裸域 xbox.com。
        # 该域由 Azure 段服务 (证书含 xbox.com, 301), 而其子域由 Akamai 服务
        # (证书 *.xbox.com, 307/302) —— 两者后端完全不同。混合进同一条 upstream 会
        # 同时踩两个坑: 裸域在 Akamai 节点上返回 400, 子域在 Azure 节点上返回 404;
        # 而 nginx 的 proxy_next_upstream 既不接受 http_400 (写了直接 [emerg] 起不来,
        # 项目已有实测记录), 默认又不重试 404 —— 单条 upstream 无法同时容错两侧。
        # 裸域直连实测可用 (DNS 解析到 Azure 段并 301 → www.xbox.com), 按"能直连的
        # 不加"原则不加速; 用户访问 xbox.com 时经直连 301 跳到 www 后即进入加速接管。
        # support.xbox.com 亦移除: 其真实后端是 Azure Front Door
        # (fde-sxc-ui-pme-prod-*.b01.azurefd.net → 150.171.110.135/136, 证书含
        # support.xbox.com, 返回 200), 与 www/store 的 Akamai 后端不同源。
        # 该域在 Akamai 节点上恒返回 400 Bad Request —— 而 http_400 **不在**
        # nginx proxy_next_upstream 编译期白名单内 (写进去直接 [emerg] 起不来),
        # 无法靠重试规避, 只能不放进这条 upstream。实测直连可用 (200), 按
        # "能直连的不加"原则不加速。
        domains=["www.xbox.com", "store.xbox.com"],
        icon="gamepad",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_xbox",
        ssl_sni_mode="host",
        # 清理依据 (openssl 实测, 证书 SAN + 状态码双验证):
        #   以下 5 个 Akamai 节点 -> www 307 / store 302, 证书均为 *.xbox.com ✅
        #     (Akamai 按 SNI 路由且边缘为多客户共享, 同段 IP 不可通用 —— 实测
        #      104.83.196.57/.59/.60/.90 的证书分别是 nike / dell / godaddy /
        #      dentalcremer, 故只能用解析到 xbox 属性的这几个)
        #   20.70.246.20 / 20.231.239.246 / 20.112.250.133 / 20.76.201.171
        #     -> 子域 404, 证书 reroute443.microsoft.com ❌
        #        (一个与 Xbox 完全无关的微软内部路由服务, 比 minecraft 的
        #         *.azureedge.net 更彻底 —— 该段从未服务过 xbox 子域)
        candidate_ips=["104.83.196.58", "23.214.124.57", "104.89.105.188",
                       "23.207.192.64", "23.41.36.71"],
        probe_domains=("www.xbox.com", "store.xbox.com"),
        retry_on_404=True,  # 兜底: 若将来再混入错误 vhost 节点, 换节点重试而非透传 404
    ),
    ServiceProfile(
        id="minecraft",
        group="gaming",
        name="Minecraft 游戏生态",
        desc="Minecraft 官网与 Mojang 账号登录 (Akamai)",
        domains=["minecraft.net", "www.minecraft.net", "account.mojang.com"],
        icon="gamepad",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_minecraft",
        ssl_sni_mode="host",
        # 2026-09-29 修复"频繁 Page not found":
        # 原候选池混入了 Azure 段 (150.171.110.137 / .70) —— 该段只服务【裸域】
        # minecraft.net (308), 对 www.minecraft.net 与 account.mojang.com 会落到
        # Azure 默认站点, 返回 266KB 的 "Page not found" 页面, 且证书退化为
        # *.azureedge.net (正确证书应为 *.minecraft.net)。证书 SAN 是判定"错误
        # vhost"的黄金判据 —— 错误 vhost 返回的是默认站点证书, 一眼可辨。
        # 因 profile 的 probe_domains 原为空, 测速只探测 domains[0] (裸域),
        # Azure 段凭 308 被判"三态全通"而混入主力池; 而用户实际访问的是 www 子域,
        # 于是轮询到 Azure 节点时 (2/5 ≈ 40%) 直接 404 —— 实测今日真实流量
        # 15 请求 5 个 404 (33.3%), 与节点占比吻合。
        # 清理依据 (openssl 实测, 证书 SAN + 状态码双验证):
        #   184.28.7.164/166/173 -> 301/302/301  证书 minecraft.net,*.minecraft.net ✅
        #   23.49.104.170/181    -> 301/302/301  证书 *.minecraft.net + *.mojang.com ✅
        #   150.171.110.137/.70  -> 308/404/404  证书 *.azureedge.net ❌ (已移除)
        candidate_ips=["184.28.7.166", "184.28.7.164", "184.28.7.173",
                       "23.49.104.181", "23.49.104.170"],
        # 全域探测: 三个域全部验证。这是根本防线 —— 只要探测覆盖用户实际访问的
        # 子域, 只服务裸域的节点就无法再蒙混进主力池 (与 github_web 同做法)。
        probe_domains=("minecraft.net", "www.minecraft.net", "account.mojang.com"),
        retry_on_404=True,  # 兜底: 若仍有漏网的错误 vhost 节点, 换节点重试而非透传 404
    ),

    # --------------------------------------------------------------------------
    # 二次元与创作者
    # --------------------------------------------------------------------------
    ServiceProfile(
        id="pixiv_web",
        group="acg",
        name="Pixiv 网页与 APP API",
        desc="解决 Pixiv 主站访问被阻断与手机端 APP 接口超时",
        domains=[
            "pixiv.net", "www.pixiv.net", "ssl.pixiv.net", "accounts.pixiv.net", "touch.pixiv.net",
            "oauth.secure.pixiv.net", "dic.pixiv.net", "en-dic.pixiv.net", "sketch.pixiv.net",
            "payment.pixiv.net", "factory.pixiv.net", "comic.pixiv.net", "novel.pixiv.net",
            "imp.pixiv.net", "sensei.pixiv.net", "fanbox.pixiv.net",
            "source.pixiv.net", "i1.pixiv.net", "i2.pixiv.net", "i3.pixiv.net", "i4.pixiv.net",
            "app-api.pixiv.net", "lc-event.pixiv.net", "embed.pixiv.net"
        ],
        icon="palette",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_pixiv_web",
        # ECH 隧道直连: Pixiv 主站 2026-09 迁至 Cloudflare 后, 原 210.140.139.x
        # 段 (cdn-origin 回源地址) 的 443 端口虽仍开放, 但已不再服务
        # www/accounts/app-api 等 vhost, 一律回默认 403 —— 这正是长期 403 的根因。
        # 而 CF 边缘按 SNI 路由, 明文 SNI 被按关键字阻断, 空 SNI 又会被 CF 拒绝,
        # 只有 ECH 的加密 SNI 能同时通过两者。
        ech_enabled=True,
        ssl_sni_mode="empty",  # 保留: 非 ECH 路径 (relay 代理转发) 仍按空 SNI 直通
        candidate_ips=["104.18.42.239", "172.64.145.17", "104.18.10.118", "104.18.11.118"]
    ),
    # embed.pixiv.net 复测后并入本组 (2026-09-28): 2026-08 曾判为"仅代理可用"而放弃,
    # 该判断实为误读 —— 当时观察到的 RST 耗时仅 0.15s, 是 GFW 按明文 SNI 的关键字
    # 阻断特征, 而非 Cloudflare 的地理封锁 (CF 地理封锁返回 HTTP 错误页, 不会瞬断)。
    # 有 ECH 隧道后复测: 与主站同 zone (证书 *.pixiv.net / Google Trust Services)、
    # 同边缘 IP 池, 明文 SNI 全灭而经隧道 28/28 成功, 稳定性与主站等价, 故并入。
    # 无需独立 IP 池: 隧道白名单按后缀匹配 pixiv.net 已覆盖, 本组 candidate_ips 直接复用。
    # proxy_connect_by_domain 字段保留: 通用能力, 未来同类场景可直接启用
    ServiceProfile(
        id="pixiv_img",
        group="acg",
        name="Pixiv pximg 插画 CDN",
        desc="解决插画大图破图，二次打开从本地磁盘缓存加载",
        # 2026-09 复测调整:
        # - 移除 source.pixiv.net: 已随主站迁至 Cloudflare, 实际由 pixiv_web (ECH 隧道)
        #   接管, 留在本组只会与 pixiv_web 重复声明 server_name。
        # - 移除 imgaz.pixiv.net: 池段实测 RST, 其真实后端 74.86.17.48 亦 TCP 超时。
        # - 新增 booth.pximg.net: BOOTH 商品图, 实测与 pximg 同后端 (210.140.139.x 返回 301)。
        domains=["i.pximg.net", "s.pximg.net", "booth.pximg.net",
                    # ★ 显式通配 (原缺陷 M3): nginx 一直在显式服务 *.pximg.net,
                    #   而这条通配原先只由 SAN 的"后两段派生"提供 —— 两边不同源。
                    "*.pximg.net"],
        icon="image",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_pixiv_img",
        ssl_sni_mode="empty",
        # ★ 2026-10-04 补证书域族门槛 (空 SNI 下运行期 `proxy_ssl_verify off`, 证书是唯一防线)。
        #   实测 9/9 候选在空 SNI 下均返回 SAN=`pximg.net`/`*.pximg.net` ⇒ **零误杀**,
        #   同时挡掉"回别家 vhost 证书的假可用" (本项目实测过的形态:
        #   fallback.wgcz.net / flirtify.com)。
        cert_families=("pximg.net",),
        enable_cache=True,
        candidate_ips=["210.140.139.131", "210.140.139.132", "210.140.139.133", "210.140.139.134", "210.140.139.135", "210.140.139.136", "210.140.139.137", "210.140.139.149", "210.140.139.150"]
    ),
    # Pixiv Sketch 直播流 (hls1~12 / hlsa / hlsc / hlse .pixivsketch.net) 已移除 (2026-09):
    # 原先与 pximg 合并在 pixiv_img 内共用 upstream, 但两者是两套后端 —— 实测 pximg 的
    # 210.140.139.129~150 池段对 hls*.pixivsketch.net 恒定返回 421 Misdirected Request
    # (应用层明确拒绝, 非抖动), 而其真实后端 (DoH 解析到的 210.140.139.172~174 与
    # 103.97.176.x / 103.56.16.x) 全部 TCP 不可达 = 线路级封锁。
    # 既有池段用不了、正确后端连不上, 符合"仅代理可用的服务不加入"原则, 故整体移除。
    ServiceProfile(
        id="pixiv_fanbox",
        group="acg",
        name="Pixiv Fanbox 创作者赞助",
        desc="解决创作者赞助平台、图文帖子与赞助列表加载",
        domains=["fanbox.cc", "www.fanbox.cc", "api.fanbox.cc", "downloads.fanbox.cc",
                    "*.fanbox.cc"],   # ★ 显式通配 (原缺陷 M3, 同上)
        icon="star",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_pixiv_fanbox",
        ssl_sni_mode="host",
        candidate_ips=["104.20.38.219", "172.66.152.186", "104.18.22.203", "104.18.23.203"]
    ),
    ServiceProfile(
        id="booth_pm",
        group="acg",
        name="BOOTH 同人商城",
        desc="Pixiv 旗下同人志、3D 模型与独立周边商城",
        domains=["booth.pm", "www.booth.pm", "api.booth.pm", "assets.booth.pm",
                    "*.booth.pm"],   # ★ 显式通配 (原缺陷 M3: 原先是 nginx 补表 + SAN 派生各一份)
        icon="shopping_bag",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_booth_pm",
        # ECH 隧道直连: 实测明文 SNI 直连稳定返回 403 (Cloudflare 防护对无 cookie 请求
        # 的确定性响应), 而经 ECH 隧道访问返回正常 302 → https://booth.pm/ja。
        # 两者差别在于 CF 观察到的连接特征不同, ECH 路径可正常加载。
        ech_enabled=True,
        ssl_sni_mode="host",
        # ⚠ 本画像的 cert_families 只在**探测阶段**生效, 运行期不受保护 —— 这是记录的缺口:
        #   ECH 画像的 TLS 由本地隧道发起, nginx_generator 对它**完全不输出 proxy_ssl_***
        #   (:389-394, 否则形成 TLS-in-TLS 使隧道无法注入 ECH 扩展), 而 ECH 隧道
        #   (`ech_tunnel.py`) 也**不读** cert_families ⇒ 运行期没有任何证书校验。
        #   添它的价值仍在于: 探测阶段可淘汰"回别家证书"的假候选 (实测 3/3 候选均
        #   SAN=`booth.pm`/`*.booth.pm` ⇒ 零误杀), 避免污染候选池。
        cert_families=("booth.pm",),
        # 保留 403 放行: 探测走的是普通握手(非 ECH), 仍会拿到 403 —— 放行避免全挂误报
        probe_ok_statuses=(403,),
        candidate_ips=["104.18.37.180", "172.64.150.76", "104.18.22.203"]
    ),
    # danbooru 已移除 (2026-08): 主站源站 4 个 DNS 轮换 IP 全部 TCP 超时 (线路级不可达),
    # 图片 CDN 走 Cloudflare 但返回 403 防护; 友好网络下实测同样全挂 = 明确封锁, 加速不可行
    ServiceProfile(
        id="vndb",
        group="acg",
        name="VNDB 视觉小说资料库",
        desc="解决 Galgame/视觉小说综合数据库及其封面原图",
        domains=["vndb.org", "t.vndb.org"],
        icon="book",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_vndb",
        ssl_sni_mode="host",
        # 2026-09-29 修复: 原 IPv4 候选 217.182.194.133 是【错误 vhost】——
        # 其证书为 srv12.arobases.fr (与 VNDB 完全无关的域名), 对 t.vndb.org 返回
        # 200 的是它的"默认站点"页面。正是这个 200 让它长期被误判为健康节点:
        # 探测只比对状态码, 而错误 vhost 只需返回一份 200 就能骗过状态码检查。
        # 真实解析 (阿里 DoH) 为 82.192.72.172, 证书 SAN 含 s.vndb.org /
        # s2.vndb.org / t.vndb.org —— 这才是正确后端, 对两域均正常服务
        # (其对根路径的 404 属"图片 CDN 无根文档", 是正常响应)。
        candidate_ips=["82.192.72.172",
                       "2001:1af8:5301:117:1c00:d7ff:fe00:ffd"]  # IPv6 实测可用
    ),
    ServiceProfile(
        id="fantia",
        group="acg",
        name="Fantia 创作者赞助",
        desc="Fanbox 竞品, 日本创作者赞助平台 (GCP)",
        domains=["fantia.jp", "www.fantia.jp", "api.fantia.jp", "fanclub.fantia.jp"],
        icon="star",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_fantia",
        ssl_sni_mode="host",
        candidate_ips=["35.241.8.68"]  # 实测 GCP 节点 (全子域 200)
    ),
    ServiceProfile(
        id="pixivision",
        group="acg",
        name="Pixivision 官方杂志",
        desc="Pixiv 官方艺术杂志 (Cloudflare, 49ms 实测)",
        domains=["pixivision.net", "www.pixivision.net"],
        icon="palette",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_pixivision",
        ssl_sni_mode="host",
        candidate_ips=["172.64.145.76", "104.18.22.203", "172.64.150.76", "104.16.1.34"]
    ),
    # Yande.re 图库 (2026-10-04 实测新增)
    #
    # ★ 本条纠正了一份**归档草案的过期前提**: 草案 (service-expansion-feasibility-2026-10-03 §8)
    #   写"Yande.re 走 L7 或 DIRECT, **二者都必须绕开 Cloudflare**, 候选池只放源站
    #   198.251.89.183, **显式排除 CF 边缘段**"。实测**该前提已不成立**:
    #     · DoH (1.1.1.1 与 8.8.8.8) 对 yande.re / www / assets 三个名字**只回源站**
    #       198.251.89.183, 对 files.yande.re 回 198.251.88.76 —— 四个答案用项目自己的
    #       `ech_tunnel.is_cloudflare_ip` 判定**全部为 False** (同一次运行里
    #       104.21.81.219 / 172.67.181.145 判 True, 即判据本身有效);
    #     · 源站响应头 `server: freenginx` —— 它跑的是**自己的 nginx**, 根本不在 CF 后面。
    #   ⇒ 既然池子里没有 CF 边缘, "排除 CF 段"就**没有对象**; 本项目也**不存在**按画像
    #     排除 IP 段的机制 (`is_cloudflare_ip` 只在 ech_tunnel.build_ech_targets 里当
    #     **白名单**用, 恰是反面)。故本条**不新增** excluded_networks 之类的字段 ——
    #     不为一个不存在的威胁加机制。
    #
    # 通道选择: DIRECT + 真 SNI。
    #   · 真 SNI 实测可用 (证书 `*.yande.re`), 故**不需要**空 SNI / 掩护 SNI;
    #   · DIRECT 只把干净 IP 钉进解析层 (hosts/dns_server), 不经本机反代 —— 与 hitomi
    #     同款; yande.re 的解析本身是干净的, 钉 IP 的价值在于防止**将来**被投毒。
    ServiceProfile(
        id="yande_re",
        group="acg",
        name="Yande.re 图库",
        desc="Yande.re 动漫图库 (非 Cloudflare, 自有 freenginx 源站, 真 SNI 直连)",
        # ⚠ hosts 不能表达通配符 (hosts_manager 会剥掉 `*.`), 故必须**逐个子域**登记。
        #   实测 `/post` 页面里引用的子域计数: assets.yande.re ×366、files.yande.re ×160 ——
        #   这两个就是全部内容域 (cdn./static./img./news. 均**未出现**, 故不登记)。
        #   `www.yande.re` 同样登记并**已实测**: 项目探针对它也是 **rank 0** (301, 无
        #   self_redirect), 与 apex 行为一致。
        domains=["yande.re", "www.yande.re", "assets.yande.re", "files.yande.re"],
        icon="image",
        mode=ServiceMode.DIRECT,     # 走解析层直指该 IP, 不经 nginx (NGINX_BYPASS_MODES)
        ssl_sni_mode="host",
        # 证书 `*.yande.re` (SAN 含 `*.yande.re` + `yande.re`) ⇒ 空 SNI 通道的唯一防线那种
        # 情形在这里不适用, 但**声明它仍有益**: 探测阶段即可淘汰"回别的域证书"的假候选。
        cert_families=("yande.re",),
        # ★ assets.yande.re 的根路径**返回 403** (无根文档, 与 steam_akamai 的 Akamai 403
        #   同类), 而**真实资源路径一律 200** —— 实测 (带不带 Referer 都是 200, 即**不需要
        #   Referer**, 不是防盗链):
        #     /assets/stubs/explicit-caa9617c15b8566f041... -> 200 · 25,639B · image/png
        #     /assets/application-c99e88fb51193c7d2860b6... -> 200 · 41,067B · text/css
        #     /assets/application_classic-fad15cf8419f47... -> 200 · 281,607B · application/javascript
        #   不放行 403 会把它判成可疑节点 (`_suspect_status`) 而丢掉**主图床** (引用 366 次)。
        probe_ok_statuses=(403, 404),
        # 探测这三个域: apex 给 301->/post (项目探针实测 rank0), files 给 200,
        # assets 给 403 (由上面放行)。多域全过 => http_subdomains_ok=True。
        probe_domains=("yande.re", "assets.yande.re", "files.yande.re"),
        # 2026-10-04 实测 (项目探针 probe_ip_endpoint_v2 + _classify_result):
        #   yande.re        @198.251.89.183  真SNI 301 (Location=https://yande.re/post) -> **rank 0**
        #   files.yande.re  @198.251.88.76   真SNI 200                              -> **rank 0**
        #   assets.yande.re @198.251.89.183  真SNI 403 (需 probe_ok_statuses 放行)
        #   `/post` 200 · 193,751B (freenginx, text/html; charset=utf-8)
        #   ⚠ 本条**不设 probe_path**: 根路径已能判别 (301/403 都是确定性响应, 非"0 字节"),
        #     与 nhentai_img 那种"根路径判不了"的情形不同 —— 只在判不了时才设真实链接。
        # ⚠ 单候选/双候选的容灾: apex 与 assets 同为 198.251.89.183, files 为 198.251.88.76,
        #   即两个独立 IP。若源站更换地址, 本画像没有第三个可换节点 (与 hitomi 同类局限),
        #   依赖健康巡检把失效候选剔除; 补足更多经复核的源站 IP 属后续工作。
        candidate_ips=["198.251.89.183", "198.251.88.76"],
        stable_ips=["198.251.89.183"],
    ),

    # --------------------------------------------------------------------------
    # 开发者 & AI
    # --------------------------------------------------------------------------
    ServiceProfile(
        id="github_web",
        group="dev",
        name="GitHub 主站 Web 与 API",
        desc="解决 GitHub 网页断流、打不开与 Gist 同步",
        domains=[
            "github.com", "www.github.com", "api.github.com", "gist.github.com", "codeload.github.com",
            "central.github.com", "collector.github.com", "copilot.github.com", "services.github.com",
            "community.github.com", "docs.github.com", "education.github.com", "enterprise.github.com",
            "classroom.github.com", "redirect.github.com"
        ],
        icon="terminal",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_github_web",
        ssl_sni_mode="host",
        probe_timeout=2.0,  # Fastly/Azure 跨洋链路高丢包, 适度放宽档位 (原 3.0 致单任务预算 11.8s 拖慢整体测速)
        measure_throughput=True,  # git clone 的 smart-HTTP pack 走 github.com, 用真实下载吞吐排序
        # 全域探测: 主域 + API 域双验证 (GFW 可能只特判封锁 api.github.com SNI 而网页仍通)
        # 404 放行: 保留 —— 部分 Fastly 段对"有 vhost 但无根文档"的路径确实返回 404。
        # 但须注意其固有局限: 放行 404 无法区分"根路径无文档"与"错误 vhost 返回 404",
        # 且副域验证共用同一放行集, 命中放行码时不触发 http_subdomains_ok=False 降权。
        # 原 .133 段正是借此蒙混过关 (详见 candidate_ips 处注释), 已从候选池移除。
        probe_domains=("github.com", "api.github.com"),
        probe_ok_statuses=(404,),
        # 稳定性策略: 跨网络(Azure/Fastly/Pages) 跨段(逐段封锁互为兜底) 跨协议(IPv4/IPv6) 三层容灾
        # 2026-09 复测修正: 原置顶的 140.82.113.22/21 + 140.82.114.22 (GitHub 自建机房) 现建连
        #   252~272ms, 而已在候选池中的 20.27.177.113 / 20.205.243.165 / 20.205.243.166 (Azure 亚太)
        #   仅 67~79ms —— 相差约 4 倍。原先只有前者被标为 stable, 于是 stable_penalty 把它们永久
        #   压在快节点之上, 排序整段倒挂。现把实测快段一并纳入 stable 组: 组内仍按延迟竞争,
        #   慢段保留在列内作为跨段兜底(某段被整段封锁时仍能顶上), 但不再占据主力位。
        # 2026-09 复测: 20.205.243.165 / 140.82.112.25 / 140.82.112.17 / 140.82.114.26
        #   已从候选池移除 —— 五采样全量返回 400 Bad Request, 而 140.82.113.22 与
        #   20.27.177.113 同期恒定 200。
        #   必须清理而不能指望重试兜住: nginx 的 proxy_next_upstream 状态码白名单只支持
        #   403/404/429/500/502/503/504, 不接受 http_400 (写了直接 [emerg] 起不来),
        #   故上游一旦返回 400 就会被原样透传给用户。
        #   20.205.243.166 同期为恒定 403 但予以保留: 403 在白名单内, nginx 会自动切节点。
        #
        # ★ 2026-10-04 实测: 把 20.205.243.166 **从 stable 组降级** (仍留在候选池作兜底)。
        #   理由: stable_penalty 优先于延迟 ⇒ 进了 stable 组就会被排到主力位。
        #   而它实测已不稳 (真实 git info/refs 连打 6 次: **2/6** 成功, 4 次 TimeoutError);
        #   同段 .168 更差 (**0/6, 恒定 403**), 已从候选池移除。
        #   实测同时确认: 140.82.113.22/21/114.22 (Fastly) 与 20.27.177.113 各 **6/6** 稳定。
        #   ⇒ stable 组只留实测稳定者; .166 降为普通候选 (可用时仍会被调度, 不再被优先)。
        stable_ips=["20.27.177.113", "140.82.113.22", "140.82.113.21", "140.82.114.22"],
        candidate_ips=["140.82.113.22", "140.82.113.21", "140.82.114.22",  # 实测证书有效+最低延迟 (git clone 最快)
                       "20.27.177.113", "20.200.245.247",  # Azure 亚太 (次选)
                       "20.205.243.166",  # Fastly 新加坡段 (github520 现行推荐)
                       # ★ 2026-10-04 移除 "20.205.243.168" —— 与 .166 必须**区别对待**:
                       #   .166 的 403 在 nginx 重试白名单内, 且实测对 git info/refs 返回 200
                       #   (3/3 采样), 故保留; 而 .168 实测**在 github_web 的每个域上都失败**:
                       #     github.com 403 / www.github.com 超时 / api.github.com 超时 /
                       #     gist 连接重置 / codeload 超时 / central, collector, copilot 超时
                       #   ⇒ 它没有任何有效面, 只是把 1/3 的采样掷进"403 或超时"。
                       #   实测该池整体 70/80 (87.5%), 失败**全部**来自 .168 (0/10)。
                       "140.82.114.21",  # Fastly Anycast 全球段 (github520 实测)
                       "140.82.121.4", "140.82.114.4", "140.82.113.4", "140.82.112.4",  # GitHub 官方 IP 列表段
                       # 原 .133 段 (185.199.108~111.133, 注释为"跨段容灾") 已移除 (2026-09):
                       # 该段属 *.githubusercontent.com 的 Fastly 服务, 并不服务本站点的多个子域 ——
                       # community / education / enterprise / classroom / redirect .github.com
                       # 以及 api.github.com 在其上恒定返回 404 (community 为 3/3 采样恒定),
                       # 而正确后端返回 301/200。且本 profile 的 probe_ok_statuses=(404,) 会把这个
                       # "错误 vhost"与"根路径无文档"一并放行, 连 probe_domains 多域验证也不触发
                       # 降权 —— 即该段能否进主力纯属排序巧合, 非设计可控。
                       # 该段在其真实归属的 github_raw 中仍为候选主力, 此处容灾职责由原生 IPv6 段承担。
                       #
                       # ★ 2026-10-04 修正: 下面这 4 个 2606:50c0: 地址**不服务 github.com** ——
                       #   实测对 github.com 全部 TimeoutError (3/3)。它们只在
                       #   github_raw 的**掩标 SNI** (objects.githubusercontent.com) 下工作,
                       #   放在本画像里等于给池子塞进 4 个恒坏候选 (让"有时不可用"有了概率)。
                       #   容灾职责改由 .4 段 (140.82.112~121.4) 承担 —— 它们实测对
                       #   git info/refs 全部 200 (3/3, 1.9~3.6s)。
                       #   那 4 个 v6 地址在 github_raw 里**保留** (那里是真主力, 实测 8/8、419ms)。
                       ],
    ),
    ServiceProfile(
        id="github_raw",
        group="dev",
        name="GitHub 静态资产与 Raw 直连",
        desc="解决 GitHub CSS/JS 样式错乱、头像破图与 Raw 脚本直连",
        domains=[
            "raw.githubusercontent.com", "user-images.githubusercontent.com", "favicons.githubusercontent.com",
            "avatars.githubusercontent.com", "avatars0.githubusercontent.com", "avatars1.githubusercontent.com",
            "avatars2.githubusercontent.com", "avatars3.githubusercontent.com", "avatars4.githubusercontent.com",
            "avatars5.githubusercontent.com", "camo.githubusercontent.com", "desktop.githubusercontent.com",
            "gist.githubusercontent.com", "cloud.githubusercontent.com",  # Gist Raw 与历史图片域
            "private-user-images.githubusercontent.com"  # 私有仓库图片 (GitHub 现行图片域)
        ],
        icon="file_text",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_github_raw",
        cdn_vendor="fastly",
        # raw.githubusercontent.com 是 32 个 GitHub 域名中唯一被 SNI 硬阻断者 (TCP 通但 TLS 一律 RST,
        # IPv6 路径同样被拦); 同段的 objects.githubusercontent.com 未被封锁, 用它作掩护 SNI 即可
        # 正常取回 raw 内容 (实测 HTTP 200 + 真实文件正文)。Host 仍由 nginx 保持真实域名。
        ssl_sni_mode="objects.githubusercontent.com",
        # ★ 2026-10-04 补证书域族门槛。这一条的域族是**掩护域自己的 githubusercontent.com
        #   而不是 raw.githubusercontent.com** —— 先实测再决定, 不是照抄画像的 domains:
        #   该掩护通道拿到的证书 SAN=`*.github.com` / `*.github.io` / `*.githubusercontent.com`
        #   / github.com / github.io (CN=`*.github.io`, 即 GitHub 自有证书),
        #   与"域族 = 目标域"的常规情形不同 (compare imgur: 证书就是 *.imgur.com)。
        #   实测 8/8 候选均命中 githubusercontent.com ⇒ **零误杀**。
        #   ⚠ 若按画像 domains 里的 raw.githubusercontent.com 声明, 会把**整条池子**判死。
        cert_families=("githubusercontent.com",),
        # ★ 2026-10-04 实测修正: 原 stable_ips 只列 109/108 两个 **IPv4**, 而排序键是
        #   `(rank, stable_penalty, ...)` —— **稳定性优先于延迟**, 于是这两个 v4 恒占主力位,
        #   把实测快 2.6 倍的 v6 压在后面。而本机对 raw 的实测 (交错采样, 每家族 20 样本):
        #     v4 p50 **994ms** / p90 1308ms;  v6 p50 **419ms** / p90 494ms
        #   探测侧同样如此 (TCP+TLS 握手): v6 84~117ms vs v4 242~252ms。
        #   ⇒ 清空 stable_ips: 不预设"哪个段更稳", 交给**实测延迟**排序 —— 这也与
        #     `_service_sort_key` 自己写下的原则一致 ("IPv6 快节点正常竞争, 修复 GitHub
        #     原生 IPv6 85ms 优于 IPv4 230ms 却被硬降权的问题")。
        #   ⚠ 不是"v6 永远更稳": 两个家族在 20/20 样本里都无停顿; 证据只支持 v6 **更快**。
        stable_ips=[],  # 见上: 交给实测延迟排序, 不预设段
        candidate_ips=["185.199.109.133", "185.199.108.133", "185.199.110.133", "185.199.111.133",
                       "2606:50c0:8000::154", "2606:50c0:8001::154",  # GitHub 原生 IPv6, 实测直连可用
                       "2606:50c0:8002::154", "2606:50c0:8003::154"]
    ),
    ServiceProfile(
        id="github_release",
        group="dev",
        name="GitHub Releases 附件与文件对象",
        desc="解决 Release 软件安装包下载卡在 0% 或极慢",
        domains=["objects.githubusercontent.com", "github-releases.githubusercontent.com", "media.githubusercontent.com"],
        icon="rocket",
        mode=ServiceMode.L4_RELAY,  # 采用 L4 Relay 旁路高带宽下载
        upstream_name="upstream_github_release",
        ssl_sni_mode="host",
        measure_throughput=True,  # 发布包/大文件, 按真实下载吞吐排序
        # 全域探测: 3 个对象域全部验证 (根路径 404/403 为 Fastly 虚拟主机"无根文档"的正常响应)
        probe_domains=("objects.githubusercontent.com", "github-releases.githubusercontent.com",
                       "media.githubusercontent.com"),
        probe_ok_statuses=(403, 404),
        candidate_ips=["185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133"]
    ),
    ServiceProfile(
        id="github_assets",
        group="dev",
        name="GitHub 前端 JS/CSS 静态 CDN",
        desc="解决 GitHub 前端 CSS/JS 静态资源、文档页与 Pages 站点加载",
        domains=["githubassets.com", "github.githubassets.com", "assets-cdn.github.com", "assets.github.dev",
                 "github.io",
                    # ★ 显式通配 (原缺陷 M3): GitHub Pages 是**任意用户子域**
                    #   (*.github.io), 必须显式声明; 原先只靠 nginx 补表 + SAN 派生。
                    "*.github.io"],  # GitHub Pages 站点 (user.github.io, DNS 模式按后缀通配路由)
        icon="file_text",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_github_assets",
        ssl_sni_mode="host",
        measure_throughput=True,  # 前端 JS/CSS 静态大文件, 按真实下载吞吐排序
        # 404 放行: githubassets.com 根路径返回 404 (Fastly 识别虚拟主机但无根文档, 实测 .215/.153/.133 全段一致)
        probe_ok_statuses=(403, 404),
        stable_ips=["185.199.110.215", "185.199.108.215"],  # githubassets 专属 .215 段 (github520 现行推荐)
        candidate_ips=["185.199.110.215", "185.199.108.215", "185.199.109.215", "185.199.111.215",  # .215 专属段
                       "185.199.108.154", "185.199.109.154", "185.199.110.154", "185.199.111.154",  # .154 资产段
                       "185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153",  # .153 Pages 段
                       "185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133",  # 跨段容灾
                       "2606:50c0:8000::215", "2606:50c0:8001::215",  # GitHub 原生 IPv6, 实测直连可用
                       "2606:50c0:8002::215", "2606:50c0:8003::215",
                       "2606:50c0:8000::153", "2606:50c0:8001::153",  # Pages 原生 IPv6
                       "2606:50c0:8002::153", "2606:50c0:8003::153"]
    ),
    ServiceProfile(
        id="github_s3",
        group="dev",
        name="GitHub 大文件对象存储 S3",
        desc="解决 Release 安装包与 Issue/Discussion 上传图片加载 (AWS S3)",
        domains=[
            "github-production-release-asset-2e65be.s3.amazonaws.com",  # Release 附件实际下载域
            "github-production-repository-file-5c1aeb.s3.amazonaws.com",  # 仓库附件/上传文件
            "github-production-user-asset-6210df.s3.amazonaws.com",  # Issue/Discussion 用户上传图片
            "github-cloud.s3.amazonaws.com", "github-com.s3.amazonaws.com"  # 其余 S3 对象域
        ],
        icon="rocket",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_github_s3",
        ssl_sni_mode="host",
        measure_throughput=True,  # 发布包 S3 对象下载, 按真实吞吐排序
        # 全域探测: 5 个 bucket 域全部验证 (S3 根路径 GET / 预期 403 AccessDenied, 非节点故障;
        # 多域验证可排除"非 S3 前端 IP"与区域不匹配节点的假阳性)
        probe_domains=("github-production-release-asset-2e65be.s3.amazonaws.com",
                       "github-production-repository-file-5c1aeb.s3.amazonaws.com",
                       "github-production-user-asset-6210df.s3.amazonaws.com",
                       "github-cloud.s3.amazonaws.com",
                       "github-com.s3.amazonaws.com"),
        probe_ok_statuses=(403,),
        candidate_ips=["16.15.246.123", "16.15.229.220", "16.15.252.11",  # AWS us-east-1 S3 段 (github520 实测)
                       "16.15.228.151", "16.15.199.204"]
    ),
    ServiceProfile(
        id="gitlab",
        group="dev",
        name="GitLab 国际版",
        desc="解决 GitLab 国际版网页与 Raw 源码直连",
        domains=["gitlab.com", "assets.gitlab-static.net",
                    "*.gitlab.com", "*.gitlab-static.net"],   # ★ 显式通配 (原缺陷 M3, 同 battle_net)
        icon="terminal",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_gitlab",
        ssl_sni_mode="host",
        measure_throughput=True,  # Git 仓库 smart-HTTP, 按真实下载吞吐排序
        candidate_ips=["104.18.37.180", "172.64.150.76", "172.65.251.78",
                       "2606:4700:90:0:f22e:fbec:5bed:a9b9"]  # Cloudflare IPv6, 实测可用
    ),
    ServiceProfile(
        id="huggingface",
        group="dev",
        name="HuggingFace AI 平台",
        desc="模型权重 LFS 直连 + 全套图片 CDN 加速 (缩略图/头像/资产图)",
        domains=[
            "huggingface.co", "www.huggingface.co", "hf.co",
            # --- 图片与静态资产 CDN 全家桶 ---
            "cdn-lfs.huggingface.co",          # 模型/数据集 LFS 文件 (含数据集卡片图片)
            "cdn-lfs-us-1.huggingface.co",     # LFS 美国区域 CDN (README/卡片图片常用域)
            "cdn-lfs-eu-1.huggingface.co",     # LFS 欧洲区域 CDN
            "cdn-thumbnails.huggingface.co",   # 模型/数据集/Paper 缩略图 CDN
            "cdn-avatars.huggingface.co",      # 用户与组织头像 CDN (CloudFront)
            "assets.huggingface.co"            # 官网静态资产 (字体/图标/展示图)
        ],
        icon="cpu",
        mode=ServiceMode.L4_RELAY,  # 采用 L4 Relay 旁路高带宽下载，突破 Nginx 缓冲与体积限制
        upstream_name="upstream_huggingface",
        cdn_vendor="cloudfront",
        ssl_sni_mode="d1cnjqbqjby1vq.cloudfront.net",  # 同分发自有域名 (非跨租户域名前置)
        measure_throughput=True,  # 模型权重 LFS 大文件, 按真实下载吞吐排序
        # 候选池按 2026-08 实测延迟排序 (CloudFront Anycast), 测速引擎会再次动态优选
        stable_ips=["54.230.71.56", "3.175.207.31", "3.175.207.30"],
        candidate_ips=[
            "54.230.71.56", "3.175.207.31", "3.175.207.30",  # 实测 63-80ms 低延迟段
            "18.155.68.106", "18.155.68.86", "18.155.68.125",
            "18.65.14.87", "18.65.14.100", "18.65.14.85", "18.65.14.125",  # HF 主站现解析段
            "13.35.190.78", "13.35.190.60", "13.35.190.73", "13.35.190.18",  # cdn-avatars 现解析段
            "18.64.8.84", "18.64.8.43", "108.138.246.7"
        ]
    ),
    ServiceProfile(
        id="npm",
        group="dev",
        name="npm 包管理生态",
        desc="npm 包索引与 registry 镜像加速 (Cloudflare)",
        domains=["npmjs.com", "registry.npmjs.com", "registry.npmjs.org"],
        icon="terminal",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_npm",
        ssl_sni_mode="host",
        candidate_ips=["104.17.135.117", "104.17.134.117", "104.16.1.34", "104.16.8.34", "104.16.3.34", "104.16.7.34"]
    ),
    ServiceProfile(
        id="pypi",
        group="dev",
        name="PyPI Python 包索引",
        desc="pip 包索引与文件分发加速 (Fastly)",
        domains=["pypi.org", "www.pypi.org", "files.pythonhosted.org", "warehouse.python.org"],
        icon="file_text",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_pypi",
        ssl_sni_mode="host",
        candidate_ips=["151.101.64.223", "151.101.0.223", "151.101.128.223", "151.101.192.223"]
    ),
    ServiceProfile(
        id="crates_io",
        group="dev",
        name="crates.io Rust 包索引",
        desc="cargo 包索引与 crates.io 下载加速 (Fastly)",
        domains=["crates.io", "www.crates.io", "index.crates.io"],
        icon="terminal",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_crates_io",
        ssl_sni_mode="host",
        # 404 放行: crates.io 根路径 GET / 返回 404 (cargo 客户端从不访问根路径,
        # 真实路径 index.crates.io/config.json 实测稳定 200)。候选池与当前 DNS 解析一致
        probe_ok_statuses=(404,),
        candidate_ips=["151.101.194.137", "151.101.2.137", "151.101.66.137", "151.101.130.137", "3.170.229.4", "146.75.46.137"]
    ),
    ServiceProfile(
        id="jsdelivr",
        group="dev",
        name="jsDelivr 前端 CDN",
        desc="npm/GitHub 等开源前端资源全球分发 CDN (Cloudflare)",
        domains=["cdn.jsdelivr.net", "data.jsdelivr.net"],
        icon="file_text",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_jsdelivr",
        ssl_sni_mode="host",
        enable_cache=True,  # 纯静态 JS/CSS, 本地磁盘缓存收益大
        candidate_ips=["104.18.22.203", "172.64.150.76", "104.16.1.34"]
    ),
    # NuGet 三拆 (2026-09): 原为单个 nuget profile, 但三个域的真实后端分属三个平台,
    # 且 IP 互不通用 —— 实测任一候选 IP 只对其中一部分域是有效前端:
    #   api.nuget.org        Azure App Service 香港 (23.101.10.x)
    #   www.nuget.org        Azure Front Door      (172.183.192.203)
    #   globalcdn.nuget.org  Akamai                (184.26.91.x / 23.32.91.x)
    # 合池的后果是 nginx 轮询必然将请求打到错误后端, 实测 (三次采样恒定):
    #   www.nuget.org       @ 23.101.10.141 → 404 Site Not Found (Azure 默认站点)
    #   api.nuget.org       @ 172.183.192.203 → 超时
    #   globalcdn.nuget.org @ 池中全部 IP → 404 (其 Akamai 后端原先一个都不在池中)
    # 其中 globalcdn 是 .nupkg 包体下载域 (api 的索引会 302 过去), 该域不可用
    # 等于 dotnet restore / nuget install 无法下载任何包。
    ServiceProfile(
        id="nuget_api",
        group="dev",
        name="NuGet 包索引 API",
        desc="dotnet/nuget 客户端索引与元数据 (Azure App Service 香港)",
        domains=["api.nuget.org"],
        icon="terminal",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_nuget_api",
        ssl_sni_mode="host",
        # 2026-09 复测: 仅 .141 可达 (302); .113 与 8.183 已 TCP 超时, 保留作跨段兜底
        # (探测层会自动剔除, 仅在主力全挂时才会被兜底分支用到)
        candidate_ips=["23.101.10.141", "23.101.10.113", "23.101.8.183"]
    ),
    ServiceProfile(
        id="nuget_www",
        group="dev",
        name="NuGet 官网",
        desc="nuget.org 网页与包详情页 (Azure Front Door + IIS)",
        domains=["www.nuget.org"],
        icon="file_text",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_nuget_www",
        ssl_sni_mode="host",
        # 52.159.113.5 虽是 nuget.org 主域的解析结果, 实测同样正确服务 www vhost (200),
        # 用作冗余避免单点; nuget.org 主域本身未纳入 profile —— 实测可直连且仅 301 跳转到
        # www, 按"能直连的不加"原则不加速, 跳转后的 www 已由本 profile 接管。
        candidate_ips=["172.183.192.203", "52.159.113.5"]
    ),
    ServiceProfile(
        id="nuget_cdn",
        group="dev",
        name="NuGet 包下载 CDN",
        desc=".nupkg 包体与客户端分发 (Akamai)，dotnet restore 下包必经",
        domains=["globalcdn.nuget.org", "dist.nuget.org"],
        icon="rocket",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_nuget_cdn",
        ssl_sni_mode="host",
        # 400 放行: globalcdn 根路径实测恒定返回 400 Bad Request (纯对象存储, 无根文档),
        # 而真实包路径 /packages/<id>.<ver>.nupkg 三个节点均 200; dist 根路径为 301。
        # 不放行则 domains[0] (globalcdn) 的根路径探测会被判可疑 → 该服务永远走兜底。
        probe_ok_statuses=(400,),
        candidate_ips=["184.26.91.32", "184.26.91.88", "23.32.91.198"]
    ),
    ServiceProfile(
        id="maven_central",
        group="dev",
        name="Maven Central 包索引",
        desc="Java 包索引与构建依赖分发 (Apache/Cloudflare)",
        domains=["repo.maven.apache.org", "repo1.maven.org", "search.maven.org"],
        icon="terminal",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_maven_central",
        ssl_sni_mode="host",
        candidate_ips=["104.18.19.12", "172.64.150.76", "104.16.1.34"]
    ),
    ServiceProfile(
        id="google_fonts",
        group="dev",
        name="Google Fonts 字体 CDN",
        desc="Google 字体与 CSS 分发 (GFW 白名单直连, 官方证书可达节点)",
        domains=["fonts.googleapis.com", "fonts.gstatic.com"],
        icon="file_text",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_google_fonts",
        ssl_sni_mode="host",
        enable_cache=True,  # 字体与 CSS 静态资源, 缓存消除重复回源
        # 404 放行: Google 字体 API 根路径返回 404 (无根文档, /css?family= 真实路径实测 200);
        # 国内电信缓存段 (120.253.x, 当前 DNS 实际解析) 绕过 GFW 封锁, 是唯一可行路径
        probe_ok_statuses=(404,),
        candidate_ips=["142.250.72.228",  # Google 官方段 (海外, 通常被 GFW 封锁, 保留兜底)
                       "120.253.253.161", "120.253.255.33",  # 电信缓存段 (原候选)
                       "120.253.255.161", "120.253.253.34"]  # 电信缓存段 (2026-08 实测解析, css 200)
    ),
    # ==========================================================================
    # Google / YouTube 三条画像 (2026-10-01 P0 情报采集后定档)
    #
    # 为什么拆三条而不是一条 "google":
    #   后端行为不同 —— 网页态带账号(不可缓存) / 静态资源(可缓存) / YouTube 网页态(不可缓存)。
    #   这是项目一贯教训 (nuget 三拆、reddit vs reddit_static、discord vs discord_gateway):
    #   **后端行为不同的域名合池必然导致多域错配**。
    #   google_fonts 已单独存在 (走国内电信缓存段 120.253.x), 本次**不动它、也不与它合并**;
    #   本组的域名刻意避开 fonts.googleapis.com / fonts.gstatic.com。
    #
    # 通道选择依据 (P0 实测):
    #   ① 掩护 SNI=g.cn 有效: 8/8 中转 IP × 真实 Host 全部 200/302, 上游证书 SAN 含
    #      *.google.cn —— 属**同租户掩护** (Google 自家域互相掩护), 不是跨租户。
    #   ② 不用空 SNI: 空 SNI 时上游回占位证书 invalid2.invalid, HTTP 层虽仍按 Host 路由
    #      (实测亦 200), 但证书不匹配 => 探测阶段无法用证书 SAN 校验"是不是真 Google 边缘"。
    #      本组统一用 g.cn, 以保留 ③ 这道硬门槛。
    #   ③ 不用 DIRECT / QUIC: 自身 SNI 直连 Google 边缘被 RST; QUIC 通道"浏览器自行采用 h3"
    #      这一前提已被 netlog 证伪 (docs 第十四节), 且 quic_probe.QUIC_ENABLED 当前为停用。
    #
    # 2026-10-01 补充实测 (候选池 + 证书门槛, 详见 docs/cover-sni-degradation.md):
    #   ④ **中转节点是按 SNI 选证书的**: 同一 IP 发 g.cn 拿到含 *.google.cn 的那张,
    #      发 www.gstatic.com 拿到 gstatic 那张, 发空 SNI 拿到占位证书 invalid2.invalid。
    #      所以上面 ② 说的"证书校验真伪"这道门槛是真门槛 —— 但它必须表述为
    #      **"证书是否属于该厂商自有证书族"**(g.cn 命中 *.google.cn), 而不是
    #      "证书名是否覆盖真实 Host": 掩护 SNI 的定义就是证书名**必然不覆盖**真实 Host,
    #      按后者写会把全部掩护策略误判为失效 (本模块的运行时实现踩过这个坑, 已固化回归测试)。
    #   ⑤ **proxy_ssl_verify off 是伪 SNI 的代价, 不是 Google 的固有属性**: 用真实域名当 SNI 时
    #      证书名 8/8 覆盖真实 Host、链 8/8 受系统信任。因此 "host" 是"Google 关闭域名前置"
    #      时的退路, 已登记进 app/cover_sni.py 的候选池 (末位空 SNI 之前)。
    #      ⚠ 但**当前仍未开启**上游证书校验: nginx 是 Windows 构建且仓库未下发 CA 包
    #      (全树无 proxy_ssl_trusted_certificate)。要开启需先随包提供 CA bundle。
    #   ⑥ ssl_sni_mode="g.cn" 是**默认值**, 不是运行时唯一取值:
    #      app/cover_sni.py 会在启动加速前回归实测, 失效时按候选池降级, 并把结果交给
    #      nginx_generator (写 $host / "" 并附降级注释) 与 UI (状态卡 + 显式不可用告警)。
    # ==========================================================================
    #
    # 真伪判别方法 (本次新引入, 供后续复用):
    #   `/generate_204` 是 Google 全线前台的通用探活端点 —— 真边缘回 204, 而"打错服务器"的
    #   Bandaid Misdirected Traffic Server 不回。实测 68/69 个候选域名经中转 IP 返回 204。
    #
    # candidate_ips 说明: 8 个国内云中转 IP 全部实测可服务本组域名。但**它们并非同质** ——
    #   例如 scholar.google.com 根路径仅在部分节点回 200 (其余回 403, 属上游按区域/节点的
    #   正常差异, /generate_204 在所有节点均为 204)。因此本组依赖测速优选按域挑选,
    #   不要假定任一节点等价。
    # ==========================================================================
    ServiceProfile(
        id="google_web",
        group="dev",
        name="Google 搜索与账号",
        desc="Google 搜索/账号/邮件/云盘/文档等网页态服务 (经本机 nginx + g.cn 掩护 SNI)",
        # 域名清单来自 2026-10-01 逐域实测 + 2026-10-02 国家域名补全
        domains=[
            "google.com", "www.google.com", "accounts.google.com", "mail.google.com",
            "gmail.com", "drive.google.com", "docs.google.com", "sheets.google.com",
            "slides.google.com", "photos.google.com", "maps.google.com", "news.google.com",
            "translate.google.com", "calendar.google.com", "myaccount.google.com",
            "contacts.google.com", "play.google.com", "id.google.com", "apis.google.com",
            "scholar.google.com", "books.google.com", "meet.google.com", "keep.google.com",
            "sites.google.com", "groups.google.com", "myactivity.google.com",
            "adssettings.google.com", "support.google.com", "workspace.google.com",
            "cloud.google.com",
            "takeout.google.com", "earth.google.com",
            # ------------------------------------------------------------------
            # Google 国家/地区域名 (2026-10-02 补全, 起因: 用户给出的
            # https://www.google.com.sg/intl/zh-CN/about/products?tab=wh )
            #
            # 判据必须是**对 Host 敏感**的路径 —— 这里踩过一个坑并有对照数据:
            #   ✗ `/generate_204`: 对 Host 完全不敏感。实测 `www.baidu.com`、
            #     `www.google.com.zz`(不存在的 TLD)、随机标签 **全部回 204**。
            #     用它当门槛会把 14 个 Google 根本没运营的 ccTLD 也判成"可用"
            #     (google.com.aw/.az/.bm/.cr/.cw/.gd/.gy/.hn/.kn/.ky/.lc/.sr/.tc/.vg)。
            #   ✓ `/search?q=test`: 真实 web vhost 回 200/301(-> www.google.com) 且带
            #     `server: gws`; 不存在的域名一律 **404** 且无 server 头。
            #     负对照 5/5 正确判否, 正对照 3/3 正确通过。
            #
            # 测法必须与运行时一致: **SNI=g.cn + Host=真实域名** 打到 8 个中转 IP
            # (拿候选域名当 SNI 测的是"能否直连", 与本通道无关)。
            # 实测 294 个候选 (147 ccTLD × apex/www) ⇒ 266 个真实 vhost, 28 个判否;
            # 266 个里**没有一个**在用户给出的那条真实路径上失败。
            #
            # ⚠ SAN 影响面: 本组域名数从 34 涨到 300, 本地 CA 的 SAN 覆盖面随之扩大
            #   (方案 §7.1 要求显式接受并披露)。为此同步修掉了 cert_manager 的一个
            #   派生缺陷: 对 `www.google.com.sg` 这类多段公共后缀会派生出 `*.com.sg`
            #   ——那等于让本机受信任的 CA 持有对**任意 .com.sg 域名**有效的证书。
            #   现已按公共后缀样式跳过派生 (见 cert_manager._PUBLIC_SUFFIX_REGISTRY_LABELS)。
            # ------------------------------------------------------------------
            "google.ae", "google.al", "google.at", "google.ba", "google.bg", "google.bs", "google.ca",
            "google.cd", "google.ch", "google.ci", "google.cl", "google.cm", "google.co.ao",
            "google.co.bw", "google.co.ck", "google.co.cr", "google.co.id", "google.co.il",
            "google.co.in", "google.co.jp", "google.co.ke", "google.co.kr", "google.co.ma",
            "google.co.mz", "google.co.nz", "google.co.th", "google.co.tz", "google.co.ug",
            "google.co.uk", "google.co.vi", "google.co.za", "google.co.zm", "google.co.zw",
            "google.com.ag", "google.com.ai", "google.com.ar", "google.com.au", "google.com.bd",
            "google.com.bh", "google.com.bo", "google.com.br", "google.com.bz", "google.com.co",
            "google.com.cy", "google.com.do", "google.com.ec", "google.com.eg", "google.com.et",
            "google.com.fj", "google.com.ge", "google.com.gh", "google.com.gi", "google.com.gt",
            "google.com.hk", "google.com.jm", "google.com.kh", "google.com.kw", "google.com.lb",
            "google.com.ly", "google.com.mm", "google.com.mt", "google.com.mx", "google.com.my",
            "google.com.na", "google.com.ng", "google.com.ni", "google.com.np", "google.com.om",
            "google.com.pa", "google.com.pe", "google.com.pg", "google.com.ph", "google.com.pk",
            "google.com.pr", "google.com.py", "google.com.qa", "google.com.sa", "google.com.sb",
            "google.com.sg", "google.com.sv", "google.com.tn", "google.com.tr", "google.com.tw",
            "google.com.ua", "google.com.uy", "google.com.vc", "google.com.ve", "google.com.vn",
            "google.cz", "google.de", "google.dk", "google.dz", "google.ee", "google.es", "google.fi",
            "google.fr", "google.gr", "google.hr", "google.hu", "google.ie", "google.iq", "google.is",
            "google.it", "google.jo", "google.kz", "google.la", "google.lk", "google.lt", "google.lv",
            "google.md", "google.mg", "google.mk", "google.mn", "google.ms", "google.mu", "google.mw",
            "google.nl", "google.no", "google.nu", "google.pl", "google.pt", "google.ro", "google.rs",
            "google.ru", "google.rw", "google.se", "google.si", "google.sk", "google.sn", "google.so",
            "google.to", "google.tt", "google.ws", "www.google.ae", "www.google.al", "www.google.at",
            "www.google.ba", "www.google.bg", "www.google.bs", "www.google.ca", "www.google.cd",
            "www.google.ch", "www.google.ci", "www.google.cl", "www.google.cm", "www.google.co.ao",
            "www.google.co.bw", "www.google.co.ck", "www.google.co.cr", "www.google.co.id",
            "www.google.co.il", "www.google.co.in", "www.google.co.jp", "www.google.co.ke",
            "www.google.co.kr", "www.google.co.ma", "www.google.co.mz", "www.google.co.nz",
            "www.google.co.th", "www.google.co.tz", "www.google.co.ug", "www.google.co.uk",
            "www.google.co.vi", "www.google.co.za", "www.google.co.zm", "www.google.co.zw",
            "www.google.com.ag", "www.google.com.ai", "www.google.com.ar", "www.google.com.au",
            "www.google.com.bd", "www.google.com.bh", "www.google.com.bo", "www.google.com.br",
            "www.google.com.bz", "www.google.com.co", "www.google.com.cy", "www.google.com.do",
            "www.google.com.ec", "www.google.com.eg", "www.google.com.et", "www.google.com.fj",
            "www.google.com.ge", "www.google.com.gh", "www.google.com.gi", "www.google.com.gt",
            "www.google.com.hk", "www.google.com.jm", "www.google.com.kh", "www.google.com.kw",
            "www.google.com.lb", "www.google.com.ly", "www.google.com.mm", "www.google.com.mt",
            "www.google.com.mx", "www.google.com.my", "www.google.com.na", "www.google.com.ng",
            "www.google.com.ni", "www.google.com.np", "www.google.com.om", "www.google.com.pa",
            "www.google.com.pe", "www.google.com.pg", "www.google.com.ph", "www.google.com.pk",
            "www.google.com.pr", "www.google.com.py", "www.google.com.qa", "www.google.com.sa",
            "www.google.com.sb", "www.google.com.sg", "www.google.com.sv", "www.google.com.tn",
            "www.google.com.tr", "www.google.com.tw", "www.google.com.ua", "www.google.com.uy",
            "www.google.com.vc", "www.google.com.ve", "www.google.com.vn", "www.google.cz",
            "www.google.de", "www.google.dk", "www.google.dz", "www.google.ee", "www.google.es",
            "www.google.fi", "www.google.fr", "www.google.gr", "www.google.hr", "www.google.hu",
            "www.google.ie", "www.google.iq", "www.google.is", "www.google.it", "www.google.jo",
            "www.google.kz", "www.google.la", "www.google.lk", "www.google.lt", "www.google.lv",
            "www.google.md", "www.google.mg", "www.google.mk", "www.google.mn", "www.google.ms",
            "www.google.mu", "www.google.mw", "www.google.nl", "www.google.no", "www.google.nu",
            "www.google.pl", "www.google.pt", "www.google.ro", "www.google.rs", "www.google.ru",
            "www.google.rw", "www.google.se", "www.google.si", "www.google.sk", "www.google.sn",
            "www.google.so", "www.google.to", "www.google.tt", "www.google.ws",
            # ------------------------------------------------------------------
            # 用户 URL 的重定向落点及其同族站点 (2026-10-02 补全)
            #
            # 起因: `https://www.google.com.sg/intl/zh-CN/about/products?tab=wh` 实测 302 到
            # `https://about.google/intl/zh-CN/products?tab=wh` —— **只登记 google.com.sg
            # 是不够的**: 浏览器会接着去请求 about.google, 该域名不在清单里就不会被劫持,
            # 最终页面照样打不开。补全必须覆盖重定向落点, 否则只是"第一跳成功"的假可用。
            #
            # 判据同样要求对 Host 敏感, 并额外看**对端自报的 server 头**
            # (Google 自有前台: sffe / ESF / gws / Google Frontend):
            #   登记 —— about.google(/=200,真实路径 301) / www.about.google(302) /
            #           policies.google.com(ESF,200) / safety.google / abc.xyz(Alphabet,200) /
            #           opensource.google / diversity.google / careers.google.com /
            #           research.google / ai.google / blog.google.com /
            #           developers.google.com / developer.android.com /
            #           source.android.com / chromewebstore.google.com / one.google.com
            #   不登记 —— blog.google / store.google / fi.google / deepmind.google /
            #           sustainability.google / impact.google: 全部路径 404 **且无 server 头**,
            #           与本通道下"不存在的域名"特征一致 (即该节点不服务它们)。
            #           按"不通的服务一律不加入"原则排除 —— 注意这与"该域名在现实世界是否
            #           存在"无关: blog.google 现实存在, 但走本通道拿不到内容, 登记就是假可用。
            # ------------------------------------------------------------------
            "about.google", "www.about.google", "policies.google.com", "safety.google",
            "abc.xyz", "opensource.google", "diversity.google", "careers.google.com",
            "research.google", "ai.google", "blog.google.com", "developers.google.com",
            "developer.android.com", "source.android.com", "chromewebstore.google.com",
            "one.google.com",
        ],
        icon="search",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_google_web",
        cdn_vendor="google",
        ssl_sni_mode="g.cn",            # 同租户掩护 (见 VENDOR_COVER_SNI 注释)
        # 账号/邮件/文档属账号态, 一律不缓存 (与 youtube_web 同理)
        enable_cache=False,
        # 副域独立 TLS 校验: 多域全部非可疑才算干净节点, 防 GFW 按子域特判封锁
        probe_domains=("www.google.com", "accounts.google.com"),
        candidate_ips=["47.104.71.109", "47.103.46.164", "47.103.34.63", "8.138.21.175",
                       "8.134.173.202", "183.56.143.147", "47.113.110.152", "47.104.21.37"]
    ),
    ServiceProfile(
        id="google_static",
        group="dev",
        name="Google 静态资源 CDN",
        desc="gstatic / googleusercontent / ggpht 静态资源 (经本机 nginx + g.cn 掩护 SNI)",
        domains=[
            "gstatic.com", "www.gstatic.com", "ssl.gstatic.com", "maps.gstatic.com",
            "t0.gstatic.com", "t1.gstatic.com", "t2.gstatic.com", "t3.gstatic.com",
            "csi.gstatic.com", "encrypted-tbn0.gstatic.com",
            "googleusercontent.com", "www.googleusercontent.com",
            "lh3.googleusercontent.com", "lh4.googleusercontent.com",
            "lh5.googleusercontent.com", "lh6.googleusercontent.com",
            "play-lh.googleusercontent.com", "ggpht.com", "yt3.ggpht.com", "yt4.ggpht.com",
        ],
        icon="image",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_google_static",
        cdn_vendor="google",
        ssl_sni_mode="g.cn",
        # 开缓存 (本画像天然可缓存: 纯静态、证书独立、URL 不含账号态)。
        # 此前**刻意关闭**, 因为它要等两道前置缺陷都修好才能安全开启 —— 2026-10-01 已双双修复:
        #   ① 缓存键串域: 全局键原为 `$scheme$proxy_host$uri$is_args$args`, 而 `$proxy_host`
        #      是 proxy_pass 里的 **upstream 名**而非真实 Host, 同一 upstream 下的不同域名
        #      算出**同一个键**。本地 nginx 最小复现已证实: 两个 server_name 指向同一 upstream
        #      时, 第二个域拿到第一个域的 HIT 内容 (响应体里 Host 仍是 a.test)。
        #      本画像有 20 个域名, 开着缓存等于把串内容影响面从 2 域放大到 20 域。
        #      修法: nginx.conf 改为 `$scheme$host$uri$is_args$args` (见该处注释)。
        #   ② 缓存与零缓冲互斥: 本画像 group=dev, 生成器会给 dev 组统一发
        #      `proxy_buffering off` + `proxy_max_temp_file_size 0`, 而 nginx 需要缓冲响应体
        #      才能落盘缓存 —— 本地实测第二次请求仍为 MISS、源站被重新命中。现已在生成器里
        #      改为「enable_cache=True 的画像保留缓冲」, 顺带修好了 google_fonts / jsdelivr /
        #      npm / pypi / crates 等 dev 组画像**缓存一直空转**的老问题。
        enable_cache=True,
        # 根路径无文档: www.gstatic.com / t0-t3 / ggpht 均 404 (sffe/fife 正常应答),
        # 与 google_fonts 同理, 必须放行 404 否则测速会把所有候选判为可疑节点而全挂
        probe_ok_statuses=(404,),
        probe_domains=("www.gstatic.com", "t0.gstatic.com"),
        candidate_ips=["47.104.71.109", "47.103.46.164", "47.103.34.63", "8.138.21.175",
                       "8.134.173.202", "183.56.143.147", "47.113.110.152", "47.104.21.37"]
    ),
    # ==========================================================================
    # Gemini (Google AI) —— 2026-10-02 实测新增
    #
    # 实测结论 (经本机 nginx + relay, 逐域 curl --resolve):
    #   · `gemini.google.com/` 与 `/app` 均 **HTTP 200 / ~855 KB 完整页面**
    #     —— 即**网页版在现有链路上本来就能开**, 此前它挂在 google_web 的域名表里。
    #   · `bard.google.com` / `aistudio.google.com` 实测 **400 "Invalid URL"**:
    #     它们能**后缀命中** google_web 画像 (会被解析到 127.0.0.1), 但 **nginx 里没有站点**
    #     ⇒ 落到默认 server 而失败。
    #     这是一类必须警惕的**假覆盖**: "能反查到画像" ≠ "nginx 有 server_name"。
    #     判据必须查**显式域名表**, 不能只信后缀匹配 (见 §下方 domains 注释)。
    #   · `generativelanguage.googleapis.com` 未登记 ⇒ 落默认 server (预期)。
    #
    # 故单独成画像: 这些域与"Google 搜索/账号"是不同的使用场景, 用户需要能单独开关;
    # 且把 gemini.google.com 从 google_web 移出, 避免同一域名被两处登记
    # (PROFILES_BY_DOMAIN 是 dict, 重复登记只会静默保留其一)。
    # ==========================================================================
    ServiceProfile(
        id="gemini",
        group="dev",
        name="Gemini (Google AI)",
        desc="Gemini 网页版 / AI Studio / 生成式语言 API (经本机 nginx + g.cn 掩护 SNI)",
        domains=[
            # —— 应用本体 (实测 200; bard 为旧域, 实测应 301 到 gemini) ——
            "gemini.google.com",
            "bard.google.com",
            "aistudio.google.com",
            # NotebookLM: 同族 AI 服务 (2026-10-02 从 google_web 移入, 与 Gemini 同类场景)
            "notebooklm.google.com",
            # ★ gemini.gstatic.com —— 实测**页面有 18 处引用**它, 而它不在劫持集合里:
            #   浏览器走真实 IP ⇒ `islands-bootstrap-runtime-*.js` / `islands-*.js`
            #   报 net::ERR_CONNECTION_TIMED_OUT, 页面靠这些分片渲染, 于是界面残缺。
            #   这是"资源主机必须逐个登记"的又一例 —— 与模型 API 不同, 它藏在
            #   HTML 的 script src 里, 不抓页面就发现不了。
            "gemini.gstatic.com",
            # 同上: 岛屿(island)静态资源主机的**分片子域** (njl0.static.usercontent.goog 等),
            # 用一层通配覆盖, 避免逐分片登记
            "*.static.usercontent.goog",
            # ⚠ 但通配**之外还必须逐个登记实测到的主机**: Hosts 不支持通配 (见下),
            #    在默认的 hosts 后端下**只有具体名字才会被劫持**。
            #    2026-10-02 用户控制台实测: `geminiweb-pa.clients6.google.com/v1/processSession`
            #    与 `waa-pa.clients6.google.com/$rpc/google.internal.waa.v1.Waa/Create`
            #    双双 net::ERR_CONNECTION_TIMED_OUT —— 而 processSession 正是
            #    **WebChannel 会话端点**, 也就是"页面外壳能开、对话完全不通"的直接原因。
            #    链路侧已实测可服务这三个主机 (curl --resolve 到 127.0.0.1 拿到的是
            #    Google 自己的 404 页, 不是 default server 的 400 "Invalid URL"),
            #    所以缺的只是"把它们劫持过来"这一步。
            "njl0.static.usercontent.goog",
            "waa-pa.clients6.google.com",
            "geminiweb-pa.clients6.google.com",
            "ogads-pa.clients6.google.com",
            # ★ aistudio 的 PA 主机 (2026-10-02 真机日志): 用户在有 aistudio 时控制台报
            #   `alkalimakersuite-pa.clients6.google.com/$rpc/.../MakerSuiteService/ListModels`
            #   → net::ERR_CONNECTION_TIMED_OUT —— 与 geminiweb-pa 完全同一类:
            #   只被 `*.clients6.google.com` 覆盖, 而 Hosts 不支持通配 ⇒ 从没被劫持。
            "alkalimakersuite-pa.clients6.google.com",
            # —— 模型 API (AI Studio / SDK 直连) ——
            # 注意: 这些域未登记时会被解析到 127.0.0.1 却落到默认 server (400),
            # 属"看着像通了"的失败, 故必须显式登记。
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com",
            "cloudcode-pa.googleapis.com",
            # —— Google 前端辅助服务 (多个 Google 网页应用的通用依赖) ——
            #   `*.clients6.google.com`: 实测页面引用 waa-pa / ogads-pa.clients6.google.com;
            #   google_web 只登记了 apex, 子域会漏 ⇒ 用通配补齐。
            "*.clients6.google.com",
            "notifications-pa.googleapis.com",
            "people-pa.googleapis.com",
            "signaler-pa.googleapis.com",
            "jnn-pa.googleapis.com",
            "play.googleapis.com",
            "csp.withgoogle.com",
            "content-autofill.googleapis.com",
            # —— 官方入口站 ——
            "labs.google",
            "deepmind.google",
            # ⚠ 刻意**未登记**:
            #   · recaptcha.net / www.recaptcha.net —— 被大量非 Google 站点共用, 无直接证据
            #     前不扩大劫持面 (与 gvt1 家族同一口径);
            #   · www.googletagmanager.com —— 纯统计脚本 (GTM), 实测页面缺它也能正常渲染,
            #     登记它等于把统计流量也卷进中继, 无收益。
        ],
        icon="sparkles",
        mode=ServiceMode.L7_NGINX,
        # 掩护 SNI 必须与厂商声明配套: 测试会断言"用了掩护 SNI 的画像, 其厂商必须在
        # 受支持名单内", 漏掉 cdn_vendor 会直接被拦下 (实测就是这条把我拦住的)。
        cdn_vendor="google",
        # ⚠ upstream_name 必须显式给: 留空会生成 `proxy_pass https://;` —— 非法配置,
        #    让 nginx **整体拒载**(实测 "no host in upstream \"\""), 全部服务一起挂。
        #    生成器现已加静态 IP 回落 + 缺配即报错 (见 nginx_generator._static_fallback_upstream),
        #    但正确定义仍是第一道防线。
        upstream_name="upstream_gemini",
        enable_cache=False,
        # ⚠ 必须与 google_web **同一条中继路径**: 那个成功的 200/~855KB 请求本来就是
        #    经 google_web 的 server 块与中继 IP 拿到的 (当时 gemini.google.com 还在它的
        #    域名表里), 故复用同一批 IP 与同一个掩护 SNI 是**据实**而非猜测。
        #    漏掉这两项的直接后果实测过: candidate_ips 为空 -> 生成的 upstream 为空 ->
        #    `nginx -t` 直接报 "no host in upstream" 拒绝重载。
        candidate_ips=["47.104.71.109", "47.103.46.164", "47.103.34.63", "8.138.21.175",
                       "8.134.173.202", "183.56.143.147", "47.113.110.152", "47.104.21.37"],
        ssl_sni_mode="g.cn",
        # 根路径有文档 (实测 200 且 ~855 KB), 故用默认放行状态
        probe_domains=("gemini.google.com",),
    ),
    ServiceProfile(
        id="youtube_web",
        group="dev",
        name="YouTube 网页与图片",
        desc="YouTube 网页态、缩略图与播放器资源 (经本机 nginx + g.cn 掩护 SNI)",
        # 注: googlevideo.com (视频流本体) 由**独立画像**承载 —— 它走不了本通道:
        #   经中转 IP 请求 /videoplayback 时上游回 "Bandaid Misdirected Traffic Server"
        #   (Google 明确回"打错服务器"), 而真实 IPv6 节点的 TCP 侧被压制 (同一时刻
        #   QUIC 5/5 成功 vs TCP 0/5)。
        #   ★ 2026-10-04 更正: 原文写"视频通路需另走 QUIC 上游腿, **未在本次范围内**" ——
        #     那是当时的范围声明, 早已落地 (见下方 googlevideo 画像 + app/h3_upstream.py)。
        #     留在这里会让读代码的人以为视频还没做。
        #   替代通路已逐条实测关闭 (docs/archive/googlevideo-node-availability.md §7.6.5):
        #     QUIC 只在 UDP **443** 听 (8443/80/8853/8080 全部 Timeout)、
        #     TCP+ALPN=h3 与 h2 均被 RST、IPv4 侧整体不可达。
        #   ⇒ 本画像**刻意不登记** googlevideo 域: 登记它只会造出"页面能开但视频永远转圈"
        #     的假可用 (视频域必须由那个画像自己的 server 块与上游腿承载)。
        domains=[
            "youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be",
            "youtube-nocookie.com", "www.youtube-nocookie.com",
            "ytimg.com", "i.ytimg.com", "s.ytimg.com",
            "youtubei.googleapis.com", "studio.youtube.com", "music.youtube.com",
            "tv.youtube.com", "gdata.youtube.com",
        ],
        icon="video",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_youtube_web",
        cdn_vendor="google",
        ssl_sni_mode="g.cn",
        # 账号态 (观看记录/订阅/登录), 明确**禁缓存**
        enable_cache=False,
        # i.ytimg.com 根路径 404 (sffe 正常应答) —— 放行以免误杀全部候选
        probe_ok_statuses=(404,),
        probe_domains=("www.youtube.com", "i.ytimg.com"),
        candidate_ips=["47.104.71.109", "47.103.46.164", "47.103.34.63", "8.138.21.175",
                       "8.134.173.202", "183.56.143.147", "47.113.110.152", "47.104.21.37"]
    ),
    # --------------------------------------------------------------------------
    # googlevideo (YouTube 视频流) —— 2026-10-02 **改为登记, 但默认不启用**
    #
    # 与 2026-10-01 那次"刻意不登记"的差别 (那次结论没错, 是本轮把通道那一半补上了):
    #
    # ① 通道侧已被实测打通 (不再是"原理上到不了"):
    #    `L7 + h3 上游腿` 这个形态**不需要自己去当 SABR 客户端** —— 让它做**哑管道**即可:
    #    浏览器照常走 TCP 明文到本机 nginx, nginx 转给 h3 上游腿, 腿用 HTTP/3 送到真实节点。
    #    实测 (客户端是纯 HTTP/1.1, **零 QUIC**):
    #      6 个候选节点触达 5 个, 其中 3 个拿到**真正的 gvs 响应**
    #      (`server: gvs 1.0` + `content-type: application/vnd.yt-ump`);
    #      对照组 cdn.jsdelivr.net 经同一条腿取到 200 + 1,272,972 B。
    #    这条路的**部署价值**: 不再依赖浏览器的 QUIC —— 实测火绒挂钩会让 Chrome 的 QUIC 全灭
    #    (`QUIC_HANDSHAKE_FAILED`), 而**同一时刻**本项目自己的 aioquic 客户端照样拿到 204。
    #
    # ② 仍然**没有解决"能不能播"**: 上面那 3 个 403 就是 SABR/UMP 本身 —— 普通 HTTP Range GET
    #    取 SABR 分片流会被 gvs 拒。上一轮逐条排除过的事实依然成立 (出口 IP / 节点 / `n=` /
    #    PO Token / 可播放性全部排除, 403 头自报 `server: gvs 1.0` 说明确实打到了真视频服务)。
    #    **本画像登记的是"通道", 不是"播放可用"** —— 故默认**不启用** (见 requires_dns_backend),
    #    由用户显式开启, 且描述里写清"播放尚未验证", 不做假可用。
    #
    #    ★ 2026-10-02 更新: **播放已实测成功** (player_state=PLAYING, currentTime=35s, 见
    #    docs/archive/googlevideo-sabr-analysis.md §13.3.6)。真因曾长期被掩盖 —— 不是通道问题, 而是
    #    本模块的响应头白名单丢掉了 `access-control-*`: 播放器用 fetch() **跨源**取 SABR,
    #    CORS 头被静默丢弃后浏览器直接判失败, 现象上与"通道不通"无法区分。
    #    仍未解决的是**节点可用性** (实测 20 条 SABR POST 里 11 条 upstream_no_response),
    #    表现为卡顿/降码率, 故仍保持默认不启用。
    #
    # ③ 为什么必须 requires_dns_backend, 以及它现在**被真正强制**:
    #    节点名是动态且海量的 (rr1---sn-xxxx.googlevideo.com), 而 **Windows hosts 文件不支持通配**,
    #    Hosts 后端无法把 *.googlevideo.com 劫持到本机 → 浏览器会走污染解析, 表现为
    #    "页面能开而视频永远转圈"。只有 NRPT 的后缀匹配能覆盖。
    #    该标记**原先只被 ip_pool 用于"排除默认启用", 并未强制** —— 用户仍可在 Hosts 后端下
    #    手动开启, 得到一个静默假可用。现已做成**两道闸门** (2026-10-02):
    #      · 启用边界: app/pyside_app.py 的 on_service_toggled 直接拒绝开启并回弹开关;
    #      · 下发规则前: _apply_redirect 再剔除一次 (挡住手改 config.json 这一路)。
    #    判据是"解析后端是否具备**通配能力**"(h3_upstream.wildcard_capable),
    #    而不是写死"必须是 NRPT" —— 将来新增浏览器 DoH 后端时无需改调用方。
    #    注: 本轮验证时用"用户级 Chrome DoH 策略"绕开了管理员权限要求 (见
    #    docs/googlevideo-other-methods.md §6.2), 生产上仍是 NRPT 或等效的解析下发路径。
    #
    # ④ 域名只登记 apex: `*.googlevideo.com` 由证书派生免费得到 (get_all_san_domains 会同时
    #    产出 googlevideo.com 与 *.googlevideo.com), 而 nginx 侧需要显式通配 —— 故这里直接写
    #    通配形式 (nginx server_name 支持 *.example.com; win_utils 也认这种写法)。
    #    **不要逐个登记节点名**: 节点名动态且海量。
    #
    # ⑤ **代码审阅 (2026-10-02) 更正了一处架构结论, 并查出 4 条传输层阻塞 —— 均已修 (E0)。**
    #    被更正的结论: 原文说"`L7 + h3 上游腿` 这个形态**原理上无法**载 SABR"。
    #    那是把"腿**不会说** SABR"错当成了"腿**载不了** SABR" —— 腿是传输层, 方法与载荷无关。
    #    4 条阻塞 (原先任何 SABR 实验都会因它们得到假阴性, 与 SABR 本身无关):
    #      1) 整周期硬上限 24s (timeout×2+8) ⇒ 分钟级流必然失败
    #      2) 超时后不取消协程即换节点 ⇒ 重复响应头 / 流被掐断 / 线程池泄漏
    #      3) 每 8s 无数据即判流结束 ⇒ 服务端合法静默被当成流结束, 静默截断
    #      4) 请求体只认 Content-Length 且 >8MiB 静默截断 ⇒ chunked 体变空体
    #    另修: 204/304 曾错误携带 `Transfer-Encoding: chunked` (违反 RFC 9110) ——
    #    这很可能就是此前记为"未解释的互操作现象"的 Chrome `ERR_ABORTED` 的根因
    #    (curl 宽容, Chrome 不宽容)。**该现象与 SABR 阻塞很可能共享根因。**
    #    E1 长流压测已通过: 静默 70s / 整周期 110s 不被任何一层掐断 (scripts/probe_sabr_carry.py)。
    #
    # 复现与证据: docs/archive/googlevideo-sabr-analysis.md (基础文档: 定因/缺陷清单/实施路径) +
    #             docs/googlevideo-other-methods.md (方法 A/B 全链实测) +
    #             docs/googlevideo-quic-channel.md §5.6 (已更正的逐条排除表)
    # --------------------------------------------------------------------------
    ServiceProfile(
        id="googlevideo",
        group="dev",
        name="YouTube 视频流 (HTTP/3 上游腿)",
        desc="经本机 HTTP/3 上游腿直连真实视频节点 (通道已实测, 浏览器实测可播放; 默认不启用)",
        # ⚠ 域名集合为什么**不能只写 *.googlevideo.com** (2026-10-02 NRPT 实测):
        #   1) 播放器除了 googlevideo 主域, 还会请求**别名域家族**。实测失败主机名是
        #      `rr1---sn-p5qs7nd7.c.youtube.com` (16 次 ERR_CERT_COMMON_NAME_INVALID):
        #      该域**不在**劫持集合里 → 浏览器走真实(被投毒的)解析 → 连到投毒 IP →
        #      拿到不匹配的证书 → 播放链断掉。
        #      注意: 腿的解析器**本来就在用这批别名域**规避投毒 (h3_upstream.ALIAS_SUFFIXES),
        #      即项目早已承认它们重要, 只是没登记进画像 —— 这是"两处各算一套"的典型。
        #   2) **nginx 的 `*.googlevideo.com` 只匹配一层标签**。而真实 GVS 证书覆盖
        #      `*.c.googlevideo.com` / `*.a1.googlevideo.com` —— 这类**两层**主机名匹配不上
        #      → 落到默认 server → 同样是不匹配的证书。故必须显式登记这两条。
        #   未登记 gvt1 家族: 它们只被腿当作**解析别名**使用, 未见播放器直接请求;
        #   在无实测证据前不扩大劫持面 (与"不做假可用"一致)。
        domains=[
            "*.googlevideo.com",     # 主域
            "*.c.googlevideo.com",   # 别名家族 (真实证书覆盖; nginx 单层通配匹配不到)
            "*.a1.googlevideo.com",  # 同上
            "*.c.youtube.com",       # ★ 实测失败主机名所在家族
        ],
        icon="video",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_googlevideo",
        # 走本地 h3 上游腿: 生成器据此输出明文回环 + 不输出 proxy_ssl_*
        h3_upstream=True,
        # 无候选 IP 池: 上游是本地代理端口, 与候选节点无关 (cdn_optimizer 的 h3 分支
        # 无条件写 127.0.0.1:44411, 不依赖任何探测结果)。节点解析由腿自己做。
        candidate_ips=[],
        # 探测对它是纯假阴性: 真实节点 TCP 侧被压制 (同一时刻 QUIC 5/5 vs TCP 0/5),
        # 走 TCP 探测只会把全部节点判死。
        skip_cdn_probe=True,
        # 视频流绝不落盘缓存
        enable_cache=False,
        # ★ M13 拆字段 (2026-10-03): 这里**既不需要 HTTPS RR**, 也与 DNS 后端能力无关 ——
        #   它真正依赖的是"**后缀通配**能把 rr1---sn-xxxx.googlevideo.com 这类海量动态
        #   子域导向本机"(hosts 不支持通配)。原先写成 requires_dns_backend=True 属于一词多义,
        #   还让 needs_wildcard_resolution() 去做二次推导, 正好把 S1 的缺陷藏住了。
        needs_wildcard_resolution=True,
        # 通道性/实验性服务: 可用性分钟级时变, 启用前必须先过 gvs_h3_probe 闸门。
        # 原先借 requires_dns_backend 兼职"不默认启用", 现在用独立字段表达真实理由。
        experimental_default_off=True,
    ),
    # --------------------------------------------------------------------------
    ServiceProfile(
        id="turnstile",
        group="dev",
        name="Cloudflare Turnstile 验证码",
        desc="Turnstile 人机验证 JS/挑战端 (解决验证码转圈加载失败)",
        domains=["challenges.cloudflare.com"],
        icon="shield",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_turnstile",
        ssl_sni_mode="host",
        enable_cache=True,  # 验证码 JS 静态资源缓存加速
        candidate_ips=["104.18.94.41", "104.18.22.203", "172.64.150.76", "104.16.1.34"]
    ),
    ServiceProfile(
        id="hcaptcha",
        group="dev",
        name="hCaptcha 人机验证",
        desc="hCaptcha 验证码全套 (JS/API/资源域, 解决登录与提交卡验证)",
        domains=["hcaptcha.com", "www.hcaptcha.com", "api.hcaptcha.com",
                 "assets.hcaptcha.com", "newassets.hcaptcha.com"],
        icon="shield",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_hcaptcha",
        ssl_sni_mode="host",
        enable_cache=True,
        candidate_ips=["104.19.230.21", "104.19.229.21", "104.18.22.203", "172.64.150.76"]
    ),
    ServiceProfile(
        id="unpkg",
        group="dev",
        name="unpkg npm 包 CDN",
        desc="npm 包直引最常用 CDN (Cloudflare, 前端依赖加载提速)",
        domains=["unpkg.com"],
        icon="file_text",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_unpkg",
        ssl_sni_mode="host",
        enable_cache=True,  # npm 包静态资源缓存
        candidate_ips=["104.18.0.22", "104.18.22.203", "172.64.150.76", "104.16.1.34"]
    ),
    ServiceProfile(
        id="cdnjs",
        group="dev",
        name="cdnjs 公共库 CDN",
        desc="Cloudflare cdnjs 老牌公共前端库 CDN (与 jsDelivr 互补)",
        domains=["cdnjs.cloudflare.com"],
        icon="file_text",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_cdnjs",
        ssl_sni_mode="host",
        enable_cache=True,
        candidate_ips=["104.17.25.14", "104.18.22.203", "172.64.150.76", "104.16.1.34"]
    ),

    # --------------------------------------------------------------------------
    # 2026-10-01 新增: 由"替代路线"实测解锁的服务
    #   伪 SNI 路线 (Fastly / Akamai): ssl_sni_mode 填掩护域名, nginx 以该 SNI 连上游,
    #     Host 仍为真实域名 —— 实测 imgur 302 / twitch 200 / myanimelist 200。
    #   QUIC 路线 (Cloudflare 等): QUIC_DIRECT 模式, 由本机 DNS 下发真实 IP 与
    #     HTTPS RR(alpn=h3), 浏览器自行走 HTTP/3 —— 实测 reddit/discord/stackoverflow 均 200。
    #   证据与复现脚本见 docs/archive/uplift-route-findings.md。
    # --------------------------------------------------------------------------
    ServiceProfile(
        id="imgur",
        group="acg",
        name="Imgur 图床",
        desc="Reddit/社交常用图床 (Fastly, 伪 SNI 掩护可直连, 图片可缓存)",
        # 子资源域必须一并登记: 只登记主域会得到"页面能开、图片全破"的假可用
        # (s.imgur.com 静态资源 / api.imgur.com 接口域, 实测掩护 SNI 下 302/301 正常)
        domains=["imgur.com", "www.imgur.com", "i.imgur.com", "s.imgur.com", "api.imgur.com",
                 # Stack Exchange 的图片域 (问题/回答里的配图): 干净解析指向 198.252.206.17,
                 # 而**系统解析被污染成 31.13.112.4** (Facebook 段), 自身 SNI 实测 502;
                 # 经 imgur 同款掩护通道 (www.fastly.com) 实测返回 301 -> 并入本画像处理。
                 "i.stack.imgur.com"],
        icon="image",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_imgur",
        cdn_vendor="fastly",
        ssl_sni_mode="www.fastly.com",   # Fastly 实测接受 SNI≠Host, 且原站 SNI 已被 RST
        # 掩护 SNI 下运行期必然 `proxy_ssl_verify off` (nginx_generator:392) ⇒ 证书是
        # **唯一防线**, 必须在探测阶段把关。实测该通道拿到的恒是目标自己的证书
        # (3/3 三个候选 **全部** SAN=`*.imgur.com`/`imgur.com`) ⇒ 声明域族**零误杀**。
        cert_families=("imgur.com",),
        enable_cache=True,
        candidate_ips=["146.75.92.193", "199.232.192.193", "199.232.196.193"]
    ),
    ServiceProfile(
        id="myanimelist",
        group="acg",
        name="MyAnimeList 动漫资料库",
        desc="欧美向动漫评分与资料库 (Akamai, 伪 SNI 掩护可直连)",
        # 同上: cdn(图片) / api / static 是页面内容与海报图的来源, 缺任一个都会"有页面没图"
        domains=["myanimelist.net", "www.myanimelist.net",
                 "cdn.myanimelist.net", "api.myanimelist.net", "static.myanimelist.net"],
        icon="book",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_myanimelist",
        cdn_vendor="akamai",
        ssl_sni_mode="steambroadcast.akamaized.net",  # 与 steam_akamai 同款 Akamai 掩护域名
        # ⚠ 本画像**不能**声明 cert_families —— 这是实测结论, 不是遗漏 (2026-10-04):
        #   在 Akamai 掩护 SNI 下拿到的证书是 **`a248.e.akamai.net`**
        #   (SAN = a248.e.akamai.net / *.akamaized.net / *.akamaihd.net …),
        #   即**通道设计上就打不到 myanimelist.net 自己的证书**。若强行声明
        #   cert_families=("myanimelist.net",) ⇒ `_cert_gate` 会把**全部候选**判死,
        #   服务直接变不可用 (实测校验: 通过 0 / 淘汰 2)。
        #   这类"共享 CDN 按 IP/边缘选证书、证书不属于目标客户"的通道, 其防线只能是
        #   cdn_vendor (但 VENDOR_CERT_SUFFIXES 当前只登记 google ⇒ akamai 无厂商门槛)。
        #   ⇒ 正确处置是**记录这个已知缺口**, 而不是加一道会误杀的门槛。
        # 图片/接口域对根路径返回 404/400 属确定性正常响应 (无根文档), 需放行否则被判"全挂"
        probe_ok_statuses=(400, 404),
        probe_domains=("myanimelist.net", "cdn.myanimelist.net"),
        candidate_ips=["23.33.184.235", "23.33.184.234"]
    ),
    # twitch_web 已于 2026-10-01 移除: 主域 www.twitch.tv 经伪 SNI 掩护可加载 (200), 但页面内容
    # 依赖的 gql/api/passport/assets.twitch.tv 实测 —— api/passport 在掩护 SNI 下返回 421 (不在该
    # Fastly 服务上), 而用其自身 SNI 又是 tls_rst (SNI 被阻断或不在可用池内), 即"主页能开、内容
    # 永远出不来"。按项目筛选原则 (不通的服务一律不加入, 不做假可用), 不予登记。
    # 注: static.twitchcdn.net / usher.ttvnw.net 走 CloudFront 本就可达, 无需也不应劫持。
    ServiceProfile(
        id="reddit",
        group="dev",
        name="Reddit 论坛",
        desc="全球最大兴趣社区 (经本机 nginx + Fastly 掩护 SNI 直连, 含图片/视频/样式域)",
        # 媒体域为什么必须走这里而不是 DIRECT (2026-10-01 用临时 nginx 复现生产路径实测):
        #   掩护 SNI=www.fastly.com 时 i.redd.it / styles.redditmedia.com / emoji.redditmedia.com /
        #   b.thumbs.redditmedia.com 返回 404, v.redd.it / preview.redd.it / external-preview.redd.it /
        #   packaged-media.redd.it 返回 403 (根路径无权限, 属正常) —— 都是 Fastly **已服务**该域;
        #   而**自身 SNI 一律 502** (被阻断) —— 所以 DIRECT(钉真实 IP + 自身 SNI) 会把图片/视频全部弄坏。
        #   反例: i.redditmedia.com 掩护下返回 421 (Fastly 拒绝跨租户) -> 不得登记。
        #
        # ⚠ 2026-10-03 三拆: **图片/样式域**已迁到 `reddit_media` (见下一个画像), 本画像只留
        #   "网页态 + 视频流"。为什么拆: 图片/样式是**可缓存**的静态资源, 而网页态是账号态
        #   (观看记录/登录, 一律不缓存)、v.redd.it / packaged-media.redd.it 是**分段视频流**
        #   (Range 请求, 进磁盘缓存无意义且会把大文件写满盘)。合在一起就只能整块不缓存 ——
        #   于是"Fastly 边缘抖动时图片必然全破"。拆开后媒体域可用 `proxy_cache_use_stale`
        #   在边缘失败时继续吐已缓存图片 (与 imgur/pixiv 同款处置)。
        domains=["reddit.com", "www.reddit.com", "old.reddit.com",
                 "v.redd.it", "packaged-media.redd.it"],
        icon="message",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_reddit",
        cdn_vendor="fastly",
        # 2026-10-01 实测: 自身 SNI 被 RST, 但掩护 SNI=www.fastly.com 时
        # @199.232.161.140 返回 **200 + CN=*.reddit.com** (Fastly 接受跨租户掩护 SNI)。
        # 因此无需 QUIC/ECH —— 浏览器经本机 nginx (本地 CA 证书) 即可正常加载,
        # 不再依赖"浏览器自行采用 HTTP/3"(该前提已被 netlog 证伪, 见 docs 第十四节)。
        ssl_sni_mode="www.fastly.com",
        # 运行时掩护 SNI 通道 (app/cover_sni.py 的 CHANNELS["reddit"]):
        # 实测这条通道是**分钟级时变**的 —— 同一组合 (www.fastly.com @199.232.161.140 +
        # Host www.reddit.com) 在 40 分钟内实测到 200 / 404 / 502 / 504 / TLS 超时 / RST
        # 全套状态; 而候选池里的 199.232.113.140 在首个窗口起 40 分钟内始终 RST/502
        # (末次回归才 2/2 通过) —— 所以候选池不能按"整池全绿"判通过。
        # 因此这里声明通道, 由启动回归按"候选池顺序 + 四关实测"选出当时可用的那一个,
        # 全部失效时显式报 UNAVAILABLE (而不是继续写死这个常量假装正常)。
        # ★ 2026-10-04 补证书域族门槛: 掩护 SNI 下运行期 `proxy_ssl_verify off`, 证书是
        #   唯一防线。实测该通道拿到的恒是目标自己的证书 (2/2 候选均 SAN=`*.reddit.com`)
        #   ⇒ 声明后**零误杀**, 同时挡掉"把 reddit 的 Host 打到别家 Fastly 边缘
        #   拿回别家证书"的跨租户错配。
        cert_families=("reddit.com",),
        cover_sni_channel="reddit",
        # 探测域必须与掩护通道的判据一致 (通道用 www.reddit.com 做四关):
        # 原先是空 -> 退化成 domains[0]="reddit.com" (apex), 与通道/图片域都不是同一个 vhost,
        # 会出现"测速说这个节点好、掩护通道却说它不可用"的口径分裂。
        probe_domains=("www.reddit.com", "i.redd.it"),
        probe_ok_statuses=(403, 404),
        candidate_ips=["199.232.161.140", "199.232.113.140"]
    ),
    ServiceProfile(
        id="reddit_media",
        group="dev",
        name="Reddit 媒体与样式",
        desc="Reddit 图片/缩略图/样式域 (Fastly 掩护 SNI + 本地磁盘缓存, 边缘抖动时继续吐已缓存内容)",
        # 为什么单独成画像 (2026-10-03): 拿掉"唯一零外部依赖"的一环 —— 这条通道是**分钟级
        # 时变**的 (实测同一组合 40 分钟内 200/404/502/504 全出现过), 而图片/样式是**可缓存**
        # 的静态资源。合在 reddit 画像里时 enable_cache 只能为 False (那里面还有账号态网页与
        # 分段视频流), 于是边缘一抖图片就全破。拆开后这里开缓存 + 生成器的
        # `proxy_cache_use_stale error timeout http_5xx` 会在上游失败时**继续吐旧缓存** ——
        # 把"外部依赖抖动"降级成"已看过的图照常显示"。
        # 域集合与 reddit 画像**互不重叠** (v.redd.it / packaged-media.redd.it 是视频流, 留在那边)。
        domains=["i.redd.it", "preview.redd.it", "external-preview.redd.it",
                 "styles.redditmedia.com", "b.thumbs.redditmedia.com", "emoji.redditmedia.com"],
        icon="image",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_reddit_media",
        cdn_vendor="fastly",
        ssl_sni_mode="www.fastly.com",
        # ⚠ 2026-10-04 **暂缓声明 cert_families** —— 这是待决策的状态, 不是遗漏:
        #   本画像的候选池里 146.75.92.193 是 **imgur 边缘**, 在该掩护通道下拿到的是
        #   `*.imgur.com` 证书 (实测), 而另两个候选 (199.232.161.140 / 199.232.113.140)
        #   拿的是 `*.reddit.com`。于是声明 cert_families=("reddit.com",) 的确切后果是
        #   **淘汰 146.75.92.193** (实测 通过 2 / 淘汰 1)。
        #   该候选是**故意加的** (见下方 §2.5 依据: 三窗口下 6 个媒体域全部可用), 所以
        #   "加门槛"与"保住这个独立边缘"二者不可兼得 —— 属需要取舍的决策, 故先留白。
        #   实测参考: 三个候选对该画像 4 个媒体域**都**是 rank 0, 即去掉它不会立刻失能,
        #   只是少一个独立边缘。
        # 与 reddit 画像**同一条掩护通道** (同一个掩护域、同一组节点、同一套四关):
        # 不新开通道 —— 通道的证书族判据 (reddit.com/redd.it/redditmedia.com/redditstatic.com)
        # 已经覆盖这些域, 而独立通道会让"同一个掩护域是否有效"被重复探测两次。
        cover_sni_channel="reddit",
        enable_cache=True,
        # 媒体域根路径本就 403/404 (无索引页/无权限), 必须放行, 否则全部候选被判"可疑"淘汰
        probe_ok_statuses=(403, 404),
        probe_domains=("i.redd.it", "b.thumbs.redditmedia.com"),
        # ⚠ 与 reddit 画像的节点池**不同**, 依据是三窗口实测 (见 docs/archive/reddit-cover-sni-channel.md §2.5):
        #   · 加 **146.75.92.193** (imgur 的边缘): 三窗口下 6 个媒体域**全部可用** (404/403) ——
        #     给媒体多一个独立边缘。它在 reddit 主域画像上会 421 (跨租户), 但 421 只出现在
        #     `old.reddit.com`, 媒体域 33 次采样里 0 次 421, 所以**只**加到这个画像。
        #   · 不加 199.232.192.193: 对媒体域逐窗口退化 (styles/thumbs/emoji/packaged 从 404 变 502)。
        candidate_ips=["199.232.161.140", "199.232.113.140", "146.75.92.193"]
    ),
    ServiceProfile(
        id="reddit_static",
        group="dev",
        name="Reddit 静态资源",
        desc="Reddit 前端 JS/CSS 资源域 (实测自身 SNI 可用, 仅需修正被污染的解析)",
        # 为什么单独成画像而不并进 reddit: 后端行为不同 —— reddit 主域与**媒体域**必须用掩护 SNI
        # (自身 SNI 一律 502), 而 www.redditstatic.com 实测**自身 SNI 可用** (curl --resolve 到
        # 199.232.161.140 返回 404, 即 Fastly 正常服务), 只需把被污染的解析结果钉回真实 IP,
        # 不涉及掩护/QUIC。合池会把资源域也推上掩护通道, 属多域错配
        # (与 nuget 三拆、myanimelist 的 fal/mxj 同类教训)。
        domains=["redditstatic.com", "www.redditstatic.com"],
        icon="code",
        mode=ServiceMode.DIRECT,      # 只钉真实 IP, 不经本机反代
        cdn_vendor="fastly",
        ssl_sni_mode="host",
        # 必须放行 404 并把探测域钉到 www: 静态资源站**根路径本就返回 404**(无索引页),
        # 而 _suspect_status 把 400-404 判为"可疑节点"→ 全部候选被淘汰 → 界面显示
        # "reddit 测速总失败"(实测踩到)。apex redditstatic.com 无服务, 因此只探 www。
        probe_ok_statuses=(403, 404),
        probe_domains=("www.redditstatic.com",),
        candidate_ips=["199.232.161.140", "199.232.113.140"]
    ),
    # stackoverflow 于 2026-10-01 移除: 实测 **可直连** —— 系统解析干净 (198.252.206.x,
    # Stack Exchange 自有边缘), 自身 SNI 对 www/apex/cdn.sstatic.net 分别返回 302/403/307,
    # 无需任何加速 (早期按 QUIC_DIRECT 登记属误判, 见 docs 第十六节)。
    # 它真正被影响的是**图片域** i.stack.imgur.com (系统解析被污染成 31.13.112.4, 自身 SNI 502),
    # 已并入 imgur 画像走掩护通道处理 —— 这属于"只加速不可达的部分"。
    ServiceProfile(
        id="discord",
        group="dev",
        name="Discord 社区",
        desc="开发者与玩家社区 (经本机 ECH 隧道直连 Cloudflare, 浏览器无需支持 HTTP/3)",
        # 域名必须覆盖客户端真正连的每一跳 (2026-10-01 依用户实测反馈补齐):
        #   - cdn.discordapp.com / media.discordapp.net / images-ext-*: 头像、表情、附件与外链图片;
        #   - discord.gg / discordapp.net: 邀请链接与旧域跳转;
        #   - status.discord.com: 客户端的服务状态轮询 (实测经 ECH 隧道 200)。
        # 注意: **WebSocket 网关 gateway.discord.gg 已拆成独立画像 discord_gateway** ——
        # 它需要 Connection "upgrade" 头, 而通用块为保 upstream keepalive 用的是字面量空串,
        # 两者不能共用一个 server 块 (见 nginx_generator 的说明)。
        # 这些域名同时是 ECH 隧道白名单的来源 (隧道按 ech_enabled 服务的 domains 聚合) ——
        # 未登记会被隧道直接拒绝 (实测 19 字节的 403 "domain not allowed")。
        domains=["discord.com", "www.discord.com", "discordapp.com", "discordapp.net",
                 "cdn.discordapp.com", "media.discordapp.net",
                 "images-ext-1.discordapp.net", "images-ext-2.discordapp.net",
                 "discord.gg", "status.discord.com"],
        icon="message",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_discord",
        cdn_vendor="cloudflare",
        # 2026-10-01 实测: Cloudflare **拒绝跨租户掩护 SNI** —— cloudflare.com/www.cloudflare.com/
        # challenges.cloudflare.com/cloudflare-ech.com 四种掩护组合 × 2 个 CF 边缘 IP 全部返回 403;
        # 自身 SNI 又被 RST。只有 ECH 的加密内层 SNI 能同时通过两者, 而项目自带 ECH 隧道实测
        # discord.com -> 200 + 真实 HTML、www.reddit.com -> 200, 故 discord 走 ECH 隧道。
        # ssl_sni_mode 仅在"隧道不健康"的退化分支生效 (与 pixiv_web 同款处理)。
        ech_enabled=True,
        ssl_sni_mode="empty",
        candidate_ips=["162.159.137.232", "162.159.136.232"]
    ),
    ServiceProfile(
        id="discord_gateway",
        group="dev",
        name="Discord 网关 (WebSocket)",
        desc="Discord 客户端长连接网关 (经本机 ECH 隧道 + WebSocket 升级头)",
        # 为什么必须单独成画像: 它的路径是 `/` 而不是 `/ws/`, 因此**不能**靠 pixiv 那种
        # "/ws/ 专用 location" 来补升级头; 而通用块为保 upstream keepalive 用的是编译期
        # 字面量空串 Connection "" —— 那会把浏览器的 WS 升级头清掉, 客户端表现为
        # "[WS CLOSED] An error with the websocket occurred" 无限重连 (实测事故)。
        # 拆出来后只有这一个域付出 "Connection: upgrade" 的代价, discord.com 的
        # keepalive 优化不受影响。
        domains=["gateway.discord.gg"],
        icon="wifi",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_discord_gateway",
        cdn_vendor="cloudflare",
        ech_enabled=True,          # 与 discord 同走 ECH 隧道 (实测 WS 握手 101 Switching Protocols)
        websocket=True,            # 关键: 让生成器写 Connection "upgrade"
        ssl_sni_mode="empty",      # 仅隧道不健康时的退化分支
        candidate_ips=["162.159.137.232", "162.159.136.232"],
        # 退化分支下根路径本就是非 2xx: 网关的真实用法是 WebSocket 升级, 裸 GET 会被
        # Cloudflare 直接回 403 / 404 —— **这是对端自己的应答, 不是链路故障**。
        # 证据 (2026-10-02 实测): 该 403 **带 `cf-ray` 头**, 即来自 Cloudflare,
        # 而非本机 nginx 生成的错误页 (后者不会有 cf-ray)。
        # 不声明它, 退化分支的探测会把候选全判"状态码可疑" ⇒ 拿不到主力位
        # (实测 403×2 + 404×5 全部 suspect=True)。与 reddit_static 的 404 同类。
        probe_ok_statuses=(403, 404),
        probe_domains=("gateway.discord.gg",),
    ),

    # ==========================================================================
    # 成人内容生态 (受控分组 adult: 默认隐藏、默认不可启用, 需在设置页显式放开)
    #
    # 2026-10-03 实测 (docs/archive/pawchive-onboarding-2026-10-03.md) —— 本地通道判定:
    #   · 系统解析**干净** (104.21.95.170 / 172.67.146.57 + CF v6), 但真 SNI 一律 RST;
    #   · 掩护 SNI 与空 SNI 都被 Cloudflare 拒 (4 候选 × 3 形态 = 12/12 全停 TLS 层)
    #   ⇒ 既不是"DNS 污染钉 IP"型, 也不是"能直连"型, 本地只剩 **ECH 隧道**一条路。
    # 为什么拆三个画像: 三台主机的后端行为完全不同 (HTML/API / 静态缩略图 / 大二进制),
    #   缓存策略与超时诉求相反, 合池必然错配 (与 nhentai/nhentai_img 同一判据)。
    # ⚠ 隧道白名单由 domains 自动聚合; 受控分组未放开时该分组域名**不进白名单**
    #   (见 app/pyside_app.py 的 _start_ech_tunnel)。
    # ==========================================================================
    ServiceProfile(
        id="pawchive",
        group="adult",
        name="Pawchive 创作档案",
        desc="Pawchive 创作者投稿档案站 (Kemono 同族; Cloudflare 托管, 经本地 ECH 隧道)",
        domains=["pawchive.pw", "www.pawchive.pw"],
        icon="book",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_pawchive",
        cdn_vendor="cloudflare",
        ech_enabled=True,
        ssl_sni_mode="empty",       # 仅"隧道不健康"的退化分支取值 (与 pixiv_web/discord 同款)
        # 实测: / 200 · 15,608B 标题 Pawchive (3/3); /posts 200 · 75,340B 标题 "Posts | Pawchive";
        #       www 301 → 裸域; /api/v1/* 为 JSON (creators 单请求实测 15.4MB / 3.77s)。
        # 候选池只放**通用 CF 边缘**: 本域解析值可用, 但同类站点(见下)的解析值不可用,
        # 统一用 CF 边缘可避免"照抄 DoH 值"这类错配 (隧道内部也只接受 CF 网段答案)。
        candidate_ips=["104.21.95.170", "172.67.146.57", "104.18.42.239", "172.64.145.17"],
    ),
    ServiceProfile(
        id="pawchive_img",
        group="adult",
        name="Pawchive 缩略图 CDN",
        desc="Pawchive 预览/缩略图主机 (同 zone Cloudflare, 经本地 ECH 隧道, 静态图可缓存)",
        domains=["img.pawchive.pw"],
        icon="image",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_pawchive_img",
        cdn_vendor="cloudflare",
        ech_enabled=True,
        ssl_sni_mode="empty",
        # 实测 /thumbnail/data/<path> → 200 · 36,712B / 50,690B, Server: cloudflare;
        # ⚠ 该站的 content-type **不可信** (…png 的头配 RIFF/WEBP 字节), 故不按 MIME 做任何判据。
        candidate_ips=["104.21.95.170", "172.67.146.57", "104.18.42.239"],
        enable_cache=True,          # 纯静态图片, 值得本地落盘 (cache 与 buffering off 互斥, 见生成器)
    ),
    ServiceProfile(
        id="pawchive_dl",
        group="adult",
        name="Pawchive 原图与附件",
        desc="Pawchive 原图/压缩包/视频下载主机 (同 zone Cloudflare, 经本地 ECH 隧道)",
        # 为什么单独成画像: 原图/附件只在 n2 节点上 (同一 path 打 img/主站的 /data 是 404),
        # 且是 1.8MB 级图片与 zip/mp4 (50 条投稿里 zip 7 / mp4 3 / pdf 2)。
        # ⚠ 该主机的 DoH 答案是 **DDoS-Guard 挡板** (185.178.208.148, 直连只得 3.2KB 挡板页),
        #   而经 ECH 隧道打同一主机拿到 1,828,047B 真图 ⇒ 它其实同属该 CF zone。
        #   故 candidate_ips 仍只放通用 CF 边缘, **绝不可**抄那条 DoH 值。
        domains=["n2.pawchive.pw"],
        icon="folder",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_pawchive_dl",
        cdn_vendor="cloudflare",
        ech_enabled=True,
        ssl_sni_mode="empty",
        candidate_ips=["104.21.95.170", "172.67.146.57", "104.18.42.239"],
        enable_cache=False,         # 大二进制先不落盘: 避免 zip/mp4 挤掉共享缓存区里的图缓存
    ),

    # ==========================================================================
    # 服务补充计划 · 批次 1（2026-10-04 落地）
    #
    # 来源: docs/archive/service-expansion-feasibility-2026-10-03.md 第四节 Profile 草案
    #      （该文档带 2026-10-03 的实测证据: 状态码 / 字节数 / 标题 / 3-3 次）
    # 复核: docs/service-expansion-review-2026-10-03.md（18 个草案里 4 个依赖不存在的
    #      机制、2 个分类错误；其要求的"批次 0 门槛"已在 §七 落地）
    #
    # 本轮(2026-10-04)实际复核了**候选地址是否仍然可用**（只读: TLS/TCP 与 CF 网段判定）,
    # 结论写在各画像里。**未**重跑内容级验证（标题/字节数）—— 那是草案 2026-10-03 的
    # 证据, 本轮沿用并在每条里标明来源, 不把"地址可达"冒称"内容可用"。
    #
    # 分组决策: 草案写的是 `group="acg"`, 但**复核报告 §六.1 与既有先例 (pawchive) 都把
    #   成人平台放进受控分组 `adult`**: 该分组默认隐藏、且默认不可启用, 需在设置里显式
    #   开启。按"安全与合规优先"的次序, 这里沿用 `adult`（如需改回 acg, 只改 group 一行,
    #   但会立刻让这些站点出现在默认可见的二次元分组里）。
    # ==========================================================================

    # E-Hentai 全家: CF 托管 + 明文 SNI 被 RST ⇒ 只能走 ECH 隧道
    ServiceProfile(
        id="ehentai",
        group="adult",
        name="E-Hentai 图库",
        desc="E-Hentai/ExHentai 图库与上传站 (Cloudflare 托管, 经本地 ECH 隧道绕开明文 SNI 阻断)",
        # ⚠ 不含 forums.e-hentai.org: 实测 CF **托管挑战** 403 (cf-mitigated: challenge) 3/3,
        #   挑战一旦出现即不可解, 登记它等于登记一个必然失败的域名。
        domains=["e-hentai.org", "www.e-hentai.org", "repo.e-hentai.org",
                 "upld.e-hentai.org", "exhentai.org", "ehwiki.org", "hentaiverse.org"],
        icon="image",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_ehentai",
        cdn_vendor="cloudflare",
        ech_enabled=True,
        ssl_sni_mode="empty",       # 仅"隧道不健康"的退化分支取值 (与 pixiv_web/discord 同款)
        # 2026-10-03 实测: e-hentai.org / 200 · 60,751B 标题 "E-Hentai Galleries …" (3/3);
        #                  repo/upld 301 (3/3); exhentai 302 → forums…/remoteapi.php (无 cookie 正常表现)
        # 2026-10-04 复核: 6 个候选地址**全部**落在 CF 网段且 443 可达;
        #                  而系统解析给出 199.59.x / 31.13.x 一类投毒值 ⇒ 必须靠静态池
        candidate_ips=["104.18.42.239", "172.64.145.17", "104.18.10.118",
                       "104.21.56.202", "172.67.187.219", "172.66.140.62"],
    ),
    # nhentai 主站 (CF ⇒ ECH)
    ServiceProfile(
        id="nhentai",
        group="adult",
        name="nhentai 本子库",
        desc="nhentai 主站 (Cloudflare 托管, 经本地 ECH 隧道)",
        domains=["nhentai.net", "www.nhentai.net"],
        icon="book",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_nhentai",
        cdn_vendor="cloudflare",
        ech_enabled=True,
        ssl_sni_mode="empty",
        # ⚠ 图床 i/t.nhentai.net **不并进本画像**: 实测它们经 ECH 会得到 520 (CF 回源错误),
        #   两者后端行为不同, 合池必错配 (草案也把这条列为"必须拆画像的反例")。
        # 2026-10-03 实测: / 200 · 44,035B 标题 "nhentai: hentai doujinshi and manga" (3/3)
        # 2026-10-04 复核: 3 个候选全在 CF 网段且可达
        candidate_ips=["104.26.4.188", "104.26.5.188", "172.67.74.203"],
    ),
    # FurAffinity (CF ⇒ ECH)
    ServiceProfile(
        id="furaffinity",
        group="adult",
        name="FurAffinity 兽圈创作社区",
        desc="FurAffinity 主站与作品图床 (Cloudflare 托管, 经本地 ECH 隧道)",
        domains=["furaffinity.net", "www.furaffinity.net", "d.furaffinity.net"],
        icon="image",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_furaffinity",
        cdn_vendor="cloudflare",
        ech_enabled=True,
        ssl_sni_mode="empty",
        # 2026-10-03 实测: www 200 · 129,706B (3/3); d.* (图床) 200 (3/3)
        # 2026-10-04 复核: 2 个候选全在 CF 网段且可达; 系统解析给 199.59.x (投毒)
        candidate_ips=["104.20.18.254", "172.66.163.196"],
        enable_cache=True,          # 静态图片, 值得本地落盘
    ),
    # DLsite 商店 (CF ⇒ ECH)
    ServiceProfile(
        id="dlsite",
        group="adult",
        name="DLsite 同人商店",
        desc="DLsite 商店与图片 CDN (Cloudflare 托管, 经本地 ECH 隧道)",
        # ⚠ 不含 play.dlsite.com: 播放器是 AWS 源站且要**掩护 SNI**, 通道性质完全不同 ⇒ 单独画像
        domains=["dlsite.com", "www.dlsite.com", "img.dlsite.jp"],
        icon="shopping_bag",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_dlsite",
        cdn_vendor="cloudflare",
        ech_enabled=True,
        ssl_sni_mode="empty",
        # 2026-10-03 实测: www 301 · 281B (3/3); img.dlsite.jp 200 · 434,454B (3/3)
        # 2026-10-04 复核: 4 个候选全在 CF 网段且可达; 系统解析给 108.160.165.48 (投毒)
        candidate_ips=["104.18.24.157", "104.18.25.157", "104.18.42.239", "172.64.145.17"],
    ),
    # Cara (CF ⇒ ECH)
    ServiceProfile(
        id="cara",
        group="adult",
        name="Cara 艺术家社区",
        desc="Cara 艺术家社区 (Cloudflare 托管, 经本地 ECH 隧道)",
        domains=["cara.app", "www.cara.app"],
        icon="palette",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_cara",
        cdn_vendor="cloudflare",
        ech_enabled=True,
        ssl_sni_mode="empty",
        # 2026-10-03 实测: 307 → /explore 属正常规范化 (已人工看 Location, 非工具假绿) 3/3
        # 2026-10-04 复核: 2 个候选全在 CF 网段且可达; 系统解析**恰好**给出同样的地址
        #                 (说明该域解析未被投毒, 但仍放 CF 边缘以避免"照抄 DoH 值"这类错配)
        candidate_ips=["104.18.4.45", "104.18.5.45"],
    ),
    # ArtStation 素材 CDN (CF ⇒ ECH)
    ServiceProfile(
        id="artstation_cdn",
        group="adult",
        name="ArtStation 素材 CDN",
        desc="ArtStation 作品/素材 CDN (Cloudflare 托管, 经本地 ECH 隧道)",
        # ⚠ 只登记图床 cdna, **不含主站**: 主站实测 2/3 且会命中 CF 托管挑战 ⇒ 归 B 类缓入
        domains=["cdna.artstation.com"],
        icon="image",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_artstation_cdn",
        cdn_vendor="cloudflare",
        ech_enabled=True,
        ssl_sni_mode="empty",
        # 2026-10-03 实测: 根路径 200 (返回 "OK") 3/3
        #   ⚠ 该 200 只有"图床可能可用"的价值, **不是**内容级可用证据 (草案 §四/复核 §四.3 自陈)
        # 2026-10-04 复核: 2 个候选全在 CF 网段且可达; 系统解析给 128.121.146.101 (可疑)
        candidate_ips=["104.19.170.40", "104.19.169.40"],
        enable_cache=True,          # 素材/作品图, 值得本地落盘
    ),
    # Hitomi: 域名级 SNI 被 RST, 但自有服务器真实 IP 可用 ⇒ DIRECT (钉静态 IP)
    ServiceProfile(
        id="hitomi",
        group="adult",
        name="Hitomi.la 图库",
        desc="Hitomi.la 图库 (DNS 被污染, 钉静态 IP 直连)",
        domains=["hitomi.la"],
        icon="image",
        mode=ServiceMode.DIRECT,    # 走解析层直指该 IP, 不经 nginx (NGINX_BYPASS_MODES)
        ssl_sni_mode="host",
        # 2026-10-03 实测: hitomi.la @185.165.169.231 → 200 · 5,145B 标题 "Hitomi.la" (3/3)
        # 2026-10-04 复核: 对**真实 SNI=hitomi.la** 的 TLS 握手成功 (证书链可协商);
        #                  而系统解析给出 128.242.245.125 / 2001::68f4:2b34 (投毒) ⇒ 必须钉 IP
        # ⚠ 单候选无容灾 (复核 §四.4 已点): 该 IP 失活时本画像没有可换的节点, 只能靠
        #   健康巡检重排 —— 而池里只有一个。补足第二个经静态复核的 IP 属后续工作。
        candidate_ips=["185.165.169.231"],
    ),
    # Pinterest 图床 (Fastly, DIRECT)
    ServiceProfile(
        id="pinimg",
        group="adult",
        name="Pinterest 图床",
        desc="Pinterest 图片 CDN (Fastly, 钉静态 IP 直连)",
        # ⚠ 只登记图床; 主站 www.pinterest.com 实测仅 1/3 (Akamai 按 SNI 选证书) ⇒ 不登记
        domains=["i.pinimg.com"],
        icon="image",
        mode=ServiceMode.DIRECT,
        ssl_sni_mode="host",
        # 2026-10-03 实测: @151.101.76.84 /robots.txt 200 · 2,756B (3/3)
        # 2026-10-04 复核: 真实 SNI=i.pinimg.com 的 TLS 握手成功; 系统解析给
        #                  108.160.166.61 / 2a03:2880:…:face:b00c (投毒段) ⇒ 必须钉 IP
        # ⚠ 单候选无容灾。草案注释建议"替换为实测的第二个 Fastly 边缘", 但**本轮没有**
        #   实测出第二个可用的边缘地址 ⇒ 这里只放已核实的那一个, 不编造候选
        #   (往池里塞未验证地址比池子小更糟: 它会成为"第一个打死整条链路"的那个)。
        candidate_ips=["151.101.76.84"],
        enable_cache=True,          # 纯静态图片, 值得本地落盘
    ),

    # ==========================================================================
    # 服务补充计划 · 批次 2（2026-10-04 落地）—— 空 SNI / 掩护 SNI 通道
    #
    # 来源同上；复核报告把这一类判为 **B 类（时变通道，需缓入）**，理由两条：
    #   ① 空 SNI 只瞒过 TLS 层, **HTTP Host 仍是明文**, GFW 可按 Host 封;
    #   ② 这类通道此前**没有证书门槛** —— `VENDOR_CERT_SUFFIXES` 只登记了 google,
    #      于是"源站忽略 SNI"与"空 SNI"两类画像根本没有防线, 别家 vhost / 链路侧
    #      劫持页的 2xx 会被当成可用收进池 (实测形态: 证书 fallback.wgcz.net / flirtify.com)。
    #
    # 因此本批**逐条补上 `cert_families`**（证书必须仍是目标域自己的, 见 _cert_gate）,
    # 并统一 `experimental_default_off=True`（时变通道不纳入默认启用清单）。
    #
    # 2026-10-04 本轮独立复核（只读 TLS 握手 + 读对端证书域族）:
    #   · ehentai_img 3/3 · nhentai_img 2/3 · dlsite_play 2/2 · sankaku 2/2
    #   · 每个可用候选都满足"**真实 SNI 失败** + 空/掩护 SNI 成功 + 证书域族 == 目标域族"
    #     —— 第三条同时证明了"没有打到别家 vhost 上"。
    #   · nhentai_img 的 109.202.100.218 已**失效**（空 SNI 亦握手超时）⇒ 从池中剔除,
    #     按"只放已核实地址"的口径降为 2 个候选。
    # ==========================================================================
    ServiceProfile(
        id="ehentai_img",
        group="adult",
        name="E-Hentai 图床",
        desc="E-Hentai 缩略图与原图服务器 (自有服务器非 CF, 空 SNI 可直连, 图片可缓存)",
        # 与 ehentai 主站**必须拆画像**: 主站是 CF 托管走 ECH, 此处是自有服务器走空 SNI,
        # 后端行为完全不同 (合池必错配 —— 这正是本计划反复强调的一条)。
        domains=["ehgt.org", "www.ehgt.org"],
        icon="image",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_ehentai_img",
        ssl_sni_mode="empty",
        # ★ 这个门槛是本画像唯一的防线 (运行期 proxy_ssl_verify 必须 off):
        #   证书域族必须是 ehgt.org —— 否则说明打到了别家 vhost 或劫持页。
        cert_families=("ehgt.org",),
        experimental_default_off=True,   # 时变通道, 不纳入默认启用
        # 2026-10-03 草案实测: 真实缩略图 /w/02/689/24860-taj1rbzd.webp →
        #                     200 · image/webp · 6,554B (2 IP × 2 次全中)
        # 2026-10-04 复核: 3 个候选都是"真 SNI 失败 + 空 SNI 通 + 证书域族 ehgt.org"
        candidate_ips=["89.39.106.43", "62.112.8.21", "109.236.85.28"],
        enable_cache=True,          # 纯静态图片, 值得本地落盘
    ),
    ServiceProfile(
        id="nhentai_img",
        group="adult",
        name="nhentai 图床",
        desc="nhentai 缩略图与原图服务器 (自有服务器非 CF, 空 SNI 可直连, 图片可缓存)",
        # ⚠ 与 nhentai 主站拆画像的必要性有**实测反例**: 图床走 ECH 会得到 520 (CF 回源错误)。
        #   故本画像的正确手法是**空 SNI** (不是真实 SNI, 也不是 ECH):
        #     空 SNI     -> 200 + 真图 (实测)
        #     真实 SNI   -> ConnectionResetError (338ms)
        #     apex SNI   -> ConnectionResetError
        #   ★ 2026-10-04 补 t3: 页面在 `t3.nhentai.net` 上取缩略图, 而原画像只登记了
        #     i./t. 两个 → 实测两个候选对 t3 都回 200 + 35KB 缩略图 (1419/1680ms)。
        #     未登记即不劫持 → 那条子域走真实解析(被投毒) → 表现为图片不全。
        domains=["i.nhentai.net", "t.nhentai.net", "t3.nhentai.net"],
        icon="image",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_nhentai_img",
        ssl_sni_mode="empty",
        cert_families=("nhentai.net",),   # 空 SNI 下的唯一防线 (见 ehentai_img 注释)
        experimental_default_off=True,
        # 2026-10-03 草案实测: 空 SNI 握手通过 · 证书 CN=*.nhentai.net · HTTP 200 (真 SNI 一律 RST)
        # 2026-10-04 复核: 213.152.165.53 / .54 通过 (证书域族 nhentai.net);
        #                  ⚠ 109.202.100.218 已失效 (空 SNI 也握手超时) ⇒ 剔除, 池降为 2
        # ★★ 2026-10-04 二次复核 —— 上一行"已失效⇒剔除"的结论**已过期**, 现按实测扩池回 4:
        #   每条都实测 3 次 (空 SNI, 取真实图 /galleries/9/1.jpg, 均 200 + 256054B):
        #     77.247.178.1      1912 / 2350 / 2101 ms   ← **最快最稳, 原先从未登记**
        #     109.202.100.218   2374 / 5662 / 11699 ms  ← 上次判"已失效", 实测已恢复
        #     213.152.165.53    7729 / 5881 / 4909 ms
        #     213.152.165.54    5959 / 2232 / 3854 ms   ← 曾达 63s, 方差极大
        #   扩池的价值: 本画像的服务器方差极大 (2.4s~63s), 池子宽 + 最快的排首位,
        #   能显著提高"nginx 抽到一个快地址"的概率。
        #
        # ⚠⚠ 但必须说清: **扩池并不能让探测判它可用** —— 根因不在池子。实测 (空 SNI):
        #       77.247.178.1  i.nhentai.net  /                  -> 200 连接后 **0 字节**
        #       77.247.178.1  i.nhentai.net  /galleries/9/1.jpg -> 200 + 256054B
        #       213.152.165.53 i.nhentai.net /                  -> 0 字节
        #       213.152.165.53 i.nhentai.net /galleries/9/1.jpg -> 200 + 256054B
        #     即**这些服务器对根路径不应答, 只对真实内容路径应答**。而
        #     `cdn_optimizer.probe_ip_endpoint_v2` 硬编码请求 `GET /` ⇒ 该画像
        #     永远 0 个 rank0 (实测 4 个档位 probe_timeout 全是 0/5), 于是
        #     `apply_optimal` 永远走候选池兜底 —— 这才是"检测不可用、实际可用"的机制。
        #   为什么**没有**顺手加 per-profile 探测路径: 量化后只有本画像受影响 ——
        #     审计中其余"快速失败"的 9 个画像 (cara/dlsite/ehentai/furaffinity/nhentai/
        #     pawchive×3/pixiv_web) 都是 ECH 隧道类, 它们的空响应是"剥离隧道"造成的,
        #     项目内走 127.0.0.1:44401 是好的。为一个画像给 probe_ip_endpoint_v2
        #     做端到端 path 穿透 (含 test_group / apply_optimal 全部调用点) 收益过小、风险过大。
        #     ⇒ 记在此处待将来批量做 (若出现第二个同类画像)。
        candidate_ips=["77.247.178.1", "213.152.165.53", "213.152.165.54",
                       "109.202.100.218"],
        # ★ 真实内容链接 —— 修掉"探测永远判它死"的根因 (见 probe_path 字段注释)。
        #   为什么必须是这一条: 本画像**对根路径不应答**(实测 `/` 回 0 字节), 而固定
        #   `GET /` 的探测因此永远 0 个 rank0。改用真实图片路径后能拿到 200 + 256054B。
        #   `media_id=9` 是 nhentai 最老的公开画廊之一, 路径 `/galleries/<media_id>/<n>.jpg`
        #   由 API 给出、长期不变 (实测 256054B 稳定复现); 且**无需鉴权、无防盗链**。
        #   ⚠ 若将来该路径失效, 探测会把它判死并回退候选池 —— 与设它之前的现状相同,
        #     不会更糟 (这是"宁可退化为旧行为"的取舍)。
        probe_path=("i.nhentai.net", "/galleries/9/1.jpg"),
        enable_cache=True,
    ),
    ServiceProfile(
        id="dlsite_play",
        group="adult",
        name="DLsite 播放器",
        desc="DLsite 作品播放器 (AWS 源站忽略 SNI, 用无害 SNI 掩护绕过域名级阻断)",
        # ⚠ 与 dlsite 商店拆画像: 商店是 CF 托管走 ECH, 播放器是 AWS 源站走掩护 SNI。
        domains=["play.dlsite.com"],
        # ⚠ 原为 icon="play" —— 该名字**不在 SVG_TEMPLATES 里**, 而 SvgIconFactory 对未知名字
        #   是**静默返回一张全透明 QPixmap** ⇒ 界面渲染成空白图标且没有任何报错 (2026-10-04
        #   由 tests/test_theme_and_layout.py::test_every_profile_icon_has_svg_template 抓到)。
        #   改用已登记的 "video" (语义相符: 播放器)。
        icon="video",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_dlsite_play",
        cdn_vendor="fastly",
        ssl_sni_mode="www.fastly.com",   # 证书仍是 play.dlsite.com ⇒ 源站忽略 SNI
        cert_families=("dlsite.com",),   # 掩护 SNI 下必须验证"证书仍是目标自己的"
        experimental_default_off=True,
        # 2026-10-03 草案实测: cover=www.fastly.com @54.95.70.54 → 200,
        #                     证书 CN=play.dlsite.com (3/3)
        # 2026-10-04 复核: 两个候选都满足"真 SNI 失败 + 掩护 SNI 通 + 证书域族 dlsite.com"
        candidate_ips=["54.95.70.54", "3.115.169.42"],
    ),
    ServiceProfile(
        id="sankaku",
        group="adult",
        name="Sankaku Channel 图库",
        desc="Sankaku 图库与新闻站 (自有 CDN 忽略 SNI, 掩护 SNI 可直连, 图片可缓存)",
        domains=["chan.sankakucomplex.com", "www.sankakucomplex.com", "sankakucomplex.com"],
        icon="image",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_sankaku",
        cdn_vendor="fastly",
        ssl_sni_mode="www.fastly.com",
        cert_families=("sankakucomplex.com",),
        experimental_default_off=True,
        # 2026-10-03 草案实测: 302 / 200, 证书 CN=iapi.sankakucomplex.com (自有 CDN, 忽略 SNI), 3/3
        # 2026-10-04 复核: 两个候选都满足"真 SNI 失败 + 掩护 SNI 通 + 证书域族 sankakucomplex.com"
        candidate_ips=["143.192.150.197", "143.192.150.194"],
        enable_cache=True,
    ),
    # --------------------------------------------------------------------------
    # hlib.cc (H图书馆) —— 2026-10-04 按用户指示接入, 走 ECH 隧道
    #
    # 通道判定 (本次实测, 详见注释内数据):
    #   · 系统解析**干净** (104.21.53.75 / 172.67.210.98) 且等于 DoH 答案 ⇒ **不是**
    #     "DNS 污染钉 IP"型 (对比 hitomi: 系统解析被投毒);
    #   · 两个地址经 `ech_tunnel.is_cloudflare_ip` 判定**都在 CF 网段** ⇒ CF 托管;
    #   · 真 SNI / 空 SNI / 两种掩护 SNI **四种形态全部停在 TLS 层** (WinError 10054
    #     ConnectionReset 与 handshake_failure) ⇒ 本地没有可直连的形态;
    #   · 该域**确实发布 ECH 配置**: DoH 的 HTTPS RR 返回
    #     `ech=AEX+DQBB+AAgACD1pZvdD5sHHANMZyCYm0HK9WMgj+BzRP7oSbbFgbGsNQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=`
    #     (外层 SNI = cloudflare-ech.com), 且该外层 SNI 在本机**可正常握手**
    #     ⇒ ECH 外层未被封, 走隧道是结构上唯一的路 (与 ehentai/nhentai/pawchive 同类)。
    #   ⇒ 结论: 与 pawchive 完全同款 —— **ECH 隧道**是本地唯一通道。
    #
    # ⚠ 2026-10-04 实测结论 (推翻本条早先的一段判断, 如实记录):
    #   ✅ **ECH 通道确认可用**。用项目自己的启动实现 (`scripts/test_ech_tunnel_live.py`,
    #      内部走 EchTunnelManager.build_command + build_ech_targets) 实测:
    #        [ech] 已更新 ECHConfig (71 字节, 来自 https://223.5.5.5/resolve)
    #        hlib.cc/n -> HTTP/1.1 200 OK · 114,820B (server: cloudflare, 真实内容)
    #      关键差异在于**生产用的是国内可达的 DoH** (223.5.5.5 / dns.alidns.com,
    #      见 ech_tunnel.DEFAULT_DOH_ENDPOINTS)。我先前手敲隧道时用的是
    #      1.1.1.1/8.8.8.8 —— 那两个在本机**被阻断**, 于是隧道拿不到 ECHConfig、
    #      只能沿用兜底配置, 表现为 `tls: server rejected ECH` + 502。
    #      同一条测试隧道对 e-hentai.org / nhentai.net (已知可用) 也报同样的错 ⇒
    #      那次测量**无效**, 不能作为本域不可用的证据 (已撤回该结论)。
    #   ⚠ **antibot 挑战**: `/n` 会被 `302 -> /antibot?token=...` 拦下, 且**每次新请求
    #      都拦** (连续 8/8 次)。但它是**可解**的, 与 artstation 主站那种"CF 托管挑战
    #      常态化即不可解"**不同类**:
    #        · 挑战页 (200 · 7,228B, 标题「人机校验」) 内含 `<script>` 与 turnstile /
    #          recaptcha 组件, 验证通过后由 JS 自行 `window.location.href = '/n'` 跳回;
    #        · 文案明确 "只需刷新此页即可自动跳转"、"如果已于其他伊蕾娜页面完成验证,
    #          则无需进行本页验证" ⇒ 它是**真人可过**的一次性校验, 不是死墙。
    #      ⇒ 真实浏览器可自行通过; 代价只是**冷启动首访需过一次人机校验**。
    #      ⚠ 但探测**不执行 JS**, 因此本画像的明文探测恒看到 302 (见下 probe_domains 说明)。
    ServiceProfile(
        id="hlib",
        group="adult",
        name="H图书馆 (hlib.cc)",
        desc="中文 H 小说站 (Cloudflare 托管, 经本地 ECH 隧道; 首访需过一次人机校验)",
        domains=["hlib.cc", "www.hlib.cc"],
        icon="book",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_hlib",
        cdn_vendor="cloudflare",
        ech_enabled=True,
        ssl_sni_mode="empty",      # 仅隧道不健康时的退化分支
        experimental_default_off=True,
        # 探测行为说明: 走默认 `/` (即 302 -> /n)。**探测不执行 JS**, 所以它看到的
        # 一定是 302 而不是挑战后的 200 —— 这不是故障, 而是本画像的确定性形态:
        #   · 302 属默认放行的 3xx, 故不会判"状态码可疑";
        #   · Location 是同域不同路径 (/n), 不是 `A -> B -> A` 死循环, 不会被
        #     self_redirect 误判;
        #   · ECH 类画像的**运行时可用性本来就不由明文探测决定** (隧道负责 TLS),
        #     探测只用于挑候选/防污染, 因此这里 302 是预期结果。
        # 不设 probe_path: 根路径已给出确定性响应 (302), 与 nhentai_img 那种
        # "根路径 0 字节、判不了"的情形不同。
        probe_domains=("hlib.cc", "www.hlib.cc"),
        # 2026-10-04 实测: DoH (1.1.1.1 与 8.8.8.8) 均返回这两个地址, 系统解析一致;
        # 两者都在 CF 网段 (build_ech_targets 只收 CF 段内的候选, 故它们都能进隧道池)。
        candidate_ips=["104.21.53.75", "172.67.210.98"],
    ),
    # --------------------------------------------------------------------------
    # Civitai (2026-10-04 接入)
    #
    # ⚠ 本条**修正了归档草案的通道判定**: 草案 (service-expansion-feasibility-2026-10-03
    #   §8.4/8.5) 写"civitai.com 全家族在 Cloudflare ⇒ ECH 隧道", 但**实测该 zone 不发布
    #   ECH 配置** —— HTTPS RR 明确回 `ech=no` (对照 hlib.cc 回 `ech=AEX+DQBB...`)。
    #   而 ECH 隧道必须服务端发布 ECHConfig 才能解密内层 SNI, 故:
    #     · 项目自己的隧道实测 civitai.com → **502**, 日志 `wsarecv: forcibly closed`
    #       (CF 边缘直接重置);
    #     · 三条 TCP 路全灭: 真 SNI → RST; 空 SNI → handshake_failure;
    #       掩护 SNI `cloudflare-ech.com` 能握手 (TLS1.3/h2) 但证书是掩护域自己的,
    #       带真实 Host 取回的是 CF **通用 403 页** (553B), 没有 ECH 就解不开内层 SNI。
    #   ⇒ 结论: civitai **不能走 ECH/掩护 SNI**。
    #
    # ★ 真正可用的通道是 **HTTP/3**: 它的 HTTPS RR 声明 `alpn=h3`, 而实测 QUIC 通:
    #     两个地址 (172.66.152.186 / 104.20.38.219) 均 HTTP/3 200 · 141,808 B,
    #     标题 "Civitai | Discover and Create AI Art"。
    #   这与 googlevideo 的先例同型 (TCP 全灭、QUIC 独活), 故复用**同一条 h3 上游腿**
    #   (app/h3_upstream, 默认 127.0.0.1:44411); 该腿的解析器本就按 Host 自行解析,
    #   且注释明确支持"也能服务普通 h3 目标"。
    ServiceProfile(
        id="civitai_web",
        group="acg",
        name="Civitai 模型站",
        desc="AI 绘画模型社区 (TCP 三路全灭, 经本地 HTTP/3 上游腿直连 Cloudflare)",
        # 内容域按方案清单登记; blobs-b2 是图片**真载体** (实测页面 43 次 200, 而
        # image.civitai.com 只做 301 中转), 漏了它就会"页面能开、图全挂"。
        # ⚠ 这些名字都**不是** CF 网段排除对象, 而是 h3 腿按 Host 解析的目标。
        domains=["civitai.com", "www.civitai.com", "auth.civitai.com",
                 "image.civitai.com", "imagecache.civitai.com",
                 "blobs-b2.civitai.com", "faro.civitai.com"],
        icon="image",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_civitai_web",
        h3_upstream=True,          # ★ 唯一可用通道 (见上)
        skip_cdn_probe=True,       # 上游是本地腿, 明文探测复现不了 h3 路径
        ssl_sni_mode="host",       # 仅腿不健康时的退化分支 (该分支对 CF 会被 403)
        # 候选地址仍写出来: 它们是腿可用的目标地址, 也是 hosts/DNS 层钉 IP 的依据。
        candidate_ips=["172.66.152.186", "104.20.38.219"],
        probe_domains=("civitai.com",),
        # 退化分支下 CF 对"无 ECH 的明文握手"回 403/421 属确定性响应, 不当作链路故障
        probe_ok_statuses=(403, 404, 421),
        # ★ 内容级验证已通过 (2026-10-04, 用真实图片 URL):
        #     image.civitai.com/<hash>/<uuid>/original=true/…jpeg
        #       → 301 → blobs-b2.civitai.com/file/blobs-managed-public/<id>
        #       → **HTTP/3 200 · 354,229 B · content-type: image/jpeg · JPEG magic 正确**
        #     (两个地址都是; 约 2.5 s —— 含两次握手与一次重定向)
        #   这同时印证了"image 只做中转、blobs-b2 才是真载体"的判定, 故两者都必须登记。
        #   ⇒ 内容可用性已确认, 与 googlevideo(播放未验证故默认关闭)不同, 本画像可默认启用。
        # 刻意**不**接管 civitai.red: 它靠**浏览器自己**过 CF 托管挑战活着, 一旦被 hosts
        # 劫持到本地, 挑战就交给本机上游去解 ⇒ 大概率过不了, 反而把"能直连"的入口弄坏
        # (方案 §8.3 实测: direct 模式下 civitai.red 页面 158 请求成功)。
    ),
    # Civitai 模型下载出口 (Cloudflare R2)
    #
    # ★ 为什么单独成画像且**不走本机 nginx** (2026-10-04 实测):
    #   · 模型下载会 307 跳到 R2 签名 URL, 主机形如
    #     `civitai-delivery-worker-prod.<hash>.r2.cloudflarestorage.com`;
    #   · 该主机**用自身真实 SNI 就能握手** (实测 TLS1.3, 证书 SAN 就是它自己
    #     `*.5ac...r2.cloudflarestorage.com`), 即**没有被 SNI 阻断** —— 与主域相反;
    #   · 因此它**不需要** ECH/掩护/h3 中的任何一条, 让它**直连**最快: 不经本机 nginx、
    #     不经 Go 隧道, 2–7 GB 的字节流不占本机磁盘与 CPU。
    #   ⇒ mode=DIRECT: 只在**解析层**把它钉到干净 IP (防系统解析被投毒), 数据面直连。
    #   ⚠ 这也顺手避开一个陷阱: `build_ech_targets` 只收 **CF 网段内**的候选, 而该主机
    #     在 CF 网段 (172.64.190.1) —— 若把它塞进任何 ech_enabled 画像, 它会被自动拉进
    #     ECH 隧道, 正是最慢的那条路。
    ServiceProfile(
        id="civitai_dl",
        group="acg",
        name="Civitai 模型下载",
        desc="模型文件下载出口 (Cloudflare R2, 真实 SNI 可用 ⇒ 直连最快)",
        # ⚠ 必须写**全名**: 隧道/白名单按后缀匹配, 只写 `cloudflarestorage.com` 会把
        #   **所有** R2 桶都放进来 (方案 §8.4 已点明这一点)。
        domains=["civitai-delivery-worker-prod.5ac0637cfd0766c97916cefa3764fbdf.r2.cloudflarestorage.com"],
        icon="folder",
        mode=ServiceMode.DIRECT,   # 只钉真实 IP, 不经本机反代
        upstream_name="upstream_civitai_dl",
        ssl_sni_mode="host",       # 真实 SNI 实测可用 (证书就是它自己)
        # 不声明 cert_families: DIRECT 走解析层, 证书由浏览器自己按真实 SNI 校验,
        # 这里没有探测阶段可言 (cert_families 只在探测/掩护通道有意义)。
        # ⚠ 顺序是**实测**定的, 不是照抄 DoH 答案顺序 (2026-10-04):
        #   DoH 回 ['172.64.66.1', '172.64.190.1'], 但 DIRECT 模式下只有
        #   `candidate_ips[0]` 会被真正钉进解析层 ⇒ **第一位就是实际用的那个**。
        #   实测 (各 3 次同刻对照, R2 主机名做 SNI):
        #     172.64.66.1   3/3 成功 (722 / 1746 / 1316 ms)  ← 稳定且更快
        #     172.64.190.1  2/3 成功 (736 / 1370 / 第三次 RST) ← 时变, 会 RST
        #   故把稳定的那个放首位, 时变的留作备选。
        candidate_ips=["172.64.66.1", "172.64.190.1"],
        stable_ips=["172.64.66.1"],
        # 不设 path_rules: 本画像在 nginx 侧**没有 server 块** (DIRECT ∈ NGINX_BYPASS_MODES),
        # path_rules 是 L7 概念, 放这里等于死配置 —— 直连路径本就没有"缓冲/超时"可调,
        # 那正是它比反代快的原因。
    ),
]

# 索引字典与导出辅助
PROFILES_BY_ID: Dict[str, ServiceProfile] = {p.id: p for p in PROFILES}
PROFILES_BY_DOMAIN: Dict[str, ServiceProfile] = {}
for _p in PROFILES:
    for _d in _p.domains:
        PROFILES_BY_DOMAIN[_d.lower()] = _p


def get_profile_by_id(service_id: str) -> Optional[ServiceProfile]:
    """通过服务 ID 获取 Profile"""
    return PROFILES_BY_ID.get(service_id)


def get_profile_by_domain(domain: str) -> Optional[ServiceProfile]:
    """通过域名获取对应的 ServiceProfile (支持基础通配符匹配)"""
    d_lower = domain.lower()
    if d_lower in PROFILES_BY_DOMAIN:
        return PROFILES_BY_DOMAIN[d_lower]
    # 查找泛域名后缀
    for registered_domain, profile in PROFILES_BY_DOMAIN.items():
        if registered_domain.startswith("*.") and d_lower.endswith(registered_domain[1:]):
            return profile
        elif d_lower.endswith("." + registered_domain):
            return profile
    return None

TOTAL_SERVICES_COUNT: int = len(PROFILES)


# ==============================================================================
# 官方生态主站快捷导航数据注册表
# ==============================================================================
NAVIGATOR_SERVICES = [
    # 二次元与创作者
    {
        "id": "pixiv",
        "group": "acg",
        "name": "Pixiv 插画主站",
        "desc": "日本知名二次元插画、漫画、小说交流与投稿平台",
        "url": "https://www.pixiv.net",
        "domain": "pixiv.net",
        "icon": "palette",
        "tags": ["插画", "画师", "二次元", "P站", "Pixiv"]
    },
    {
        "id": "fanbox",
        "group": "acg",
        "name": "Pixiv FANBOX",
        "desc": "Pixiv 旗下创作者赞助与粉丝专属俱乐部",
        "url": "https://www.fanbox.cc",
        "domain": "fanbox.cc",
        "icon": "palette",
        "tags": ["赞助", "创作者", "插画", "画师", "FANBOX"]
    },
    {
        "id": "booth",
        "group": "acg",
        "name": "BOOTH 同人商城",
        "desc": "二次元同人志、3D模型、Cosplay与手作市集",
        "url": "https://booth.pm",
        "domain": "booth.pm",
        "icon": "shopping_bag",
        "tags": ["同人", "商城", "3D模型", "周边", "BOOTH"]
    },
    {
        "id": "pixivision",
        "group": "acg",
        "name": "Pixivision 官方杂志",
        "desc": "Pixiv 官方二次元文化、特辑与插画精选杂志",
        "url": "https://www.pixivision.net",
        "domain": "pixivision.net",
        "icon": "book",
        "tags": ["特辑", "画师专访", "资讯", "Pixivision"]
    },
    {
        "id": "danbooru",
        "group": "acg",
        "name": "Danbooru 动漫图库",
        "desc": "全球知名二次元动漫标签化图库与插画检索站",
        "url": "https://danbooru.donmai.us",
        "domain": "danbooru.donmai.us",
        "icon": "image",
        "tags": ["图库", "动漫", "壁纸", "标签检索", "Danbooru"]
    },
    {
        "id": "vndb",
        "group": "acg",
        "name": "VNDB 视觉小说资料库",
        "desc": "全球权威的 Galgame / 视觉小说综合百科资料库",
        "url": "https://vndb.org",
        "domain": "vndb.org",
        "icon": "book",
        "tags": ["Galgame", "视觉小说", "评分", "百科", "VNDB"]
    },
    {
        "id": "fantia",
        "group": "acg",
        "name": "Fantia 创作者俱乐部",
        "desc": "日本知名同人插画、声优与 Cosplay 创作者赞助平台",
        "url": "https://fantia.jp",
        "domain": "fantia.jp",
        "icon": "star",
        "tags": ["创作者", "赞助", "同人", "Cosplay", "Fantia"]
    },

    # 游戏生态
    {
        "id": "steam_store",
        "group": "gaming",
        "name": "Steam 游戏商店",
        "desc": "Valve 旗下全球最大的 PC 游戏分发与购买平台",
        "url": "https://store.steampowered.com",
        "domain": "store.steampowered.com",
        "icon": "shopping_bag",
        "tags": ["游戏", "Steam", "商店", "特惠", "Steam商店"]
    },
    {
        "id": "steam_community",
        "group": "gaming",
        "name": "Steam 玩家社区",
        "desc": "Steam 玩家个人资料、动态、创意工坊与讨论区",
        "url": "https://steamcommunity.com",
        "domain": "steamcommunity.com",
        "icon": "gamepad",
        "tags": ["社区", "创意工坊", "好友", "动态", "Steam社区"]
    },
    {
        "id": "ubisoft",
        "group": "gaming",
        "name": "Ubisoft 育碧官方商城",
        "desc": "刺客信条、彩虹六号等育碧旗下游戏官方商城",
        "url": "https://store.ubi.com",
        "domain": "store.ubi.com",
        "icon": "rocket",
        "tags": ["育碧", "Ubisoft", "Uplay", "商城"]
    },
    {
        "id": "battle_net",
        "group": "gaming",
        "name": "Battle.net 战网国际服",
        "desc": "暴雪娱乐旗下魔兽世界、守望先锋、暗黑破坏神战网",
        "url": "https://shop.battle.net",
        "domain": "battle.net",
        "icon": "rocket",
        "tags": ["战网", "暴雪", "国际服", "魔兽", "Battle.net"]
    },
    {
        "id": "gog",
        "group": "gaming",
        "name": "GOG 游戏商城",
        "desc": "CD Projekt 旗下无 DRM 保护的精选 PC 游戏商城",
        "url": "https://www.gog.com",
        "domain": "gog.com",
        "icon": "shopping_bag",
        "tags": ["GOG", "DRM-Free", "波兰蠢驴", "经典游戏"]
    },
    {
        "id": "xbox",
        "group": "gaming",
        "name": "Xbox 微软游戏官网",
        "desc": "Xbox Game Pass (XGP) 与微软游戏生态主页",
        "url": "https://www.xbox.com",
        "domain": "xbox.com",
        "icon": "gamepad",
        "tags": ["Xbox", "XGP", "微软", "游戏主机"]
    },
    {
        "id": "minecraft",
        "group": "gaming",
        "name": "Minecraft 官方网站",
        "desc": "我的世界官方主页、皮肤下载与 Mojang 账户管理",
        "url": "https://www.minecraft.net",
        "domain": "minecraft.net",
        "icon": "gamepad",
        "tags": ["Minecraft", "我的世界", "Mojang", "沙盒"]
    },

    # 开发者与 AI
    {
        "id": "github",
        "group": "dev",
        "name": "GitHub 代码托管",
        "desc": "全球最大的开源代码托管与开发者协作平台",
        "url": "https://github.com",
        "domain": "github.com",
        "icon": "terminal",
        "tags": ["GitHub", "开源", "Git", "开发者", "代码"]
    },
    {
        "id": "gitlab",
        "group": "dev",
        "name": "GitLab 国际版",
        "desc": "企业级 DevOps 与全生命周期 Git 项目管理平台",
        "url": "https://gitlab.com",
        "domain": "gitlab.com",
        "icon": "terminal",
        "tags": ["GitLab", "DevOps", "CI/CD", "代码托管"]
    },
    {
        "id": "huggingface",
        "group": "dev",
        "name": "HuggingFace AI 开源社区",
        "desc": "全球顶级开源 AI 大模型、数据集与 Spaces 应用社区",
        "url": "https://huggingface.co",
        "domain": "huggingface.co",
        "icon": "cpu",
        "tags": ["AI", "大模型", "Transformers", "机器学习", "HuggingFace"]
    },

    # 2026-10-01 替代路线解锁的站点 (详见 docs/archive/uplift-route-findings.md)
    {
        "id": "imgur_site",
        "group": "acg",
        "name": "Imgur 图床",
        "desc": "Reddit / 社交平台最常用图床 (Fastly, 伪 SNI 掩护直连)",
        "url": "https://imgur.com",
        "domain": "imgur.com",
        "icon": "image",
        "tags": ["图床", "图片", "Imgur", "贴图"]
    },
    {
        "id": "myanimelist_site",
        "group": "acg",
        "name": "MyAnimeList 动漫资料库",
        "desc": "欧美向动漫评分、排行榜与追番记录 (Akamai)",
        "url": "https://myanimelist.net",
        "domain": "myanimelist.net",
        "icon": "book",
        "tags": ["动漫", "评分", "追番", "MAL"]
    },
    {
        "id": "reddit_site",
        "group": "dev",
        "name": "Reddit 社区",
        "desc": "全球最大兴趣社区 (经本机 nginx + Fastly 掩护 SNI 直连, 浏览器直接可开)",
        "url": "https://www.reddit.com",
        "domain": "www.reddit.com",
        "icon": "message",
        "tags": ["社区", "论坛", "Reddit", "讨论"]
    },
    {
        "id": "stackoverflow_site",
        "group": "dev",
        "name": "Stack Overflow",
        "desc": "全球最大编程问答社区 (实测可直连, 无需加速; 图片域走 Imgur 画像)",
        "url": "https://stackoverflow.com",
        "domain": "stackoverflow.com",
        "icon": "terminal",
        "tags": ["编程", "问答", "StackOverflow", "报错"]
    },
    {
        "id": "discord_site",
        "group": "dev",
        "name": "Discord 社区",
        "desc": "开发者与玩家社区 (经本机 ECH 隧道直连 Cloudflare, 浏览器直接可开)",
        "url": "https://discord.com",
        "domain": "discord.com",
        "icon": "message",
        "tags": ["社区", "语音", "Discord", "开发群"]
    }
]




