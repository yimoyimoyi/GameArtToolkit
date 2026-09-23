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


class SniMode(str, Enum):
    """TLS SNI 模式"""
    HOST = "host"             # 使用客户端请求的原始 Host 域名作为 SNI
    EMPTY = "empty"           # 空 SNI (不发送 server_name 扩展，绕过 SNI 审查)
    CUSTOM = "custom"         # 使用指定伪装域名 (如 CloudFront 分发域名 / Akamai 状态页)


@dataclass
class PathRule:
    """特定路径的路由与转发规则"""
    path: str
    proxy_pass: Optional[str] = None
    buffering: bool = True
    websocket: bool = False
    custom_headers: Dict[str, str] = field(default_factory=dict)


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
    proxy_connect_by_domain: bool = False     # 代理通道探测时 CONNECT 域名而非候选 IP (适配 Clash 按 IP 段 DIRECT 规则直连、CDN geo 限制中国 IP 的场景)
    ech_enabled: bool = False                 # 经本地 ECH 隧道直连 (要求目标托管在 Cloudflare; 见 docs/ech-tunnel-proposal.md)

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
    }
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
        domains=["store.steampowered.com", "checkout.steampowered.com", "help.steampowered.com", "login.steampowered.com"],
        icon="shopping_bag",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_steam_store",
        ssl_sni_mode="steambroadcast.akamaized.net",  # 统一伪 SNI
        candidate_ips=["23.1.179.144", "23.46.229.9", "104.91.87.202", "96.7.99.225"]
    ),
    ServiceProfile(
        id="steam_community",
        group="gaming",
        name="Steam 社区与个人资料",
        desc="解决 118 错误代码、玩家动态、讨论区与徽章展示",
        domains=["steamcommunity.com", "api.steampowered.com"],
        icon="gamepad",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_steam_community",
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
                 "cdn.akamai.steamstatic.com", "community.cloudflare.steamstatic.com"],  # 静态资源 CDN
        icon="zap",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_steam_akamai",
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
                 "level3.blizzard.com", "blznav.akamaized.net"],
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
        desc="Xbox 商店、支持与游戏生态 (Azure + Akamai)",
        domains=["xbox.com", "www.xbox.com", "store.xbox.com", "support.xbox.com"],
        icon="gamepad",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_xbox",
        ssl_sni_mode="host",
        candidate_ips=["20.76.201.171", "20.70.246.20", "20.231.239.246", "20.112.250.133", "104.83.196.58", "150.171.110.133"]
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
        candidate_ips=["150.171.110.137", "184.28.7.173", "184.28.7.166", "184.28.7.164"]
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
            "app-api.pixiv.net", "lc-event.pixiv.net"
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
    # embed.pixiv.net 已实测并放弃 (2026-08): Cloudflare geo 限制中国 IP (直连 403/RST),
    # 仅代理可用 -> 按"仅代理可用的服务不加入"原则移除 (影响面小, 代理本身即可解决)。
    # proxy_connect_by_domain 字段保留: 通用能力, 未来同类场景可直接启用
    ServiceProfile(
        id="pixiv_img",
        group="acg",
        name="Pixiv pximg 插画 CDN",
        desc="解决插画大图破图，二次打开从本地磁盘缓存加载",
        domains=[
            "i.pximg.net", "s.pximg.net", "source.pixiv.net", "imgaz.pixiv.net",
            "hls1.pixivsketch.net", "hls2.pixivsketch.net", "hls3.pixivsketch.net", "hls4.pixivsketch.net",
            "hls5.pixivsketch.net", "hls6.pixivsketch.net", "hls7.pixivsketch.net", "hls8.pixivsketch.net",
            "hls9.pixivsketch.net", "hls10.pixivsketch.net", "hls11.pixivsketch.net", "hls12.pixivsketch.net",
            "hlsa1.pixivsketch.net", "hlsa2.pixivsketch.net", "hlsa3.pixivsketch.net", "hlsa4.pixivsketch.net",
            "hlsc1.pixivsketch.net", "hlsc2.pixivsketch.net", "hlse1.pixivsketch.net", "hlse2.pixivsketch.net"
        ],
        icon="image",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_pixiv_img",
        ssl_sni_mode="empty",
        enable_cache=True,
        candidate_ips=["210.140.139.131", "210.140.139.132", "210.140.139.133", "210.140.139.134", "210.140.139.135", "210.140.139.136", "210.140.139.137", "210.140.139.149", "210.140.139.150"]
    ),
    ServiceProfile(
        id="pixiv_fanbox",
        group="acg",
        name="Pixiv Fanbox 创作者赞助",
        desc="解决创作者赞助平台、图文帖子与赞助列表加载",
        domains=["fanbox.cc", "www.fanbox.cc", "api.fanbox.cc", "downloads.fanbox.cc"],
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
        domains=["booth.pm", "www.booth.pm", "api.booth.pm", "assets.booth.pm"],
        icon="shopping_bag",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_booth_pm",
        # ECH 隧道直连: 实测明文 SNI 直连稳定返回 403 (Cloudflare 防护对无 cookie 请求
        # 的确定性响应), 而经 ECH 隧道访问返回正常 302 → https://booth.pm/ja。
        # 两者差别在于 CF 观察到的连接特征不同, ECH 路径可正常加载。
        ech_enabled=True,
        ssl_sni_mode="host",
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
        candidate_ips=["217.182.194.133",
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
        # 404 放行: raw 容灾段 (.133) 对 api.github.com 根路径返回 404 (Fastly 识别虚拟主机但无根文档)
        probe_domains=("github.com", "api.github.com"),
        probe_ok_statuses=(404,),
        # 稳定性策略: 跨网络(Azure/Fastly/Pages) 跨段(逐段封锁互为兜底) 跨协议(IPv4/IPv6) 三层容灾
        # 实测: 140.82.113.22 / 140.82.113.21 / 140.82.114.22 证书有效且 git 端点延迟最低 (~1.4s) 置顶
        stable_ips=["140.82.113.22", "140.82.113.21", "140.82.114.22", "20.27.177.113"],  # 已知稳定段, 排序稳优先
        candidate_ips=["140.82.113.22", "140.82.113.21", "140.82.114.22",  # 实测证书有效+最低延迟 (git clone 最快)
                       "20.27.177.113", "20.200.245.247",  # Azure 亚太 (次选)
                       "20.205.243.166", "20.205.243.165", "20.205.243.168",  # Fastly 新加坡段 (github520 现行推荐)
                       "140.82.112.25", "140.82.114.21", "140.82.112.17", "140.82.114.26", "140.82.113.22",  # Fastly Anycast 全球段 (github520 实测)
                       "140.82.121.4", "140.82.114.4", "140.82.113.4", "140.82.112.4",  # GitHub 官方 IP 列表段
                       "185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133",  # 跨段容灾: raw 段实测可服务 github.com (200), GFW 逐段封锁时互为兜底
                       "2606:50c0:8000::154", "2606:50c0:8001::154",  # GitHub 原生 IPv6, 实测直连可用
                       "2606:50c0:8002::154", "2606:50c0:8003::154"]
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
        ssl_sni_mode="host",
        stable_ips=["185.199.109.133", "185.199.108.133"],  # 实测低延迟稳定段 (github520 现行推荐 109 段)
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
                 "github.io"],  # GitHub Pages 站点 (user.github.io, DNS 模式按后缀通配路由)
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
        domains=["gitlab.com", "assets.gitlab-static.net"],
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
        ssl_sni_mode="d1cnjqbqjby1vq.cloudfront.net",
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
    ServiceProfile(
        id="nuget",
        group="dev",
        name="NuGet 包索引",
        desc=".NET 包索引与文件分发加速 (Azure, 110ms 实测)",
        domains=["api.nuget.org", "www.nuget.org", "globalcdn.nuget.org"],
        icon="terminal",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_nuget",
        ssl_sni_mode="host",
        candidate_ips=["23.101.10.141", "23.101.10.113", "23.101.8.183",
                       "172.183.192.203"]  # www.nuget.org 当前实测解析 (Azure 新段, 200)
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
    )
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
    }
]

