# -*- coding: utf-8 -*-
"""
PixivToolkit - 统一声明式服务元数据模型与配置体系 (Service Profile)

核心功能:
- 声明式定义各加速服务的元数据、域名、路径规则、加速模式 (L7 Nginx / L4 Relay / Direct)
- 集中管理 SNI 策略 (host / empty / 伪 SNI) 与 CDN 候选 IP 池
- 提供统一的数据源，消除跨模块配置漂移 (Single Source of Truth)
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any


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
    mode: ServiceMode = ServiceMode.L7_NGINX # 默认处理模式
    upstream_name: str = ""                  # Nginx upstream 标识符 (如 upstream_pixiv_web)
    ssl_sni_mode: str = "host"               # SNI 模式: 'host', 'empty', 或自定义伪装域名
    candidate_ips: List[str] = field(default_factory=list) # CDN 优质候选 IP 池
    enable_cache: bool = False               # 是否启用本地磁盘缓存
    path_rules: List[PathRule] = field(default_factory=list) # 特殊路径规则列表
    custom_headers: Dict[str, str] = field(default_factory=dict) # 自定义 HTTP 头部

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
        "desc": "Steam 全生态、Ubisoft、EA App"
    },
    "acg": {
        "id": "acg",
        "name": "二次元与创作者",
        "icon": "palette",
        "desc": "Pixiv全生态、Fanbox、BOOTH、Danbooru、Yande.re、VNDB"
    },
    "dev": {
        "id": "dev",
        "name": "开发者与 AI",
        "icon": "terminal",
        "desc": "GitHub (Web/Raw/Releases)、HuggingFace、GitLab"
    }
}


# ==============================================================================
# 21 项核心加速服务 Profile 注册表 (声明式单源定义)
# ==============================================================================
PROFILES: List[ServiceProfile] = [
    # --------------------------------------------------------------------------
    # 🎮 游戏生态
    # --------------------------------------------------------------------------
    ServiceProfile(
        id="steam_store",
        group="gaming",
        name="Steam 商店与结账",
        desc="解决 Steam 商店首页白屏、愿望单与购物车结账卡死",
        domains=["store.steampowered.com", "checkout.steampowered.com", "help.steampowered.com", "login.steampowered.com"],
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_steam_store",
        ssl_sni_mode="host",
        candidate_ips=["23.1.179.144", "104.71.154.102", "96.7.99.225", "23.41.142.46"]
    ),
    ServiceProfile(
        id="steam_community",
        group="gaming",
        name="Steam 社区与个人资料",
        desc="解决 118 错误代码、玩家动态、讨论区与徽章展示",
        domains=["steamcommunity.com", "api.steampowered.com"],
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_steam_community",
        ssl_sni_mode="statuspage.akamaized.net",  # 伪 SNI 绕过 GFW
        candidate_ips=["104.69.160.135", "104.91.87.202", "23.1.179.144", "96.7.99.225"],
        custom_headers={"Host": "steamcommunity.com"}
    ),
    ServiceProfile(
        id="steam_akamai",
        group="gaming",
        name="Steam 静态图片 CDN",
        desc="解决好友头像加载失败、创意工坊 Mod 预览图破图",
        domains=["community.akamai.steamstatic.com", "avatars.akamai.steamstatic.com", "clan.akamai.steamstatic.com",
                 "community.akamai.steamstatic.com",
                 "steamcommunity-a.akamaihd.net", "steamuserimages-a.akamaihd.net",  # 创意工坊封面/用户上传图
                 "cdn.akamai.steamstatic.com", "community.cloudflare.steamstatic.com"],  # 静态资源 CDN
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_steam_akamai",
        ssl_sni_mode="community.steamstatic.com",
        candidate_ips=["184.27.185.73", "23.202.34.90", "23.46.197.62"]
    ),
    ServiceProfile(
        id="ubisoft",
        group="gaming",
        name="Ubisoft 育碧商城",
        desc="解决育碧“无法建立连接”、Club 奖励加载超时",
        domains=["store.ubi.com", "ubisoftconnect.com", "api-ubiservices.ubi.com"],
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_ubisoft",
        ssl_sni_mode="host",
        candidate_ips=["23.41.142.46", "104.91.87.202"]
    ),
    ServiceProfile(
        id="ea_app",
        group="gaming",
        name="EA App / Origin",
        desc="解决 EA 登录凭据验证超时、商城加载失败",
        domains=["api.origin.com", "signin.ea.com", "api1.origin.com"],
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_ea_app",
        ssl_sni_mode="host",
        candidate_ips=["23.1.179.144", "184.27.185.73", "23.202.34.90", "23.41.142.46"]
    ),

    # --------------------------------------------------------------------------
    # 🎨 二次元与创作者
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
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_pixiv_web",
        ssl_sni_mode="empty",  # 空 SNI 直通
        candidate_ips=["210.140.139.151", "210.140.139.153", "210.140.139.154", "210.140.139.157", "210.140.139.161", "210.140.139.162"]
    ),
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
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_booth_pm",
        ssl_sni_mode="host",
        candidate_ips=["104.18.37.180", "172.64.150.76", "104.18.22.203"]
    ),
    ServiceProfile(
        id="danbooru",
        group="acg",
        name="Danbooru 动漫图库",
        desc="解决动漫插画检索图库缩略图与大图加载缓慢",
        domains=["danbooru.donmai.us", "cdn.donmai.us"],
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_danbooru",
        ssl_sni_mode="host",
        candidate_ips=["104.21.49.191", "172.67.168.170"]
    ),
    ServiceProfile(
        id="yandere",
        group="acg",
        name="Yande.re 高清动漫壁纸",
        desc="解决超高清壁纸原图下载超时与死循环重定向",
        domains=["yande.re", "www.yande.re", "files.yande.re", "assets.yande.re"],
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_yandere",
        ssl_sni_mode="host",
        candidate_ips=["104.26.12.197", "172.67.69.123", "172.64.150.76"]
    ),
    ServiceProfile(
        id="vndb",
        group="acg",
        name="VNDB 视觉小说资料库",
        desc="解决 Galgame/视觉小说综合数据库及其封面原图",
        domains=["vndb.org", "t.vndb.org"],
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_vndb",
        ssl_sni_mode="host",
        candidate_ips=["217.182.194.133",
                       "2001:1af8:5301:117:1c00:d7ff:fe00:ffd"]  # IPv6 实测可用
    ),

    # --------------------------------------------------------------------------
    # 💻 开发者 & AI
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
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_github_web",
        ssl_sni_mode="host",
        candidate_ips=["140.82.121.4", "140.82.114.4", "140.82.113.4", "140.82.112.4", "20.27.177.113", "20.200.245.247"]
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
            "avatars5.githubusercontent.com", "camo.githubusercontent.com", "desktop.githubusercontent.com"
        ],
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_github_raw",
        ssl_sni_mode="host",
        candidate_ips=["185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133",
                       "2606:50c0:8000::154", "2606:50c0:8001::154",  # GitHub 原生 IPv6, 实测直连可用
                       "2606:50c0:8002::154", "2606:50c0:8003::154"]
    ),
    ServiceProfile(
        id="github_release",
        group="dev",
        name="GitHub Releases 附件与文件对象",
        desc="解决 Release 软件安装包下载卡在 0% 或极慢",
        domains=["objects.githubusercontent.com", "github-releases.githubusercontent.com", "media.githubusercontent.com"],
        mode=ServiceMode.L4_RELAY,  # 采用 L4 Relay 旁路高带宽下载
        upstream_name="upstream_github_release",
        ssl_sni_mode="host",
        candidate_ips=["185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133"]
    ),
    ServiceProfile(
        id="github_assets",
        group="dev",
        name="GitHub 前端 JS/CSS 静态 CDN",
        desc="解决 GitHub 前端 CSS/JS 静态资源与文档页加载",
        domains=["githubassets.com", "github.githubassets.com", "assets-cdn.github.com", "assets.github.dev"],
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_github_assets",
        ssl_sni_mode="host",
        candidate_ips=["185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133", "185.199.108.154",
                       "2606:50c0:8000::215", "2606:50c0:8001::215",  # GitHub 原生 IPv6, 实测直连可用
                       "2606:50c0:8002::215", "2606:50c0:8003::215"]
    ),
    ServiceProfile(
        id="gitlab",
        group="dev",
        name="GitLab 国际版",
        desc="解决 GitLab 国际版网页与 Raw 源码直连",
        domains=["gitlab.com", "assets.gitlab-static.net"],
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_gitlab",
        ssl_sni_mode="host",
        candidate_ips=["104.18.37.180", "172.64.150.76", "172.65.251.78",
                       "2606:4700:90:0:f22e:fbec:5bed:a9b9"]  # Cloudflare IPv6, 实测可用
    ),
    ServiceProfile(
        id="huggingface",
        group="dev",
        name="HuggingFace AI 平台",
        desc="解决开源大模型权重文件与 Space 空间直连加速 (L4 极速直通)",
        domains=["huggingface.co", "www.huggingface.co", "cdn-lfs.huggingface.co", "cdn-thumbnails.huggingface.co", "hf.co"],
        mode=ServiceMode.L4_RELAY,  # 采用 L4 Relay 旁路高带宽下载，突破 Nginx 缓冲与体积限制
        upstream_name="upstream_huggingface",
        ssl_sni_mode="d1cnjqbqjby1vq.cloudfront.net",
        candidate_ips=[
            "18.155.68.86", "18.155.68.106", "18.155.68.125",
            "18.64.8.43", "18.64.8.84", "108.138.246.7",
            "54.230.71.56", "3.175.207.30", "3.175.207.31"
        ]
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
