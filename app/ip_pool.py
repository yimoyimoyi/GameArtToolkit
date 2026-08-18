# -*- coding: utf-8 -*-
"""
PixivToolkit - 加速服务元数据、域名映射与优质 CDN 候选池 (纯直连加速 19 项)
"""

# 服务分组定义
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
        "desc": "Pixiv全生态、Fanbox、BOOTH、Danbooru、Yande.re、ArtStation、VNDB、Kemono"
    },
    "dev": {
        "id": "dev",
        "name": "开发者与 AI",
        "icon": "terminal",
        "desc": "GitHub (Web/Raw/Releases)、HuggingFace、GitLab"
    }
}

# 28 项全量加速服务清单
SERVICES_LIST = [
    # 🎮 游戏生态
    {
        "id": "steam_store",
        "group": "gaming",
        "name": "Steam 商店与结账",
        "domains": ["store.steampowered.com", "checkout.steampowered.com", "help.steampowered.com", "login.steampowered.com"],
        "desc": "解决 Steam 商店首页白屏、愿望单与购物车结账卡死"
    },
    {
        "id": "steam_community",
        "group": "gaming",
        "name": "Steam 社区与个人资料",
        "domains": ["steamcommunity.com", "api.steampowered.com"],
        "desc": "解决 118 错误代码、玩家动态、讨论区与徽章展示"
    },
    {
        "id": "steam_akamai",
        "group": "gaming",
        "name": "Steam 静态图片 CDN",
        "domains": ["community.akamai.steamstatic.com", "avatars.akamai.steamstatic.com", "clan.akamai.steamstatic.com"],
        "desc": "解决好友头像加载失败、创意工坊 Mod 预览图破图"
    },
    {
        "id": "ubisoft",
        "group": "gaming",
        "name": "Ubisoft 育碧商城",
        "domains": ["store.ubi.com", "ubisoftconnect.com", "api-ubiservices.ubi.com"],
        "desc": "解决育碧“无法建立连接”、Club 奖励加载超时"
    },
    {
        "id": "ea_app",
        "group": "gaming",
        "name": "EA App / Origin",
        "domains": ["api.origin.com", "signin.ea.com", "api1.origin.com"],
        "desc": "解决 EA 登录凭据验证超时、商城加载失败"
    },
    # 🎨 二次元与创作者
    {
        "id": "pixiv_web",
        "group": "acg",
        "name": "Pixiv 网页与 APP API",
        "domains": [
            "pixiv.net", "www.pixiv.net", "ssl.pixiv.net", "accounts.pixiv.net", "touch.pixiv.net",
            "oauth.secure.pixiv.net", "dic.pixiv.net", "en-dic.pixiv.net", "sketch.pixiv.net",
            "payment.pixiv.net", "factory.pixiv.net", "comic.pixiv.net", "novel.pixiv.net",
            "imgaz.pixiv.net", "imp.pixiv.net", "sensei.pixiv.net", "fanbox.pixiv.net",
            "source.pixiv.net", "i1.pixiv.net", "i2.pixiv.net", "i3.pixiv.net", "i4.pixiv.net",
            "app-api.pixiv.net", "lc-event.pixiv.net"
        ],
        "desc": "解决 Pixiv 主站访问被阻断与手机端 APP 接口超时"
    },
    {
        "id": "pixiv_img",
        "group": "acg",
        "name": "Pixiv pximg 插画 CDN",
        "domains": [
            "i.pximg.net", "s.pximg.net", "source.pixiv.net", "imgaz.pixiv.net",
            "hls1.pixivsketch.net", "hls2.pixivsketch.net", "hls3.pixivsketch.net", "hls4.pixivsketch.net",
            "hls5.pixivsketch.net", "hls6.pixivsketch.net", "hls7.pixivsketch.net", "hls8.pixivsketch.net",
            "hls9.pixivsketch.net", "hls10.pixivsketch.net", "hls11.pixivsketch.net", "hls12.pixivsketch.net",
            "hlsa1.pixivsketch.net", "hlsa2.pixivsketch.net", "hlsa3.pixivsketch.net", "hlsa4.pixivsketch.net",
            "hlsc1.pixivsketch.net", "hlsc2.pixivsketch.net", "hlse1.pixivsketch.net", "hlse2.pixivsketch.net"
        ],
        "desc": "解决插画大图破图，启用本地磁盘高速缓存秒开"
    },
    {
        "id": "pixiv_fanbox",
        "group": "acg",
        "name": "Pixiv Fanbox 创作者赞助",
        "domains": ["fanbox.cc", "www.fanbox.cc", "api.fanbox.cc", "downloads.fanbox.cc"],
        "desc": "解决创作者赞助平台、图文帖子与赞助列表加载"
    },
    {
        "id": "booth_pm",
        "group": "acg",
        "name": "BOOTH 同人商城",
        "domains": ["booth.pm", "www.booth.pm", "api.booth.pm", "assets.booth.pm"],
        "desc": "Pixiv 旗下同人志、3D 模型与独立周边商城"
    },
    {
        "id": "danbooru",
        "group": "acg",
        "name": "Danbooru 动漫图库",
        "domains": ["danbooru.donmai.us", "cdn.donmai.us"],
        "desc": "解决动漫插画检索图库缩略图与大图加载缓慢"
    },
    {
        "id": "yandere",
        "group": "acg",
        "name": "Yande.re 高清动漫壁纸",
        "domains": ["yande.re", "www.yande.re", "files.yande.re"],
        "desc": "解决超高清壁纸原图下载超时与断流"
    },
    {
        "id": "vndb",
        "group": "acg",
        "name": "VNDB 视觉小说资料库",
        "domains": ["vndb.org", "t.vndb.org"],
        "desc": "解决 Galgame/视觉小说综合数据库及其封面原图"
    },
    # 💻 开发者 & AI
    {
        "id": "github_web",
        "group": "dev",
        "name": "GitHub 主站 Web 与 API",
        "domains": [
            "github.com", "www.github.com", "api.github.com", "gist.github.com", "codeload.github.com",
            "central.github.com", "collector.github.com", "copilot.github.com", "services.github.com",
            "community.github.com", "docs.github.com", "education.github.com", "enterprise.github.com",
            "classroom.github.com", "redirect.github.com"
        ],
        "desc": "解决 GitHub 网页断流、打不开与 Gist 同步"
    },
    {
        "id": "github_raw",
        "group": "dev",
        "name": "GitHub 静态资产与 Raw 直连",
        "domains": [
            "githubassets.com", "github.githubassets.com", "assets-cdn.github.com", "assets.github.dev",
            "raw.githubusercontent.com", "user-images.githubusercontent.com", "favicons.githubusercontent.com",
            "avatars.githubusercontent.com", "avatars0.githubusercontent.com", "avatars1.githubusercontent.com",
            "avatars2.githubusercontent.com", "avatars3.githubusercontent.com", "avatars4.githubusercontent.com",
            "avatars5.githubusercontent.com", "camo.githubusercontent.com", "desktop.githubusercontent.com"
        ],
        "desc": "解决 GitHub CSS/JS 样式错乱、头像破图与 Raw 脚本直连"
    },
    {
        "id": "github_release",
        "group": "dev",
        "name": "GitHub Releases 附件与文件对象",
        "domains": [
            "objects.githubusercontent.com", "github-releases.githubusercontent.com", "media.githubusercontent.com"
        ],
        "desc": "解决 Release 软件安装包下载卡在 0% 或极慢"
    },
    {
        "id": "github_assets",
        "group": "dev",
        "name": "GitHub 前端 JS/CSS 静态 CDN",
        "domains": [
            "githubassets.com", "github.githubassets.com", "assets-cdn.github.com", "assets.github.dev",
            "docs.github.com"
        ],
        "desc": "解决 GitHub 前端 CSS/JS 静态资源与文档页加载"
    },
    {
        "id": "gitlab",
        "group": "dev",
        "name": "GitLab 国际版",
        "domains": ["gitlab.com", "assets.gitlab-static.net"],
        "desc": "解决 GitLab 国际版网页与 Raw 源码直连"
    },
    {
        "id": "huggingface",
        "group": "dev",
        "name": "HuggingFace AI 平台",
        "domains": ["huggingface.co", "www.huggingface.co", "cdn-lfs.huggingface.co", "cdn-thumbnails.huggingface.co"],
        "desc": "解决开源大模型权重文件与 Space 空间直连加速"
    },

]

# 按 ID 建立索引字典
SERVICES_BY_ID = {s["id"]: s for s in SERVICES_LIST}

# 各服务的优质 CDN Anycast IP 候选池 (经 E:\pixiv-nginx / SteamTools 与双通道实测验证)
# 说明: huggingface 使用 CloudFront IPv6 + 伪SNI; steam_community 使用 Akamai IPv4(伪SNI/空SNI)
CANDIDATE_IPS = {
    "pixiv_web": ["210.140.139.151", "210.140.139.153", "210.140.139.154", "210.140.139.157", "210.140.139.161", "210.140.139.162"],
    "pixiv_img": ["210.140.139.131", "210.140.139.132", "210.140.139.133", "210.140.139.134", "210.140.139.135", "210.140.139.136", "210.140.139.137", "210.140.139.149", "210.140.139.150"],
    "pixiv_fanbox": ["104.20.38.219", "172.66.152.186", "104.18.22.203", "104.18.23.203"],
    "booth_pm": ["104.18.37.180", "172.64.150.76", "104.18.22.203"],
    "danbooru": ["104.21.49.191", "172.67.168.170"],
    "yandere": ["104.26.12.197", "172.67.69.123"],
    "vndb": ["217.182.194.133"],

    "steam_store": ["23.1.179.144", "104.71.154.102", "96.7.99.225", "23.41.142.46"],
    "steam_community": ["104.69.160.135", "104.91.87.202", "23.1.179.144", "96.7.99.225"],
    "steam_akamai": ["184.27.185.73", "23.202.34.90", "23.46.197.62"],
    "ubisoft": ["23.41.142.46", "104.91.87.202"],
    "ea_app": ["23.41.142.46", "104.91.87.202"],

    "github_web": ["140.82.121.4", "140.82.114.4", "140.82.113.4", "140.82.112.4", "20.27.177.113", "20.200.245.247"],
    "github_raw": ["185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133"],
    "github_assets": ["185.199.108.154", "185.199.109.154", "185.199.110.154", "185.199.111.154"],
    "github_release": ["185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133"],
    "gitlab": ["172.65.251.78"],
    "huggingface": [
        "2600:9000:2014:a400:17:b174:6d00:93a1",
        "2600:9000:2939:7600:17:b174:6d00:93a1",
        "2600:9000:2804:ce00:1c:55ad:4180:93a1",
        "54.230.71.56", "3.175.207.30", "3.175.207.31"
    ],
}

# 默认全部开启已验证的优质服务 ID 集合
DEFAULT_ENABLED_SERVICES = [s["id"] for s in SERVICES_LIST]
