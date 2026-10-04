# GameArt Toolkit (PixivToolkit) 已添加服务全景清单

## 一、总体服务规模统计
- **已配置加速服务总数**: 64 个服务单元
- **纳管加速域名总数**: 625 个
- **加速模式分布**:
  - `L7 Nginx` (Layer-7 智能反向代理 + 缓存 + SNI 改写): 58 个
  - `L4 Relay` (Layer-4 TCP 隧道转发 + SNI 嗅探): 2 个
  - `Direct` (纯 DNS/Hosts 优选直连，无代理开销): 4 个
  - `QUIC Direct` (HTTP/3 引导直连): 0 个

## 1. 游戏平台生态 (Gaming)（共 8 个服务）

### 1. Steam 商店与结账 (`steam_store`)
- **服务描述**: 解决 Steam 商店首页白屏、愿望单与购物车结账卡死
- **技术方案**: 模式: l7_nginx | CDN: akamai | SNI策略: steambroadcast.akamaized.net | 默认启用
- **覆盖域名**: `store.steampowered.com`, `checkout.steampowered.com`, `help.steampowered.com`, `login.steampowered.com`, `*.steampowered.com` (共 5 个域名)

### 2. Steam 社区与个人资料 (`steam_community`)
- **服务描述**: 解决 118 错误代码、玩家动态、讨论区与徽章展示
- **技术方案**: 模式: l7_nginx | CDN: akamai | SNI策略: steambroadcast.akamaized.net | 默认启用
- **覆盖域名**: `steamcommunity.com`, `api.steampowered.com`, `*.steamcommunity.com` (共 3 个域名)

### 3. Steam 静态图片 CDN (`steam_akamai`)
- **服务描述**: 解决好友头像加载失败、创意工坊 Mod 预览图破图
- **技术方案**: 模式: l7_nginx | CDN: akamai | SNI策略: steambroadcast.akamaized.net | 本地静态缓存 | 默认启用
- **覆盖域名**: `community.akamai.steamstatic.com`, `avatars.akamai.steamstatic.com`, `clan.akamai.steamstatic.com`, `steamcommunity-a.akamaihd.net`, `steamuserimages-a.akamaihd.net` 等共 **8** 个域名

### 4. Ubisoft 育碧商城 (`ubisoft`)
- **服务描述**: 解决育碧“无法建立连接”、Club 奖励加载超时
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `store.ubi.com`, `ubisoftconnect.com`, `api-ubiservices.ubi.com` (共 3 个域名)

### 5. Battle.net 战网国际服 (`battle_net`)
- **服务描述**: 战网国际服账号、商店与补丁 CDN 加速 (Akamai + CloudFront)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `battle.net`, `www.battle.net`, `us.battle.net`, `eu.battle.net`, `kr.battle.net` 等共 **14** 个域名

### 6. GOG 游戏商城 (`gog`)
- **服务描述**: CD Projekt 旗下游戏商城与客户端分发 (Fastly Anycast)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `gog.com`, `www.gog.com`, `api.gog.com`, `login.gog.com`, `images.gog.com` (共 5 个域名)

### 7. Xbox 微软游戏生态 (`xbox`)
- **服务描述**: Xbox 商店、支持与游戏生态 (Akamai)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `www.xbox.com`, `store.xbox.com` (共 2 个域名)

### 8. Minecraft 游戏生态 (`minecraft`)
- **服务描述**: Minecraft 官网与 Mojang 账号登录 (Akamai)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `minecraft.net`, `www.minecraft.net`, `account.mojang.com` (共 3 个域名)

## 2. ACG 与二次元创作者生态 (ACG)（共 10 个服务）

### 1. Pixiv 网页与 APP API (`pixiv_web`)
- **服务描述**: 解决 Pixiv 主站访问被阻断与手机端 APP 接口超时
- **技术方案**: 模式: l7_nginx | SNI策略: empty | ECH 分流隧道 | 默认启用
- **覆盖域名**: `pixiv.net`, `www.pixiv.net`, `ssl.pixiv.net`, `accounts.pixiv.net`, `touch.pixiv.net` 等共 **24** 个域名

### 2. Pixiv pximg 插画 CDN (`pixiv_img`)
- **服务描述**: 解决插画大图破图，二次打开从本地磁盘缓存加载
- **技术方案**: 模式: l7_nginx | SNI策略: empty | 本地静态缓存 | 默认启用
- **覆盖域名**: `i.pximg.net`, `s.pximg.net`, `booth.pximg.net`, `*.pximg.net` (共 4 个域名)

### 3. Pixiv Fanbox 创作者赞助 (`pixiv_fanbox`)
- **服务描述**: 解决创作者赞助平台、图文帖子与赞助列表加载
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `fanbox.cc`, `www.fanbox.cc`, `api.fanbox.cc`, `downloads.fanbox.cc`, `*.fanbox.cc` (共 5 个域名)

### 4. BOOTH 同人商城 (`booth_pm`)
- **服务描述**: Pixiv 旗下同人志、3D 模型与独立周边商城
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | ECH 分流隧道 | 默认启用
- **覆盖域名**: `booth.pm`, `www.booth.pm`, `api.booth.pm`, `assets.booth.pm`, `*.booth.pm` (共 5 个域名)

### 5. VNDB 视觉小说资料库 (`vndb`)
- **服务描述**: 解决 Galgame/视觉小说综合数据库及其封面原图
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `vndb.org`, `t.vndb.org` (共 2 个域名)

### 6. Fantia 创作者赞助 (`fantia`)
- **服务描述**: Fanbox 竞品, 日本创作者赞助平台 (GCP)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `fantia.jp`, `www.fantia.jp`, `api.fantia.jp`, `fanclub.fantia.jp` (共 4 个域名)

### 7. Pixivision 官方杂志 (`pixivision`)
- **服务描述**: Pixiv 官方艺术杂志 (Cloudflare, 49ms 实测)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `pixivision.net`, `www.pixivision.net` (共 2 个域名)

### 8. Yande.re 图库 (`yande_re`)
- **服务描述**: Yande.re 动漫图库 (非 Cloudflare, 自有 freenginx 源站, 真 SNI 直连)
- **技术方案**: 模式: direct | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `yande.re`, `www.yande.re`, `assets.yande.re`, `files.yande.re` (共 4 个域名)

### 9. Imgur 图床 (`imgur`)
- **服务描述**: Reddit/社交常用图床 (Fastly, 伪 SNI 掩护可直连, 图片可缓存)
- **技术方案**: 模式: l7_nginx | CDN: fastly | SNI策略: www.fastly.com | 本地静态缓存 | 默认启用
- **覆盖域名**: `imgur.com`, `www.imgur.com`, `i.imgur.com`, `s.imgur.com`, `api.imgur.com` 等共 **6** 个域名

### 10. MyAnimeList 动漫资料库 (`myanimelist`)
- **服务描述**: 欧美向动漫评分与资料库 (Akamai, 伪 SNI 掩护可直连)
- **技术方案**: 模式: l7_nginx | CDN: akamai | SNI策略: steambroadcast.akamaized.net | 默认启用
- **覆盖域名**: `myanimelist.net`, `www.myanimelist.net`, `cdn.myanimelist.net`, `api.myanimelist.net`, `static.myanimelist.net` (共 5 个域名)

## 3. 开发者服务与技术社区 (Dev & Tech)（共 30 个服务）

### 1. GitHub 主站 Web 与 API (`github_web`)
- **服务描述**: 解决 GitHub 网页断流、打不开与 Gist 同步
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `github.com`, `www.github.com`, `api.github.com`, `gist.github.com`, `codeload.github.com` 等共 **15** 个域名

### 2. GitHub 静态资产与 Raw 直连 (`github_raw`)
- **服务描述**: 解决 GitHub CSS/JS 样式错乱、头像破图与 Raw 脚本直连
- **技术方案**: 模式: l7_nginx | CDN: fastly | SNI策略: objects.githubusercontent.com | 默认启用
- **覆盖域名**: `raw.githubusercontent.com`, `user-images.githubusercontent.com`, `favicons.githubusercontent.com`, `avatars.githubusercontent.com`, `avatars0.githubusercontent.com` 等共 **15** 个域名

### 3. GitHub Releases 附件与文件对象 (`github_release`)
- **服务描述**: 解决 Release 软件安装包下载卡在 0% 或极慢
- **技术方案**: 模式: l4_relay | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `objects.githubusercontent.com`, `github-releases.githubusercontent.com`, `media.githubusercontent.com` (共 3 个域名)

### 4. GitHub 前端 JS/CSS 静态 CDN (`github_assets`)
- **服务描述**: 解决 GitHub 前端 CSS/JS 静态资源、文档页与 Pages 站点加载
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `githubassets.com`, `github.githubassets.com`, `assets-cdn.github.com`, `assets.github.dev`, `github.io` 等共 **6** 个域名

### 5. GitHub 大文件对象存储 S3 (`github_s3`)
- **服务描述**: 解决 Release 安装包与 Issue/Discussion 上传图片加载 (AWS S3)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `github-production-release-asset-2e65be.s3.amazonaws.com`, `github-production-repository-file-5c1aeb.s3.amazonaws.com`, `github-production-user-asset-6210df.s3.amazonaws.com`, `github-cloud.s3.amazonaws.com`, `github-com.s3.amazonaws.com` (共 5 个域名)

### 6. GitLab 国际版 (`gitlab`)
- **服务描述**: 解决 GitLab 国际版网页与 Raw 源码直连
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `gitlab.com`, `assets.gitlab-static.net`, `*.gitlab.com`, `*.gitlab-static.net` (共 4 个域名)

### 7. HuggingFace AI 平台 (`huggingface`)
- **服务描述**: 模型权重 LFS 直连 + 全套图片 CDN 加速 (缩略图/头像/资产图)
- **技术方案**: 模式: l4_relay | CDN: cloudfront | SNI策略: d1cnjqbqjby1vq.cloudfront.net | 默认启用
- **覆盖域名**: `huggingface.co`, `www.huggingface.co`, `hf.co`, `cdn-lfs.huggingface.co`, `cdn-lfs-us-1.huggingface.co` 等共 **9** 个域名

### 8. npm 包管理生态 (`npm`)
- **服务描述**: npm 包索引与 registry 镜像加速 (Cloudflare)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `npmjs.com`, `registry.npmjs.com`, `registry.npmjs.org` (共 3 个域名)

### 9. PyPI Python 包索引 (`pypi`)
- **服务描述**: pip 包索引与文件分发加速 (Fastly)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `pypi.org`, `www.pypi.org`, `files.pythonhosted.org`, `warehouse.python.org` (共 4 个域名)

### 10. crates.io Rust 包索引 (`crates_io`)
- **服务描述**: cargo 包索引与 crates.io 下载加速 (Fastly)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `crates.io`, `www.crates.io`, `index.crates.io` (共 3 个域名)

### 11. jsDelivr 前端 CDN (`jsdelivr`)
- **服务描述**: npm/GitHub 等开源前端资源全球分发 CDN (Cloudflare)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 本地静态缓存 | 默认启用
- **覆盖域名**: `cdn.jsdelivr.net`, `data.jsdelivr.net` (共 2 个域名)

### 12. NuGet 包索引 API (`nuget_api`)
- **服务描述**: dotnet/nuget 客户端索引与元数据 (Azure App Service 香港)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `api.nuget.org` (共 1 个域名)

### 13. NuGet 官网 (`nuget_www`)
- **服务描述**: nuget.org 网页与包详情页 (Azure Front Door + IIS)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `www.nuget.org` (共 1 个域名)

### 14. NuGet 包下载 CDN (`nuget_cdn`)
- **服务描述**: .nupkg 包体与客户端分发 (Akamai)，dotnet restore 下包必经
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `globalcdn.nuget.org`, `dist.nuget.org` (共 2 个域名)

### 15. Maven Central 包索引 (`maven_central`)
- **服务描述**: Java 包索引与构建依赖分发 (Apache/Cloudflare)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `repo.maven.apache.org`, `repo1.maven.org`, `search.maven.org` (共 3 个域名)

### 16. Google Fonts 字体 CDN (`google_fonts`)
- **服务描述**: Google 字体与 CSS 分发 (GFW 白名单直连, 官方证书可达节点)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 本地静态缓存 | 默认启用
- **覆盖域名**: `fonts.googleapis.com`, `fonts.gstatic.com` (共 2 个域名)

### 17. Google 搜索与账号 (`google_web`)
- **服务描述**: Google 搜索/账号/邮件/云盘/文档等网页态服务 (经本机 nginx + g.cn 掩护 SNI)
- **技术方案**: 模式: l7_nginx | CDN: google | SNI策略: g.cn | 默认启用
- **覆盖域名**: `google.com`, `www.google.com`, `accounts.google.com`, `mail.google.com`, `gmail.com` 等共 **314** 个域名

### 18. Google 静态资源 CDN (`google_static`)
- **服务描述**: gstatic / googleusercontent / ggpht 静态资源 (经本机 nginx + g.cn 掩护 SNI)
- **技术方案**: 模式: l7_nginx | CDN: google | SNI策略: g.cn | 本地静态缓存 | 默认启用
- **覆盖域名**: `gstatic.com`, `www.gstatic.com`, `ssl.gstatic.com`, `maps.gstatic.com`, `t0.gstatic.com` 等共 **20** 个域名

### 19. Gemini (Google AI) (`gemini`)
- **服务描述**: Gemini 网页版 / AI Studio / 生成式语言 API (经本机 nginx + g.cn 掩护 SNI)
- **技术方案**: 模式: l7_nginx | CDN: google | SNI策略: g.cn | 默认启用
- **覆盖域名**: `gemini.google.com`, `bard.google.com`, `aistudio.google.com`, `notebooklm.google.com`, `gemini.gstatic.com` 等共 **24** 个域名

### 20. YouTube 网页与图片 (`youtube_web`)
- **服务描述**: YouTube 网页态、缩略图与播放器资源 (经本机 nginx + g.cn 掩护 SNI)
- **技术方案**: 模式: l7_nginx | CDN: google | SNI策略: g.cn | 默认启用
- **覆盖域名**: `youtube.com`, `www.youtube.com`, `m.youtube.com`, `youtu.be`, `youtube-nocookie.com` 等共 **14** 个域名

### 21. YouTube 视频流 (HTTP/3 上游腿) (`googlevideo`)
- **服务描述**: 经本机 HTTP/3 上游腿直连真实视频节点 (通道已实测, 浏览器实测可播放; 默认不启用)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | HTTP/3 上游 | 【实验性·默认关闭】
- **覆盖域名**: `*.googlevideo.com`, `*.c.googlevideo.com`, `*.a1.googlevideo.com`, `*.c.youtube.com` (共 4 个域名)

### 22. Cloudflare Turnstile 验证码 (`turnstile`)
- **服务描述**: Turnstile 人机验证 JS/挑战端 (解决验证码转圈加载失败)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 本地静态缓存 | 默认启用
- **覆盖域名**: `challenges.cloudflare.com` (共 1 个域名)

### 23. hCaptcha 人机验证 (`hcaptcha`)
- **服务描述**: hCaptcha 验证码全套 (JS/API/资源域, 解决登录与提交卡验证)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 本地静态缓存 | 默认启用
- **覆盖域名**: `hcaptcha.com`, `www.hcaptcha.com`, `api.hcaptcha.com`, `assets.hcaptcha.com`, `newassets.hcaptcha.com` (共 5 个域名)

### 24. unpkg npm 包 CDN (`unpkg`)
- **服务描述**: npm 包直引最常用 CDN (Cloudflare, 前端依赖加载提速)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 本地静态缓存 | 默认启用
- **覆盖域名**: `unpkg.com` (共 1 个域名)

### 25. cdnjs 公共库 CDN (`cdnjs`)
- **服务描述**: Cloudflare cdnjs 老牌公共前端库 CDN (与 jsDelivr 互补)
- **技术方案**: 模式: l7_nginx | SNI: host (直通/透传) | 本地静态缓存 | 默认启用
- **覆盖域名**: `cdnjs.cloudflare.com` (共 1 个域名)

### 26. Reddit 论坛 (`reddit`)
- **服务描述**: 全球最大兴趣社区 (经本机 nginx + Fastly 掩护 SNI 直连, 含图片/视频/样式域)
- **技术方案**: 模式: l7_nginx | CDN: fastly | SNI策略: www.fastly.com | 默认启用
- **覆盖域名**: `reddit.com`, `www.reddit.com`, `old.reddit.com`, `v.redd.it`, `packaged-media.redd.it` (共 5 个域名)

### 27. Reddit 媒体与样式 (`reddit_media`)
- **服务描述**: Reddit 图片/缩略图/样式域 (Fastly 掩护 SNI + 本地磁盘缓存, 边缘抖动时继续吐已缓存内容)
- **技术方案**: 模式: l7_nginx | CDN: fastly | SNI策略: www.fastly.com | 本地静态缓存 | 默认启用
- **覆盖域名**: `i.redd.it`, `preview.redd.it`, `external-preview.redd.it`, `styles.redditmedia.com`, `b.thumbs.redditmedia.com` 等共 **6** 个域名

### 28. Reddit 静态资源 (`reddit_static`)
- **服务描述**: Reddit 前端 JS/CSS 资源域 (实测自身 SNI 可用, 仅需修正被污染的解析)
- **技术方案**: 模式: direct | CDN: fastly | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `redditstatic.com`, `www.redditstatic.com` (共 2 个域名)

### 29. Discord 社区 (`discord`)
- **服务描述**: 开发者与玩家社区 (经本机 ECH 隧道直连 Cloudflare, 浏览器无需支持 HTTP/3)
- **技术方案**: 模式: l7_nginx | CDN: cloudflare | SNI策略: empty | ECH 分流隧道 | 默认启用
- **覆盖域名**: `discord.com`, `www.discord.com`, `discordapp.com`, `discordapp.net`, `cdn.discordapp.com` 等共 **10** 个域名

### 30. Discord 网关 (WebSocket) (`discord_gateway`)
- **服务描述**: Discord 客户端长连接网关 (经本机 ECH 隧道 + WebSocket 升级头)
- **技术方案**: 模式: l7_nginx | CDN: cloudflare | SNI策略: empty | ECH 分流隧道 | WebSocket 支持 | 默认启用
- **覆盖域名**: `gateway.discord.gg` (共 1 个域名)

## 4. 艺术社区与扩展站点 (Adult & Art)（共 16 个服务）

### 1. Pawchive 创作档案 (`pawchive`)
- **服务描述**: Pawchive 创作者投稿档案站 (Kemono 同族; Cloudflare 托管, 经本地 ECH 隧道)
- **技术方案**: 模式: l7_nginx | CDN: cloudflare | SNI策略: empty | ECH 分流隧道 | 默认启用
- **覆盖域名**: `pawchive.pw`, `www.pawchive.pw` (共 2 个域名)

### 2. Pawchive 缩略图 CDN (`pawchive_img`)
- **服务描述**: Pawchive 预览/缩略图主机 (同 zone Cloudflare, 经本地 ECH 隧道, 静态图可缓存)
- **技术方案**: 模式: l7_nginx | CDN: cloudflare | SNI策略: empty | ECH 分流隧道 | 本地静态缓存 | 默认启用
- **覆盖域名**: `img.pawchive.pw` (共 1 个域名)

### 3. Pawchive 原图与附件 (`pawchive_dl`)
- **服务描述**: Pawchive 原图/压缩包/视频下载主机 (同 zone Cloudflare, 经本地 ECH 隧道)
- **技术方案**: 模式: l7_nginx | CDN: cloudflare | SNI策略: empty | ECH 分流隧道 | 默认启用
- **覆盖域名**: `n2.pawchive.pw` (共 1 个域名)

### 4. E-Hentai 图库 (`ehentai`)
- **服务描述**: E-Hentai/ExHentai 图库与上传站 (Cloudflare 托管, 经本地 ECH 隧道绕开明文 SNI 阻断)
- **技术方案**: 模式: l7_nginx | CDN: cloudflare | SNI策略: empty | ECH 分流隧道 | 默认启用
- **覆盖域名**: `e-hentai.org`, `www.e-hentai.org`, `repo.e-hentai.org`, `upld.e-hentai.org`, `exhentai.org` 等共 **7** 个域名

### 5. nhentai 本子库 (`nhentai`)
- **服务描述**: nhentai 主站 (Cloudflare 托管, 经本地 ECH 隧道)
- **技术方案**: 模式: l7_nginx | CDN: cloudflare | SNI策略: empty | ECH 分流隧道 | 默认启用
- **覆盖域名**: `nhentai.net`, `www.nhentai.net` (共 2 个域名)

### 6. FurAffinity 兽圈创作社区 (`furaffinity`)
- **服务描述**: FurAffinity 主站与作品图床 (Cloudflare 托管, 经本地 ECH 隧道)
- **技术方案**: 模式: l7_nginx | CDN: cloudflare | SNI策略: empty | ECH 分流隧道 | 本地静态缓存 | 默认启用
- **覆盖域名**: `furaffinity.net`, `www.furaffinity.net`, `d.furaffinity.net` (共 3 个域名)

### 7. DLsite 同人商店 (`dlsite`)
- **服务描述**: DLsite 商店与图片 CDN (Cloudflare 托管, 经本地 ECH 隧道)
- **技术方案**: 模式: l7_nginx | CDN: cloudflare | SNI策略: empty | ECH 分流隧道 | 默认启用
- **覆盖域名**: `dlsite.com`, `www.dlsite.com`, `img.dlsite.jp` (共 3 个域名)

### 8. Cara 艺术家社区 (`cara`)
- **服务描述**: Cara 艺术家社区 (Cloudflare 托管, 经本地 ECH 隧道)
- **技术方案**: 模式: l7_nginx | CDN: cloudflare | SNI策略: empty | ECH 分流隧道 | 默认启用
- **覆盖域名**: `cara.app`, `www.cara.app` (共 2 个域名)

### 9. ArtStation 素材 CDN (`artstation_cdn`)
- **服务描述**: ArtStation 作品/素材 CDN (Cloudflare 托管, 经本地 ECH 隧道)
- **技术方案**: 模式: l7_nginx | CDN: cloudflare | SNI策略: empty | ECH 分流隧道 | 本地静态缓存 | 默认启用
- **覆盖域名**: `cdna.artstation.com` (共 1 个域名)

### 10. Hitomi.la 图库 (`hitomi`)
- **服务描述**: Hitomi.la 图库 (DNS 被污染, 钉静态 IP 直连)
- **技术方案**: 模式: direct | SNI: host (直通/透传) | 默认启用
- **覆盖域名**: `hitomi.la` (共 1 个域名)

### 11. Pinterest 图床 (`pinimg`)
- **服务描述**: Pinterest 图片 CDN (Fastly, 钉静态 IP 直连)
- **技术方案**: 模式: direct | SNI: host (直通/透传) | 本地静态缓存 | 默认启用
- **覆盖域名**: `i.pinimg.com` (共 1 个域名)

### 12. E-Hentai 图床 (`ehentai_img`)
- **服务描述**: E-Hentai 缩略图与原图服务器 (自有服务器非 CF, 空 SNI 可直连, 图片可缓存)
- **技术方案**: 模式: l7_nginx | SNI策略: empty | 本地静态缓存 | 【实验性·默认关闭】
- **覆盖域名**: `ehgt.org`, `www.ehgt.org` (共 2 个域名)

### 13. nhentai 图床 (`nhentai_img`)
- **服务描述**: nhentai 缩略图与原图服务器 (自有服务器非 CF, 空 SNI 可直连, 图片可缓存)
- **技术方案**: 模式: l7_nginx | SNI策略: empty | 本地静态缓存 | 【实验性·默认关闭】
- **覆盖域名**: `i.nhentai.net`, `t.nhentai.net`, `t3.nhentai.net` (共 3 个域名)

### 14. DLsite 播放器 (`dlsite_play`)
- **服务描述**: DLsite 作品播放器 (AWS 源站忽略 SNI, 用无害 SNI 掩护绕过域名级阻断)
- **技术方案**: 模式: l7_nginx | CDN: fastly | SNI策略: www.fastly.com | 【实验性·默认关闭】
- **覆盖域名**: `play.dlsite.com` (共 1 个域名)

### 15. Sankaku Channel 图库 (`sankaku`)
- **服务描述**: Sankaku 图库与新闻站 (自有 CDN 忽略 SNI, 掩护 SNI 可直连, 图片可缓存)
- **技术方案**: 模式: l7_nginx | CDN: fastly | SNI策略: www.fastly.com | 本地静态缓存 | 【实验性·默认关闭】
- **覆盖域名**: `chan.sankakucomplex.com`, `www.sankakucomplex.com`, `sankakucomplex.com` (共 3 个域名)

### 16. H图书馆 (hlib.cc) (`hlib`)
- **服务描述**: 中文 H 小说站 (Cloudflare 托管, 经本地 ECH 隧道; 首访需过一次人机校验)
- **技术方案**: 模式: l7_nginx | CDN: cloudflare | SNI策略: empty | ECH 分流隧道 | 【实验性·默认关闭】
- **覆盖域名**: `hlib.cc`, `www.hlib.cc` (共 2 个域名)
