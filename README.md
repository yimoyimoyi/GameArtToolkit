# GameArt Toolkit

<p align="center">
  <b>面向 Windows 平台的现代二次元与游戏生态网络加速与 Steam 账号管理工具箱</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/GUI-PySide6%20MD3-emerald.svg" alt="PySide6">
  <img src="https://img.shields.io/badge/Proxy-Nginx%20%2B%20L4%20Relay-green.svg" alt="Proxy Engine">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey.svg" alt="License">
</p>

---

## 📖 项目简介

**GameArt Toolkit** 是一款专为 Windows 10/11 深度定制的轻量、高效网络加速与游戏辅助工具。基于 **PySide6 Material Design 3** 现代化自绘架构与本地便携式 **Nginx / L4 Relay** 双引擎，提供全链路网络反向代理加速、全网 Anycast CDN 节点测速优选、以及 Steam 多账号免密快速切换管理。

### ✨ 核心特性

- **🚀 本地多协议反代加速数据平面 (覆盖 3 大生态热门核心服务)**
  - **二次元与创作者生态**：Pixiv 网页/API/APP 接口、pximg 插画 CDN、Pixivision 官方杂志、Fanbox 创作者赞助、BOOTH 同人商城、Danbooru 动漫图库、VNDB 视觉小说资料库、Fantia 创作者俱乐部。
  - **游戏生态**：Steam 商店/结账、Steam 社区 118 修复、Steam Akamai 图片 CDN、Ubisoft 育碧商城、EA App / Origin、Battle.net 战网国际服、GOG 游戏商城、Xbox 微软游戏生态、Minecraft 游戏生态。
  - **开发者与 AI 生态**：GitHub 主站 Web/API、GitHub 静态资产与 Raw 直连、GitHub Releases 附件极速下载 (L4 Relay 旁路直通)、GitHub 前端 JS/CSS CDN、GitHub S3 大文件对象存储 (Release 安装包与 Issue 上传图片)、GitLab 国际版、HuggingFace 模型权重 LFS 直连与全套图片 CDN (缩略图/头像/资产图)、**Google 搜索/账号/邮件/云盘/文档全家族**、**Google 静态资源 CDN (gstatic / googleusercontent / ggpht)**、**YouTube 网页与缩略图**、Cloudflare Turnstile 与 hCaptcha 人机验证码加速、公共前端 CDN (jsDelivr / unpkg / cdnjs) 矩阵加速。
  - **Google / YouTube 走"同租户掩护 SNI"（`g.cn`）**：Google 自家边缘按 HTTP Host 路由，
    因此用未被封锁的自家短域名 `g.cn` 作掩护 SNI、Host 保持真域名即可直连。2026-10-01 实测
    8/8 中转 IP × 真实 Host 全部 200/302，上游证书 SAN 含 `*.google.cn`（Google Trust Services
    WR2/WE2）。**68/69 个候选域名实测 `/generate_204` 返回 204**（真 Google 前台的判据，
    "打错服务器"的 Bandaid 兜底服务不回 204）。首选仍保持掩护域是有意为之：真实域名作 SNI
    会把域名明文写进 ClientHello（客户端→中转节点这一段）。
    刻意拆成 `google_web` / `google_static` / `youtube_web` 三条画像（后端行为不同，合池必然错配）；
    `google_fonts` 保持独立（它走国内电信缓存段 `120.253.x`），域名互不重叠。
    ⚠️ **`googlevideo.com` 视频流域不登记**（2026-10-01 定案）：该通道下上游返回
    `Bandaid Misdirected Traffic Server`（Google 明确回"打错服务器"）；唯一可用的
    `HTTP/3 + IPv6 真实节点`通道虽有完整实现（`app/h3_upstream.py` 上游腿 +
    `app/gvs_h3_probe` 闸门 + 应用启动/看门狗/退出接线），但**已定因不适用**：
    403 的响应头自报 `server: gvs 1.0`（确实打到了真 Google Video Server）
    + `content-type: application/vnd.yt-ump` —— 该 URL 是 **SABR/UMP 分片流**，
    用普通 HTTP Range GET 会被拒。即 **`L7 + h3 上游腿` 无法充当 SABR 客户端**，
    属**形态选错**而非"暂时调不通"（出口 IP / 节点 / `n=` / PO Token / 可播放性均已逐条排除）。
    故按「不通的服务一律不加入，不做假可用」原则（同 `twitch_web` / `stackoverflow`）
    **不登记**；HTTP/3 上游腿作为**已验证的潜伏能力**保留（同 QUIC 通道的处置）。
    正确形态是让**浏览器自己**说 h3/SABR —— 即项目已有的 `app/quic_launcher.py`
    （`--origin-to-force-quic-on`），它恰好绕开了"Chrome 不会因明文 DNS 自行采用 h3"这一前提。
    完整证据链与逐条排除表见 [docs/googlevideo-quic-channel.md](docs/googlevideo-quic-channel.md)。
  - **掩护 SNI 候选池 + 自动回归 + 降级链**（`app/cover_sni.py`）：掩护 SNI 不是常量，而是
    **运行时状态** —— 启动加速前实测「掩护域是否仍然有效」，失效时按候选池自动降级：
    `g.cn → www.g.cn → google.cn → www.google.cn → gstatic.com → www.gstatic.com → 真实域名 → 空 SNI`，
    全失败则**显式判为不可用并在界面红色告警**（宁可报错也不静默白屏）。
    验证四关（§6.2）：TCP → TLS → **证书必须属于该厂商自有证书族** → 用真实 Host 请求
    `/generate_204`。主控制台有专门的状态卡显示当前层级与已淘汰候选，设置页有两个开关
    （「自动回归与降级」「允许降级到空 SNI」）。
    两个实测要点：① 中转节点**按 SNI 选证书**（发 `g.cn` 拿到 `*.google.cn` 那张，发空 SNI
    拿到占位证书 `invalid2.invalid`），所以"证书族"这道门槛是真门槛；
    ② **`proxy_ssl_verify off` 是伪 SNI 的代价而非 Google 的固有属性** —— 用真实域名当 SNI 时
    证书名 8/8 覆盖、链 8/8 受信，这条可完整校验的退路正是"Google 关闭域名前置"时的兜底。
    详见 [docs/cover-sni-degradation.md](docs/cover-sni-degradation.md)。
  - **本地磁盘二级缓存**：二次打开插画与静态资源实现本地 0ms 闪电响应。
    本轮修掉两个既有缺陷（均以真实 nginx 最小复现证实）：① 缓存键原为
    `$proxy_host`（= proxy_pass 里的 upstream 名，不是真实 Host），导致**同一 upstream 下
    不同域名互相串内容**（实测 `b.test` 直接命中 `a.test` 的缓存并拿到它的响应体）；
    改为 `$host` 后各域隔离。② `proxy_buffering off` 与 `proxy_cache` **互斥**，
    dev 组画像同时写这两条会让缓存**完全空转**（实测第二次请求仍是 MISS）——
    影响面覆盖 `google_fonts` / `jsdelivr` / `npm` / `pypi` / `crates` 等，
    现已改为「开了缓存的画像保留缓冲」。`google_static` 因此得以按方案 P3 开启缓存，
    端到端实测 `MISS → HIT`。
  - **L4 Relay 旁路隧道**：针对直连受阻的海外服务，自动经由本地上游代理端口透明转发，无需修改系统全局代理。
  - **域名劫持双后端 (Hosts / NRPT)**：可在「系统 Hosts 注入」与「Windows NRPT 名称解析策略表」之间切换。NRPT 后端不改动 Hosts 文件，且后缀匹配天然覆盖整棵子域树，代价是需管理员权限并独占 53/UDP；前置条件不满足时按配置自动回退 Hosts，并把回退原因（含 53 端口占用进程名）显示在设置页。
  - **替代路线解锁（按站点选最轻通道）**：对"TCP 侧 TLS 标准 SNI 被 RST / 被污染"的站点，逐站点选择
    真正需要的那一层，**全部无需第三方代理**：
    - **厂商化伪 SNI 掩护**（Fastly / Akamai 实测接受跨租户掩护 SNI）→ 已解 `imgur` / `myanimelist` / **`reddit`**
      （实测 `cover=www.fastly.com` @199.232.16x.140 → 200 + `CN=*.reddit.com`）；
    - **本地 ECH 隧道**（项目自带 Go 组件，加密内层 SNI）→ 已解 `discord`（Cloudflare 拒绝跨租户掩护 SNI，
      四种掩护组合实测全 403；经隧道实测 200 + 真实 HTML），并同时承载 `pixiv_web` / `booth_pm`；
    - **普通自身 SNI** → `stackoverflow`（实测 @198.252.206.1 返回 302 且证书匹配，早期按 QUIC 处理属配置错误）；
    - **HTTP/3(QUIC) 直连**保留为**备选通道**与内置「QUIC 直连」启动器（强制 h3，无需管理员）。
    ⚠️ **重要实测结论（2026-10-01，netlog 实证）**：本机 DNS 只能**修正被污染的 A 记录**，
    但**默认浏览器不会因此改走 HTTP/3** —— Chrome 在非安全 DNS（`secure_dns_mode=0`）下不会采用 HTTPS RR 的
    `alpn`，仍只用 TCP（`HTTP_STREAM_JOB expect_spdy=false`）。因此把"浏览器自行走 h3"当作前提的方案不可靠，
    已按上表改为"由本机 nginx 终止浏览器 TLS、上游腿选可用通道"，**默认浏览器零配置即可打开**。
    实测数据与复现脚本见 [docs/uplift-route-findings.md](docs/uplift-route-findings.md) 第十四～十六节。
  - **QUIC 独立测速与自愈**：QUIC 直连类服务的 TCP 侧必然被 RST，常规测速对它们只会给出"全挂"的假阴性 ——
    因此为它们单独建立**真实 QUIC 握手 + HTTP/3 请求**的测速通道，优选结果持久化到 `config.quic_optimal_ips`，
    并由本机解析器与 Hosts 消费；健康巡检发现主力节点失效时自动切换并落盘。
    （QUIC 探测不依赖可选库：缺 `aioquic` 时自动回退到标准库+cryptography 的 Initial 探测。）

- **⚡ 全网 CDN 节点双通道测速与热重载**
  - 多线程高并发探测全部候选节点 TLS / TCP 握手延迟。
  - 自动优选毫秒级最低延迟节点，并原子化注入 Nginx 负载均衡池，支持 `nginx -s reload` 无感热重载。
  - 测速延迟本地安全持久化，软件开启即显历史优选延迟胶囊。

- **🎮 Steam 多账号免密快速切换**
  - 原生词法解析本地 `loginusers.vdf`，展示历史登录用户、SteamID64、昵称与头像。
  - 桌面卡片与系统托盘菜单支持**双击一键免密重启切换**，无需重复输入账号密码与令牌。
  - 支持账号自定义备注别名（主号、小号、交易号），原位内联保存。

- **💎 Material Design 3 现代桌面交互**
  - 采用 Windows 11 Fluent 调色板与 DWM 原生贴靠无边框设计。
  - 完美支持深色 (Dark)、浅色 (Light) 与樱粉 (Pink) **三套主题**无缝自适应切换 (快捷键 `Alt+T`)，全矢量 SVG 图标开关联动变色。
  - **零侵入交互 (Zero-Modal)**：彻底移除系统弹窗，统一采用平滑悬浮 Toast 通知。
  - 单调三次样条 (Monotone Spline) 实时网络流量监控波形图。

- **🛡️ 纯净安全与系统零残留**
  - **Hosts 隔离与备份轮转**：专属标签块原子化读写，退出或异常关机自动无损还原，备份子目录自动轮转保留 5 份历史。
  - **Windows CryptoAPI 原生证书管理**：纯内存原生校验根证书受信任状态，安全防护无误报。

---

## 🛠️ 技术架构

```
[ 游戏客户端 / 浏览器 / 本地开发工具 ]
             │ (Hosts 解析定向到 127.0.0.1)
             ▼
    [ Nginx & L4 Relay 双引擎数据平面 (Port: 80 / 443) ]
             │
             ├──► 本地磁盘缓存 (nginx/cache/img)
             ├──► 动态 Anycast Upstream 负载均衡池 ──► (直连海外 CDN 节点)
             └──► 本地 L4 Relay 旁路隧道 ───────────► (上游 Mixed 代理出口)

    [ PySide6 Material Design 3 控制管理平面 ]
       ├── Hosts 原子注入、体检修复与子目录轮转备份 (HostsManager)
       ├── CryptoAPI 原生证书环境自检与静默管理 (CertManager)
       ├── 多线程 Anycast CDN 延迟探测与动态 Upstream 生成 (CDNOptimizer)
       └── Steam VDF 原生词法解析与免密切换引擎 (SteamManager)
```

---

## 🚀 快速开始

### 运行环境要求
- **操作系统**：Windows 10 / Windows 11 (x64)
- **Python 环境**（仅源码开发调试需）：Python 3.10+
- **系统权限**：管理员权限（用于 Hosts 接管与本地加速证书配置）

### 方式一：运行已打包的客户端
直接运行发布目录中的独立可执行程序（已内嵌所有运行时与 UAC 清单）：
```bash
dist/GameArtToolkit/GameArtToolkit.exe
```

### 方式二：从源码启动开发环境

1. **安装依赖环境**
   ```bash
   pip install PySide6 PyInstaller cryptography
   ```

2. **启动桌面客户端**
   - 双击根目录下的 `启动桌面客户端(双击运行).bat` 或执行命令：
   ```bash
   python app/pyside_app.py
   ```

---

## 📦 自动化编译与打包

项目提供了完整的自动化打包脚本，可一键编译生成附带管理员清单的绿色便携客户端：

- 双击运行根目录下的 `一键打包为EXE(双击运行).bat`，或在终端执行：
  ```bash
  python build.py
  ```
- 构建产物将生成至 `dist/GameArtToolkit/` 目录。

---

## 📂 项目结构概览

```
GameArtToolkit/
├── app/                     # Python 核心控制平面与 PySide6 客户端
│   ├── pyside_app.py        # 客户端主程序入口 (UI 架构 / 系统托盘 / 守护监听)
│   ├── service_profile.py   # 服务 Profile 声明式元数据与路由注册表
│   ├── material_theme.py    # Material Design 3 三套主题调色板与 QSS 样式表
│   ├── md_widgets.py        # MD3 原生自绘控件 (波形图/延迟微徽章/开关/Toast)
│   ├── svg_icons.py         # MD3 / Lucide 矢量 SVG 渲染工厂
│   ├── steam_manager.py     # Steam 路径嗅探、VDF 词法解析与账号免密切换
│   ├── nginx_manager.py     # Nginx 进程生命周期、端口健康与热重载
│   ├── nginx_generator.py   # 动态 Nginx 站点配置模板生成引擎
│   ├── cdn_optimizer.py     # 多线程 Anycast CDN 延迟并发测速与优选
│   ├── dns_server.py        # 本地轻量 UDP DNS 解析器 (无污染分流)
│   ├── l4_relay.py          # L4 TCP SNI 透明代理隧道
│   ├── cert_manager.py      # Windows CryptoAPI 原生根证书自检与静默管理
│   ├── hosts_manager.py     # 标签化 Hosts 原子读写、体检修复与备份轮转
│   ├── nrpt_manager.py      # Windows NRPT 策略表域名重定向后端 (能力探测/规则增删/体检)
│   ├── redirect_manager.py  # 域名重定向后端分派 (Hosts / NRPT 切换、回退与幂等清理)
│   ├── config_store.py      # 配置原子持久化与自动迁移
│   ├── ip_pool.py           # 兼容层服务导出字典与候选池索引
│   ├── frameless_helper.py  # Win32 DWM 原生无边框与贴靠布局支持
│   └── win_utils.py         # Windows 底层 API 封装与静默子进程运行
├── nginx/                   # Nginx 本地反代数据平面
│   ├── nginx.exe            # 高性能代理引擎
│   ├── ca.cer               # 本地自签 Root CA 根证书公钥
│   └── conf/                # Nginx 配置文件与分站规则模板
├── backups/                 # 自动备份管理子目录
│   └── hosts/               # Hosts 结构化历史备份 (自动保持 5 份轮转)
├── tests/                   # 自动化测试与质量保障套件 (全量专项回归测试模块)
├── scripts/                 # 图标生成与维护工具脚本
├── build.py                 # PyInstaller 自动化一键打包构建程序
└── README.md                # 项目设计与使用说明文档
```

---

## ⚠️ 常见问题排查

1. **80 / 443 端口占用**：本地加速需要绑定 80 与 443 端口。若被 IIS、Skype 或 VMware 占用，请在设置页面中进行端口诊断并释放对应端口。
2. **退出 Hosts 自动还原**：程序正常关闭或系统异常关机时均会自动还原系统 Hosts；下次启动时若检测到残留亦会自动体检修复。
3. **Steam 账号安全保证**：免密切换功能基于 Steam 官方在本地生成的凭据配置 (`loginusers.vdf`)，本程序不涉及任何用户密码或令牌的网络传输。
4. **NRPT 重定向开关显示"暂不可用"**：NRPT 的 DNS 目标端口固定为 53，若本机 53/UDP 已被 Clash Verge 等代理的 DNS 覆写占用，则无法启用（设置页会直接标出占用进程名）。此时可继续使用 Hosts 后端，或在代理软件中关闭 DNS 覆写 / 把其 DNS 监听端口改到非 53 端口后再开启。设计说明见 [docs/nrpt-redirect-design.md](docs/nrpt-redirect-design.md)。
5. **受信任根证书里有一堆历史证书**：早期版本的卸载路径 `certutil -delstore` 对根证书是空操作（返回成功但并未删除），导致每次 CA 重新生成都会在受信任根里新增一个永不回收的证书。现已改为 crypt32 原生删除 + **删除后复查确认**，并在每次安装前自动清理历史代际。清理既有残留需管理员权限：`python -m app.cert_manager --report` 查看、`--prune` 执行。详见 [docs/cert-trust-hygiene.md](docs/cert-trust-hygiene.md)。
6. **证书私钥对本机所有用户可读（已修复）**：本地 CA 私钥 `nginx/ca/ca.key` 原先在用户可写目录里直接写出，继承了父目录 ACL —— 实测为
   `BUILTIN\Authenticated Users:(M)`（可改）+ `BUILTIN\Users:(RX)`（可读），即**任意本地进程都能读走全机受信任的 CA 私钥**，
   等价于完整的 TLS 劫持能力；服务端叶子私钥被读走则允许冒充全部被反代的域名。
   现已改为：生成时把目录 ACL 收紧为 **`SYSTEM` + `Administrators` + 当前用户**（并带 `(OI)(CI)` 继承，使新私钥"生来即紧"），
   断开继承，且每次生成/自愈后**回读校验**（设置调用返回成功不算数）。自查与修复均**无需管理员**：

   ```
   python -m app.cert_manager --report        # 含私钥 ACL 体检
   python -m app.cert_manager --harden-keys   # 一键收紧 (幂等)
   python -m app.private_key_acl --audit      # 等价的自查入口
   ```

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 授权开源。

第三方参考与许可边界说明（含被参考项目的许可核查、"明确未取用"清单与干净室记录）见 [docs/third-party-provenance.md](docs/third-party-provenance.md)。
