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
  - **二次元与创作者生态**：Pixiv 网页/API/APP 接口、pximg 插画 CDN、Fanbox 创作者赞助、BOOTH 同人商城、Danbooru 动漫图库、Yande.re 高清壁纸、VNDB 视觉小说资料库、Fantia 创作者俱乐部、MyAnimeList 动漫数据库、DLsite 同人发布、Patreon 创作者赞助。
  - **游戏生态**：Steam 商店/结账、Steam 社区 118 修复、Steam Akamai 图片 CDN、Ubisoft 育碧商城、EA App / Origin、Battle.net 战网国际服、GOG 游戏商城、Xbox 微软游戏生态、Minecraft 游戏生态。
  - **开发者与 AI 生态**：GitHub 主站 Web/API、GitHub 静态资产与 Raw 直连、GitHub Releases 附件极速下载 (L4 Relay 旁路直通)、GitHub 前端 JS/CSS CDN、GitLab 国际版、HuggingFace AI 大模型权重直连。
  - **本地磁盘二级缓存**：二次打开插画与静态资源实现本地 0ms 闪电响应。
  - **L4 Relay 旁路隧道**：针对直连受阻的海外服务，自动经由本地上游代理端口透明转发，无需修改系统全局代理。

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

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 授权开源。
