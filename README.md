# PixivToolkit 🧰

现代化网络加速与 Steam 多账号快速免密切换管理工具（**PySide6 Material Design 3 原生桌面客户端**）。

结合了 **Pixiv-Nginx 的极致高性能、超低内存反代架构** 与 **SteamTools (Watt Toolkit) 的多功能账号管理及智能 CDN 调度思想**，支持**系统托盘后台常驻**与**代理自动托管自愈**。

---

## ✨ 核心特性

### 1. 🎨 Material Design 3 原生桌面客户端 (PySide6)
- **极简高质感 MD3 界面**：深色 Material 3 配色规范、动态状态圆点、发光状态指示、柔和圆角卡片。
- **后台常驻与系统托盘 (System Tray)**：关闭窗口自动最小化到系统托盘，加速不中断；托盘右键直接支持**一键启动/停止加速**与 **Steam 账号快速秒切子菜单**。
- **代理自动托管与看门狗自愈**：开启后，开机/启动自动应用 Hosts 并拉起 Nginx，后台看门狗每 8 秒自动检测代理健康状态并实时自愈。

### 2. 🎮 Steam 快速账号管家 (Steam Account Switcher)
- **多账号自动识别**：深度解析本地 `loginusers.vdf`，自动提取已记住的所有 Steam 账号、昵称、历史登录时间与头像。
- **免密一键无缝切换**：主界面或托盘右键一键点击，自动安全退出当前 Steam、切换注册表与 VDF 活跃标记，并以选定账号重新拉起 Steam 客户端。
- **个性化备注标签**：支持为账号设置备注别名（如：主号、小号、交易号、挂卡号）。

### 3. 🚀 全能网络加速引擎 (Next-Gen Acceleration)
- **Pixiv 插画与社区**：解决 Pixiv 网页端、插画大图加载缓慢或破图、APP 接口、Fanbox 赞助平台、WebSocket 等访问问题。
- **本地图片高速磁盘缓存 (Proxy Cache)**：基于 Nginx 磁盘缓存，浏览过的插画原图二次打开秒加载。
- **Steam 全平台加速**：解决 Steam 商店打不开、社区错误代码 118/105、个人资料与讨论区论坛打不开等问题。
- **GitHub & HuggingFace 开发者加速**：支持加速 GitHub Web、Raw 脚本直连、Release 附件下载以及 HuggingFace 大模型权重（LFS）下载。

### 4. ⚡ 智能 CDN 多线程测速与零停机优选 (Smart CDN Ping)
- **多线程高并发探测**：对候选 IP 池并发进行毫秒级 TCP/TLS 握手测速与连通性检测。
- **动态 Upstream 热重载**：自动筛选最优 Top N 节点并写入配置，触发 Nginx 零中断平滑热重载（`nginx -s reload`）。

### 5. 🔐 证书与 Hosts 安全无残留管理
- **Windows 根证书自检**：自动检测系统“受信任的根证书颁发机构”，支持一键静默导入与卸载。
- **标签化原子 Hosts 读写**：采用独立标记块管理，退出时一键还原系统 Hosts，绝不破坏用户原本的 hosts 文件。

---

## 🖥 启动与使用方式

### 方式 1：直接运行已编译好的 EXE（推荐）
直接进入发布目录双击运行：
👉 **[`E:\PixivToolkit\dist\PixivToolkit\PixivToolkit.exe`](file:///E:/PixivToolkit/dist/PixivToolkit/PixivToolkit.exe)**

### 方式 2：通过源码脚本运行
- 双击运行根目录下的 **[`启动Material桌面端(双击运行).bat`](file:///E:/PixivToolkit/启动Material桌面端(双击运行).bat)**。

### 方式 3：重新一键打包 EXE
- 双击运行 **[`一键打包为EXE(双击运行).bat`](file:///E:/PixivToolkit/一键打包为EXE(双击运行).bat)**，将自动编译生成全新的 `PixivToolkit.exe`。

---

## 📂 项目结构

```
E:\PixivToolkit\
├── dist\
│   └── PixivToolkit\
│       ├── PixivToolkit.exe # 独立 Windows 桌面可执行文件
│       └── nginx\           # 内置便携 Nginx 数据平面
├── app\                     # Python 核心引擎与 PySide6 客户端
│   ├── pyside_app.py        # PySide6 Material 桌面主程序 (托盘/看门狗/界面)
│   ├── material_theme.py    # Material Design 3 QSS 样式系统
│   ├── steam_manager.py     # Steam 路径检测、VDF解析、多账号管理与一键免密切换
│   ├── nginx_manager.py     # Nginx 进程托管、状态检测、80/443端口冲突排查
│   ├── cert_manager.py      # Windows 系统根证书自检与静默安装/卸载
│   ├── hosts_manager.py     # 标签化安全 Hosts 读写、无损备份、还原与 DNS 刷新
│   ├── cdn_optimizer.py     # 智能多线程 TCP/TLS 延迟测速、动态 Upstream 生成与热重载
│   ├── config_store.py      # 用户偏好、服务勾选与账号别名数据持久化
│   ├── ip_pool.py           # Pixiv/Steam/GitHub/HuggingFace 候选 CDN 节点 IP 池
│   └── main.py              # 本地 REST API 核心
├── nginx\                   # Nginx 高性能数据平面
│   ├── nginx.exe            # 核心代理引擎
│   ├── ca\                  # 自签根证书与私钥
│   └── conf\                # Nginx 配置与动态 Upstream
├── web\                     # Web 前端资源
├── scripts\                 # 辅助批处理脚本 (UTF-8 with BOM)
├── 启动Material桌面端(双击运行).bat  # 原生桌面客户端入口 (UTF-8 with BOM)
├── 一键打包为EXE(双击运行).bat       # 一键打包编译脚本 (UTF-8 with BOM)
├── build.py                 # PyInstaller 编译构建程序
├── test_suite.py            # 全自动化集成测试套件
└── README.md                # 项目详细说明文档
```
