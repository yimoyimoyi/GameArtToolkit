# PixivToolkit

<p align="center">
  <b>基于 PySide6 (Material Design 3) 与高性能 Nginx 的 Windows 本地网络加速与 Steam 多账号快速免密切换管理套件</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/GUI-PySide6%20MD3-emerald.svg" alt="PySide6">
  <img src="https://img.shields.io/badge/Proxy-Nginx-green.svg" alt="Nginx">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey.svg" alt="License">
</p>

---

## 📖 项目简介

**PixivToolkit** 是一款专为 Windows 平台打造的现代化网络加速与游戏生态辅助工具。

通过将 **PySide6 Material Design 3 桌面交互** 与 **本地便携式 Nginx 高性能反代数据平面** 深度结合，提供透明网络加速、动态 CDN 多线程优选以及 Steam 多账号免密快速切换体验。

### 🌟 核心特性

- 🚀 **高性能透明反向代理**
  - 内置便携式 Nginx 引擎，毫秒级响应与超低内存占用。
  - 支持 Pixiv（插画大图、Fanbox、APP 接口）、Steam（商店、社区 118/105 修复、Akamai CDN）、GitHub（Web、Raw、Releases 附件）及 HuggingFace 等服务加速。
  - 基于 Nginx 磁盘缓存的插画本地极速二次加载。

- ⚡ **智能 CDN 节点测速与平滑热重载**
  - 多线程高并发 TCP / TLS 握手连通性与延迟测速。
  - 自动优选最优节点并动态写入 Upstream 配置，支持零停机热重载 (`nginx -s reload`)。

- 🎮 **Steam 账号快速免密秒切**
  - 自动解析本地 `loginusers.vdf`，直观展示已记住账号、昵称、历史登录时间及头像。
  - 主界面与系统托盘右键菜单支持一键免密安全秒切。
  - 支持自定义账号备注标签（如：主号、小号、交易号）。

- 🎨 **Material Design 3 沉浸式桌面客户端**
  - 深度集成深浅色主题切换与流畅过渡动画。
  - 支持无边框沉浸式窗口与 Windows 11 Snap Layouts 贴靠对齐。
  - 完善的系统托盘后台常驻、流量与请求实时监控波形图。
  - 8 秒看门狗守护机制，保障代理链路稳定与异常自动自愈。

- 🔐 **安全原子管理与零残留**
  - 标签化独立 Hosts 规则块管理，退出时一键完整还原，不污染系统原有 Hosts。
  - 自签 Universal Root CA 根证书自检，支持一键静默安全导入与卸载。

---

## 🛠️ 技术架构

```
[ 用户应用 / 浏览器 / Steam ]
             │ (Hosts 解析定向到 127.0.0.1)
             ▼
    [ Nginx 本地反代数据平面 (Port: 80 / 443) ]
             │
             ├──► 磁盘高速图片缓存 (cache/img)
             └──► 动态优选 Upstream 负载均衡池
                      │ (TCP / TLS 直连)
                      ▼
            [ 目标海外 CDN / 官方服务器 ]

    [ PySide6 客户端管理控制平面 ]
      ├── Hosts 原子注入与无损还原
      ├── SSL 根证书自检与静默管理
      ├── 多线程高并发 CDN 延迟探测 (Smart CDN Ping)
      └── Steam VDF 解析与多账号免密调度
```

---

## 🚀 快速开始

### 运行环境要求
- **操作系统**：Windows 10 / Windows 11 (x64)
- **Python 环境**（仅源码运行需）：Python 3.10+
- **系统权限**：管理员权限（用于写入 Hosts 及安装自签加速证书）

### 方式一：运行已编译的独立客户端（推荐）
直接运行发布目录中的可执行程序（已内嵌所有依赖与管理员清单）：
```
dist/PixivToolkit/PixivToolkit.exe
```

### 方式二：从源码运行

1. **安装依赖**
   ```bash
   pip install PySide6 PyInstaller
   ```

2. **启动桌面客户端**
   - 双击根目录下的 `启动Material桌面端(双击运行).bat` 或执行命令：
   ```bash
   python app/pyside_app.py
   ```

---

## 📦 编译与打包

项目提供了自动化构建脚本，支持一键打包为附带 UAC 管理员权限清单的独立绿色客户端：

- 双击运行根目录下的 `一键打包为EXE(双击运行).bat`，或执行命令：
  ```bash
  python build.py
  ```
- 构建产物将生成至 `dist/PixivToolkit/` 目录。

---

## 📂 项目结构

```
PixivToolkit/
├── app/                     # Python 核心控制平面与 PySide6 客户端
│   ├── pyside_app.py        # 客户端主程序入口 (UI / 系统托盘 / 看门狗)
│   ├── material_theme.py    # Material Design 3 样式规范与主题管理
│   ├── md_widgets.py        # 自定义 Material 风格控件与动态图表
│   ├── steam_manager.py     # Steam 路径检测、VDF 解析与账号免密秒切
│   ├── nginx_manager.py     # Nginx 进程生命周期、端口与热重载管理
│   ├── cdn_optimizer.py     # 智能多线程 TCP/TLS 测速与动态 Upstream 生成
│   ├── cert_manager.py      # Windows 系统根证书自检与安全管理
│   ├── hosts_manager.py     # 标签化安全 Hosts 原子读写与 DNS 刷新
│   ├── config_store.py      # 配置持久化存储与原子灾备
│   ├── ip_pool.py           # 候选加速服务与 CDN 节点 IP 池
│   ├── frameless_helper.py  # Win32 DWM 原生无边框贴靠支持
│   ├── svg_icons.py         # 矢量 SVG 图标资源
│   └── win_utils.py         # Windows 底层 API 与静默执行封装
├── nginx/                   # Nginx 高性能反代数据平面
│   ├── nginx.exe            # 核心代理引擎
│   ├── ca/                  # 自签加速根证书与私钥
│   └── conf/                # Nginx 主配置与各生态分站规则
├── scripts/                 # 辅助维护批处理脚本
├── build.py                 # PyInstaller 一键编译打包程序
├── test_suite.py            # 自动化集成测试套件
├── .gitignore               # Git 忽略规则
└── README.md                # 项目文档
```

---

## ⚠️ 注意事项

1. **端口冲突排查**：本工具需要占用本地 `80` 和 `443` 端口作为反向代理网关。若被 IIS、Skype、VMware 等服务占用，请先释放对应端口。
2. **安全与 Hosts 还原**：程序退出时会自动安全清理注入的 Hosts 规则；若遭遇异常断电，下次启动客户端将自动检测并自愈还原。
3. **Steam 令牌安全**：Steam 快速切换功能仅通过官方支持的本地记住凭据 (`loginusers.vdf`) 与注册表切换活跃状态，不会收集或上传任何用户密码与令牌信息。

---

## 📄 许可证

本项目基于 [MIT License](LICENSE) 开源。
