# PixivToolkit

<p align="center">
  <b>基于 PySide6 (Material Design 3) 与本地 Nginx 的 Windows 网络加速与 Steam 多账号免密切换工具</b>
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

**PixivToolkit** 是面向 Windows 平台的网络加速与游戏生态辅助工具，由 PySide6 Material Design 3 桌面客户端与本地便携式 Nginx 反向代理组成，提供网络加速、CDN 节点测速优选与 Steam 多账号免密切换功能。

### 核心特性

- **本地反向代理 (支持 3 大分类 18 项服务)**
  - **二次元与创作者生态**：Pixiv 网页/API/APP 接口、pximg 插画 CDN、Fanbox 创作者赞助、BOOTH 同人商城、Danbooru 动漫图库、Yande.re 高清壁纸、VNDB 视觉小说资料库。
  - **游戏生态**：Steam 商店/结账、Steam 社区 118 修复、Steam Akamai 图片 CDN、Ubisoft 育碧商城、EA App / Origin。
  - **开发者与 AI**：GitHub 主站 Web/API、GitHub 静态资源/Raw 直连、GitHub Releases 附件与对象、GitHub 前端 CDN、GitLab 国际版、HuggingFace AI 模型库。
  - 基于 Nginx 本地磁盘缓存，二次加载插画与静态资源从本地缓存毫秒级读取。

- **CDN 节点双通道测速与热重载**
  - 多线程并发 TCP / TLS 握手连通性与延迟测速，支持直连与本地代理双通道探测。
  - 自动选择延迟最低的节点并写入 Upstream 配置，支持热重载 (`nginx -s reload`)。

- **Steam 账号免密切换**
  - 解析本地 `loginusers.vdf`，展示已记住账号、昵称、历史登录时间及头像。
  - 主界面与系统托盘右键菜单支持双击免密切换。
  - 支持自定义账号备注标签（如：主号、小号、交易号）。

- **Material Design 3 桌面客户端**
  - 深浅色主题自适应切换。
  - Win32 DWM 原生无边框窗口与 Windows 11 Snap Layouts 贴靠对齐。
  - 系统托盘后台常驻、加速链路心跳状态指示。
  - 8 秒定时环境检查，异常断电或退出残留自动恢复。

- **安全管理与零残留**
  - 标签化独立 Hosts 规则块管理，退出时自动完整还原，不污染系统原有 Hosts。
  - Windows CryptoAPI 原生自签 Universal Root CA 自检，支持静默导入与卸载。

---

## 🛠️ 技术架构

```
[ 用户应用 / 浏览器 / Steam ]
             │ (Hosts 解析定向到 127.0.0.1)
             ▼
    [ Nginx 本地反代数据平面 (Port: 80 / 443) ]
             │
             ├──► 磁盘图片缓存 (cache/img)
             └──► 动态优选 Upstream 负载均衡池
                      │ (TCP / TLS 直连)
                      ▼
            [ 目标海外 CDN / 官方服务器 ]

    [ PySide6 客户端管理控制平面 ]
      ├── Hosts 原子注入与还原 (18 项服务独立细粒度控制)
      ├── SSL 根证书自检与静默管理 (CryptoAPI 原生调用)
      ├── 多线程并发 CDN 延迟探测与动态 Upstream 刷新
      └── Steam VDF 解析与多账号免密切换
```

---

## 🚀 快速开始

### 运行环境要求
- **操作系统**：Windows 10 / Windows 11 (x64)
- **Python 环境**（仅源码运行需）：Python 3.10+
- **系统权限**：管理员权限（用于写入 Hosts 及安装自签加速证书）

### 方式一：运行已编译的独立客户端
直接运行发布目录中的可执行程序（已内嵌所有依赖与管理员清单）：
```
dist/PixivToolkit/PixivToolkit.exe
```

### 方式二：从源码运行

1. **安装依赖**
   ```bash
   pip install PySide6 PyInstaller cryptography
   ```

2. **启动桌面客户端**
   - 双击根目录下的 `启动桌面客户端(双击运行).bat` 或执行命令：
   ```bash
   python app/pyside_app.py
   ```

---

## 📦 编译与打包

项目提供了自动化构建脚本，可打包为附带 UAC 管理员权限清单的独立绿色客户端：

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
│   ├── pyside_app.py        # 客户端主程序入口 (UI / 系统托盘 / 定时检查)
│   ├── material_theme.py    # Material Design 3 样式规范与主题管理
│   ├── md_widgets.py        # 自定义 Material 风格控件与动态图表
│   ├── steam_manager.py     # Steam 路径检测、VDF 解析与账号免密切换
│   ├── nginx_manager.py     # Nginx 进程生命周期、端口与热重载管理
│   ├── cdn_optimizer.py     # 多线程 TCP/TLS 测速与动态 Upstream 生成
│   ├── cert_manager.py      # Windows 系统根证书自检与管理 (CryptoAPI)
│   ├── hosts_manager.py     # 标签化 Hosts 原子读写与 DNS 刷新
│   ├── config_store.py      # 配置持久化存储与自动迁移
│   ├── ip_pool.py           # 18 项加速服务元数据与 CDN 候选池
│   ├── frameless_helper.py  # Win32 DWM 无边框贴靠支持
│   ├── svg_icons.py         # SVG 矢量图标资源
│   └── win_utils.py         # Windows 底层 API 与静默执行封装
├── nginx/                   # Nginx 反代数据平面
│   ├── nginx.exe            # 核心代理引擎
│   ├── ca.cer               # Universal Root CA 根证书公钥
│   ├── ca/                  # 服务端证书 (pixiv.net.crt / pixiv.net.key)
│   └── conf/                # Nginx 主配置与 3 大分类生态分站规则
├── tests/                   # 自动化单元与回归测试套件
│   ├── test_regression.py   # 6 大专项自动化回归测试套件
│   ├── test_gui.py          # 桌面 UI 组件与交互自动化测试
│   └── test_lifecycle.py    # 退出与关机 Hosts 恢复生命周期测试
├── scripts/                 # 辅助维护批处理脚本
├── build.py                 # PyInstaller 编译打包程序
├── .gitignore               # Git 忽略规则
└── README.md                # 项目文档
```

---

## ⚠️ 注意事项

1. **端口冲突排查**：本工具需要占用本地 `80` 和 `443` 端口作为反向代理网关。若被 IIS、Skype、VMware 等服务占用，请先释放对应端口。
2. **安全与 Hosts 还原**：程序退出时会自动清理注入的 Hosts 规则；若遭遇异常断电，下次启动客户端将自动检测并修复。
3. **Steam 令牌安全**：Steam 快速切换功能仅通过官方支持的本地记住凭据 (`loginusers.vdf`) 与注册表切换活跃状态，不会收集或上传任何用户密码与令牌信息。

---

## 📄 许可证

本项目基于 [MIT License](LICENSE) 开源。
