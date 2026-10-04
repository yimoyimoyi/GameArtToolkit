# GameArt Toolkit

<p align="center">
  <b>面向 Windows 平台的桌面工具箱：网络访问优化 + Steam 账号管理</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/GUI-PySide6%20MD3-emerald.svg" alt="PySide6">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey.svg" alt="License">
</p>

---

## ⚠️ 免责声明

> **本项目仅供学习与技术研究使用。**
>
> - 请勿用于任何商业用途，或用于违反你所在地区法律法规的场景。
> - 本项目按「现状」提供，**不提供任何可用性保证**，也不对任何特定站点、平台或服务作出承诺；
>   相关能力会随外部环境变化而随时失效，属正常现象，不作为缺陷处理。
> - 使用本项目的风险与全部后果由使用者自行承担，作者不承担任何直接或间接责任。

---

## 📖 项目简介

**GameArt Toolkit** 是一款 Windows 10/11 桌面工具，使用 Python + PySide6（Material Design 3）构建，
在本机侧提供两类能力：

- **网络访问优化** —— 在本机建立加速通道，自动探测并优选可用节点，让目标站点尽量"打开即可用"，
  无需改动浏览器的代理设置。
- **Steam 账号管理** —— 解析本地 Steam 配置，实现多账号免密快速切换。

界面为无边框 Fluent 风格，提供深色 / 浅色 / 樱粉三套主题；对系统的改动均可还原。

---

## ✨ 主要功能

- 本地加速通道，免第三方代理软件，默认零配置
- 节点自动测速与优选，配置热重载，无需重启
- 本地磁盘缓存，静态资源重复访问秒开
- 系统改动可逆：独占区块读写；退出或异常关机后，下次启动自动回收残留
- 部分内容分组默认隐藏，需在设置中显式开启
- Steam 多账号免密切换（含头像与自定义备注别名）
- Material Design 3 三主题、零弹窗 Toast 交互

> 本文档只做**通用介绍**：具体支持哪些站点、经由哪种通道，属实现细节，会随外部环境频繁变化，
> 因此不在此逐一列举，也不随版本更新维护。

---

## 🚀 快速开始

### 环境要求

- **操作系统**：Windows 10 / Windows 11 (x64)
- **权限**：默认 PAC 后端免管理员；仅 Hosts / NRPT / 证书安装等系统级配置需要管理员权限
- **仅源码运行需要**：Python 3.10+

### 运行

1. **使用打包版本**（推荐）：运行 `dist/GameArtToolkit/GameArtToolkit.exe`
2. **从源码启动**：

   ```bash
   pip install PySide6 cryptography
   python app/pyside_app.py
   ```

   也可以直接双击根目录下的 `启动桌面客户端(双击运行).bat`。

### 打包

双击根目录下的 `一键打包为EXE(双击运行).bat`，或执行：

```bash
python build.py
```

产物生成于 `dist/GameArtToolkit/`。

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 授权开源。

使用前请再次阅读上方的免责声明。
