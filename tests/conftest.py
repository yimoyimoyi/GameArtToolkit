# -*- coding: utf-8 -*-
"""
测试全局隔离与清理 fixture

背景: 组合运行测试套件时耗时从 ~75s(单文件合计)恶化到 10 分钟+ 无法完成,
根因是 GUI 测试创建 MainWindow 时执行大量真实系统副作用(schtasks 子进程 /
hosts 体检修复 / 状态探针线程 / 环境诊断端口扫描 / 自动 CDN 测速 / 看门狗巡检),
且测试从不销毁窗口, 在全局 QApplication 单例中线性累积, 拖垮后续所有测试。

本文件提供 autouse fixture:
1. 屏蔽 MainWindow 构造路径上的真实系统操作(组合运行提速 10 倍以上)
2. 每个测试结束后强制销毁所有残留 Qt 顶层窗口, 释放 QTimer/QThread/信号槽资源
"""

import gc
import os
import sys
from pathlib import Path

import pytest

# 与 test_gui.py 保持一致: 无显示器/CI/命令行自动化环境下使用 offscreen 渲染
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

APP_DIR = Path(__file__).resolve().parent.parent / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))


@pytest.fixture(autouse=True)
def _gui_side_effect_isolation(monkeypatch):
    """屏蔽 MainWindow 构造时的真实系统副作用, 测试结束后清理 Qt 窗口泄漏"""
    try:
        import pyside_app
    except Exception:
        yield
        return

    # 1. 开机自启检测: 会执行 schtasks 子进程(GBK 输出在 UTF-8 模式下崩溃 reader 线程)
    #    仅屏蔽 pyside_app 命名空间中的引用, 不影响 test_lifecycle 对 win_utils 的直测
    monkeypatch.setattr(pyside_app, "is_autostart_enabled", lambda: False)

    # 2. 构造时 hosts 体检: auto_fix=True 会真实修改系统 hosts 文件并操作注册表
    monkeypatch.setattr(pyside_app.hosts_mgr, "diagnose_and_repair",
                        lambda auto_fix=True, **kw: {"issues": [], "fixes": []})

    # 3. 状态探针线程: 真实检查证书/端口/进程(组合运行时大量线程叠加抢 GIL)
    monkeypatch.setattr(pyside_app.MainWindow, "_start_status_probe", lambda self: None)

    # 4. 环境诊断: 代理端口扫描在防火墙 DROP 环境下每个端口等满 50ms 超时
    monkeypatch.setattr(pyside_app.MainWindow, "refresh_env_diagnostics_ui", lambda self: None)

    # 5. 启动后 2.5s 自动 CDN 测速 + 8s 看门狗巡检: 均会发起真实网络探针
    monkeypatch.setattr(pyside_app.MainWindow, "trigger_startup_auto_cdn", lambda self: None)
    monkeypatch.setattr(pyside_app.MainWindow, "watchdog_auto_heal", lambda self: None)

    yield

    # 测试后清理: 销毁所有残留顶层窗口(测试从不 close/deleteLater, 对象在 C++ 层堆积)
    # 注意: 无事件循环环境中 processEvents() 不处理 DeferredDelete 事件,
    # 必须显式 sendPostedEvents(QEvent.DeferredDelete) 才能真正销毁窗口
    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtCore import QEvent
    except ImportError:
        return
    app = QApplication.instance()
    if app is None:
        return
    for w in list(app.topLevelWidgets()):
        try:
            w.deleteLater()
        except RuntimeError:
            pass
    app.sendPostedEvents(None, QEvent.DeferredDelete)
    app.processEvents()
    gc.collect()
