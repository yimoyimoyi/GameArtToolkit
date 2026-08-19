# -*- coding: utf-8 -*-
"""
PixivToolkit - 设置项扩展、退出与关机 Hosts 修正自动恢复专项自动化测试
"""

import os
import sys
import time
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "app"))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from config_store import load_config, save_config, update_config_key, DEFAULT_CONFIG
from hosts_manager import HostsManager, BLOCK_START, BLOCK_END
from win_utils import (
    is_autostart_enabled, set_autostart, register_shutdown_handler,
    check_proxy_alive, fast_terminate_pid, flush_dns_native
)

def test_config_expansion():
    print("\n[Test 1/5] 测试配置项扩充与默认值规范...")
    cfg = load_config()
    required_keys = [
        "auto_start", "start_minimized", "close_action",
        "auto_clean_hosts_on_exit", "auto_heal_on_startup",
        "tray_notifications", "upstream_proxy"
    ]
    for key in required_keys:
        assert key in cfg, f"配置项缺失: {key}"
        print(f"  ✓ 配置项 '{key}': {cfg[key]}")

    # 测试原子更新
    update_config_key("close_action", "quit_directly")
    cfg2 = load_config()
    assert cfg2["close_action"] == "quit_directly", "配置更新失败"
    update_config_key("close_action", "minimize_to_tray")
    print("  => 配置项扩充与原子持久化测试通过 [PASS]")

def test_autostart_registry():
    print("\n[Test 2/5] 测试 Windows HKCU 注册表开机自启读写...")
    original_state = is_autostart_enabled()
    print(f"  - 初始自启动状态: {original_state}")

    # 测试开启
    ok, msg = set_autostart(True, start_minimized=True)
    print(f"  - 设置自启结果: {ok}, {msg}")
    assert ok, f"开启开机自启失败: {msg}"
    assert is_autostart_enabled() is True, "注册表未检测到自启项"

    # 测试关闭
    ok, msg = set_autostart(False)
    print(f"  - 取消自启结果: {ok}, {msg}")
    assert ok, f"关闭开机自启失败: {msg}"
    assert is_autostart_enabled() is False, "注册表自启项清理失败"

    # 还原初始状态
    if original_state:
        set_autostart(True)
    print("  => Windows 注册表开机自启无特权管理测试通过 [PASS]")

def test_hosts_diagnosis_and_restore():
    print("\n[Test 3/5] 测试 Hosts 体检修复与官方纯净模板恢复...")
    # 使用临时测试 hosts 文件以避免干扰系统 hosts
    test_hosts_path = BASE_DIR / "temp_test_hosts"
    try:
        # 1. 模拟写入包含破损标签与第三方残留的 hosts
        dirty_content = (
            "# Normal Header\n"
            "127.0.0.1 localhost\n"
            "# >>>>> PixivToolkit Rules Start >>>>>\n"
            "127.0.0.1 www.pixiv.net\n"
            "# Missing END block intentionally\n"
        )
        test_hosts_path.write_text(dirty_content, encoding="utf-8")

        hm = HostsManager(hosts_file=test_hosts_path)
        diag = hm.diagnose_and_repair(auto_fix=True)
        print(f"  - 体检报告: issues={diag['issues']}, fixes={diag['fixes']}")
        assert len(diag["issues"]) > 0, "未能检出异常破损标签"
        assert len(diag["fixes"]) > 0, "未能自动修复破损标签"

        # 2. 测试恢复官方默认 Hosts
        ok, msg = hm.restore_default_windows_hosts()
        print(f"  - 恢复官方 Hosts: {ok}, {msg}")
        assert ok, "恢复官方纯净 Hosts 失败"
        content_after = test_hosts_path.read_text(encoding="utf-8")
        assert "localhost" in content_after and "Pixiv" not in content_after, "还原内容不符合纯净规范"

    finally:
        if test_hosts_path.exists():
            test_hosts_path.unlink(missing_ok=True)
        # 清理备份文件
        for f in BASE_DIR.glob("temp_test_hosts*.bak"):
            f.unlink(missing_ok=True)
    print("  => Hosts 诊断与官方纯净模板恢复测试通过 [PASS]")

def test_fast_remove_performance():
    print("\n[Test 4/5] 测试关机快速清理 (fast_remove_rules) 性能与幂等性...")
    test_hosts_path = BASE_DIR / "temp_fast_hosts"
    try:
        injected_content = (
            "# Base hosts\n"
            "127.0.0.1 localhost\n\n"
            f"{BLOCK_START}\n"
            "127.0.0.1 www.pixiv.net\n"
            "127.0.0.1 i.pximg.net\n"
            f"{BLOCK_END}\n"
        )
        test_hosts_path.write_text(injected_content, encoding="utf-8")

        hm = HostsManager(hosts_file=test_hosts_path)
        t0 = time.perf_counter()
        success = hm.fast_remove_rules()
        t1 = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000

        print(f"  - fast_remove_rules 执行耗时: {elapsed_ms:.3f} ms (要求 < 30ms)")
        assert success, "fast_remove_rules 执行失败"
        assert elapsed_ms < 30.0, f"关机清理耗时过高: {elapsed_ms}ms"

        content_after = test_hosts_path.read_text(encoding="utf-8")
        assert BLOCK_START not in content_after, "规则未被完全清理"

        # 测试幂等性 (再次调用耗时更短且安全)
        t2 = time.perf_counter()
        success2 = hm.fast_remove_rules()
        t3 = time.perf_counter()
        print(f"  - 幂等重复调用耗时: {(t3 - t2) * 1000:.3f} ms")
        assert success2, "幂等重复调用失败"

    finally:
        if test_hosts_path.exists():
            test_hosts_path.unlink(missing_ok=True)
    print("  => 关机快速清理性能与幂等性验证通过 [PASS]")

def test_proxy_alive_probe():
    print("\n[Test 5/6] 测试上游测速代理连通性探测与关机钩子注册...")
    # 测试本机无效端口
    res_dead = check_proxy_alive("127.0.0.1", 59999, timeout=0.1)
    print(f"  - 探测无效端口 59999 连通性: {res_dead} (预期 False)")
    assert res_dead is False, "无效端口误报为连通"

    # 测试关机钩子注册
    called = []
    def dummy_shutdown_hook():
        called.append(True)

    ok = register_shutdown_handler(dummy_shutdown_hook)
    print(f"  - 注册 Win32 控制台/关机事件钩子: {ok}")
    assert ok, "注册关机钩子失败"
    print("  => 上游测速代理探测与关机钩子注册测试通过 [PASS]")

def test_hosts_backup_rotation_and_subfolder():
    print("\n[Test 6/6] 测试 Hosts 备份子目录收敛与自动轮转上限 (保留 5 份)...")
    test_hosts_path = BASE_DIR / "temp_test_hosts_bak"
    test_backup_dir = BASE_DIR / "backups" / "test_hosts"
    test_hosts_path.write_text("127.0.0.1 test.local\n", encoding="utf-8")

    try:
        if test_backup_dir.exists():
            shutil.rmtree(test_backup_dir, ignore_errors=True)

        hm = HostsManager(hosts_file=test_hosts_path, backup_dir=test_backup_dir)

        # 连续生成 10 次备份 (设置 max_keep=5)
        created_paths = []
        for i in range(10):
            test_hosts_path.write_text(f"127.0.0.1 test{i}.local\n", encoding="utf-8")
            time.sleep(0.01)  # 确保时间戳微差
            p = hm.create_backup(max_keep=5)
            assert p is not None, f"第 {i+1} 次创建备份失败"
            assert p.parent == test_backup_dir, "备份文件未保存在指定的子目录中"
            created_paths.append(p)

        # 检查最终保留的备份
        remaining_baks = hm.list_backups()
        print(f"  - 连续生成 10 次备份后，子目录中实际保留数量: {len(remaining_baks)} (预期: 5)")
        assert len(remaining_baks) == 5, f"备份数量超过上限: {len(remaining_baks)}"

        # 验证保留的文件全在最后生成的批次中
        remaining_names = {f.name for f in remaining_baks}
        latest_5_names = {p.name for p in created_paths[-5:]}
        assert remaining_names == latest_5_names, "旧备份淘汰错误，未保留最新生成的 5 份"

        # 验证根目录没有散落文件
        legacy_scattered = list(BASE_DIR.glob("temp_test_hosts_bak.ptk_bak_*.bak"))
        assert len(legacy_scattered) == 0, "根目录发现散落的旧版 bak 文件"

        print("  => Hosts 备份子目录隔离与数量自动轮转验证通过 [PASS]")
    finally:
        if test_hosts_path.exists():
            test_hosts_path.unlink(missing_ok=True)
        if test_backup_dir.exists():
            shutil.rmtree(test_backup_dir, ignore_errors=True)

def run_all():
    print("==================================================")
    print("   GameArt Toolkit 设置扩展与关机自动恢复自动化验证")
    print("==================================================")
    test_config_expansion()
    test_autostart_registry()
    test_hosts_diagnosis_and_restore()
    test_fast_remove_performance()
    test_proxy_alive_probe()
    test_hosts_backup_rotation_and_subfolder()
    print("\n==================================================")
    print("  [SUCCESS] 6 大专项生命周期与设置验证全部通过！")
    print("==================================================")

if __name__ == "__main__":
    run_all()
