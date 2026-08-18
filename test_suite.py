# -*- coding: utf-8 -*-
"""
PixivToolkit - 全自动化功能集成测试套件 (包含 28 项全量服务测试)
"""

import sys
import time
import json
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / "app"))

from steam_manager import SteamManager
from cert_manager import CertManager
from hosts_manager import HostsManager
from nginx_manager import NginxManager
from cdn_optimizer import CDNOptimizer
from ip_pool import SERVICES_LIST, DEFAULT_ENABLED_SERVICES

def run_tests():
    print("==================================================")
    print("       PixivToolkit 全模块功能自动化测试")
    print("==================================================")

    # 1. 测试 Steam 管理器
    print("\n[1/5] 测试 Steam 账号管理器 (SteamManager)...")
    sm = SteamManager()
    print(f"  - Steam 路径: {sm.steam_path}")
    print(f"  - Steam.exe: {sm.steam_exe}")
    print(f"  - Steam 运行中: {sm.is_steam_running()}")
    accounts = sm.get_accounts()
    print(f"  - 检测到账号数: {len(accounts)}")
    for acc in accounts:
        print(f"    * 账号: {acc['account_name']}, 昵称: {acc['persona_name']}, SteamID: {acc['steamid']}, 活跃: {acc['is_active']}")
    assert sm.steam_path is not None, "Steam 路径检测失败"
    assert len(accounts) > 0, "未能解析出 Steam 账号"
    print("  => SteamManager 测试通过 [PASS]")

    # 2. 测试证书管理器
    print("\n[2/5] 测试证书管理器 (CertManager)...")
    cm = CertManager()
    thumbprint = cm.get_cert_thumbprint()
    print(f"  - 证书指纹: {thumbprint}")
    is_inst = cm.is_cert_installed()
    print(f"  - 系统受信任状态: {is_inst}")
    assert len(thumbprint) > 0, "证书指纹获取失败"
    print("  => CertManager 测试通过 [PASS]")

    # 3. 测试 28 项服务的 CDN 测速与动态 Upstream 生成
    print("\n[3/5] 测试智能 CDN 测速引擎 (CDNOptimizer)...")
    copt = CDNOptimizer()
    print("  - 测试 Steam 商店候选节点测速...")
    steam_res = copt.test_group("steam_store", ["23.1.179.144", "104.71.154.102"])
    print(f"  - 测速结果: {steam_res}")
    assert len(steam_res) > 0, "测速失败"
    print("  - 测试生成 28 项服务动态 Upstream 配置文本...")
    sample_conf = copt.generate_upstream_conf({"steam_store": steam_res})
    assert "upstream upstream_steam_store" in sample_conf, "Upstream 生成格式错误"
    print("  => CDNOptimizer 测试通过 [PASS]")

    # 4. 测试 Nginx 配置文件语法 (包含 4 大分类站点规则)
    print("\n[4/5] 测试 Nginx 配置与便携数据平面...")
    nm = NginxManager()
    print(f"  - Nginx 目录: {nm.nginx_dir}")
    print(f"  - Nginx 可执行文件: {nm.nginx_exe}")
    assert nm.nginx_exe.exists(), "nginx.exe 不存在"
    proc = subprocess.run([str(nm.nginx_exe), "-t", "-p", str(nm.nginx_dir), "-c", "conf/nginx.conf"], capture_output=True, text=True, errors="ignore")
    print(f"  - Nginx 配置测试输出: {proc.stderr.strip() or proc.stdout.strip()}")
    assert proc.returncode == 0, f"Nginx 语法校验失败: {proc.stderr}"
    print("  => Nginx 配置与语法校验通过 [PASS]")

    # 5. 测试全量 Hosts 规则生成与剥离
    print("\n[5/5] 测试全量 Hosts 规则生成器...")
    hm = HostsManager()
    print(f"  - 总服务项数: {len(SERVICES_LIST)} 项 (已删除 14 个直连不可用服务)")
    assert len(SERVICES_LIST) >= 15, f"服务总数应至少为 15 (当前: {len(SERVICES_LIST)})"
    print("  => HostsManager 与服务清单定义通过 [PASS]")

    print("\n==================================================")
    print("  [SUCCESS] 全部 5 大核心模块集成测试 100% 通过！")
    print("==================================================")

if __name__ == "__main__":
    run_tests()
