# -*- coding: utf-8 -*-
"""
PixivToolkit - 系统网络环境与代理冲突检测器 (Env & Proxy Conflict Detector)

核心原则:
- 不修改系统代理设置
- 不修改/不干扰第三方代理软件 (Clash / sing-box / v2rayN 等)
- 仅提供精准诊断与透明状态提示，保障多代理环境和平共存
"""

import sys
import socket
import winreg
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from win_utils import is_port_in_use
from service_profile import PROFILES

# 常见第三方代理客户端默认监听端口映射
KNOWN_PROXY_PORTS = {
    7890: "Clash / Mihomo (HTTP 代理)",
    7891: "Clash / Mihomo (SOCKS5 代理)",
    7897: "Clash Verge / Mihomo (Mixed 混合代理)",
    10808: "v2rayN / Xray (SOCKS5 代理)",
    10809: "v2rayN / Xray (HTTP 代理)",
    2080: "Steam++ / Watt Toolkit (本地代理)",
    1080: "Shadowsocks (SOCKS5 代理)",
    8080: "常规本地 HTTP 代理",
    9090: "Clash 外部控制端口",
}


class EnvDetector:
    """系统网络与代理冲突探测引擎"""

    @staticmethod
    def get_system_proxy() -> Dict[str, Any]:
        """读取 Windows 注册表 Internet Settings 获取系统代理配置"""
        result = {
            "enabled": False,
            "server": "",
            "pac_url": "",
            "override": "",
            "raw_status": "未开启系统代理"
        }
        try:
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ) as key:
                try:
                    proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                    result["enabled"] = bool(proxy_enable)
                except FileNotFoundError:
                    result["enabled"] = False

                try:
                    proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    result["server"] = str(proxy_server)
                except FileNotFoundError:
                    result["server"] = ""

                try:
                    auto_config_url, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                    result["pac_url"] = str(auto_config_url)
                except FileNotFoundError:
                    result["pac_url"] = ""

                try:
                    proxy_override, _ = winreg.QueryValueEx(key, "ProxyOverride")
                    result["override"] = str(proxy_override)
                except FileNotFoundError:
                    result["override"] = ""

            if result["enabled"] and result["server"]:
                result["raw_status"] = f"系统代理已开启 ({result['server']})"
            elif result["pac_url"]:
                result["raw_status"] = f"PAC 自动配置已开启 ({result['pac_url']})"
            else:
                result["raw_status"] = "系统代理未开启 (直连模式)"
        except Exception as e:
            result["raw_status"] = f"读取代理状态异常: {e}"

        return result

    @staticmethod
    def scan_active_proxy_ports() -> List[Dict[str, Any]]:
        """扫描本地常见第三方代理端口活动状态"""
        active_ports = []
        for port, desc in KNOWN_PROXY_PORTS.items():
            if is_port_in_use(port):
                active_ports.append({
                    "port": port,
                    "desc": desc,
                    "status": "活跃/正在监听"
                })
        return active_ports

    @staticmethod
    def check_hosts_conflicts(hosts_content: str) -> List[Dict[str, str]]:
        """检测 Hosts 文件中是否存在非 PixivToolkit 写入但可能冲突的域名规则"""
        conflicts = []
        all_managed_domains = set()
        for p in PROFILES:
            for d in p.domains:
                all_managed_domains.add(d.lower())

        lines = hosts_content.splitlines()
        in_ptk_block = False

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                if ">>>>> PixivToolkit Rules Start" in stripped:
                    in_ptk_block = True
                elif "<<<<< PixivToolkit Rules End" in stripped:
                    in_ptk_block = False
                continue

            if in_ptk_block:
                continue

            # 分析行内 IP 与域名映射 (如 127.0.0.1 pixiv.net 或 0.0.0.0 steamcommunity.com)
            parts = stripped.split()
            if len(parts) >= 2:
                ip = parts[0]
                domains = [d.lower() for d in parts[1:]]
                for d in domains:
                    if d in all_managed_domains:
                        conflicts.append({
                            "ip": ip,
                            "domain": d,
                            "raw_line": stripped
                        })

        return conflicts

    @classmethod
    def get_full_diagnostics(cls, hosts_content: str = "") -> Dict[str, Any]:
        """综合环境诊断汇总"""
        sys_proxy = cls.get_system_proxy()
        active_ports = cls.scan_active_proxy_ports()
        hosts_conflicts = cls.check_hosts_conflicts(hosts_content) if hosts_content else []

        warnings = []
        suggestions = []

        if sys_proxy["enabled"]:
            warnings.append(f"检测到系统代理已激活: {sys_proxy['server']}")
            suggestions.append("PixivToolkit 仅接管指定加速域名，若与您的代理规则冲突，可在代理客户端中为 Pixiv/Steam 设置直连(Direct)。")

        if active_ports:
            port_desc_list = [f"{p['port']} ({p['desc']})" for p in active_ports]
            warnings.append(f"检测到本地运行的代理进程: {', '.join(port_desc_list)}")

        if hosts_conflicts:
            warnings.append(f"检测到 Hosts 中存在 {len(hosts_conflicts)} 条外部冲突条目")
            suggestions.append("建议在 PixivToolkit 中一键覆盖注入，或清理第三方工具遗留的旧规则。")

        return {
            "system_proxy": sys_proxy,
            "active_proxy_ports": active_ports,
            "hosts_conflicts": hosts_conflicts,
            "has_warnings": len(warnings) > 0,
            "warnings": warnings,
            "suggestions": suggestions,
            "summary_text": "环境健康，可与现有代理共存" if not warnings else f"共存环境感知: {warnings[0]}"
        }
