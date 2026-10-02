# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 配置持久化存储模块 (原子安全写入与备份)
"""

import os
import json
import shutil
import threading
from path_utils import BASE_DIR
from ip_pool import DEFAULT_ENABLED_SERVICES, SERVICES_BY_ID

CONFIG_FILE = BASE_DIR / "config.json"
CONFIG_BAK = BASE_DIR / "config.json.bak"
_CONFIG_LOCK = threading.RLock()

DEFAULT_CONFIG = {
    # 界面与交互外观
    "theme": "dark",
    "theme_mode": "dark",  # "system" | "dark" | "light"
    "tray_notifications": True,

    # 运行生命周期与托盘行为
    "auto_proxy": True,
    "auto_start": False,
    "start_minimized": False,
    "close_action": "minimize_to_tray",  # "minimize_to_tray" | "quit_directly"

    # Hosts 规则与自动恢复
    "auto_clean_hosts_on_exit": True,
    "auto_heal_on_startup": True,

    # 服务与路由规则 (默认开启预设服务)
    "enabled_services": list(DEFAULT_ENABLED_SERVICES),
    "steam_account_aliases": {},
    "custom_steam_path": "",
    "steam_launch_args": ["-tcp"],
    "steam_custom_args_str": "",
    "collapsed_dashboard_sections": [],

    # CDN 测速与自愈参数
    "auto_cdn_optimize": True,
    "auto_cdn_optimize_on_startup": True,
    "auto_cdn_min_interval_minutes": 30,
    "auto_cdn_only_enabled": True,
    "auto_cdn_wait_network_ready": True,
    "auto_cdn_network_stable_delay_seconds": 60,
    "auto_proxy_after_cdn": True,
    "network_probe_target": "www.baidu.com",
    "ip_version_mode": "prefer_ipv4",  # "prefer_ipv4" | "prefer_ipv6" | "dual_stack" | "ipv4_only"
    "cdn_timeout_seconds": 1.5,
    "cdn_max_workers": 16,
    "health_check_interval_seconds": 30,
    "last_optimal_time": 0,

    # 本地 DNS 与网络缓存维护
    "dns_mode_enabled": True,
    "dns_listen_port": 5353,
    "upstream_dns_servers": ["223.5.5.5", "119.29.29.29"],

    # 加速域名解析劫持后端: "pac_auto" (默认) | "pac" | "hosts" | "nrpt"
    #
    # ★ 默认为何是 pac_auto 而不是 hosts (2026-10-02 按用户决策变更):
    #   通配域名 (如 *.clients6.google.com、动态节点名 rr1---sn-xxx.googlevideo.com)
    #   **只有具备通配能力的后端才劫持得到**, 而 Hosts 不支持通配 —— 在 Hosts 下
    #   googlevideo 会被硬拦、gemini 的会话端点会静默漏走 (实测"页面能开、对话不通")。
    #   pac_auto 免管理员、通配是一等公民、运行中的浏览器即刻采纳, 且只改**一个**
    #   注册表值 (AutoConfigURL), 备份还原面最小。
    #   NRPT 仍保留但**不再推荐**: 它要管理员 + 独占本机 53/UDP, 改的是整机 DNS,
    #   残留危害最大 (数百域名被指向没人监听的 127.0.0.1:53), 且实测其 cmdlet 会在
    #   某些环境下抛 EndProcessing NullReferenceException (源码环境复现不出)。
    "redirect_mode": "pac_auto",
    "nrpt_auto_fallback": True,

    # QUIC(HTTP/3) 直连服务的优选 IP 顺序 (由 quic_probe 用真实 QUIC 握手测速生成)
    "quic_optimal_ips": {},

    # Google/YouTube 掩护 SNI 通道 (方案 §5.1 / §6.4 / §8)
    # auto_regress: 启动加速前自动回归"掩护 SNI 是否仍然有效", 失效时按候选池自动降级
    #               (g.cn → 其它 Google 自有域 → 真实域名 → 空 SNI)。关掉则一律用画像里
    #               写死的 ssl_sni_mode, 不降级 —— 便于排障时排除"自动切换"这个变量。
    "cover_sni_auto_regress": True,
    # allow_empty: 是否允许降级链的最后一级"空 SNI"。该级证书必为占位证书
    #              (invalid2.invalid), 上游证书完全无法校验; 关掉它则宁可在 UI 显式报
    #              "不可用", 也不静默降到一条没有任何证书保障的通路上。
    "cover_sni_allow_empty": True,

    "cache_max_size_mb": 1024,
    "auto_clear_cache_on_exit": False,

    # 测速探测专用本地代理 (Clash/v2ray/Sing-box mixed 端口, 仅作真实节点筛选, 不参与 nginx 转发)
    "upstream_proxy": {"enabled": False, "host": "127.0.0.1", "port": 7897},
    "cached_latencies": {},
    "cached_cdn_full_results": {}
}

# 旧版粗粒度服务 ID 到细粒度 ID 的映射转换字典 (自动兼容历史配置)
# 注: ea_app / danbooru 已从服务列表移除 (明确封锁), 不再出现在映射中
_LEGACY_SERVICE_MAPPING = {
    "pixiv": ["pixiv_web", "pixiv_img", "pixiv_fanbox", "booth_pm", "vndb"],
    "steam": ["steam_store", "steam_community", "steam_akamai", "ubisoft"],
    "github": ["github_web", "github_raw", "github_release", "github_assets", "github_s3", "gitlab"],
    "huggingface": ["huggingface"],
    # nuget 于 2026-09 拆为三个独立后端 (api/www/包 CDN 的 IP 互不通用, 合池必然错配)
    "nuget": ["nuget_api", "nuget_www", "nuget_cdn"],
}

# 一次性迁移表: "本次升级新增且默认启用"的服务, 用于还没有 known_service_ids 快照的老配置。
# 之后新增服务由快照机制自动接纳 (见 _sanitize_config 的 2.1), 无需再往这里加。
_AUTO_ENABLE_MIGRATIONS = (
    "discord_gateway",   # 2026-10-01: Discord WebSocket 网关独立画像 (需 upgrade 头)
)


def _sanitize_config(data: dict) -> dict:
    """清洗配置项，自动迁移旧版粗粒度服务 ID 并移除废弃字段"""
    # 1. 移除废弃的 Web 控制台端口字段
    if "server_port" in data:
        data.pop("server_port", None)

    # 2. 迁移或清洗 enabled_services (严格保留用户显式开关状态)
    curr_services = data.get("enabled_services")
    if isinstance(curr_services, list):
        new_services = set()
        for sid in curr_services:
            if sid in SERVICES_BY_ID:
                new_services.add(sid)
            elif sid in _LEGACY_SERVICE_MAPPING:
                for target_id in _LEGACY_SERVICE_MAPPING[sid]:
                    if target_id in SERVICES_BY_ID:
                        new_services.add(target_id)
        # 2.1 新增服务的自动接纳 (升级迁移)
        # 为什么必须做: 老配置里 `enabled_services` 是一份**显式清单**, 版本升级新增的
        # 默认启用服务不会被它接纳 —— 实测事故: 新增的 discord_gateway (WebSocket 网关)
        # 未进入清单, 于是 gateway.discord.gg 没被劫持、走污染解析, 客户端 WS 一直失败,
        # 而其它 discord 域正常 (因为它们早就在清单里)。
        # 判定依据: 与 known_service_ids (上次写配置时存在的全部服务 id) 求差 —— 只有
        # "本次升级新出现" 的服务才会被自动加入, 因此**用户手动关闭的服务不会被重新打开**。
        known = data.get("known_service_ids")
        current_ids = set(SERVICES_BY_ID)
        if isinstance(known, list):
            new_ids = current_ids - set(known)
            for sid in DEFAULT_ENABLED_SERVICES:
                if sid in new_ids:
                    new_services.add(sid)
        else:
            # 首次引入 known_service_ids 快照时没有"上一版服务清单"可比对, 只能靠一次性
            # 迁移表: 把"本次升级新增且默认启用"的服务补进老配置。
            # 实测事故: discord_gateway (WebSocket 网关) 未进老配置的显式清单 →
            # gateway.discord.gg 没被劫持 → 客户端 WS 无限失败, 而其它 discord 域正常。
            for sid in _AUTO_ENABLE_MIGRATIONS:
                if sid in SERVICES_BY_ID:
                    new_services.add(sid)
        data["known_service_ids"] = sorted(current_ids)
        data["enabled_services"] = sorted(list(new_services))
    elif curr_services is None:
        data["enabled_services"] = list(DEFAULT_ENABLED_SERVICES)
        data["known_service_ids"] = sorted(SERVICES_BY_ID)

    # 2. 归一化重定向后端取值
    #    ⚠ 这里刻意区分**"键缺失"与"值非法"** (2026-10-02):
    #      · 键缺失 = 用户还没表达过偏好 ⇒ 用当前默认 pac_auto;
    #      · 值非法 = 配置被手改坏了 ⇒ 回落 hosts。
    #        为什么不跟着用 pac_auto: pac_auto 会**写系统的自动配置脚本**(注册表),
    #        拿一个坏配置去触发注册表写入是过激的副作用; hosts 只是"不生效", 安全得多。
    #        配置坏掉时应当"少做", 而不是"换一种方式做"。
    #    pac_auto: 把 PAC 写进 Windows「自动配置脚本」(不拉起浏览器, 实测运行中的
    #              浏览器会当场采用; 退出时自动还原用户原有代理设置)
    #    pac: PAC + 本地 CONNECT 转发, 把通配表达在 PAC 的 JS 里
    #         —— 免管理员、不写注册表、不占 53、不动系统 DNS (见 app/pac_redirect.py)
    _raw = data.get("redirect_mode", DEFAULT_CONFIG["redirect_mode"])
    mode = str(_raw if _raw else DEFAULT_CONFIG["redirect_mode"]).strip().lower()
    data["redirect_mode"] = mode if mode in ("hosts", "nrpt", "pac", "pac_auto") else "hosts"

    return data

def load_config() -> dict:
    with _CONFIG_LOCK:
        for target_path in [CONFIG_FILE, CONFIG_BAK]:
            if target_path.exists():
                try:
                    with open(target_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, dict):
                            for k, v in DEFAULT_CONFIG.items():
                                if k not in data:
                                    data[k] = v
                                elif isinstance(v, dict) and isinstance(data[k], dict):
                                    # 深度合并：补全缺失的子字段
                                    for sub_k, sub_v in v.items():
                                        if sub_k not in data[k]:
                                            data[k][sub_k] = sub_v
                            data = _sanitize_config(data)
                            return data
                except Exception as e:
                    print(f"[Config] 加载 {target_path.name} 异常: {e}")
                    continue

        # 若均不存在或已损毁，初始化默认配置
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

def save_config(config: dict):
    with _CONFIG_LOCK:
        tmp_file = CONFIG_FILE.with_suffix(".tmp")
        try:
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            # 1. 写入临时文件并强制刷盘
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())

            # 2. 维护备份文件
            if CONFIG_FILE.exists():
                try:
                    shutil.copyfile(CONFIG_FILE, CONFIG_BAK)
                except Exception:
                    pass

            # 3. 原子替换 (Windows 下原子重命名)
            os.replace(tmp_file, CONFIG_FILE)
        except Exception as e:
            if tmp_file.exists():
                try:
                    tmp_file.unlink(missing_ok=True)
                except Exception:
                    pass
            print(f"[Config] 保存配置文件失败: {e}")

def update_config_key(key: str, value):
    with _CONFIG_LOCK:
        config = load_config()
        config[key] = value
        save_config(config)
