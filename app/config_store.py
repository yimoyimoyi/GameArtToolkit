# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 配置持久化存储模块 (原子安全写入与备份)
"""

import os
import json
import shutil
import threading
from path_utils import BASE_DIR
from ip_pool import DEFAULT_ENABLED_SERVICES, SERVICES_BY_ID, GATED_GROUPS

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
    # 受控分组总闸 (2026-10-03): 分组 id -> 是否放开。
    #   默认全部 False ⇒ 该分组在控制台**不显示**, 且其中任何服务**不可启用**。
    #   默认值由 GATED_GROUPS 动态生成 (而非写死 "adult"), 这样新增受控分组时
    #   配置默认值与代码不会漂移 —— 本项目已多次因"两处各写一份"翻车。
    #   真正生效的判定在 ip_pool.gated_group_enabled / _sanitize_config 的 2.2。
    "gated_groups_enabled": {gid: False for gid in GATED_GROUPS},
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

    # googlevideo 的**节点成绩单** (2026-10-03): 由 h3 上游腿按浏览器真实播放请求累加,
    # 键 = 节点名 (`rr1---sn-xxxx`), 值 = {ok, fail, classes, bytes, last_ok, last_fail, fb_ms}。
    # 为什么存这里而不是另开文件: 与 quic_optimal_ips / cached_cdn_full_results 同一模式
    # (运行时状态都在 config.json), 落盘有节流 (见 NODE_SCORE_FLUSH_SECONDS), 有界 (最多 60 节点)。
    "gvs_node_scores": {},

    # Google/YouTube 掩护 SNI 通道 (方案 §5.1 / §6.4 / §8)
    # auto_regress: 启动加速前自动回归"掩护 SNI 是否仍然有效", 失效时按候选池自动降级
    #               (g.cn → 其它 Google 自有域 → 真实域名 → 空 SNI)。关掉则一律用画像里
    #               写死的 ssl_sni_mode, 不降级 —— 便于排障时排除"自动切换"这个变量。
    "cover_sni_auto_regress": True,
    # allow_empty: 是否允许降级链的最后一级"空 SNI"。该级证书必为占位证书
    #              (invalid2.invalid), 上游证书完全无法校验; 关掉它则宁可在 UI 显式报
    #              "不可用", 也不静默降到一条没有任何证书保障的通路上。
    "cover_sni_allow_empty": True,

    # ⚠ `cache_max_size_mb` 已删除 (缺陷 D4, 2026-10-04): 它**没有任何读取方**
    #   (全仓库零引用), 于是"配置写 1GB、实际 nginx 长到 5GB" —— 而用户能看到的那份
    #   是错的那份。磁盘上限的唯一真源现在是 nginx/conf/nginx.conf 的
    #   `proxy_cache_path ... max_size`, 理由与改法都写在那里。
    #   教训: 一个没人读的配置项不是"预留", 它会变成一份**互相矛盾的文档** ——
    #   而这正是本项目根因一(注释/文档描述了一个不成立的前提)的又一种形态。
    "auto_clear_cache_on_exit": False,

    # 测速探测专用本地代理 (Clash/v2ray/Sing-box mixed 端口, 仅作真实节点筛选, 不参与 nginx 转发)
    "upstream_proxy": {"enabled": False, "host": "127.0.0.1", "port": 7897},
    "cached_latencies": {},
    "cached_cdn_full_results": {}
}

# 已退役的配置键: 加载时剔除, 避免它们永久留在用户配置里冒充有效设置。
# 只列**确认没有任何读取方**的键; 删除原因写在各键原先的位置 (见上方 cache_max_size_mb)。
RETIRED_CONFIG_KEYS = (
    "cache_max_size_mb",
)

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

    # 2.2 受控分组总闸 (2026-10-03): 分组未放开时, 其中的服务**不得留在启用清单里**。
    #
    # 为什么这是必须的一层 (而不是只在界面上置灰): 界面之外还有三条能把这些服务打开的路 ——
    #   ① 用户手改 config.json (或被别的工具改);
    #   ② 升级前就在清单里的历史 id (那时还没有总闸);
    #   ③ `known_service_ids` 的自动接纳 (升级迁移) —— 虽然它只接纳
    #      DEFAULT_ENABLED_SERVICES, 但默认清单本身也是会变的。
    # 本项目反复吃过"闸门建在能被绕过的地方"的亏, 所以判定落在**配置加载**这一层:
    # 任何来源的清单在这里被清洗一次, 之后 hosts/DNS/nginx 拿到的都不含受控服务。
    # 判定与 ip_pool 共用同一份真源 (GATED_GROUPS + 这份用户配置), 不另判一次。
    _enabled = data.get("enabled_services")
    if isinstance(_enabled, list) and GATED_GROUPS:
        _gate_on = data.get("gated_groups_enabled") or {}
        _dropped = sorted({
            sid for sid in _enabled
            if (SERVICES_BY_ID.get(sid, {}) or {}).get("group") in GATED_GROUPS
            and not bool((_gate_on or {}).get(
                (SERVICES_BY_ID.get(sid, {}) or {}).get("group"), False))
        })
        if _dropped:
            data["enabled_services"] = sorted(set(_enabled) - set(_dropped))
            # 留痕而不静默: 剔除了什么必须能被界面/日志说出来 (与 redirect_mode_invalid 同一取向)
            data["gated_services_dropped"] = _dropped
        else:
            data.pop("gated_services_dropped", None)

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
    _VALID_MODES = ("hosts", "nrpt", "pac", "pac_auto")
    if mode in _VALID_MODES:
        data["redirect_mode"] = mode
        data.pop("redirect_mode_invalid", None)
    else:
        # ★ L5 (2026-10-03): 静默回落 hosts 的理由成立 (见上方注释), 但**静默**本身有害 ——
        #   降级的后果不是"没反应", 而是**能力降级**: hosts 表达不了通配 ⇒
        #   googlevideo 被硬拦、Gemini 的 `*.clients6.google.com` 劫持不到,
        #   而界面上看不出任何异常 (用户只会觉得"某些站点没加速")。
        #   所以把原始非法值**留痕**, 由界面/日志告知 —— 判据可以保守, 但必须可见。
        data["redirect_mode"] = "hosts"
        data["redirect_mode_invalid"] = str(_raw)

    return data

def _drop_retired_keys(data: dict) -> dict:
    """剔除已退役的配置键 (缺陷 D4, 2026-10-04)

    为什么需要: `load_config` 只做"补默认值", 从不删键 ⇒ 用户配置里会**永久留着**
    一个已经没人读的键, 下次 save 还会把它写回去。它无害, 但会一直躺在用户文件里
    冒充一个有效设置 —— 而这正是 D4 的成因 (那份"1GB"的假文档就是这么来的)。

    只做**剔除**, 不做改名映射: 退役键的语义已被别处取代 (如 cache_max_size_mb 的
    真源移到 nginx.conf 的 max_size), 猜一个映射反而会造出新的错值。
    """
    for k in RETIRED_CONFIG_KEYS:
        data.pop(k, None)
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
                            data = _drop_retired_keys(data)
                            return data
                except Exception as e:
                    print(f"[Config] 加载 {target_path.name} 异常: {e}")
                    continue

        # 若均不存在或已损毁，初始化默认配置
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

def save_config(config: dict) -> bool:
    """落盘配置 (原子替换); **返回是否真的写成功**

    ★ 为什么必须有返回值 (2026-10-03 定因): 本函数原先失败只 print, 调用方无从判断。
    而 `redirect_manager._persist_proxy_backup` 依赖它来判断"用户原有代理设置的备份
    到底有没有落盘" —— 那是进程被强杀后**唯一**的还原依据。没有返回值时, 备份写失败
    仍会对外宣称"已自动备份并还原原有代理设置", 把"可恢复"建立在一次静默失败上。
    """
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
            return True
        except Exception as e:
            if tmp_file.exists():
                try:
                    tmp_file.unlink(missing_ok=True)
                except Exception:
                    pass
            print(f"[Config] 保存配置文件失败: {e}")
            return False

def update_config_key(key: str, value):
    with _CONFIG_LOCK:
        config = load_config()
        config[key] = value
        save_config(config)
