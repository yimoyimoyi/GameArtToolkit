# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 加速服务元数据、域名映射与 CDN 候选池 (对接 Service Profile 架构)

向后兼容导出:
- SERVICE_GROUPS: 服务分组字典
- SERVICES_LIST: 核心服务列表 (全部为已实测直连可用服务)
- SERVICES_BY_ID: 服务字典索引
- CANDIDATE_IPS: 各服务优质候选 CDN IP 池
- DEFAULT_ENABLED_SERVICES: 默认开启的服务列表
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from service_profile import (
    SERVICE_GROUPS,
    PROFILES,
    PROFILES_BY_ID,
    ServiceProfile,
    ServiceMode,
    get_profile_by_id,
    get_profile_by_domain,
    TOTAL_SERVICES_COUNT
)

# 兼容现有数据结构的 SERVICES_LIST 字典列表
SERVICES_LIST = [
    {
        "id": p.id,
        "group": p.group,
        "name": p.name,
        "domains": p.domains,
        "desc": p.desc,
        "icon": getattr(p, "icon", "zap"),
        "mode": p.mode.value,
        "enable_cache": p.enable_cache
    }
    for p in PROFILES
]

# 按 ID 建立索引字典
SERVICES_BY_ID = {s["id"]: s for s in SERVICES_LIST}

# 各服务的优质 CDN Anycast IP 候选池
CANDIDATE_IPS = {p.id: p.candidate_ips for p in PROFILES}

# 不纳入默认启用的服务, 四条**互不相同**的理由 (2026-10-03 明确化, 原缺陷 M13):
#   ① QUIC 直连类 (requires_dns_backend): 解析结果必须由本机 DNS 下发 (Hosts 无法传递
#      HTTPS RR), 在默认的 Hosts 模式下启用它们只会得到"有延迟但不可用"的假象;
#   ② 实验/通道性服务 (experimental_default_off): 可用性分钟级时变, 启用前有前置闸门;
#   ③ 依赖通配的服务 (needs_wildcard_resolution): 域名全是 `*.`, Hosts 表达不了;
#   ④ 受控分组的服务 (分组的 gated=True): 默认隐藏且不可启用, 必须由用户显式放开。
# ★ 原先这三件事全压在 `requires_dns_backend` 一个字段上, 于是"它到底为什么被排除"
#   在代码里读不出来, 改一个语义会连带影响另外两件 —— 见 service_profile 的字段注释。
# 默认开启全部已实测直连可用的服务 (需代理的 fandom/wikipedia/google_translate 已移除;
# yandere 区域 301 循环已知不可用已移除)
EXPERIMENTAL_OR_PROXY_SERVICES = set()

# ── 受控分组 (gated) ──────────────────────────────────────────────────────────
# 语义: 分组带 `gated: True` 时, **默认既不在控制台显示, 也不允许其中任何服务被启用**;
# 只有用户在设置页显式打开该组的开关 (config.json → "gated_groups_enabled") 才放开。
#
# 为什么在 ip_pool 这一层做 (而不是只做成界面置灰):
#   "能否启用"的最终后果是 hosts/DNS 真的把域名劫持到本地 —— 只看界面等于把闸门建在
#   一个可以被配置文件绕过的地方 (用户手改 config.json、老配置里本就带着这些 id 都能绕过)。
#   所以判定必须落在**配置加载**这一层: see config_store._sanitize_config 的 2.2 与
#   DEFAULT_ENABLED_SERVICES (默认清单直接不含受控分组服务)。
GATED_GROUPS = {
    gid: dict(info) for gid, info in SERVICE_GROUPS.items() if info.get("gated")
}


def services_in_gated_groups() -> set:
    """受控分组下的全部服务 id (用于配置清洗与默认启用过滤, **不读用户配置**)"""
    if not GATED_GROUPS:
        return set()
    return {s["id"] for s in SERVICES_LIST if s.get("group") in GATED_GROUPS}


def gated_group_enabled(group_id: str) -> bool:
    """受控分组是否被用户显式放开 (非受控分组恒为 True)

    读不到配置时**保守返回 False**: 宁可"开了却没显示", 也不要"配置损坏时把成人分组
    亮出来并允许启用"。误判代价不对称, 与 ech_tunnel._domains_unchanged 同一取向。
    """
    if group_id not in GATED_GROUPS:
        return True
    try:
        from config_store import load_config
        cfg = load_config() or {}
    except Exception:
        return False
    enabled = cfg.get("gated_groups_enabled") or {}
    try:
        return bool(enabled.get(group_id, False))
    except Exception:
        return False


def is_service_allowed(service_id: str) -> bool:
    """该服务此刻是否允许被启用 (受控分组未放开时为 False)

    单一真源: 界面开关、批量启用、启动清单都调它, 避免"三处各判各的"。
    """
    srv = SERVICES_BY_ID.get(service_id)
    if not srv:
        return False
    return gated_group_enabled(srv.get("group", ""))


# 默认开启 = 已实测可用 且 非受控分组 (受控分组必须由用户显式放开, 见上)
DEFAULT_ENABLED_SERVICES = [
    p.id for p in PROFILES
    if p.id not in EXPERIMENTAL_OR_PROXY_SERVICES
    and not getattr(p, "requires_dns_backend", False)
    and not getattr(p, "experimental_default_off", False)
    and p.group not in GATED_GROUPS
]


