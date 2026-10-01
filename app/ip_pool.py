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

# 默认开启全部已实测直连可用的服务 (需代理的 fandom/wikipedia/google_translate 已移除;
# yandere 区域 301 循环已知不可用已移除)
EXPERIMENTAL_OR_PROXY_SERVICES = set()

# 需要本机 DNS 后端 (NRPT / 手动指定 DNS) 才能生效的服务不纳入默认启用:
# QUIC 直连类的解析结果必须由本机 DNS 下发 (Hosts 无法传递 HTTPS RR), 在默认的 Hosts 模式下
# 启用它们只会得到"有延迟但不可用"的假象 —— 宁可默认关闭, 由用户显式开启并被告知前置条件。
DEFAULT_ENABLED_SERVICES = [
    p.id for p in PROFILES
    if p.id not in EXPERIMENTAL_OR_PROXY_SERVICES and not getattr(p, "requires_dns_backend", False)
]


