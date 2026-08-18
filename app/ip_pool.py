# -*- coding: utf-8 -*-
"""
PixivToolkit - 加速服务元数据、域名映射与 CDN 候选池 (对接 Service Profile 架构)

向后兼容导出:
- SERVICE_GROUPS: 服务分组字典
- SERVICES_LIST: 18 项服务列表
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
    get_profile_by_domain
)

# 兼容现有数据结构的 SERVICES_LIST 字典列表
SERVICES_LIST = [
    {
        "id": p.id,
        "group": p.group,
        "name": p.name,
        "domains": p.domains,
        "desc": p.desc,
        "mode": p.mode.value,
        "enable_cache": p.enable_cache
    }
    for p in PROFILES
]

# 按 ID 建立索引字典
SERVICES_BY_ID = {s["id"]: s for s in SERVICES_LIST}

# 各服务的优质 CDN Anycast IP 候选池
CANDIDATE_IPS = {p.id: p.candidate_ips for p in PROFILES}

# 默认全部开启已验证的优质服务 ID 集合
DEFAULT_ENABLED_SERVICES = [p.id for p in PROFILES]
