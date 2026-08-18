# -*- coding: utf-8 -*-
"""
PixivToolkit - Nginx 站点配置声明式模板生成器 (Nginx Configuration Generator)

核心功能:
- 基于 ServiceProfile 单源注册表，自动生成 site-gaming.conf / site-acg.conf / site-dev.conf
- 彻底消除手写 Nginx 配置文件的重复维护风险，实现代码与配置 100% 自动同步
- 精准映射 WebSocket、Range 206、图片磁盘缓存、Steam 302 重定向与伪装 SNI
"""

import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from path_utils import NGINX_DIR
from service_profile import (
    PROFILES,
    PROFILES_BY_ID,
    ServiceProfile,
    ServiceMode,
    SERVICE_GROUPS
)

CONF_DIR = NGINX_DIR / "conf"


class NginxConfGenerator:
    """Nginx 站点配置文件生成引擎"""

    @classmethod
    def render_server_block(cls, profile: ServiceProfile) -> str:
        """为单个 ServiceProfile 渲染标准 Nginx Server 块"""
        domains_list = list(profile.domains)

        # 自动补全常见的通配子域并保序去重
        if profile.id == "steam_store" and "*.steampowered.com" not in domains_list:
            domains_list.append("*.steampowered.com")
        elif profile.id == "steam_community" and "*.steamcommunity.com" not in domains_list:
            domains_list.append("*.steamcommunity.com")
        elif profile.id == "steam_akamai" and "*.steamstatic.com" not in domains_list:
            domains_list.append("*.steamstatic.com")
        elif profile.id == "booth_pm" and "*.booth.pm" not in domains_list:
            domains_list.append("*.booth.pm")
        elif profile.id == "pixiv_fanbox" and "*.fanbox.cc" not in domains_list:
            domains_list.append("*.fanbox.cc")
        elif profile.id == "gitlab" and "*.gitlab.com" not in domains_list:
            domains_list.extend(["*.gitlab.com", "*.gitlab-static.net"])
        elif profile.id == "yandere" and "*.yande.re" not in domains_list:
            domains_list.append("*.yande.re")
        elif profile.id == "fandom" and "*.fandom.com" not in domains_list:
            domains_list.extend(["*.fandom.com", "*.wikia.com", "*.nocookie.net"])
        elif profile.id == "wikipedia" and "*.wikipedia.org" not in domains_list:
            domains_list.extend(["*.wikipedia.org", "*.wikimedia.org", "*.wikidata.org"])

        # 保序去重
        domains_list = list(dict.fromkeys(domains_list))
        domains_str = " ".join(domains_list)

        # SNI 与 Host 头部策略
        if profile.ssl_sni_mode == "empty":
            sni_str = '""'
        elif profile.ssl_sni_mode == "host":
            sni_str = "$host"
        else:
            sni_str = f'"{profile.ssl_sni_mode}"'

        host_header = profile.custom_headers.get("Host", "$host")

        # ----------------------------------------------------------------------
        # 1. Pixiv 主站特殊处理 (包含 /ajax/ CORS 与 /ws/ WebSocket)
        # ----------------------------------------------------------------------
        if profile.id == "pixiv_web":
            return cls._render_pixiv_web_server(profile)

        # ----------------------------------------------------------------------
        # 2. Pixiv 图片 CDN 特殊处理 (包含 pximg 缓存与 Sketch 直播流)
        # ----------------------------------------------------------------------
        if profile.id == "pixiv_img":
            return cls._render_pixiv_img_server(profile)

        # ----------------------------------------------------------------------
        # 3. 标准通用 Server 块渲染
        # ----------------------------------------------------------------------
        lines = [
            f"# {profile.name}",
            "server {",
            "    listen 80;",
            "    listen 443 ssl;",
            "    http2 on;",
            f"    server_name {domains_str};",
            ""
        ]

        if profile.group == "dev":
            lines.append("    client_max_body_size 0;  # 支持任意体积大文件与 Git packfile")
        elif profile.id in ("pixiv_fanbox", "booth_pm"):
            lines.append("    client_max_body_size 50M;")

        lines.extend([
            "    location / {",
            f"        proxy_pass https://{profile.upstream_name};",
            "        proxy_http_version 1.1;",
            "        proxy_set_header Upgrade $http_upgrade;",
            "        proxy_set_header Connection $connection_upgrade;",
            f"        proxy_set_header Host {host_header};",
            "        proxy_set_header X-Real-IP $remote_addr;",
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "        proxy_set_header X-Forwarded-Proto https;",
            f"        proxy_ssl_name {sni_str};",
            "        proxy_ssl_server_name on;",
            "        proxy_ssl_verify off;",
            "        proxy_ssl_session_reuse on;",
        ])

        # Steam 社区与图库/百科重定向防死循环自适应
        if profile.id in ("steam_community", "yandere", "fandom", "wikipedia"):
            if profile.id == "steam_community":
                lines.insert(len(lines) - 4, '        proxy_set_header User-Agent "${http_user_agent} Googlebot/2.1 (+http://www.google.com/bot.html)";')
            lines.extend([
                "        proxy_redirect default;",
                "        proxy_redirect http:// https://;",
            ])
            if profile.group != "dev":
                lines.append("        proxy_force_ranges on;")

        # 针对开发生态 (Git/GitHub/GitLab/大文件) 开启全链路流式零缓冲、Range 穿透与超长超时
        if profile.group == "dev":
            lines.extend([
                "        # 大文件与 Git Smart HTTP 极速流式透传配置 (彻底消灭磁盘 I/O 缓冲假死)",
                "        proxy_buffering off;",
                "        proxy_request_buffering off;",
                "        proxy_max_temp_file_size 0;",
                "        proxy_force_ranges on;",
                "        proxy_set_header Range $http_range;",
                "        proxy_set_header If-Range $http_if_range;",
                "        proxy_read_timeout 3600s;",
                "        proxy_send_timeout 3600s;",
                "        proxy_connect_timeout 15s;",
            ])
        else:
            lines.extend([
                "        proxy_read_timeout 60s;",
                "        proxy_send_timeout 60s;",
            ])

        lines.extend([
            "        proxy_next_upstream error timeout http_403 http_429 http_500 http_502 http_503 http_504 non_idempotent;",
            "    }",
            "}\n"
        ])
        return "\n".join(lines)

    @classmethod
    def _render_pixiv_web_server(cls, profile: ServiceProfile) -> str:
        """渲染 Pixiv 主站专用规则 (包含 /ajax/ CORS 与 /ws/ WebSocket)"""
        main_domains = [d for d in profile.domains if d != "lc-event.pixiv.net"]
        domains_str = " ".join(main_domains)
        return f"""# {profile.name} (采用空 SNI 策略，绕过 GFW SNI 阻断)
server {{
    listen 80;
    listen 443 ssl;
    http2 on;
    server_name {domains_str};

    client_max_body_size 50M;

    location / {{
        proxy_pass https://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_max_temp_file_size 0;
        proxy_buffering off;
        proxy_ssl_name "";
        proxy_ssl_server_name on;
        proxy_ssl_verify off;
        proxy_ssl_session_reuse on;
        proxy_next_upstream error timeout http_429 http_404 http_500 http_502 http_503 http_504 non_idempotent;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }}

    location /ajax/ {{
        proxy_pass https://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_max_temp_file_size 0;
        proxy_buffering off;
        proxy_ssl_name "";
        proxy_ssl_server_name on;
        proxy_ssl_verify off;
        proxy_ssl_session_reuse on;
        proxy_hide_header Access-Control-Allow-Origin;
        add_header Access-Control-Allow-Origin $http_origin always;
        proxy_next_upstream error timeout http_429 http_404 http_500 http_502 http_503 http_504 non_idempotent;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }}

    location /ws/ {{
        proxy_pass https://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Connection "upgrade";
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_max_temp_file_size 0;
        proxy_buffering off;
        proxy_ssl_name "";
        proxy_ssl_server_name on;
        proxy_ssl_verify off;
        proxy_ssl_session_reuse on;
        proxy_hide_header Access-Control-Allow-Origin;
        add_header Access-Control-Allow-Origin $http_origin always;
        proxy_read_timeout 7200s;
        proxy_send_timeout 7200s;
    }}
}}

# Pixiv lc-event 专属流
server {{
    listen 80;
    listen 443 ssl;
    http2 on;
    server_name lc-event.pixiv.net;

    location / {{
        proxy_pass https://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_max_temp_file_size 0;
        proxy_buffering off;
        proxy_ssl_name "";
        proxy_ssl_server_name on;
        proxy_ssl_verify off;
        proxy_ssl_session_reuse on;
        proxy_next_upstream error timeout http_429 http_404 http_500 http_502 http_503 http_504 non_idempotent;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }}
}}
"""

    @classmethod
    def _render_pixiv_img_server(cls, profile: ServiceProfile) -> str:
        """渲染 Pixiv pximg 插画 CDN 专用规则 (带磁盘缓存与 Range 续传)"""
        domains_str = " ".join(profile.domains)
        return f"""# {profile.name} (带本地图片磁盘缓存与 Range 断点续传)
server {{
    listen 80;
    listen 443 ssl;
    http2 on;
    server_name *.pximg.net s.pximg.net i.pximg.net imgaz.pixiv.net;

    location / {{
        proxy_pass https://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_set_header Referer "https://www.pixiv.net/";
        proxy_set_header Sec-Fetch-Site "cross-site";
        proxy_ssl_name "";
        proxy_ssl_server_name on;
        proxy_ssl_verify off;
        proxy_ssl_session_reuse on;

        proxy_cache pixiv_img_cache;
        proxy_cache_valid 200 304 30d;
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
        proxy_force_ranges on;
        add_header X-Cache-Status $upstream_cache_status;
        proxy_next_upstream_timeout 60;
        proxy_next_upstream error timeout http_429 http_404 http_500 http_502 http_503 http_504 non_idempotent;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }}
}}

# Pixiv Sketch 绘图直播流 CDN
server {{
    listen 80;
    listen 443 ssl;
    http2 on;
    server_name *.pixivsketch.net;

    location / {{
        proxy_pass https://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_ssl_name "";
        proxy_ssl_server_name on;
        proxy_ssl_verify off;
        proxy_ssl_session_reuse on;
        proxy_next_upstream error timeout http_429 http_500 http_502 http_503 http_504;
    }}
}}
"""

    @classmethod
    def generate_all(cls, target_dir: Path = CONF_DIR) -> Dict[str, str]:
        """全量渲染并原子写入三大站点配置文件"""
        target_dir.mkdir(parents=True, exist_ok=True)
        results = {}

        # 1. 渲染 site-gaming.conf
        gaming_profiles = [p for p in PROFILES if p.group == "gaming"]
        gaming_blocks = [
            "# ==============================================================================",
            "# PixivToolkit - 游戏生态全平台加速规则 (由 ServiceProfile 模板自动生成)",
            "# ==============================================================================\n"
        ]
        for p in gaming_profiles:
            gaming_blocks.append(cls.render_server_block(p))
        gaming_content = "\n".join(gaming_blocks)
        (target_dir / "site-gaming.conf").write_text(gaming_content, encoding="utf-8")
        results["site-gaming.conf"] = gaming_content

        # 2. 渲染 site-acg.conf
        acg_profiles = [p for p in PROFILES if p.group == "acg"]
        acg_blocks = [
            "# ==============================================================================",
            "# PixivToolkit - 二次元与创作者生态加速规则 (由 ServiceProfile 模板自动生成)",
            "# ==============================================================================\n"
        ]
        for p in acg_profiles:
            acg_blocks.append(cls.render_server_block(p))
        acg_content = "\n".join(acg_blocks)
        (target_dir / "site-acg.conf").write_text(acg_content, encoding="utf-8")
        results["site-acg.conf"] = acg_content

        # 3. 渲染 site-dev.conf
        dev_profiles = [p for p in PROFILES if p.group == "dev"]
        dev_blocks = [
            "# ==============================================================================",
            "# PixivToolkit - 开发者与 AI 平台加速规则 (由 ServiceProfile 模板自动生成)",
            "# ==============================================================================\n"
        ]
        for p in dev_profiles:
            dev_blocks.append(cls.render_server_block(p))
        dev_content = "\n".join(dev_blocks)
        (target_dir / "site-dev.conf").write_text(dev_content, encoding="utf-8")
        results["site-dev.conf"] = dev_content

        return results
