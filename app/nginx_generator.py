# -*- coding: utf-8 -*-
"""
GameArt Toolkit - Nginx 站点配置声明式模板生成器 (Nginx Configuration Generator)

核心功能:
- 基于 ServiceProfile 单源注册表，自动生成 site-gaming.conf / site-acg.conf / site-dev.conf
- 彻底消除手写 Nginx 配置文件的重复维护风险，实现代码与配置 100% 自动同步
- 精准映射 WebSocket、Range 206、图片磁盘缓存、Steam 302 重定向与伪装 SNI
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ech_tunnel import ech_tunnel
import h3_upstream
from path_utils import NGINX_DIR
from service_profile import (
    PROFILES,
    PROFILES_BY_ID,
    ServiceProfile,
    ServiceMode,
    SERVICE_GROUPS
)

CONF_DIR = NGINX_DIR / "conf"

# 上游故障切换策略 (与 cdn_optimizer 的 upstream 熔断参数配套)
#
# 为什么是"最多尝试 4 个节点": 上游池按可用性分层后可达 8 个节点, 若不限制尝试次数,
# 一次请求会在坏节点之间串行等待 (3s 连接超时 × 8 = 24s), 用户感知就是"卡死"。
# 限 4 次后最坏约 12s; 而坏节点会被 max_fails 迅速熔断, 后续请求直接命中健康节点。
UPSTREAM_NEXT_TRIES = 4

# 不经 Nginx 的模式: Direct (Hosts/DNS 直指真实 CDN IP) 与 QUIC 直连 (浏览器自行走
# HTTP/3) 都由解析层直接引导, 本地 Nginx 既不该也无法承载它们 —— 若仍渲染 server 块,
# 会生成空上游池并导致 nginx -t 直接报 "no host in upstream" 启动失败。
NGINX_BYPASS_MODES = (ServiceMode.DIRECT, ServiceMode.QUIC_DIRECT)


class NginxConfGenerator:
    """Nginx 站点配置文件生成引擎"""

    # ------------------------------------------------------------------
    # ECH 隧道上游判定
    # ------------------------------------------------------------------
    @classmethod
    def _ech_services_from_upstream(cls, upstream_conf: Path) -> Optional[Set[str]]:
        """从 upstream-dynamic.conf 解析实际走 ECH 隧道的服务 id 集合

        返回 None 表示文件不存在 (调用方回退到实时健康检查)。

        为什么以文件内容为准、而不是 profile.ech_enabled: 后者是静态标记, 而
        CDNOptimizer 是否真的写入隧道地址是动态的 (隧道健康才写)。两者不一致时,
        site 配置若仍按静态标记输出 http://, 就会把明文 HTTP 打到候选池的 :443
        (HTTPS 端口), 上游直接回 400 "The plain HTTP request was sent to HTTPS
        port" —— 已实测复现 (curl http://210.140.139.158:443/ -H "Host: www.pixiv.net")。

        必须匹配 ECH 的精确端口而非笼统的 127.0.0.1: relay 分支同样写回环地址
        (127.0.0.1:443xx), 但它承载的是 TLS, 需要 https:// —— 混为一谈会反向错配。
        """
        if not upstream_conf.exists():
            return None
        try:
            text = upstream_conf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

        marker = f"127.0.0.1:{ech_tunnel.port}"
        found: Set[str] = set()
        for m in re.finditer(r"upstream\s+(upstream_[a-z0-9_]+)\s*\{(.*?)\}", text, re.S):
            if marker in m.group(2):
                found.add(m.group(1)[len("upstream_"):])
        return found

    @classmethod
    def _h3_services_from_upstream(cls, upstream_conf: Path) -> Optional[Set[str]]:
        """从 upstream-dynamic.conf 解析"上游走本地 HTTP/3 腿"的服务 id 集合

        与 ECH 分支同源: 判据必须取自**文件实际内容**(CDNOptimizer 真写了回环地址),
        而不是 profile 的静态标记 —— 两者脱钩会产出"明文 HTTP 打向真实 :443",
        上游直接回 400 (该错配已实测复现, 见 _ech_services_from_upstream 注释)。

        同样必须匹配**精确端口**: relay 分支也写 127.0.0.1:443xx, 但它承载 TLS, 需 https://。
        """
        if not upstream_conf.exists():
            return None
        try:
            text = upstream_conf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None
        marker = f"127.0.0.1:{h3_upstream.PORT}"
        found: Set[str] = set()
        for m in re.finditer(r"upstream\s+(upstream_[a-z0-9_]+)\s*\{(.*?)\}", text, re.S):
            if marker in m.group(2):
                found.add(m.group(1)[len("upstream_"):])
        return found

    @classmethod
    def _use_ech(cls, profile: ServiceProfile, ech_services: Optional[Set[str]]) -> bool:
        """该服务本次是否走 ECH 隧道 (必须与 CDNOptimizer 写入的 upstream 一致)"""
        if not getattr(profile, "ech_enabled", False):
            return False
        if ech_services is None:
            # 无 upstream 快照可用 (首次生成/文件缺失): 以隧道实时健康为准,
            # 与 CDNOptimizer 的 ECH 分支判据保持一致
            return ech_tunnel.is_healthy()
        return profile.id in ech_services

    @classmethod
    def _use_h3(cls, profile: ServiceProfile, h3_services: Optional[Set[str]]) -> bool:
        """该服务本次是否走本地 HTTP/3 上游腿 (与 CDNOptimizer 写入的 upstream 保持一致)"""
        if not getattr(profile, "h3_upstream", False):
            return False
        if h3_services is None:
            # 无 upstream 快照 (首次生成/文件缺失): 以静态标记为准 ——
            # h3 腿是本地常驻进程, 没有 ECH 那种"隧道健康"外部状态需要复核
            return True
        return profile.id in h3_services

    @classmethod
    def render_server_block(cls, profile: ServiceProfile,
                           ech_services: Optional[Set[str]] = None,
                           h3_services: Optional[Set[str]] = None) -> str:
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
        elif profile.id == "github_assets" and "*.github.io" not in domains_list:
            domains_list.append("*.github.io")  # GitHub Pages 任意用户站点 (本地 DNS 后缀通配路由)
        elif profile.id == "gitlab" and "*.gitlab.com" not in domains_list:
            domains_list.extend(["*.gitlab.com", "*.gitlab-static.net"])
        elif profile.id == "dlsite" and "*.dlsite.com" not in domains_list:
            domains_list.append("*.dlsite.com")
        elif profile.id == "battle_net":
            for _wd in ("*.battle.net", "*.blizzard.com"):
                if _wd not in domains_list:
                    domains_list.append(_wd)
        elif profile.id == "patreon":
            for _wd in ("*.patreon.com", "*.patreonusercontent.com"):
                if _wd not in domains_list:
                    domains_list.append(_wd)
        # 注: googlevideo 曾在此补 `*.googlevideo.com` (动态节点名)。该服务已于 2026-10-01
        # 按"不通不加入"原则撤下登记 (签名 URL 绑定出口 IP, 本设计无法播放), 见
        # service_profile 里的长注释与 docs/googlevideo-quic-channel.md。

        # 保序去重
        domains_list = list(dict.fromkeys(domains_list))
        domains_str = " ".join(domains_list)

        # SNI 与 Host 头部策略
        #
        # 掩护 SNI 不是常量 (方案 §5.1 / §6.4): 这里不再直接读 profile.ssl_sni_mode,
        # 而是问 cover_sni 模块"当前该用哪个策略"。该模块按候选池实测, 掩护域失效时
        # 自动降级 (g.cn → 其它 Google 自有域 → 真实 SNI → 空 SNI); **没有新鲜探测结果时
        # 原样返回画像配置值**, 因此本处不改变任何既有行为, 只在探测明确说"首选已失效"
        # 时才换 SNI。降级结果同时由 UI 显示 (方案 §10 验收标准 6)。
        sni_mode = profile.ssl_sni_mode
        try:
            import cover_sni as _cover_sni
            sni_mode = _cover_sni.effective_sni_mode(profile) or profile.ssl_sni_mode
        except Exception:      # pragma: no cover - 探测模块不可用时绝不阻断生成
            sni_mode = profile.ssl_sni_mode
        if sni_mode != profile.ssl_sni_mode:
            lines_note_downgrade = (
                f"    # [降级] 掩护 SNI 回归探测判定 {profile.ssl_sni_mode} 失效, "
                f"本块实际使用 {sni_mode} (见 app/cover_sni.py)"
            )
        else:
            lines_note_downgrade = ""

        if sni_mode == "empty":
            sni_str = '""'
        elif sni_mode == "host":
            sni_str = "$host"
        else:
            sni_str = f'"{sni_mode}"'

        if profile.id == "steam_community":
            # Host 分流: api.steampowered.com 必须保持原 Host 才能命中 API 网关 vhost
            # (Host 被改写为 steamcommunity.com 时 API 路径会被上游 302 重定向到社区首页),
            # 其余域名 (steamcommunity.com 及子域) 归一化到主域防 118
            # 对应文件顶部 map $host $steam_upstream_host
            host_header = "$steam_upstream_host"
        else:
            host_header = profile.custom_headers.get("Host", "$host")

        # ECH 隧道分支: 上游指向本地回环上的明文 HTTP 入口, 真正的 TLS 与 ECH
        # 握手由隧道自己发起。此时必须完全不输出 proxy_ssl_* —— 否则形成
        # TLS-in-TLS, 隧道无法在中间注入 ECH 扩展。
        # 协议必须与 upstream 实际写入的后端一致 (隧道=明文回环, 退化候选池=https),
        # 判据取自 upstream-dynamic.conf 而非静态标记, 详见 _ech_services_from_upstream。
        ech = cls._use_ech(profile, ech_services)
        # HTTP/3 上游腿与 ECH 同款: 后端是本地回环上的**明文** HTTP 入口, 真正的 TLS/QUIC
        # 由本地代理自己发起。此时同样必须完全不输出 proxy_ssl_*。
        h3 = cls._use_h3(profile, h3_services)
        plaintext_local = bool(ech or h3)
        scheme = "http" if plaintext_local else "https"
        ssl_lines = [] if plaintext_local else [
            f"        proxy_ssl_name {sni_str};",
            "        proxy_ssl_server_name on;",
            "        proxy_ssl_verify off;",
            "        proxy_ssl_session_reuse on;",
        ]
        title = f"{profile.name} (经本地 ECH 隧道直连 Cloudflare)" if ech else (
            f"{profile.name} (经本地 HTTP/3 上游腿)" if h3 else profile.name)

        # ----------------------------------------------------------------------
        # 1. Pixiv 主站特殊处理 (包含 /ajax/ CORS 与 /ws/ WebSocket)
        # ----------------------------------------------------------------------
        if profile.id == "pixiv_web":
            return cls._render_pixiv_web_server(profile, ech_services)

        # ----------------------------------------------------------------------
        # 2. Pixiv 图片 CDN 特殊处理 (包含 pximg 缓存与 Sketch 直播流)
        # ----------------------------------------------------------------------
        if profile.id == "pixiv_img":
            return cls._render_pixiv_img_server(profile)

        # ----------------------------------------------------------------------
        # 3. 标准通用 Server 块渲染
        # ----------------------------------------------------------------------
        lines = [
            f"# {title}",
            "server {",
            "    listen 80;",
            "    listen 443 ssl;",
            "    http2 on;",
            f"    server_name {domains_str};",
            ""
        ]
        if lines_note_downgrade:
            lines.append(lines_note_downgrade)

        if profile.group == "dev":
            lines.append("    client_max_body_size 0;  # 支持任意体积大文件与 Git packfile")
        elif profile.id in ("pixiv_fanbox", "booth_pm"):
            lines.append("    client_max_body_size 50M;")

        # WebSocket 升级头的取舍 (项目实测, 见下方注释):
        #   普通服务用编译期字面量空串 "" -> upstream keepalive 生效 (TTFB 0.22~0.24s);
        #   但**真正需要 WebSocket 的服务** (如 Discord 网关 gateway.discord.gg, 路径是 /
        #   而非 /ws/) 必须发 "upgrade", 否则浏览器 WS 握手被清掉、客户端持续
        #   "[WS CLOSED] An error with the websocket occurred" (实测事故)。
        # 两者都是**生成期就写死的字面量**, 因此 keepalive 语义不受影响。
        conn_header = '"upgrade"' if getattr(profile, "websocket", False) else '""'

        lines.extend([
            "    location / {",
            f"        proxy_pass {scheme}://{profile.upstream_name};",
            "        proxy_http_version 1.1;",
            "        proxy_set_header Upgrade $http_upgrade;",
            # 必须是字面量空串, 不能写 $connection_upgrade —— 实测两者的行为并不等价:
            # nginx 只在值是编译期字面量空串时才真正"删除该头"; 变量求值得到的空串
            # 仍会发出空的 Connection 头, upstream 因此不进入 keepalive 复用。
            # 实测同一服务: 用 map 变量时 TTFB 恒为 0.55~0.71s 且上游 ESTABLISHED=0;
            # 改成 "" 后第 3 个请求起稳定降到 0.22~0.24s, 上游保留 3 条长连接。
            f"        proxy_set_header Connection {conn_header};",
            f"        proxy_set_header Host {host_header};",
            "        proxy_set_header User-Agent $http_user_agent;",
            "        proxy_set_header Accept-Encoding $http_accept_encoding;",
            "        proxy_set_header Accept-Language $http_accept_language;",
            *ssl_lines,
        ])

        # 本地静态资源/图片磁盘缓存挂载
        if profile.enable_cache:
            lines.extend([
                "        # 开启本地磁盘缓存 (消除频次冲击与 0ms 秒开)",
                "        proxy_cache pixiv_img_cache;",
                "        proxy_cache_valid 200 304 7d;",
                "        proxy_cache_valid 404 1m;",
                "        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;",
                "        proxy_cache_revalidate on;",
                "        proxy_cache_lock on;",
                "        add_header X-Cache-Status $upstream_cache_status;",
            ])

        # Steam 商店与社区防网关 Portal 劫持重定向 (阻断深澜 srun 等局域网认证页面渗透到客户端)
        if profile.id in ("steam_store", "steam_community"):
            lines.append("        # 防网关 Portal 劫持重定向，阻断局域网登录地址下发给客户端")
            lines.append("        proxy_redirect ~*^https?://(?:172\\.|192\\.168\\.|10\\.|.*srun.*|.*portal.*)(.*)$ /;")

        # Steam 社区重定向防死循环自适应
        if profile.id == "steam_community":
            lines.extend([
                "        proxy_redirect default;",
                "        proxy_redirect http:// https://;",
            ])
            if profile.group != "dev":
                lines.append("        proxy_force_ranges on;")

        # 针对开发生态 (Git/GitHub/GitLab/大文件) 开启全链路流式零缓冲、Range 穿透与超长超时
        if profile.group == "dev":
            lines.append("        # 大文件与 Git Smart HTTP 极速流式透传配置 (彻底消灭磁盘 I/O 缓冲假死)")
            # ⚠ proxy_buffering off 与 proxy_cache **互斥** —— 二者不可同时出现在一个 location。
            # 实测依据 (2026-10-01, 本地 nginx 最小复现, 见 cache_probe 实验): 同一 location
            # 同时写 `proxy_cache` 与 `proxy_buffering off` + `proxy_max_temp_file_size 0` 时,
            # 第二次请求 `$upstream_cache_status` 仍是 MISS、源站被重新命中 (seq 4→5);
            # 仅把缓冲改回 on, 第二次即 HIT。原因: nginx 需要缓冲响应体才能落盘缓存。
            # 影响面 (修复前): 所有 group=dev 且 enable_cache=True 的画像缓存**全是空转**
            # (google_fonts / jsdelivr / npm / pypi / crates 等), 白白多打一次回源。
            # 故: 开了缓存的画像保留缓冲 (缓存优先), 未开缓存的才走零缓冲流式透传。
            if profile.enable_cache:
                lines.append("        proxy_buffering on;   # 本画像开了磁盘缓存, 必须保留缓冲否则缓存不生效 (见上)")
            else:
                lines.extend([
                    "        proxy_buffering off;",
                    "        proxy_max_temp_file_size 0;",
                ])
            lines.extend([
                "        proxy_request_buffering off;",
                "        proxy_force_ranges on;",
                "        proxy_set_header Range $http_range;",
                "        proxy_set_header If-Range $http_if_range;",
                "        proxy_read_timeout 3600s;",
                "        proxy_send_timeout 3600s;",
                # 连接超时 3s (nginx.conf 全局为 5s, 开发组更激进)。
                # 原为 15s: 开发组 upstream 里混有失活节点, 配合 proxy_next_upstream
                # 逐个试错, 单个请求最坏要等 15s × 节点数 —— 这是"经代理反而更卡"的
                # 直接来源。实测 GitHub 存在整段间歇性中断(日志中三个主力同时
                # "while connecting" 超时, 而间隔数秒的独立探测又全部可达), 3s 既能
                # 覆盖最慢的正常建连(实测峰值 1.1s), 又能在整段不可用时尽快交棒给
                # 下一个节点; 持续失败的节点由 max_fails=3/fail_timeout=30s 熔断。
                "        proxy_connect_timeout 3s;",
            ])
        else:
            lines.extend([
                "        proxy_read_timeout 60s;",
                "        proxy_send_timeout 60s;",
            ])

        # 状态码白名单仅限 nginx 编译期支持的这几个 (403/404/429/500/502/503/504),
        # 写 http_400 会导致 nginx 直接 [emerg] invalid value 起不来 —— 已实测验证。
        # 因此"上游返回 400"无法靠重试规避, 只能靠清理候选池中恒 400 的节点解决。
        #
        # http_404 默认【不】加入: githubassets / crates.io / google_fonts 等服务的
        # 根路径 404 属正常响应, 一律重试纯属浪费。仅当 profile 标记了 retry_on_404
        # (即已确认 upstream 内混有"错误 vhost"节点) 时才附带 —— nginx 的 max_fails
        # 熔断只对连接失败/超时生效, 对"成功返回 404"完全无感, 不重试就等于把错误
        # vhost 的 404 原样透传给用户 (minecraft "频繁 Page not found" 的直接成因)。
        retry_codes = (
            "http_403 http_429 http_404 http_500 http_502 http_503 http_504"
            if getattr(profile, "retry_on_404", False)
            else "http_403 http_429 http_500 http_502 http_503 http_504"
        )
        lines.extend([
            f"        proxy_next_upstream error timeout {retry_codes} non_idempotent;",
            # 限制单请求的上游尝试次数: 上游池可达 8 节点, 配合 3s 连接超时若不加限制,
            # 一次请求最坏会在坏节点间串行等待 8×3=24s (用户感知即"卡死")。限 4 次后
            # 最坏约 12s, 且持续失败的节点会被 max_fails 迅速熔断, 后续请求直达健康节点。
            f"        proxy_next_upstream_tries {UPSTREAM_NEXT_TRIES};",
            "    }",
            "}\n"
        ])
        return "\n".join(lines)

    @classmethod
    def _render_pixiv_web_server(cls, profile: ServiceProfile,
                                 ech_services: Optional[Set[str]] = None) -> str:
        """渲染 Pixiv 主站专用规则 (包含 /ajax/ CORS 与 /ws/ WebSocket)

        ECH 分支: 当该服务本次确实走隧道时, 上游指向本地回环上的明文 HTTP
        入口 (ECH 隧道), 真正的 TLS 与 ECH 握手由隧道自己发起。此时必须完全
        不输出 proxy_ssl_* —— 否则形成 TLS-in-TLS, 隧道无法在中间注入 ECH 扩展。
        """
        main_domains = [d for d in profile.domains if d != "lc-event.pixiv.net"]
        domains_str = " ".join(main_domains)

        ech = cls._use_ech(profile, ech_services)
        scheme = "http" if ech else "https"
        if ech:
            banner = f"# {profile.name} (经本地 ECH 隧道直连 Cloudflare)"
            ssl_opts = ""
        else:
            banner = f"# {profile.name} (采用空 SNI 策略，绕过 GFW SNI 阻断)"
            ssl_opts = """        proxy_ssl_name "";
        proxy_ssl_server_name on;
        proxy_ssl_verify off;
        proxy_ssl_session_reuse on;
"""

        return f"""{banner}
server {{
    listen 80;
    listen 443 ssl;
    http2 on;
    server_name {domains_str};

    client_max_body_size 50M;

    location / {{
        proxy_pass {scheme}://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "";   # 字面量空串才能让 upstream keepalive 生效, 见 _render_generic 注释
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_max_temp_file_size 0;
        proxy_buffering off;
{ssl_opts}        proxy_next_upstream error timeout http_403 http_429 http_404 http_500 http_502 http_503 http_504 non_idempotent;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }}

    location /ajax/ {{
        proxy_pass {scheme}://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "";   # 字面量空串才能让 upstream keepalive 生效, 见 _render_generic 注释
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_max_temp_file_size 0;
        proxy_buffering off;
{ssl_opts}        proxy_hide_header Access-Control-Allow-Origin;
        add_header Access-Control-Allow-Origin $http_origin always;
        proxy_next_upstream error timeout http_403 http_429 http_404 http_500 http_502 http_503 http_504 non_idempotent;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }}

    location /ws/ {{
        proxy_pass {scheme}://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Connection "upgrade";
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_max_temp_file_size 0;
        proxy_buffering off;
{ssl_opts}        proxy_hide_header Access-Control-Allow-Origin;
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
        proxy_pass {scheme}://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "";   # 字面量空串才能让 upstream keepalive 生效, 见 _render_generic 注释
        proxy_set_header Host $http_host;
        proxy_set_header User-Agent $http_user_agent;
        proxy_max_temp_file_size 0;
        proxy_buffering off;
{ssl_opts}        proxy_next_upstream error timeout http_403 http_429 http_404 http_500 http_502 http_503 http_504 non_idempotent;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }}
}}
"""

    @classmethod
    def _render_pixiv_img_server(cls, profile: ServiceProfile) -> str:
        """渲染 Pixiv pximg 插画 CDN 专用规则 (带磁盘缓存与 Range 续传)

        server_name 由 *.pximg.net 通配 + profile.domains 组成 (原先硬编码,
        导致改 domains 后此处静默失配 —— 例如已迁走的 source.pixiv.net 仍被
        列在此处, 而新纳入的 booth.pximg.net 反而漏掉)。
        """
        names = list(dict.fromkeys(["*.pximg.net"] + list(profile.domains)))
        domains_str = " ".join(names)
        return f"""# {profile.name} (带本地图片磁盘缓存与 Range 断点续传)
server {{
    listen 80;
    listen 443 ssl;
    http2 on;
    server_name {domains_str};

    location / {{
        proxy_pass https://{profile.upstream_name};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "";   # 字面量空串才能让 upstream keepalive 生效, 见 _render_generic 注释
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
        proxy_next_upstream error timeout http_403 http_429 http_404 http_500 http_502 http_503 http_504 non_idempotent;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }}
}}
"""

    @classmethod
    def generate_all(cls, target_dir: Path = CONF_DIR,
                     ech_services: Optional[Set[str]] = None,
                     h3_services: Optional[Set[str]] = None) -> Dict[str, str]:
        """全量渲染并原子写入三大站点配置文件

        ech_services 为走 ECH 隧道的服务 id 集合 (决定 proxy_pass 用 http 还是
        https)。缺省时从 target_dir 下已生成的 upstream-dynamic.conf 反推 —— 即
        以实际写进上游的后端为准, 保证两者不会脱钩; 该文件尚不存在时回退到隧道
        实时健康检查。
        """
        target_dir.mkdir(parents=True, exist_ok=True)
        results = {}
        if ech_services is None:
            ech_services = cls._ech_services_from_upstream(target_dir / "upstream-dynamic.conf")
        if h3_services is None:
            h3_services = cls._h3_services_from_upstream(target_dir / "upstream-dynamic.conf")

        # 1. 渲染 site-gaming.conf
        gaming_profiles = [p for p in PROFILES
                           if p.group == "gaming" and p.mode not in NGINX_BYPASS_MODES]
        gaming_blocks = [
            "# ==============================================================================",
            "# GameArt Toolkit - 游戏生态全平台加速规则 (由 ServiceProfile 模板自动生成)",
            "# ==============================================================================\n"
        ]
        # Steam 社区 Host 分流 map: api.steampowered.com 保持原 Host 路由 API 网关,
        # 其余域名 (steamcommunity.com 及子域) 归一化到主域防 118 (由 steam_community 渲染引用)
        if any(p.id == "steam_community" for p in gaming_profiles):
            gaming_blocks.append(
                "map $host $steam_upstream_host {\n"
                "    hostnames;\n"
                "    api.steampowered.com api.steampowered.com;\n"
                "    default steamcommunity.com;\n"
                "}\n"
            )
        for p in gaming_profiles:
            gaming_blocks.append(cls.render_server_block(p, ech_services, h3_services))
        gaming_content = "\n".join(gaming_blocks)
        (target_dir / "site-gaming.conf").write_text(gaming_content, encoding="utf-8")
        results["site-gaming.conf"] = gaming_content

        # 2. 渲染 site-acg.conf
        acg_profiles = [p for p in PROFILES
                        if p.group == "acg" and p.mode not in NGINX_BYPASS_MODES]
        acg_blocks = [
            "# ==============================================================================",
            "# GameArt Toolkit - 二次元与创作者生态加速规则 (由 ServiceProfile 模板自动生成)",
            "# ==============================================================================\n"
        ]
        for p in acg_profiles:
            acg_blocks.append(cls.render_server_block(p, ech_services, h3_services))
        acg_content = "\n".join(acg_blocks)
        (target_dir / "site-acg.conf").write_text(acg_content, encoding="utf-8")
        results["site-acg.conf"] = acg_content

        # 3. 渲染 site-dev.conf
        dev_profiles = [p for p in PROFILES
                        if p.group == "dev" and p.mode not in NGINX_BYPASS_MODES]
        dev_blocks = [
            "# ==============================================================================",
            "# GameArt Toolkit - 开发者与 AI 平台加速规则 (由 ServiceProfile 模板自动生成)",
            "# ==============================================================================\n"
        ]
        for p in dev_profiles:
            dev_blocks.append(cls.render_server_block(p, ech_services, h3_services))
        dev_content = "\n".join(dev_blocks)
        (target_dir / "site-dev.conf").write_text(dev_content, encoding="utf-8")
        results["site-dev.conf"] = dev_content

        return results

