# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 可添加反代目标 (动态注册) 架构能力验证测试集

验证运行时"添加反代目标"的完整链路是否可扩展:
1. 动态注册 4 个真实候选服务 Profile (DLsite / Epic Games / Battle.net / Patreon)
2. 域名查找索引 (get_profile_by_id / get_profile_by_domain) 同步生效
3. ip_pool 导出索引 (SERVICES_LIST / SERVICES_BY_ID / CANDIDATE_IPS) 同步生效
4. Nginx 站点配置生成 (generate_all) 输出候选服务的 server 块 (按组路由)
5. Upstream 增量注入 (apply_optimal) 保留存量 18 块并生成候选块, 交叉校验通过
6. 临时 nginx 沙箱内执行 nginx -t 语法预检通过 (含证书 SAN 动态更新)
7. Hosts 规则注入与本地 DNS 域名路由生效
8. 测试结束后完整还原现场 (注册表数量回基线, 生产配置零污染)

注意: 注册窗口严格限定在单个测试方法内 (try/finally), 避免与其他测试交错;
候选 Profile 定义仅存在于本测试文件, 绝不写入生产 PROFILES 注册表。
"""

import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import List

APP_DIR = Path(__file__).resolve().parent.parent / "app"
NGINX_DIR = Path(__file__).resolve().parent.parent / "nginx"
sys.path.insert(0, str(APP_DIR))

import service_profile as sp
import ip_pool
from service_profile import ServiceProfile, ServiceMode, get_profile_by_id, get_profile_by_domain
from nginx_generator import NginxConfGenerator
from nginx_manager import NginxManager
from hosts_manager import HostsManager
from cdn_optimizer import CDNOptimizer, SNI_MODES
from dns_server import LocalDnsServer
from cert_manager import get_all_san_domains
from cryptography import x509 as _crypto_x509

# ==============================================================================
# 3 个候选反代目标定义 (测试专用数据, 验证运行时动态扩展架构, 不写入生产 PROFILES)
# ==============================================================================
CANDIDATE_PROFILES: List[ServiceProfile] = [
    ServiceProfile(
        id="gog_galaxy",
        group="gaming",
        name="GOG Galaxy 商城",
        desc="GOG 游戏商城与客户端分发 (Fastly Anycast)",
        domains=["gog.com", "www.gog.com", "api.gog.com"],
        icon="shopping_bag",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_gog_galaxy",
        ssl_sni_mode="host",
        candidate_ips=["151.101.194.133", "151.101.66.133"],
    ),
    ServiceProfile(
        id="artstation",
        group="acg",
        name="ArtStation 艺术社区",
        desc="数字艺术画廊与创作者作品展示",
        domains=["artstation.com", "www.artstation.com", "cdn.artstation.com"],
        icon="image",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_artstation",
        ssl_sni_mode="host",
        candidate_ips=["151.101.194.133", "151.101.66.133"],
    ),
    ServiceProfile(
        id="civitai",
        group="dev",
        name="Civitai AI 模型社区",
        desc="AI 生态模型与图片展示 (Cloudflare)",
        domains=["civitai.com", "www.civitai.com", "image.civitai.com"],
        icon="cpu",
        mode=ServiceMode.L7_NGINX,
        upstream_name="upstream_civitai",
        ssl_sni_mode="host",
        candidate_ips=["104.18.22.203", "104.18.23.203"],
    ),
]

CANDIDATE_IDS: List[str] = [p.id for p in CANDIDATE_PROFILES]


def _register_candidates():
    """原地注册 4 个候选反代目标: 同步注入所有 import 期索引 (无需 reload)"""
    sp.PROFILES.extend(CANDIDATE_PROFILES)
    for p in CANDIDATE_PROFILES:
        # service_profile 静态索引
        sp.PROFILES_BY_ID[p.id] = p
        for d in p.domains:
            sp.PROFILES_BY_DOMAIN[d.lower()] = p
        # ip_pool 导出索引
        ip_pool.SERVICES_LIST.append({
            "id": p.id,
            "group": p.group,
            "name": p.name,
            "domains": p.domains,
            "desc": p.desc,
            "icon": getattr(p, "icon", "zap"),
            "mode": p.mode.value,
            "enable_cache": p.enable_cache,
        })
        ip_pool.SERVICES_BY_ID[p.id] = ip_pool.SERVICES_LIST[-1]
        ip_pool.CANDIDATE_IPS[p.id] = p.candidate_ips
        # cdn_optimizer SNI 模式索引
        SNI_MODES[p.id] = p.ssl_sni_mode
    sp.TOTAL_SERVICES_COUNT = len(sp.PROFILES)


def _unregister_candidates():
    """完整还原现场: 移除注册的候选与所有同步注入的索引"""
    ids = set(CANDIDATE_IDS)
    sp.PROFILES[:] = [p for p in sp.PROFILES if p.id not in ids]
    for p in CANDIDATE_PROFILES:
        sp.PROFILES_BY_ID.pop(p.id, None)
        for d in p.domains:
            sp.PROFILES_BY_DOMAIN.pop(d.lower(), None)
        SNI_MODES.pop(p.id, None)
    ip_pool.SERVICES_LIST[:] = [s for s in ip_pool.SERVICES_LIST if s["id"] not in ids]
    for sid in ids:
        ip_pool.SERVICES_BY_ID.pop(sid, None)
        ip_pool.CANDIDATE_IPS.pop(sid, None)
    sp.TOTAL_SERVICES_COUNT = len(sp.PROFILES)


def _build_nginx_sandbox() -> Path:
    """构建临时 nginx 沙箱: 复制二进制/证书/配置模板并预建运行时目录"""
    tmp = Path(tempfile.mkdtemp(prefix="gat_sandbox_"))
    (tmp / "conf").mkdir(parents=True, exist_ok=True)
    (tmp / "ca").mkdir(parents=True, exist_ok=True)
    (tmp / "cache" / "img").mkdir(parents=True, exist_ok=True)
    (tmp / "logs").mkdir(parents=True, exist_ok=True)
    (tmp / "temp").mkdir(parents=True, exist_ok=True)
    # nginx 二进制
    shutil.copy2(NGINX_DIR / "nginx.exe", tmp / "nginx.exe")
    # 证书 (CA + 服务端证书, nginx.conf 按 prefix 相对路径 ca/ 解析)
    for cert in ("ca.cer", "ca.key", "pixiv.net.crt", "pixiv.net.key"):
        src = NGINX_DIR / "ca" / cert
        if src.exists():
            shutil.copy2(src, tmp / "ca" / cert)
    if (NGINX_DIR / "ca.cer").exists():
        shutil.copy2(NGINX_DIR / "ca.cer", tmp / "ca.cer")
    # 配置模板
    shutil.copy2(NGINX_DIR / "conf" / "nginx.conf", tmp / "conf" / "nginx.conf")
    shutil.copy2(NGINX_DIR / "conf" / "mime.types", tmp / "conf" / "mime.types")
    return tmp


class TestAddableProxyTargets(unittest.TestCase):
    """验证运行时可添加反代目标的架构能力 (全链路 + 现场还原)"""

    def test_add_proxy_target_full_chain(self):
        """动态注册 4 个候选反代目标 -> 全链路验证 -> 完整还原"""
        base_count = len(sp.PROFILES)
        sandbox = None
        try:
            _register_candidates()

            # ------------------------------------------------------------------
            # 1. 注册生效: 域名查找索引与 ip_pool 导出索引同步
            # ------------------------------------------------------------------
            self.assertEqual(len(sp.PROFILES), base_count + len(CANDIDATE_PROFILES))
            for p in CANDIDATE_PROFILES:
                self.assertIs(get_profile_by_id(p.id), p)
                self.assertIs(get_profile_by_domain(p.domains[0]), p)
                self.assertIn(p.id, ip_pool.SERVICES_BY_ID)
                self.assertIn(p.id, ip_pool.CANDIDATE_IPS)
                self.assertEqual(ip_pool.CANDIDATE_IPS[p.id], p.candidate_ips)
            # 证书 SAN 域名动态更新 (get_all_san_domains 遍历 PROFILES)
            sans = get_all_san_domains()
            for p in CANDIDATE_PROFILES:
                self.assertIn(p.domains[0], sans)

            # ------------------------------------------------------------------
            # 2. nginx 站点配置生成 (全部落在沙箱, 不触碰生产目录)
            # ------------------------------------------------------------------
            sandbox = _build_nginx_sandbox()
            conf_dir = sandbox / "conf"
            results = NginxConfGenerator.generate_all(conf_dir)
            self.assertIn("site-gaming.conf", results)
            self.assertIn("site-acg.conf", results)
            self.assertIn("site-dev.conf", results)
            for p in CANDIDATE_PROFILES:
                site_text = results[f"site-{p.group}.conf"]
                self.assertIn(p.domains[0], site_text, f"{p.id} 首域名未进入 {p.group} 站点配置")
                self.assertIn(p.domains[1], site_text, f"{p.id} 次域名未进入 {p.group} 站点配置")
                self.assertIn(f"https://{p.upstream_name}", site_text, f"{p.id} 的 proxy_pass 未生成")
            # 组路由正确性: acg 候选不进 dev 配置
            dev_text = results["site-dev.conf"]
            self.assertNotIn("artstation.com", dev_text)
            self.assertNotIn("gog.com", dev_text)

            # ------------------------------------------------------------------
            # 3. upstream 增量注入: 存量 22 块保留 + 3 个候选新块 (交叉校验)
            # ------------------------------------------------------------------
            sandbox_upstream = conf_dir / "upstream-dynamic.conf"
            shutil.copy2(NGINX_DIR / "conf" / "upstream-dynamic.conf", sandbox_upstream)
            mock_results = {}
            for p in CANDIDATE_PROFILES:
                ips = p.candidate_ips
                mock_results[p.id] = [
                    {"ip": ips[0], "latency": 25.0, "available": True, "rank": 0},
                    {"ip": ips[1], "latency": 45.0, "available": True, "rank": 0},
                ]
            opt = CDNOptimizer(sandbox_upstream)
            ok, msg = opt.apply_optimal(mock_results)
            self.assertTrue(ok, f"apply_optimal 交叉校验失败: {msg}")
            up_text = sandbox_upstream.read_text(encoding="utf-8")
            for p in CANDIDATE_PROFILES:
                self.assertIn(f"upstream {p.upstream_name} {{", up_text)
                self.assertIn(f"server {p.candidate_ips[0]}:443", up_text)
            defined = set(re.findall(r"upstream (upstream_[a-z0-9_]+)", up_text))
            self.assertIn("upstream_pixiv_web", defined, "存量 upstream 块在增量注入中丢失")
            self.assertEqual(len(defined), base_count + len(CANDIDATE_PROFILES),
                             "upstream 总量应为存量 + 候选数")

            # ------------------------------------------------------------------
            # 4. nginx -t 语法预检 (沙箱内, 证书 SAN 动态重签发后通过)
            # ------------------------------------------------------------------
            mgr = NginxManager(sandbox)
            ok_t, msg_t = mgr.test_config()
            self.assertTrue(ok_t, f"沙箱 nginx -t 失败: {msg_t}")
            self.assertTrue((sandbox / "conf" / "ca" / "pixiv.net.crt").exists(),
                            "证书重签发后 conf/ca 镜像缺失")
            # 证书 SAN 动态更新: 重签发的服务端证书必须包含候选域名
            crt_bytes = (sandbox / "ca" / "pixiv.net.crt").read_bytes()
            cert_obj = _crypto_x509.load_pem_x509_certificate(crt_bytes)
            san_ext = cert_obj.extensions.get_extension_for_oid(
                _crypto_x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            cert_sans = set(san_ext.value.get_values_for_type(_crypto_x509.DNSName))
            for p in CANDIDATE_PROFILES:
                self.assertIn(p.domains[0], cert_sans,
                              f"重签发证书 SAN 缺少 {p.id} 域名")

            # ------------------------------------------------------------------
            # 5. Hosts 规则注入 (临时 hosts 文件)
            # ------------------------------------------------------------------
            with tempfile.TemporaryDirectory() as td:
                fake_hosts = Path(td) / "hosts"
                fake_hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
                hm = HostsManager(hosts_file=fake_hosts)
                ok_h, msg_h = hm.apply_rules(CANDIDATE_IDS)
                self.assertTrue(ok_h, f"Hosts 规则注入失败: {msg_h}")
                content = fake_hosts.read_text(encoding="utf-8")
                for p in CANDIDATE_PROFILES:
                    self.assertIn(f"127.0.0.1 {p.domains[0]}", content,
                                  f"{p.id} 域名未注入 Hosts 规则")
                hm.remove_rules()

            # ------------------------------------------------------------------
            # 6. 本地 DNS 域名路由 (L7 服务应答 127.0.0.1, 自定义映射优先)
            # ------------------------------------------------------------------
            dns = LocalDnsServer()
            for p in CANDIDATE_PROFILES:
                self.assertEqual(dns._resolve_locally(p.domains[0]), "127.0.0.1",
                                 f"{p.id} 域名未被本地 DNS 路由")
            dns.add_custom_mapping("api.gog.com", "1.2.3.4")
            self.assertEqual(dns._resolve_locally("api.gog.com"), "1.2.3.4")
            self.assertIsNone(dns._resolve_locally("unknown.example.com"))
        finally:
            if sandbox is not None:
                shutil.rmtree(sandbox, ignore_errors=True)
            _unregister_candidates()

        # ------------------------------------------------------------------
        # 7. 现场还原断言: 注册表回基线, 生产配置零污染
        # ------------------------------------------------------------------
        self.assertEqual(len(sp.PROFILES), base_count)
        self.assertIsNone(get_profile_by_id("gog_galaxy"))
        self.assertIsNone(get_profile_by_domain("api.gog.com"))
        for sid in CANDIDATE_IDS:
            self.assertNotIn(sid, ip_pool.SERVICES_BY_ID)
            self.assertNotIn(sid, ip_pool.CANDIDATE_IPS)
        # 生产 site 配置未被候选域名污染
        acg_prod = (NGINX_DIR / "conf" / "site-acg.conf").read_text(encoding="utf-8", errors="ignore")
        gaming_prod = (NGINX_DIR / "conf" / "site-gaming.conf").read_text(encoding="utf-8", errors="ignore")
        dev_prod = (NGINX_DIR / "conf" / "site-dev.conf").read_text(encoding="utf-8", errors="ignore")
        self.assertNotIn("artstation.com", dev_prod)
        self.assertNotIn("gog.com", acg_prod)
        self.assertNotIn("civitai.com", gaming_prod)
        # 生产 upstream-dynamic.conf 未被候选 upstream 污染
        up_prod = (NGINX_DIR / "conf" / "upstream-dynamic.conf").read_text(encoding="utf-8", errors="ignore")
        self.assertNotIn("upstream_gog_galaxy", up_prod)
        self.assertNotIn("upstream_artstation", up_prod)
        self.assertNotIn("upstream_civitai", up_prod)


if __name__ == "__main__":
    unittest.main()
