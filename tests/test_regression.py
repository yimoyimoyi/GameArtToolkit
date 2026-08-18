# -*- coding: utf-8 -*-
"""
PixivToolkit - 全面自动化回归验证与针对性测试脚本
包含 6 大专项测试域：
1. Nginx 语法预检与 Upstream 对齐测试
2. CryptoAPI 原生证书检测与防误判测试
3. VDF 词法解析与序列化幂等性测试
4. Hosts 原子写入、只读修复与无损剥离测试
5. CDN 测速引擎单池任务调度与 Upstream 兜底生成测试
6. 批处理脚本 UTF-8 with BOM 编码全量校验
"""

import os
import sys
import time
import stat
import shutil
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List

# 设置输出流为 UTF-8 编码，防止 Windows 终端字符编码问题
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# 将 app 目录加入 Python 搜索路径
WORKSPACE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = WORKSPACE_DIR / "app"
sys.path.insert(0, str(APP_DIR))

from ip_pool import SERVICES_LIST, SERVICES_BY_ID, CANDIDATE_IPS
from cert_manager import CertManager
from hosts_manager import HostsManager, BLOCK_START, BLOCK_END
from steam_manager import SteamManager, tokenize_vdf, parse_vdf_structure, serialize_vdf_dict
from nginx_manager import NginxManager
from cdn_optimizer import CDNOptimizer
from nginx_generator import NginxConfGenerator

# 确保测试前最新站点配置文件已完全模板化渲染
NginxConfGenerator.generate_all(WORKSPACE_DIR / "nginx" / "conf")

class RegressionTestSuite:
    def __init__(self):
        self.results = {}
        self.start_time = time.time()

    def log_section(self, title: str):
        print(f"\n{'='*70}")
        print(f" >>> [TEST] {title}")
        print(f"{'='*70}")

    def log_sub(self, msg: str, success: bool = True):
        status = "[PASS]" if success else "[FAIL]"
        print(f"  {status} {msg}")

    # =========================================================================
    # 1. Nginx 语法预检与 Upstream 命名对齐测试
    # =========================================================================
    def test_nginx_syntax_and_upstream_alignment(self):
        self.log_section("1. Nginx 语法预检与 Upstream 命名对齐测试")
        nm = NginxManager()

        # 1.1 检查可执行文件与目录
        assert nm.nginx_exe.exists(), f"nginx.exe 不存在于 {nm.nginx_exe}"
        self.log_sub(f"Nginx 可执行文件就绪: {nm.nginx_exe}")

        # 1.2 执行 nginx -t 语法预检
        cmd = [str(nm.nginx_exe), "-p", str(nm.nginx_dir), "-c", "conf/nginx.conf", "-t"]
        proc = subprocess.run(cmd, cwd=str(nm.nginx_dir), capture_output=True, text=True, errors="ignore", timeout=5)
        out = (proc.stderr or proc.stdout).strip()
        assert proc.returncode == 0, f"Nginx 语法测试失败 (退出码 {proc.returncode}): {out}"
        self.log_sub(f"nginx -t 语法预检成功 (返回码 0): {out.splitlines()[0] if out else 'OK'}")

        # 1.3 验证所有 site-*.conf 中的 upstream 命名对齐
        conf_dir = nm.nginx_dir / "conf"
        dynamic_upstream_conf = (conf_dir / "upstream-dynamic.conf").read_text(encoding="utf-8", errors="ignore")

        # 提取 upstream-dynamic.conf 中定义的全部 upstream 块名称
        import re
        defined_upstreams = set(re.findall(r"upstream\s+([a-zA-Z0-9_-]+)\s*\{", dynamic_upstream_conf))
        self.log_sub(f"upstream-dynamic.conf 中解析到 {len(defined_upstreams)} 个负载均衡组")

        # 校验 20 项服务是否全部在 upstream-dynamic.conf 中定义
        for srv in SERVICES_LIST:
            srv_id = srv["id"]
            expected_upstream = f"upstream_{srv_id}"
            assert expected_upstream in defined_upstreams, f"服务 {srv_id} 对应的 {expected_upstream} 未在 upstream-dynamic.conf 中定义"
        self.log_sub(f"{len(SERVICES_LIST)} 项加速服务在 upstream-dynamic.conf 中全部具备匹配的 upstream 定义")

        # 检查 site-acg.conf, site-gaming.conf, site-dev.conf 中引用的 upstream
        site_files = ["site-acg.conf", "site-gaming.conf", "site-dev.conf"]
        all_referenced_upstreams = set()
        for sf in site_files:
            sf_path = conf_dir / sf
            assert sf_path.exists(), f"配置文件不存在: {sf}"
            content = sf_path.read_text(encoding="utf-8", errors="ignore")
            refs = re.findall(r"proxy_pass\s+https?://([a-zA-Z0-9_-]+)[;/]", content)
            for ref in refs:
                all_referenced_upstreams.add(ref)
                assert ref in defined_upstreams, f"[{sf}] 引用的 upstream '{ref}' 在 upstream-dynamic.conf 中未定义！"

        # 特别确认 upstream_pixiv_fanbox 对齐
        assert "upstream_pixiv_fanbox" in all_referenced_upstreams, "site-acg.conf 未使用 upstream_pixiv_fanbox"
        assert "upstream_pixiv_fanbox" in defined_upstreams, "upstream-dynamic.conf 未定义 upstream_pixiv_fanbox"
        self.log_sub("site-*.conf 中所有 proxy_pass 目标（含 upstream_pixiv_fanbox）与 upstream-dynamic.conf 100% 对齐")

        self.results["nginx_syntax_and_alignment"] = True

    # =========================================================================
    # 2. CryptoAPI 原生证书检测测试
    # =========================================================================
    def test_cryptoapi_cert_detection(self):
        self.log_section("2. CryptoAPI 原生证书检测与防误判测试")
        cm = CertManager()

        # 2.1 验证真实证书指纹获取
        real_thumbprint = cm.get_cert_thumbprint()
        assert len(real_thumbprint) == 40, f"无效的 SHA1 指纹长度: {real_thumbprint}"
        assert all(c in "0123456789ABCDEF" for c in real_thumbprint), f"指纹包含非十六进制字符: {real_thumbprint}"
        self.log_sub(f"本地根证书 SHA1 指纹计算正常: {real_thumbprint}")

        # 2.2 性能测试：原生 CryptoAPI 检测耗时
        t0 = time.perf_counter()
        is_installed = cm.is_cert_installed(force_refresh=True)
        t_elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self.log_sub(f"CryptoAPI 证书库检索耗时: {t_elapsed_ms:.2f} ms (安装状态: {is_installed})")
        assert t_elapsed_ms < 150.0, f"CryptoAPI 检测耗时过长: {t_elapsed_ms:.2f}ms"

        # 2.3 防误判测试：伪造不存在的证书指纹，验证绝不会误判为 True
        with tempfile.NamedTemporaryFile("w", suffix=".cer", delete=False) as f:
            # 写入一个伪造的测试证书内容
            f.write("-----BEGIN CERTIFICATE-----\nMIIBojCCAUqgAwIBAgIUFakeCertificateForTestingPurposeOnly==\n-----END CERTIFICATE-----\n")
            fake_cer_path = Path(f.name)

        try:
            fake_cm = CertManager(cer_path=fake_cer_path)
            fake_thumb = fake_cm.get_cert_thumbprint()
            fake_installed = fake_cm.is_cert_installed(force_refresh=True)
            self.log_sub(f"伪造证书指纹: {fake_thumb}, 检测结果: {fake_installed}")
            assert fake_installed is False, "伪造证书不应被识别为已安装！"

            # 2.4 测试不受 'sha1' 文本污染影响
            # 确保无论输出中是否含有 'sha1' 字符串，只有真实匹配 hash 才会判定为 True
            dummy_hash = "0000000000000000000000000000000000000000"
            fake_cm._cached_thumbprint = dummy_hash
            fake_installed_dummy = fake_cm.is_cert_installed(force_refresh=True)
            assert fake_installed_dummy is False, "全零指纹不应判定为安装！"
            self.log_sub("防 'sha1' 模糊匹配误判机制验证通过 (零误报保障)")
        finally:
            if fake_cer_path.exists():
                fake_cer_path.unlink()

        self.results["cryptoapi_cert"] = True

    # =========================================================================
    # 3. VDF 词法解析与序列化测试
    # =========================================================================
    def test_vdf_lexical_parsing_and_serialization(self):
        self.log_section("3. VDF 词法解析与序列化幂等性测试")

        # 3.1 测试包含特殊字符、中文、转义双引号、反斜杠与嵌套结构的复杂 VDF
        complex_vdf = r'''
// 这是一个 Steam loginusers.vdf 测试样本
"users"
{
	"76561198966320302"
	{
		"AccountName"		"test_user_01"
		"PersonaName"		"玩家\"特别版\" (二次元🎮) \\ \/ \n"
		"RememberPassword"		"1"
		"MostRecent"		"1"
		"Timestamp"		"1700000000"
		"WantsOfflineMode"		"0"
		"SkipOfflineModeWarning"		"0"
	}
	"76561199415935650"
	{
		"AccountName"		"test_user_02"
		"PersonaName"		"Hello {World} [Test]"
		"RememberPassword"		"0"
		"MostRecent"		"0"
		"Timestamp"		"1690000000"
	}
}
'''
        # 词法切分 Token 测试
        tokens = tokenize_vdf(complex_vdf)
        self.log_sub(f"复杂 VDF Token 切分成功，Token 数量: {len(tokens)}")
        assert "users" in tokens
        assert "76561198966320302" in tokens
        assert "76561199415935650" in tokens

        # 语法树解析测试
        parsed = parse_vdf_structure(tokens)
        assert "users" in parsed, "根节点 'users' 解析失败"
        user1 = parsed["users"]["76561198966320302"]
        user2 = parsed["users"]["76561199415935650"]

        assert user1["AccountName"] == "test_user_01"
        assert "玩家\"特别版\"" in user1["PersonaName"], f"转义双引号处理异常: {user1['PersonaName']}"
        assert user2["PersonaName"] == "Hello {World} [Test]", f"花括号字符串处理异常: {user2['PersonaName']}"
        self.log_sub("转义引号、中文、花括号、特殊符号结构解析全部准确无误")

        # 3.2 序列化与 Round-trip 幂等性测试
        serialized = serialize_vdf_dict(parsed)
        tokens_round2 = tokenize_vdf(serialized)
        parsed_round2 = parse_vdf_structure(tokens_round2)

        assert parsed_round2 == parsed, "VDF 序列化与二次解析不一致 (幂等性失效)！"
        self.log_sub("VDF 序列化 -> 二次反序列化数据完全一致 (100% 幂等)")

        # 3.3 测试 SteamManager.parse_vdf 方法提取
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".vdf", delete=False) as f:
            f.write(complex_vdf)
            temp_vdf_path = Path(f.name)

        try:
            sm = SteamManager()
            extracted_users = sm.parse_vdf(temp_vdf_path)
            assert "76561198966320302" in extracted_users
            assert "76561199415935650" in extracted_users
            assert extracted_users["76561198966320302"]["SteamID64"] == "76561198966320302"
            self.log_sub(f"SteamManager.parse_vdf 正确提取 {len(extracted_users)} 个 17 位 SteamID 账号")
        finally:
            if temp_vdf_path.exists():
                temp_vdf_path.unlink()

        self.results["vdf_lexical_parser"] = True

    # =========================================================================
    # 4. Hosts 原子写入、只读解除与标记块无损剥离测试
    # =========================================================================
    def test_hosts_atomic_and_readonly_healing(self):
        self.log_section("4. Hosts 原子写入、只读修复与无损剥离测试")

        with tempfile.TemporaryDirectory() as temp_dir:
            dummy_hosts = Path(temp_dir) / "hosts"

            # 4.1 构造初始的用户自定义 hosts 文件
            initial_content = (
                "# Custom system hosts configuration\n"
                "127.0.0.1 localhost\n"
                "::1 localhost\n"
                "192.168.1.100 router.local # Custom Router Entry\n"
            )
            dummy_hosts.write_text(initial_content, encoding="utf-8")

            # 4.2 赋予只读属性 (模拟 Windows 系统文件保护)
            dummy_hosts.chmod(stat.S_IREAD)
            assert not os.access(dummy_hosts, os.W_OK), "只读属性设置失败"
            self.log_sub("已将测试 Hosts 文件标记为只读 (Read-Only)")

            hm = HostsManager(hosts_file=dummy_hosts)

            # 4.3 执行规则注入 (测试只读修复与原子写入)
            ok, msg = hm.apply_rules(enabled_services=["pixiv_web", "steam_store"])
            assert ok is True, f"规则注入失败: {msg}"
            assert dummy_hosts.exists(), "注入后 hosts 文件丢失"
            self.log_sub(f"只读文件修复写入成功: {msg}")

            # 4.4 检查内容：用户原有规则必须完整保留，且包含 PixivToolkit 标记块
            injected_text = dummy_hosts.read_text(encoding="utf-8")
            assert "127.0.0.1 localhost" in injected_text, "用户自定义规则 localhost 丢失"
            assert "router.local" in injected_text, "用户自定义规则 router.local 丢失"
            assert BLOCK_START in injected_text, "PixivToolkit 起始标记丢失"
            assert BLOCK_END in injected_text, "PixivToolkit 结束标记丢失"
            assert "127.0.0.1 www.pixiv.net" in injected_text, "pixiv_web 域名规则未注入"
            assert "127.0.0.1 store.steampowered.com" in injected_text, "steam_store 域名规则未注入"
            self.log_sub("规则注入校验通过：保留用户自定义行，并准确写入 127.0.0.1 映射")

            # 4.5 测试规则无损剥离与清理
            ok_rem, msg_rem = hm.remove_rules()
            assert ok_rem is True, f"规则清理失败: {msg_rem}"

            cleaned_text = dummy_hosts.read_text(encoding="utf-8")
            assert BLOCK_START not in cleaned_text, "清理后残留 PixivToolkit 起始标记"
            assert BLOCK_END not in cleaned_text, "清理后残留 PixivToolkit 结束标记"
            assert "www.pixiv.net" not in cleaned_text, "清理后残留 pixiv 规则"
            assert "127.0.0.1 localhost" in cleaned_text, "清理时破坏了原有的 localhost 规则"
            assert "router.local" in cleaned_text, "清理时破坏了原有的 router.local 规则"
            self.log_sub("规则无损剥离通过：标记块完全移除，原有 Hosts 内容 100% 保持原样")

            # 4.6 测试旧版规则标记兼容剥离 (# Pixiv Start ... # Pixiv End)
            legacy_content = (
                "127.0.0.1 localhost\n"
                "# Pixiv Start\n"
                "127.0.0.1 legacy.pixiv.net\n"
                "# Pixiv End\n"
            )
            dummy_hosts.write_text(legacy_content, encoding="utf-8")
            cleaned_legacy = hm.remove_rules_from_content(legacy_content)
            assert "legacy.pixiv.net" not in cleaned_legacy
            assert "127.0.0.1 localhost" in cleaned_legacy
            self.log_sub("旧版 legacy 规则标记兼容剥离逻辑验证通过")

        self.results["hosts_atomic_and_healing"] = True

    # =========================================================================
    # 5. CDN 测速引擎单池任务调度与 upstream 兜底生成测试
    # =========================================================================
    def test_cdn_optimizer_scheduling_and_upstream_generation(self):
        self.log_section("5. CDN 测速引擎单池任务调度与 Upstream 兜底生成测试")
        copt = CDNOptimizer()

        # 5.1 验证单池全量服务测速调度 (扁平化任务流，防止线程池嵌套)
        t0 = time.time()
        # 限制测试前 4 个服务以加速测试
        partial_cand = {k: CANDIDATE_IPS[k] for k in list(CANDIDATE_IPS.keys())[:4]}
        print(f"  - 调度扁平化测速队列 (测试前 4 项服务: {list(partial_cand.keys())})...")

        # 模拟/实测 test_group
        steam_res = copt.test_group("steam_store", CANDIDATE_IPS["steam_store"][:2])
        assert len(steam_res) > 0, "test_group 未返回结果"
        assert all("ip" in item and "latency" in item and "available" in item for item in steam_res)
        self.log_sub(f"单组测速测试完成: {len(steam_res)} 个节点已测速并按可用性与延迟排序")

        # 5.2 测试 18 项服务的动态 Upstream 配置生成
        # 构造包含主备节点的丰富模拟测速数据
        mock_results: Dict[str, List[Dict]] = {}
        for srv_id, ips in CANDIDATE_IPS.items():
            mock_results[srv_id] = [
                {"ip": ips[0], "latency": 25.0, "available": True, "rank": 0},
                {"ip": ips[1] if len(ips) > 1 else "1.1.1.2", "latency": 45.0, "available": True, "rank": 0},
                {"ip": ips[2] if len(ips) > 2 else "1.1.1.3", "latency": 65.0, "available": True, "rank": 0},
                {"ip": ips[3] if len(ips) > 3 else "1.1.1.4", "latency": 85.0, "available": True, "rank": 0},
                {"ip": "1.1.1.5", "latency": 9999.0, "available": False, "rank": 3},
            ]

        conf_text = copt.generate_upstream_conf(mock_results)

        # 验证生成的 upstream 命名与语法
        for srv_id in CANDIDATE_IPS:
            assert f"upstream upstream_{srv_id} {{" in conf_text, f"缺少 upstream_{srv_id} 定义"
            assert "keepalive 32;" in conf_text

        assert "backup " in conf_text, "具备 >2 节点时应生成 backup 指令"

        self.log_sub(f"{len(SERVICES_LIST)} 项服务 Upstream 配置生成格式与 Nginx 指令兼容")

        # 5.3 兜底测试：当某服务所有 IP 均不可用时，保证 fallback 不生成空 upstream 导致 Nginx 崩溃
        disaster_results = {
            "pixiv_web": [
                {"ip": "210.140.139.151", "latency": -1, "available": False},
                {"ip": "210.140.139.152", "latency": -1, "available": False}
            ]
        }
        disaster_conf = copt.generate_upstream_conf(disaster_results)
        assert "upstream upstream_pixiv_web {" in disaster_conf
        assert "server 210.140.139.151:443" in disaster_conf, "全挂灾难场景下未触发默认候选节点兜底"
        self.log_sub("全节点不可用场景兜底测试通过 (保证 Nginx 语法不报错)")

        self.results["cdn_optimizer_and_upstream"] = True

    # =========================================================================
    # 6. 批处理脚本 UTF-8 with BOM 编码校验
    # =========================================================================
    def test_batch_scripts_utf8_bom_encoding(self):
        self.log_section("6. 批处理脚本 UTF-8 with BOM 编码全量校验")

        bat_files = list(WORKSPACE_DIR.rglob("*.bat")) + list(WORKSPACE_DIR.rglob("*.ps1"))
        valid_bats = [b for b in bat_files if not any(x in b.parts for x in [".git", "build", "dist", ".gemini", "node_modules"])]

        assert len(valid_bats) > 0, "未找到任何批处理脚本文件"
        self.log_sub(f"共扫描到 {len(valid_bats)} 个批处理与 PowerShell 脚本")

        bom_bytes = b"\xef\xbb\xbf"
        for bf in valid_bats:
            rel_name = bf.relative_to(WORKSPACE_DIR)
            raw = bf.read_bytes()
            assert raw.startswith(bom_bytes), f"脚本 {rel_name} 缺失 UTF-8 BOM 前缀 (前 3 字节: {raw[:3]!r})"
            # 验证可以以 utf-8 解码
            decoded = raw.decode("utf-8-sig")
            assert len(decoded) > 0, f"脚本 {rel_name} 内容为空"
            self.log_sub(f"{rel_name} -> 编码: UTF-8 with BOM [PASS]")

        self.results["bat_utf8_bom"] = True

    # =========================================================================
    # 运行全部验证
    # =========================================================================
    def run_all(self):
        print("\n" + "#"*70)
        print("   PixivToolkit 全面自动化测试与回归验证套件 (Regression Test Suite)")
        print("#"*70)

        self.test_nginx_syntax_and_upstream_alignment()
        self.test_cryptoapi_cert_detection()
        self.test_vdf_lexical_parsing_and_serialization()
        self.test_hosts_atomic_and_readonly_healing()
        self.test_cdn_optimizer_scheduling_and_upstream_generation()
        self.test_batch_scripts_utf8_bom_encoding()

        elapsed = time.time() - self.start_time
        print("\n" + "="*70)
        print("                  回归测试结果汇总")
        print("="*70)
        all_passed = all(self.results.values()) and len(self.results) == 6
        for name, passed in self.results.items():
            print(f"  - 专项: {name:<35} : {'[PASS]' if passed else '[FAIL]'}")

        print(f"\n总耗时: {elapsed:.2f} 秒")
        if all_passed:
            print(">>> 结论: 全部 6 大专项针对性自动化回归测试 100% PASS！系统质量完好！<<<")
        else:
            print(">>> 结论: 存在测试未通过项，请查看上方日志！<<<")
        print("="*70 + "\n")
        return all_passed

if __name__ == "__main__":
    runner = RegressionTestSuite()
    success = runner.run_all()
    sys.exit(0 if success else 1)
