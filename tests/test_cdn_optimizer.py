# -*- coding: utf-8 -*-
"""
PixivToolkit - 代理链路修复专项回归测试集

覆盖本轮修复的核心行为(全部使用临时目录与本地 mock, 严禁触碰真实配置文件):
1. test_service_dual 双通道探测接口与返回结构
2. _classify_result rank 分级(修复: HTTP 阶段超时不得误判 rank0)
3. _suspect_status 可疑状态码判定
4. probe_ip_endpoint_v2 经本地 mock CONNECT 代理隧道的三态探测
5. generate_upstream_conf 增量合并(未测速服务保留旧 upstream 块)
6. apply_optimal 交叉校验失败路径(引用缺失 upstream 时报错)
7. CDNHealthMonitor.check_and_heal_service 自愈流程(失败计数与连续失败触发)
8. check_proxy_alive 双重验证(TCP 探活 + CONNECT 握手)
"""

import sys
import time
import socket
import threading
from pathlib import Path
from typing import List, Optional

import pytest
from unittest.mock import patch

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

APP_DIR = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP_DIR))

from cdn_optimizer import (
    CDNOptimizer,
    CDNHealthMonitor,
    probe_ip_endpoint_v2,
    _classify_result,
    _suspect_status,
)
from win_utils import check_proxy_alive


# ==============================================================================
# 本地 mock HTTP CONNECT 代理 (线程安全, context 生命周期由 fixture 管理)
# ==============================================================================
class MockConnectProxy:
    """本地 mock HTTP CONNECT 代理

    - 监听 127.0.0.1 空闲端口, 收到 CONNECT 请求后按配置的响应行回复
    - 记录所有 CONNECT 请求的目标 host:port(供断言隧道是否真正建立)
    - 响应后保持连接 hold_time 秒再关闭(模拟真实代理的隧道生命周期)
    """

    def __init__(self, response_line: str = "HTTP/1.1 200 Connection established",
                 hold_time: float = 0.1, record: Optional[List[str]] = None):
        self.response_line = response_line
        self.hold_time = hold_time
        self.record = record if record is not None else []
        self.port: Optional[int] = None
        self._listen = None
        self._thread = None
        self._conn_threads: List[threading.Thread] = []

    def start(self) -> "MockConnectProxy":
        self._listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen.bind(("127.0.0.1", 0))
        self._listen.listen(8)
        self.port = self._listen.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True, name="MockConnectProxy")
        self._thread.start()
        return self

    def _serve(self):
        while True:
            try:
                conn, _ = self._listen.accept()
            except OSError:
                break  # 监听 socket 关闭, 退出
            t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            self._conn_threads.append(t)
            t.start()

    def _handle(self, conn):
        try:
            conn.settimeout(5.0)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            first = data.split(b"\r\n", 1)[0].decode("utf-8", "replace")
            if first.startswith("CONNECT "):
                # CONNECT host:port HTTP/1.1 -> 记录 "host:port"
                self.record.append(first.split(" ", 2)[1])
            conn.sendall(f"{self.response_line}\r\n\r\n".encode("utf-8"))
            time.sleep(self.hold_time)  # 短暂保持隧道, 让客户端完成响应读取
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def stop(self):
        if self._listen:
            try:
                self._listen.close()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        for t in self._conn_threads:
            t.join(timeout=0.5)


@pytest.fixture
def mock_proxy():
    """启动一个返回 200 的 mock CONNECT 代理, 测试结束后关闭"""
    proxy = MockConnectProxy()
    proxy.start()
    yield proxy
    proxy.stop()


def _find_free_port() -> int:
    """获取一个当前空闲的本地端口(用于死端口探测)"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_silent_server():
    """启动一个监听但不响应任何数据的 TCP 服务, 返回 (port, cleanup)"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def _drain(c):
        try:
            c.recv(4096)  # 收下请求但不回复
        except Exception:
            pass
        finally:
            try:
                c.close()
            except Exception:
                pass

    def _serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            t = threading.Thread(target=_drain, args=(conn,), daemon=True)
            t.start()

    th = threading.Thread(target=_serve, daemon=True)
    th.start()

    def _cleanup():
        stop.set()
        try:
            srv.close()
        except Exception:
            pass
        th.join(timeout=1.0)

    return port, _cleanup


# ==============================================================================
# 1. test_service_dual 存在性 (本地 mock CONNECT 代理 + 不可达目标)
# ==============================================================================
class TestServiceDual:
    def test_service_dual_returns_list_with_full_fields(self, mock_proxy):
        """test_service_dual 存在且经双通道探测返回结构完整的 list"""
        opt = CDNOptimizer()
        # 240.0.0.1 (保留网段) 在本机环境稳定返回 "网络不可达", 用于模拟双通道全挂
        unreachable = "240.0.0.1"
        with patch("cdn_optimizer.CANDIDATE_IPS", {"steam_store": [unreachable]}), \
             patch("cdn_optimizer._load_proxy_config", return_value=("127.0.0.1", mock_proxy.port)), \
             patch("cdn_optimizer.is_proxy_available", return_value=True):
            results = opt.test_service_dual("steam_store", max_workers=2)

        assert isinstance(results, list)
        assert len(results) == 1
        item = results[0]
        # 返回结构必须包含完整 rank 字段
        for key in ("ip", "rank", "latency", "available", "via_proxy", "recommend",
                    "sni_mode", "proxy_used", "direct", "proxy"):
            assert key in item, f"返回项缺少字段: {key}"
        assert item["ip"] == unreachable
        # 直连不可达 + 代理隧道后 TLS 无法完成 -> 双通道全挂 -> rank3
        assert item["rank"] == 3
        assert item["available"] is False
        assert item["proxy_used"] is True
        # 代理确实收到了对不可达目标的 CONNECT 隧道请求
        assert f"{unreachable}:443" in mock_proxy.record


# ==============================================================================
# 2. _classify_result rank 分级 (本次修复点: HTTP 阶段超时不得误判 rank0)
# ==============================================================================
def _probe_dict(tcp: bool = True, tls: bool = True, http_ok: bool = True,
                status: Optional[int] = 200, latency: float = 10.0) -> dict:
    """构造一条链路探测结果字典"""
    return {"tcp_ok": tcp, "tcp_latency": latency, "tls_ok": tls, "tls_latency": 20.0,
            "http_ok": http_ok, "http_status": status, "error": ""}


class TestClassifyResult:
    def test_direct_clean_rank0(self):
        """TCP+TLS 通 + HTTP 200 -> rank0 直连首选"""
        item = _classify_result(_probe_dict(), None)
        assert item["rank"] == 0
        assert item["via_proxy"] is False
        assert item["recommend"] == "direct"
        assert item["available"] is True
        assert item["latency"] == 10.0

    def test_http_timeout_not_rank0(self):
        """TCP+TLS 通但 HTTP 阶段超时(http_ok=False/http_status=None) -> 不得 rank0(修复点)"""
        direct = _probe_dict(http_ok=False, status=None)
        item = _classify_result(direct, None)
        assert item["rank"] != 0, "HTTP 阶段超时的节点被误判为 rank0"
        assert item["rank"] == 3
        assert item["available"] is False

    def test_http_500_exempt_rank0(self):
        """HTTP 500 豁免(githubassets 根路径) -> 仍 rank0"""
        item = _classify_result(_probe_dict(status=500), None)
        assert item["rank"] == 0
        assert item["recommend"] == "direct"

    @pytest.mark.parametrize("status", [421, 502, 503, 504])
    def test_suspect_direct_downgraded_to_proxy(self, status):
        """直连 HTTP 可疑(421/502-504) -> 直连非 rank0, 代理干净路径降级为 rank1"""
        direct = _probe_dict(status=status)
        proxy = _probe_dict(latency=5.0)  # 代理链路干净(200)
        item = _classify_result(direct, proxy)
        assert item["rank"] == 1
        assert item["via_proxy"] is True
        assert item["recommend"] == "proxy"

    def test_direct_fail_proxy_ok_rank1(self):
        """直连失败 + 代理 TCP+TLS+HTTP200 全通 -> rank1 via_proxy"""
        direct = _probe_dict(tcp=False, http_ok=False, status=None)
        direct["error"] = "tcp:timed out"
        proxy = _probe_dict(latency=5.0)
        item = _classify_result(direct, proxy)
        assert item["rank"] == 1
        assert item["via_proxy"] is True
        assert item["recommend"] == "proxy"
        assert item["available"] is True

    def test_proxy_suspect_rank2(self):
        """直连失败 + 代理可疑(5xx/421) -> rank2 仅兜底"""
        direct = _probe_dict(tcp=False, http_ok=False, status=None)
        proxy = _probe_dict(latency=5.0, status=502)
        item = _classify_result(direct, proxy)
        assert item["rank"] == 2
        assert item["available"] is True


# ==============================================================================
# 3. _suspect_status
# ==============================================================================
class TestSuspectStatus:
    @pytest.mark.parametrize("status", [421, 502, 503, 504])
    def test_suspect_status_true(self, status):
        assert _suspect_status(status) is True

    @pytest.mark.parametrize("status", [200, 500, 404, 301, None])
    def test_suspect_status_false(self, status):
        assert _suspect_status(status) is False


# ==============================================================================
# 4. probe_ip_endpoint_v2 经本地 mock CONNECT 代理隧道
# ==============================================================================
class TestProbeViaProxy:
    def test_proxy_tunnel_tcp_ok_tls_fail(self, mock_proxy):
        """CONNECT 200 -> tcp_ok=True; 隧道后对不可达目标 TLS 无法完成 -> tls_ok=False"""
        res = probe_ip_endpoint_v2(
            "240.0.0.1", domain="store.steampowered.com", sni_mode="host",
            proxy=("127.0.0.1", mock_proxy.port), timeout=1.0)
        assert res["tcp_ok"] is True, f"CONNECT 成功后 tcp_ok 应为 True: {res}"
        assert isinstance(res["tcp_latency"], (int, float)), "tcp_latency 应为数值"
        assert res["tls_ok"] is False, "隧道后 TLS 无法完成, tls_ok 应为 False"
        assert "tls" in res["error"], f"error 应包含 tls 信息: {res['error']}"
        assert "240.0.0.1:443" in mock_proxy.record, "代理未收到目标 CONNECT 请求"

    def test_proxy_reject_tunnel_tcp_fail(self):
        """mock 代理返回非 200(407) -> CONNECT 隧道建立失败 -> tcp_ok=False"""
        proxy = MockConnectProxy(response_line="HTTP/1.1 407 Proxy Authentication Required")
        proxy.start()
        try:
            res = probe_ip_endpoint_v2("240.0.0.1", proxy=("127.0.0.1", proxy.port), timeout=1.0)
            assert res["tcp_ok"] is False
            assert "tcp" in res["error"]
            assert res["tls_ok"] is False
        finally:
            proxy.stop()


# ==============================================================================
# 5. generate_upstream_conf 增量合并 (R6)
# ==============================================================================
class TestIncrementalMerge:
    OLD_CONF = (
        "upstream upstream_steam_store {\n"
        "    # 警告: 服务 steam_store 双通道探测全部失败, 回退候选池兜底\n"
        "    server 1.1.1.1:443 max_fails=3 fail_timeout=30s;\n"
        "    server 1.1.1.2:443 backup max_fails=3 fail_timeout=30s;\n"
        "    keepalive 32;\n"
        "    keepalive_timeout 120;\n"
        "    keepalive_requests 10000;\n"
        "}\n"
        "\n"
        "upstream upstream_github_web {\n"
        "    # 警告: 服务 github_web 双通道探测全部失败, 回退候选池兜底\n"
        "    server 9.9.9.9:443 max_fails=3 fail_timeout=30s;\n"
        "    server 8.8.4.4:443 backup max_fails=3 fail_timeout=30s;\n"
        "    keepalive 32;\n"
        "    keepalive_timeout 120;\n"
        "    keepalive_requests 10000;\n"
        "}\n"
    )

    def _make_optimizer(self, tmp_path):
        conf_dir = tmp_path / "conf"
        conf_dir.mkdir()
        conf_path = conf_dir / "upstream-dynamic.conf"
        conf_path.write_text(self.OLD_CONF, encoding="utf-8")
        return CDNOptimizer(conf_path), conf_path

    def test_incremental_merge_keeps_unmeasured_service(self, tmp_path):
        """只测 github_web: steam_store 旧块完整保留, github_web 更新为新 IP, 旧兜底被替换"""
        opt, conf_path = self._make_optimizer(tmp_path)
        new_results = {"github_web": [{"ip": "8.8.8.8", "rank": 0, "latency": 5.0}]}

        # 1. generate_upstream_conf 生成的字符串即包含增量合并结果
        conf_str = opt.generate_upstream_conf(new_results)
        assert "upstream upstream_steam_store {" in conf_str
        assert "server 1.1.1.1:443" in conf_str
        assert "server 1.1.1.2:443 backup" in conf_str
        assert "server 8.8.8.8:443" in conf_str
        assert "server 9.9.9.9:443" not in conf_str, "github_web 旧兜底未被替换"
        assert "server 8.8.4.4:443" not in conf_str, "github_web 旧兜底未被替换"

        # 2. apply_optimal 写入后文件内容与生成结果一致
        ok, msg = opt.apply_optimal(new_results)
        assert ok, msg
        new_text = conf_path.read_text(encoding="utf-8")
        # steam_store 旧块完整保留(含 fallback 警告注释)
        assert "upstream upstream_steam_store {" in new_text
        assert "回退候选池兜底" in new_text
        assert "server 1.1.1.1:443" in new_text
        # github_web 更新为新 IP, 旧兜底 IP 消失
        assert "server 8.8.8.8:443 max_fails=3 fail_timeout=30s" in new_text
        assert "server 9.9.9.9:443" not in new_text


# ==============================================================================
# 6. apply_optimal 交叉校验失败路径
# ==============================================================================
class TestApplyOptimalCrossCheck:
    def test_missing_upstream_ref_rejected(self, tmp_path):
        """site conf 引用不存在的 upstream -> apply_optimal 返回 (False, 含'缺失'的 msg), 不写文件"""
        conf_dir = tmp_path / "conf"
        conf_dir.mkdir()
        (conf_dir / "site-gaming.conf").write_text(
            "location / {\n    proxy_pass https://upstream_nonexist;\n}\n",
            encoding="utf-8")
        conf_path = conf_dir / "upstream-dynamic.conf"
        opt = CDNOptimizer(conf_path)

        ok, msg = opt.apply_optimal({"github_web": [{"ip": "8.8.8.8", "rank": 0, "latency": 5.0}]})
        assert ok is False, "引用缺失 upstream 时 apply_optimal 应失败"
        assert "缺失" in msg, f"失败消息应包含'缺失': {msg}"
        assert "upstream_nonexist" in msg
        assert not conf_path.exists(), "校验失败时不应写入 upstream-dynamic.conf"


# ==============================================================================
# 7. check_and_heal_service 自愈流程 (stub optimizer 注入)
# ==============================================================================
class FakeOptimizer:
    """最小 stub: 记录 test_service_dual / apply_optimal 调用次数"""

    def __init__(self):
        self.apply_calls = 0
        self.dual_calls = 0
        self.current = [{"ip": "10.255.255.1", "rank": 0, "available": True, "latency": 5.0}]

    def test_service_dual(self, srv_id, max_workers=8):
        self.dual_calls += 1
        return self.current

    def apply_optimal(self, results):
        self.apply_calls += 1
        return True, "ok"


def _make_monitor(fake: FakeOptimizer) -> CDNHealthMonitor:
    monitor = CDNHealthMonitor(fake)
    monitor.update_services(["github_web"], {"github_web": fake.current})
    return monitor


class TestHealthHeal:
    def test_healthy_no_heal(self):
        """主力节点健康(tls_ok=True) -> 不自愈, 不重测, 失败计数清零"""
        fake = FakeOptimizer()
        monitor = _make_monitor(fake)
        with patch("cdn_optimizer.probe_ip_endpoint_v2",
                   return_value={"tls_ok": True, "tcp_ok": True, "http_ok": True}):
            assert monitor.check_and_heal_service("github_web") is False
            assert monitor.failure_counts.get("github_web", 0) == 0
            assert fake.dual_calls == 0
            assert fake.apply_calls == 0

    def test_failure_counts_accumulate_then_heal(self):
        """连续 2 次失败 -> 触发自愈重测并 apply_optimal, 失败计数复位"""
        fake = FakeOptimizer()
        monitor = _make_monitor(fake)
        dead = {"tls_ok": False, "tcp_ok": True, "http_ok": False}

        with patch("cdn_optimizer.probe_ip_endpoint_v2", return_value=dead):
            # 第 1 次: 失败计数 1, 未达阈值
            ok1, healed1 = monitor.run_health_check_cycle()
            assert ok1 is False and healed1 == []
            assert monitor.failure_counts["github_web"] == 1
            assert fake.dual_calls == 0

            # 第 2 次: 连续失败触发自愈
            ok2, healed2 = monitor.run_health_check_cycle()
            assert ok2 is True and healed2 == ["github_web"]
            assert fake.dual_calls == 1, "自愈应触发单服务重测"
            assert fake.apply_calls == 1, "自愈后应调用 apply_optimal 重渲染配置"
            assert monitor.failure_counts["github_web"] == 0, "自愈后失败计数应复位"


# ==============================================================================
# 8. check_proxy_alive 双重验证
# ==============================================================================
class TestCheckProxyAlive:
    def test_dead_port_false(self):
        """死端口 -> False"""
        assert check_proxy_alive("127.0.0.1", _find_free_port(), timeout=0.3) is False

    def test_mock_connect_proxy_true(self, mock_proxy):
        """mock CONNECT 代理(返回 200) -> True"""
        assert check_proxy_alive("127.0.0.1", mock_proxy.port, timeout=0.5) is True

    def test_garbage_response_false(self):
        """普通 TCP 服务返回垃圾数据(非 HTTP 代理) -> False"""
        proxy = MockConnectProxy(response_line="HELLO WORLD", hold_time=0.05)
        proxy.start()
        try:
            assert check_proxy_alive("127.0.0.1", proxy.port, timeout=0.5) is False
        finally:
            proxy.stop()

    def test_silent_tcp_service_false(self):
        """普通 TCP 服务不响应 CONNECT -> False"""
        port, cleanup = _start_silent_server()
        try:
            assert check_proxy_alive("127.0.0.1", port, timeout=0.5) is False
        finally:
            cleanup()
