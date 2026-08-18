# -*- coding: utf-8 -*-
"""
PixivToolkit - 高并发 CDN 测速与动态 Upstream 优选引擎 (双通道三态探测)

核心改进:
- 双通道探测: 直连 + 经本地代理(默认 127.0.0.1:7897 Clash mixed) HTTP CONNECT 隧道
- 三态验证: TCP 握手 → TLS 握手(按服务 SNI 模式) → HTTP 状态码, 排除"TCP 通但 TLS 被阻断"的假可用节点
- rank 分级: 0=直连可用 1=经代理验证的真节点 2=代理可疑(5xx/421) 3=不可用(不入选)
- 代理仅作"节点筛选器", 最终写入 nginx 的仍是直连 IP
"""

import sys
import time
import socket
import ssl
import re
import concurrent.futures
import threading
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Callable, Any

from path_utils import NGINX_DIR
from ip_pool import CANDIDATE_IPS, SERVICES_BY_ID
from config_store import load_config

UPSTREAM_CONF_PATH = NGINX_DIR / "conf" / "upstream-dynamic.conf"

# 默认本地代理 (Clash mixed 端口, HTTP CONNECT 隧道, 仅作探测筛选)
DEFAULT_PROXY = ("127.0.0.1", 7897)

from service_profile import PROFILES

# 各服务的 SNI 模式自动由 ServiceProfile 单源导出
SNI_MODES = {p.id: p.ssl_sni_mode for p in PROFILES}

# nginx.conf include 的有效站点配置 (site-tools.conf 服务已全部删除)
SITE_CONF_NAMES = ["site-gaming.conf", "site-acg.conf", "site-dev.conf"]


def _load_proxy_config() -> Optional[Tuple[str, int]]:
    """读取 config.json 的 upstream_proxy 配置, 返回 (host, port); 显式禁用或异常时返回 None"""
    try:
        cfg = load_config().get("upstream_proxy", {})
        if not cfg.get("enabled", True):
            return None
        return (str(cfg.get("host", DEFAULT_PROXY[0])), int(cfg.get("port", DEFAULT_PROXY[1])))
    except Exception:
        return DEFAULT_PROXY


def is_proxy_available(proxy: Optional[Tuple[str, int]], timeout: float = 0.3) -> bool:
    """预检本地代理端口是否可达"""
    if not proxy:
        return False
    try:
        with socket.create_connection(proxy, timeout=timeout):
            return True
    except Exception:
        return False


def _send_connect_and_read_200(sock: socket.socket, host: str, port: int, timeout: float) -> None:
    """向 HTTP 代理发送 CONNECT 隧道请求并读取响应头, 首行非 200 抛异常"""
    sock.settimeout(timeout)
    sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode("utf-8"))
    hdr = b""
    while b"\r\n\r\n" not in hdr:
        chunk = sock.recv(4096)
        if not chunk:
            break
        hdr += chunk
    line = hdr.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
    if " 200 " not in line:
        raise ConnectionError(f"CONNECT 隧道建立失败: {line or '无响应'}")


def _suspect_status(status: Optional[int]) -> bool:
    """HTTP 状态码是否表示"可疑节点" (网关错误 502-504 或 Cloudflare 421 重路由)

    注意: 500 豁免——部分服务(如 githubassets.com)对根路径返回 500 但节点真实可用
    """
    return status is not None and (status == 421 or 502 <= status <= 504)


def probe_ip_endpoint_v2(ip: str, domain: str = "", timeout: float = 1.5,
                         sni_mode: str = "host",
                         proxy: Optional[Tuple[str, int]] = None) -> Dict:
    """单链路三态探测: TCP → TLS(按 SNI 模式) → HTTP 状态码

    proxy=None 为直连; proxy=(host,port) 先经 HTTP CONNECT 隧道再探测。
    返回: tcp_ok/tcp_latency/tls_ok/tls_latency/http_ok/http_status/error
    """
    out = {"tcp_ok": False, "tcp_latency": None, "tls_ok": False,
           "tls_latency": None, "http_ok": False, "http_status": None, "error": ""}
    deadline = time.monotonic() + timeout * 3 + 2.0  # 总预算兜底, 防慢节点拖垮并发池

    # 1. TCP 握手 (直连或经 CONNECT 隧道)
    try:
        if proxy:
            t0 = time.perf_counter()
            sock = socket.create_connection(proxy, timeout=timeout)
            _send_connect_and_read_200(sock, ip, 443, timeout)
            out["tcp_latency"] = round((time.perf_counter() - t0) * 1000.0, 1)
        else:
            t0 = time.perf_counter()
            sock = socket.create_connection((ip, 443), timeout=timeout)
            out["tcp_latency"] = round((time.perf_counter() - t0) * 1000.0, 1)
        out["tcp_ok"] = True
    except Exception as e:
        out["error"] = f"tcp:{e}"
        return out

    # 2. TLS 握手 (宽松校验: 本地证书链不可信, 以握手成功 + HTTP 状态码佐证真实性)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # 复刻 nginx 的 SNI 行为: empty=空SNI host=域名SNI 其他=自定义伪SNI域名
        if sni_mode == "host":
            server_hostname = domain or None
        elif sni_mode == "empty":
            server_hostname = None
        else:
            server_hostname = sni_mode
        sock.settimeout(max(deadline - time.monotonic(), 0.5))
        t0 = time.perf_counter()
        ssock = ctx.wrap_socket(sock, server_hostname=server_hostname)
        out["tls_ok"] = True
        out["tls_latency"] = round((time.perf_counter() - t0) * 1000.0, 1)
    except Exception as e:
        out["error"] = f"tls:{e}"
        try:
            sock.close()
        except Exception:
            pass
        return out

    # 3. HTTP 状态码探测 (5xx/421 仍记 http_ok=True, 由调用方判定 suspect)
    try:
        ssock.settimeout(max(deadline - time.monotonic(), 0.5))
        ssock.sendall(f"GET / HTTP/1.1\r\nHost: {domain}\r\n"
                      f"User-Agent: PixivToolkit/1.0\r\nConnection: close\r\n\r\n".encode("utf-8"))
        hdr = b""
        while b"\r\n\r\n" not in hdr:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            hdr += chunk
        line = hdr.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                out["http_status"] = int(parts[1])
                out["http_ok"] = True
    except Exception as e:
        out["error"] = f"http:{e}"
    finally:
        try:
            ssock.close()
        except Exception:
            pass
    return out


def _classify_result(direct: Dict, proxy: Dict) -> Dict:
    """合并直连与代理两条链路结果, 输出 rank/via_proxy/recommend/latency 等扁平字段

    rank 0: 直连 TCP+TLS 通且 HTTP 无 5xx/421 → 首选 (写主节点)
    rank 1: 经代理 TCP+TLS 通且 HTTP 干净 → 真实节点 (写备节点)
    rank 2: 经代理 TCP+TLS 通但 HTTP 可疑 (5xx/421) → 仅兜底
    rank 3: 双通道全挂 → 不写入
    """
    d_clean = bool(direct and direct.get("tcp_ok") and direct.get("tls_ok")
                   and direct.get("http_ok") and not _suspect_status(direct.get("http_status")))
    p_clean = bool(proxy and proxy.get("tcp_ok") and proxy.get("tls_ok")
                   and proxy.get("http_ok") and not _suspect_status(proxy.get("http_status")))
    p_suspect = bool(proxy and proxy.get("tcp_ok") and proxy.get("tls_ok")
                     and proxy.get("http_ok") and _suspect_status(proxy.get("http_status")))

    item = {"latency": None, "available": False, "rank": 3,
            "via_proxy": False, "recommend": "none", "sni_mode": "host",
            "direct": direct, "proxy": proxy, "proxy_used": bool(proxy)}
    if d_clean:
        item.update(rank=0, via_proxy=False, recommend="direct", available=True,
                    latency=direct.get("tcp_latency"))
    elif p_clean:
        item.update(rank=1, via_proxy=True, recommend="proxy", available=True,
                    latency=(proxy.get("tcp_latency") or 0) + (proxy.get("tls_latency") or 0))
    elif p_suspect:
        item.update(rank=2, via_proxy=True, recommend="proxy", available=True,
                    latency=(proxy.get("tcp_latency") or 0) + (proxy.get("tls_latency") or 0))
    return item


class CDNOptimizer:
    def __init__(self, conf_path: Path = UPSTREAM_CONF_PATH):
        self.conf_path = Path(conf_path)

    def test_service_dual(self, srv_id: str, max_workers: int = 8) -> List[Dict]:
        """单服务双通道探测 (直连 + 经本地代理 CONNECT 隧道, 供健康巡检自愈调用)"""
        ips = CANDIDATE_IPS.get(srv_id, [])
        return self.test_group(srv_id, ips, max_workers=max_workers)

    def test_group(self, group_name: str, ip_list: List[str], max_workers: int = 8) -> List[Dict]:
        """测试指定服务的一组候选 IP (双通道三态探测)"""
        srv = SERVICES_BY_ID.get(group_name, {})
        domain = srv.get("domains", [""])[0] if srv else ""
        sni_mode = SNI_MODES.get(group_name, "host")
        proxy = _load_proxy_config()
        proxy_ready = is_proxy_available(proxy)
        if not proxy_ready:
            proxy = None

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            def run_one(ip):
                direct = probe_ip_endpoint_v2(ip, domain, sni_mode=sni_mode, proxy=None)
                proxy_res = probe_ip_endpoint_v2(ip, domain, sni_mode=sni_mode, proxy=proxy) if proxy else None
                return ip, direct, proxy_res

            future_to_ip = {executor.submit(run_one, ip): ip for ip in ip_list}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    ret_ip, direct, proxy_res = future.result()
                    item = _classify_result(direct, proxy_res)
                    item["ip"] = ret_ip
                    item["sni_mode"] = sni_mode
                    item["proxy_used"] = proxy_ready
                except Exception:
                    item = {"ip": ip, "latency": None, "available": False, "rank": 3,
                            "via_proxy": False, "recommend": "none", "sni_mode": sni_mode,
                            "direct": None, "proxy": None, "proxy_used": proxy_ready}
                results.append(item)

        results.sort(key=lambda x: (x.get("rank", 3), x.get("latency") if x.get("latency") is not None else 99999))
        return results

    def test_all_services(self, max_workers: int = 16, total_timeout: float = 30.0,
                          filter_services: Optional[List[str]] = None) -> Dict[str, List[Dict]]:
        """全量/按需双通道探测: 直连 + 经本地代理 CONNECT 隧道, 三态验证后 rank 合并排序
        
        若指定 filter_services 则仅对指定服务进行并发网络探测，其他服务快速填充默认候选
        """
        proxy = _load_proxy_config()
        proxy_ready = is_proxy_available(proxy, timeout=0.5)
        if not proxy_ready:
            proxy = None

        target_set = set(filter_services) if filter_services is not None else None
        flat_tasks = []
        for srv_id, ips in CANDIDATE_IPS.items():
            if target_set is not None and srv_id not in target_set:
                continue
            srv = SERVICES_BY_ID.get(srv_id, {})
            domain = srv.get("domains", [""])[0] if srv else ""
            sni_mode = SNI_MODES.get(srv_id, "host")
            for ip in ips:
                flat_tasks.append((srv_id, ip, domain, sni_mode))

        results_by_srv: Dict[str, List[Dict]] = {srv_id: [] for srv_id in CANDIDATE_IPS}

        def run_both(task):
            srv_id, ip, domain, sni_mode = task
            direct = probe_ip_endpoint_v2(ip, domain, timeout=1.5, sni_mode=sni_mode, proxy=None)
            proxy_res = probe_ip_endpoint_v2(ip, domain, timeout=1.5, sni_mode=sni_mode, proxy=proxy) if proxy else None
            return srv_id, ip, direct, proxy_res

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(run_both, t): t for t in flat_tasks}
            try:
                for future in concurrent.futures.as_completed(future_map, timeout=total_timeout):
                    task = future_map[future]
                    try:
                        srv_id, ip, direct, proxy_res = future.result()
                        item = _classify_result(direct, proxy_res)
                        item["ip"] = ip
                        item["sni_mode"] = task[3]
                        item["proxy_used"] = proxy_ready
                    except Exception:
                        item = {"ip": task[1], "latency": None, "available": False, "rank": 3,
                                "via_proxy": False, "recommend": "none", "sni_mode": task[3],
                                "direct": None, "proxy": None, "proxy_used": proxy_ready}
                    results_by_srv[srv_id].append(item)
            except concurrent.futures.TimeoutError:
                pass

        # 补齐超时未完成项并排序 (rank 升序, latency 升序; rank 3 全部排最后)
        for srv_id, items in results_by_srv.items():
            done_ips = {it["ip"] for it in items}
            for expected_ip in CANDIDATE_IPS.get(srv_id, []):
                if expected_ip not in done_ips:
                    items.append({"ip": expected_ip, "latency": None, "available": False, "rank": 3,
                                  "via_proxy": False, "recommend": "none", "sni_mode": SNI_MODES.get(srv_id, "host"),
                                  "direct": None, "proxy": None, "proxy_used": proxy_ready})
            items.sort(key=lambda x: (x.get("rank", 3), x.get("latency") if x.get("latency") is not None else 99999))

        return results_by_srv

    def _load_existing_upstream_blocks(self) -> Dict[str, str]:
        """读取现有 upstream-dynamic.conf, 按服务提取已有 upstream 块 (供增量合并)"""
        blocks: Dict[str, str] = {}
        if not self.conf_path.exists():
            return blocks
        try:
            text = self.conf_path.read_text(encoding="utf-8", errors="ignore")
            pattern = re.compile(r"upstream\s+(upstream_[a-z0-9_]+)\s*\{.*?\n\}", re.S)
            for m in pattern.finditer(text):
                blocks[m.group(1)] = m.group(0)
        except Exception:
            pass
        return blocks

    @staticmethod
    def _fmt_server(ip: str, extra: str = "") -> str:
        """生成 upstream server 行: IPv6 地址必须加方括号 (nginx 语法要求), 行尾必须带分号"""
        if ":" in ip:
            return f"    server [{ip}]:443 {extra};".rstrip()
        return f"    server {ip}:443 {extra};".rstrip()

    def generate_upstream_conf(self, test_results: Dict[str, List[Dict]]) -> str:
        """根据 rank 分级结果生成延迟最低的 upstream-dynamic.conf

        规则:
        - 每个服务永远生成 upstream 块 (保证 nginx 引用不缺失, 防 host not found 启动失败)
        - 只写 rank0 (直连三态全通) 节点; rank1(经代理验证) 直连不可用, 不写入
        - 全挂服务回退候选池默认 IP, 并加注释告警 (宁可用假节点也绝不让 nginx 起不来)
        - max_fails=3 fail_timeout=30s 减缓熔断雪崩; hash/least_conn 组不携带 backup 参数
        """
        lines = [
            "# ==============================================================================",
            "# PixivToolkit - 动态 Upstream 优选配置 (由双通道测速引擎自动生成)",
            f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "# 仅写入 rank0 (直连三态全通) 节点, 排除假节点导致 502",
            "# max_fails=3 fail_timeout=30s 减缓节点熔断雪崩",
            "# ==============================================================================\n"
        ]

        # 读取现有配置用于增量合并: 未参与本次测速的服务保留其已有 upstream 块,
        # 避免单服务自愈/局部重测顺带把其余服务重置回候选池
        existing_blocks = self._load_existing_upstream_blocks()

        # 确保全量服务均生成 upstream 块 (若某服务未测速，则自动取 CANDIDATE_IPS 默认兜底)
        for srv_id in CANDIDATE_IPS:
            ip_items = test_results.get(srv_id)
            if not ip_items:
                old_block = existing_blocks.get(f"upstream_{srv_id}")
                if old_block:
                    lines.append(old_block + "\n")
                    continue
                ip_items = [{"ip": ip} for ip in CANDIDATE_IPS.get(srv_id, [])]

            # 只写 rank0 直连可用节点; 无 rank0 则回退候选池兜底 (保证 nginx 可启动)
            usable = [it for it in ip_items if it.get("rank", 3) == 0]
            fallback = not usable
            if not usable:
                usable = [{"ip": it["ip"]} for it in ip_items]

            # 防御性排序: 保证 rank0 在前、延迟升序, 不依赖调用方预排序
            usable.sort(key=lambda x: (x.get("rank", 3), x.get("latency") if x.get("latency") is not None else 99999))
            valid_ips = [it["ip"] for it in usable]
            primary_ips = valid_ips[:2]
            backup_ips = valid_ips[2:4]

            lines.append(f"upstream upstream_{srv_id} {{")
            if fallback:
                lines.append(f"    # 警告: 服务 {srv_id} 双通道探测全部失败, 回退候选池兜底")
            if srv_id == "pixiv_web":
                lines.append("    hash $connection consistent;")
                for ip in valid_ips[:6]:
                    lines.append(self._fmt_server(ip, "max_fails=3 fail_timeout=30s"))
            elif srv_id == "pixiv_img":
                lines.append("    least_conn;")
                for ip in valid_ips[:6]:
                    lines.append(self._fmt_server(ip, "max_fails=3 fail_timeout=30s"))
            else:
                for ip in primary_ips:
                    lines.append(self._fmt_server(ip, "max_fails=3 fail_timeout=30s"))
                for ip in backup_ips:
                    lines.append(self._fmt_server(ip, "backup max_fails=3 fail_timeout=30s"))

            lines.append("    keepalive 32;")
            lines.append("    keepalive_timeout 120;")
            lines.append("    keepalive_requests 10000;")
            lines.append("}\n")

        return "\n".join(lines)

    def _scan_site_upstream_refs(self) -> set:
        """扫描 nginx.conf 实际 include 的 site 配置, 提取所有 proxy_pass 引用的 upstream 名"""
        refs = set()
        for name in SITE_CONF_NAMES:
            conf_file = self.conf_path.parent / name
            if not conf_file.exists():
                continue
            text = conf_file.read_text(encoding="utf-8", errors="ignore")
            for m in re.finditer(r"proxy_pass\s+https://(upstream_[a-z0-9_]+)", text):
                refs.add(m.group(1))
        return refs

    def apply_optimal(self, test_results: Dict[str, List[Dict]]) -> Tuple[bool, str]:
        """将延迟最低的节点配置原子写入 upstream-dynamic.conf (含引用交叉校验)"""
        try:
            conf_str = self.generate_upstream_conf(test_results)

            # 交叉校验: site 引用的 upstream 必须全部有定义, 防 host not found 导致 nginx 启动失败
            defined = set(re.findall(r"upstream (upstream_[a-z0-9_]+)", conf_str))
            refs = self._scan_site_upstream_refs()
            missing = refs - defined
            if missing:
                return False, f"上游引用不一致, 以下 upstream 缺失定义: {', '.join(sorted(missing))}"

            self.conf_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.conf_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(conf_str)
            tmp_path.replace(self.conf_path)

            failed = [srv_id for srv_id, items in test_results.items()
                      if not any(it.get("rank", 3) == 0 for it in items)]
            msg = "已生成延迟最低的节点配置并写入 upstream-dynamic.conf！"
            if failed:
                msg += f" 注意: {len(failed)} 个服务直连探测全部失败已回退候选池({', '.join(sorted(failed))})"
                # 代理可用但直连被阻断: 数据平面仍直连, 明确提示用户 (代理仅作测速筛选)
                proxy = _load_proxy_config()
                if proxy and is_proxy_available(proxy):
                    msg += "。当前直连被阻断而本地代理可用, 但 Nginx 数据平面仍为直连, 请检查网络直连状态"
                else:
                    msg += ", 建议检查网络后重试"
            return True, msg
        except Exception as e:
            return False, f"写入 upstream 配置失败: {e}"


class CDNHealthMonitor:
    """持续 CDN 节点健康巡检与故障自愈引擎"""

    def __init__(self, optimizer: CDNOptimizer, check_interval: float = 300.0,
                 on_healed: Optional[Callable[[], Any]] = None):
        self.optimizer = optimizer
        self.check_interval = check_interval
        self.on_healed = on_healed
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False
        self.enabled_services: List[str] = []
        self.cached_results: Dict[str, List[Dict]] = {}
        self.failure_counts: Dict[str, int] = {}

    def is_running(self) -> bool:
        return self._is_running

    def update_services(self, enabled_services: List[str], current_results: Optional[Dict[str, List[Dict]]] = None):
        """更新当前监听的服务清单与基准测试结果"""
        self.enabled_services = list(enabled_services)
        if current_results:
            self.cached_results = dict(current_results)

    def check_and_heal_service(self, srv_id: str) -> bool:
        """检查单个服务的当前主力节点，并在故障时自动选举自愈"""
        srv = SERVICES_BY_ID.get(srv_id)
        if not srv:
            return False

        items = self.cached_results.get(srv_id)
        if not items:
            items = self.optimizer.test_service_dual(srv_id)
            self.cached_results[srv_id] = items

        best_item = next((it for it in items if it.get("rank", 3) == 0), items[0] if items else None)
        if not best_item:
            return False

        # 轻量探针检查当前主力节点
        sni_mode = SNI_MODES.get(srv_id, "host")
        domain = srv["domains"][0] if srv["domains"] else ""
        probe_res = probe_ip_endpoint_v2(best_item["ip"], domain=domain, timeout=2.0, sni_mode=sni_mode)

        if probe_res.get("tls_ok", False):
            self.failure_counts[srv_id] = 0
            return False  # 主力节点健康，无需自愈

        # 连续失败计数累加
        self.failure_counts[srv_id] = self.failure_counts.get(srv_id, 0) + 1
        if self.failure_counts[srv_id] >= 2:
            # 触发故障自愈：单服务重测并选举新节点
            new_items = self.optimizer.test_service_dual(srv_id)
            self.cached_results[srv_id] = new_items
            self.failure_counts[srv_id] = 0
            return True

        return False

    def run_health_check_cycle(self) -> Tuple[bool, List[str]]:
        """执行一轮轻量健康巡检周期，返回 (是否有自愈发生, 自愈服务列表)"""
        healed_services = []
        for srv_id in self.enabled_services:
            if self._stop_event.is_set():
                break
            try:
                if self.check_and_heal_service(srv_id):
                    healed_services.append(srv_id)
            except Exception:
                pass

        if healed_services and self.cached_results:
            # 重新渲染 upstream 配置并应用
            ok, _ = self.optimizer.apply_optimal(self.cached_results)
            if ok and self.on_healed:
                try:
                    self.on_healed()
                except Exception:
                    pass
            return True, healed_services

        return False, []

    def _worker_loop(self):
        """后台低开销巡检工作循环"""
        self._is_running = True
        while not self._stop_event.is_set():
            # 休眠指定周期（支持快速唤醒退出）
            if self._stop_event.wait(timeout=self.check_interval):
                break
            try:
                self.run_health_check_cycle()
            except Exception:
                pass
        self._is_running = False

    def start(self, enabled_services: Optional[List[str]] = None):
        """启动后台健康巡检守护线程"""
        if self._is_running:
            return
        if enabled_services is not None:
            self.enabled_services = list(enabled_services)
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="CDNHealthMonitorThread")
        self._thread.start()

    def stop(self):
        """停止后台健康巡检"""
        if not self._is_running:
            return
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        self._is_running = False


# ==============================================================================
# 独立运行入口: 支持用户/开发者在终端手动执行一键测速与节点优选
# ==============================================================================
if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print("=" * 80)
    print(">>> PixivToolkit - CDN 节点全网深度探测与动态优选 CLI <<<")
    print("=" * 80)

    conf_file = Path(__file__).resolve().parent.parent / "nginx" / "conf" / "upstream-dynamic.conf"
    opt = CDNOptimizer(conf_file)
    print("正在对全量加速服务的 Anycast 节点进行并发探测 (超时阈值 3.5s)...")

    t0 = time.perf_counter()
    res = opt.test_all_services(max_workers=16, total_timeout=25.0)
    elapsed = time.perf_counter() - t0

    print("\n" + "=" * 80)
    print(f"测速完成！总耗时: {elapsed:.2f} 秒")
    print("=" * 80)

    for srv_id, ip_items in res.items():
        usable = [it for it in ip_items if it.get("available")]
        best_lat = usable[0].get("latency") if usable else None
        lat_str = f"{best_lat}ms" if best_lat is not None else "超时/不可用"
        print(f"【{srv_id:<20}】可用节点: {len(usable)}/{len(ip_items)} | 最低延迟: {lat_str}")
        for it in ip_items:
            ip = it.get("ip")
            lat = it.get("latency")
            status = f"✅ {lat}ms" if lat is not None else "❌ 超时"
            via = "(代理)" if it.get("via_proxy") else "(直连)"
            print(f"    - {ip:<18} | {status:<12} {via}")

    ok, msg = opt.apply_optimal(res)
    print("\n" + "=" * 80)
    print(f"优选结果应用状态: {'[成功]' if ok else '[失败]'} -> {msg}")
    print("=" * 80)
