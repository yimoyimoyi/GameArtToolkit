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
from pathlib import Path
from typing import Dict, List, Tuple, Optional

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
                   and not _suspect_status(direct.get("http_status")))
    p_clean = bool(proxy and proxy.get("tcp_ok") and proxy.get("tls_ok")
                   and not _suspect_status(proxy.get("http_status")))
    p_suspect = bool(proxy and proxy.get("tcp_ok") and proxy.get("tls_ok")
                     and _suspect_status(proxy.get("http_status")))

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

    def test_all_services(self, max_workers: int = 16, total_timeout: float = 30.0) -> Dict[str, List[Dict]]:
        """全量双通道探测: 直连 + 经本地代理 CONNECT 隧道, 三态验证后 rank 合并排序"""
        proxy = _load_proxy_config()
        proxy_ready = is_proxy_available(proxy, timeout=0.5)
        if not proxy_ready:
            proxy = None

        flat_tasks = []
        for srv_id, ips in CANDIDATE_IPS.items():
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

        for srv_id, ip_items in test_results.items():
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
                msg += f" 注意: {len(failed)} 个服务双通道探测全部失败已回退候选池({', '.join(sorted(failed))}), 建议检查网络后重试"
            return True, msg
        except Exception as e:
            return False, f"写入 upstream 配置失败: {e}"
