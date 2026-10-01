# -*- coding: utf-8 -*-
"""
GameArt Toolkit - QUIC(HTTP/3) 候选 IP 测速与优选

为什么需要独立的测速通道:
  QUIC 直连类服务 (ServiceMode.QUIC_DIRECT) 的 **TCP 侧 SNI 会被 GFW 立即 RST**, 常规
  TCP/TLS 测速对它们只会给出"全挂"的假阴性 —— 这正是不该让它们参与普通测速、也不该
  让它们的候选 IP 停留在静态实测值的原因 (静态值一旦被封就永久失效, 无自愈能力)。
  本模块用**真实 QUIC 握手 + HTTP/3 请求**测量延迟与可用性, 并把优选结果持久化到
  config.quic_optimal_ips, 供本机解析器 (下发真实 IP) 与 Hosts 直连模式读取。

依赖 aioquic (项目环境已具备, 见 scripts/probe_h3_sni.py 的端到端验证)。缺依赖时所有
接口返回"不可用"而不抛异常, 不影响主流程。
"""

import sys as _sys

# 版本前置检查 (与 cert_manager 一致): 旧解释器下类型标注会抛 TypeError, 这里给出可操作提示
if _sys.version_info < (3, 10):
    _sys.stderr.write(
        f"\n[错误] 需要 Python 3.10 及以上, 当前为 {_sys.version.split()[0]}。\n"
        f"       请使用运行客户端的同一解释器, 例如: py -3.13 -m app.{0}\n"
        f"       当前解释器: {_sys.executable}\n\n".format(__name__.rsplit('.', 1)[-1]))
    raise SystemExit(2)
import ssl
import sys
import json
import time
import asyncio
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

DEFAULT_TIMEOUT = 6.0
CONFIG_KEY = "quic_optimal_ips"
MAX_PERSISTED = 8       # 持久化池上限: 可用节点在前, 失效节点在后 (保留以便日后恢复, 但必须有界)

# ============================ QUIC 通道总开关 ============================
# 2026-10-01 用户要求: **暂时停用 QUIC 通道**。
# 背景: 原先依赖 QUIC 的三个服务 (reddit / stackoverflow / discord) 已按实测改走
# "L7 + 掩标 SNI" 与 "L7 + ECH 隧道" —— 默认浏览器即可打开, 不再需要"浏览器自行采用 h3"
# (该前提已被 netlog 证伪)。因此 QUIC 侧不再有使用者, 停用可减少后台探测与误配面。
#
# 为什么用开关而不是删除/注释代码: ① 一键恢复 (改回 True 即可); ② 代码与测试保持完整,
# 未来出现新的"仅 UDP/443 可达"站点时可直接复用; ③ 字面注释会破坏导入与测试收集。
# 需要覆盖 QUIC 逻辑的用例通过 tests/quic_helpers.py::quic_mode 临时打开本开关。
QUIC_ENABLED = False


def is_enabled() -> bool:
    """QUIC 通道是否启用 (总开关)"""
    return bool(QUIC_ENABLED)


def _disabled_reason() -> str:
    return "QUIC 通道已暂时停用 (见 quic_probe.QUIC_ENABLED)"

# 进程内缓存: DNS 解析是热路径 (每次查询都会调用), 不能每次都读配置文件
_CACHE: Dict[str, List[str]] = {}
_CACHE_TS = 0.0
_CACHE_TTL = 5.0


def is_available() -> Tuple[bool, str]:
    """探测 QUIC 探测能力是否可用 (总开关关闭 / 缺 aioquic 都视为不可用)

    注意: 缺 aioquic 时 probe_candidates 会回退到无依赖 Initial 探测 (见下), 所以本函数
    返回 False 并不代表"探测不了" —— 真正决定是否探测的是 QUIC_ENABLED。
    """
    if not is_enabled():
        return False, _disabled_reason()
    try:
        import aioquic  # noqa: F401
        from aioquic.h3.connection import H3_ALPN  # noqa: F401
        return True, ""
    except Exception as e:
        return False, f"缺少 aioquic 依赖: {e}"


# --------------------------------------------------------------------------- 无依赖回退探测
#
# 为什么必须有这条回退路径: aioquic 是**可选**第三方库, 打包产物 (PyInstaller) 里并不存在。
# 早期版本把 QUIC 测速完全建立在 aioquic 之上, 结果打包运行时所有 QUIC 直连服务都报
# "缺少依赖" → 界面恒定显示"检测失败"。QUIC 测速属核心功能, 不能依赖可选库。
#
# 回退实现: 手工构造 QUIC v1 Initial 报文 (内含带目标 SNI 的 TLS ClientHello), 只需
# 标准库 + cryptography (项目硬依赖, 打包产物自带)。它测"到首个响应的 RTT"与"传输层是否
# 被丢弃", 拿不到 HTTP 状态码 —— 因此结果里用 method 字段区分可信度。

_QUIC_V1 = 0x00000001
_INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    import hmac as _hmac
    import hashlib as _hashlib
    return _hmac.new(salt, ikm, _hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    """RFC 8446 §7.1 HKDF-Expand-Label"""
    import hmac as _hmac
    import hashlib as _hashlib
    import struct as _struct
    full = b"tls13 " + label
    info = _struct.pack("!H", length) + bytes([len(full)]) + full + bytes([0])
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = _hmac.new(secret, block + info + bytes([counter]), _hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _varint(n: int) -> bytes:
    import struct as _struct
    if n < 64:
        return bytes([n])
    if n < 16384:
        return _struct.pack("!H", n | 0x4000)
    if n < (1 << 30):
        return _struct.pack("!I", n | 0x80000000)
    return _struct.pack("!Q", n | 0xC000000000000000)


def _build_client_hello(sni: str) -> bytes:
    import os as _os
    import struct as _struct

    def ext(t, body):
        return _struct.pack("!HH", t, len(body)) + body

    name = sni.encode()
    exts = b"".join([
        ext(0x0000, _struct.pack("!H", len(name) + 3) + b"\x00"
            + _struct.pack("!H", len(name)) + name),                      # SNI
        ext(0x002B, b"\x02\x03\x04"),                                      # supported_versions
        ext(0x000A, _struct.pack("!H", 2) + _struct.pack("!H", 0x001D)),   # x25519
        ext(0x000D, _struct.pack("!H", 4) + _struct.pack("!HH", 0x0804, 0x0403)),
        ext(0x0010, _struct.pack("!H", 3) + _struct.pack("!H", 2) + b"h3"),
        ext(0x0033, _struct.pack("!HH", 0x001D, 32) + _os.urandom(32)),    # key_share
    ])
    body = (b"\x03\x03" + _os.urandom(32) + b"\x20" + _os.urandom(32)
            + _struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
            + _struct.pack("!H", len(exts)) + exts)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def _build_initial(dcid: bytes, sni: str, datagram_size: int = 1200) -> bytes:
    """构造完整 QUIC v1 Initial 报文 (AEAD + 头保护)"""
    import os as _os
    import struct as _struct
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    initial_secret = _hkdf_extract(_INITIAL_SALT_V1, dcid)
    client_secret = _hkdf_expand_label(initial_secret, b"client in", 32)
    key = _hkdf_expand_label(client_secret, b"quic key", 16)
    iv = _hkdf_expand_label(client_secret, b"quic iv", 12)
    hp = _hkdf_expand_label(client_secret, b"quic hp", 16)

    scid = _os.urandom(8)
    pn_bytes = _struct.pack("!I", 0)
    hello = _build_client_hello(sni)
    crypto_frame = b"\x06" + _varint(0) + _varint(len(hello)) + hello

    header_no_len = (bytes([0xC0 | 0x03]) + _struct.pack("!I", _QUIC_V1)
                     + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\x00")
    length_len = 2
    overhead = len(header_no_len) + length_len + 4 + 16
    frames_len = max(len(crypto_frame), datagram_size - overhead)
    frames = crypto_frame + b"\x00" * (frames_len - len(crypto_frame))
    length_field = _varint(4 + frames_len + 16)
    if len(length_field) != length_len:
        overhead = len(header_no_len) + len(length_field) + 4 + 16
        frames_len = max(len(crypto_frame), datagram_size - overhead)
        frames = crypto_frame + b"\x00" * (frames_len - len(crypto_frame))
        length_field = _varint(4 + frames_len + 16)

    header = header_no_len + length_field
    aad = header + pn_bytes
    nonce = bytes(iv)                                    # pn=0 -> nonce == iv
    ciphertext = AESGCM(key).encrypt(nonce, frames, aad)

    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(ciphertext[:16]) + enc.finalize()
    protected_first = bytes([header[0] ^ (mask[0] & 0x0F)])
    protected_pn = bytes(pn_bytes[i] ^ mask[1 + i] for i in range(4))
    return protected_first + header[1:] + protected_pn + ciphertext


def _probe_one_initial(ip: str, sni: str, timeout: float) -> Dict:
    """无 aioquic 回退: 发送真实 QUIC Initial, 测到首个响应的 RTT"""
    import os as _os
    import socket as _socket
    import time as _time

    result: Dict = {"ip": ip, "ok": False, "status": None, "handshake_ms": None,
                    "latency_ms": None, "error": "", "method": "initial"}
    fam = _socket.AF_INET6 if ":" in ip else _socket.AF_INET
    try:
        pkt = _build_initial(_os.urandom(8), sni)
    except Exception as e:
        result["error"] = f"build:{type(e).__name__}"
        return result
    try:
        with _socket.socket(fam, _socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            t0 = _time.perf_counter()
            s.sendto(pkt, (ip, 443))
            data, _ = s.recvfrom(4096)
            rtt = round((_time.perf_counter() - t0) * 1000, 1)
        # 合法 QUIC 响应必为长头报文 (首字节最高位为 1): ServerHello/CONNECTION_CLOSE/Retry
        if data and (data[0] & 0x80):
            result.update(ok=True, latency_ms=rtt, handshake_ms=rtt)
        else:
            result["error"] = f"异常响应({len(data)}B)"
    except _socket.timeout:
        result["error"] = "timeout"
    except ConnectionResetError:
        result["error"] = "udp_rst"
    except Exception as e:
        result["error"] = type(e).__name__
    return result


# --------------------------------------------------------------------------- 探测

def _build_protocol_class():
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived, DataReceived

    class _H3Probe(QuicConnectionProtocol):
        """最小 HTTP/3 探测客户端: 记录握手完成时刻与响应状态"""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._http = H3Connection(self._quic)
            self.status: Optional[int] = None
            self.body_bytes = 0
            self.first_headers_at: Optional[float] = None
            self.headers_ready = asyncio.Event()
            self.done = asyncio.Event()

        def http_event_received(self, event):
            if isinstance(event, HeadersReceived):
                if self.first_headers_at is None:
                    self.first_headers_at = time.perf_counter()
                for k, v in event.headers:
                    if k == b":status":
                        try:
                            self.status = int(v)
                        except Exception:
                            pass
                self.headers_ready.set()
            elif isinstance(event, DataReceived):
                self.body_bytes += len(event.data)
                try:
                    self._http.acknowledge_data(event.stream_id, event.data)
                except Exception:
                    pass
                if event.stream_ended:
                    self.done.set()

        def quic_event_received(self, event):
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

        async def send_get(self, authority: str, path: str = "/"):
            stream_id = self._quic.get_next_available_stream_id()
            self._http.send_headers(stream_id, [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
                (b"user-agent", b"GameArtToolkit/QUIC-probe"),
                (b"accept", b"*/*"),
            ], end_stream=True)
            self.transmit()

    return _H3Probe


async def _probe_one_async(ip: str, sni: str, timeout: float, path: str,
                           sem: asyncio.Semaphore) -> Dict:
    from aioquic.asyncio.client import connect
    from aioquic.h3.connection import H3_ALPN
    from aioquic.quic.configuration import QuicConfiguration

    proto_cls = _build_protocol_class()
    result: Dict = {"ip": ip, "ok": False, "status": None, "handshake_ms": None,
                    "latency_ms": None, "error": ""}
    async def _attempt():
        async with connect(ip, 443, configuration=cfg, create_protocol=proto_cls,
                           wait_connected=True) as client:
            result["handshake_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            await client.send_get(sni, path)
            # 只等响应头: 状态码 + 首字节时刻已足够判定"可用性 + 延迟"。
            # 若改为等完整正文 (stream_ended), 对 301/302/204 这类无正文响应会一直等到超时 ——
            # 实测这让每个候选白等满 6s, 3 个服务就要 30s, 是"测速很慢/像卡住"的直接来源。
            try:
                await asyncio.wait_for(client.headers_ready.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                pass
            if client.first_headers_at:
                result["latency_ms"] = round((client.first_headers_at - t0) * 1000, 1)
            elif result["handshake_ms"] is not None:
                result["latency_ms"] = result["handshake_ms"]
            result["status"] = client.status
            result["ok"] = client.status is not None
            if not result["ok"]:
                result["error"] = "握手成功但无 HTTP 响应"

    async with sem:
        cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                verify_mode=ssl.CERT_NONE)
        cfg.server_name = sni
        # 关键: aioquic 默认 idle_timeout 为 60s。遇到**静默丢包**的对端 (既无响应也无
        # ICMP/RST) 时, 握手不会快速失败, 而是一直等到 idle timeout —— 实测会让一次候选
        # 探测卡住整整 60s, 把 QUIC 优选变成"界面假死"。这里把它压到与本次探测预算同量级,
        # 并额外用 wait_for 兜底, 保证单个候选的耗时可控。
        cfg.idle_timeout = max(3.0, min(float(timeout), 15.0))
        t0 = time.perf_counter()
        try:
            await asyncio.wait_for(_attempt(), timeout=cfg.idle_timeout + 3.0)
        except asyncio.TimeoutError:
            result["error"] = "timeout"
        except Exception as e:
            result["error"] = type(e).__name__
    return result


def probe_candidates(ips: Sequence[str], sni: str, timeout: float = DEFAULT_TIMEOUT,
                     path: str = "/", max_concurrency: int = 6) -> List[Dict]:
    """并发探测一组候选 IP 的 QUIC 可达性与延迟

    优先用 aioquic 发真实 HTTP/3 请求 (可拿到状态码); 缺 aioquic 时自动回退到
    纯标准库+cryptography 的 Initial 探测 (只测 RTT 与可达性, 不依赖可选库)。
    返回按 (可用优先, 延迟升序) 排序的列表; 每项含 ip/ok/status/latency_ms/error/method。
    """
    targets = [ip for ip in dict.fromkeys(ips or []) if ip]
    if not targets:
        return []

    if not is_enabled():
        # 停用时不发任何探测包, 如实标注原因 (而不是伪装成"不可用")
        return [{"ip": ip, "ok": False, "status": None, "handshake_ms": None,
                 "latency_ms": None, "error": _disabled_reason(), "method": "disabled"}
                for ip in targets]

    ok_dep, why = is_available()
    if ok_dep:
        async def _run():
            sem = asyncio.Semaphore(max(1, max_concurrency))
            return await asyncio.gather(*[
                _probe_one_async(ip, sni, timeout, path, sem) for ip in targets])

        try:
            results = asyncio.run(_run())
            for r in results:
                r.setdefault("method", "h3")
        except Exception as e:
            results = [{"ip": ip, "ok": False, "status": None, "handshake_ms": None,
                        "latency_ms": None, "error": f"{type(e).__name__}: {e}",
                        "method": "h3"} for ip in targets]
    else:
        # 回退路径: 并发执行无依赖探测 (aioquic 缺失不应让服务"检测失败")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_concurrency)) as pool:
            results = list(pool.map(lambda ip: _probe_one_initial(ip, sni, timeout), targets))

    def sort_key(item: Dict):
        if item.get("ok") and item.get("latency_ms") is not None:
            return (0, item["latency_ms"])
        if item.get("handshake_ms") is not None:
            return (1, item["handshake_ms"])
        return (2, 1e9)

    return sorted(results, key=sort_key)


# --------------------------------------------------------------------------- 持久化

def _invalidate_cache():
    global _CACHE, _CACHE_TS
    _CACHE = {}
    _CACHE_TS = 0.0


def get_optimal_ips(srv_id: str) -> List[str]:
    """读取某服务的 QUIC 优选 IP 列表 (带 5s 进程内缓存, 供 DNS 热路径使用)

    防御: ① 总开关停用时直接返回空; ② 画像已不再是 QUIC_DIRECT 的服务也返回空 ——
    否则升级后 config 里遗留的 `quic_optimal_ips` 条目会被 DNS/Hosts 消费, 把 L7 服务
    错误地钉到旧 QUIC 节点上 (实测: reddit 改档为 L7 后, 配置里仍留着 QUIC 优选 IP)。
    """
    if not is_enabled():
        return []
    try:
        from service_profile import PROFILES_BY_ID, ServiceMode
        profile = PROFILES_BY_ID.get(str(srv_id))
        if profile is not None and profile.mode != ServiceMode.QUIC_DIRECT:
            return []
    except Exception:
        pass

    global _CACHE, _CACHE_TS
    now = time.time()
    if not _CACHE or (now - _CACHE_TS) > _CACHE_TTL:
        try:
            from config_store import load_config
            stored = load_config().get(CONFIG_KEY) or {}
            _CACHE = {str(k): [str(i) for i in (v or [])] for k, v in stored.items()
                      if isinstance(v, (list, tuple))}
        except Exception:
            _CACHE = {}
        _CACHE_TS = now
    return list(_CACHE.get(str(srv_id), []))


def set_optimal_ips(srv_id: str, ips: Sequence[str]) -> bool:
    """持久化某服务的 QUIC 优选 IP 顺序"""
    try:
        from config_store import load_config, save_config
        cfg = load_config()
        table = cfg.get(CONFIG_KEY)
        if not isinstance(table, dict):
            table = {}
        table[str(srv_id)] = [str(i) for i in ips if i]
        cfg[CONFIG_KEY] = table
        save_config(cfg)
        _invalidate_cache()
        return True
    except Exception:
        return False


def clear_optimal_ips(srv_id: Optional[str] = None) -> bool:
    """清空 QUIC 优选结果 (srv_id 为空则全清)"""
    try:
        from config_store import load_config, save_config
        cfg = load_config()
        if srv_id is None:
            cfg[CONFIG_KEY] = {}
        else:
            table = cfg.get(CONFIG_KEY) or {}
            table.pop(str(srv_id), None)
            cfg[CONFIG_KEY] = table
        save_config(cfg)
        _invalidate_cache()
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- 服务级

def _quic_services(services: Optional[Sequence[str]] = None) -> List:
    """筛选 QUIC 直连类服务画像"""
    try:
        from service_profile import PROFILES, ServiceMode, PROFILES_BY_ID
    except Exception:
        return []
    if services:
        ids = {str(s) for s in services}
        return [p for p in PROFILES if p.id in ids and p.mode == ServiceMode.QUIC_DIRECT]
    return [p for p in PROFILES if p.mode == ServiceMode.QUIC_DIRECT]


def optimize_service(srv_id: str, timeout: float = DEFAULT_TIMEOUT,
                     persist: bool = True, extra_ips: Sequence[str] = ()) -> Dict:
    """对单个 QUIC 服务做候选测速与优选, 并把顺序写回配置

    候选来源 = 静态实测池 ∪ 历史优选 ∪ 调用方补充, 去重后全部重测 —— 这样既能发现
    新可用节点, 也能在旧节点被封时自动切换到仍可用的节点。
    """
    if not is_enabled():
        return {"srv_id": srv_id, "domain": "", "ok": False, "usable": 0, "tested": 0,
                "best_ip": "", "best_latency_ms": None, "results": [],
                "error": _disabled_reason()}
    from service_profile import PROFILES_BY_ID
    profile = PROFILES_BY_ID.get(srv_id)
    if profile is None:
        return {"srv_id": srv_id, "ok": False, "error": "未知服务", "results": []}

    candidates: List[str] = []
    for group in (get_optimal_ips(srv_id), list(profile.candidate_ips or []), list(extra_ips or [])):
        for ip in group:
            if ip and ip not in candidates:
                candidates.append(ip)

    domain = (profile.domains or [""])[0]
    results = probe_candidates(candidates, domain, timeout=timeout)
    usable = [r["ip"] for r in results if r.get("ok")]
    ranked = usable + [r["ip"] for r in results if not r.get("ok")]

    if persist and usable:
        # 可用节点优先; 失效节点保留在尾部以便日后恢复, 但必须有界, 防止长期累积成噪声池
        set_optimal_ips(srv_id, ranked[:MAX_PERSISTED])

    best = next((r for r in results if r.get("ok")), None)
    return {
        "srv_id": srv_id,
        "domain": domain,
        "ok": bool(usable),
        "usable": len(usable),
        "tested": len(candidates),
        "best_ip": best["ip"] if best else "",
        "best_latency_ms": best.get("latency_ms") if best else None,
        "results": results,
        "error": "" if usable else "全部候选 QUIC 不可用",
    }


def optimize_quic_services(services: Optional[Sequence[str]] = None,
                           timeout: float = DEFAULT_TIMEOUT,
                           persist: bool = True, max_workers: int = 3) -> Dict:
    """批量优选 QUIC 直连服务 (供 CDN 优化流程挂钩调用)

    返回 {"services": {id: report}, "ok_count": n, "summary": "..."}；任何异常都吞掉并
    如实写进 summary —— 绝不能让 QUIC 侧的问题影响主测速流程。
    """
    reports: Dict[str, Dict] = {}
    try:
        profiles = _quic_services(services)
    except Exception as e:
        return {"services": {}, "ok_count": 0, "summary": f"QUIC 优选跳过: {e}"}

    if not profiles:
        return {"services": {}, "ok_count": 0, "summary": "无 QUIC 直连服务"}

    ok_dep, why = is_available()
    if not ok_dep:
        return {"services": {}, "ok_count": 0, "summary": f"QUIC 优选跳过: {why}"}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
        futures = {pool.submit(optimize_service, p.id, timeout, persist): p.id for p in profiles}
        for fut in concurrent.futures.as_completed(futures):
            srv_id = futures[fut]
            try:
                reports[srv_id] = fut.result()
            except Exception as e:
                reports[srv_id] = {"srv_id": srv_id, "ok": False, "error": str(e), "results": []}

    ok_ids = [sid for sid, r in reports.items() if r.get("ok")]
    bad_ids = [sid for sid, r in reports.items() if not r.get("ok")]
    parts = []
    if ok_ids:
        detail = ", ".join(f"{sid}({reports[sid].get('best_ip')} {reports[sid].get('best_latency_ms')}ms)"
                           for sid in sorted(ok_ids))
        parts.append(f"{len(ok_ids)} 个 QUIC 服务已优选: {detail}")
    if bad_ids:
        parts.append(f"{len(bad_ids)} 个 QUIC 服务当前不可用({', '.join(sorted(bad_ids))})")
    return {"services": reports, "ok_count": len(ok_ids), "summary": "; ".join(parts) or "无结果"}


def current_best_ip(srv_id: str, fallback: str = "") -> str:
    """取该服务当前最优 QUIC IP (供 DNS / Hosts 读取)

    总开关停用时返回 fallback —— 调用方 (DNS/Hosts) 据此走各自的非 QUIC 分支,
    不会把域名钉到一个"已停用通道"的 IP 上。
    """
    if not is_enabled():
        return fallback
    ips = get_optimal_ips(srv_id)
    if ips:
        return ips[0]
    try:
        from service_profile import PROFILES_BY_ID
        profile = PROFILES_BY_ID.get(srv_id)
        if profile and profile.candidate_ips:
            return profile.candidate_ips[0]
    except Exception:
        pass
    return fallback


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="QUIC(HTTP/3) 候选 IP 测速与优选")
    ap.add_argument("--services", help="逗号分隔的服务 id, 缺省为全部 QUIC 直连服务")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--dry-run", action="store_true", help="只测速不写配置")
    ap.add_argument("--show", action="store_true", help="打印每项测速明细")
    args = ap.parse_args(argv)

    ids = [s.strip() for s in args.services.split(",")] if args.services else None
    report = optimize_quic_services(ids, timeout=args.timeout, persist=not args.dry_run)
    print(report["summary"])
    if args.show:
        for sid, rep in sorted(report["services"].items()):
            print(f"\n[{sid}] {rep.get('domain')} 可用 {rep.get('usable')}/{rep.get('tested')}")
            for item in rep.get("results", []):
                flag = "OK " if item.get("ok") else "FAIL"
                print(f"   {flag} {item['ip']:16s} status={item.get('status')} "
                      f"handshake={item.get('handshake_ms')}ms latency={item.get('latency_ms')}ms "
                      f"{item.get('error') or ''}")
    print("\n已写入配置" if not args.dry_run else "\n(dry-run: 未写入配置)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

