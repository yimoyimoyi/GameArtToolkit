# -*- coding: utf-8 -*-
"""
PixivToolkit - L4 Relay 代理转发器 (Proxy Tunnel) 专项测试集

覆盖本轮"全部修复"架构改造中 app/l4_relay.py 新增的代理转发模式:
1. 端口 -> CONNECT 目标域名静态映射 (proxy_routes), 与 SNI 直连路由并存
2. 纯 asyncio CONNECT 隧道 (经本地 HTTP 代理), 200 校验 + 残留字节回放
3. 真隧道字节透明性: 回显透传 / 本机自签 TLS 服务器端到端握手
4. 空 SNI 兼容 (代理端口不解析 SNI, 一律按端口映射 CONNECT)
5. 代理不可达 / CONNECT 非 200 -> 关闭客户端连接
6. SNI 直连路径不受代理路由注册影响
7. 代理端口首包无限等待 (nginx keepalive 兼容), SNI 端口 2.0s
8. set_proxy_tunnels 运行中在线增删监听端口
9. relay 生命周期 start/stop 多端口正常

全部使用本地 mock 代理与临时端口, 严禁触碰 config.json / nginx/conf/*
代理地址一律通过 set_proxy_addr 显式注入, 不读取真实 upstream_proxy。
"""

import sys
import time
import ssl
import socket
import struct
import tempfile
import threading
from pathlib import Path
from typing import List, Optional, Tuple

import pytest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

APP_DIR = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP_DIR))

from l4_relay import L4RelayServer, extract_sni_from_client_hello

# ==============================================================================
# 自签 TLS 测试证书 (有效期 2026-08 ~ 2036-08, CN=relay-test.local)
# 仅供本机回环隧道测试, 客户端 check_hostname=False 不校验
# ==============================================================================
TEST_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAo4reePNGirK4KbYNqrC+Vul7P1KDMpkFfochE3GBpbed7AkP
FFkBtlT0JCQl0lwQdVLDU1vOC+FAZuQFkjdk8W0elFPZdwqx+c+vqwsYIAmBLKwd
8Xsbmbf+fohUc1imJ6sn3I9TwiGmisF41owYFrfPRIvVAe4nwPTmkiM27AHAs0X9
tH8euzZtt4Fx05D2KPCQfiIhO24Z0UPhdH2X8VydvIEBLXW79SHS2CSbNbxzTlK+
W9hhehKidHAU0qHUgzOZXQlWveVTZSFff/uwitpRSYTO7jjw5j7TM+uogDgZ7VzR
NmmrhT+orVJ9n5KHYgHfRLYd3/h58ZciRJc7HQIDAQABAoIBAAP1Pru6cFW3mPmf
DgcFODreDR1AtkUmUYafTZkgKtOWzvJUW8v4K+O8rzXxHATSm2FdHrYPQQk/kXGM
CWh7AVOCFEN7VGy4Bdh2aTMTolwjVSZLU7D+Jwvzph8FowmYA4yiBn8+ufe3HPk7
UN0Pm4U9O8pvmewHvM8qMV30qGxSXdVgyCYTi1C6ca0TJzA5tpWMgHR4XSVsR37W
O/UqDwRGJ3zRyArM3NuPJjILJyYEJPMka67G+IPspQGo/aD3zOqGzex8GKM13sPK
wJcMRXc+hx1dR6BwQ70Ibpq98N1i5+Cshovbl6c8kPMPP6Haev47bmJ6B2fY3/oY
7X4kQRECgYEAzU8if23+C/L4oghj7adMEGDL0bHiYAryAdLyT/Ap+Iee8yBAcwh3
QtO1+m0mQt/JwT67M7seHpcMXOm0u1rVWjL5U4ICgnzEqntQ6d0yCoLmMqItCMa1
kb8ZhCBNxRA+R2k4zwuZJf5v4f92TP3sIhwgHFt3PEf5d+/ToAkkWpUCgYEAy+vP
k3El1YSzfUm3vfVX/WrOknL1VFeGGQH2Jq9ets+jhoZrYaYdb9itG4vY4oiEOKPk
n4ee9AbIFBJHICUCxqscIYaT7F3nguShaebjtnm1/Iz4e88+ZGH7SjTbuHOctxjj
bZ2IcAXtyHNNwP0+YWnWnzUqwdmLcKLsS/EExGkCgYEAoFxgMLJEDSdBpqXxD25t
zhkc+fP8QlIqRtxyYZfP4IxlzbbyQCdrp6nfaPQaP3+2gZcy9yv/UZtfj68HeJNx
M9u+vMg+l5dGsXZSc+hOrsEhdokPrdwvc+CU2Iu20uZmDrcUJTwE6hU7ZIV57Jck
+luHhT63+kCpjVGotUaOu6UCgYAl9Sv7Tvly6DOc46bvFgcd5c6z1fAyleQhLYtL
IiOoNbhDpyu/znL2ScfXM83YRP8Pp/o7c7wzwjtl+Q0CP8Fnh5xB5VINkmEwrSwa
kV7brYYhj4AFU8tSVia3ZmVrzSFjt59F3Sfzajcbs9LKVJlS+qd3lSbzVHIvMjR3
4lI32QKBgHaK8bxXjpGJRqFFVtRAeEaGluH3EBX9FZdCtkhcf/uwzZtx7gCgs751
eeB5PVK1It45ZMz05d5Zbp6Dc7J4e4+25iKu6rGf2WDPn/dew0Xqgh+Ctc5C2VCZ
y/ipb61LuQ8dD6+PVjSU9YVDArg9xWlTb5k6uqUjP6O1SZGKxBIj
-----END RSA PRIVATE KEY-----
"""

TEST_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIC4zCCAcugAwIBAgIUY0C67VxTRztFxHRekc3sH2HBjPMwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQcmVsYXktdGVzdC5sb2NhbDAeFw0yNjA4MTcxNzIwMzha
Fw0zNjA4MTUxNzIwMzhaMBsxGTAXBgNVBAMMEHJlbGF5LXRlc3QubG9jYWwwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjit5480aKsrgptg2qsL5W6Xs/
UoMymQV+hyETcYGlt53sCQ8UWQG2VPQkJCXSXBB1UsNTW84L4UBm5AWSN2TxbR6U
U9l3CrH5z6+rCxggCYEsrB3xexuZt/5+iFRzWKYnqyfcj1PCIaaKwXjWjBgWt89E
i9UB7ifA9OaSIzbsAcCzRf20fx67Nm23gXHTkPYo8JB+IiE7bhnRQ+F0fZfxXJ28
gQEtdbv1IdLYJJs1vHNOUr5b2GF6EqJ0cBTSodSDM5ldCVa95VNlIV9/+7CK2lFJ
hM7uOPDmPtMz66iAOBntXNE2aauFP6itUn2fkodiAd9Eth3f+HnxlyJElzsdAgMB
AAGjHzAdMBsGA1UdEQQUMBKCEHJlbGF5LXRlc3QubG9jYWwwDQYJKoZIhvcNAQEL
BQADggEBACt0bq0XS8+scdPb5/2iy3uyLaWGaItFrWqzkEFk3kdvOmnHTZuLI+EE
nCOsRsI8A0pJonFqO0Wc8E/bbBQN7GyGMeDtIFCKBp/CpohlhVrtJAlsnBtXxCjy
QqQyk/jowZALsTKri9W95OS2bj8oeP6IkIprp5xTszmZ2lWNHiYWE2J/ykYXwUjF
21x6aU8ItR5jAut9CeWYj2F32ngXzYmCGESDosrL7eQaIur5OpEuKT744ogEOjgE
UWyZzc5+O6erjGrv4gg9soi2A7zKrx4VunJIgwV7Yl6C1EWBUKlLmLFr9d3ey6hz
yfdUVWMDSNHEPZDQnLjCpgd7QljClAE=
-----END CERTIFICATE-----
"""

# 证书临时文件 (进程生命周期内保留)
_TLS_CERT_FILES: Optional[Tuple[Path, Path]] = None
_TLS_TMP_DIR: Optional[tempfile.TemporaryDirectory] = None


def _ensure_cert_files() -> Tuple[Path, Path]:
    """把模块内嵌的自签证书写入临时文件, 返回 (cert, key) 路径"""
    global _TLS_CERT_FILES, _TLS_TMP_DIR
    if _TLS_CERT_FILES is None:
        _TLS_TMP_DIR = tempfile.TemporaryDirectory(prefix="ptk_tls_cert_")
        cert = Path(_TLS_TMP_DIR.name) / "cert.pem"
        key = Path(_TLS_TMP_DIR.name) / "key.pem"
        cert.write_text(TEST_CERT_PEM, encoding="utf-8")
        key.write_text(TEST_KEY_PEM, encoding="utf-8")
        _TLS_CERT_FILES = (cert, key)
    return _TLS_CERT_FILES


# ==============================================================================
# 本地 mock 基础设施
# ==============================================================================
class TunnelMockProxy:
    """增强版 mock CONNECT 代理: 200 响应后把隧道字节转发到本机 target (真隧道)

    - target=None: 回显模式 (收到字节原样回发)
    - target=(host, port): CONNECT 建立后字节原样转发到该服务器 (双向泵)
    - 记录所有 CONNECT 目标 host:port (供断言隧道是否真正建立)
    """

    def __init__(self, target: Optional[Tuple[str, int]] = None,
                 response_line: str = "HTTP/1.1 200 Connection established",
                 record: Optional[List[str]] = None):
        self.target = target
        self.response_line = response_line
        self.record = record if record is not None else []
        self.port: Optional[int] = None
        self._listen = None
        self._thread = None
        self._conn_threads: List[threading.Thread] = []

    def start(self) -> "TunnelMockProxy":
        self._listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen.bind(("127.0.0.1", 0))
        self._listen.listen(8)
        self.port = self._listen.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True, name="TunnelMockProxy")
        self._thread.start()
        return self

    def _serve(self):
        while True:
            try:
                conn, _ = self._listen.accept()
            except OSError:
                break
            t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            self._conn_threads.append(t)
            t.start()

    def _handle(self, conn):
        peer = None
        try:
            conn.settimeout(10.0)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            first = data.split(b"\r\n", 1)[0].decode("utf-8", "replace")
            if first.startswith("CONNECT "):
                self.record.append(first.split(" ", 2)[1])
            conn.sendall(f"{self.response_line}\r\n\r\n".encode("utf-8"))
            rest = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""

            if self.target is None:
                # 回显模式: 原样回发 (含 CONNECT 头后顺带读入的隧道数据)
                if rest:
                    conn.sendall(rest)
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    conn.sendall(chunk)
            else:
                # 真隧道: 转发到本机 target 服务器
                peer = socket.create_connection(self.target, timeout=5.0)
                if rest:
                    peer.sendall(rest)
                t1 = threading.Thread(target=self._pump, args=(conn, peer), daemon=True)
                t2 = threading.Thread(target=self._pump, args=(peer, conn), daemon=True)
                self._conn_threads += [t1, t2]
                t1.start()
                t2.start()
                t1.join(timeout=15.0)
                t2.join(timeout=15.0)
        except Exception:
            pass
        finally:
            for s in (peer, conn):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

    @staticmethod
    def _pump(src: socket.socket, dst: socket.socket):
        """单向数据泵: src -> dst, src EOF 时半关闭 dst 写侧"""
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dst.sendall(chunk)
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
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


class EchoServer:
    """本地 TCP 回显服务器 (SNI 直连路径的模拟上游)"""

    def __init__(self):
        self.port: Optional[int] = None
        self._listen = None
        self._thread = None

    def start(self) -> "EchoServer":
        self._listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen.bind(("127.0.0.1", 0))
        self._listen.listen(8)
        self.port = self._listen.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True, name="EchoServer")
        self._thread.start()
        return self

    def _serve(self):
        while True:
            try:
                conn, _ = self._listen.accept()
            except OSError:
                break
            t = threading.Thread(target=self._echo, args=(conn,), daemon=True)
            t.start()

    @staticmethod
    def _echo(conn):
        try:
            conn.settimeout(10.0)
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                conn.sendall(chunk)
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


def start_tls_echo_server() -> Tuple[int, object]:
    """启动本机自签 TLS 回显服务器 (ssl.PROTOCOL_TLS_SERVER), 返回 (port, cleanup)"""
    cert_path, key_path = _ensure_cert_files()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.bind(("127.0.0.1", 0))
    raw.listen(8)
    port = raw.getsockname()[1]
    stop = threading.Event()

    def _tls_echo(conn):
        ssock = None
        try:
            ssock = ctx.wrap_socket(conn, server_side=True)
            ssock.settimeout(10.0)
            while True:
                chunk = ssock.recv(65536)
                if not chunk:
                    break
                ssock.sendall(chunk)
        except Exception:
            pass
        finally:
            if ssock:
                try:
                    ssock.close()
                except Exception:
                    pass

    def _serve():
        while not stop.is_set():
            try:
                conn, _ = raw.accept()
            except OSError:
                break
            t = threading.Thread(target=_tls_echo, args=(conn,), daemon=True)
            t.start()

    th = threading.Thread(target=_serve, daemon=True, name="TlsEchoServer")
    th.start()

    def cleanup():
        stop.set()
        try:
            raw.close()
        except Exception:
            pass
        th.join(timeout=1.0)

    return port, cleanup


def _find_free_port() -> int:
    """获取一个当前空闲的本地端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_client_hello(sni: Optional[str]) -> bytes:
    """构造标准 TLS ClientHello 二进制包; sni=None 时不带 server_name 扩展 (空 SNI)"""
    if sni:
        sni_bytes = sni.encode("ascii")
        sni_entry = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
        server_name_ext = struct.pack("!H", len(sni_entry)) + sni_entry
        ext_block = struct.pack("!HH", 0x0000, len(server_name_ext)) + server_name_ext
        ext_total = struct.pack("!H", len(ext_block)) + ext_block
    else:
        ext_total = b"\x00\x00"  # 无扩展 (extensions_length = 0)

    client_hello_body = (
        b"\x03\x03"  # Client Version TLS 1.2
        + b"\x00" * 32  # Random
        + b"\x00"  # Session ID Length = 0
        + struct.pack("!H", 2) + b"\x00\x9c"  # Cipher Suites (1 suite)
        + b"\x01\x00"  # Compression (1 method)
        + ext_total
    )
    handshake_header = b"\x01" + struct.pack("!I", len(client_hello_body))[1:] + client_hello_body
    record_header = b"\x16\x03\x01" + struct.pack("!H", len(handshake_header))
    return record_header + handshake_header


def _recv_exact(sock: socket.socket, n: int, timeout: float = 5.0) -> bytes:
    """循环读取直到收满 n 字节 (TCP 流式)"""
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _wait_for(predicate, timeout: float = 5.0, interval: float = 0.05) -> bool:
    """轮询等待条件成立, 返回是否在超时前成立"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


# ==============================================================================
# fixtures
# ==============================================================================
@pytest.fixture
def relay():
    """启动独立 L4RelayServer 实例 (SNI 主端口空闲端口), 测试后停止"""
    server = L4RelayServer(host="127.0.0.1", port=_find_free_port())
    yield server
    server.stop()


@pytest.fixture
def mock_proxy_echo():
    """回显模式 mock CONNECT 代理"""
    proxy = TunnelMockProxy().start()
    yield proxy
    proxy.stop()


def _start_relay_with(server: L4RelayServer, proxy_port: int, domain: str,
                      proxy_addr: Optional[Tuple[str, int]] = None) -> None:
    """注册代理路由 + 注入代理地址 + 启动 relay (集中公共步骤)"""
    server.add_proxy_route(proxy_port, domain)
    if proxy_addr is not None:
        server.set_proxy_addr(*proxy_addr)
    ok, msg = server.start()
    assert ok, f"relay 启动失败: {msg}"


def _assert_conn_closed(sock: socket.socket) -> bool:
    """读取直到 EOF/重置, 返回连接是否被对端关闭"""
    try:
        data = sock.recv(1024)
        return data == b""
    except (ConnectionResetError, OSError):
        return True


# ==============================================================================
# 1. CONNECT 目标来自端口映射而非 SNI
# ==============================================================================
class TestPortMappingNotSni:
    def test_connect_target_from_port_mapping_not_sni(self, relay, mock_proxy_echo):
        """连接 relay 代理端口, ClientHello SNI 为无关域名 -> mock 代理记录 CONNECT 目标 == 端口映射域名"""
        proxy_port = _find_free_port()
        _start_relay_with(relay, proxy_port, "mapped.example.com", ("127.0.0.1", mock_proxy_echo.port))

        sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0)
        try:
            sock.sendall(_build_client_hello("unrelated.example.com"))
            assert _wait_for(lambda: bool(mock_proxy_echo.record)), "mock 代理未收到 CONNECT 请求"
            assert mock_proxy_echo.record == ["mapped.example.com:443"], \
                f"CONNECT 目标应来自端口映射, 实际: {mock_proxy_echo.record}"
            assert "unrelated.example.com" not in "".join(mock_proxy_echo.record), \
                "CONNECT 目标混入了 SNI 域名"
        finally:
            sock.close()


# ==============================================================================
# 2. 真隧道字节透明性 (回显透传)
# ==============================================================================
class TestTunnelTransparency:
    def test_byte_transparent_through_tunnel(self, relay, mock_proxy_echo):
        """回显模式下随机字节流双向透传一致 (含 0x00 / 0xff)"""
        proxy_port = _find_free_port()
        _start_relay_with(relay, proxy_port, "mapped.example.com", ("127.0.0.1", mock_proxy_echo.port))

        payload = bytes(range(256)) * 4 + b"\x00\xff\x00\xfe"  # 1028 字节
        sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0)
        try:
            sock.sendall(payload)
            echoed = _recv_exact(sock, len(payload))
            assert echoed == payload, "隧道字节透传不一致"
        finally:
            sock.close()


# ==============================================================================
# 3. 端到端 TLS 隧道 (relay 未篡改 TLS 握手)
# ==============================================================================
class TestEndToEndTls:
    def test_end_to_end_tls_through_tunnel(self, relay):
        """本机自签 TLS 服务器 + mock 代理 CONNECT 后转发 -> 客户端经 relay 端口握手成功 + 应用数据往返"""
        tls_port, cleanup_tls = start_tls_echo_server()
        try:
            proxy = TunnelMockProxy(target=("127.0.0.1", tls_port)).start()
            try:
                proxy_port = _find_free_port()
                _start_relay_with(relay, proxy_port, "relay-test.local", ("127.0.0.1", proxy.port))

                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0)
                tls = ctx.wrap_socket(raw, server_hostname="relay-test.local")
                try:
                    payload = b"hello over tls tunnel \x00\x01\xff"
                    tls.sendall(payload)
                    echoed = tls.recv(4096)
                    assert echoed == payload, "TLS 隧道应用数据往返不一致"
                    assert proxy.record == ["relay-test.local:443"]
                finally:
                    tls.close()
            finally:
                proxy.stop()
        finally:
            cleanup_tls()


# ==============================================================================
# 4. 空 SNI 兼容
# ==============================================================================
class TestEmptySni:
    def test_empty_sni_compatible(self, relay, mock_proxy_echo):
        """无 SNI ClientHello (extract_sni 返回 None) -> CONNECT 仍按端口映射域名"""
        proxy_port = _find_free_port()
        _start_relay_with(relay, proxy_port, "pixiv.net", ("127.0.0.1", mock_proxy_echo.port))

        hello = _build_client_hello(None)
        assert extract_sni_from_client_hello(hello) is None, "构造的 ClientHello 不应含 SNI"

        sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0)
        try:
            sock.sendall(hello)
            assert _wait_for(lambda: bool(mock_proxy_echo.record)), "mock 代理未收到 CONNECT 请求"
            assert mock_proxy_echo.record == ["pixiv.net:443"], \
                f"空 SNI 下 CONNECT 仍应按端口映射, 实际: {mock_proxy_echo.record}"
        finally:
            sock.close()


# ==============================================================================
# 5/6. 代理不可达 / CONNECT 非 200 -> 关闭连接
# ==============================================================================
class TestProxyFailureCloses:
    def test_proxy_unavailable_closes(self, relay):
        """set_proxy_addr 指向死端口 -> 代理不可达 -> 客户端连接被关闭"""
        proxy_port = _find_free_port()
        _start_relay_with(relay, proxy_port, "mapped.example.com", ("127.0.0.1", _find_free_port()))

        sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0)
        try:
            sock.sendall(_build_client_hello("mapped.example.com"))
            assert _assert_conn_closed(sock), "代理不可达时连接应被关闭而非悬挂/透传"
        finally:
            sock.close()

    def test_connect_reject_non_200(self, relay):
        """mock 代理返回 407 -> CONNECT 非 200 -> 连接被关闭"""
        proxy = TunnelMockProxy(response_line="HTTP/1.1 407 Proxy Authentication Required").start()
        try:
            proxy_port = _find_free_port()
            _start_relay_with(relay, proxy_port, "mapped.example.com", ("127.0.0.1", proxy.port))

            sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5.0)
            try:
                sock.sendall(_build_client_hello("mapped.example.com"))
                assert _assert_conn_closed(sock), "CONNECT 非 200 时连接应被关闭"
                assert proxy.record == ["mapped.example.com:443"], "代理应收到 CONNECT 请求"
            finally:
                sock.close()
        finally:
            proxy.stop()


# ==============================================================================
# 7. SNI 直连路径不受代理路由注册影响
# ==============================================================================
class TestSniDirectPath:
    # 已知问题暴露点: l4_relay._sync_tunnel_servers 启动时会把不在 proxy_routes
    # 中的 SNI 主端口当作废弃端口关闭 (current - desired), 导致本用例在修复前失败。
    # 本用例断言的是架构文档规定的行为: 主端口 + 代理端口应同时存活。
    def test_sni_direct_path_untouched(self, relay):
        """注册代理路由后, SNI 直连路由 (add_route + 本地 TCP 回显服务器) 仍正常"""
        echo = EchoServer().start()
        try:
            proxy_port = _find_free_port()
            relay.add_proxy_route(proxy_port, "mapped.example.com")
            relay.add_route("echo.example.com", "127.0.0.1", echo.port)
            # 代理指向死端口: 若 relay 误走代理转发路径, 连接必然被关闭 (测试即失败)
            _start_relay_with(relay, proxy_port, "mapped.example.com", ("127.0.0.1", _find_free_port()))

            # SNI 主端口直连路径
            # relay 直连路径会回放完整首包 (ClientHello + payload), echo 服务器回显全部字节,
            # 客户端需先读掉 ClientHello 回显, 再读 payload 进行比较
            payload = b"direct-path-data-\x00-\xff"
            client_hello = _build_client_hello("echo.example.com")
            sock = socket.create_connection(("127.0.0.1", relay.port), timeout=5.0)
            try:
                sock.sendall(client_hello + payload)
                echoed_hello = _recv_exact(sock, len(client_hello))
                assert echoed_hello == client_hello, "SNI 直连路径 ClientHello 回显不一致"
                echoed = _recv_exact(sock, len(payload))
                assert echoed == payload, "SNI 直连路径回显不一致"
            finally:
                sock.close()
        finally:
            echo.stop()


# ==============================================================================
# 8. 代理端口首包无限等待 (nginx keepalive 兼容)
# ==============================================================================
class TestKeepaliveIdle:
    def test_keepalive_idle_survives(self, relay, mock_proxy_echo):
        """连接代理端口后空闲 >3s (超过 SNI 端口 2.0s 阈值) 连接仍存活, 再发数据正常透传"""
        proxy_port = _find_free_port()
        _start_relay_with(relay, proxy_port, "mapped.example.com", ("127.0.0.1", mock_proxy_echo.port))

        sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=8.0)
        try:
            time.sleep(3.2)  # 空闲超过 SNI 端口首包 2.0s 超时
            payload = b"ping-after-idle"
            sock.sendall(payload)
            echoed = _recv_exact(sock, len(payload), timeout=5.0)
            assert echoed == payload, "keepalive 空闲后透传失败 (连接可能被 2s 超时关闭)"
        finally:
            sock.close()


# ==============================================================================
# 9. set_proxy_tunnels 运行中在线增删监听端口
# ==============================================================================
class TestDynamicTunnels:
    def test_set_proxy_tunnels_dynamic(self, relay, mock_proxy_echo):
        """运行中 set_proxy_tunnels 新增端口 -> 新端口可连可透传; clear 后端口关闭"""
        relay.set_proxy_addr("127.0.0.1", mock_proxy_echo.port)
        ok, msg = relay.start()
        assert ok, msg

        new_port = _find_free_port()
        relay.set_proxy_tunnels({new_port: "mapped.example.com"})

        # 轮询等待新端口监听就绪 (asyncio 线程内异步同步)
        sock = None
        for _ in range(100):
            try:
                sock = socket.create_connection(("127.0.0.1", new_port), timeout=1.0)
                break
            except OSError:
                time.sleep(0.05)
        assert sock is not None, "set_proxy_tunnels 后新端口未就绪"
        try:
            payload = b"dynamic-tunnel"
            sock.sendall(payload)
            echoed = _recv_exact(sock, len(payload), timeout=5.0)
            assert echoed == payload, "动态端口隧道透传失败"
            assert mock_proxy_echo.record == ["mapped.example.com:443"]
        finally:
            sock.close()

        # clear_proxy_routes -> 端口应关闭
        relay.clear_proxy_routes()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                s = socket.create_connection(("127.0.0.1", new_port), timeout=1.0)
                s.close()
                time.sleep(0.05)
            except OSError:
                break
        else:
            pytest.fail("clear_proxy_routes 后代理端口仍可连接")


# ==============================================================================
# 10. relay 生命周期 (多端口)
# ==============================================================================
class TestRelayLifecycle:
    # 与 TestSniDirectPath 同一根因: SNI 主端口启动后即被 _sync_tunnel_servers 关闭,
    # 修复前 "两端口均在监听" 断言会失败。
    def test_relay_lifecycle_multi_port(self):
        """start/stop 多端口 (SNI 主端口 + 代理端口) 正常, 停止后端口全部关闭"""
        server = L4RelayServer(host="127.0.0.1", port=_find_free_port())
        proxy_port = _find_free_port()
        server.add_proxy_route(proxy_port, "mapped.example.com")

        ok, msg = server.start()
        assert ok, msg
        assert server.is_running()

        # 两个端口均在监听
        for p in (server.port, proxy_port):
            c = socket.create_connection(("127.0.0.1", p), timeout=3.0)
            c.close()

        stop_ok, stop_msg = server.stop()
        assert stop_ok, stop_msg
        assert not server.is_running()

        # 停止后端口应关闭
        for p in (server.port, proxy_port):
            with pytest.raises(OSError):
                socket.create_connection(("127.0.0.1", p), timeout=1.0)
