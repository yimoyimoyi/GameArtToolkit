# -*- coding: utf-8 -*-
"""
PixivToolkit - 极简 L4 TCP Relay 与 TLS SNI 嗅探路由引擎 (L4 Relay & SNI Router)

核心特性:
- 极轻量 (<20MB 内存), 原生 asyncio 异步并发
- 零侵入解析 TLS 1.2 / TLS 1.3 ClientHello 首包中的 SNI (server_name 扩展)
- 动态路由: 根据 SNI 路由到对应服务的最优 CDN 节点
- 首包完整回放 + 双向透明数据流管道 (TCP Tunnel)
"""

import sys
import struct
import asyncio
import threading
import socket
import functools
from pathlib import Path
from typing import Dict, Optional, Tuple, Callable, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from service_profile import get_profile_by_domain, PROFILES_BY_ID
from config_store import load_config


def extract_sni_from_client_hello(data: bytes) -> Optional[str]:
    """
    从 TLS ClientHello 首包二进制流中提取 SNI (Server Name Indication)

    RFC 5246 / RFC 8446 协议解析规范:
    - 0x16: TLS Handshake Record
    - 0x01: ClientHello
    - 扩展类型 0x0000: server_name
    """
    try:
        if len(data) < 44:
            return None

        # 校验 TLS 握手记录头
        if data[0] != 0x16:  # Handshake Record
            return None

        # record_len = struct.unpack("!H", data[3:5])[0]
        if data[5] != 0x01:  # Handshake Type: ClientHello
            return None

        pos = 43  # 5 (Record Header) + 4 (Handshake Header) + 2 (Version) + 32 (Random)

        # 1. 跳过 Session ID
        if pos >= len(data):
            return None
        session_id_len = data[pos]
        pos += 1 + session_id_len

        # 2. 跳过 Cipher Suites
        if pos + 2 > len(data):
            return None
        cipher_suites_len = struct.unpack("!H", data[pos:pos + 2])[0]
        pos += 2 + cipher_suites_len

        # 3. 跳过 Compression Methods
        if pos >= len(data):
            return None
        compression_len = data[pos]
        pos += 1 + compression_len

        # 4. 进入 Extensions 扩展列表
        if pos + 2 > len(data):
            return None
        extensions_len = struct.unpack("!H", data[pos:pos + 2])[0]
        pos += 2
        extensions_end = pos + extensions_len

        # 遍历扩展项
        while pos + 4 <= min(extensions_end, len(data)):
            ext_type, ext_len = struct.unpack("!HH", data[pos:pos + 4])
            pos += 4
            if ext_type == 0x0000:  # server_name 扩展
                if pos + 2 > len(data):
                    return None
                # server_name_list_len = struct.unpack("!H", data[pos:pos + 2])[0]
                name_pos = pos + 2
                if name_pos >= len(data):
                    return None
                name_type = data[name_pos]
                name_pos += 1
                if name_type == 0:  # 0 = host_name
                    if name_pos + 2 > len(data):
                        return None
                    name_len = struct.unpack("!H", data[name_pos:name_pos + 2])[0]
                    name_pos += 2
                    sni_bytes = data[name_pos:name_pos + name_len]
                    return sni_bytes.decode("ascii", errors="ignore").lower()
            pos += ext_len

    except Exception:
        pass

    return None


class L4RelayServer:
    """L4 TCP 隧道与 SNI 路由转发服务 (支持经本地 HTTP 代理 CONNECT 转发)

    双模式:
    - SNI 直连模式 (默认端口): 嗅探 ClientHello SNI -> 匹配候选 IP 直连
    - 代理转发模式 (端口静态映射): 端口 -> 目标域名, 经本地代理 (upstream_proxy)
      CONNECT 域名:443 隧道转发, 兼容空 SNI / 伪 SNI / host SNI 三种模式
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 44301):
        self.host = host
        self.port = port
        self.routes: Dict[str, Tuple[str, int]] = {}  # domain -> (target_ip, target_port)
        self.default_upstream: Optional[Tuple[str, int]] = None
        # 代理转发模式: 监听端口 -> CONNECT 目标域名 (静态映射, 端口即路由)
        self.proxy_routes: Dict[int, str] = {}
        # 显式注入的代理地址 (测试用); None 时从 config.json 实时读取
        self._proxy_addr_override: Optional[Tuple[str, int]] = None
        self._server: Optional[asyncio.Server] = None
        # 多端口监听: 端口 -> asyncio.Server (含 SNI 主端口与代理转发端口)
        self._servers: Dict[int, asyncio.Server] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._is_running = False

    def add_route(self, domain: str, target_ip: str, target_port: int = 443):
        """注册或更新 SNI 目标路由"""
        self.routes[domain.lower()] = (target_ip, target_port)

    def set_default_upstream(self, target_ip: str, target_port: int = 443):
        """设置未匹配到 SNI 时的兜底上游"""
        self.default_upstream = (target_ip, target_port)

    # --------------------------------------------------------------------------
    # 代理转发模式路由管理 (端口 -> CONNECT 目标域名)
    # --------------------------------------------------------------------------
    def add_proxy_route(self, port: int, domain: str):
        """注册代理转发端口路由: 该端口收到的 TLS 流量经本地代理 CONNECT <domain>:443 转发"""
        self.proxy_routes[port] = domain.lower()

    def set_proxy_tunnels(self, mapping: Dict[int, str]):
        """批量更新代理转发端口映射; 运行中则在线同步监听端口 (新增/移除)"""
        self.proxy_routes = {int(p): str(d).lower() for p, d in mapping.items()}
        if self._is_running and self._loop:
            asyncio.run_coroutine_threadsafe(self._sync_tunnel_servers(), self._loop)

    def clear_proxy_routes(self):
        """清空全部代理转发端口映射 (运行中同步移除监听)"""
        self.set_proxy_tunnels({})

    def set_proxy_addr(self, host: Optional[str], port: Optional[int] = None):
        """显式注入上游代理地址 (测试用); 传 None 恢复从 config.json 实时读取"""
        if host is None:
            self._proxy_addr_override = None
        else:
            self._proxy_addr_override = (host, int(port))

    def _load_proxy_addr(self) -> Optional[Tuple[str, int]]:
        """获取上游代理地址: 优先显式注入, 否则实时读取 config.json upstream_proxy"""
        if self._proxy_addr_override is not None:
            return self._proxy_addr_override
        try:
            cfg = load_config().get("upstream_proxy", {})
            if not cfg.get("enabled", True):
                return None
            return (str(cfg.get("host", "127.0.0.1")), int(cfg.get("port", 7897)))
        except Exception:
            return None

    def is_running(self) -> bool:
        return self._is_running

    def _tune_socket(self, writer: asyncio.StreamWriter):
        """对底层 TCP Socket 进行性能调优 (禁用 Nagle, 扩大收发窗口)"""
        try:
            sock = writer.get_extra_info("socket")
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
        except Exception:
            pass

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """双向单向数据泵 (带 128KB 缓冲高吞吐流式 copy 与半关闭协同)"""
        try:
            while True:
                buf = await reader.read(131072)
                if not buf:
                    break
                writer.write(buf)
                await writer.drain()
            try:
                if hasattr(writer, "write_eof") and writer.can_write_eof():
                    writer.write_eof()
            except Exception:
                pass
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    def _format_connect_target(domain: str, port: int = 443) -> str:
        """格式化 CONNECT 目标, IPv6 地址必须加方括号 (HTTP 标准要求)"""
        if ":" in domain:
            return f"[{domain}]:{port}"
        return f"{domain}:{port}"

    async def _proxy_connect(self, proxy: Tuple[str, int], domain: str, timeout: float = 2.5):
        """连接本地 HTTP 代理 -> 发送 CONNECT 隧道 -> 校验 200 -> 返回 (reader, writer, 隧道残留字节)

        纯 asyncio 实现 (与 cdn_optimizer 同步版语义一致); 读取响应头时顺带吞入的
        隧道数据通过 rest 返回, 由调用方回放, 防止丢字节
        """
        proxy_reader, proxy_writer = await asyncio.wait_for(
            asyncio.open_connection(*proxy), timeout=timeout)
        try:
            target = self._format_connect_target(domain)
            proxy_writer.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("utf-8"))
            await proxy_writer.drain()
            hdr = b""
            while b"\r\n\r\n" not in hdr:
                chunk = await asyncio.wait_for(proxy_reader.read(4096), timeout=timeout)
                if not chunk:
                    raise ConnectionError("CONNECT 响应提前 EOF")
                hdr += chunk
                if len(hdr) > 8192:
                    raise ConnectionError("CONNECT 响应头超长")
            line = hdr.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
            if " 200 " not in line:
                raise ConnectionError(f"CONNECT 隧道建立失败: {line or '无响应'}")
            rest = hdr.split(b"\r\n\r\n", 1)[1]  # 响应头之外顺带读入的隧道数据
            return proxy_reader, proxy_writer, rest
        except Exception:
            try:
                proxy_writer.close()
            except Exception:
                pass
            raise

    async def _handle_proxy_forward(self, client_reader: asyncio.StreamReader,
                                    client_writer: asyncio.StreamWriter,
                                    first_chunk: bytes, domain: str):
        """代理转发模式: 经本地代理 CONNECT <domain>:443 隧道, 首包回放 + 双向管道"""
        proxy = self._load_proxy_addr()
        if not proxy:
            # 代理未配置/禁用: 拒绝连接, 由 nginx upstream backup 直连兜底
            client_writer.close()
            return
        try:
            up_reader, up_writer, rest = await self._proxy_connect(proxy, domain)
        except Exception:
            client_writer.close()
            return
        self._tune_socket(up_writer)
        try:
            # 回放: CONNECT 响应头顺带吞入的隧道数据 + 客户端首包 (代理隧道无需 DPI 切片)
            if rest:
                up_writer.write(rest)
            up_writer.write(first_chunk)
            await up_writer.drain()
            await asyncio.gather(
                self._pipe(client_reader, up_writer),
                self._pipe(up_reader, client_writer),
                return_exceptions=True)
        finally:
            try:
                up_writer.close()
            except Exception:
                pass

    async def _handle_connection(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                                 listen_port: Optional[int] = None):
        """处理入站 TCP 连接: 代理端口 -> CONNECT 域名隧道; SNI 端口 -> 嗅探 SNI -> 直连转发"""
        upstream_reader = None
        upstream_writer = None
        try:
            self._tune_socket(client_writer)

            # 1. 尝试读取前导握手包 (代理端口无限等待以兼容 nginx keepalive 空闲; SNI 端口 2.0s)
            if listen_port and listen_port in self.proxy_routes:
                first_chunk = await client_reader.read(4096)
            else:
                first_chunk = await asyncio.wait_for(client_reader.read(4096), timeout=2.0)
            if not first_chunk:
                client_writer.close()
                return

            # 2. 代理转发模式: 端口命中静态映射 -> CONNECT 域名 (不解析 SNI, 兼容三种 SNI 模式)
            connect_domain = self.proxy_routes.get(listen_port) if listen_port else None
            if connect_domain:
                await self._handle_proxy_forward(client_reader, client_writer, first_chunk, connect_domain)
                return

            # 2. 嗅探 SNI
            sni = extract_sni_from_client_hello(first_chunk)
            candidate_list = []

            if sni:
                # 1. 查自定义路由表 (精确匹配)
                if sni in self.routes:
                    candidate_list = [self.routes[sni]]
                else:
                    # 2. 查 Service Profile (精确匹配或泛域名通配)
                    profile = get_profile_by_domain(sni)
                    if not profile:
                        # 尝试主域名后缀通配匹配
                        parts = sni.split(".")
                        for i in range(1, len(parts) - 1):
                            parent_domain = ".".join(parts[i:])
                            profile = get_profile_by_domain(parent_domain)
                            if profile:
                                break
                    if profile and profile.candidate_ips:
                        candidate_list = [(ip, 443) for ip in profile.candidate_ips]

            if not candidate_list and self.default_upstream:
                candidate_list = [self.default_upstream]

            if not candidate_list:
                # 无上游可用，安全关闭
                client_writer.close()
                return

            # 3. 连接目标上游 (尝试候选列表，支持故障转移)
            connected = False
            for target_ip, target_port in candidate_list:
                try:
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_connection(target_ip, target_port),
                        timeout=2.5
                    )
                    connected = True
                    break
                except Exception:
                    continue

            if not connected or not upstream_writer:
                client_writer.close()
                return

            self._tune_socket(upstream_writer)

            # 4. 回放首个握手包给上游 (支持 TLS 报文微切片分发以抵抗 SNI DPI 阻断)
            if len(first_chunk) > 32:
                split_point = 24  # 在 SNI 扩展前切片
                upstream_writer.write(first_chunk[:split_point])
                await upstream_writer.drain()
                upstream_writer.write(first_chunk[split_point:])
                await upstream_writer.drain()
            else:
                upstream_writer.write(first_chunk)
                await upstream_writer.drain()

            # 5. 启动双向透明高速数据管道 (256KB 内存泵)
            await asyncio.gather(
                self._pipe(client_reader, upstream_writer),
                self._pipe(upstream_reader, client_writer),
                return_exceptions=True
            )

        except Exception:
            pass
        finally:
            for w in [client_writer, upstream_writer]:
                if w:
                    try:
                        w.close()
                    except Exception:
                        pass

    async def _sync_tunnel_servers(self):
        """在线同步多端口监听: 按当前 proxy_routes 增删代理转发端口 (循环线程内调用)"""
        desired = set(self.proxy_routes.keys())
        current = set(self._servers.keys())
        # 排除 SNI 主端口 (自举端口永不参与代理端口同步, 防止被误关闭)
        for p in (current - desired) - {self.port}:
            srv = self._servers.pop(p, None)
            if srv:
                srv.close()
                await srv.wait_closed()
        for p in sorted(desired - current):
            try:
                srv = await asyncio.start_server(
                    functools.partial(self._handle_connection, listen_port=p),
                    self.host, p, reuse_address=True)
                self._servers[p] = srv
            except OSError:
                # 端口被第三方占用: 跳过该端口 (nginx 将 502, 由 backup 兜底)
                self.proxy_routes.pop(p, None)

    def _run_event_loop(self):
        """后台独立线程运行 asyncio 事件循环"""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._stop_event = asyncio.Event()

        async def _main():
            # SNI 主端口 + 全部代理转发端口
            self._servers.clear()
            try:
                srv = await asyncio.start_server(
                    functools.partial(self._handle_connection, listen_port=self.port),
                    self.host, self.port, reuse_address=True)
                self._servers[self.port] = srv
            except OSError:
                pass  # 主端口被占: 仅代理转发端口可用
            await self._sync_tunnel_servers()
            self._is_running = True
            try:
                await self._stop_event.wait()
            finally:
                for srv in list(self._servers.values()):
                    srv.close()
                    await srv.wait_closed()
                self._servers.clear()

        try:
            self._loop.run_until_complete(_main())
        except Exception:
            pass
        finally:
            try:
                # 取消并清理所有剩余任务
                pending = [t for t in asyncio.all_tasks(self._loop) if not t.done()]
                for t in pending:
                    t.cancel()
                if pending:
                    self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                self._loop.run_until_complete(self._loop.shutdown_asyncgens())
                self._loop.close()
            except Exception:
                pass
            self._is_running = False

    def start(self) -> Tuple[bool, str]:
        """在后台守护线程中启动 L4 Relay 服务 (SNI 主端口 + 代理转发端口)"""
        if self._is_running:
            return True, f"L4 Relay 已经在运行中 ({self.host}:{self.port})"
        try:
            self._thread = threading.Thread(target=self._run_event_loop, daemon=True, name="L4RelayThread")
            self._thread.start()
            import time
            time.sleep(0.2)
            if self._is_running:
                extra = f" + {len(self._servers) - 1} 个代理转发端口" if len(self._servers) > 1 else ""
                return True, f"L4 Relay 启动成功 (监听 {self.host}:{self.port}{extra})"
            return False, "L4 Relay 启动未就绪 (端口可能被占用)"
        except Exception as e:
            return False, f"启动 L4 Relay 异常: {e}"

    def stop(self) -> Tuple[bool, str]:
        """安全停止 L4 Relay 服务"""
        if not self._is_running or not self._loop:
            return True, "L4 Relay 未在运行"
        try:
            if hasattr(self, "_stop_event") and self._stop_event:
                self._loop.call_soon_threadsafe(self._stop_event.set)
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=1.5)
            self._is_running = False
            return True, "L4 Relay 已安全停止"
        except Exception as e:
            return False, f"停止 L4 Relay 异常: {e}"


# 全局单例
relay_server = L4RelayServer()
