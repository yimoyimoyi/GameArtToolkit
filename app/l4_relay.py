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
from pathlib import Path
from typing import Dict, Optional, Tuple, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from service_profile import get_profile_by_domain, PROFILES_BY_ID


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
    """L4 TCP 隧道与 SNI 路由转发服务"""

    def __init__(self, host: str = "127.0.0.1", port: int = 44301):
        self.host = host
        self.port = port
        self.routes: Dict[str, Tuple[str, int]] = {}  # domain -> (target_ip, target_port)
        self.default_upstream: Optional[Tuple[str, int]] = None
        self._server: Optional[asyncio.Server] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._is_running = False

    def add_route(self, domain: str, target_ip: str, target_port: int = 443):
        """注册或更新 SNI 目标路由"""
        self.routes[domain.lower()] = (target_ip, target_port)

    def set_default_upstream(self, target_ip: str, target_port: int = 443):
        """设置未匹配到 SNI 时的兜底上游"""
        self.default_upstream = (target_ip, target_port)

    def is_running(self) -> bool:
        return self._is_running

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """双向单向数据泵 (带缓冲高吞吐流式 copy)"""
        try:
            while True:
                buf = await reader.read(65536)
                if not buf:
                    break
                writer.write(buf)
                await writer.drain()
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

    async def _handle_connection(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        """处理入站 TCP 连接: 嗅探 SNI -> 匹配 Upstream -> 透明转发"""
        upstream_reader = None
        upstream_writer = None
        try:
            # 1. 尝试读取前导握手包 (最多等待 2.0 秒)
            first_chunk = await asyncio.wait_for(client_reader.read(4096), timeout=2.0)
            if not first_chunk:
                client_writer.close()
                return

            # 2. 嗅探 SNI
            sni = extract_sni_from_client_hello(first_chunk)
            target = None

            if sni:
                # 查自定义路由表
                if sni in self.routes:
                    target = self.routes[sni]
                else:
                    # 查 Service Profile 候选 IP
                    profile = get_profile_by_domain(sni)
                    if profile and profile.candidate_ips:
                        target = (profile.candidate_ips[0], 443)

            if not target:
                target = self.default_upstream

            if not target:
                # 无上游可用，安全关闭
                client_writer.close()
                return

            target_ip, target_port = target

            # 3. 连接目标上游
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, target_port),
                timeout=3.0
            )

            # 4. 回放首个握手包给上游
            upstream_writer.write(first_chunk)
            await upstream_writer.drain()

            # 5. 启动双向透明数据传输
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

    def _run_event_loop(self):
        """后台独立线程运行 asyncio 事件循环"""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._stop_event = asyncio.Event()

        async def _main():
            self._server = await asyncio.start_server(
                self._handle_connection, self.host, self.port, reuse_address=True
            )
            self._is_running = True
            try:
                await self._stop_event.wait()
            finally:
                if self._server:
                    self._server.close()
                    await self._server.wait_closed()

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
        """在后台守护线程中启动 L4 Relay 服务"""
        if self._is_running:
            return True, f"L4 Relay 已经在运行中 ({self.host}:{self.port})"
        try:
            self._thread = threading.Thread(target=self._run_event_loop, daemon=True, name="L4RelayThread")
            self._thread.start()
            import time
            time.sleep(0.15)
            if self._is_running:
                return True, f"L4 Relay 启动成功 (监听 {self.host}:{self.port})"
            return False, "L4 Relay 启动未就绪"
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
