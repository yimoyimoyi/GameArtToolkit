#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一次性验证: nginx stub_status 在本机可用、且输出可解析 (不碰生产配置)。

在临时 prefix 下起一个**只监听 127.0.0.1:44421** 的极简 nginx, 请求 /nginx_status,
打印原始响应与解析结果, 然后立刻关掉。用于在改生产 nginx.conf 之前确认:
  · 该 nginx 构建确实带 stub_status 模块;
  · 输出格式与我们的解析器一致;
  · 该端口仅回环可达。
"""
from __future__ import annotations

import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NGINX_EXE = ROOT / "nginx" / "nginx.exe"
PORT = 44421

CONF = f"""worker_processes 1;
error_log logs/error.log;
pid logs/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    server {{
        listen 127.0.0.1:{PORT};
        server_name _;
        location = /nginx_status {{
            stub_status;
        }}
        location / {{ return 404; }}
    }}
}}
"""


def fetch(path: str = "/nginx_status", timeout: float = 5.0):
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    except Exception as e:
        return None, f"CONNECT-FAIL {type(e).__name__}: {e}"
    try:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                  f"Connection: close\r\n\r\n".encode())
        buf = b""
        while len(buf) < 65536:
            c = s.recv(4096)
            if not c:
                break
            buf += c
        return buf, None
    except Exception as e:
        return None, f"IO-FAIL {type(e).__name__}: {e}"
    finally:
        try:
            s.close()
        except Exception:
            pass


def parse_status(text: str):
    """解析 stub_status 回应体 (与将写进 nginx_manager 的解析器同判据)"""
    out = {}
    for pat, key in ((r"Active connections:\s*(\d+)", "active"),
                     (r"\s(\d+)\s+\d+\s+\d+\s*$", None)):
        pass
    m = re.search(r"Active connections:\s*(\d+)", text)
    if m:
        out["active"] = int(m.group(1))
    m = re.search(r"server accepts handled requests\s*\n\s*(\d+)\s+(\d+)\s+(\d+)", text)
    if m:
        out["accepts"], out["handled"], out["requests"] = (int(m.group(1)),
                                                           int(m.group(2)),
                                                           int(m.group(3)))
    m = re.search(r"Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)", text)
    if m:
        out["reading"], out["writing"], out["waiting"] = (int(m.group(1)),
                                                          int(m.group(2)),
                                                          int(m.group(3)))
    return out


def main() -> int:
    if not NGINX_EXE.exists():
        print(f"未找到 {NGINX_EXE}", file=sys.stderr)
        return 2
    # ⚠ 不用 TemporaryDirectory: Windows 下 nginx 退出后仍可能短暂持有 prefix 目录,
    #   清理会抛 PermissionError: [WinError 32] 并把真实结论淹没在 traceback 里
    #   (实测踩到)。这里用固定目录 + 显式 best-effort 清理。
    import shutil
    prefix = Path(tempfile.gettempdir()) / "gat_nginx_stub_check"
    if prefix.exists():
        shutil.rmtree(prefix, ignore_errors=True)
    (prefix / "logs").mkdir(parents=True, exist_ok=True)
    (prefix / "conf").mkdir(parents=True, exist_ok=True)
    # nginx 启动时需要这些临时目录**已存在** (Win 下它自己不会建) ——
    # 否则报 [emerg] CreateDirectory() ".../temp/client_body_temp" failed
    for _d in ("client_body_temp", "proxy_temp", "fastcgi_temp", "scgi_temp", "uwsgi_temp"):
        (prefix / "temp" / _d).mkdir(parents=True, exist_ok=True)
    (prefix / "conf" / "nginx.conf").write_text(CONF, encoding="utf-8")

    proc = subprocess.Popen([str(NGINX_EXE), "-p", str(prefix), "-c", "conf/nginx.conf"],
                            cwd=str(prefix),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        resp, err = fetch()
        print("=== /nginx_status ===")
        if err:
            print("  ", err)
            print("   (nginx 启动失败或端口不可达)")
            errlog = prefix / "logs" / "error.log"
            if errlog.exists():
                print("   error.log:", errlog.read_text(encoding="utf-8",
                                                        errors="ignore")[-600:])
            return 1
        head, _, body = resp.partition(b"\r\n\r\n")
        print("  status line:", head.split(b"\r\n")[0].decode("latin1"))
        print("  raw body:")
        for ln in body.decode("utf-8", "replace").splitlines():
            print("     | " + ln)
        print("  parsed:", parse_status(body.decode("utf-8", "replace")))
        print()
        print("=== 非回环可达性 (应连不上/被拒) ===")
        try:
            ip = socket.gethostbyname(socket.gethostname())
            t = socket.create_connection((ip, PORT), timeout=3)
            t.close()
            print(f"  ⚠ 从 {ip} 也能连上 —— listen 未限定回环?")
        except Exception as e:
            print(f"  从本机网卡地址连接: {type(e).__name__} (预期: 连不上)")
        return 0
    finally:
        try:
            subprocess.run([str(NGINX_EXE), "-p", str(prefix), "-c", "conf/nginx.conf",
                            "-s", "stop"], cwd=str(prefix), timeout=5,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        time.sleep(0.5)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        shutil.rmtree(prefix, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
