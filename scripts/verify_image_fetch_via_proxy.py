# -*- coding: utf-8 -*-
"""
端到端验证: **经代理之后, e-hentai / nhentai 的图片到底能不能取到** (只读)

为什么要做这一步 (用户提问):
  "经代理可用属于不干扰的决策问题, 问题是经服务能否使用"
  —— 根路径 200/404 只证明"域名活着", **不证明图片可取**。
  对图床, 真正的判据是"从真实画廊页拿到真实图片 URL, 并把它下下来"。

做法 (全程经本地代理 CONNECT, 不依赖本机 DNS):
  1. 取 e-hentai 首页 → 抽一个画廊链接;
  2. 取画廊页 → 抽真实图片 URL (e-hentai 的图在 `*.hath.network:15443` 或 ehgt.org);
  3. 逐个下载, 报告状态码 + 字节数 + 是否为图片魔数;
  4. 对 nhentai 做同样的事 (t3.nhentai.net 的 API 给图路径)。

用法: python -X utf8 scripts/verify_image_fetch_via_proxy.py [--proxy 127.0.0.1:7897]
"""

import argparse
import re
import socket
import ssl
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"

_MAGIC = {b"\xff\xd8\xff": "JPEG", b"\x89PNG": "PNG", b"RIFF": "WEBP",
          b"GIF8": "GIF"}


def _tunnel(host: str, port: int, proxy: tuple, timeout: float):
    import socket as _s
    s = _s.create_connection(proxy, timeout=timeout)
    s.settimeout(timeout)
    s.sendall((f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").encode())
    b = b""
    while b"\r\n\r\n" not in b:
        c = s.recv(4096)
        if not c:
            break
        b += c
    if b" 200" not in b.split(b"\r\n")[0]:
        s.close()
        raise OSError("CONNECT 被拒: " + b.split(b"\r\n")[0].decode("latin-1", "replace"))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(s, server_hostname=host)


def get(host: str, path: str, proxy: tuple, port: int = 443,
        timeout: float = 25.0, referer: str = "", limit: int = 400000):
    """经代理取一个 URL; 返回 (status, body_bytes, note)"""
    ss = None
    try:
        ss = _tunnel(host, port, proxy, timeout)
        hdr = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {_UA}\r\n"
               f"Accept: */*\r\nAccept-Language: en-US,en;q=0.9\r\n")
        if referer:
            hdr += f"Referer: {referer}\r\n"
        ss.sendall((hdr + "Connection: close\r\n\r\n").encode())
        got = b""
        while len(got) < limit:
            c = ss.recv(32768)
            if not c:
                break
            got += c
        if not got:
            return None, b"", "0 字节 (服务端不应答)"
        head, _, body = got.partition(b"\r\n\r\n")
        first = head.split(b"\r\n")[0].decode("latin-1", "replace")
        m = re.match(r"HTTP/\d\.\d\s+(\d+)", first)
        return (int(m.group(1)) if m else None), body, first
    except Exception as e:
        return None, b"", f"{type(e).__name__}: {str(e)[:70]}"
    finally:
        if ss is not None:
            try:
                ss.close()
            except Exception:
                pass


def kind(body: bytes) -> str:
    for magic, name in _MAGIC.items():
        if body.startswith(magic):
            return name
    return "非图片"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy", default="127.0.0.1:7897")
    args = ap.parse_args()
    ph, _, pp = args.proxy.partition(":")
    proxy = (ph, int(pp or 7897))

    print("=" * 100)
    print("e-hentai: 首页 → 画廊页 → 真实图片 URL → 下载")
    print("=" * 100)
    st, body, note = get("e-hentai.org", "/", proxy)
    print(f"  首页 /                            -> {st}  {len(body)} 字节")
    txt = body.decode("utf-8", "replace")
    gals = sorted(set(re.findall(r'href="(https?://e-hentai\.org/g/\d+/[a-f0-9]+/)"', txt)))
    gals += sorted(set(re.findall(r'href="(/g/\d+/[a-f0-9]+/)"', txt)))
    gals = list(dict.fromkeys(gals))[:2]
    print(f"  画廊链接: {gals or '(未抽到)'}")

    img_urls = []
    for g in gals:
        gpath = g if g.startswith("/") else "/" + g.split("e-hentai.org", 1)[1]
        st2, b2, note2 = get("e-hentai.org", gpath, proxy, referer="https://e-hentai.org/")
        t2 = b2.decode("utf-8", "replace")
        print(f"  画廊 {gpath[:44]:44} -> {st2}  {len(b2)} 字节")
        # e-hentai 图片 URL 出现在 a href / img src / data-src
        found = re.findall(r'["\'](https?://[^"\']+\.(?:jpg|jpeg|png|webp|gif))["\']', t2)
        found += re.findall(r'["\'](https?://[^"\']*hath\.network[^"\']*)["\']', t2)
        img_urls += found
    img_urls = list(dict.fromkeys(img_urls))[:4]
    print(f"  抽到图片 URL: {len(img_urls)} 条")

    print()
    print("%-52s %-6s %-10s %s" % ("图片 URL", "HTTP", "字节", "类型"))
    print("-" * 100)
    ok_img = 0
    for u in img_urls:
        m = re.match(r"https?://([^/]+)(:\d+)?(/.*)$", u)
        if not m:
            continue
        h, port_s, p = m.group(1), m.group(2), m.group(3)
        port = int(port_s[1:]) if port_s else 443
        st3, b3, _ = get(h, p, proxy, port=port, referer="https://e-hentai.org/")
        k = kind(b3) if st3 == 200 else "-"
        if st3 == 200 and k != "非图片":
            ok_img += 1
        print("%-52s %-6s %-10s %s" % ((h + p)[:52], st3, len(b3), k))

    print()
    print("=" * 100)
    print(f"e-hentai 结论: 抽到 {len(img_urls)} 条图片 URL, 其中**真正下到图片** {ok_img} 条")
    print("=" * 100)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
