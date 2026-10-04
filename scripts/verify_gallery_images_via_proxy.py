# -*- coding: utf-8 -*-
"""
端到端验证 (第二段): **画廊缩略图 / 大图 / H@H 节点** 经代理能否真正取到

上一段已证: e-hentai 首页与画廊页 200, ehgt.org 的 UI 图能下 (4/4 是 PNG/GIF 魔数)。
本段继续取**真正的画廊图片**:
  · e-hentai: 查看页 (/-<token>) 里的 `#img` 大图 URL —— 通常指向 `*.hath.network`
  · nhentai : API `https://nhentai.net/api/gallery/<id>` 给 `pages[].path`,
             图片在 `https://i.nhentai.net/galleries/<media_id>/<path>`

判据: HTTP 200 + 图片魔数 ⇒ **经服务真的能用** (这才是用户要的结论)。

用法: python -X utf8 scripts/verify_gallery_images_via_proxy.py
"""

import json
import re
import socket
import ssl
import sys
from pathlib import Path

_PROXY = ("127.0.0.1", 7897)
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
_MAGIC = {b"\xff\xd8\xff": "JPEG", b"\x89PNG": "PNG", b"RIFF": "WEBP", b"GIF8": "GIF"}


def get(host, path, port=443, referer="", limit=600000, timeout=30.0):
    ss = None
    try:
        s = socket.create_connection(_PROXY, timeout=timeout)
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
            return None, b"", "CONNECT 被拒"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=host)
        hdr = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {_UA}\r\n"
               f"Accept: */*\r\n")
        if referer:
            hdr += f"Referer: {referer}\r\n"
        ss.sendall((hdr + "Connection: close\r\n\r\n").encode())
        got = b""
        while len(got) < limit:
            c = ss.recv(65536)
            if not c:
                break
            got += c
        if not got:
            return None, b"", "0 字节"
        head, _, body = got.partition(b"\r\n\r\n")
        m = re.match(r"HTTP/\d\.\d\s+(\d+)",
                     head.split(b"\r\n")[0].decode("latin-1", "replace"))
        return (int(m.group(1)) if m else None), body, ""
    except Exception as e:
        return None, b"", f"{type(e).__name__}: {str(e)[:60]}"
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


def report(label, host, path, port=443, referer=""):
    st, body, note = get(host, path, port=port, referer=referer)
    k = kind(body) if st == 200 else "-"
    verdict = "✅ 真图片" if (st == 200 and k != "非图片") else (
        f"HTTP {st}" if st else note)
    print("  %-30s %-42s %-10s %-8s %s" % (
        label, (host + path)[:42], f"{len(body)}B", k, verdict))
    return st == 200 and k != "非图片"


def main() -> int:
    print("=" * 104)
    print("一、e-hentai: 进画廊查看页, 抓 #img 大图 (通常指向 *.hath.network)")
    print("=" * 104)
    st, body, _ = get("e-hentai.org", "/g/4230053/c21653f19f/", referer="https://e-hentai.org/")
    txt = body.decode("utf-8", "replace")
    # e-hentai 用页面里的 gid/token 构造查看页: /s/<token>/<gid>-<page>
    view = re.findall(r'href="(https?://e-hentai\.org/s/[^"]+)"', txt)
    print(f"  画廊页 {st}, 查看页链接 {len(view)} 条: {view[:2]}")

    # 缩略图 (画廊页内嵌的 <img src>)
    thumbs = re.findall(r'<img[^>]+src="(https?://[^"]+)"', txt)
    thumbs = [t for t in dict.fromkeys(thumbs) if "ehgt.org" in t][:3]
    got_any = False
    for t in thumbs:
        m = re.match(r"https?://([^/]+)(/.*)$", t)
        if m:
            got_any |= report("缩略图", m.group(1), m.group(2),
                              referer="https://e-hentai.org/")

    # 进查看页拿大图
    if view:
        vp = "/" + view[0].split("e-hentai.org", 1)[1]
        st2, b2, _ = get("e-hentai.org", vp, referer="https://e-hentai.org/")
        t2 = b2.decode("utf-8", "replace")
        print(f"  查看页 {vp[:56]} -> {st2}, {len(b2)} 字节")
        full = re.findall(r'id="img"[^>]+src="(https?://[^"]+)"', t2)
        if not full:
            full = re.findall(r'"(https?://[^"]*hath\.network[^"]*)"', t2)
        print(f"  大图 URL: {full[:2]}")
        for u in full[:2]:
            m = re.match(r"https?://([^/]+?)(:(\d+))?(/.*)$", u)
            if m:
                port = int(m.group(3)) if m.group(3) else 443
                got_any |= report(f"H@H 大图 :{port}", m.group(1), m.group(4),
                                  port=port, referer="https://e-hentai.org/")

    print()
    print("=" * 104)
    print("二、nhentai: API 取 media_id + pages, 再取真实图片")
    print("=" * 104)
    st3, b3, note3 = get("nhentai.net", "/api/gallery/1")
    print(f"  API /api/gallery/1 -> {st3} ({note3 or 'ok'}), {len(b3)} 字节")
    media_id = None
    if b3:
        try:
            j = json.loads(b3.decode("utf-8", "replace"))
            media_id = j.get("media_id")
            pages = (j.get("images") or {}).get("pages") or []
            print(f"  media_id={media_id}  pages={len(pages)}  首项={pages[0] if pages else None}")
        except Exception as e:
            print("  JSON 解析失败:", type(e).__name__)
    if media_id:
        # 封面 (thumb) 与首图都试
        for label, path in (("封面 jpg", f"/galleries/{media_id}/cover.jpg"),
                            ("封面 webp", f"/galleries/{media_id}/cover.webp"),
                            ("缩略图", f"/galleries/{media_id}/thumb.jpg"),
                            ("首图", f"/galleries/{media_id}/1.jpg")):
            report(label, "i.nhentai.net", path, referer="https://nhentai.net/")
        report("首图(t3)", "t3.nhentai.net", f"/galleries/{media_id}/1.jpg",
               referer="https://nhentai.net/")
        report("首图(同目录)", "i.nhentai.net",
               f"/galleries/{media_id}/1.webp", referer="https://nhentai.net/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
