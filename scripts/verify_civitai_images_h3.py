#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证 civitai 的图片是否真能经 HTTP/3 取到 (而不只是主页能开)。

为什么必须单独验 (2026-10-04): 主页 200 只证明"文档能开"。civitai 的图片走
`image.civitai.com` → 301 → `blobs-b2.civitai.com`, 而 blobs-b2 的**根路径**只是
Backblaze 的默认索引页 (301 到 backblaze.com), 完全不能说明图片可用。
必须从真实页面里取**真实图片 URL** 再打一次 —— 这是本项目"内容级可用"的一贯口径。
"""
from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "app"))
sys.path.insert(0, str(_ROOT / "scripts"))

from probe_http3_site import try_h3  # noqa: E402

IP = "172.66.152.186"
IMG_RE = re.compile(r"https://(?:image|blobs-b2)\.civitai\.com/[^\"'<>\s)]+")


def main() -> int:
    st, body, hd = asyncio.run(try_h3(IP, "civitai.com", "/"))
    html = body.decode("utf-8", "replace")
    print(f"主页: HTTP/3 {st} · {len(body)}B")
    urls, seen = [], set()
    for u in IMG_RE.findall(html):
        if u not in seen:
            seen.add(u)
            urls.append(u)
    print(f"页面内图片 URL: {len(urls)} 条 (去重后)")
    if not urls:
        print("!! 页面里没有 image./blobs-b2. URL —— 无法做内容级验证")
        return 1
    ok = failing = 0
    for u in urls[:6]:
        parts = u.split("/")
        host = parts[2]
        path = "/" + "/".join(parts[3:])
        st2, body2, hd2 = asyncio.run(try_h3(IP, host, path))
        ct = hd2.get("content-type", "")
        loc = hd2.get("location", "")
        good = bool(st2 and (200 <= st2 < 400) and (len(body2) > 1000 or "image" in ct))
        ok += 1 if good else 0
        failing += 0 if good else 1
        print(f"  {'OK  ' if good else 'BAD '} {host:<22} {st2}  {len(body2):>8}B  ct={ct[:28]:<28} {('→ ' + loc[:40]) if loc else ''}")
        print(f"       {path[:96]}")
    print()
    print(f"结论: 图片可用 {ok} / 失败 {failing}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
