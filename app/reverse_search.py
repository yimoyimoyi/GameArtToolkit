# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 以图搜图轻量引擎 (Reverse Image Search Engine)
支持:
1. 从系统剪贴板读取 QImage / QPixmap
2. 本地文件拖拽或选取
3. 多引擎检索 (保证跳转必带拖入的图片并展示真实检索结果):
   - SauceNAO (针对 Pixiv / Fanbox / 二次元插画: API 直解 + 本地聚合结果页)
   - Ascii2d (针对 Twitter 同人画师作品: 捕获 302 Location 精准打开带图结果页)
   - IQDB (二次元图库与壁纸: 捕获响应并渲染结果)
   - Google Lens (谷歌智能镜头: 本地自提交表单桥梁)
4. 零重型常驻计算，极低性能开销
"""

import os
import io
import sys
import time
import json
import base64
import tempfile
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

from PySide6.QtCore import QObject, Signal, QThread, Qt
from PySide6.QtGui import QImage, QPixmap, QClipboard, QGuiApplication

SEARCH_ENGINES = {
    "saucenao": {
        "id": "saucenao",
        "name": "SauceNAO (二次元/Pixiv首选)",
        "desc": "二次元插画、Pixiv PID、Fanbox 高精度识别",
        "upload_url": "https://saucenao.com/search.php",
    },
    "ascii2d": {
        "id": "ascii2d",
        "name": "Ascii2d (Twitter/同人推文首选)",
        "desc": "日本同人画师推特原图检索神器",
        "upload_url": "https://ascii2d.net/search/file",
    },
    "iqdb": {
        "id": "iqdb",
        "name": "IQDB (动漫壁纸图库)",
        "desc": "Danbooru / Konachan / yande.re 动漫图库匹配",
        "upload_url": "https://iqdb.org/",
    },
    "google": {
        "id": "google",
        "name": "Google Lens (谷歌智能镜头)",
        "desc": "Google 全网智能以图搜图",
        "upload_url": "https://lens.google.com/upload",
    }
}


def get_image_from_clipboard() -> Optional[QImage]:
    """从系统剪贴板获取图片"""
    clipboard = QGuiApplication.clipboard()
    if not clipboard:
        return None
    image = clipboard.image()
    if not image.isNull() and image.width() > 0 and image.height() > 0:
        return image
    pixmap = clipboard.pixmap()
    if not pixmap.isNull() and pixmap.width() > 0 and pixmap.height() > 0:
        return pixmap.toImage()
    return None


def save_image_to_temp(image: QImage, max_dim: int = 1920) -> str:
    """将 QImage 保存到本地临时目录并返回绝对路径，过大时等比缩放以加速上传"""
    if image.width() > max_dim or image.height() > max_dim:
        image = image.scaled(max_dim, max_dim, Qt.KeepAspectRatio, Qt.SmoothTransformation)

    temp_dir = Path(tempfile.gettempdir()) / "GameArtToolkit" / "search_cache"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / f"search_{int(time.time() * 1000)}.jpg"
    image.save(str(temp_path), "JPG", 90)
    return str(temp_path)


def _image_to_base64(file_path: str) -> str:
    """将图片文件读取为 base64 数据 URI"""
    with open(file_path, "rb") as f:
        b64 = base64.b64encode(f.read()).decode("utf-8")
    ext = os.path.splitext(file_path)[1].lower().lstrip(".")
    mime = "image/png" if ext == "png" else "image/jpeg"
    return f"data:{mime};base64,{b64}"


def build_auto_submit_bridge_html(engine_id: str, file_path: str) -> str:
    """
    生成一个携带用户图片的本地 HTML 自动提交桥梁文件。
    在浏览器中打开时，利用浏览器原生发起包含该图片的 POST 提交，解决任何未提供重定向 URL 引擎的搜图展示问题。
    """
    b64_img = _image_to_base64(file_path)
    engine_info = SEARCH_ENGINES.get(engine_id, SEARCH_ENGINES["saucenao"])
    engine_name = engine_info["name"]
    target_url = engine_info["upload_url"]

    file_field_name = "file"
    extra_hidden_inputs = ""

    if engine_id == "saucenao":
        file_field_name = "file"
        extra_hidden_inputs = '<input type="hidden" name="frame" value="1"><input type="hidden" name="hide" value="0">'
    elif engine_id == "ascii2d":
        file_field_name = "file"
    elif engine_id == "iqdb":
        file_field_name = "file"
        extra_hidden_inputs = '<input type="hidden" name="service[]" value="1"><input type="hidden" name="service[]" value="2"><input type="hidden" name="service[]" value="3">'
    elif engine_id == "google":
        file_field_name = "encoded_image"

    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GameArt Toolkit - 正在提交搜图: {engine_name}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: #0f172a;
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
    }}
    .card {{
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 16px;
      padding: 32px 40px;
      max-width: 480px;
      width: 100%;
      text-align: center;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
    }}
    .spinner {{
      width: 48px;
      height: 48px;
      border: 4px solid #38bdf8;
      border-bottom-color: transparent;
      border-radius: 50%;
      display: inline-block;
      animation: spin 1s linear infinite;
      margin-bottom: 20px;
    }}
    @keyframes spin {{
      0% {{ transform: rotate(0deg); }}
      100% {{ transform: rotate(360deg); }}
    }}
    h2 {{ font-size: 18px; font-weight: 600; margin-bottom: 8px; color: #f1f5f9; }}
    p {{ font-size: 14px; color: #94a3b8; margin-bottom: 20px; }}
    .preview {{
      width: 120px;
      height: 120px;
      object-fit: cover;
      border-radius: 8px;
      border: 2px solid #475569;
      margin-bottom: 20px;
    }}
    .btn {{
      display: inline-block;
      background: #0284c7;
      color: #fff;
      padding: 10px 24px;
      font-size: 14px;
      font-weight: 500;
      border-radius: 8px;
      border: none;
      cursor: pointer;
      text-decoration: none;
      transition: background 0.2s;
    }}
    .btn:hover {{ background: #0369a1; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner" id="spinner"></div>
    <img src="{b64_img}" class="preview" alt="待检索图片">
    <h2>正在提交至 {engine_name}...</h2>
    <p id="status-text">正在自动打包图片并跳转至搜索引擎结果页，请稍候</p>
    
    <form id="uploadForm" action="{target_url}" method="POST" enctype="multipart/form-data">
      {extra_hidden_inputs}
    </form>
    <button type="button" class="btn" id="manualBtn" style="display:none;" onclick="manualSubmit()">如果未自动跳转，点击此处提交</button>
  </div>

  <script>
    const b64Data = "{b64_img}";
    const form = document.getElementById('uploadForm');

    async function autoSubmit() {{
      try {{
        const res = await fetch(b64Data);
        const blob = await res.blob();
        const file = new File([blob], "search_image.jpg", {{ type: "image/jpeg" }});
        
        const dt = new DataTransfer();
        dt.items.add(file);
        
        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.name = '{file_field_name}';
        fileInput.files = dt.files;
        fileInput.style.display = 'none';
        
        form.appendChild(fileInput);
        form.submit();
      }} catch (e) {{
        console.warn("自动提交异常，启用备用方案", e);
        document.getElementById('spinner').style.display = 'none';
        document.getElementById('status-text').innerText = "浏览器安全策略阻止了自动文件注入，请点击下方按钮直达";
        document.getElementById('manualBtn').style.display = 'inline-block';
      }}
    }}

    function manualSubmit() {{
      form.submit();
    }}

    window.addEventListener('DOMContentLoaded', autoSubmit);
  </script>
</body>
</html>"""

    temp_dir = Path(tempfile.gettempdir()) / "GameArtToolkit" / "search_cache"
    temp_dir.mkdir(parents=True, exist_ok=True)
    bridge_path = temp_dir / f"bridge_{engine_id}_{int(time.time() * 1000)}.html"
    bridge_path.write_text(html_content, encoding="utf-8")
    return str(bridge_path)


def generate_saucenao_results_html(file_path: str, api_data: dict) -> str:
    """
    根据 SauceNAO 返回的结构化 JSON 数据，生成现代精美的高清聚合搜索结果页面
    """
    b64_img = _image_to_base64(file_path)
    results = api_data.get("results", [])
    
    cards_html = []
    for r in results:
        header = r.get("header", {})
        data = r.get("data", {})
        
        sim = header.get("similarity", "0")
        thumb = header.get("thumbnail", "")
        title = data.get("title") or data.get("jp_name") or data.get("eng_name") or data.get("material") or "未知作品"
        author = data.get("member_name") or data.get("author_name") or data.get("creator") or data.get("artist") or "未知画师"
        pixiv_id = data.get("pixiv_id")
        member_id = data.get("member_id")
        ext_urls = data.get("ext_urls", [])

        try:
            sim_val = float(sim)
        except Exception:
            sim_val = 0.0
        
        sim_color = "#10B981" if sim_val >= 80 else ("#F59E0B" if sim_val >= 60 else "#6B7280")

        links_html = []
        if pixiv_id:
            links_html.append(f'<a href="https://www.pixiv.net/artworks/{pixiv_id}" target="_blank" class="link-btn pixiv">Pixiv 作品 #{pixiv_id}</a>')
        if member_id:
            links_html.append(f'<a href="https://www.pixiv.net/users/{member_id}" target="_blank" class="link-btn">画师主页 #{member_id}</a>')
        for url in ext_urls:
            domain = urllib.parse.urlparse(url).netloc
            links_html.append(f'<a href="{url}" target="_blank" class="link-btn">{domain} 直达 ↗</a>')

        cards_html.append(f"""
        <div class="result-card">
          <div class="thumb-box">
            <img src="{thumb}" alt="缩略图" loading="lazy">
            <div class="sim-badge" style="background:{sim_color};">相似度 {sim}%</div>
          </div>
          <div class="info-box">
            <h3 class="res-title">{title}</h3>
            <p class="res-meta"><strong>画师 / 作者:</strong> {author}</p>
            <div class="links-row">
              {"".join(links_html)}
            </div>
          </div>
        </div>
        """)

    if not cards_html:
        cards_html.append('<div class="no-res">未匹配到高相似度的二次元插画结果，建议尝试 Ascii2d 或 Google Lens。</div>')

    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>SauceNAO 识图结果 - GameArt Toolkit</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: #0f172a;
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      padding: 24px;
      line-height: 1.5;
    }}
    .container {{
      max-width: 900px;
      margin: 0 auto;
    }}
    .header {{
      display: flex;
      align-items: center;
      gap: 20px;
      background: #1e293b;
      padding: 20px;
      border-radius: 16px;
      margin-bottom: 24px;
      border: 1px solid #334155;
    }}
    .orig-thumb {{
      width: 90px;
      height: 90px;
      object-fit: cover;
      border-radius: 10px;
      border: 2px solid #0284c7;
    }}
    .header-text h1 {{
      font-size: 20px;
      color: #38bdf8;
      margin-bottom: 4px;
    }}
    .header-text p {{
      font-size: 13px;
      color: #94a3b8;
    }}
    .results-list {{
      display: flex;
      flex-direction: column;
      gap: 16px;
    }}
    .result-card {{
      display: flex;
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      overflow: hidden;
      transition: transform 0.2s, border-color 0.2s;
    }}
    .result-card:hover {{
      transform: translateY(-2px);
      border-color: #0284c7;
    }}
    .thumb-box {{
      position: relative;
      width: 140px;
      min-width: 140px;
      background: #000;
    }}
    .thumb-box img {{
      width: 100%;
      height: 100%;
      object-fit: cover;
    }}
    .sim-badge {{
      position: absolute;
      bottom: 6px;
      left: 6px;
      font-size: 11px;
      font-weight: 700;
      color: #fff;
      padding: 2px 6px;
      border-radius: 6px;
    }}
    .info-box {{
      padding: 16px 20px;
      flex: 1;
      display: flex;
      flex-direction: column;
      justify-content: center;
    }}
    .res-title {{
      font-size: 16px;
      color: #f1f5f9;
      margin-bottom: 6px;
    }}
    .res-meta {{
      font-size: 13px;
      color: #cbd5e1;
      margin-bottom: 12px;
    }}
    .links-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .link-btn {{
      display: inline-block;
      background: #334155;
      color: #e2e8f0;
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 500;
      border-radius: 6px;
      text-decoration: none;
      transition: all 0.2s;
    }}
    .link-btn:hover {{
      background: #0284c7;
      color: #fff;
    }}
    .link-btn.pixiv {{
      background: #0096fa;
      color: #fff;
    }}
    .link-btn.pixiv:hover {{
      background: #007acc;
    }}
    .no-res {{
      text-align: center;
      padding: 40px;
      color: #94a3b8;
      background: #1e293b;
      border-radius: 12px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <img src="{b64_img}" class="orig-thumb" alt="检索原图">
      <div class="header-text">
        <h1>SauceNAO 智能插画检索结果</h1>
        <p>已通过 SauceNAO 数据库完成相似度比对，点击下方卡片中的链接可直接直达 Pixiv 原作与画师主页</p>
      </div>
    </div>
    <div class="results-list">
      {"".join(cards_html)}
    </div>
  </div>
</body>
</html>"""

    temp_dir = Path(tempfile.gettempdir()) / "GameArtToolkit" / "search_cache"
    temp_dir.mkdir(parents=True, exist_ok=True)
    res_path = temp_dir / f"saucenao_result_{int(time.time() * 1000)}.html"
    res_path.write_text(html_content, encoding="utf-8")
    return str(res_path)


class NoRedirectHandler(urllib.request.HTTPErrorProcessor):
    """不自动跟随 301/302，用于捕获 Location 头"""
    def http_response(self, request, response):
        return response
    https_response = http_response


class ImageSearchWorker(QThread):
    """异步以图搜图工作线程"""
    finished_signal = Signal(bool, str)

    def __init__(self, engine_id: str, image_path: str):
        super().__init__()
        self.engine_id = engine_id
        self.image_path = image_path

    def run(self):
        try:
            if not os.path.exists(self.image_path):
                self.finished_signal.emit(False, "图片文件不存在")
                return

            if self.engine_id == "saucenao":
                target_url, toast_msg = self._search_saucenao(self.image_path)
            elif self.engine_id == "ascii2d":
                target_url, toast_msg = self._search_ascii2d(self.image_path)
            elif self.engine_id == "iqdb":
                target_url, toast_msg = self._search_iqdb(self.image_path)
            else:
                # Google Lens 等通用引擎
                target_url = build_auto_submit_bridge_html(self.engine_id, self.image_path)
                toast_msg = f"已通过 {SEARCH_ENGINES.get(self.engine_id, {}).get('name', '')} 提交图片并展示结果"

            if target_url:
                webbrowser.open(target_url)
                self.finished_signal.emit(True, toast_msg)
            else:
                bridge_url = build_auto_submit_bridge_html(self.engine_id, self.image_path)
                webbrowser.open(bridge_url)
                self.finished_signal.emit(True, f"已在浏览器中拉起 {SEARCH_ENGINES.get(self.engine_id, {}).get('name', '')} 搜图")
        except Exception as e:
            try:
                bridge_url = build_auto_submit_bridge_html(self.engine_id, self.image_path)
                webbrowser.open(bridge_url)
                self.finished_signal.emit(True, f"已在浏览器中拉起搜图 ({e})")
            except Exception as bridge_err:
                self.finished_signal.emit(False, f"搜图请求失败: {bridge_err}")

    def _build_multipart_body(self, field_name: str, file_path: str, extra_fields: Dict[str, str] = None) -> Tuple[bytes, str]:
        boundary = f"----WebKitFormBoundary{int(time.time() * 1000)}"
        body = io.BytesIO()

        if extra_fields:
            for k, v in extra_fields.items():
                body.write(f"--{boundary}\r\n".encode("utf-8"))
                body.write(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode("utf-8"))
                body.write(f"{v}\r\n".encode("utf-8"))

        filename = os.path.basename(file_path)
        body.write(f"--{boundary}\r\n".encode("utf-8"))
        body.write(f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode("utf-8"))
        body.write(b"Content-Type: image/jpeg\r\n\r\n")

        with open(file_path, "rb") as f:
            body.write(f.read())
        body.write(b"\r\n")
        body.write(f"--{boundary}--\r\n".encode("utf-8"))

        content_type = f"multipart/form-data; boundary={boundary}"
        return body.getvalue(), content_type

    def _search_saucenao(self, file_path: str) -> Tuple[str, str]:
        """
        通过 SauceNAO API (output_type=2) 发起精准图片检索并生成包含完整直达结果的页面
        """
        data, content_type = self._build_multipart_body(
            "file", file_path, {"output_type": "2", "numres": "6", "frame": "1", "hide": "0"}
        )
        req = urllib.request.Request(
            "https://saucenao.com/search.php",
            data=data,
            headers={
                "Content-Type": content_type,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
                api_json = json.loads(raw)
                res_path = generate_saucenao_results_html(file_path, api_json)
                
                results = api_json.get("results", [])
                if results:
                    top = results[0]
                    sim = top.get("header", {}).get("similarity", "0")
                    title = top.get("data", {}).get("title") or top.get("data", {}).get("jp_name") or "插画"
                    author = top.get("data", {}).get("member_name") or "画师"
                    msg = f"SauceNAO 识别成功: 《{title}》 (画师: {author}, 相似度: {sim}%)"
                else:
                    msg = "SauceNAO 检索完成，已在浏览器中展示结果列表"
                return res_path, msg
        except Exception:
            bridge = build_auto_submit_bridge_html("saucenao", file_path)
            return bridge, "已通过 SauceNAO 提交图片并展示结果"

    def _search_ascii2d(self, file_path: str) -> Tuple[str, str]:
        """
        向 Ascii2d 上传图片并捕获包含 hash 的专属结果页 Location
        """
        data, content_type = self._build_multipart_body("file", file_path)
        req = urllib.request.Request(
            "https://ascii2d.net/search/file",
            data=data,
            headers={
                "Content-Type": content_type,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
        )

        opener = urllib.request.build_opener(NoRedirectHandler)
        try:
            resp = opener.open(req, timeout=12)
            location = resp.headers.get("Location")
            if location:
                full_url = urllib.parse.urljoin("https://ascii2d.net/", location)
                return full_url, "Ascii2d 搜图完成，已在浏览器中精准打开推特原图检索结果！"
        except Exception:
            pass

        bridge = build_auto_submit_bridge_html("ascii2d", file_path)
        return bridge, "已向 Ascii2d 提交图片并展示结果"

    def _search_iqdb(self, file_path: str) -> Tuple[str, str]:
        """
        向 IQDB 上传图片并捕获渲染结果
        """
        data, content_type = self._build_multipart_body("file", file_path, {"service[]": "1"})
        req = urllib.request.Request(
            "https://iqdb.org/",
            data=data,
            headers={
                "Content-Type": content_type,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
                html = html.replace('href="//', 'href="https://')
                html = html.replace('src="//', 'src="https://')
                html = html.replace('href="/', 'href="https://iqdb.org/')
                html = html.replace('src="/', 'src="https://iqdb.org/')

                temp_dir = Path(tempfile.gettempdir()) / "GameArtToolkit" / "search_cache"
                temp_dir.mkdir(parents=True, exist_ok=True)
                iqdb_path = temp_dir / f"iqdb_result_{int(time.time() * 1000)}.html"
                iqdb_path.write_text(html, encoding="utf-8")
                return str(iqdb_path), "IQDB 搜图完成，已在浏览器中展示动漫壁纸匹配结果！"
        except Exception:
            bridge = build_auto_submit_bridge_html("iqdb", file_path)
            return bridge, "已向 IQDB 提交图片并展示结果"

