# -*- coding: utf-8 -*-
"""
PixivToolkit - NginxConfGenerator 模板生成器与 Nginx 语法预检测试集
"""

import sys
import unittest
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "app"
NGINX_DIR = Path(__file__).resolve().parent.parent / "nginx"
sys.path.insert(0, str(APP_DIR))

from nginx_generator import NginxConfGenerator
from nginx_manager import NginxManager
from service_profile import PROFILES


class TestNginxGenerator(unittest.TestCase):
    """测试 Nginx 站点配置模板生成器"""

    def test_generate_all(self):
        """测试生成三大站点配置文件并验证完整性"""
        conf_dir = NGINX_DIR / "conf"
        results = NginxConfGenerator.generate_all(conf_dir)

        self.assertIn("site-gaming.conf", results)
        self.assertIn("site-acg.conf", results)
        self.assertIn("site-dev.conf", results)

        gaming_text = results["site-gaming.conf"]
        self.assertIn("store.steampowered.com", gaming_text)
        self.assertIn("steamcommunity.com", gaming_text)
        self.assertIn("steambroadcast.akamaized.net", gaming_text)
        self.assertNotIn("epicgames.com", gaming_text)  # epic_games 服务已移除

        acg_text = results["site-acg.conf"]
        self.assertIn("www.pixiv.net", acg_text)
        self.assertIn("i.pximg.net", acg_text)
        self.assertIn("proxy_cache pixiv_img_cache", acg_text)
        self.assertNotIn("yande.re", acg_text)  # yandere 服务已移除
        self.assertNotIn("assets.yande.re", acg_text)
        self.assertNotIn("fandom.com", acg_text)  # fandom 服务已移除
        self.assertNotIn("static.wikia.nocookie.net", acg_text)

        dev_text = results["site-dev.conf"]
        self.assertIn("github.com", dev_text)
        self.assertIn("objects.githubusercontent.com", dev_text)
        self.assertIn("proxy_buffering off", dev_text)
        self.assertNotIn("wikipedia.org", dev_text)  # wikipedia 服务已移除
        self.assertNotIn("translate.googleapis.com", dev_text)  # google_translate 服务已移除

    def test_nginx_syntax_validation(self):
        """执行全量生成后通过 nginx -t 校验最终语法"""
        mgr = NginxManager(NGINX_DIR)
        ok, msg = mgr.test_config()
        self.assertTrue(ok, f"Nginx 语法验证失败: {msg}")


if __name__ == "__main__":
    unittest.main()
