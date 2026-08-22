# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 本地 SSL 根证书与服务端多域名 SAN 证书生成 CLI 脚本
基于 CertManager 统一底层引擎，支持按需/强制重新签发
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "app"))

from cert_manager import CertManager, get_all_san_domains
from service_profile import TOTAL_SERVICES_COUNT

def main():
    print("========================================================")
    print("   GameArt Toolkit - 本地 SSL 证书生成器")
    print("========================================================")

    all_sans = get_all_san_domains()
    print(f"[*] 准备覆盖 {len(all_sans)} 个 SAN 域名 (包含通配符子域)...")

    cm = CertManager()
    ok, msg = cm.ensure_certificates(force=True)
    if ok:
        thumbprint = cm.get_cert_thumbprint()
        print("\n========================================================")
        print("  [SUCCESS] 本地 Root CA 与服务端多域名证书签发成功！")
        print(f"  * 本地 Root CA 指纹 (SHA1): {thumbprint}")
        print(f"  * 覆盖 SAN 域名总数: {len(all_sans)} 个")
        print("  * 存储路径: nginx/ca.cer, nginx/ca/pixiv.net.crt, nginx/ca/pixiv.net.key")
        print("========================================================")
    else:
        print(f"\n[ERROR] 证书生成失败: {msg}")
        sys.exit(1)

if __name__ == "__main__":
    main()
