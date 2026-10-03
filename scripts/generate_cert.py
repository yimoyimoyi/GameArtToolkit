# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 本地 SSL 根证书与服务端多域名 SAN 证书生成 CLI 脚本
基于 CertManager 统一底层引擎，支持按需/强制重新签发

## ★ 默认只重签**叶证书**, 不旋转根 CA (2026-10-03 实机踩到后修正)

原实现直接调 `ensure_certificates(force=True)`。而那个 `force` 会**同时**作用到
`generate_root_ca(force=True)` —— 实测把本机根证书从 `542D3B4C…` 换成了 `DF84A1D…`。
后果不是"多一个文件", 而是: **用户机器上已安装的旧根立刻失效** ⇒
nginx 端上的仍是旧根签发的叶证书 ⇒ 浏览器对**所有**域名报
`ERR_CERT_AUTHORITY_INVALID`, 而脚本自己打印的是"签发成功"。

为什么这件事特别容易误伤: 换根需要用户**重新安装信任**, 而脚本完全没有提示。

现在:
  · 默认: 只调 `generate_server_cert(force=True)` —— 它内部**只在 CA 无效时**才重建根
    (见 cert_manager 的 `if not self._is_ca_valid(): generate_root_ca(force=True)`),
    因此根被完整复用, 已安装的信任继续有效;
  · 若根真的不得不换 (缺失/过期/私钥坏了), **大声告警**并说明需要重装信任;
  · 额外做一次"根指纹前后比对"作为**守卫**: 一旦发现根被换掉, 就把备份的根还原回去并
    以失败退出 —— 让"意外换根"不可能悄悄发生。
"""

import hashlib
import shutil
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "app"))

from cert_manager import CertManager, get_all_san_domains  # noqa: E402
from service_profile import TOTAL_SERVICES_COUNT  # noqa: E402


def _sha(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return ""


def main():
    print("========================================================")
    print("   GameArt Toolkit - 本地 SSL 证书生成器")
    print("========================================================")

    all_sans = get_all_san_domains()
    print(f"[*] 准备覆盖 {len(all_sans)} 个 SAN 域名 (包含通配符子域)...")

    cm = CertManager()
    root_before = cm.get_cert_thumbprint()
    print(f"[*] 当前根 CA 指纹: {root_before}")

    # 换根是**破坏性**动作 (用户需重装信任), 因此先把根的两个文件抓在内存里,
    # 以便万一被换掉能原样还原。
    ca_backup = {}
    for p in (cm.ca_cer_path, cm.ca_key_path):
        try:
            ca_backup[p] = p.read_bytes()
        except Exception:
            pass

    # 根不可用时必须先告知: 换根要求用户重新安装信任, 不能悄悄做
    try:
        ca_ok = cm._is_ca_valid()
    except Exception:
        ca_ok = False
    if not ca_ok:
        print("\n[!] 注意: 当前根 CA **无效** (缺失 / 过期 / 私钥不可用)。")
        print("    本次将**重建根证书** —— 之后必须重新安装信任, 否则所有站点证书都不受信。")

    ok, msg = cm.generate_server_cert(force=True)
    cm._cached_thumbprint = None
    root_after = cm.get_cert_thumbprint()

    if not ok:
        print(f"\n[ERROR] 证书生成失败: {msg}")
        sys.exit(1)

    # ★ 守卫: 根**意外**被换掉 ⇒ 还原根文件 + 明确失败, 让这件事不可能悄悄发生
    if root_before and root_after != root_before:
        restored = True
        for p, data in ca_backup.items():
            try:
                p.write_bytes(data)
            except Exception as e:
                restored = False
                print(f"    还原 {p.name} 失败: {e}")
        print("\n[ERROR] 检测到根 CA **被意外更换**:")
        print(f"        改前 {root_before}")
        print(f"        改后 {root_after}")
        print("        这会使已安装的旧根失效, 用户必须重新安装信任。")
        print("        根文件已还原。" if restored else "        ⚠ 根文件还原不完整, 请手工检查 nginx/ca/。")
        print("        若确实要换根, 请显式备份并重新安装信任后再操作。")
        sys.exit(2)

    print("\n========================================================")
    print("  [SUCCESS] 服务端多域名 SAN 证书已签发")
    print(f"  * 根 CA 指纹 (SHA1): {root_after}   (未变 = 无需重装信任)")
    print(f"  * 覆盖 SAN 域名总数: {len(all_sans)} 个")
    print("  * 存储路径: nginx/ca.cer, nginx/ca/pixiv.net.crt, nginx/ca/pixiv.net.key")
    print("========================================================")


if __name__ == "__main__":
    main()
