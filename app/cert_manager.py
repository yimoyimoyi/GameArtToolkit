# -*- coding: utf-8 -*-
"""
PixivToolkit - Windows 根证书自检与静默管理模块 (Native CryptoAPI 极速版)
"""

import os
import hashlib
import ctypes
from ctypes import wintypes
import subprocess
from pathlib import Path
from typing import Tuple, Optional
from path_utils import NGINX_DIR
from win_utils import get_silent_startup_kwargs

CA_CER_PATH = NGINX_DIR / "ca.cer"

class CertManager:
    def __init__(self, cer_path: Path = CA_CER_PATH):
        self.cer_path = cer_path
        self._cached_thumbprint: Optional[str] = None
        self._cached_installed: Optional[bool] = None

    def get_cert_thumbprint(self) -> str:
        """获取本地 ca.cer 的证书指纹 (SHA1) (内存缓存)"""
        if self._cached_thumbprint:
            return self._cached_thumbprint

        if not self.cer_path.exists():
            return ""
        try:
            with open(self.cer_path, "rb") as f:
                data = f.read()
                if b"-----BEGIN CERTIFICATE-----" in data:
                    import base64
                    b64_content = b"".join([l for l in data.splitlines() if not l.startswith(b"-----")])
                    der_bytes = base64.b64decode(b64_content)
                    self._cached_thumbprint = hashlib.sha1(der_bytes).hexdigest().upper()
                else:
                    self._cached_thumbprint = hashlib.sha1(data).hexdigest().upper()
                return self._cached_thumbprint
        except Exception:
            return ""

    def is_cert_installed(self, force_refresh: bool = False) -> bool:
        """使用 Windows 原生 crypt32.dll 检查根证书是否已在受信任存储区中 (0误判、全语言兼容、耗时<0.2ms)"""
        if not force_refresh and self._cached_installed is not None:
            return self._cached_installed

        thumbprint = self.get_cert_thumbprint()
        if not thumbprint:
            self._cached_installed = False
            return False

        # 1. 优先使用 Windows CryptoAPI 内存直接检索 (检查 CurrentUser 与 LocalMachine 的 Root/AuthRoot)
        try:
            crypt32 = ctypes.windll.crypt32
            # 0x00010000 = CERT_SYSTEM_STORE_CURRENT_USER, 0x00020000 = CERT_SYSTEM_STORE_LOCAL_MACHINE
            flags_list = [0x00010000, 0x00020000]
            store_names = ["Root", "AuthRoot", "ROOT", "CA"]

            for flags in flags_list:
                for store_name in store_names:
                    h_store = crypt32.CertOpenStore(10, 0, 0, flags, store_name)
                    if not h_store:
                        continue
                    try:
                        p_cert = crypt32.CertEnumCertificatesInStore(h_store, None)
                        while p_cert:
                            hash_buf = (ctypes.c_ubyte * 20)()
                            buf_len = wintypes.DWORD(20)
                            # 3 = CERT_SHA1_HASH_PROP_ID
                            if crypt32.CertGetCertificateContextProperty(p_cert, 3, hash_buf, ctypes.byref(buf_len)):
                                curr_hash = "".join(f"{b:02X}" for b in hash_buf)
                                if curr_hash.upper() == thumbprint.upper():
                                    crypt32.CertFreeCertificateContext(p_cert)
                                    self._cached_installed = True
                                    return True
                            p_cert = crypt32.CertEnumCertificatesInStore(h_store, p_cert)
                    except Exception:
                        # 异常时确保释放当前证书上下文，避免非托管内存泄漏
                        if p_cert:
                            try:
                                crypt32.CertFreeCertificateContext(p_cert)
                            except Exception:
                                pass
                    finally:
                        crypt32.CertCloseStore(h_store, 0)
        except Exception:
            pass

        # 2. 兜底使用 certutil (严格比对 thumbprint 十六进制，全静默无窗)
        for store_flag in ["", "-user"]:
            try:
                cmd = ["certutil"] + ([store_flag] if store_flag else []) + ["-store", "ROOT", thumbprint]
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    errors="ignore",
                    timeout=2,
                    shell=False,
                    **get_silent_startup_kwargs()
                )
                if proc.returncode == 0 and thumbprint.lower() in proc.stdout.lower():
                    self._cached_installed = True
                    return True
            except Exception:
                pass

        self._cached_installed = False
        return False

    def install_cert(self) -> Tuple[bool, str]:
        """静默安装证书到系统与当前用户受信任根证书存储区 (全静默无黑框)"""
        if not self.cer_path.exists():
            return False, f"证书文件不存在: {self.cer_path}"

        # 1. 优先使用 PowerShell Import-Certificate (系统级，静默无弹窗)
        ps_cmd = f"Import-Certificate -FilePath '{self.cer_path}' -CertStoreLocation Cert:\\LocalMachine\\Root"
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                capture_output=True, timeout=5, shell=False, **get_silent_startup_kwargs()
            )
            if self.is_cert_installed(force_refresh=True):
                return True, "根证书已成功安装到系统受信任根证书存储区！"
        except Exception:
            pass

        # 2. 尝试 certutil 本地计算机与当前用户库
        for cmd_args, target_desc in [
            (["certutil", "-addstore", "-f", "ROOT", str(self.cer_path)], "系统受信任根证书存储区"),
            (["certutil", "-addstore", "-user", "-f", "ROOT", str(self.cer_path)], "当前用户受信任根证书存储区")
        ]:
            try:
                subprocess.run(
                    cmd_args, capture_output=True, text=True, errors="ignore",
                    timeout=5, shell=False, **get_silent_startup_kwargs()
                )
                if self.is_cert_installed(force_refresh=True):
                    # 自动配置 Git 命令行客户端信任 Windows 原生 SChannel 证书库
                    try:
                        subprocess.run(
                            ["git", "config", "--global", "http.sslBackend", "schannel"],
                            capture_output=True, timeout=2, shell=False, **get_silent_startup_kwargs()
                        )
                    except Exception:
                        pass
                    return True, f"根证书已成功安装到{target_desc}！"
            except Exception:
                continue

        # 无论如何，尝试为 Git 配置原生 SChannel 支持
        try:
            subprocess.run(
                ["git", "config", "--global", "http.sslBackend", "schannel"],
                capture_output=True, timeout=2, shell=False, **get_silent_startup_kwargs()
            )
        except Exception:
            pass

        return False, "未能成功导入根证书，请以管理员身份运行本程序以完成受信任授权。"

    def uninstall_cert(self) -> Tuple[bool, str]:
        """从系统和用户根证书库中安全卸载 (全静默无黑框)"""
        thumbprint = self.get_cert_thumbprint()
        if not thumbprint:
            return False, "未能识别证书指纹"

        try:
            subprocess.run(
                ["certutil", "-delstore", "ROOT", thumbprint],
                capture_output=True, timeout=5, shell=False, **get_silent_startup_kwargs()
            )
            subprocess.run(
                ["certutil", "-delstore", "-user", "ROOT", thumbprint],
                capture_output=True, timeout=5, shell=False, **get_silent_startup_kwargs()
            )
            self._cached_installed = False
            return True, "已从系统卸载根证书"
        except Exception as e:
            return False, f"卸载证书异常: {e}"
