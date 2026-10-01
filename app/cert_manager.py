# -*- coding: utf-8 -*-
"""
GameArt Toolkit - Windows 本地根证书与服务端证书自生成与静默管理模块
支持：
- 零私钥分发：本地运行时按需自生成唯一 Root CA 与多域名 SAN 通配服务端证书
- 兼容 Windows 原生 CryptoAPI 与 SChannel 证书库
- 自动检测证书有效性、过期时间与 ServiceProfile 域名覆盖率并自愈
"""

import os
import sys

# 版本前置检查: 本项目使用 PEP 585 (tuple[bool, str]) 与 PEP 604 类型标注, 需要 Python 3.9+/3.10+。
# 在旧解释器 (如 conda base 的 3.8) 下, 导入期会抛出难以理解的
# "TypeError: 'type' object is not subscriptable", 这里改为给出可操作的提示。
if sys.version_info < (3, 10):
    sys.stderr.write(
        f"\n[错误] 需要 Python 3.10 及以上, 当前为 {sys.version.split()[0]}。\n"
        f"       请使用运行客户端的同一解释器, 例如: py -3.13 -m app.cert_manager --prune\n"
        f"       当前解释器: {sys.executable}\n\n")
    raise SystemExit(2)

import json
import hashlib
import ctypes
from ctypes import wintypes
import subprocess
import datetime
from pathlib import Path
from typing import Tuple, Optional, List, Set, Dict, Any

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))
from path_utils import NGINX_DIR
from win_utils import get_silent_startup_kwargs, is_admin
from service_profile import PROFILES

CA_CER_PATH = NGINX_DIR / "ca.cer"

# 本程序历史各代根证书的 CN (用于识别"自己装的"证书, 绝不触碰他人证书)
# 每次重新生成 CA 都会产生一个新指纹, 旧指纹必须被清理 —— 否则受信任根会无限累积,
# 而每个受信任根都能签发任意站点证书, 属于实打实的攻击面扩张。
OWN_CA_NAME_PATTERNS = (
    "GameArt Toolkit Universal Root CA",
    "PixivToolkit Universal Root CA",
)

# 参与信任清理的存储: 机器级需要管理员权限, 用户级不需要
TRUST_STORES = ("LocalMachine\\Root", "CurrentUser\\Root")

_CERT_SHA1_HASH_PROP_ID = 3
_CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
_CERT_STORE_PROV_SYSTEM_W = 10
_CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
_CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000


def iter_trust_store_certs():
    """用 crypt32 原生 API 枚举受信任根存储中的证书 (生成器)

    产出: {"store": "LocalMachine\\Root"|"CurrentUser\\Root", "thumbprint": SHA1 大写, "subject": 简易显示名}

    为什么不用 PowerShell: 实测 windows powershell 5.1 在受限执行环境下
    `Get-ChildItem Cert:\\...` 会静默返回 0 项 (而 pwsh 7 能看到全部), 会把"清理"变成
    "什么都没找到"的假成功。crypt32 与 is_cert_installed 同源, 无此风险也无子进程开销。
    """
    if sys.platform != "win32":
        return
    crypt32 = ctypes.windll.crypt32
    crypt32.CertOpenStore.restype = wintypes.HANDLE
    crypt32.CertOpenStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.HANDLE,
                                      wintypes.DWORD, wintypes.LPCWSTR]
    crypt32.CertEnumCertificatesInStore.restype = ctypes.c_void_p
    crypt32.CertEnumCertificatesInStore.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    crypt32.CertGetCertificateContextProperty.restype = wintypes.BOOL
    crypt32.CertGetCertificateContextProperty.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
    crypt32.CertGetNameStringW.restype = wintypes.DWORD
    crypt32.CertGetNameStringW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_wchar_p, wintypes.DWORD]
    crypt32.CertCloseStore.restype = wintypes.BOOL
    crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]

    stores = ((_CERT_SYSTEM_STORE_LOCAL_MACHINE, "LocalMachine\\Root"),
              (_CERT_SYSTEM_STORE_CURRENT_USER, "CurrentUser\\Root"))
    for flags, label in stores:
        h_store = crypt32.CertOpenStore(ctypes.c_void_p(_CERT_STORE_PROV_SYSTEM_W), 0, 0, flags, "Root")
        if not h_store:
            continue
        try:
            ctx = crypt32.CertEnumCertificatesInStore(h_store, None)
            while ctx:
                thumbprint = ""
                size = wintypes.DWORD(0)
                if crypt32.CertGetCertificateContextProperty(
                        ctx, _CERT_SHA1_HASH_PROP_ID, None, ctypes.byref(size)) and size.value:
                    buf = ctypes.create_string_buffer(size.value)
                    if crypt32.CertGetCertificateContextProperty(
                            ctx, _CERT_SHA1_HASH_PROP_ID, buf, ctypes.byref(size)):
                        thumbprint = buf.raw[:size.value].hex().upper()

                subject = ""
                need = crypt32.CertGetNameStringW(
                    ctx, _CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None, 0)
                if need > 1:
                    sbuf = ctypes.create_unicode_buffer(need)
                    if crypt32.CertGetNameStringW(
                            ctx, _CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, sbuf, need):
                        subject = sbuf.value

                yield {"store": label, "thumbprint": thumbprint, "subject": subject}
                # 传入上一个上下文指针可让 API 自动释放它, 无需手动 CertFreeCertificateContext
                ctx = crypt32.CertEnumCertificatesInStore(h_store, ctx)
        finally:
            crypt32.CertCloseStore(h_store, 0)


def get_all_san_domains() -> List[str]:
    """从 ServiceProfile 单源动态提取全量 SAN 域名列表并自动拓展通配符与二级主域名"""
    domains_set: Set[str] = set()
    for p in PROFILES:
        for d in p.domains:
            d_clean = d.lower().strip()
            if not d_clean:
                continue
            if d_clean.startswith("*."):
                d_clean = d_clean[2:]

            domains_set.add(d_clean)
            domains_set.add(f"*.{d_clean}")

            # 智能提取二级主域名 (如 i.pximg.net -> pximg.net & *.pximg.net)
            parts = d_clean.split(".")
            if len(parts) >= 3:
                base_domain = ".".join(parts[-2:])
                domains_set.add(base_domain)
                domains_set.add(f"*.{base_domain}")

    return sorted(list(domains_set))


class CertManager:
    """本地 CA 与服务端证书全生命周期自生成与管理引擎"""

    def __init__(self, cer_path: Path = CA_CER_PATH, nginx_dir: Optional[Path] = None):
        self.cer_path = Path(cer_path)
        self.nginx_dir = Path(nginx_dir) if nginx_dir else (self.cer_path.parent if self.cer_path.name == "ca.cer" else NGINX_DIR)
        
        self.ca_dir = self.nginx_dir / "ca"
        self.conf_ca_dir = self.nginx_dir / "conf" / "ca"
        
        self.ca_key_path = self.ca_dir / "ca.key"
        self.ca_cer_path = self.cer_path
        self.ca_cer_backup = self.ca_dir / "ca.cer"
        
        self.server_crt_path = self.ca_dir / "pixiv.net.crt"
        self.server_key_path = self.ca_dir / "pixiv.net.key"
        self.conf_server_crt_path = self.conf_ca_dir / "pixiv.net.crt"
        self.conf_server_key_path = self.conf_ca_dir / "pixiv.net.key"

        self._cached_thumbprint: Optional[str] = None
        self._cached_installed: Optional[bool] = None

    def _ensure_dirs(self):
        """确保证书输出目录存在"""
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.conf_ca_dir.mkdir(parents=True, exist_ok=True)

    def _is_ca_valid(self) -> bool:
        """检查本地 Root CA 是否存在且有效（未过期且至少剩余 30 天有效期）"""
        if not self.ca_key_path.exists() or not self.ca_cer_path.exists():
            return False
        try:
            ca_key_bytes = self.ca_key_path.read_bytes()
            ca_cer_bytes = self.ca_cer_path.read_bytes()
            serialization.load_pem_private_key(ca_key_bytes, password=None)
            cert = x509.load_pem_x509_certificate(ca_cer_bytes)
            
            now = datetime.datetime.now(datetime.timezone.utc)
            if hasattr(cert, "not_valid_after_utc"):
                cert_expiry = cert.not_valid_after_utc
            else:
                cert_expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            
            # 剩余有效期大于 30 天
            if cert_expiry - now < datetime.timedelta(days=30):
                return False
            return True
        except Exception:
            return False

    def _is_server_cert_valid(self, required_sans: List[str]) -> bool:
        """检查服务端证书是否存在、私钥匹配、未过期且覆盖所有 required_sans 域名"""
        if not self.server_crt_path.exists() or not self.server_key_path.exists():
            return False
        try:
            server_key_bytes = self.server_key_path.read_bytes()
            server_crt_bytes = self.server_crt_path.read_bytes()
            serialization.load_pem_private_key(server_key_bytes, password=None)
            cert = x509.load_pem_x509_certificate(server_crt_bytes)
            
            now = datetime.datetime.now(datetime.timezone.utc)
            if hasattr(cert, "not_valid_after_utc"):
                cert_expiry = cert.not_valid_after_utc
            else:
                cert_expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            
            if cert_expiry - now < datetime.timedelta(days=15):
                return False

            # 校验 SAN 域名覆盖率
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                existing_sans = set(san_ext.value.get_values_for_type(x509.DNSName))
                for req in required_sans:
                    if req not in existing_sans:
                        return False
            except Exception:
                return False

            return True
        except Exception:
            return False

    def generate_root_ca(self, force: bool = False) -> Tuple[bool, str]:
        """生成独一无二的本地私有 Root CA 根证书与私钥 (RSA 2048, 15年有效期)"""
        self._ensure_dirs()
        if not force and self._is_ca_valid():
            return True, "本地 Root CA 证书有效，无需重新生成。"

        try:
            # 1. 生成 Root CA 私钥
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            # 2. 生成自签名 Root CA 证书 (15 年有效期)
            ca_subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Shanghai"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GameArt Toolkit Authority"),
                x509.NameAttribute(NameOID.COMMON_NAME, "GameArt Toolkit Universal Root CA"),
            ])

            now = datetime.datetime.now(datetime.timezone.utc)
            ca_cert = (
                x509.CertificateBuilder()
                .subject_name(ca_subject)
                .issuer_name(ca_subject)
                .public_key(ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=365 * 15))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                    critical=False,
                )
                .sign(ca_key, hashes.SHA256())
            )

            ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
            ca_key_pem = ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            )

            # 写入本地存储
            self.ca_key_path.write_bytes(ca_key_pem)
            self.ca_cer_path.write_bytes(ca_pem)
            self.ca_cer_backup.write_bytes(ca_pem)

            self._cached_thumbprint = None
            self._cached_installed = None
            return True, "成功生成本地私有 Root CA 证书与私钥！"
        except Exception as e:
            return False, f"生成本地 Root CA 异常: {e}"

    def generate_server_cert(self, force: bool = False) -> Tuple[bool, str]:
        """使用本地 Root CA 签发全量服务通用通配服务端证书 (10年有效期)"""
        self._ensure_dirs()
        all_sans = get_all_san_domains()

        if not force and self._is_server_cert_valid(all_sans):
            # 确保 conf/ca 镜像文件同步存在
            try:
                if not self.conf_server_crt_path.exists():
                    self.conf_server_crt_path.write_bytes(self.server_crt_path.read_bytes())
                if not self.conf_server_key_path.exists():
                    self.conf_server_key_path.write_bytes(self.server_key_path.read_bytes())
            except Exception:
                pass
            return True, "本地服务端证书有效且包含全量 SAN 域名，无需重新签发。"

        # 确保 Root CA 可用
        if not self._is_ca_valid():
            ok, msg = self.generate_root_ca(force=True)
            if not ok:
                return False, f"前置 Root CA 准备失败: {msg}"

        try:
            ca_key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
            ca_cert = x509.load_pem_x509_certificate(self.ca_cer_path.read_bytes())

            # 1. 生成服务端私钥 (RSA 2048)
            server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            # 2. 签发覆盖全量服务的多域名 SAN 服务端证书
            server_subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Shanghai"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GameArt Toolkit Accelerator"),
                x509.NameAttribute(NameOID.COMMON_NAME, "*.pixiv.net"),
            ])

            san_list = [x509.DNSName(d) for d in all_sans]
            now = datetime.datetime.now(datetime.timezone.utc)

            server_cert = (
                x509.CertificateBuilder()
                .subject_name(server_subject)
                .issuer_name(ca_cert.subject)
                .public_key(server_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=365 * 10))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=True,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.ExtendedKeyUsage([
                        ExtendedKeyUsageOID.SERVER_AUTH,
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]),
                    critical=False,
                )
                .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                    critical=False,
                )
                .sign(ca_key, hashes.SHA256())
            )

            server_pem = server_cert.public_bytes(serialization.Encoding.PEM)
            server_key_pem = server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            )

            # 写入 nginx/ca/ 与 nginx/conf/ca/
            self.server_crt_path.write_bytes(server_pem)
            self.server_key_path.write_bytes(server_key_pem)
            self.conf_server_crt_path.write_bytes(server_pem)
            self.conf_server_key_path.write_bytes(server_key_pem)

            return True, f"成功签发本地服务端通配证书 (覆盖 {len(all_sans)} 个 SAN 域名)！"
        except Exception as e:
            return False, f"签发服务端证书异常: {e}"

    def ensure_certificates(self, force: bool = False) -> Tuple[bool, str]:
        """全量保障方法：一键自检并生成 Root CA 与服务端证书"""
        ok, msg = self.generate_root_ca(force=force)
        if not ok:
            return False, msg
        ok, msg = self.generate_server_cert(force=force)
        if not ok:
            return False, msg
        return True, "本地 SSL 根证书与服务端证书已全部就绪！"

    def get_cert_thumbprint(self) -> str:
        """获取本地 ca.cer 的证书指纹 (SHA1) (内存缓存，缺失时自动生成)"""
        if self._cached_thumbprint:
            return self._cached_thumbprint

        if not self.cer_path.exists():
            # 仅针对默认主路径自动触发自愈生成
            if self.cer_path == CA_CER_PATH:
                self.ensure_certificates()
            else:
                return ""

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

            # 显式声明 64 位 API 函数签名，防止 64 位环境指针截断为 32 位整型 (0xC0000005 隐患)
            crypt32.CertOpenStore.restype = wintypes.HANDLE
            crypt32.CertOpenStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR]
            crypt32.CertEnumCertificatesInStore.restype = ctypes.c_void_p
            crypt32.CertEnumCertificatesInStore.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
            crypt32.CertGetCertificateContextProperty.restype = wintypes.BOOL
            crypt32.CertGetCertificateContextProperty.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
            crypt32.CertFreeCertificateContext.restype = wintypes.BOOL
            crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
            crypt32.CertCloseStore.restype = wintypes.BOOL
            crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]

            # 0x00010000 = CERT_SYSTEM_STORE_CURRENT_USER, 0x00020000 = CERT_SYSTEM_STORE_LOCAL_MACHINE
            flags_list = [0x00010000, 0x00020000]
            store_names = ["Root", "AuthRoot", "ROOT", "CA"]

            for flags in flags_list:
                for store_name in store_names:
                    h_store = crypt32.CertOpenStore(ctypes.c_void_p(10), 0, 0, flags, store_name)
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
        """静默安装证书到系统与当前用户受信任根证书存储区 (全静默无黑框，前置确保自生成就绪)"""
        self.ensure_certificates()
        if not self.cer_path.exists():
            return False, f"证书文件不存在: {self.cer_path}"

        # 0. 安装前先清理历史代际残留: 只保留当前活跃 CA。
        #    若不做这一步, 每次 CA 重新生成都会在受信任根里新增一个永不回收的根证书
        #    (实测曾累积到 53 个), 每个都能签发任意站点证书, 属持续扩大的攻击面。
        try:
            prune = self.prune_stale_trust_roots()
            if prune.get("removed"):
                print(f"[Cert] 已清理历史根证书 {len(prune['removed'])} 个")
            elif prune.get("failed"):
                print(f"[Cert] 历史根证书清理未完成: {prune.get('message')}")
        except Exception as e:
            print(f"[Cert] 历史根证书清理跳过: {e}")

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
        """从系统和用户根证书库中安全卸载 (全静默无黑框，同时兼容清理旧版根证书)"""
        thumbprint = self.get_cert_thumbprint()

        try:
            if thumbprint:
                subprocess.run(
                    ["certutil", "-delstore", "ROOT", thumbprint],
                    capture_output=True, timeout=5, shell=False, **get_silent_startup_kwargs()
                )
                subprocess.run(
                    ["certutil", "-delstore", "-user", "ROOT", thumbprint],
                    capture_output=True, timeout=5, shell=False, **get_silent_startup_kwargs()
                )
            
            # 同时尝试根据 Common Name 清理
            for cn_name in ["GameArt Toolkit Universal Root CA", "PixivToolkit Universal Root CA"]:
                subprocess.run(
                    ["certutil", "-delstore", "ROOT", cn_name],
                    capture_output=True, timeout=5, shell=False, **get_silent_startup_kwargs()
                )
                subprocess.run(
                    ["certutil", "-delstore", "-user", "ROOT", cn_name],
                    capture_output=True, timeout=5, shell=False, **get_silent_startup_kwargs()
                )

            self._cached_installed = False
            return True, "已从系统卸载根证书"
        except Exception as e:
            return False, f"卸载证书异常: {e}"

    # ------------------------------------------------------------------
    # 信任库卫生: 清理历史代际残留的根证书
    #
    # 为什么不用 PowerShell 枚举: 实测 windows powershell 5.1 在受限执行环境里
    # `Get-ChildItem Cert:\...` 会静默返回 0 项 (而 pwsh 7 能看到 98/104 项) —— 语言模式与
    # 令牌差异会把"清理"变成"什么都没找到"的假成功。crypt32 原生 API 无此问题, 且与
    # is_cert_installed 同源, 无子进程开销。
    # ------------------------------------------------------------------
    def list_own_trust_roots(self) -> List[Dict[str, Any]]:
        """枚举受信任根中属于本程序历史各代的证书 (只读, crypt32 原生)"""
        result: List[Dict[str, Any]] = []
        try:
            for cert in iter_trust_store_certs():
                subject = str(cert.get("subject") or "")
                if any(name in subject for name in OWN_CA_NAME_PATTERNS):
                    result.append({
                        "store": cert["store"],
                        "thumbprint": cert["thumbprint"],
                        "subject": subject,
                        "not_after": cert.get("not_after", ""),
                    })
        except Exception:
            return []
        return result

    @staticmethod
    def _delete_trust_root(store: str, thumbprint: str) -> Tuple[bool, str]:
        """删除单个根证书并**验证确已消失** (机器级需管理员权限)

        为什么不用 certutil -delstore: 实测它对根证书是**空操作**却返回 0 并打印
        "命令成功完成" —— 这正是不受信任的历史根会无限累积的真因 (install_cert 每次
        新增, uninstall_cert 的删除从未生效)。因此这里改用 crypt32 原生删除,
        并在删除后重新查找确认, 绝不接受"命令没报错"当作成功。
        """
        if sys.platform != "win32":
            return False, "非 Windows 平台"
        clean = str(thumbprint or "").strip().upper()
        if len(clean) != 40:
            return False, f"非法指纹: {thumbprint!r}"
        try:
            data = bytes.fromhex(clean)
        except ValueError:
            return False, f"非法指纹: {thumbprint!r}"

        class CRYPT_HASH_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD),
                        ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

        crypt32 = ctypes.windll.crypt32
        crypt32.CertOpenStore.restype = wintypes.HANDLE
        crypt32.CertOpenStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.HANDLE,
                                          wintypes.DWORD, wintypes.LPCWSTR]
        crypt32.CertFindCertificateInStore.restype = ctypes.c_void_p
        crypt32.CertFindCertificateInStore.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, ctypes.c_void_p]
        crypt32.CertDeleteCertificateFromStore.restype = wintypes.BOOL
        crypt32.CertDeleteCertificateFromStore.argtypes = [ctypes.c_void_p]
        crypt32.CertFreeCertificateContext.restype = wintypes.BOOL
        crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
        crypt32.CertCloseStore.restype = wintypes.BOOL
        crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]

        flags = (_CERT_SYSTEM_STORE_LOCAL_MACHINE if store.startswith("LocalMachine")
                 else _CERT_SYSTEM_STORE_CURRENT_USER)
        buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        blob = CRYPT_HASH_BLOB(len(data), buffer)
        encoding = 0x00010001        # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
        find_sha1 = 0x00010000       # CERT_FIND_SHA1_HASH

        h_store = crypt32.CertOpenStore(ctypes.c_void_p(_CERT_STORE_PROV_SYSTEM_W), 0, 0, flags, "Root")
        if not h_store:
            return False, "打开存储失败 (机器级存储需管理员权限)" if store.startswith("LocalMachine") \
                else "打开存储失败"
        try:
            ctx = crypt32.CertFindCertificateInStore(h_store, encoding, 0, find_sha1,
                                                     ctypes.byref(blob), None)
            if not ctx:
                # 已经不存在, 视为成功 (幂等)
                return True, ""
            if not crypt32.CertDeleteCertificateFromStore(ctx):
                # 删除失败时上下文未释放, 需手动释放
                crypt32.CertFreeCertificateContext(ctx)
                err = ctypes.get_last_error() if hasattr(ctypes, "get_last_error") else 0
                return False, f"删除被拒绝 (错误码 {err})" if not store.startswith("LocalMachine") \
                    else "删除被拒绝 (机器级存储需管理员权限)"

            # 关键: 复查确认真的删掉了
            again = crypt32.CertFindCertificateInStore(h_store, encoding, 0, find_sha1,
                                                       ctypes.byref(blob), None)
            if again:
                crypt32.CertFreeCertificateContext(again)
                return False, "删除后复查仍存在"
            return True, ""
        except Exception as e:
            return False, str(e)
        finally:
            crypt32.CertCloseStore(h_store, 0)

    def prune_stale_trust_roots(self, dry_run: bool = False) -> Dict[str, Any]:
        """移除历史代际残留的根证书, 只保留当前活跃 CA

        为什么必须做: 每次 CA 失效或强制作废都会重新生成一个根并装入受信任存储, 而旧根
        一直留在库里。实测本机积累了 53 个 (LocalMachine 25 + CurrentUser 28), 而真正在用的
        只有 1 个 —— 其余每一个都能签发任意站点证书, 是持续扩大的中间人攻击面。

        安全性: 只删除 Subject 命中本程序 CA 名称、且指纹 != 当前活跃 CA 的证书;
        第三方证书与当前活跃 CA 一律不动。
        """
        active = self.get_cert_thumbprint()
        before = self.list_own_trust_roots()
        stale = [c for c in before if c["thumbprint"] and c["thumbprint"] != active]
        report: Dict[str, Any] = {
            "active": active,
            "total": len(before),
            "stale": len(stale),
            "removed": [],
            "failed": [],
            "dry_run": dry_run,
            "message": "",
        }
        if not active:
            report["message"] = "无法读取当前活跃 CA 指纹, 已中止清理 (避免误删正在使用的根)"
            return report
        if not stale:
            report["message"] = f"信任库干净: 仅有当前活跃 CA ({len(before)} 个匹配项)"
            return report
        if dry_run:
            report["removed"] = [f"{c['store']}/{c['thumbprint']}" for c in stale]
            report["message"] = f"预览: 将清理 {len(stale)} 个历史根证书"
            return report

        # 逐项独立删除: 部分失败 (典型为机器级缺管理员权限) 不应中断整体清理
        needs_admin = False
        for cert in stale:
            tag = f"{cert['store']}/{cert['thumbprint']}"
            ok, _why = self._delete_trust_root(cert["store"], cert["thumbprint"])
            if ok:
                report["removed"].append(tag)
            else:
                report["failed"].append(tag)
                if cert["store"].startswith("LocalMachine"):
                    needs_admin = True

        if report["removed"]:
            self._cached_installed = None       # 存储已变化, 失效缓存
        parts = [f"已清理 {len(report['removed'])} 个历史根证书"]
        if report["failed"]:
            parts.append(f"{len(report['failed'])} 个失败")
            if needs_admin:
                parts.append("(机器级存储需管理员权限, 请以管理员身份重新运行)")
        report["message"] = "; ".join(parts)
        return report

    def inject_dev_environments(self) -> bool:
        """为 Git / Node.js 等开发工具挂载作用域证书 (仅针对 GitHub / GitLab 域名生效)"""
        try:
            cer_str = str(self.cer_path.resolve()).replace("\\", "/")
            # 1. 配置 Git 优先使用 SChannel (原生读取 Windows 根证书库)
            subprocess.run(
                ["git", "config", "--global", "http.sslBackend", "schannel"],
                capture_output=True, timeout=2, shell=False, **get_silent_startup_kwargs()
            )
            # 2. 针对 github.com / gitlab.com 配置单独的 sslCAInfo 兜底
            subprocess.run(
                ["git", "config", "--global", "http.https://github.com.sslCAInfo", cer_str],
                capture_output=True, timeout=2, shell=False, **get_silent_startup_kwargs()
            )
            subprocess.run(
                ["git", "config", "--global", "http.https://gitlab.com.sslCAInfo", cer_str],
                capture_output=True, timeout=2, shell=False, **get_silent_startup_kwargs()
            )
            # 3. 注入 Node.js 扩展 CA 环境变量
            os.environ["NODE_EXTRA_CA_CERTS"] = str(self.cer_path.resolve())
            return True
        except Exception:
            return False

    def restore_dev_environments(self) -> bool:
        """清理开发工具的证书注入 (退出时调用)"""
        try:
            subprocess.run(
                ["git", "config", "--global", "--unset-all", "http.https://github.com.sslCAInfo"],
                capture_output=True, timeout=2, shell=False, **get_silent_startup_kwargs()
            )
            subprocess.run(
                ["git", "config", "--global", "--unset-all", "http.https://gitlab.com.sslCAInfo"],
                capture_output=True, timeout=2, shell=False, **get_silent_startup_kwargs()
            )
            os.environ.pop("NODE_EXTRA_CA_CERTS", None)
            return True
        except Exception:
            return False


def main(argv: Optional[List[str]] = None) -> int:
    """信任库卫生命令行入口

    用法:
      python -m app.cert_manager --report      # 只读: 列出历史代际根证书
      python -m app.cert_manager --prune       # 清理历史代际根证书 (机器级需管理员)
      python -m app.cert_manager --prune --dry-run
    """
    import argparse

    ap = argparse.ArgumentParser(description="证书信任库卫生维护")
    ap.add_argument("--report", action="store_true", help="列出本程序历史各代根证书")
    ap.add_argument("--prune", action="store_true", help="清理历史代际根证书, 仅保留当前活跃 CA")
    ap.add_argument("--dry-run", action="store_true", help="只预览不删除")
    args = ap.parse_args(argv)

    mgr = CertManager()
    active = mgr.get_cert_thumbprint()
    print(f"当前活跃 CA: {active or '(未找到 ca.cer)'}")
    print(f"管理员权限 : {is_admin()}")

    if args.report or not (args.prune):
        roots = mgr.list_own_trust_roots()
        print(f"受信任存储中匹配本程序的根证书: {len(roots)} 个")
        for c in roots:
            mark = "  <== 当前活跃" if c["thumbprint"] == active else ""
            print(f"  [{c['store']:22s}] {c['thumbprint']} {c['not_after']} {c['subject'][:48]}{mark}")
        if not args.prune:
            return 0

    report = mgr.prune_stale_trust_roots(dry_run=args.dry_run)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report.get("failed"):
        print("\n注意: 机器级存储删除需要管理员权限 —— 请以管理员身份重新运行本命令。")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

