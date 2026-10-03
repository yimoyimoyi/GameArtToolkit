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
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))
from path_utils import NGINX_DIR
from win_utils import get_silent_startup_kwargs, is_admin
from service_profile import PROFILES
import private_key_acl

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
# 只读打开标志。**审计/枚举路径必须带上它**: 不带时 crypt32 会以"可写"方式打开存储,
# 而机器级存储的写访问需要管理员 —— 非提权下 CertOpenStore 直接失败(实测 GetLastError=5),
# 于是枚举被静默跳过、报告**低报**问题。实测同一台机器同一时刻:
#   PowerShell(Cert:\LocalMachine\Root) 非提权可读到 74 张, 而项目实现一张都读不到;
#   提权前 --report 报"2 个", 提权后同一次 prune 却报 total=3 (多出机器级那份 C8B7...)。
# 审计绝不能因为读不到就说"干净" —— 那是比不审计更危险的结果。
_CERT_STORE_READONLY_FLAG = 0x00008000


# 枚举失败的存储 (label -> 原因)。存在的意义: 让审计**说出自己没看到什么** ——
# "读不到"被静默吞掉时, 报告会把"看不见"显示成"没问题", 这比不审计更危险。
_STORE_ENUM_ERRORS: List[tuple] = []


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
        # 必须 OR 上只读标志, 否则机器级存储会因"要写权限"而打开失败 (见常量处注释)
        h_store = crypt32.CertOpenStore(ctypes.c_void_p(_CERT_STORE_PROV_SYSTEM_W), 0, 0,
                                        flags | _CERT_STORE_READONLY_FLAG, "Root")
        if not h_store:
            # 不能静默跳过: 读不到的存储会被下游当成"里面没有问题"
            _STORE_ENUM_ERRORS.append(
                (label, f"CertOpenStore 失败 (GetLastError={ctypes.get_last_error()})"))
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


# 公共后缀样式的"注册局标签": 若域名的**后两段**形如 <这些标签>.<两位国家码>,
# 则这两段是公共后缀而不是可注册主域, 不得据此派生通配 SAN。
# 为什么需要 (2026-10-02 实测): get_all_san_domains 会把 3 段以上域名的后两段
# 当作"二级主域"并加通配 (i.pximg.net -> pximg.net, 正确)。但补全 Google 国家域名时
# `www.google.com.sg` 会被推导出 `com.sg` 与 `*.com.sg` —— 那等于让**本机受信任的 CA
# 持有一张对任意 .com.sg 域名有效的证书**。实测统计: 登记 266 个国家域名会引入
# 21+ 个这类过宽通配 (`*.co.uk` / `*.co.jp` / `*.com.sg` …), 把信任面扩大到与
# Google 完全无关的第三方域名上。这不是"多几个域名"的规模问题, 而是信任边界问题。
# 注: 这是启发式 (不是完整 PSL)。判定条件是"后两段 + 两位国家码", 对 Google 的
# ccTLD 全覆盖; 完整 PSL 需引入额外依赖与定期更新, 与本项目"零依赖自包含"取向不符。
_PUBLIC_SUFFIX_REGISTRY_LABELS = {
    "com", "co", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "in",
    "info", "biz", "mil", "sch", "gen", "firm", "nom", "web",
}


def _is_public_suffix_pair(last_two: List[str]) -> bool:
    """后两段是否形如公共后缀 (如 com.sg / co.uk / com.hk)"""
    if len(last_two) != 2:
        return False
    registry, cc = last_two[0].lower(), last_two[1].lower()
    return len(cc) == 2 and registry in _PUBLIC_SUFFIX_REGISTRY_LABELS


def get_all_san_domains() -> List[str]:
    """从 ServiceProfile 单源提取全量 SAN 域名列表

    ## ★ 只取画像**显式声明**的域名 —— 不再做"后两段派生" (2026-10-03 定因, 原缺陷 M3)

    ## 旧实现做了什么, 以及为什么它是信任边界问题

    旧实现除了声明域名本身, 还会把**任意** 3 段以上域名的"后两段"当二级主域,
    并额外加一条通配 SAN:

        i.pximg.net   -> pximg.net   + *.pximg.net     (合理, 这是本项目自己的 CDN)
        www.google.com.sg -> (被 _is_public_suffix_pair 挡掉, 见下)
        s3.amazonaws.com  -> amazonaws.com + *.amazonaws.com   ← ★ 无关第三方!

    于是**用户装进受信任根的这张 CA, 签署了一张对 `*.amazonaws.com` 有效的证书** ——
    实测叶子证书里 1202 条 SAN 中有 **601 条通配**, 覆盖
    `*.amazonaws.com` / `*.apache.org` / `*.python.org` / `*.pythonhosted.org` /
    `*.maven.org` / `*.npmjs.com` / `*.crates.io` / `*.pypi.org` / `*.nuget.org` /
    `*.cloudflare.com` / `*.akamaihd.net` / `*.akamaized.net` / `*.jsdelivr.net` 等
    **与加速完全无关**的第三方基础设施。

    这不是"多几个域名"的规模问题, 而是**信任面被扩大**: 任何能让这些域名解析到本机
    的场景下, 我们的 nginx 都能给它们出一个被全机信任的证书。`_is_public_suffix_pair`
    那条守卫只挡住了"注册局标签 + 两位国家码"形态, 挡不住上面这一大批。

    ## 新口径

    只保留声明域名的**原样**形式 (通配 `*.x` 原样保留、apex 保留)。
    于是 `.pximg.net` 这类"我们确实需要"的通配必须由画像**显式声明** —— nginx 那边
    本来也是靠一张硬编码补表才拿到它的 (原缺陷 M6), 现在两边同源。

    ## 安全性论证 (为什么不会削掉在服务的主机名)

    本项目的 SNI 集合 = nginx `server_name` 的取值 (浏览器必须用 SNI 才能落到对应 vhost)。
    实测: 584 个 `server_name` 条目里, 旧实现覆盖 584/584;
    改成"仅声明"后, 只有 **11 条通配** 失去覆盖 —— 而那 11 条原先只存在于
    `nginx_generator` 的硬编码补表里, **画像从未声明过**。
    已把它们补进各自画像 (见 service_profile), 因此改后覆盖仍是 584/584。

    同时: 原先被派生出来的 595 条第三方通配**全部消失**, SAN 从 1202 降到 ~586。
    """
    domains_set: Set[str] = set()
    for p in PROFILES:
        for d in p.domains:
            d_clean = (d or "").lower().strip()
            if not d_clean:
                continue
            domains_set.add(d_clean)

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
        self._last_harden_report: Dict[str, Any] = {}
        # `http.sslBackend` 被我们覆盖前的原值 (缺陷 W9, 2026-10-04)。
        # None = "还没注入过/不知道原值"; "" = 原本未设置该键 (还原时应 unset)。
        self._git_sslbackend_backup: Optional[str] = None

    def _ensure_dirs(self):
        """确保证书输出目录存在, 并把目录 ACL 先收紧

        顺序很关键: **目录先收紧 (带 (OI)(CI) 继承), 随后写出的私钥就"生来"是紧 ACL**,
        不必依赖"写完再改" —— 后者存在一个窗口期, 期间私钥是任何本地进程可读的。
        """
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.conf_ca_dir.mkdir(parents=True, exist_ok=True)
        for d in (self.ca_dir, self.conf_ca_dir):
            private_key_acl.harden_path(d, is_dir=True)

    def harden_private_keys(self) -> Dict[str, Any]:
        """收紧本机全部证书私钥 (ca.key / pixiv.net.key) 的 ACL 并回读校验

        为什么必须做: 私钥写在用户可写目录里, 会继承父目录 ACL —— 实测
        `nginx\\ca\\ca.key` 对 `Authenticated Users` 可写、对 `BUILTIN\\Users` 可读,
        即**任意本地进程都能读走全机受信任的 CA 私钥**(等价于完整 TLS 劫持能力)。
        详见 private_key_acl 模块头部说明。幂等, 可在每次启动时调用。
        """
        report = private_key_acl.harden_private_keys(self.nginx_dir)
        self._last_harden_report = report
        return report

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
        """检查服务端证书是否存在、私钥匹配、未过期、**由当前根签发**且覆盖所有 required_sans

        ## ★ 为什么要加"由当前根签发"(2026-10-03 定因, 原缺陷 M4)

        原实现只验四件事: 文件在、私钥能解析、≥15 天未过期、SAN 覆盖。
        **从不检查签发者是谁** —— 而这个函数是"要不要重签叶子"的唯一判据。
        配合"活跃根"判据是"`ca.cer` 文件在不在"(见 `prune_stale_trust_roots`),
        就构成这条链:
          ① CA 换代 ⇒ 目录里出现新 `ca.cer`, 旧根被当"陈旧"从受信任存储删除;
          ② 但**叶子证书没人重签** —— `_is_server_cert_valid()` 对它返回 True
             (存在/未过期/SAN 齐全, 而签发者是谁根本没看);
          ③ 于是全机信任的是新根, 而 nginx 端上的是**旧根签的叶子** ⇒
             浏览器对**所有**域名报 `ERR_CERT_AUTHORITY_INVALID`;
          ④ 而所有路径都报成功 (每一步都"没报错")。
        这正是本项目反复出现的"假可用"形态, 只是后果最重: 加速全挂而上层毫无察觉。

        ⇒ 现在要求 `cert.issuer == ca.cer 的 subject`, 且**用 ca.cer 的公钥验签**。
          验签比只比 DN 更硬: DN 相同但密钥换了(重新生成过同名 CA)也必须重签。
        """
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

            # ★ 由当前 CA 签发 (issuer 匹配 + 公钥验签) —— 见上方 docstring
            if not self._is_signed_by_current_ca(cert):
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

    def _is_signed_by_current_ca(self, leaf) -> bool:
        """叶子证书是否**由当前 ca.cer 签发** (issuer 匹配 + 公钥验签)

        为什么两道都做:
          · 只比 issuer DN: CA 被重新生成(同名不同密钥)时会误判为有效 ⇒
            全机信任的是新根, 而 nginx 上的是旧根签的叶子 ⇒ 全部域名证书不受信;
          · 加验签: 直接证明"这确实是用当前 CA 的私钥签的", 与信任链一致。
        任何一步无法判定 (ca.cer 缺失/读不出) 都返回 False —— 宁可重签一次
        (幂等、代价可控), 也不要让"不受信的叶子"留在数据平面上。
        """
        try:
            if not self.ca_cer_path.exists():
                return False
            ca = x509.load_pem_x509_certificate(self.ca_cer_path.read_bytes())
        except Exception:
            return False
        try:
            if leaf.issuer != ca.subject:
                return False
        except Exception:
            return False
        try:
            ca_pub = ca.public_key()
            if isinstance(ca_pub, rsa.RSAPublicKey):
                ca_pub.verify(
                    leaf.signature,
                    leaf.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    leaf.signature_hash_algorithm,
                )
            elif isinstance(ca_pub, ec.EllipticCurvePublicKey):
                ca_pub.verify(
                    leaf.signature,
                    leaf.tbs_certificate_bytes,
                    ec.ECDSA(leaf.signature_hash_algorithm),
                )
            else:
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

            # 私钥 ACL 收紧 (目录已在 _ensure_dirs 收紧, 这里对文件再确认一次并回读校验)
            harden = self.harden_private_keys()
            if harden.get("failed"):
                # 不阻断证书生成 (证书本身可用), 但必须如实上报, 绝不静默
                return True, (f"成功生成本地私有 Root CA, 但私钥 ACL 收紧未完全成功: "
                              f"{harden.get('message')}")

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

            # 服务端叶子私钥同样收紧 (被读走即可冒充全部被反代的域名)
            self.harden_private_keys()

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
        # 自愈路径: 证书已存在时上面的生成函数会提前返回, 于是"老私钥的松散 ACL"不会被修。
        # 这里无条件再收紧一次 (幂等), 保证升级/换用户后也能自动收敛。
        harden = self.harden_private_keys()
        if harden.get("failed"):
            return True, (f"本地 SSL 根证书与服务端证书已就绪; 但私钥 ACL 收紧未完全成功: "
                          f"{harden.get('message')}")
        return True, "本地 SSL 根证书与服务端证书已全部就绪 (私钥 ACL 已收紧)！"

    def get_cert_thumbprint(self) -> str:
        """获取本地 cer_path 的证书指纹 (SHA1) —— **只读, 缺文件返回空串**

        ⚠ 原先在文件缺失时会**自动调用 `ensure_certificates()`** (2026-10-02 移除此副作用)。
        那意味着"读一下指纹"这个纯查询动作可以**生成一整套 CA 并改写全机受信任存储** ——
        而本方法被 prune 之类的清理/审计路径调用, 于是"审计"变成了"改配置"。
        现在缺文件就如实返回空串, 由调用方显式决定要不要生成:
          · `prune_stale_trust_roots` 见到空串会**中止清理**(已有行为, 保守且正确);
          · 启动流程在 `NginxManager.start()` 里显式 ensure 一次。
        """
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

    def _prune_after_install(self) -> None:
        """安装**成功之后**才清理历史代际残留 (只保留仍在使用的根)

        ⚠ 顺序是安全属性, 不是风格问题 (2026-10-02 定因):
        原先 `install_cert` 是在**安装之前**就 prune —— 于是先删掉旧根、再去尝试装新根,
        中间存在"一个受信任的程序根都没有"的窗口。若随后的安装失败
        (非提权 / PowerShell 被策略拦下 / 5s 超时), 机器就被留在**零信任**状态:
        **所有**走本地 CA 的服务一起 net::ERR_CERT_AUTHORITY_INVALID。
        信任只能"先增后减": 新的装好了, 才轮到清理旧的。
        """
        try:
            prune = self.prune_stale_trust_roots()
            if prune.get("removed"):
                print(f"[Cert] 已清理历史根证书 {len(prune['removed'])} 个")
            if prune.get("protected"):
                print(f"[Cert] 保留仍在使用的根 {len(prune['protected'])} 个 "
                      f"(未被当陈旧清理)")
            if prune.get("failed"):
                print(f"[Cert] 历史根证书清理未完成: {prune.get('message')}")
        except Exception as e:
            print(f"[Cert] 历史根证书清理跳过: {e}")

    def install_cert(self) -> Tuple[bool, str]:
        """静默安装证书到系统与当前用户受信任根证书存储区 (全静默无黑框，前置确保自生成就绪)"""
        self.ensure_certificates()
        if not self.cer_path.exists():
            return False, f"证书文件不存在: {self.cer_path}"

        # ⚠ 这里**不再**先 prune —— 见 _prune_after_install 的顺序说明。
        # 安装成功后才清理, 保证信任集合"先增后减", 失败时宁可留残留也不留零信任。

        # 1. 优先使用 PowerShell Import-Certificate (系统级，静默无弹窗)
        ps_cmd = f"Import-Certificate -FilePath '{self.cer_path}' -CertStoreLocation Cert:\\LocalMachine\\Root"
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                capture_output=True, timeout=5, shell=False, **get_silent_startup_kwargs()
            )
            if self.is_cert_installed(force_refresh=True):
                self._prune_after_install()
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
                    self._prune_after_install()
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
        """从系统与用户根证书库中卸载**本程序的**根证书 (crypt32 原生 + 复查)

        ⚠ 这里原先用的是 `certutil -delstore`, **而且按 CN 名字删** —— 两条都是本项目
        自己已经定过案的错误做法 (2026-10-02 一并改掉):

        1) `certutil -delstore` 对**根证书是空操作**: 它返回 0 并打印"命令成功完成",
           证书却纹丝不动。这正是"不受信任的历史根无限累积"的真因 (实测本机曾累积 53 个)。
           `prune_stale_trust_roots` 早已改用 crypt32 原生删除, 但**卸载路径漏改了** ——
           于是"卸载"从未真正卸载过, 用户以为已经清干净了。
        2) **绝不能按名字删**: 两代根的 Subject 几乎同名
           (`GameArt Toolkit Universal Root CA` / `PixivToolkit Universal Root CA`),
           而同一时刻可能有一个**正在签发叶子证书**。按名字批量删会把它一起带走,
           导致全机 net::ERR_CERT_AUTHORITY_INVALID。必须**按指纹精确删**。

        删除范围: 只删 `list_own_trust_roots()` 认出的自有根 (Subject 命中本程序两代 CN),
        第三方根一律不动。
        """
        own = self.list_own_trust_roots()
        if not own:
            self._cached_installed = None
            return True, "受信任存储中没有本程序的根证书 (无需卸载)"

        removed, failed = [], []
        for cert in own:
            ok, why = self._delete_trust_root(cert["store"], cert["thumbprint"])
            tag = f"{cert['store']}/{cert['thumbprint']}"
            (removed if ok else failed).append(tag if ok else {"root": tag, "reason": why})

        self._cached_installed = None      # 存储已变化, 失效缓存
        if failed:
            detail = "; ".join(f"{f['root']}: {f['reason']}" for f in failed[:3])
            return False, (f"已卸载 {len(removed)} 个本程序根证书, {len(failed)} 个失败 "
                           f"({detail})")
        return True, f"已从受信任存储卸载本程序的全部根证书 ({len(removed)} 个)"

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

        # ⚠ 必须用 `use_last_error=True` 的句柄 + `ctypes.get_last_error()`。
        # 原先写的是 `ctypes.windll.crypt32` + `ctypes.get_last_error()` —— 而 ctypes
        # **没有** get_last_error 这个属性, hasattr 为假时它 fallback 到 0, 于是所有
        # 删除失败都被报成"错误码 0"(毫无信息量)。实测正是它把真实的 E_ACCESSDENIED
        # 掩盖成了无从下手的"1 个失败"。
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
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
                err = ctypes.get_last_error() & 0xFFFFFFFF
                # E_ACCESSDENIED: Windows **保护受信任根**的移除 —— 无论 CurrentUser 还是
                # LocalMachine, 删除根证书都需要管理员权限 (实测: 非管理员下 crypt32 与
                # PowerShell X509Store.Remove 都回 E_ACCESSDENIED)。原先只在 LocalMachine
                # 分支提示管理员, 恰好漏掉了实际会遇到的 CurrentUser 情形。
                if err == 0x80070005:
                    return False, (f"删除被拒绝: E_ACCESSDENIED (0x{err:08X}) —— 移除受信任根"
                                   f"需要管理员权限 (CurrentUser\\Root 同样受保护)")
                if store.startswith("LocalMachine"):
                    return False, f"删除被拒绝 (GetLastError=0x{err:08X}) (机器级存储需管理员权限)"
                return False, f"删除被拒绝 (GetLastError=0x{err:08X})"

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

    def live_ca_thumbprints(self) -> Dict[str, str]:
        """本机上**仍可能在被使用**的自有根指纹 → 出处 (这些一律不得当"陈旧"删除)

        为什么必须有这道保护 (2026-10-02 本会话**第 4 次**事故):
          `prune_stale_trust_roots` 原来只把**本实例** `cer_path` 的指纹当"活跃",
          其余自有根一律判为陈旧并删除。于是只要有人用
          `nginx_dir=<dist>/GameArtToolkit/nginx` 跑一次证书生成, "活跃"就变成 dist 里
          那个新根 (实测 144B3D6C), 而**源码树 nginx 正在真正使用的根**
          (实测 542D3B4C) 被判为陈旧删掉 ⇒ 浏览器 net::ERR_CERT_AUTHORITY_INVALID,
          **全部**走本地 CA 的服务一起失效。
          根因是"活跃"的判据太窄 —— 它只看得见一个目录。这里放宽为:
          **凡在"规范目录"或"本实例目录"里还能找到 ca.cer 的根, 就算在用。**
          这是保守取向: 宁可少清一个, 也不能把正在签发叶子证书的根删掉。
        """
        out: Dict[str, str] = {}
        dirs: List[Path] = []
        try:
            from path_utils import NGINX_DIR as _canon   # 规范目录 (源码树 / 安装目录)
            dirs.append(Path(_canon))
        except Exception:
            pass
        try:
            dirs.append(Path(self.nginx_dir))            # 本实例目录 (可能是 dist)
        except Exception:
            pass
        for root in dirs:
            for rel in ("ca.cer", "ca/ca.cer", "conf/ca/ca.cer"):
                f = root / rel
                try:
                    if not f.is_file():
                        continue
                    raw = f.read_bytes()
                    if b"BEGIN CERTIFICATE" in raw:
                        fp = x509.load_pem_x509_certificate(raw) \
                            .fingerprint(hashes.SHA1()).hex()
                    else:
                        fp = hashlib.sha1(raw).hexdigest()
                    out[fp.upper()] = str(f)
                except Exception:
                    continue
        return out

    def prune_stale_trust_roots(self, dry_run: bool = False) -> Dict[str, Any]:
        """移除历史代际残留的根证书, 只保留当前活跃 CA

        为什么必须做: 每次 CA 失效或强制作废都会重新生成一个根并装入受信任存储, 而旧根
        一直留在库里。实测本机积累了 53 个 (LocalMachine 25 + CurrentUser 28), 而真正在用的
        只有 1 个 —— 其余每一个都能签发任意站点证书, 是持续扩大的中间人攻击面。

        安全性: 只删除 Subject 命中本程序 CA 名称、且指纹 != 当前活跃 CA 的证书;
        第三方证书与当前活跃 CA 一律不动。

        **2026-10-02 加固**: 除"当前活跃 CA"外, 还要保护 `live_ca_thumbprints()` 认出的
        那些"仍在被使用"的根。原先只看本实例 cer_path 一个目录 —— 只要生成动作发生在
        **另一个目录** (实测 dist), 真正在用的根就会被当陈旧删掉, 全机证书信任一起坏掉。
        """
        active = self.get_cert_thumbprint()
        live = self.live_ca_thumbprints()
        before = self.list_own_trust_roots()
        stale = [c for c in before
                 if c["thumbprint"] and c["thumbprint"] != active
                 and c["thumbprint"].upper() not in live]
        # 被保护而刻意不清理的项 —— 必须显式报出来, 否则"清理后仍有残留"会被误判成失败
        protected = [c for c in before
                     if c["thumbprint"] and c["thumbprint"] != active
                     and c["thumbprint"].upper() in live]
        report: Dict[str, Any] = {
            "active": active,
            "live": live,
            "protected": [f"{c['store']}/{c['thumbprint']}"
                          for c in protected],
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
            report["message"] = (
                f"信任库干净: 仅有当前活跃 CA ({len(before)} 个匹配项)"
                + (f"; 另有 {len(protected)} 个仍在被使用的根已保留"
                   if protected else ""))
            return report
        if dry_run:
            report["removed"] = [f"{c['store']}/{c['thumbprint']}" for c in stale]
            report["message"] = (f"预览: 将清理 {len(stale)} 个历史根证书"
                                 + (f", 保留 {len(protected)} 个仍在被使用的"
                                    if protected else ""))
            return report

        # 逐项独立删除: 部分失败 (典型为机器级缺管理员权限) 不应中断整体清理
        needs_admin = False
        for cert in stale:
            tag = f"{cert['store']}/{cert['thumbprint']}"
            # 保留失败原因 —— 原先写成 `ok, _why = ...` 把它丢掉了, 用户只看到"1 个失败",
            # 完全无从判断是权限、是锁、还是 API 语义问题 (实测就是被这一条掩盖了真因)。
            ok, why = self._delete_trust_root(cert["store"], cert["thumbprint"])
            if ok:
                report["removed"].append(tag)
            else:
                report["failed"].append({"root": tag, "reason": why})
                # E_ACCESSDENIED 对 CurrentUser\Root 同样出现, 不能再只按 store 名判断
                if "E_ACCESSDENIED" in why or cert["store"].startswith("LocalMachine"):
                    needs_admin = True

        if report["removed"]:
            self._cached_installed = None       # 存储已变化, 失效缓存
        parts = [f"已清理 {len(report['removed'])} 个历史根证书"]
        if protected:
            # 显式说明, 否则"清理后仍有自有根残留"会被当成清理失败
            parts.append(f"保留 {len(protected)} 个仍在被使用的根 "
                         f"({', '.join(sorted(set(report['protected'])))[:120]})")
        if report["failed"]:
            parts.append(f"{len(report['failed'])} 个失败")
            if needs_admin:
                parts.append("(移除受信任根需要管理员权限, 请以管理员身份重新运行)")
        report["message"] = "; ".join(parts)
        return report

    def _git_global_get(self, key: str) -> Optional[str]:
        """读一个 git 全局配置值; 未设置/读不到/无 git 一律返回 None"""
        try:
            r = subprocess.run(
                ["git", "config", "--global", "--get", key],
                capture_output=True, text=True, timeout=2, shell=False,
                errors="replace", **get_silent_startup_kwargs()
            )
            if r.returncode == 0:
                return (r.stdout or "").strip() or None
        except Exception:
            pass
        return None

    def inject_dev_environments(self) -> bool:
        """为 Git / Node.js 等开发工具挂载作用域证书 (仅针对 GitHub / GitLab 域名生效)

        ⚠ `http.sslBackend` 会被**覆盖**(不是新增), 所以注入前必须记下用户原值
        (缺陷 W9, 2026-10-04)。原实现直接写 `schannel` 且退出时**从不还原**,
        于是用户自己的 `sslBackend` 设置被永久改掉 —— 这属于"改变了用户全部 Git
        仓库的行为"却没有留退路。两个 `sslCAInfo` 是**新增**的键, 卸载即可, 无需备份。
        """
        try:
            cer_str = str(self.cer_path.resolve()).replace("\\", "/")
            # 0. 记下被覆盖的那个键的原值 (None = 原本未设置 ⇒ 还原时应当 unset)
            if self._git_sslbackend_backup is None:
                self._git_sslbackend_backup = self._git_global_get("http.sslBackend") or ""
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
        """清理开发工具的证书注入 (退出/卸载时调用)

        `http.sslBackend` 按注入前记下的原值还原 (缺陷 W9, 2026-10-04):
          · 有备份且原值非空  -> 写回原值;
          · 有备份且原值为空  -> unset (原本没设过这个键);
          · **没有备份** (例如卸载路径: 清理发生在新进程里, 内存备份自然不存在)
            -> 只有当现值确实是**我们写的** `schannel` 时才 unset。绝不无条件 unset ——
            那会把用户自己主动设的 `openssl`/`schannel` 一起抹掉, 把"还原"做成新的破坏。
        """
        try:
            subprocess.run(
                ["git", "config", "--global", "--unset-all", "http.https://github.com.sslCAInfo"],
                capture_output=True, timeout=2, shell=False, **get_silent_startup_kwargs()
            )
            subprocess.run(
                ["git", "config", "--global", "--unset-all", "http.https://gitlab.com.sslCAInfo"],
                capture_output=True, timeout=2, shell=False, **get_silent_startup_kwargs()
            )

            # ── http.sslBackend 的还原 ──────────────────────────────────────
            backup = self._git_sslbackend_backup
            if backup is not None:
                if backup:
                    subprocess.run(
                        ["git", "config", "--global", "http.sslBackend", backup],
                        capture_output=True, timeout=2, shell=False,
                        **get_silent_startup_kwargs()
                    )
                else:
                    subprocess.run(
                        ["git", "config", "--global", "--unset-all", "http.sslBackend"],
                        capture_output=True, timeout=2, shell=False,
                        **get_silent_startup_kwargs()
                    )
                self._git_sslbackend_backup = None
            elif self._git_global_get("http.sslBackend") == "schannel":
                # 无备份但现值是我们的值 ⇒ 安全地收回它
                subprocess.run(
                    ["git", "config", "--global", "--unset-all", "http.sslBackend"],
                    capture_output=True, timeout=2, shell=False,
                    **get_silent_startup_kwargs()
                )

            os.environ.pop("NODE_EXTRA_CA_CERTS", None)
            return True
        except Exception:
            return False


def main(argv: Optional[List[str]] = None) -> int:
    """信任库卫生命令行入口

    用法:
      python -m app.cert_manager --report      # 只读: 列出历史代际根证书 + 私钥 ACL 体检
      python -m app.cert_manager --prune       # 清理历史代际根证书 (机器级需管理员)
      python -m app.cert_manager --prune --dry-run
      python -m app.cert_manager --harden-keys # 收紧私钥 ACL (幂等, 无需管理员)
    """
    import argparse

    ap = argparse.ArgumentParser(description="证书信任库卫生维护")
    ap.add_argument("--report", action="store_true", help="列出本程序历史各代根证书 + 私钥 ACL 体检")
    ap.add_argument("--prune", action="store_true", help="清理历史代际根证书, 仅保留当前活跃 CA")
    ap.add_argument("--dry-run", action="store_true", help="只预览不删除")
    ap.add_argument("--harden-keys", action="store_true", help="收紧证书私钥 ACL (幂等, 无需管理员)")
    args = ap.parse_args(argv)

    mgr = CertManager()
    active = mgr.get_cert_thumbprint()
    print(f"当前活跃 CA: {active or '(未找到 ca.cer)'}")
    print(f"管理员权限 : {is_admin()}")

    if args.harden_keys:
        rep = mgr.harden_private_keys()
        print(rep.get("message", ""))
        for it in rep.get("done", []):
            print(f"  [OK]   {it['path']}")
        for it in rep.get("failed", []):
            print(f"  [FAIL] {it['path']}  {it.get('reason', '')}")
        return 1 if rep.get("failed") else 0

    if args.report or not (args.prune):
        roots = mgr.list_own_trust_roots()
        print(f"受信任存储中匹配本程序的根证书: {len(roots)} 个")
        # 说明: 枚举失败的存储必须显式说出 —— 否则"读不到"会被读成"没问题"
        if _STORE_ENUM_ERRORS:
            print("  ⚠ 以下存储未能枚举, 其结果**未计入**上面的数量:")
            for _lbl, _why in _STORE_ENUM_ERRORS:
                print(f"      {_lbl}: {_why}")
        for c in roots:
            mark = "  <== 当前活跃" if c["thumbprint"] == active else ""
            print(f"  [{c['store']:22s}] {c['thumbprint']} {c['not_after']} {c['subject'][:48]}{mark}")

        # 私钥 ACL 体检 (只读) —— CA 私钥是全机信任锚, 泄露等价于完整中间人能力
        acl = private_key_acl.audit_private_keys(mgr.nginx_dir)
        print(f"\n私钥 ACL 体检: 检查 {acl['checked']} 个文件, 暴露给宽泛受托人的 {acl['exposed']} 个")
        for e in acl["entries"]:
            if not e["readable"]:
                print(f"  [?]    {e['path']}  ({e['error']})")
            elif e["exposed_to"]:
                print(f"  [暴露] {e['path']}  -> {', '.join(e['exposed_to'])}")
            else:
                print(f"  [OK]   {e['path']}")
        if acl["exposed"]:
            print("  提示: 运行 `python -m app.cert_manager --harden-keys` 收紧 (无需管理员)")

        if not args.prune:
            return 0

    report = mgr.prune_stale_trust_roots(dry_run=args.dry_run)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report.get("failed"):
        print("\n失败明细:")
        for it in report["failed"]:
            # failed 现在是 [{root, reason}] 结构 (原先只是个字符串列表, 原因被丢弃)
            if isinstance(it, dict):
                print(f"  [FAIL] {it.get('root')}  {it.get('reason', '')}")
            else:
                print(f"  [FAIL] {it}")
        print("\n提示: 移除受信任根证书需要管理员权限 "
              "(CurrentUser\\Root 与 LocalMachine\\Root 都受 Windows 保护), "
              "请以管理员身份重新运行本命令。")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())


def ensure_single_usable_ca(cm: Optional["CertManager"] = None,
                            allow_trust_changes: bool = True) -> Tuple[bool, str]:
    """把证书状态**收敛到"任一刻恰好有一个可用的根"** (幂等自愈)

    用户定的不变式 (2026-10-03): CA 是自动生成的, 不要求保住某个特定的根, 只要求
    **同时有且仅有一个能用的**。一次收敛包含三件事, 每件都已实测可用:

      1. **叶子必须由当前 ca.cer 签发** —— 用 `_is_signed_by_current_ca` 判定;
         不成立就 `generate_server_cert(force=True)` 重签 (幂等);
      2. **当前根必须在系统信任库里** —— 不在就 `install_cert()`;
      3. **信任库里不得残留其它自有根** —— `prune_stale_trust_roots()` (它会保护在用的那个)。

    为什么必须由代码做而不是靠人记得跑脚本: `nginx -t` 与 `curl -k` **都测不出**断链,
    而断链的表现是"所有本地域名不受信" —— 只有显式验签能发现。实测本机就出现过
    "源码树 ca.cer 不在信任库、库里是另一个根"的状态。

    ⚠ 关于"换了根却不重签叶子": 我一度这么断言过, 但那个判断建立在**一个有 bug 的验签**
      (恒返回 False) 之上, 因此**不成立**, 这里不再声称。第 1 步存在的意义是: 无论根是
      因何被换掉的, 收敛后叶子一定与当前根配套 —— 判据是"结果", 不是"猜测原因"。

    `allow_trust_changes=False` 时只做本地收敛 (不动信任库), 供无管理员权限或测试场景。
    返回 (ok, 人类可读消息); **任何一步失败都不抛异常**, 便于在启动路径上调用。
    """
    cm = cm or CertManager()
    notes: List[str] = []

    # ── 1. 本地: 叶子必须由当前 CA 签发 ─────────────────────────────
    try:
        ok, msg = cm.ensure_certificates()
        if not ok:
            return False, f"本地证书准备失败: {msg}"
        leaf_path = None
        for cand in ("pixiv.net.crt", "server.crt", "localhost.crt"):
            for base in (cm.nginx_dir / "ca", cm.nginx_dir / "conf" / "ca", cm.nginx_dir):
                f = base / cand
                if f.is_file():
                    leaf_path = f
                    break
            if leaf_path:
                break
        if leaf_path is not None:
            try:
                leaf = x509.load_pem_x509_certificate(leaf_path.read_bytes())
                if not cm._is_signed_by_current_ca(leaf):       # noqa: SLF001
                    ok2, msg2 = cm.generate_server_cert(force=True)
                    notes.append(f"叶子与当前根不配套, 已重签 ({msg2 if ok2 else msg2})")
                else:
                    notes.append("叶子与当前根配套")
            except Exception as e:
                notes.append(f"叶子复核跳过: {type(e).__name__}")
    except Exception as e:
        return False, f"本地证书收敛异常: {type(e).__name__}: {e}"

    # ── 2/3. 信任库: 当前根在、其它自有根不在 ────────────────────────
    if not allow_trust_changes:
        notes.append("按要求未改动信任库")
        return True, "; ".join(notes)

    try:
        want = cm.get_cert_thumbprint()
        roots = cm.list_own_trust_roots()
        have = {str(r.get("thumbprint", "")).upper() for r in roots}
        if want and want.upper() not in have:
            ok3, msg3 = cm.install_cert()
            notes.append(f"当前根未装机, 已安装 ({msg3 if ok3 else msg3})")
        try:
            rep = cm.prune_stale_trust_roots()
            removed = rep.get("removed") or []
            if removed:
                notes.append(f"清理其它自有根 {len(removed)} 个")
        except Exception as e:
            notes.append(f"清理其它自有根失败: {type(e).__name__}")
        left = {str(r.get("thumbprint", "")).upper() for r in cm.list_own_trust_roots()}
        notes.append(f"信任库自有根数={len(left)}" + (" (恰为一个 ✓)" if len(left) == 1 else ""))
    except Exception as e:
        # 无管理员权限时走到这里 —— 不阻断, 如实报告
        notes.append(f"信任库收敛未完成 (可能需要管理员): {type(e).__name__}: {e}")

    return True, "; ".join(notes)
