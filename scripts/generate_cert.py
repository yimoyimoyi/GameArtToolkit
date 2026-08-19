# -*- coding: utf-8 -*-
"""
PixivToolkit - 18 项加速服务通用 SAN 证书生成器 (X.509 v3 + SHA256)
自动生成覆盖 18 项服务的根证书 (Root CA) 与多域名通用通配符服务端证书
"""

import sys
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

BASE_DIR = Path(__file__).resolve().parent.parent
NGINX_DIR = BASE_DIR / "nginx"
CA_DIR = NGINX_DIR / "ca"
CONF_DIR = NGINX_DIR / "conf"
CONF_CA_DIR = CONF_DIR / "ca"

sys.path.insert(0, str(BASE_DIR / "app"))
from service_profile import PROFILES, TOTAL_SERVICES_COUNT

def get_all_san_domains() -> list:
    """从 ServiceProfile 单源动态提取全量 SAN 域名列表并自动拓展通配符"""
    domains_set = set()
    for p in PROFILES:
        for d in p.domains:
            d_clean = d.lower().strip()
            if not d_clean:
                continue
            domains_set.add(d_clean)
            if d_clean.startswith("*."):
                domains_set.add(d_clean[2:])
            else:
                domains_set.add(f"*.{d_clean}")
    return sorted(list(domains_set))

def generate_certificates():
    all_san_domains = get_all_san_domains()
    print("========================================================")
    print(f"   PixivToolkit - 生成 {TOTAL_SERVICES_COUNT} 项加速服务通用 SSL 根证书与服务端证书")
    print("========================================================")

    # 1. 创建 Root CA 私钥
    print("\n[1/4] 生成 Root CA 私钥 (RSA 2048)...")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 2. 生成自签名 Root CA 证书 (15 年有效期)
    print("[2/4] 签发 PixivToolkit Universal Root CA 根证书 (15年有效期)...")
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Shanghai"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PixivToolkit Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, "PixivToolkit Universal Root CA"),
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

    # 3. 生成服务端私钥
    print("[3/4] 生成服务端私钥 (RSA 2048)...")
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 4. 签发覆盖全量服务的多域名 SAN 服务端证书
    unique_sans = sorted(list(set(all_san_domains)))
    print(f"[4/4] 签发全量多域名通用证书 (包含 {len(unique_sans)} 个通配符与独立域名)...")
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Shanghai"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PixivToolkit Accelerator"),
        x509.NameAttribute(NameOID.COMMON_NAME, "*.pixiv.net"),
    ])

    san_list = [x509.DNSName(d) for d in unique_sans]

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
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

    # 导出 PEM 与 DER 格式
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    ca_key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    )

    server_pem = server_cert.public_bytes(serialization.Encoding.PEM)
    server_key_pem = server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    )

    # 写入规范部署路径 (根证书位于 nginx/ca.cer, 服务端证书位于 nginx/ca/ 与 nginx/conf/ca/)
    CA_DIR.mkdir(parents=True, exist_ok=True)
    CONF_CA_DIR.mkdir(parents=True, exist_ok=True)

    # 1. 根证书 (供 Windows 导入受信任根证书库)
    (NGINX_DIR / "ca.cer").write_bytes(ca_pem)

    # 2. 服务端证书 (Nginx ssl_certificate 引用)
    (CA_DIR / "pixiv.net.crt").write_bytes(server_pem)
    (CA_DIR / "pixiv.net.key").write_bytes(server_key_pem)
    (CONF_CA_DIR / "pixiv.net.crt").write_bytes(server_pem)
    (CONF_CA_DIR / "pixiv.net.key").write_bytes(server_key_pem)

    print("\n========================================================")
    print("  [SUCCESS] 证书生成完毕！")
    print(f"  * Root CA 指纹 (SHA1): {ca_cert.fingerprint(hashes.SHA1()).hex().upper()}")
    print(f"  * 包含 SAN 域名总数: {len(unique_sans)} 个")
    print("========================================================")

if __name__ == "__main__":
    generate_certificates()
