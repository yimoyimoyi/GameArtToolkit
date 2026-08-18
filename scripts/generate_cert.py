# -*- coding: utf-8 -*-
"""
PixivToolkit - 28 项全量加速服务通用 SAN 证书生成器 (X.509 v3 + SHA256)
自动生成覆盖全生态 28 项服务的根证书 (Root CA) 与多域名通用通配符服务端证书
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

# 28 项全量加速服务全域名 & 通配符 SAN 列表
ALL_SAN_DOMAINS = [
    # 🎨 Pixiv 二次元 & 创作生态
    "*.pixiv.net", "pixiv.net", "www.pixiv.net", "touch.pixiv.net", "app-api.pixiv.net",
    "oauth.secure.pixiv.net", "accounts.pixiv.net", "comic.pixiv.net", "novel.pixiv.net",
    "dic.pixiv.net", "sketch.pixiv.net", "public-api.secure.pixiv.net",
    "*.secure.pixiv.net", "pixivision.net", "*.pixivision.net", "pixiv.me", "*.pixiv.me",
    "*.pximg.net", "pximg.net", "i.pximg.net", "s.pximg.net", "source.pixiv.net", "imgaz.pixiv.net",
    "*.fanbox.cc", "fanbox.cc", "api.fanbox.cc", "downloads.fanbox.cc",
    "*.booth.pm", "booth.pm", "api.booth.pm", "assets.booth.pm",
    "*.donmai.us", "donmai.us", "danbooru.donmai.us", "cdn.donmai.us",
    "*.yande.re", "yande.re", "files.yande.re",
    "*.artstation.com", "artstation.com", "www.artstation.com", "cdna.artstation.com", "cdnb.artstation.com",
    "*.vndb.org", "vndb.org", "t.vndb.org",
    "*.kemono.su", "kemono.su", "c.kemono.su",

    # 🎮 游戏生态 (Steam / Epic / Ubisoft / EA / GOG / 战网)
    "*.steampowered.com", "steampowered.com", "store.steampowered.com", "checkout.steampowered.com",
    "help.steampowered.com", "login.steampowered.com", "api.steampowered.com",
    "*.steamcommunity.com", "steamcommunity.com",
    "*.steamstatic.com", "steamstatic.com", "community.akamai.steamstatic.com",
    "avatars.akamai.steamstatic.com", "clan.akamai.steamstatic.com", "community.steamstatic.com",
    "*.steam-chat.com", "steam-chat.com", "*.steamserver.net", "steamserver.net",
    "*.akamaized.net", "akamaized.net", "*.akamaiedge.net", "akamaiedge.net", "*.akamaihd.net", "akamaihd.net",
    "*.epicgames.com", "epicgames.com", "store.epicgames.com", "launcher-website-prod07.ol.epicgames.com", "static-assets-prod.epicgames.com",
    "*.ubi.com", "ubi.com", "store.ubi.com", "*.ubisoftconnect.com", "ubisoftconnect.com", "api-ubiservices.ubi.com",
    "*.origin.com", "origin.com", "api.origin.com", "api1.origin.com", "signin.ea.com", "*.ea.com", "ea.com",
    "*.gog.com", "gog.com", "api.gog.com", "*.gog-statics.com", "images.gog-statics.com",
    "*.battle.net", "battle.net", "shop.battle.net", "account.battle.net", "oauth.battle.net",

    # 💻 开发者与 AI
    "*.github.com", "github.com", "www.github.com", "api.github.com", "gist.github.com", "codeload.github.com",
    "*.githubusercontent.com", "githubusercontent.com", "raw.githubusercontent.com",
    "objects.githubusercontent.com", "github-releases.githubusercontent.com", "user-images.githubusercontent.com",
    "*.githubassets.com", "githubassets.com", "*.github.dev", "github.dev",
    "*.civitai.com", "civitai.com", "image.civitai.com", "image-b2.civitai.com", "model-delivery.civitai.com", "orchestration.civitai.com", "ws.civitai.com", "*.civitai.red", "civitai.red", "image.civitai.red",
    "*.docker.com", "docker.com", "hub.docker.com", "*.docker.io", "registry-1.docker.io",
    "*.stackoverflow.com", "stackoverflow.com", "*.sstatic.net", "cdn.sstatic.net",
    "*.gitlab.com", "gitlab.com", "*.gitlab-static.net", "assets.gitlab-static.net",
    "*.huggingface.co", "huggingface.co", "*.hf.co", "hf.co", "*.hf.space", "hf.space",

    # 🌐 海外日常工具
    "*.discord.com", "discord.com", "*.discordapp.com", "cdn.discordapp.com", "*.discordapp.net", "media.discordapp.net", "*.discord.gg", "discord.gg",
    "*.reddit.com", "reddit.com", "www.reddit.com", "*.redd.it", "i.redd.it", "v.redd.it",
    "*.wikipedia.org", "wikipedia.org", "en.wikipedia.org", "zh.wikipedia.org", "*.wikimedia.org", "upload.wikimedia.org",
    "*.live.com", "onedrive.live.com", "*.onedrive.com", "api.onedrive.com",
]

def generate_certificates():
    print("========================================================")
    print("   PixivToolkit - 生成 28 项全量加速生态通用 SSL 根证书与服务端证书")
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

    # 4. 签发覆盖全生态 28 项服务的多域名 SAN 服务端证书
    print(f"[4/4] 签发全量多域名通用证书 (包含 {len(ALL_SAN_DOMAINS)} 个通配符与独立域名)...")
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Shanghai"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PixivToolkit Accelerator"),
        x509.NameAttribute(NameOID.COMMON_NAME, "*.pixiv.net"),
    ])

    # 去重 SAN 列表
    unique_sans = sorted(list(set(ALL_SAN_DOMAINS)))
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

    # 写入各部署目录
    CA_DIR.mkdir(parents=True, exist_ok=True)
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    CONF_CA_DIR.mkdir(parents=True, exist_ok=True)

    # 1. 根证书 (供 Windows 导入受信任根证书库)
    (NGINX_DIR / "ca.cer").write_bytes(ca_pem)
    (CA_DIR / "ca.cer").write_bytes(ca_pem)

    # 2. 服务端证书 (Nginx ssl_certificate 引用)
    (CA_DIR / "pixiv.net.crt").write_bytes(server_pem)
    (CA_DIR / "pixiv.net.key").write_bytes(server_key_pem)

    (CONF_DIR / "cert.pem").write_bytes(server_pem)
    (CONF_DIR / "key.pem").write_bytes(server_key_pem)

    (CONF_CA_DIR / "pixiv.net.crt").write_bytes(server_pem)
    (CONF_CA_DIR / "pixiv.net.key").write_bytes(server_key_pem)

    print("\n========================================================")
    print("  [SUCCESS] 证书生成完毕！")
    print(f"  * Root CA 指纹 (SHA1): {ca_cert.fingerprint(hashes.SHA1()).hex().upper()}")
    print(f"  * 包含 SAN 域名总数: {len(unique_sans)} 个")
    print("========================================================")

if __name__ == "__main__":
    generate_certificates()
