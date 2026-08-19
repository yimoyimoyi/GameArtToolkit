# -*- coding: utf-8 -*-
"""
PixivToolkit - 本地证书自生成与生命周期管理单元测试
"""

import sys
import shutil
import datetime
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_DIR / "app"))

from cert_manager import CertManager, get_all_san_domains
from service_profile import PROFILES, TOTAL_SERVICES_COUNT


class TestCertManager:
    """证书自生成、动态 SAN 映射与自愈机制测试"""

    def test_get_all_san_domains(self):
        """测试从 ServiceProfile 动态提取 SAN 域名列表"""
        sans = get_all_san_domains()
        assert len(sans) > 0
        assert isinstance(sans, list)
        
        # 必须包含主要通配符和主域名
        assert "*.pixiv.net" in sans
        assert "pixiv.net" in sans
        assert "*.pximg.net" in sans
        assert "pximg.net" in sans
        assert "*.steampowered.com" in sans
        assert "*.steamcommunity.com" in sans
        assert "*.github.com" in sans
        assert "*.githubusercontent.com" in sans

        # 确保全部小写、去重并排序
        assert sans == sorted(list(set(sans)))
        for d in sans:
            assert d == d.lower().strip()

    def test_generate_root_ca_in_temp_dir(self, tmp_path):
        """测试在全新临时目录中自生成 Root CA"""
        nginx_dir = tmp_path / "nginx"
        ca_cer = nginx_dir / "ca.cer"
        
        cm = CertManager(cer_path=ca_cer, nginx_dir=nginx_dir)
        ok, msg = cm.generate_root_ca()
        assert ok is True
        assert ca_cer.exists()
        assert (nginx_dir / "ca" / "ca.key").exists()
        assert (nginx_dir / "ca" / "ca.cer").exists()

        # 验证 Root CA 证书与私钥
        ca_pem = ca_cer.read_bytes()
        cert = x509.load_pem_x509_certificate(ca_pem)
        
        # 验证自签名
        assert cert.subject == cert.issuer
        assert "GameArt Toolkit Universal Root CA" in cert.subject.rfc4514_string()

        # 验证 CA 约束
        bc = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS).value
        assert bc.ca is True

        # 验证 KeyUsage
        ku = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE).value
        assert ku.key_cert_sign is True
        assert ku.crl_sign is True

        # 验证有效期 (>= 14 年)
        now = datetime.datetime.now(datetime.timezone.utc)
        if hasattr(cert, "not_valid_after_utc"):
            expiry = cert.not_valid_after_utc
        else:
            expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        assert (expiry - now).days >= 365 * 14

        # 验证指纹提取
        thumb = cm.get_cert_thumbprint()
        assert len(thumb) == 40
        assert thumb.isupper()

    def test_generate_server_cert_in_temp_dir(self, tmp_path):
        """测试使用本地 Root CA 签发包含全量 SAN 的服务端证书"""
        nginx_dir = tmp_path / "nginx"
        ca_cer = nginx_dir / "ca.cer"
        
        cm = CertManager(cer_path=ca_cer, nginx_dir=nginx_dir)
        ok, msg = cm.generate_server_cert()
        assert ok is True
        
        server_crt_path = nginx_dir / "ca" / "pixiv.net.crt"
        server_key_path = nginx_dir / "ca" / "pixiv.net.key"
        conf_crt_path = nginx_dir / "conf" / "ca" / "pixiv.net.crt"
        conf_key_path = nginx_dir / "conf" / "ca" / "pixiv.net.key"

        assert server_crt_path.exists()
        assert server_key_path.exists()
        assert conf_crt_path.exists()
        assert conf_key_path.exists()

        # 验证服务端证书
        cert = x509.load_pem_x509_certificate(server_crt_path.read_bytes())
        
        # 验证服务端不是 CA
        bc = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS).value
        assert bc.ca is False

        # 验证 SAN 域名覆盖率
        san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns_names = set(san_ext.get_values_for_type(x509.DNSName))
        
        all_sans = get_all_san_domains()
        for expected_domain in all_sans:
            assert expected_domain in dns_names

        # 验证私钥可解析
        key = serialization.load_pem_private_key(server_key_path.read_bytes(), password=None)
        assert key.key_size == 2048

    def test_ensure_certificates_and_self_healing(self, tmp_path):
        """测试一键保障方法以及缺失文件自动自愈机制"""
        nginx_dir = tmp_path / "nginx"
        ca_cer = nginx_dir / "ca.cer"
        
        cm = CertManager(cer_path=ca_cer, nginx_dir=nginx_dir)
        
        # 1. 首次保障生成
        ok, msg = cm.ensure_certificates()
        assert ok is True
        
        thumb1 = cm.get_cert_thumbprint()
        assert len(thumb1) == 40

        # 2. 再次保障时由于未过期应复用已存在证书 (幂等性)
        ok2, msg2 = cm.ensure_certificates(force=False)
        assert ok2 is True
        thumb2 = cm.get_cert_thumbprint()
        assert thumb1 == thumb2

        # 3. 故意删除服务端私钥与证书，测试自愈重签
        (nginx_dir / "ca" / "pixiv.net.key").unlink()
        (nginx_dir / "ca" / "pixiv.net.crt").unlink()
        assert not (nginx_dir / "ca" / "pixiv.net.key").exists()

        ok3, msg3 = cm.ensure_certificates()
        assert ok3 is True
        assert (nginx_dir / "ca" / "pixiv.net.key").exists()
        assert (nginx_dir / "ca" / "pixiv.net.crt").exists()
        # CA 保持不变
        assert cm.get_cert_thumbprint() == thumb1

        # 4. 故意删除 Root CA 私钥，测试彻底重新生成
        (nginx_dir / "ca" / "ca.key").unlink()
        ok4, msg4 = cm.ensure_certificates()
        assert ok4 is True
        assert (nginx_dir / "ca" / "ca.key").exists()
        # 重新生成后产生新指纹
        cm._cached_thumbprint = None
        new_thumb = cm.get_cert_thumbprint()
        assert len(new_thumb) == 40
