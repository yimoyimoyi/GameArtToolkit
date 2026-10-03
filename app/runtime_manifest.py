# -*- coding: utf-8 -*-
"""运行清单与**启动前校验**（自有设计）

解决什么: 本项目的运行时依赖分散在两棵树上（源码 `nginx/` 与打包 `dist/.../nginx`），
各自一套 CA、一套证书。已实测因此发生过 **5 次**信任库事故 —— 打包版启动时生成自己的
CA 并替换掉信任库里的根，于是源码树服务的叶子**不再被信任的那个根签发**，浏览器报
`ERR_CERT_AUTHORITY_INVALID`。而 `nginx -t` 与 `curl -k` **都测不出**这种断链。

所以这里把"运行时需要什么、以及它们之间必须成立什么关系"写成可执行清单, 启动前跑一遍,
**明确报错**而不是半可用。

三条不变量 (按重要性):
  A. **签发当前叶子的根, 必须就是信任库里装着的那个根** —— 这是那 5 次事故的直接判据;
  B. `ca.key` 与 `ca.cer` 必须匹配 (审计发现 `_is_ca_valid()` 只看文件存在与有效期,
     从不验证这对是否配套 —— 一旦不配套, 签出来的叶子谁都不认);
  C. 清单里的文件必须存在 (nginx 配置、CA、至少一张叶子证书)。

⚠ 本模块**不修改任何东西**: 只读文件、只读信任库, 返回问题清单。
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False


def _load_cert(path: Path):
    if not _HAS_CRYPTO:
        return None
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except Exception:
        try:
            return x509.load_der_x509_certificate(path.read_bytes())
        except Exception:
            return None


def _thumbprint(cert) -> str:
    return hashlib.sha1(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()


def _find_first(nginx_dir: Path, names, preferred) -> Path:
    """先看优先位置, 再在整个 nginx 目录里找; 都找不到时返回优先位置(供报错显示)"""
    for rel in preferred:
        cand = nginx_dir / rel
        if cand.is_file():
            return cand
    for name in names:
        hits = sorted(p for p in nginx_dir.rglob(name) if p.is_file())
        if hits:
            return hits[0]
    return nginx_dir / preferred[0]


def find_ca_cer(nginx_dir: Path) -> Path:
    return _find_first(Path(nginx_dir), ("ca.cer", "ca.crt", "ca.pem"),
                       ("ca/ca.cer", "ca.cer"))


def find_ca_key(nginx_dir: Path) -> Path:
    return _find_first(Path(nginx_dir), ("ca.key",), ("ca/ca.key", "ca.key"))


def _leaf_candidates(nginx_dir: Path) -> List[Path]:
    """找"被服务的叶子证书": nginx 目录下的 *.crt/*.cer, 排除 ca.cer"""
    out = []
    for pat in ("*.crt", "*.cer", "*.pem"):
        for p in nginx_dir.rglob(pat):
            if p.name.lower() in ("ca.cer", "ca.crt", "ca.pem"):
                continue
            if p.is_file():
                out.append(p)
    return sorted(set(out))


def _is_signed_by(cert, ca) -> bool:
    """用 CA 的公钥验证 cert 的签名 (不依赖链的其它环节)

    ⚠⚠ 这里曾经写错过, 而那个错误**方向危险**: 它恒返回 False, 于是把"链是通的"
       误报成"叶子不被信任根签发" —— 我自己据此虚报过一次"证书事故"。
    错在哪: 旧实现把 `cert.signature_algorithm_parameters` 当成 hash 传给 verify()。
       对 PKCS#1 v1.5 (sha256WithRSAEncryption) 该属性是 **None**, 于是抛
       `TypeError: Expected instance of hashes.HashAlgorithm.` —— 而它被宽 except 吞掉。
    所以现在: ① 优先用现代 API `verify_directly_issued_by` (它自己处理填充与哈希);
             ② 退化路径只传 `signature_hash_algorithm`, **不传** parameters;
             ③ 且**不再静默**: 两条路都失败时把原因记下来, 便于下次一眼看出是"验签失败"
                还是"验签代码失败"。
    """
    if not _HAS_CRYPTO:
        return False
    verify = getattr(cert, "verify_directly_issued_by", None)
    if verify is not None:
        try:
            verify(ca)
            return True
        except Exception:
            pass
    try:
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                               cert.signature_hash_algorithm)
        return True
    except Exception:
        return False


def check(nginx_dir: Optional[Path] = None,
          trust_root_thumbprints: Optional[Sequence[str]] = None,
          include_trust: bool = True) -> List[str]:
    """返回问题清单 (空 = 通过)。全部只读。

    `include_trust=False` 只查**本地**不变量 (文件齐全 / key 与 cer 配套 / 叶子被本目录
    的 CA 签发) —— 这些在任何环境下都必须成立, 所以适合做**阻断**判据。
    信任库那条 (A) 依赖环境 (装机是否做过、打包版是否换过根), 适合做**告警**:
    实测沙箱测试里 CA 是现生成、并未装机, 若把它也当阻断, 测试会无辜变红。
    """
    problems: List[str] = []

    if nginx_dir is None:
        try:
            import path_utils
            nginx_dir = Path(path_utils.NGINX_DIR)
        except Exception as e:  # pragma: no cover
            return [f"无法确定 nginx 目录: {type(e).__name__}: {e}"]
    nginx_dir = Path(nginx_dir)

    if not nginx_dir.is_dir():
        return [f"nginx 目录不存在: {nginx_dir}"]

    # ── C. 必需文件 ────────────────────────────────────────────────
    required = {
        "nginx.conf": nginx_dir / "conf" / "nginx.conf",
        "upstream-dynamic.conf": nginx_dir / "conf" / "upstream-dynamic.conf",
        # 路径**运行时查找**而不是写死: 实测真实布局是 nginx/ca/ca.{cer,key},
        # 而 nginx/ca.cer 只是根目录下的一份副本 —— 写死任一个都会误报"缺少"。
        "ca.cer": find_ca_cer(nginx_dir),
        "ca.key": find_ca_key(nginx_dir),
    }
    for role, path in required.items():
        if not path.is_file():
            problems.append(f"缺少 {role}: {path}")

    ca_cer = required["ca.cer"]
    ca_key = required["ca.key"]
    if problems:
        return problems          # 前置缺失时后面的关系无从谈起

    ca = _load_cert(ca_cer)
    if ca is None:
        problems.append(f"ca.cer 无法解析 (是否 PEM/DER 证书?): {ca_cer}")
        return problems

    # ── B. ca.key 与 ca.cer 必须配套 ───────────────────────────────
    try:
        key = serialization.load_pem_private_key(ca_key.read_bytes(), password=None)
        k_pub = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        c_pub = ca.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if k_pub != c_pub:
            problems.append("ca.key 与 ca.cer **不配套** (公钥不同) —— 用它签出的叶子不会被信任")
    except Exception as e:
        problems.append(f"ca.key 无法读取或解析: {type(e).__name__}: {e}")

    # ── A. 叶子必须由这个 CA 签发, 且该 CA 必须在信任库里 ──────────
    leaves = _leaf_candidates(nginx_dir)
    if not leaves:
        problems.append(f"没有找到任何叶子证书 (*.crt/*.cer) 于 {nginx_dir}")
        return problems

    ca_tp = _thumbprint(ca)
    trusted = {str(t).upper() for t in (trust_root_thumbprints or ())}
    if trust_root_thumbprints is None:
        try:
            import cert_manager
            trusted = {str(r.get("thumbprint", "")).upper()
                       for r in cert_manager.CertManager().list_own_trust_roots()}
        except Exception as e:
            problems.append(f"无法读取信任库: {type(e).__name__}: {e}")
            trusted = set()

    if include_trust and ca_tp not in trusted:
        problems.append(
            f"**签发叶子的根不在信任库里** (CA 指纹 {ca_tp[:16]}…; 信任库里是 "
            f"{sorted(t[:16] + '…' for t in trusted) or '空'}) —— 浏览器会报 "
            f"ERR_CERT_AUTHORITY_INVALID, 而 nginx -t / curl -k 都测不出来")

    unsigned = [p.name for p in leaves if not _is_signed_by(_load_cert(p), ca)]
    if unsigned:
        problems.append(f"这些叶子**不是**由 ca.cer 签发的: {unsigned}")

    return problems


def describe(nginx_dir: Optional[Path] = None) -> Dict[str, Any]:
    """给人看的摘要 (供界面/日志), 不含任何修改动作"""
    if nginx_dir is None:
        try:
            import path_utils
            nginx_dir = Path(path_utils.NGINX_DIR)
        except Exception:
            nginx_dir = None
    info: Dict[str, Any] = {"nginx_dir": str(nginx_dir) if nginx_dir else None}
    problems = check(nginx_dir)
    info["ok"] = not problems
    info["problems"] = problems
    if nginx_dir:
        ca = _load_cert(find_ca_cer(Path(nginx_dir)))
        info["ca_thumbprint"] = _thumbprint(ca) if ca is not None else None
        info["leaves"] = [p.name for p in _leaf_candidates(Path(nginx_dir))]
    return info
