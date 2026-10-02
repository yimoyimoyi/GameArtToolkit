# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 私钥文件 ACL 收紧 (Windows)

为什么需要本模块 (2026-10-01 实测):
  本地 CA 私钥 `nginx/ca/ca.key` 是在**用户可写目录**里直接写出的普通文件, 因此继承了
  父目录的 ACL。实测本机:

      nginx\\ca\\ca.key       BUILTIN\\Authenticated Users:(I)(M)     ← 还能改
      nginx\\conf\\ca\\pixiv.net.key
      C:\\Program Files\\GameArt Toolkit\\nginx\\ca\\ca.key
                              BUILTIN\\Users:(I)(RX)                  ← 能读

  后果: **任意本地进程(含低权限进程)都能把全机受信任的 CA 私钥读走**, 等价于获得对本机的
  完整 TLS 劫持能力 —— 而该根证书是被系统信任的。服务端叶子私钥被读走的危害小一级, 但同样
  允许冒充所有被反代的域名。全仓库 grep `icacls` / `Set-Acl` / `DACL` 零命中, 即此问题从未被处理。

为什么用 crypt32/advapi32 原生 API 而不是 icacls:
  本项目已有教训 —— `certutil -delstore` 对根证书是**空操作**却返回 0 并打印"命令成功完成"
  (见 cert_manager._delete_trust_root 的注释)。文本工具的输出受**系统语言**影响, 解析
  "BUILTIN\\Users" 这类名字在非英文 Windows 上并不可靠。因此这里:
    1. 设置权限走 SetNamedSecurityInfoW (显式 DACL, 无子进程、无引号/语言问题);
    2. 判读受托人一律用 **SID 字符串**(语言无关), 并把"禁止的受托人"写成黑名单;
    3. 设置后**回读校验**, 校验不过一律返回失败 —— 绝不把"调用没报错"当成功。

安全设计要点:
  * 收紧后仅保留 SYSTEM + Administrators + **当前用户**。
    必须保留当前用户: 本程序以普通用户身份运行, 若只留 SYSTEM/Administrators, 程序自己
    下次就再也读不到自己的 CA 私钥 (会触发 CA 重新生成, 反而制造信任库垃圾)。
  * 目录级收紧带 (OI)(CI) 继承 —— 这样将来**新生成**的私钥自动继承紧 ACL, 不会因为
    "先建文件后收紧目录"的时序问题漏掉。
  * 断开继承 (PROTECTED_DACL_SECURITY_INFORMATION) —— 否则父目录一放宽就前功尽弃。
"""

import ctypes
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CA_DIR_NAME = "ca"
CONF_CA_RELATIVE = Path("conf") / CA_DIR_NAME
PRIVATE_KEY_SUFFIXES = (".key",)

# --------------------------------------------------------------------------- 常量
SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
ACL_REVISION = 2
FILE_ALL_ACCESS = 0x001F01FF
OBJECT_INHERIT_ACE = 0x1
CONTAINER_INHERIT_ACE = 0x2
ACCESS_ALLOWED_ACE_TYPE = 0x0
ACCESS_DENIED_ACE_TYPE = 0x1

TOKEN_QUERY = 0x0008
TokenUser = 1

SID_SYSTEM = "S-1-5-18"
SID_ADMINISTRATORS = "S-1-5-32-544"

# 必须从私钥 ACL 中消失的受托人 —— 这些是"任何本地用户/进程都能读"的元凶
FORBIDDEN_SIDS: Dict[str, str] = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-4": "INTERACTIVE",
    "S-1-5-6": "SERVICE",
    "S-1-15-2-1": "ALL APPLICATION PACKAGES",
    "S-1-15-2-2": "ALL RESTRICTED APPLICATION PACKAGES",
}

# 收紧后应当保留的受托人 (当前用户每次动态求值, 故只列固定项做文档用)
KEPT_SIDS_DOC = (SID_SYSTEM, SID_ADMINISTRATORS)


def is_supported() -> bool:
    """本模块仅在 Windows 上可用 (其余平台返回"不支持", 绝不静默假装成功)"""
    return sys.platform == "win32"


# --------------------------------------------------------------------------- ctypes 绑定
if is_supported():  # pragma: no cover - 平台分支
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _ACL(ctypes.Structure):
        _fields_ = [("AclRevision", ctypes.c_ubyte),
                    ("Sbz1", ctypes.c_ubyte),
                    ("AclSize", wintypes.WORD),
                    ("AceCount", wintypes.WORD),
                    ("Sbz2", wintypes.WORD)]

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = [("AceType", ctypes.c_ubyte),
                    ("AceFlags", ctypes.c_ubyte),
                    ("AceSize", wintypes.WORD)]

    class _ACCESS_ALLOWED_ACE(ctypes.Structure):
        _fields_ = [("Header", _ACE_HEADER),
                    ("Mask", wintypes.DWORD),
                    ("SidStart", wintypes.DWORD)]

    _advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    _advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p)]
    _advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    _advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    _advapi32.InitializeAcl.restype = wintypes.BOOL
    _advapi32.InitializeAcl.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    _advapi32.AddAccessAllowedAceEx.restype = wintypes.BOOL
    _advapi32.AddAccessAllowedAceEx.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    _advapi32.GetAce.restype = wintypes.BOOL
    _advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                 ctypes.POINTER(ctypes.c_void_p)]
    _advapi32.GetLengthSid.restype = wintypes.DWORD
    _advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]
    _advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    _advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR,
                                                 ctypes.POINTER(ctypes.c_void_p)]
    _advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p,
                                                 ctypes.POINTER(wintypes.LPWSTR)]
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                           ctypes.POINTER(wintypes.HANDLE)]
    _advapi32.GetTokenInformation.restype = wintypes.BOOL
    _advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                              ctypes.c_void_p, wintypes.DWORD,
                                              ctypes.POINTER(wintypes.DWORD)]
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


# --------------------------------------------------------------------------- 基础工具
def _sid_to_str(psid) -> str:
    out = wintypes.LPWSTR()
    if not _advapi32.ConvertSidToStringSidW(psid, ctypes.byref(out)):
        return ""
    try:
        return out.value or ""
    finally:
        _kernel32.LocalFree(out)


def _str_to_sid(sid: str):
    p = ctypes.c_void_p()
    if not _advapi32.ConvertStringSidToSidW(sid, ctypes.byref(p)):
        raise OSError(f"非法 SID: {sid!r}")
    return p


def current_user_sid() -> str:
    """从进程令牌取当前用户 SID

    刻意不用 os.getlogin()/USERNAME: 账户名受语言与登录方式影响, 而 SID 是稳定标识。
    收紧 ACL 时漏掉自己会把程序锁在门外, 所以这里必须可靠。
    """
    if not is_supported():
        return ""
    h = wintypes.HANDLE()
    if not _advapi32.OpenProcessToken(_kernel32.GetCurrentProcess(), TOKEN_QUERY,
                                      ctypes.byref(h)):
        return ""
    try:
        size = wintypes.DWORD(0)
        _advapi32.GetTokenInformation(h, TokenUser, None, 0, ctypes.byref(size))
        if not size.value:
            return ""
        buf = ctypes.create_string_buffer(size.value)
        if not _advapi32.GetTokenInformation(h, TokenUser, buf, size.value,
                                             ctypes.byref(size)):
            return ""
        p_sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        return _sid_to_str(p_sid)
    except Exception:
        return ""
    finally:
        _kernel32.CloseHandle(h)


def read_acl(path: Path) -> Dict[str, Any]:
    """读回路径的 DACL, 受托人一律以 SID 字符串表达

    返回 {"ok", "error", "null_dacl", "aces": [{"sid","mask","ace_type","ace_flags"}]}
    null_dacl=True 是最坏情况: NULL DACL 表示**所有人完全控制**。
    """
    result: Dict[str, Any] = {"ok": False, "error": "", "null_dacl": False, "aces": []}
    if not is_supported():
        result["error"] = "非 Windows 平台"
        return result
    p = Path(path)
    if not p.exists():
        result["error"] = "路径不存在"
        return result
    pdacl = ctypes.c_void_p()
    psd = ctypes.c_void_p()
    try:
        rc = _advapi32.GetNamedSecurityInfoW(
            str(p), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            None, None, ctypes.byref(pdacl), None, ctypes.byref(psd))
        if rc != 0:
            result["error"] = f"GetNamedSecurityInfoW rc={rc}"
            return result
        if not pdacl:
            result["ok"] = True
            result["null_dacl"] = True
            return result
        acl = ctypes.cast(pdacl, ctypes.POINTER(_ACL)).contents
        aces: List[Dict[str, Any]] = []
        for i in range(acl.AceCount):
            pace = ctypes.c_void_p()
            if not _advapi32.GetAce(pdacl, i, ctypes.byref(pace)):
                continue
            ace = ctypes.cast(pace, ctypes.POINTER(_ACCESS_ALLOWED_ACE)).contents
            if ace.Header.AceType not in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE):
                continue
            sid_ptr = ctypes.c_void_p(pace.value + 8)
            aces.append({
                "sid": _sid_to_str(sid_ptr),
                "mask": int(ace.Mask),
                "ace_type": int(ace.Header.AceType),
                "ace_flags": int(ace.Header.AceFlags),
            })
        result["ok"] = True
        result["aces"] = aces
        return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        return result
    finally:
        if psd:
            _kernel32.LocalFree(psd)


def forbidden_trustees(path: Path) -> List[str]:
    """列出该路径上仍然存在的"宽泛受托人"的人类可读名 (空列表 = 干净)"""
    acl = read_acl(path)
    if not acl["ok"]:
        return []
    found = set()
    for ace in acl["aces"]:
        if ace["sid"] in FORBIDDEN_SIDS:
            found.add(FORBIDDEN_SIDS[ace["sid"]])
    return sorted(found)


def verify_path(path: Path, require_current_user: bool = True) -> Tuple[bool, str]:
    """回读校验: 禁止的受托人必须全部消失, 且当前用户本人仍在列

    这是本模块的**唯一成功判据** —— 设置调用返回成功不算数 (与 certutil 的教训一致)。
    """
    acl = read_acl(path)
    if not acl["ok"]:
        return False, acl["error"] or "无法读取 ACL"
    if acl["null_dacl"]:
        return False, "DACL 为空(NULL) —— 等于所有人完全控制"
    present = {a["sid"] for a in acl["aces"]}
    bad = sorted(FORBIDDEN_SIDS[s] for s in present if s in FORBIDDEN_SIDS)
    if bad:
        return False, f"仍存在宽泛受托人: {', '.join(bad)}"
    if require_current_user:
        me = current_user_sid()
        if not me:
            return False, "无法确定当前用户 SID, 不能确认收紧后自己仍可访问"
        if me not in present:
            return False, f"当前用户({me})不在 ACL 中 —— 会把自己锁在门外"
    return True, "OK"


def harden_path(path: Path, is_dir: Optional[bool] = None) -> Tuple[bool, str]:
    """把路径 DACL 收紧为 SYSTEM + Administrators + 当前用户, 并断开继承

    目录会带 (OI)(CI) 继承, 使其后新建的私钥自动获得紧 ACL。
    返回 (是否成功, 说明); 成功的前提是**回读校验通过**。
    """
    if not is_supported():
        return False, "非 Windows 平台, 无法收紧 ACL"
    p = Path(path)
    if not p.exists():
        return False, "路径不存在"
    if is_dir is None:
        is_dir = p.is_dir()

    me = current_user_sid()
    if not me:
        return False, "无法确定当前用户 SID (拒绝在不确定的情况下改 ACL, 以免把自己锁在外面)"

    wanted = [SID_SYSTEM, SID_ADMINISTRATORS, me]
    sid_ptrs = []
    try:
        for sid in wanted:
            sid_ptrs.append(_str_to_sid(sid))

        need = ctypes.sizeof(_ACL)
        for sp in sid_ptrs:
            need += (ctypes.sizeof(_ACCESS_ALLOWED_ACE) - ctypes.sizeof(wintypes.DWORD)
                     + _advapi32.GetLengthSid(sp))
        buf = ctypes.create_string_buffer(need)
        pacl = ctypes.cast(buf, ctypes.c_void_p)
        if not _advapi32.InitializeAcl(pacl, need, ACL_REVISION):
            return False, f"InitializeAcl 失败 (err={ctypes.get_last_error()})"

        ace_flags = (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) if is_dir else 0
        for sp in sid_ptrs:
            if not _advapi32.AddAccessAllowedAceEx(pacl, ACL_REVISION, ace_flags,
                                                   FILE_ALL_ACCESS, sp):
                return False, f"AddAccessAllowedAceEx 失败 (err={ctypes.get_last_error()})"

        info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        rc = _advapi32.SetNamedSecurityInfoW(str(p), SE_FILE_OBJECT, info,
                                             None, None, pacl, None)
        if rc != 0:
            hint = " (需要对该文件的所有权或管理员权限)" if rc == 5 else ""
            return False, f"SetNamedSecurityInfoW rc={rc}{hint}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        for sp in sid_ptrs:
            try:
                _kernel32.LocalFree(sp)
            except Exception:
                pass

    # 唯一成功判据: 回读校验
    ok, why = verify_path(p)
    if not ok:
        return False, f"设置后校验未通过: {why}"
    return True, ""


# --------------------------------------------------------------------------- 面向证书目录的封装
def private_key_paths(nginx_dir: Path) -> List[Path]:
    """枚举需要保护的私钥文件 (nginx/ca 与 nginx/conf/ca 下的 *.key)"""
    nginx_dir = Path(nginx_dir)
    out: List[Path] = []
    for d in (nginx_dir / CA_DIR_NAME, nginx_dir / CONF_CA_RELATIVE):
        if not d.is_dir():
            continue
        for f in sorted(d.iterdir()):
            if f.is_file() and f.suffix.lower() in PRIVATE_KEY_SUFFIXES:
                out.append(f)
    return out


def audit_private_keys(nginx_dir: Path) -> Dict[str, Any]:
    """只读体检: 列出私钥当前是否暴露给宽泛受托人 (供 --report 使用)"""
    nginx_dir = Path(nginx_dir)
    entries: List[Dict[str, Any]] = []
    for p in private_key_paths(nginx_dir):
        acl = read_acl(p)
        entries.append({
            "path": str(p),
            "readable": acl["ok"],
            "error": acl["error"],
            "exposed_to": forbidden_trustees(p),
            "aces": [{"sid": a["sid"], "mask": hex(a["mask"])} for a in acl["aces"]],
        })
    exposed = [e for e in entries if e["exposed_to"]]
    return {
        "supported": is_supported(),
        "current_user_sid": current_user_sid(),
        "checked": len(entries),
        "exposed": len(exposed),
        "entries": entries,
        "clean": bool(entries) and not exposed,
    }


def harden_private_keys(nginx_dir: Path) -> Dict[str, Any]:
    """收紧全部私钥及其所在目录的 ACL (幂等; 可在每次启动时调用)

    顺序: 先收紧目录 (带继承), 再逐个收紧已存在的私钥文件 —— 这样"目录先建、文件后建"
    与"文件先建、目录后收紧"两种时序都能覆盖。
    """
    nginx_dir = Path(nginx_dir)
    report: Dict[str, Any] = {"supported": is_supported(), "done": [], "failed": [],
                              "skipped": [], "exposed_before": [], "message": ""}
    if not is_supported():
        report["message"] = "非 Windows 平台, 跳过私钥 ACL 收紧"
        return report

    dirs = [nginx_dir / CA_DIR_NAME, nginx_dir / CONF_CA_RELATIVE]
    keys = private_key_paths(nginx_dir)
    report["exposed_before"] = sorted(
        {name for p in keys for name in forbidden_trustees(p)})

    targets: List[Tuple[Path, bool]] = [(d, True) for d in dirs if d.is_dir()]
    targets += [(k, False) for k in keys]

    for path, is_dir in targets:
        ok, why = harden_path(path, is_dir=is_dir)
        item = {"path": str(path), "reason": why}
        if ok:
            report["done"].append(item)
        else:
            report["failed"].append(item)

    if report["failed"]:
        report["message"] = (f"私钥 ACL 收紧部分失败: {len(report['failed'])} 项 "
                             f"(成功 {len(report['done'])} 项)")
    elif report["done"]:
        report["message"] = f"私钥 ACL 已收紧为 SYSTEM + Administrators + 当前用户 ({len(report['done'])} 项)"
    else:
        report["message"] = "未发现需要收紧的私钥文件"
    return report


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    # 与 cert_manager/quic_probe 同款: 直接以脚本方式运行时也要能找到同目录模块
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from path_utils import NGINX_DIR

    ap = argparse.ArgumentParser(description="私钥文件 ACL 体检与收紧")
    ap.add_argument("--audit", action="store_true", help="只读: 列出私钥当前的宽泛受托人")
    ap.add_argument("--harden", action="store_true", help="收紧 ACL (幂等)")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    ap.add_argument("--nginx-dir", default=str(NGINX_DIR), help="nginx 目录 (便于测试)")
    args = ap.parse_args(argv)

    if args.harden:
        rep = harden_private_keys(Path(args.nginx_dir))
    else:
        rep = audit_private_keys(Path(args.nginx_dir))

    if args.json:
        import json as _json
        print(_json.dumps(rep, ensure_ascii=False, indent=2))
        return 0 if not rep.get("failed") else 1

    print(f"当前用户 SID: {rep.get('current_user_sid', '-')}")
    if args.harden:
        print(rep["message"])
        for it in rep["done"]:
            print(f"  [OK]   {it['path']}")
        for it in rep["failed"]:
            print(f"  [FAIL] {it['path']}  {it['reason']}")
        return 0 if not rep["failed"] else 1

    if not rep["supported"]:
        print("非 Windows 平台, 无 ACL 概念")
        return 0
    print(f"检查 {rep['checked']} 个私钥文件; 暴露给宽泛受托人的: {rep['exposed']}")
    for e in rep["entries"]:
        if not e["readable"]:
            print(f"  [?] {e['path']}  读取失败: {e['error']}")
        elif e["exposed_to"]:
            print(f"  [暴露] {e['path']}  -> {', '.join(e['exposed_to'])}")
        else:
            print(f"  [OK]   {e['path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
