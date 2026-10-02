# -*- coding: utf-8 -*-
"""
GameArt Toolkit - Windows NRPT 域名重定向后端 (DnsClient 名称解析策略表)

与 Hosts 注入的定位差异:
- 不改动系统 Hosts 文件, 而是向 Windows DNS 客户端的名称解析策略表
  (Name Resolution Policy Table, NRPT) 写入命名空间规则, 把命中域名的 DNS 查询
  定向到本机解析器 (127.0.0.1:53), 由本机解析器决定应答 127.0.0.1 (反代劫持)
  还是最优 CDN IP (直连优选)。
- 天然支持后缀树匹配: 规则以 ".example.com" 形式登记即覆盖整个子域, 无需像 Hosts
  那样逐个精确域名枚举。

实现依据 (全部为 Microsoft 公开契约, 未参考任何第三方项目的实现):
  Microsoft Learn / DnsClient 模块:
    Add-DnsClientNrptRule    -Namespace <String[]> 命名空间 (必需, 前缀 "." 表示后缀匹配)
                             -NameServers <String[]> DirectAccess 关闭时接收查询的 DNS 服务器
                             -DisplayName / -Comment 自定义标识与备注
    Get-DnsClientNrptRule    枚举规则 (无需管理员权限)
    Remove-DnsClientNrptRule -Name <String[]> 按规则名 (GUID) 删除

两条硬约束 (本机实测确认, 直接决定可用性):
1. 端口约束: NRPT 的 -NameServers 只能填 IP, 查询固定发往 53 端口。因此本模式要求
   本机 53/UDP 可用。第三方代理的 DNS 覆写常占用 :53 (实测 Clash Verge 的
   verge-mihomo 以双栈 :::53 监听, 此时连 SO_REUSEADDR 也绑不上 127.0.0.1:53,
   报 WSAEACCES 10013)。冲突时 capabilities() 会给出占用进程名, 由上游决定回退。
2. 权限约束: 写入 NRPT 必须提权 (非管理员报 "无法加载 NRPT 信息 ... 请验证你具有
   该计算机的管理权限"), 读取不需要。故 apply/remove 前必须过 is_admin()。
"""

import os
import re
import sys
import json
import time
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from win_utils import is_admin, get_silent_startup_kwargs, flush_dns_native, get_port_process_info

NRPT_DISPLAY_PREFIX = "GameArt Toolkit"
NRPT_DISPLAY_NAME = "GameArt Toolkit 域名重定向"
NRPT_COMMENT = "由 GameArt Toolkit 自动托管, 退出程序时会自动完全清理"
NRPT_DNS_PORT = 53
NRPT_NAME_SERVER = "127.0.0.1"
# 共用策略的备份地址: 代理占满 IPv4 53 时改指向 IPv6 回环 (实测两个地址族互不冲突,
# 而 SO_REUSEADDR 在 IPv4 通配被占用时无效 —— 见 port53_status 的说明)
_NRPT_NAME_SERVER_V6 = "::1"

_RULE_CACHE_TTL = 30.0
_PORT_STATUS_CACHE_TTL = 30.0
_PS_TIMEOUT = 15.0
_PS_FAST_TIMEOUT = 5.0
# 删除规则的专用超时。为什么必须比 _PS_TIMEOUT 宽得多 (2026-10-02 实测):
#   一条 NRPT 规则可以携带 **550 个命名空间** (本项目按已启用服务的域名写入),
#   `Get-DnsClientNrptRule` + `Remove-DnsClientNrptRule` 在这种规模下远超 15s。
#   实测后果**很严重**: 超时 → 规则残留 → 那 550 个域名全部指向已退出的本机解析器
#   (`::1:53`), **整机范围解析失败**, 而应用只回一句"清理失败"就结束。
#   ⇒ 清理路径的预算必须按"最坏数据量"给, 不能沿用查询所用的短预算。
_NRPT_REMOVE_TIMEOUT = 60.0

# 域名白名单校验: 仅放行合法主机名, 从根上杜绝构建 PowerShell 脚本时的注入面
_DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+$"
)

_PS_PREAMBLE = (
    "$ErrorActionPreference = 'Stop'\n"
    "try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}\n"
)


def is_valid_domain(domain: str) -> bool:
    """校验域名是否可安全写入 NRPT 命名空间 (严格匹配, 不做任何宽容化处理)"""
    if not domain or not isinstance(domain, str):
        return False
    return bool(_DOMAIN_RE.match(domain))


def build_namespace_entries(domains: List[str]) -> List[str]:
    """
    把加速域名列表转换为 NRPT 命名空间条目

    NRPT 的命名空间语义:
      - "example.com"  -> 精确匹配该名字
      - ".example.com" -> 后缀匹配整个子域树
    两种语义在文档中未明确包含关系, 故两者同时登记, 保证"主域 + 全部子域"都被覆盖,
    避免边界情况下主域自身绕过本地解析器。
    """
    entries: List[str] = []
    seen = set()
    for raw in domains or []:
        dom = str(raw or "").strip().lower().rstrip(".")
        if not is_valid_domain(dom):
            continue
        for entry in (f".{dom}", dom):
            if entry not in seen:
                seen.add(entry)
                entries.append(entry)
    return sorted(entries, key=lambda x: (x.lstrip("."), x.startswith(".")))


def _as_list(value: Any) -> List[str]:
    """PowerShell 单元素数组会被自动解包为字符串, 此处统一归一化为列表"""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def _is_elevation_error(text: str) -> bool:
    """识别 NRPT 写入被权限拦截的报错 (中文/英文两套文案)"""
    markers = (
        "管理权限", "管理员", "无法加载 NRPT", "Access is denied", "access denied",
        "requires elevation", "not have permission", "权限",
    )
    low = (text or "").lower()
    return any(m.lower() in low for m in markers)


class NrptManager:
    """Windows NRPT 策略表规则的全生命周期管理"""

    def __init__(self, display_prefix: str = NRPT_DISPLAY_PREFIX,
                 display_name: str = NRPT_DISPLAY_NAME):
        self.display_prefix = display_prefix
        self.display_name = display_name
        self.last_error = ""
        self._cache: Optional[List[Dict[str, Any]]] = None
        self._cache_ts = 0.0
        self._port_cache: Optional[Dict[str, Any]] = None
        self._port_cache_ts = 0.0

    # ------------------------------------------------------------------ 能力探测

    def is_supported(self) -> bool:
        """DnsClient 模块是否存在 (Windows 8+ 客户端系统自带, 无需子进程探测)"""
        if sys.platform != "win32":
            return False
        windir = os.environ.get("WINDIR", r"C:\Windows")
        module_dir = Path(windir) / "System32" / "WindowsPowerShell" / "v1.0" / "Modules" / "DnsClient"
        return module_dir.exists()

    def port53_status(self, force: bool = False) -> Dict[str, Any]:
        """探测 53 端口可用性并给出**推荐 NameServer 地址**, 不可用时给出占用进程名

        为什么按地址族分别探测: 第三方代理(实测 mihomo)常只占用某一个地址族 ——
          - 只绑 `:::53` 时 IPv4 侧空闲 -> 我们用 127.0.0.1:53 可共存 (实测能收到查询);
          - 占满 `0.0.0.0:53` 时 IPv4 侧任何 127.x 都绑不上 (连 SO_REUSEADDR 也无效),
            但 IPv6 回环 ::1:53 仍可用 -> 改用 ::1 仍可共存。
        这样绝大多数"端口冲突"都能自动化解, 无需改动用户的代理配置。

        带 TTL 缓存: 占用进程查询要走 psutil/netstat 全量连接枚举 (实测约 0.8s), 而本方法
        会被"打开设置页"与"切换 NRPT 开关"这类 UI 路径调用 —— 不缓存就是一次明显的界面卡顿。
        """
        now = time.time()
        if not force and self._port_cache is not None and (now - self._port_cache_ts) < _PORT_STATUS_CACHE_TTL:
            return dict(self._port_cache)

        def _try_bind(host: str) -> bool:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            probe = socket.socket(family, socket.SOCK_DGRAM)
            try:
                if family == socket.AF_INET6:
                    try:
                        probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    except Exception:
                        pass
                probe.bind((host, NRPT_DNS_PORT))
                return True
            except OSError:
                return False
            finally:
                try:
                    probe.close()
                except Exception:
                    pass

        v4_free = _try_bind(NRPT_NAME_SERVER)          # 127.0.0.1
        v6_free = False if v4_free else _try_bind(_NRPT_NAME_SERVER_V6)   # ::1

        if v4_free or v6_free:
            result = {"available": True, "owner": "",
                      "name_server": NRPT_NAME_SERVER if v4_free else _NRPT_NAME_SERVER_V6,
                      "family": "ipv4" if v4_free else "ipv6",
                      "ipv4_available": v4_free, "ipv6_available": v6_free,
                      "note": "" if v4_free else "IPv4 53 被占用, 已改用 IPv6 回环 ::1 共存"}
        else:
            owners: List[str] = []
            try:
                for info in get_port_process_info(NRPT_DNS_PORT):
                    name = str(info.get("name") or "").strip() or "未知进程"
                    if name not in owners:
                        owners.append(name)
            except Exception:
                pass
            result = {"available": False, "owner": ", ".join(owners) or "未知进程",
                      "name_server": "", "family": "", "ipv4_available": False,
                      "ipv6_available": False,
                      "note": "IPv4/IPv6 的 53 端口均被占用"}

        # 本机解析器自己占着 53 时不算冲突 (这正是 NRPT 模式的目标状态)
        if not result["available"]:
            try:
                from dns_server import local_dns_server
                if local_dns_server.is_running() and local_dns_server.port == NRPT_DNS_PORT:
                    result = {"available": True, "owner": "本机 DNS 解析器 (已接管)",
                              "name_server": getattr(local_dns_server, "host", NRPT_NAME_SERVER),
                              "family": "ipv6" if ":" in str(getattr(local_dns_server, "host", "")) else "ipv4",
                              "ipv4_available": False, "ipv6_available": False, "note": ""}
            except Exception:
                pass

        self._port_cache = result
        self._port_cache_ts = now
        return dict(result)

    def capabilities(self) -> Dict[str, Any]:
        """汇总 NRPT 模式的前置条件, 供界面与分派层决策"""
        supported = self.is_supported()
        admin = is_admin() if supported else False
        port = self.port53_status() if supported else {
            "available": False, "owner": "", "name_server": "", "family": "",
            "ipv4_available": False, "ipv6_available": False}

        reasons: List[str] = []
        if not supported:
            reasons.append("当前系统缺少 DnsClient 模块 (需 Windows 8 及以上客户端系统)")
        else:
            if not admin:
                reasons.append("写 NRPT 需要管理员权限, 请点击侧栏【提权】")
            if not port["available"]:
                reasons.append(
                    f"本机 53/UDP 的 IPv4 与 IPv6 均被 {port['owner']} 占用 "
                    f"(NRPT 的目标端口固定为 53, 无法改端口; 可先关闭代理的 DNS 接管)"
                )

        return {
            "supported": supported,
            "admin": admin,
            "port53_available": bool(port["available"]),
            "port53_owner": port["owner"],
            "port53": port,                       # 含推荐 NameServer 与地址族信息
            "name_server": port.get("name_server") or NRPT_NAME_SERVER,
            "ready": supported and admin and bool(port["available"]),
            "reason": "; ".join(reasons),
        }

    # ------------------------------------------------------------------ 进程调用

    def _run_ps(self, script: str, timeout: float = _PS_TIMEOUT) -> Tuple[int, str, str]:
        """执行 PowerShell 脚本, 静默窗口且不继承控制台"""
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", _PS_PREAMBLE + script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout, **get_silent_startup_kwargs(),
            )
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except Exception as e:
            return -1, "", str(e)

    def _invalidate_cache(self):
        self._cache = None
        self._cache_ts = 0.0

    # ------------------------------------------------------------------ 规则读取

    def _list_script(self) -> str:
        return (
            "$own = @(Get-DnsClientNrptRule | Where-Object { $_.DisplayName -like '"
            + self.display_prefix + "*' })\n"
            "if ($own.Count -eq 0) { Write-Output '[]' }\n"
            "else { Write-Output (ConvertTo-Json -InputObject @($own | Select-Object Name,DisplayName,Namespace,NameServers,Comment) -Compress -Depth 4) }\n"
        )

    def list_rules(self, force: bool = False) -> Optional[List[Dict[str, Any]]]:
        """
        枚举本程序托管的 NRPT 规则 (带 TTL 缓存, 避免 GUI 高频状态查询反复起子进程)
        返回 None 表示查询失败 (与"查询成功但无规则"的 [] 严格区分)
        """
        now = time.time()
        if not force and self._cache is not None and (now - self._cache_ts) < _RULE_CACHE_TTL:
            return list(self._cache)

        if not self.is_supported():
            self.last_error = "当前系统不支持 NRPT"
            return None

        rc, out, err = self._run_ps(self._list_script())
        if rc != 0:
            self.last_error = (err or out or "NRPT 规则查询失败").strip()
            return None

        text = (out or "").strip()
        if not text:
            rules: List[Dict[str, Any]] = []
        else:
            try:
                data = json.loads(text)
            except Exception as e:
                self.last_error = f"NRPT 规则解析失败: {e}"
                return None
            if isinstance(data, dict):
                data = [data]
            rules = []
            for item in data if isinstance(data, list) else []:
                if not isinstance(item, dict):
                    continue
                rules.append({
                    "name": str(item.get("Name") or ""),
                    "display_name": str(item.get("DisplayName") or ""),
                    "namespaces": _as_list(item.get("Namespace")),
                    "name_servers": _as_list(item.get("NameServers")),
                    "comment": str(item.get("Comment") or ""),
                })

        self.last_error = ""
        self._cache = rules
        self._cache_ts = now
        return list(rules)

    def list_own_rules(self) -> List[Dict[str, Any]]:
        """枚举本程序专属规则 (查询失败时返回空列表, 不抛异常)"""
        rules = self.list_rules()
        return rules if rules else []

    def is_applied(self) -> bool:
        """是否已存在本程序托管的 NRPT 规则"""
        return len(self.list_own_rules()) > 0

    # ------------------------------------------------------------------ 规则写入

    def _write_namespace_file(self, entries: List[str]) -> Path:
        """命名空间条目落盘为临时文件, 规避超长命令行与转义问题"""
        fd, path = tempfile.mkstemp(prefix="gamt_nrpt_", suffix=".txt")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("\n".join(entries))
        except Exception:
            try:
                os.close(fd)
            except Exception:
                pass
            raise
        return Path(path)

    def apply(self, domains: List[str], name_server: str = NRPT_NAME_SERVER) -> Tuple[bool, str]:
        """
        写入 (覆盖式) 本程序的 NRPT 域名重定向规则

        先删除本程序全部历史规则再新增, 保证域名开关的增减是原子的全集覆盖,
        不会残留已关闭服务的命名空间。
        """
        entries = build_namespace_entries(domains)
        if not entries:
            return True, "无加速域名需写入 NRPT 规则"

        caps = self.capabilities()
        if not caps["supported"]:
            return False, f"NRPT 模式不可用: {caps['reason']}"
        if not caps["admin"]:
            return False, f"NRPT 写入失败: {caps['reason']}"
        if not caps["port53_available"]:
            return False, f"NRPT 写入失败: {caps['reason']}"

        ns_file = None
        try:
            ns_file = self._write_namespace_file(entries)
            script = (
                "$ns = @(Get-Content -LiteralPath '" + str(ns_file) + "' -Encoding UTF8 | Where-Object { $_.Trim() -ne '' })\n"
                "if ($ns.Count -eq 0) { throw '空命名空间列表' }\n"
                "$own = @(Get-DnsClientNrptRule | Where-Object { $_.DisplayName -like '" + self.display_prefix + "*' })\n"
                "foreach ($r in $own) { Remove-DnsClientNrptRule -Name $r.Name }\n"
                "Add-DnsClientNrptRule -Namespace $ns -NameServers '" + name_server + "' "
                "-DisplayName '" + self.display_name + "' -Comment '" + NRPT_COMMENT + "' | Out-Null\n"
                "Write-Output ('GAMT_NRPT_APPLIED=' + $ns.Count)\n"
            )
            rc, out, err = self._run_ps(script)
            if rc != 0 or "GAMT_NRPT_APPLIED=" not in (out or ""):
                detail = (err or out or "未知错误").strip()
                if _is_elevation_error(detail):
                    return False, "NRPT 写入失败: 未检测到管理员权限, 请以管理员身份运行本程序。"
                return False, f"NRPT 写入失败: {detail}"
        except Exception as e:
            return False, f"NRPT 写入异常: {e}"
        finally:
            if ns_file is not None:
                try:
                    ns_file.unlink(missing_ok=True)
                except Exception:
                    pass

        self._invalidate_cache()
        flush_dns_native()
        return True, f"已写入 {len(entries)} 条 NRPT 命名空间规则 (定向本机 127.0.0.1)"

    def remove_all(self, fast: bool = False) -> Tuple[bool, str]:
        """删除本程序托管的全部 NRPT 规则 (绝不触碰他人规则)"""
        if not self.is_supported():
            return True, "当前系统不支持 NRPT, 无需清理"

        # `-Force -Confirm:$false`: 删除**必须非交互**。应用退出路径上不可能有人回答确认提示,
        # 一旦 cmdlet 因确认而等待, 就会撞上超时并把规则留在机器上 (实测事故)。
        def _script() -> str:
            return (
                "$own = @(Get-DnsClientNrptRule | Where-Object { $_.DisplayName -like '"
                + self.display_prefix + "*' })\n"
                "$n = $own.Count\n"
                "foreach ($r in $own) { Remove-DnsClientNrptRule -Name $r.Name -Force"
                " -Confirm:$false }\n"
                "Write-Output ('GAMT_NRPT_REMOVED=' + $n)\n"
            )

        budget = _PS_FAST_TIMEOUT if fast else _NRPT_REMOVE_TIMEOUT
        rc, out, err = self._run_ps(_script(), timeout=budget)
        self._invalidate_cache()

        ok = (rc == 0 and "GAMT_NRPT_REMOVED=" in (out or ""))
        # ★ 复核 + 重试一次 (2026-10-02 实测新增): 只看命令返回码是不够的 ——
        # 实测"命令超时"与"规则真的没了"是两回事, 而**规则残留会让整机解析失败**。
        # 故删除后必须**回读确认**, 未清空则再给一次更宽的机会。
        if not fast:
            # 注意用 list_rules(force=True): `force` 是 list_rules 的形参,
            # list_own_rules() 不接受参数 (第一版写成 list_own_rules(force=True) 会抛
            # TypeError, 反而把"清理失败"变成"清理时崩溃" —— 比原缺陷更糟)。
            left = self.list_rules(force=True) or []
            if left:
                rc2, out2, err2 = self._run_ps(_script(), timeout=_NRPT_REMOVE_TIMEOUT * 2)
                self._invalidate_cache()
                left = self.list_rules(force=True) or []
                if left:
                    return False, (f"NRPT 清理失败: 仍有 {len(left)} 条规则残留 "
                                   f"(残留会把命中域名指向无人监听的解析器, 请以管理员"
                                   f"身份手动执行 Remove-DnsClientNrptRule)。"
                                   f" 详情: {(err2 or err or out2 or out or '')[:200]}")

        if not ok:
            if fast:
                return False, "NRPT 快速清理未完成"
            detail = (err or out or "未知错误").strip()
            if _is_elevation_error(detail):
                return False, "NRPT 清理失败: 未检测到管理员权限, 请以管理员身份运行本程序。"
            return False, f"NRPT 清理失败: {detail}"

        if not fast:
            flush_dns_native()
        return True, "已清理 NRPT 域名重定向规则"

    # ------------------------------------------------------------------ 体检诊断

    def diagnose_and_repair(self, auto_fix: bool = True) -> Dict[str, Any]:
        """NRPT 后端体检 (返回结构与 HostsManager.diagnose_and_repair 保持一致)"""
        issues: List[str] = []
        fixes: List[str] = []
        caps = self.capabilities()

        if not caps["supported"]:
            issues.append(caps["reason"])

        rules = self.list_rules(force=True)
        if rules is None:
            issues.append(f"NRPT 规则查询失败: {self.last_error}")
            rules = []

        if caps["supported"] and not caps["admin"]:
            issues.append(caps["reason"])
        if caps["supported"] and not caps["port53_available"]:
            issues.append(caps["reason"])

        # 残留检测: 规则存在但本机解析器未在 53 端口服务时, 域名会解析失败
        if rules and caps["admin"]:
            from dns_server import local_dns_server
            if not (local_dns_server.is_running() and local_dns_server.port == NRPT_DNS_PORT):
                issues.append("存在 NRPT 规则但本机解析器未监听 53 端口, 加速域名将解析失败")
                if auto_fix:
                    ok, msg = local_dns_server.ensure_bind(NRPT_DNS_PORT)
                    fixes.append(msg if ok else f"解析器拉起失败: {msg}")

        # 孤儿解析器检测: 解析器占着 53 但没有规则, 属于异常残留
        if not rules and caps["supported"]:
            from dns_server import local_dns_server
            if local_dns_server.is_running() and local_dns_server.port == NRPT_DNS_PORT:
                issues.append("本机解析器占用 53 端口但无 NRPT 规则")
                if auto_fix:
                    local_dns_server.stop()
                    local_dns_server.set_port(None)
                    fixes.append("已释放 53 端口并恢复默认监听端口")

        details_lines: List[str] = []
        if issues:
            details_lines.append("【检测到以下问题】:")
            details_lines.extend([f"  • {i}" for i in issues])
        if fixes:
            details_lines.append("【已执行修复】:")
            details_lines.extend([f"  ✓ {f}" for f in fixes])
        if not issues:
            details_lines.append(
                f"NRPT 后端就绪: 已托管 {len(rules)} 条规则, 目标解析器 127.0.0.1:{NRPT_DNS_PORT}"
            )

        return {
            "is_healthy": len(issues) == 0,
            "issues": issues,
            "fixes": fixes,
            "is_writable": bool(caps["admin"]),
            "has_ptk_rules": len(rules) > 0,
            "has_conflicts": bool(rules) and not caps["port53_available"],
            "capabilities": caps,
            "details": "\n".join(details_lines),
        }
