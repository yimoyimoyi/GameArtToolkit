# -*- coding: utf-8 -*-
"""
PixivToolkit - 标签化安全 Hosts 管理引擎 (原子替换与只读自愈版)
"""

import os
import re
import sys
import stat
import shutil
from pathlib import Path
from typing import List, Tuple, Set

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ip_pool import SERVICES_LIST, SERVICES_BY_ID
from win_utils import flush_dns_native

HOSTS_PATH = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
HOSTS_BAK_PATH = HOSTS_PATH.with_suffix(".ptk.bak")

BLOCK_START = "# >>>>> PixivToolkit Rules Start >>>>>"
BLOCK_END = "# <<<<< PixivToolkit Rules End <<<<<"

class HostsManager:
    def __init__(self, hosts_file: Path = HOSTS_PATH):
        self.hosts_file = hosts_file

    def is_writable(self) -> bool:
        """检查 hosts 文件是否可写"""
        try:
            if not self.hosts_file.exists():
                return False
            with open(self.hosts_file, "a", encoding="utf-8", errors="ignore") as f:
                pass
            return True
        except Exception:
            return False

    def is_applied(self) -> bool:
        """检查 PixivToolkit 规则是否已注入 hosts"""
        if not self.hosts_file.exists():
            return False
        try:
            with open(self.hosts_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                return BLOCK_START in content and BLOCK_END in content
        except Exception:
            return False

    def remove_rules_from_content(self, text: str) -> str:
        """从 hosts 文本中安全剥离 PixivToolkit 规则块，保持原有排版"""
        pattern = re.compile(rf"{re.escape(BLOCK_START)}.*?{re.escape(BLOCK_END)}\r?\n?", re.DOTALL)
        text = pattern.sub("", text)

        legacy_pattern = re.compile(r"# Pixiv Start.*?# Pixiv End\r?\n?", re.DOTALL)
        text = legacy_pattern.sub("", text)

        # 清理旧版 (参考项目/Steam++) 遗留的 HuggingFace 劫持块与散落条目
        legacy_hf_pattern = re.compile(r"# HuggingFace Start.*?# HuggingFace End\r?\n?", re.DOTALL)
        text = legacy_hf_pattern.sub("", text)
        scatter_pattern = re.compile(r"(?m)^127\.0\.0\.1\s+(?:[\w-]+\.)*huggingface\.co\s*\r?\n?$")
        text = scatter_pattern.sub("", text)

        return text.rstrip() + "\n"

    def _safe_write_hosts(self, content: str):
        """安全可靠写入 hosts 文件，支持 Windows 原生属性自愈与多重容灾写入机制"""
        # 1. 创建前置灾备副本
        if self.hosts_file.exists() and not HOSTS_BAK_PATH.exists():
            try:
                shutil.copy2(self.hosts_file, HOSTS_BAK_PATH)
            except Exception:
                pass

        # 2. 清除只读、系统、隐藏等 Windows 文件属性 (FILE_ATTRIBUTE_NORMAL = 0x80)
        if self.hosts_file.exists():
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(self.hosts_file), 0x80)
            except Exception:
                pass
            try:
                os.chmod(self.hosts_file, stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass

        # 3. 策略 A：直接覆盖写入 (最适配 Windows NTFS DACL 与杀毒软件白名单机制)
        write_success = False
        last_exc = None

        for _ in range(3):
            try:
                with open(self.hosts_file, "w", encoding="utf-8", newline="\r\n") as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())
                write_success = True
                break
            except Exception as e:
                last_exc = e
                import time
                time.sleep(0.06)

        if write_success:
            return

        # 策略 B：若直接写失败，尝试通过临时文件原子替换回退
        tmp_path = self.hosts_file.with_name("hosts.ptk.tmp")
        try:
            if tmp_path.exists():
                try:
                    import ctypes
                    ctypes.windll.kernel32.SetFileAttributesW(str(tmp_path), 0x80)
                    tmp_path.unlink(missing_ok=True)
                except Exception:
                    pass
            with open(tmp_path, "w", encoding="utf-8", newline="\r\n") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.hosts_file)
            write_success = True
        except Exception as e:
            raise last_exc or e
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink(missing_ok=True)
                except Exception:
                    pass

    def apply_rules(self, enabled_services: List[str]) -> Tuple[bool, str]:
        """应用选定服务的加速 Hosts 规则"""
        try:
            content = ""
            if self.hosts_file.exists():
                with open(self.hosts_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

            base_content = self.remove_rules_from_content(content)

            # 收集所有已启用服务的域名 (去重)
            all_domains: Set[str] = set()
            for s_id in enabled_services:
                srv = SERVICES_BY_ID.get(s_id)
                if srv:
                    for d in srv.get("domains", []):
                        all_domains.add(d)

            # 兼容旧版服务组键名 ('pixiv', 'steam', 'github', 'huggingface')
            if "pixiv" in enabled_services:
                for s in SERVICES_LIST:
                    if s["group"] == "acg":
                        all_domains.update(s["domains"])
            if "steam" in enabled_services:
                for s in SERVICES_LIST:
                    if s["group"] == "gaming":
                        all_domains.update(s["domains"])
            if "github" in enabled_services:
                for s in SERVICES_LIST:
                    if s["group"] == "dev":
                        all_domains.update(s["domains"])

            if not all_domains:
                self._safe_write_hosts(base_content)
                self.flush_dns()
                return True, "已清空所有加速 Hosts 规则"

            # 构造全新的注入规则块
            lines = [BLOCK_START, "# 本规则由 PixivToolkit 自动安全托管，退出程序时将自动完全清理"]
            for dom in sorted(all_domains):
                lines.append(f"127.0.0.1 {dom}")
            lines.append(BLOCK_END)
            rule_block = "\r\n".join(lines) + "\r\n"

            new_hosts_content = base_content.rstrip() + "\r\n\r\n" + rule_block
            self._safe_write_hosts(new_hosts_content)

            self.flush_dns()
            return True, f"已成功注入 {len(all_domains)} 条加速域名规则！"
        except PermissionError:
            from win_utils import is_admin
            if not is_admin():
                return False, "修改 Hosts 失败：未检测到管理员权限，请以管理员身份运行本程序。"
            else:
                return False, "修改 Hosts 失败：Hosts 文件被杀毒软件（如火绒/360/Defender）保护拦截，请在安全软件中放行 Hosts 写入。"
        except Exception as e:
            return False, f"修改 Hosts 异常: {e}"

    def remove_rules(self) -> Tuple[bool, str]:
        """安全移除 PixivToolkit 注入的全部规则"""
        if not self.hosts_file.exists():
            return True, "Hosts 文件不存在"

        try:
            with open(self.hosts_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if BLOCK_START not in content and "# Pixiv Start" not in content:
                return True, "Hosts 中无残留规则"

            clean_content = self.remove_rules_from_content(content)
            self._safe_write_hosts(clean_content)

            self.flush_dns()
            return True, "已安全清理 Hosts 加速规则！"
        except PermissionError:
            from win_utils import is_admin
            if not is_admin():
                return False, "清理 Hosts 失败：未检测到管理员权限，请以管理员身份运行。"
            else:
                return False, "清理 Hosts 失败：Hosts 文件被杀毒软件保护拦截，请在安全软件中放行 Hosts 写入。"
        except Exception as e:
            return False, f"清理 Hosts 异常: {e}"

    def fast_remove_rules(self) -> bool:
        """专为 Windows 关机与极速退出设计的无阻塞 Hosts 清理 (<2ms，零子进程/零重试)"""
        if not self.hosts_file.exists():
            return True
        try:
            # 1. 尝试去除只读属性
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(self.hosts_file), 0x80)
            except Exception:
                pass

            # 2. 快速读取内容
            with open(self.hosts_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if BLOCK_START not in content and "# Pixiv Start" not in content:
                return True

            clean_content = self.remove_rules_from_content(content)

            # 3. 内存直接覆写
            with open(self.hosts_file, "w", encoding="utf-8", newline="\r\n") as f:
                f.write(clean_content)
                f.flush()

            # 4. 原生 API 刷新 DNS
            flush_dns_native()
            return True
        except Exception:
            return False

    def diagnose_and_repair(self, auto_fix: bool = True) -> dict:
        """深度自检 Hosts 状态（属性、编码、不对称标签、历史残留）并自动执行修复自愈"""
        issues = []
        fixes = []

        # 1. 检查文件是否存在
        if not self.hosts_file.exists():
            issues.append("Hosts 文件丢失")
            if auto_fix:
                ok, _ = self.restore_default_windows_hosts()
                if ok:
                    fixes.append("已自动重建 Windows 默认 Hosts 文件")

        # 2. 检查只读/隐藏属性
        try:
            import ctypes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(self.hosts_file))
            if attrs != -1 and (attrs & 0x01 or attrs & 0x02):  # READONLY or HIDDEN
                issues.append("Hosts 文件包含只读或隐藏属性限制")
                if auto_fix:
                    ctypes.windll.kernel32.SetFileAttributesW(str(self.hosts_file), 0x80)
                    fixes.append("已成功清除只读与隐藏限制属性")
        except Exception as e:
            issues.append(f"检测文件属性异常: {e}")

        # 3. 检测文件可写权限
        writable = False
        try:
            with open(self.hosts_file, "a", encoding="utf-8") as f:
                pass
            writable = True
        except PermissionError:
            issues.append("Hosts 写入权限不足 (可能未获管理员权限或被安全软件拦截)")
        except Exception as e:
            issues.append(f"写入权限测试异常: {e}")

        # 4. 编码与内容排查
        content = ""
        has_ptk = False
        has_conflicts = False
        try:
            if self.hosts_file.exists():
                raw_bytes = self.hosts_file.read_bytes()
                if raw_bytes.startswith(b'\xef\xbb\xbf'):
                    issues.append("Hosts 文件包含 UTF-8 BOM 头")
                    if auto_fix:
                        raw_bytes = raw_bytes[3:]
                        fixes.append("已剥离多余的 UTF-8 BOM 头")

                content = raw_bytes.decode("utf-8", errors="ignore")

                has_start = BLOCK_START in content
                has_end = BLOCK_END in content
                has_ptk = has_start and has_end

                if has_start != has_end:
                    issues.append("检测到不对称破损的 PixivToolkit 规则标签")
                    if auto_fix:
                        content = self.remove_rules_from_content(content)
                        fixes.append("已修复并剥离损坏的不对称标签")

                # 检测遗留的旧版/第三方工具劫持残留
                for kw in ["pixiv.net", "steamcommunity.com", "github.com", "huggingface.co"]:
                    if f"127.0.0.1 {kw}" in content and not (has_start and has_end):
                        has_conflicts = True
                        issues.append(f"发现外部/旧版残留规则: {kw}")
        except Exception as e:
            issues.append(f"分析文件内容异常: {e}")

        # 5. 执行自动修复写入
        if auto_fix and writable and fixes:
            try:
                clean_c = self.remove_rules_from_content(content)
                self._safe_write_hosts(clean_c)
                self.flush_dns()
            except Exception as e:
                issues.append(f"应用修复写入失败: {e}")

        details_lines = []
        if issues:
            details_lines.append("【检测到以下问题】:")
            details_lines.extend([f"  • {i}" for i in issues])
        if fixes:
            details_lines.append("【已执行自愈修复】:")
            details_lines.extend([f"  ✓ {f}" for f in fixes])
        if not issues:
            details_lines.append("Hosts 文件环境与权限完全正常，无任何冲突或异常残留。")

        return {
            "is_healthy": len(issues) == 0,
            "issues": issues,
            "fixes": fixes,
            "is_writable": writable,
            "has_ptk_rules": has_ptk,
            "has_conflicts": has_conflicts,
            "details": "\n".join(details_lines)
        }

    def restore_default_windows_hosts(self) -> Tuple[bool, str]:
        """一键重置为 Windows 官方原生纯净 Hosts 文件 (带灾备备份)"""
        template = (
            "# Copyright (c) 1993-2009 Microsoft Corp.\r\n"
            "#\r\n"
            "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n"
            "#\r\n"
            "# This file contains the mappings of IP addresses to host names. Each\r\n"
            "# entry should be kept on an individual line. The IP address should\r\n"
            "# be placed in the first column followed by the corresponding host name.\r\n"
            "# The IP address and the host name should be separated by at least one\r\n"
            "# space.\r\n"
            "#\r\n"
            "# Additionally, comments (such as these) may be inserted on individual\r\n"
            "# lines or following the machine name denoted by a '#' symbol.\r\n"
            "#\r\n"
            "# For example:\r\n"
            "#\r\n"
            "#      102.54.94.97     rhino.acme.com          # source server\r\n"
            "#       38.25.63.10     x.acme.com              # x client host\r\n"
            "\r\n"
            "# localhost name resolution is handled within DNS itself.\r\n"
            "#\t127.0.0.1       localhost\r\n"
            "#\t::1             localhost\r\n"
        )
        try:
            # 1. 强制生成时间戳灾备副本
            if self.hosts_file.exists():
                import time
                ts = int(time.time())
                bak_path = self.hosts_file.with_name(f"hosts.ptk_bak_{ts}.bak")
                try:
                    shutil.copy2(self.hosts_file, bak_path)
                except Exception:
                    pass

            # 2. 强清文件属性
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(self.hosts_file), 0x80)
            except Exception:
                pass

            # 3. 写入纯净模板
            with open(self.hosts_file, "w", encoding="utf-8", newline="\r\n") as f:
                f.write(template)
                f.flush()
                os.fsync(f.fileno())

            # 4. 极速刷新 DNS 缓存
            self.flush_dns()
            return True, "已成功恢复 Windows 官方原生纯净 Hosts 文件！"
        except PermissionError:
            from win_utils import is_admin
            if not is_admin():
                return False, "恢复失败：未检测到管理员权限，请以管理员身份运行。"
            return False, "恢复失败：Hosts 被安全软件拦截保护，请在安全软件中放行 Hosts 写入。"
        except Exception as e:
            return False, f"恢复默认 Hosts 异常: {e}"

    def flush_dns(self):
        """极速刷新 Windows DNS 缓存 (<0.1ms)"""
        flush_dns_native()

