# -*- coding: utf-8 -*-
"""
PixivToolkit - Steam 快速账号切换管理引擎 (健壮词法解析与原子灾备版)
"""

import os
import re
import sys
import time
import shutil
import winreg
import base64
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config_store import load_config, update_config_key
from win_utils import is_process_running

def _escape_vdf_val(val: Any) -> str:
    """对 VDF 字符串中的反斜杠、双引号及特殊换行进行标准转义"""
    s = str(val)
    s = s.replace('\\', '\\\\').replace('"', '\\"')
    s = s.replace('\n', '\\n').replace('\t', '\\t')
    return s

def tokenize_vdf(text: str) -> List[str]:
    """将 VDF 文本拆解为 Token 流，支持双引号与特殊字符转义和注释剔除"""
    tokens = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        # 跳过空白字符
        if c.isspace():
            i += 1
            continue
        # 跳过单行注释 //
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            i += 2
            while i < n and text[i] not in '\r\n':
                i += 1
            continue
        # 结构符号 { }
        if c in '{}':
            tokens.append(c)
            i += 1
            continue
        # 带引号的字符串
        if c == '"':
            i += 1
            chars = []
            while i < n:
                if text[i] == '\\' and i + 1 < n:
                    esc = text[i + 1]
                    if esc == 'n':
                        chars.append('\n')
                    elif esc == 't':
                        chars.append('\t')
                    elif esc == '\\':
                        chars.append('\\')
                    elif esc == '"':
                        chars.append('"')
                    else:
                        chars.append(esc)
                    i += 2
                elif text[i] == '"':
                    break
                else:
                    chars.append(text[i])
                    i += 1
            tokens.append("".join(chars))
            if i < n and text[i] == '"':
                i += 1
            continue
        # 不带引号的连续字面量 (如 1, 0, true)
        start = i
        while i < n and not text[i].isspace() and text[i] not in '{}"':
            i += 1
        tokens.append(text[start:i])
    return tokens

def parse_vdf_structure(tokens: List[str]) -> dict:
    """递归将 Token 流解析为嵌套字典结构"""
    root = {}
    stack = [root]
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == '}':
            if len(stack) > 1:
                stack.pop()
            i += 1
            continue
        if tok == '{':
            i += 1
            continue
        # 键名
        key = tok
        i += 1
        if i >= n:
            break
        val_tok = tokens[i]
        if val_tok == '{':
            # 进入子对象
            child = {}
            if isinstance(stack[-1], dict):
                stack[-1][key] = child
            stack.append(child)
            i += 1
        elif val_tok == '}':
            # 异常闭合
            if isinstance(stack[-1], dict):
                stack[-1][key] = ""
            if len(stack) > 1:
                stack.pop()
            i += 1
        else:
            # 键值对
            if isinstance(stack[-1], dict):
                stack[-1][key] = val_tok
            i += 1
    return root

def serialize_vdf_dict(data: dict, indent: int = 0) -> str:
    """将字典结构序列化为标准 Valve KeyValues VDF 文本格式"""
    lines = []
    tab = "\t" * indent
    for k, v in data.items():
        safe_k = _escape_vdf_val(k)
        if isinstance(v, dict):
            lines.append(f'{tab}"{safe_k}"')
            lines.append(f'{tab}{{')
            lines.append(serialize_vdf_dict(v, indent + 1))
            lines.append(f'{tab}}}')
        else:
            safe_v = _escape_vdf_val(v)
            lines.append(f'{tab}"{safe_k}"\t\t"{safe_v}"')
    return "\n".join(lines)

class SteamManager:
    def __init__(self):
        self.steam_path = self.detect_steam_path()
        self.steam_exe = self.detect_steam_exe()

    def detect_steam_path(self) -> Optional[Path]:
        """多重探测 Steam 安装目录 (支持 64/32 位注册表与多盘符)"""
        # 1. 优先从 HKCU 注册表读取
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam") as key:
                val, _ = winreg.QueryValueEx(key, "SteamPath")
                if val and os.path.exists(val):
                    return Path(val.replace("/", "\\"))
        except Exception:
            pass

        # 2. 从 HKLM 注册表读取 (支持 WOW64 32/64 位重定向视图)
        for hklm_root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for hklm_path in [r"SOFTWARE\WOW6432Node\Valve\Steam", r"SOFTWARE\Valve\Steam"]:
                for access_flag in [winreg.KEY_READ | getattr(winreg, "KEY_WOW64_32KEY", 0), winreg.KEY_READ]:
                    try:
                        with winreg.OpenKey(hklm_root, hklm_path, 0, access_flag) as key:
                            for val_name in ["InstallPath", "SteamPath", "SteamExe"]:
                                try:
                                    val, _ = winreg.QueryValueEx(key, val_name)
                                    if val and os.path.exists(val):
                                        p = Path(val.replace("/", "\\"))
                                        return p.parent if p.is_file() else p
                                except Exception:
                                    pass
                    except Exception:
                        pass

        # 3. 常见盘符与目录扫描
        drives = [f"{d}:" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ"]
        common_subs = [
            r"Program Files (x86)\Steam",
            r"Program Files\Steam",
            r"Steam",
            r"SteamLibrary\Steam",
            r"Games\Steam",
        ]
        for d in drives:
            for sub in common_subs:
                candidate = Path(d) / sub
                if (candidate / "steam.exe").exists():
                    return candidate

        return None

    def detect_steam_exe(self) -> Optional[Path]:
        if self.steam_path:
            exe = self.steam_path / "steam.exe"
            if exe.exists():
                return exe
        return None

    def is_installed(self) -> bool:
        return self.steam_exe is not None and self.steam_exe.exists()

    def is_steam_running(self) -> bool:
        """检查 Steam 是否在运行 (毫秒级)"""
        return is_process_running("steam.exe")

    def close_steam(self, timeout: float = 6.0) -> bool:
        """安全关闭 Steam 进程树与所有 Chromium webhelper 子进程 (全静默无窗)"""
        if not self.is_steam_running():
            return True

        # 1. 尝试优雅退出
        if self.steam_exe:
            try:
                subprocess.run(
                    [str(self.steam_exe), "-shutdown"],
                    cwd=str(self.steam_path), capture_output=True,
                    timeout=3, shell=False, **get_silent_startup_kwargs()
                )
            except Exception:
                pass

        start_time = time.time()
        while self.is_steam_running() and time.time() - start_time < timeout:
            time.sleep(0.4)

        # 2. 超时强制终止整个进程树
        if self.is_steam_running():
            try:
                subprocess.run("taskkill /F /T /IM steam.exe", shell=True, capture_output=True, **get_silent_startup_kwargs())
                subprocess.run("taskkill /F /IM steamwebhelper.exe", shell=True, capture_output=True, **get_silent_startup_kwargs())
                time.sleep(0.4)
            except Exception:
                pass

        return not self.is_steam_running()

    def get_current_login_user(self) -> Optional[str]:
        """获取当前注册表中记录的自动登录用户名"""
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam") as key:
                val, _ = winreg.QueryValueEx(key, "AutoLoginUser")
                return val
        except Exception:
            return None

    def parse_vdf(self, file_path: Path) -> dict:
        """使用 Token 词法解析器精准提取 loginusers.vdf 中的所有账号信息"""
        if not file_path.exists():
            return {}
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            tokens = tokenize_vdf(text)
            parsed = parse_vdf_structure(tokens)

            # 寻找包含 17 位 SteamID64 的根结构或 users 结构
            users = {}
            # 常见结构可能是 parsed["users"] 或直接 parsed
            target_dict = parsed.get("users", parsed) if isinstance(parsed, dict) else {}
            if not isinstance(target_dict, dict):
                target_dict = parsed

            for k, v in target_dict.items():
                if isinstance(v, dict) and (k.isdigit() and len(k) == 17):
                    user_data = {"SteamID64": k}
                    for sub_k, sub_v in v.items():
                        if not isinstance(sub_v, dict):
                            user_data[sub_k] = str(sub_v)
                    users[k] = user_data
            return users
        except Exception as e:
            print(f"[SteamManager] 解析 VDF 失败: {e}")
            return {}

    def get_avatar_data_uri(self, steamid: str) -> Optional[str]:
        """提取本地头像并转为 Base64 Data URI"""
        if not self.steam_path:
            return None
        avatar_dir = self.steam_path / "config" / "avatarcache"
        for ext in [".png", ".jpg"]:
            av_file = avatar_dir / f"{steamid}{ext}"
            if av_file.exists():
                try:
                    with open(av_file, "rb") as f:
                        b64 = base64.b64encode(f.read()).decode("ascii")
                        mime = "image/png" if ext == ".png" else "image/jpeg"
                        return f"data:{mime};base64,{b64}"
                except Exception:
                    pass
        return None

    def get_accounts(self) -> List[Dict]:
        """获取所有已记住的 Steam 账号信息列表"""
        if not self.steam_path:
            return []

        vdf_path = self.steam_path / "config" / "loginusers.vdf"
        raw_users = self.parse_vdf(vdf_path)
        current_active = self.get_current_login_user()

        config = load_config()
        aliases = config.get("steam_account_aliases", {})

        account_list = []
        for steamid, info in raw_users.items():
            acc_name = info.get("AccountName", "")
            persona = info.get("PersonaName", acc_name)
            most_recent = str(info.get("MostRecent", "0")) == "1"
            timestamp = int(info.get("Timestamp", "0"))
            remember = str(info.get("RememberPassword", "1")) == "1"

            # 判断是否是当前激活的账号
            is_active = (acc_name.lower() == (current_active or "").lower()) or (most_recent and not current_active)

            avatar_uri = self.get_avatar_data_uri(steamid)

            account_list.append({
                "steamid": steamid,
                "account_name": acc_name,
                "persona_name": persona,
                "alias": aliases.get(steamid, ""),
                "is_active": is_active,
                "remember_password": remember,
                "timestamp": timestamp,
                "avatar_uri": avatar_uri
            })

        # 按最后登录时间降序排序
        account_list.sort(key=lambda x: x["timestamp"], reverse=True)
        return account_list

    def set_account_alias(self, steamid: str, alias: str):
        """设置账号备注别名"""
        config = load_config()
        aliases = config.get("steam_account_aliases", {})
        aliases[steamid] = alias.strip()
        config["steam_account_aliases"] = aliases
        update_config_key("steam_account_aliases", aliases)

    def switch_account(self, steamid: str, restart_steam: bool = True) -> Tuple[bool, str]:
        """一键免密切换 Steam 账号并安全重启客户端"""
        if not self.steam_path or not self.steam_exe:
            return False, "未检测到 Steam 安装路径，请确认 Steam 是否已安装。"

        vdf_path = self.steam_path / "config" / "loginusers.vdf"
        if not vdf_path.exists():
            return False, "找不到 loginusers.vdf 文件。"

        # 1. 词法解析 VDF 完整数据
        try:
            with open(vdf_path, "r", encoding="utf-8", errors="ignore") as f:
                full_text = f.read()
            tokens = tokenize_vdf(full_text)
            full_data = parse_vdf_structure(tokens)
        except Exception as e:
            return False, f"读取 loginusers.vdf 失败: {e}"

        target_container = full_data.get("users", full_data) if isinstance(full_data, dict) else {}
        if steamid not in target_container or not isinstance(target_container[steamid], dict):
            return False, f"未在 Steam 本地记录中找到 SteamID: {steamid}"

        target_user = target_container[steamid]
        target_acc = target_user.get("AccountName", "")
        if not target_acc:
            return False, "该账号数据缺失 AccountName。"

        # 2. 安全关闭正在运行的 Steam 及其子进程树
        if not self.close_steam(timeout=6.0):
            return False, "无法关闭当前运行的 Steam 进程，请手动关闭后重试。"

        # 循环等待 Steam 进程完全退出，避免异步刷盘覆写注册表
        for _ in range(25):  # 最多等待 2.5 秒
            if not is_process_running("steam.exe"):
                break
            time.sleep(0.1)
        time.sleep(0.1)  # 最终额外等待确保文件句柄释放

        # 3. 修改 Windows 注册表
        try:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "AutoLoginUser", 0, winreg.REG_SZ, target_acc)
                winreg.SetValueEx(key, "RememberPassword", 0, winreg.REG_DWORD, 1)
        except Exception as e:
            return False, f"修改注册表失败: {e}"

        # 4. 修改 VDF 数据并安全写入 (备份 + 临时文件原子替换)
        try:
            # 更新目标账号状态
            for sid, u_info in target_container.items():
                if isinstance(u_info, dict) and sid.isdigit():
                    if sid == steamid:
                        u_info["MostRecent"] = "1"
                        u_info["RememberPassword"] = "1"
                        u_info["WantsOfflineMode"] = "0"
                        u_info["SkipOfflineModeWarning"] = "0"
                    else:
                        u_info["MostRecent"] = "0"

            # 重新序列化
            new_vdf_text = serialize_vdf_dict(full_data)

            # 创建备份副本
            bak_path = vdf_path.with_suffix(".vdf.bak")
            try:
                shutil.copy2(vdf_path, bak_path)
            except Exception:
                pass

            # 临时文件原子替换
            tmp_path = vdf_path.with_suffix(".vdf.tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(new_vdf_text)
                f.flush()
                os.fsync(f.fileno())

            os.replace(tmp_path, vdf_path)
        except Exception as e:
            return False, f"更新 loginusers.vdf 失败: {e}"

        # 5. 重新启动 Steam (带标准工作目录，不使用 shell=True)
        if restart_steam:
            try:
                subprocess.Popen([str(self.steam_exe)], cwd=str(self.steam_path), shell=False)
            except Exception as e:
                return True, f"账号切换成功，但自动拉起 Steam 失败: {e}"

        persona = target_user.get("PersonaName", target_acc)
        return True, f"已成功切换至 Steam 账号 [{persona}]！"

    def launch_steam(self) -> Tuple[bool, str]:
        if not self.steam_exe:
            return False, "未找到 Steam.exe"
        try:
            subprocess.Popen([str(self.steam_exe)], cwd=str(self.steam_path), shell=False)
            return True, "已启动 Steam"
        except Exception as e:
            return False, f"启动 Steam 失败: {e}"
