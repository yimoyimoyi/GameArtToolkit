# -*- coding: utf-8 -*-
"""
PixivToolkit - 配置持久化存储模块 (原子安全写入与灾备版)
"""

import os
import json
import shutil
import threading
from path_utils import BASE_DIR

CONFIG_FILE = BASE_DIR / "config.json"
CONFIG_BAK = BASE_DIR / "config.json.bak"
_CONFIG_LOCK = threading.RLock()

DEFAULT_CONFIG = {
    # 界面与交互外观
    "theme": "dark",
    "tray_notifications": True,

    # 运行生命周期与托盘行为
    "auto_proxy": True,
    "auto_start": False,
    "start_minimized": True,
    "close_action": "minimize_to_tray",  # "minimize_to_tray" | "quit_directly"

    # Hosts 规则与安全自愈
    "auto_clean_hosts_on_exit": True,
    "auto_heal_on_startup": True,

    # 服务与路由规则
    "enabled_services": ["pixiv", "steam", "github", "huggingface"],
    "steam_account_aliases": {},
    "server_port": 17890,
    "auto_cdn_optimize": True,
    "last_optimal_time": 0,

    # 测速探测专用本地代理 (Clash/v2ray/Sing-box mixed 端口, 仅作真实节点筛选, 不参与 nginx 转发)
    "upstream_proxy": {"enabled": False, "host": "127.0.0.1", "port": 7897}
}

def load_config() -> dict:
    with _CONFIG_LOCK:
        for target_path in [CONFIG_FILE, CONFIG_BAK]:
            if target_path.exists():
                try:
                    with open(target_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, dict):
                            for k, v in DEFAULT_CONFIG.items():
                                if k not in data:
                                    data[k] = v
                                elif isinstance(v, dict) and isinstance(data[k], dict):
                                    # 深度合并：补全缺失的子字段
                                    for sub_k, sub_v in v.items():
                                        if sub_k not in data[k]:
                                            data[k][sub_k] = sub_v
                            return data
                except Exception as e:
                    print(f"[Config] 加载 {target_path.name} 异常: {e}")
                    continue

        # 若均不存在或已损毁，初始化默认配置
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

def save_config(config: dict):
    with _CONFIG_LOCK:
        tmp_file = CONFIG_FILE.with_suffix(".tmp")
        try:
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            # 1. 写入临时文件并强制刷盘
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())

            # 2. 维护备份文件
            if CONFIG_FILE.exists():
                try:
                    shutil.copyfile(CONFIG_FILE, CONFIG_BAK)
                except Exception:
                    pass

            # 3. 原子替换 (Windows 下原子重命名)
            os.replace(tmp_file, CONFIG_FILE)
        except Exception as e:
            if tmp_file.exists():
                try:
                    tmp_file.unlink(missing_ok=True)
                except Exception:
                    pass
            print(f"[Config] 保存配置文件失败: {e}")

def update_config_key(key: str, value):
    with _CONFIG_LOCK:
        config = load_config()
        config[key] = value
        save_config(config)
