# config.py
import json
from pathlib import Path

# 配置文件与缓存文件存储路径
CONFIG_DIR = Path.home() / ".ipv6_port_tool"
CONFIG_FILE = CONFIG_DIR / "config.json"
CACHE_FILE = CONFIG_DIR / "last_ipv6_cache"

# 默认配置字典
DEFAULT_CONFIG = {
    "router_ip": "192.168.1.1",
    "username": "root",
    "password": "",
    "check_online": False,
    "send_mail": False,
    "autostart": False,
    "mail_to": "",
    "smtp_host": "smtp.qq.com",
    "smtp_port": 465,
    "smtp_user": "",
    "smtp_pass": "",
    "software_auto_update": True,
    "rows": [],
}

def ensure_dir():
    """确保配置文件夹存在"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

def load_config() -> dict:
    """读取用户配置文件，如果不存在则返回默认配置"""
    ensure_dir()
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            # 补齐缺失的键（防止旧版本配置文件缺少新字段报错）
            for k, v in DEFAULT_CONFIG.items():
                data.setdefault(k, v)
            return data
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)

def save_config(cfg: dict):
    """保存用户配置到本地 JSON 文件"""
    ensure_dir()
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

def load_cached_ipv6() -> dict:
    """读取上次记录的 IPv6 缓存"""
    ensure_dir()
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_cached_ipv6(ips: dict):
    """保存当前的 IPv6 缓存，用于比对 IP 是否发生变化"""
    ensure_dir()
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(ips, f, ensure_ascii=False, indent=2)