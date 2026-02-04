"""
VPS Manager - Configuration Module
Loads, saves and provides defaults for all configurable values.
"""

import json
import threading
from pathlib import Path

DATA_DIR = Path(__file__).parent / 'data'
DATA_DIR.mkdir(exist_ok=True)

CONFIG_PATH = DATA_DIR / 'config.json'

_config_lock = threading.Lock()


def get_default_config():
    """Return all default configuration values"""
    return {
        "auth": {
            "username": "admin",
            "password_hash": None,
            "totp_secret": None,
            "session_lifetime_hours": 24,
        },
        "services": ["nginx", "php8.3-fpm", "mariadb", "fail2ban"],
        "thresholds": {
            "disk_warning": 80,
            "disk_critical": 95,
            "memory_warning": 85,
            "swap_warning": 50,
            "ssl_warning_days": 14,
            "ssl_critical_days": 3,
        },
        "monitor_interval": 300,
        "notification_cooldown": 3600,
        "vapid_mailto": "mailto:push@vps.dmmusic.nl",
        "file_browser": {
            "default_path": "/var/www",
            "blocked_paths": ["/proc", "/sys", "/dev"],
        },
        "backup": {
            "log_path": "/var/log/vps-backup.log",
            "backup_dir": "/var/backups/vps/",
            "db_backup_dir": "/var/backups/vps/databases/",
        },
        "ddos_detection": {
            "enabled": True,
            "connection_threshold": 100,
            "syn_threshold": 50,
            "single_ip_threshold": 50,
        },
        "nginx": {
            "error_log": "/var/log/nginx/error.log",
            "access_log": "/var/log/nginx/access.log",
            "sites_enabled": "/etc/nginx/sites-enabled/",
        },
        "phpmyadmin_path": "/phpmyadmin/",
    }


def _deep_merge(base, override):
    """Recursively merge override into base, returning merged dict"""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config():
    """Load config from disk, merged with defaults for any missing keys"""
    defaults = get_default_config()
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, 'r') as f:
                user_config = json.load(f)
            return _deep_merge(defaults, user_config)
        except (json.JSONDecodeError, OSError):
            pass
    return defaults


def save_config(config):
    """Save config to disk with thread safety"""
    with _config_lock:
        CONFIG_PATH.write_text(json.dumps(config, indent=2))
