#!/usr/bin/env python3
"""
VPS Manager - Web Interface
Flask-based web dashboard for managing a VPS.
Runs locally on the VPS itself (subprocess.run instead of SSH).
"""

import gc
import grp
import os
import pwd
import re
import io
import json
import hmac
import shlex
import shutil
import stat as stat_module
import subprocess
import tempfile
import threading
import time
import logging
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file, after_this_request, Response
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from pywebpush import webpush, WebPushException
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import urllib.error
import urllib.request
import base64

try:
    import pyotp
    import qrcode
    HAS_2FA = True
except ImportError:
    HAS_2FA = False

from config import load_config, save_config

app = Flask(__name__)

# Secret key: env var > persisted file > generate and persist
_secret_key_file = Path(__file__).parent / 'data' / '.secret_key'
_env_secret = os.environ.get('VPS_MANAGER_SECRET')
if _env_secret:
    app.secret_key = _env_secret
elif _secret_key_file.exists():
    app.secret_key = _secret_key_file.read_bytes()
else:
    _secret_key_file.parent.mkdir(exist_ok=True)
    _generated = os.urandom(32)
    _secret_key_file.write_bytes(_generated)
    os.chmod(_secret_key_file, 0o600)
    app.secret_key = _generated

app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB upload limit


@app.template_filter('country_flag')
def country_flag_filter(country_code):
    """Convert 2-letter country code to emoji flag"""
    if not country_code or len(country_code) != 2:
        return ''
    cc = country_code.upper()
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
csrf = CSRFProtect(app)

# Load configuration
CONFIG = load_config()
app.permanent_session_lifetime = timedelta(hours=CONFIG['auth'].get('session_lifetime_hours', 24))

# Auth configuration - env vars take precedence, then config, then defaults
USERNAME = os.environ.get('VPS_MANAGER_USER') or CONFIG['auth'].get('username') or 'admin'
_env_pass = os.environ.get('VPS_MANAGER_PASS', '')
if CONFIG['auth'].get('password_hash'):
    PASSWORD_HASH = CONFIG['auth']['password_hash']
elif _env_pass:
    PASSWORD_HASH = generate_password_hash(_env_pass)
else:
    import secrets as _secrets
    _generated_pass = _secrets.token_urlsafe(16)
    PASSWORD_HASH = generate_password_hash(_generated_pass)
    _pw_file = Path(__file__).parent / 'data' / '.generated_password'
    try:
        _pw_file.write_text(_generated_pass)
        os.chmod(_pw_file, 0o600)
    except OSError:
        pass
    logging.warning(
        'WARNING: No password configured. Generated temporary password saved to data/.generated_password  '
        'Set VPS_MANAGER_PASS env var or change password in settings.'
    )

# ---------------------------------------------------------------------------
# Push Notification Setup
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).parent / 'data'
DATA_DIR.mkdir(exist_ok=True)

VAPID_PRIVATE_KEY_PATH = DATA_DIR / 'vapid_private.pem'
VAPID_PUBLIC_KEY_PATH = DATA_DIR / 'vapid_public.txt'
SUBSCRIPTIONS_PATH = DATA_DIR / 'subscriptions.json'
NOTIFICATION_LOG_PATH = DATA_DIR / 'notification_log.json'
NOTIFICATION_HISTORY_PATH = DATA_DIR / 'notification_history.json'

MONITOR_INTERVAL = CONFIG.get('monitor_interval', 300)
METRICS_PATH = DATA_DIR / 'metrics.json'
_SEVERITY_ORDER = {'error': 0, 'warning': 1, 'info': 2}


# ---------------------------------------------------------------------------
# Atomic JSON writes (prevents corruption on crash/power loss)
# ---------------------------------------------------------------------------

def _atomic_write_json(path, data):
    """Write JSON to file atomically via temp file + os.replace()"""
    path = Path(path)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix='.tmp')
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f)
        os.replace(tmp_path, str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Terminal: Allowed commands (allowlist approach)
# ---------------------------------------------------------------------------

TERMINAL_ALLOWED_COMMANDS = {
    # File system
    'ls', 'cat', 'head', 'tail', 'less', 'more', 'wc', 'file', 'stat',
    'find', 'locate', 'du', 'df', 'tree', 'readlink', 'realpath', 'basename',
    'dirname', 'pwd', 'cd', 'touch',
    # Text processing
    'grep', 'egrep', 'fgrep', 'sed', 'awk', 'sort', 'uniq', 'cut', 'tr',
    'diff', 'comm', 'tee', 'xargs',
    # System info
    'uname', 'hostname', 'uptime', 'whoami', 'id', 'w', 'who', 'last',
    'free', 'vmstat', 'iostat', 'top', 'htop', 'ps', 'pgrep', 'lscpu',
    'lsblk', 'mount', 'lsof',
    # Networking
    'ping', 'traceroute', 'dig', 'nslookup', 'host', 'curl', 'wget',
    'ss', 'netstat', 'ip', 'ifconfig', 'mtr',
    # Package management
    'apt', 'apt-get', 'apt-cache', 'dpkg',
    # Service management
    'systemctl', 'journalctl', 'service',
    # Web server
    'nginx', 'caddy', 'php', 'php8.3-fpm',
    # PM2
    'pm2',
    # Certificates
    'certbot',
    # Firewall
    'ufw', 'fail2ban-client',
    # Git
    'git',
    # Database
    'mysql', 'mysqldump', 'mariadb',
    # Misc tools
    'date', 'cal', 'echo', 'printf', 'true', 'false', 'test',
    'tar', 'gzip', 'gunzip', 'zip', 'unzip', 'zcat',
    'md5sum', 'sha256sum', 'openssl',
    'crontab',
}

# Paths that must never be configured as allowed_paths for the file browser
FORBIDDEN_ALLOWED_PATHS = {
    '/', '/etc', '/root', '/proc', '/sys', '/dev', '/boot',
    '/usr', '/bin', '/sbin', '/lib', '/lib64',
}

# Allowed path prefixes for web server config operations
CADDY_ALLOWED_PREFIXES = ('/etc/caddy/',)
CADDY_ALLOWED_LOG_PREFIXES = ('/var/log/caddy/',)
NGINX_ALLOWED_LOG_PREFIXES = ('/var/log/nginx/',)


def _is_caddy_path_safe(path):
    """Validate that a path is within allowed Caddy directories"""
    try:
        resolved = os.path.realpath(path)
    except OSError:
        resolved = path
    return any(resolved.startswith(prefix) for prefix in CADDY_ALLOWED_PREFIXES)


def _is_log_path_safe(path, web_server='nginx'):
    """Validate that a log path is within allowed directories"""
    try:
        resolved = os.path.realpath(path)
    except OSError:
        resolved = path
    prefixes = CADDY_ALLOWED_LOG_PREFIXES if web_server == 'caddy' else NGINX_ALLOWED_LOG_PREFIXES
    return any(resolved.startswith(prefix) for prefix in prefixes)


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------

AUDIT_LOG_PATH = DATA_DIR / 'audit_log.json'
AUDIT_MAX_ENTRIES = 1000
_audit_lock = threading.Lock()


def log_audit(action, details=None):
    """Log an action to the audit trail"""
    entry = {
        'timestamp': datetime.now().isoformat(),
        'user': session.get('username', 'system') if request else 'system',
        'ip': request.remote_addr if request else '-',
        'action': action,
        'details': details or {},
    }
    with _audit_lock:
        try:
            log = json.loads(AUDIT_LOG_PATH.read_text()) if AUDIT_LOG_PATH.exists() else []
        except (json.JSONDecodeError, OSError):
            log = []
        log.append(entry)
        if len(log) > AUDIT_MAX_ENTRIES:
            log = log[-AUDIT_MAX_ENTRIES:]
        _atomic_write_json(AUDIT_LOG_PATH, log)

# ---------------------------------------------------------------------------
# TTL Cache for expensive system queries
# ---------------------------------------------------------------------------
_cache_store = {}
_cache_lock = threading.Lock()
_config_runtime_lock = threading.Lock()


def _ttl_cache(seconds):
    """Simple TTL cache decorator for expensive functions"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = func.__name__
            now = time.time()
            with _cache_lock:
                if key in _cache_store:
                    result, ts = _cache_store[key]
                    if now - ts < seconds:
                        return result
            result = func(*args, **kwargs)
            with _cache_lock:
                _cache_store[key] = (result, now)
            return result
        return wrapper
    return decorator


def _invalidate_cache(*func_names):
    """Invalidate cached results for given function names"""
    with _cache_lock:
        for name in func_names:
            _cache_store.pop(name, None)


_metrics_lock = threading.Lock()
_prev_net = {'rx': None, 'tx': None, 'ts': None}

logger = logging.getLogger('vps-manager')


def _generate_vapid_keys():
    """Generate VAPID key pair and save to disk"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    # Save private key PEM
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    VAPID_PRIVATE_KEY_PATH.write_bytes(pem)
    # Extract raw public key bytes (uncompressed point, skip first byte 0x04)
    pub_numbers = private_key.public_key().public_numbers()
    x = pub_numbers.x.to_bytes(32, 'big')
    y = pub_numbers.y.to_bytes(32, 'big')
    raw_pub = b'\x04' + x + y
    pub_b64 = base64.urlsafe_b64encode(raw_pub).rstrip(b'=').decode()
    VAPID_PUBLIC_KEY_PATH.write_text(pub_b64)
    return pub_b64


def _get_vapid_keys():
    """Load or generate VAPID keys. Returns (public_key_b64, private_key_path)"""
    if not VAPID_PRIVATE_KEY_PATH.exists() or not VAPID_PUBLIC_KEY_PATH.exists():
        _generate_vapid_keys()
    public_key = VAPID_PUBLIC_KEY_PATH.read_text().strip()
    return public_key, str(VAPID_PRIVATE_KEY_PATH)


def _load_subscriptions():
    """Load subscriptions from JSON file"""
    if SUBSCRIPTIONS_PATH.exists():
        try:
            return json.loads(SUBSCRIPTIONS_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return []


def _save_subscriptions(subs):
    """Save subscriptions to JSON file"""
    _atomic_write_json(SUBSCRIPTIONS_PATH, subs)


def _load_notification_log():
    """Load notification cooldown log"""
    if NOTIFICATION_LOG_PATH.exists():
        try:
            return json.loads(NOTIFICATION_LOG_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_notification_log(log):
    """Save notification cooldown log"""
    _atomic_write_json(NOTIFICATION_LOG_PATH, log)


def _load_notification_history():
    """Load notification history"""
    if NOTIFICATION_HISTORY_PATH.exists():
        try:
            return json.loads(NOTIFICATION_HISTORY_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return []


def _save_notification_history(history):
    """Save notification history (max 100 entries)"""
    _atomic_write_json(NOTIFICATION_HISTORY_PATH, history[-100:])


def _add_notification_history(title, body, category):
    """Add an entry to notification history, deduplicating active alerts.

    If an unread entry with the same category and body already exists,
    update its timestamp instead of creating a duplicate.
    """
    history = _load_notification_history()

    # Check for existing unread entry with same category + body
    for item in history:
        if not item.get('read') and item.get('category') == category and item.get('body') == body:
            item['timestamp'] = datetime.now().isoformat()
            item['count'] = item.get('count', 1) + 1
            _save_notification_history(history)
            return

    history.append({
        'timestamp': datetime.now().isoformat(),
        'title': title,
        'body': body,
        'category': category,
        'read': False,
        'count': 1,
    })
    _save_notification_history(history)


def _send_push(subscription_info, payload, private_key_pem):
    """Send a push notification to a single subscription.
    Returns: True=sent, False=expired (remove sub), None=transient error (keep sub)
    """
    try:
        webpush(
            subscription_info=subscription_info,
            data=json.dumps(payload),
            vapid_private_key=private_key_pem,
            vapid_claims={"sub": CONFIG.get('vapid_mailto', 'mailto:admin@localhost')},
        )
        return True
    except WebPushException as e:
        if e.response and e.response.status_code in (404, 410):
            return False  # Subscription expired, should be removed
        logger.warning(f"Push failed: {e}")
        return None  # Transient error, keep subscription


def _classify_alert(alert):
    """Classify an alert into a notification category"""
    msg = alert.get('message', '').lower()
    severity = alert.get('severity', '')
    key = alert.get('key', '')

    if key == 'app_update_available':
        return 'app_update'
    if 'ddos' in msg or 'syn flood' in msg or 'connections from single' in msg:
        return 'ddos'
    if 'backup' in msg:
        return 'backup'
    if severity == 'error':
        return 'critical'
    if 'fail2ban' in msg or 'ssh' in msg or 'banned' in msg:
        return 'security'
    if 'update' in msg:
        return 'updates'
    if severity == 'warning':
        return 'warnings'
    return 'warnings'


def _load_metrics():
    """Load metrics from JSON file"""
    if METRICS_PATH.exists():
        try:
            return json.loads(METRICS_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return []


def _save_metrics(metrics):
    """Save metrics to JSON file, pruning entries older than 24h"""
    cutoff = time.time() - 86400
    metrics = [m for m in metrics if m.get('ts', 0) > cutoff]
    # Max 288 entries (24h * 60min / 5min)
    metrics = metrics[-288:]
    _atomic_write_json(METRICS_PATH, metrics)


def _get_net_interface():
    """Detect primary network interface from /proc/net/dev"""
    try:
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()
        for line in lines[2:]:
            parts = line.split(':')
            if len(parts) >= 2:
                iface = parts[0].strip()
                if iface in ('eth0', 'ens6', 'ens3', 'enp0s3', 'eno1'):
                    return iface
        # Fallback: first non-lo interface
        for line in lines[2:]:
            parts = line.split(':')
            if len(parts) >= 2:
                iface = parts[0].strip()
                if iface != 'lo':
                    return iface
    except OSError:
        pass
    return None


def _read_net_bytes(iface):
    """Read RX/TX bytes for a network interface from /proc/net/dev"""
    try:
        with open('/proc/net/dev', 'r') as f:
            for line in f:
                if iface + ':' in line:
                    parts = line.split(':')[1].split()
                    rx = int(parts[0])
                    tx = int(parts[8])
                    return rx, tx
    except (OSError, IndexError, ValueError):
        pass
    return None, None


def collect_metrics():
    """Collect a single metrics data point"""
    global _prev_net
    now = time.time()
    point = {'ts': int(now)}

    # CPU load (1 min avg)
    try:
        with open('/proc/loadavg', 'r') as f:
            point['cpu'] = float(f.read().split()[0])
    except (OSError, ValueError, IndexError):
        point['cpu'] = 0

    # Memory and Swap from free -b
    result = run_cmd("free -b", timeout=5)
    if result.returncode == 0:
        for line in result.stdout.split('\n'):
            parts = line.split()
            if parts and parts[0] == 'Mem:' and len(parts) >= 3:
                try:
                    total = int(parts[1])
                    used = int(parts[2])
                    point['mem'] = round(used / total * 100, 1) if total else 0
                except (ValueError, ZeroDivisionError):
                    point['mem'] = 0
            elif parts and parts[0] == 'Swap:' and len(parts) >= 3:
                try:
                    total = int(parts[1])
                    used = int(parts[2])
                    point['swap'] = round(used / total * 100, 1) if total else 0
                except (ValueError, ZeroDivisionError):
                    point['swap'] = 0
    point.setdefault('mem', 0)
    point.setdefault('swap', 0)

    # Disk usage
    result = run_cmd("df / | tail -1", timeout=5)
    if result.returncode == 0:
        parts = result.stdout.split()
        if len(parts) >= 5:
            try:
                point['disk'] = int(parts[4].rstrip('%'))
            except ValueError:
                point['disk'] = 0
        else:
            point['disk'] = 0
    else:
        point['disk'] = 0

    # Network I/O
    iface = _get_net_interface()
    if iface:
        rx, tx = _read_net_bytes(iface)
        if rx is not None and _prev_net['rx'] is not None and _prev_net['ts'] is not None:
            elapsed = now - _prev_net['ts']
            if elapsed > 0:
                point['net_rx'] = int((rx - _prev_net['rx']) / elapsed)
                point['net_tx'] = int((tx - _prev_net['tx']) / elapsed)
            else:
                point['net_rx'] = 0
                point['net_tx'] = 0
        else:
            point['net_rx'] = 0
            point['net_tx'] = 0
        _prev_net = {'rx': rx, 'tx': tx, 'ts': now}
    else:
        point['net_rx'] = 0
        point['net_tx'] = 0

    # Save
    with _metrics_lock:
        metrics = _load_metrics()
        metrics.append(point)
        _save_metrics(metrics)

    return point


def _monitor_loop():
    """Background thread: check alerts and send push notifications"""
    # Wait for app to fully start
    time.sleep(30)
    logger.info("Push notification monitor started")

    while True:
        cycle_start = time.time()
        try:
            # Collect metrics every cycle (independent of subscriptions)
            try:
                collect_metrics()
            except Exception as e:
                logger.warning(f"Metrics collection error: {e}")

            # Check uptime for all sites and save history
            try:
                check_uptime_all()
            except Exception as e:
                logger.warning(f"Uptime check error: {e}")

            subs = _load_subscriptions()
            if not subs:
                time.sleep(MONITOR_INTERVAL)
                continue

            # Gather current state - free intermediate data after building alerts
            data = get_server_overview()
            services = get_services_status()
            pm2 = get_pm2_processes()
            ssl = get_ssl_info()
            alerts = get_dashboard_alerts(data, services, pm2, ssl)
            del data, services, pm2, ssl

            # Add DDoS alerts
            alerts.extend(check_ddos_indicators())

            # Add backup alerts
            alerts.extend(check_backup_alerts())

            # Add app update alert
            alerts.extend(check_app_update_alert())

            _, private_key_pem = _get_vapid_keys()
            notif_log = _load_notification_log()
            now = time.time()
            log_changed = False

            # Build set of current alert keys so we can detect resolved alerts
            current_alert_keys = set()

            if alerts:
                for alert in alerts:
                    category = _classify_alert(alert)
                    alert_key = f"{category}:{alert.get('key', alert['message'][:80])}"
                    current_alert_keys.add(alert_key)

                    log_entry = notif_log.get(alert_key)

                    # State-based dedup: skip if already notified with the same message
                    # Only re-send if the message content changed (e.g. "2 updates" -> "5 updates")
                    if isinstance(log_entry, dict):
                        if log_entry.get('message') == alert['message']:
                            continue
                        # Time-based cooldown: don't re-notify too frequently even if message changed
                        cooldown = CONFIG.get('notification_cooldown', 3600)
                        if now - log_entry.get('ts', 0) < cooldown:
                            continue
                    elif isinstance(log_entry, (int, float)):
                        # Legacy cooldown format: migrate to new format, skip this cycle
                        notif_log[alert_key] = {'ts': log_entry, 'message': alert['message']}
                        log_changed = True
                        continue

                    payload = {
                        'title': 'VPS Manager',
                        'body': alert['message'],
                        'tag': category,
                        'url': alert.get('link') or '/',
                    }

                    # Send to matching subscribers
                    expired = []
                    sent_count = 0
                    for i, sub in enumerate(subs):
                        prefs = sub.get('preferences', {})
                        if not prefs.get(category, category != 'updates'):
                            continue

                        sub_info = {
                            'endpoint': sub['endpoint'],
                            'keys': sub['keys'],
                        }
                        result = _send_push(sub_info, payload, private_key_pem)
                        if result is False:
                            expired.append(i)
                        elif result is True:
                            sent_count += 1

                    # Remove expired subscriptions
                    if expired:
                        subs = [s for i, s in enumerate(subs) if i not in expired]
                        _save_subscriptions(subs)

                    if sent_count > 0:
                        notif_log[alert_key] = {'ts': now, 'message': alert['message']}
                        log_changed = True
                        logger.info(f"Push sent: {alert['message']} → {sent_count} subscriber(s)")

                        # Save to notification history
                        _add_notification_history(
                            payload['title'],
                            payload['body'],
                            category,
                        )
                    else:
                        logger.warning(f"Push skipped (no matching subscribers): {alert['message']} [category={category}]")

            # Remove log entries for alerts that have resolved, so they
            # trigger a new notification if they come back later
            resolved_keys = [k for k in notif_log if k not in current_alert_keys]
            for k in resolved_keys:
                del notif_log[k]
                log_changed = True

            # Clean entries older than 7 days as a safety net
            cleaned = {}
            for k, v in notif_log.items():
                ts = v.get('ts', 0) if isinstance(v, dict) else v
                if now - ts < 604800:
                    cleaned[k] = v
            if len(cleaned) != len(notif_log) or log_changed:
                _save_notification_log(cleaned)

        except Exception:
            logger.warning("Monitor error", exc_info=True)

        gc.collect()
        elapsed = time.time() - cycle_start
        remaining = max(10, MONITOR_INTERVAL - elapsed)
        time.sleep(remaining)

# Cached server info (fetched once at startup)
_server_ip = None
_server_hostname = None


def get_server_ip():
    """Get the public IP of this server (cached)"""
    global _server_ip
    if _server_ip is None:
        result = subprocess.run(
            "hostname -I | awk '{print $1}'",
            shell=True, capture_output=True, text=True, timeout=5
        )
        _server_ip = result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else '?'
    return _server_ip


def get_server_hostname():
    """Get hostname (cached)"""
    global _server_hostname
    if _server_hostname is None:
        result = subprocess.run(
            "hostname", shell=True, capture_output=True, text=True, timeout=5
        )
        _server_hostname = result.stdout.strip() if result.returncode == 0 else '?'
    return _server_hostname


def get_server_uptime_short():
    """Get uptime as formatted string"""
    try:
        with open('/proc/uptime', 'r') as f:
            seconds = float(f.read().split()[0])
        return format_server_uptime(seconds)
    except Exception:
        return '?'


VERSION_FILE = Path(__file__).parent / 'VERSION'

def _resolve_app_dir():
    """Resolve APP_DIR: find the directory containing .git"""
    if os.environ.get('VPS_MANAGER_DIR'):
        return os.environ['VPS_MANAGER_DIR']
    # Check parent (flat deployment: app.py in root with .git)
    app_parent = Path(__file__).parent.resolve()
    if (app_parent / '.git').is_dir():
        return str(app_parent)
    # Check parent.parent (repo structure: web/app.py with .git in root)
    repo_root = app_parent.parent.resolve()
    if (repo_root / '.git').is_dir():
        return str(repo_root)
    # Fallback to parent
    return str(app_parent)

APP_DIR = _resolve_app_dir()


def _get_current_version():
    """Read current version from VERSION file"""
    try:
        return VERSION_FILE.read_text().strip()
    except (OSError, FileNotFoundError):
        return '0.0.0'


@_ttl_cache(3600)
def check_app_update_alert():
    """Check GitHub for a new VPS Manager release and return an alert if available"""
    import urllib.request

    current = _get_current_version()
    url = 'https://api.github.com/repos/martijnrenkema/vps-manager/releases/latest'
    req = urllib.request.Request(url, headers={
        'User-Agent': 'VPS-Manager/' + current,
        'Accept': 'application/vnd.github.v3+json',
    })

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        logger.debug('GitHub API check failed', exc_info=True)
        return []

    latest = data.get('tag_name', '').lstrip('v')
    if latest and latest != current:
        return [{
            'severity': 'info',
            'message': f"VPS Manager update available: v{current} → v{latest}",
            'link': '/updates',
            'key': 'app_update_available',
        }]
    return []


@app.context_processor
def inject_global_info():
    return {
        'server_ip': get_server_ip(),
        'global_hostname': get_server_hostname(),
        'global_uptime': get_server_uptime_short(),
        'app_version': _get_current_version(),
        'web_server': get_web_server(),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_cmd(cmd, timeout=30):
    """Run a shell command locally on the VPS (only for hardcoded commands)"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result
    except subprocess.TimeoutExpired:
        class Timeout:
            stdout = ''
            stderr = 'Command timed out'
            returncode = 1
        return Timeout()


def run_cmd_safe(args, timeout=30):
    """Run a command with argument list (no shell injection possible)"""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        return result
    except subprocess.TimeoutExpired:
        class Timeout:
            stdout = ''
            stderr = 'Command timed out'
            returncode = 1
        return Timeout()


def is_safe_name(name):
    """Validate that a name only contains safe characters (alphanumeric, dot, dash, underscore)"""
    return bool(re.match(r'^[a-zA-Z0-9._-]+$', name))


# ---------------------------------------------------------------------------
# Web server abstraction (Nginx / Caddy)
# ---------------------------------------------------------------------------

def get_web_server():
    """Return current web server type: 'nginx' or 'caddy'"""
    return CONFIG.get('web_server', 'nginx')


def detect_web_server():
    """Auto-detect installed web server"""
    nginx = run_cmd_safe(['which', 'nginx'], timeout=5)
    caddy = run_cmd_safe(['which', 'caddy'], timeout=5)
    has_nginx = nginx.returncode == 0
    has_caddy = caddy.returncode == 0
    if has_caddy and not has_nginx:
        return 'caddy'
    if has_nginx and not has_caddy:
        return 'nginx'
    # Both or neither: return configured value
    return CONFIG.get('web_server', 'nginx')


def get_sites():
    """Dispatcher: get sites from active web server"""
    if get_web_server() == 'caddy':
        return get_caddy_sites()
    return get_nginx_sites()


def get_web_logs():
    """Dispatcher: get web server logs"""
    if get_web_server() == 'caddy':
        return get_caddy_logs()
    return get_nginx_logs()


def get_ssl_info():
    """Dispatcher: get SSL certificate info"""
    if get_web_server() == 'caddy':
        return get_caddy_certificates()
    return get_ssl_certificates()


def validate_web_config():
    """Dispatcher: validate web server config"""
    if get_web_server() == 'caddy':
        return validate_caddy()
    return validate_nginx()


# Login rate limiting: max 5 attempts per IP per 5 minutes
_login_attempts = {}  # {ip: [timestamp, ...]}
_login_attempts_lock = threading.Lock()
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW = 300  # seconds
_LOGIN_MAX_IPS = 1000  # max tracked IPs to prevent memory growth
_login_last_cleanup = 0


def _cleanup_login_attempts():
    """Remove all expired entries and enforce max IP limit"""
    global _login_last_cleanup
    now = time.time()
    # Only run full cleanup every 60 seconds
    if now - _login_last_cleanup < 60:
        return
    _login_last_cleanup = now
    expired = [ip for ip, attempts in _login_attempts.items()
               if not any(t > now - _LOGIN_WINDOW for t in attempts)]
    for ip in expired:
        del _login_attempts[ip]
    # If still too many IPs, drop the oldest entries
    if len(_login_attempts) > _LOGIN_MAX_IPS:
        sorted_ips = sorted(_login_attempts.items(), key=lambda x: max(x[1]) if x[1] else 0)
        for ip, _ in sorted_ips[:len(_login_attempts) - _LOGIN_MAX_IPS]:
            del _login_attempts[ip]


def _is_rate_limited(ip):
    """Check if an IP has exceeded login attempt limits"""
    with _login_attempts_lock:
        now = time.time()
        attempts = _login_attempts.get(ip, [])
        # Remove expired attempts for this IP
        attempts = [t for t in attempts if now - t < _LOGIN_WINDOW]
        _login_attempts[ip] = attempts
        _cleanup_login_attempts()
        return len(attempts) >= _LOGIN_MAX_ATTEMPTS


def _record_attempt(ip):
    """Record a failed login attempt"""
    with _login_attempts_lock:
        _login_attempts.setdefault(ip, []).append(time.time())


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    show_2fa = False
    if request.method == 'POST':
        client_ip = request.remote_addr

        # Rate limiting check
        if _is_rate_limited(client_ip):
            flash('Too many login attempts. Try again later.', 'danger')
            return render_template('login.html', show_2fa=False)

        username = request.form.get('username', '')
        password = request.form.get('password', '')
        totp_code = request.form.get('totp_code', '').strip()

        # If we're in 2FA step, credentials are stored in session
        if session.get('2fa_pending'):
            username = session.get('2fa_username', '')
            totp_secret = CONFIG['auth'].get('totp_secret')
            if totp_secret and HAS_2FA and totp_code:
                totp = pyotp.TOTP(totp_secret)
                if totp.verify(totp_code, valid_window=1):
                    session.pop('2fa_pending', None)
                    session.pop('2fa_username', None)
                    session.permanent = True
                    session['logged_in'] = True
                    session['username'] = username
                    log_audit('login', {'method': '2fa'})
                    return redirect(url_for('dashboard'))
                else:
                    _record_attempt(client_ip)
                    flash('Invalid 2FA code', 'danger')
                    return render_template('login.html', show_2fa=True)
            _record_attempt(client_ip)
            flash('Invalid 2FA code', 'danger')
            return render_template('login.html', show_2fa=True)

        if username == USERNAME and check_password_hash(PASSWORD_HASH, password):
            # Check if 2FA is enabled
            totp_secret = CONFIG['auth'].get('totp_secret')
            if totp_secret and HAS_2FA:
                # Store credentials in session and show 2FA form
                session['2fa_pending'] = True
                session['2fa_username'] = username
                return render_template('login.html', show_2fa=True)

            session.permanent = True
            session['logged_in'] = True
            session['username'] = username
            log_audit('login', {'method': 'password'})
            return redirect(url_for('dashboard'))
        _record_attempt(client_ip)
        log_audit('login_failed', {'username': username})
        flash('Invalid username or password', 'danger')
    return render_template('login.html', show_2fa=show_2fa)


@app.route('/logout')
def logout():
    log_audit('logout')
    session.clear()
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# Data gathering functions
# ---------------------------------------------------------------------------

def format_server_uptime(seconds):
    """Format uptime seconds to '5d 03:24:15' or '03:24:15'"""
    try:
        total = int(float(seconds))
        days = total // 86400
        remainder = total % 86400
        hours = remainder // 3600
        minutes = (remainder % 3600) // 60
        secs = remainder % 60
        if days > 0:
            return f"{days}d {hours:02d}:{minutes:02d}:{secs:02d}"
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    except (ValueError, TypeError):
        return "?"


@_ttl_cache(30)
def get_server_overview():
    """Gather server overview data"""
    cmd = (
        "hostname && echo '---SEP---' && "
        "cat /proc/uptime && echo '---SEP---' && "
        "cat /proc/cpuinfo | grep 'model name' | head -1 && echo '---SEP---' && "
        "nproc && echo '---SEP---' && "
        "free -b | grep Mem && echo '---SEP---' && "
        "free -b | grep Swap && echo '---SEP---' && "
        "df -h / | tail -1 && echo '---SEP---' && "
        "cat /etc/os-release | grep PRETTY_NAME && echo '---SEP---' && "
        "cat /proc/loadavg"
    )
    result = run_cmd(cmd)
    if result.returncode != 0:
        return None

    parts = result.stdout.split('---SEP---')
    if len(parts) < 9:
        return None

    hostname = parts[0].strip()
    uptime_raw = parts[1].strip()
    cpu_model = parts[2].strip().replace('model name\t: ', '').replace('model name  : ', '')
    cpu_cores = parts[3].strip()
    mem_line = parts[4].strip()
    swap_line = parts[5].strip()
    disk_line = parts[6].strip()
    os_info = parts[7].strip().replace('PRETTY_NAME=', '').strip('"')
    loadavg = parts[8].strip().split()

    # Parse uptime from /proc/uptime (first value = seconds since boot)
    uptime_seconds = uptime_raw.split()[0] if uptime_raw else '0'
    uptime_clean = format_server_uptime(uptime_seconds)

    # Parse memory
    mem_parts = mem_line.split()
    try:
        if len(mem_parts) >= 7:
            mem_total = int(mem_parts[1])
            mem_used = int(mem_parts[2])
            mem_available = int(mem_parts[6])
            mem_pct = round(mem_used / mem_total * 100) if mem_total else 0
            mem_total_gb = f"{mem_total / (1024**3):.1f}"
            mem_used_gb = f"{mem_used / (1024**3):.1f}"
            mem_avail_gb = f"{mem_available / (1024**3):.1f}"
        else:
            raise ValueError("Not enough memory fields")
    except (ValueError, IndexError):
        mem_total_gb = mem_used_gb = mem_avail_gb = "?"
        mem_pct = 0

    # Parse swap
    swap_parts = swap_line.split()
    swap_pct = 0
    try:
        if len(swap_parts) >= 3:
            swap_total = int(swap_parts[1])
            swap_used = int(swap_parts[2])
            if swap_total > 0:
                swap_str = f"{swap_used / (1024**3):.1f}G / {swap_total / (1024**3):.1f}G"
                swap_pct = round(swap_used / swap_total * 100)
            else:
                swap_str = "Disabled"
        else:
            swap_str = "?"
    except (ValueError, IndexError):
        swap_str = "?"

    # Parse disk
    disk_parts = disk_line.split()
    try:
        if len(disk_parts) >= 6:
            disk_size = disk_parts[1]
            disk_used = disk_parts[2]
            disk_avail = disk_parts[3]
            disk_pct_str = disk_parts[4]
            disk_pct = int(disk_pct_str.rstrip('%'))
        else:
            raise ValueError("Not enough disk fields")
    except (ValueError, IndexError):
        disk_size = disk_used = disk_avail = disk_pct_str = "?"
        disk_pct = 0

    load_1 = loadavg[0] if len(loadavg) > 0 else '?'
    load_5 = loadavg[1] if len(loadavg) > 1 else '?'
    load_15 = loadavg[2] if len(loadavg) > 2 else '?'

    return {
        'hostname': hostname,
        'os': os_info,
        'uptime': uptime_clean,
        'cpu_model': cpu_model,
        'cpu_cores': cpu_cores,
        'load': f"{load_1} / {load_5} / {load_15}",
        'mem_used_gb': mem_used_gb,
        'mem_total_gb': mem_total_gb,
        'mem_avail_gb': mem_avail_gb,
        'mem_pct': mem_pct,
        'swap': swap_str,
        'swap_pct': swap_pct,
        'disk_used': disk_used,
        'disk_size': disk_size,
        'disk_avail': disk_avail,
        'disk_pct': disk_pct,
    }


def _ensure_nginx_site_logs(config_path, domain):
    """Auto-add access_log and error_log directives to an nginx config that lacks them.
    Inserts after the first 'server_name' line in the first HTTPS server block.
    Returns True if the config was modified."""
    result = run_cmd_safe(["sudo", "cat", config_path], timeout=5)
    if result.returncode != 0:
        return False

    lines = result.stdout.split('\n')
    has_error_log = any('error_log' in l for l in lines)
    has_access_log = any('access_log' in l and 'off' not in l for l in lines)

    if has_error_log and has_access_log:
        return False

    # Find the first 'server_name' line that is NOT inside an 'if' block or port-80 redirect
    # We look for the server_name in the main HTTPS block (after listen 443 or after root)
    insert_idx = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('root ') or (stripped.startswith('server_name') and i > 0):
            # Check if this is in the main block (not the redirect block)
            # Use 'root' as anchor since redirect blocks don't have it
            if stripped.startswith('root '):
                insert_idx = i + 1
                break

    if insert_idx is None:
        # Fallback: insert after first server_name
        for i, line in enumerate(lines):
            if line.strip().startswith('server_name') and 'if' not in lines[max(0, i-1)]:
                insert_idx = i + 1
                break

    if insert_idx is None:
        return False

    # Build log directives to insert
    safe_domain = re.sub(r'[^a-zA-Z0-9._-]', '', domain)
    new_lines = []
    if not has_access_log:
        new_lines.append(f'    access_log /var/log/nginx/{safe_domain}-access.log;')
    if not has_error_log:
        new_lines.append(f'    error_log /var/log/nginx/{safe_domain}-error.log;')

    # Insert the new lines
    for offset, new_line in enumerate(new_lines):
        lines.insert(insert_idx + offset, new_line)

    new_content = '\n'.join(lines)

    # Write via temp file
    temp_path = str(DATA_DIR / f'nginx_autolog_{safe_domain}')
    try:
        with open(temp_path, 'w') as f:
            f.write(new_content)
        cp_result = run_cmd_safe(["sudo", "cp", temp_path, config_path], timeout=5)
        if cp_result.returncode != 0:
            return False
    except OSError:
        return False
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass

    log_audit('nginx_auto_add_logs', {'config': os.path.basename(config_path), 'domain': domain})
    return True


@_ttl_cache(60)
def get_nginx_sites():
    """Get nginx sites with HTTP status"""
    sites_dir = CONFIG['nginx'].get('sites_enabled', '/etc/nginx/sites-enabled/')
    result = run_cmd_safe(["ls", sites_dir])
    if result.returncode != 0:
        return []

    configs = [s.strip() for s in result.stdout.strip().split('\n')
               if s.strip() and s.strip() != 'default']
    sites = []
    configs_modified = False

    for config in configs:
        config_path = os.path.join(sites_dir, config)
        info_result = run_cmd_safe(
            ["grep", "-E", "server_name|root |proxy_pass|access_log |error_log ", config_path]
        )
        if info_result.returncode != 0:
            continue

        domains = []
        doc_root = None
        proxy = None
        access_log_path = None
        error_log_path = None

        for line in info_result.stdout.strip().split('\n'):
            line = line.strip()
            if line.startswith('server_name'):
                names = line.replace('server_name', '').rstrip(';').strip().split()
                for name in names:
                    name = name.strip()
                    if name and name != '_' and name != 'localhost':
                        domains.append(name)
            elif line.startswith('root '):
                doc_root = line.replace('root ', '').rstrip(';').strip()
            elif 'proxy_pass' in line:
                proxy = line.replace('proxy_pass', '').rstrip(';').strip()
            elif line.startswith('access_log') and 'off' not in line:
                access_log_path = line.replace('access_log', '').rstrip(';').strip().split()[0]
            elif line.startswith('error_log'):
                error_log_path = line.replace('error_log', '').rstrip(';').strip().split()[0]

        # Deduplicate domains (certbot creates 2 server blocks per config)
        domains = list(dict.fromkeys(domains))

        if domains:
            # Auto-add log directives if missing
            if not access_log_path or not error_log_path:
                if _ensure_nginx_site_logs(config_path, domains[0]):
                    configs_modified = True
                    # Re-read the updated config
                    info_result = run_cmd_safe(
                        ["grep", "-E", "access_log |error_log ", config_path]
                    )
                    if info_result.returncode == 0:
                        for line in info_result.stdout.strip().split('\n'):
                            line = line.strip()
                            if line.startswith('access_log') and 'off' not in line:
                                access_log_path = line.replace('access_log', '').rstrip(';').strip().split()[0]
                            elif line.startswith('error_log'):
                                error_log_path = line.replace('error_log', '').rstrip(';').strip().split()[0]

            # Check HTTP status for first domain (HTTPS with HTTP fallback, follow redirects)
            http_result = run_cmd_safe(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-L",
                 f"https://{domains[0]}", "--max-time", "5"],
                timeout=10
            )
            http_status = http_result.stdout.strip() if http_result.stdout else '---'
            if http_status == '000':
                # HTTPS failed, try HTTP
                http_result = run_cmd_safe(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-L",
                     f"http://{domains[0]}", "--max-time", "5"],
                    timeout=10
                )
                http_status = http_result.stdout.strip() if http_result.stdout else '---'

            sites.append({
                'config': config,
                'domains': domains,
                'domain': ', '.join(domains),
                'root': doc_root,
                'proxy': proxy,
                'type': 'proxy' if proxy else 'static',
                'location': proxy if proxy else (doc_root or 'n/a'),
                'http_status': http_status,
                'access_log': access_log_path,
                'error_log': error_log_path,
            })

    # Reload nginx if we modified any configs
    if configs_modified:
        valid = run_cmd_safe(["sudo", "nginx", "-t"], timeout=10)
        if valid.returncode == 0:
            run_cmd_safe(["sudo", "systemctl", "reload", "nginx"], timeout=10)
        else:
            logger.warning("Nginx config invalid after auto-adding logs, skipping reload")

    return sites


@_ttl_cache(30)
def get_pm2_processes():
    """Get PM2 process list as structured data"""
    result = run_cmd("pm2 jlist")
    if result.returncode != 0 or not result.stdout.strip():
        return []

    try:
        processes = json.loads(result.stdout.strip())
        pm2_list = []
        for p in processes:
            env = p.get('pm2_env', {})
            monit = p.get('monit', {})
            pm2_list.append({
                'name': p.get('name', '?'),
                'pm_id': p.get('pm_id', 0),
                'status': env.get('status', '?'),
                'cpu': monit.get('cpu', 0),
                'memory': round(monit.get('memory', 0) / (1024 * 1024), 1),
                'uptime': _format_uptime(env.get('pm_uptime', 0)),
                'restarts': env.get('restart_time', 0),
            })
        return pm2_list
    except (json.JSONDecodeError, KeyError):
        return []


def _format_uptime(pm_uptime):
    """Format PM2 uptime timestamp to human readable"""
    if not pm_uptime:
        return '?'
    try:
        start = datetime.fromtimestamp(pm_uptime / 1000)
        delta = datetime.now() - start
        days = delta.days
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        if days > 0:
            return f"{days}d {hours}h"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    except (ValueError, OSError):
        return '?'


@_ttl_cache(120)
def get_ssl_certificates():
    """Get SSL certificate info"""
    result = run_cmd("sudo certbot certificates 2>/dev/null", timeout=15)
    if result.returncode != 0:
        return []

    certs = []
    current_domains = None
    for line in result.stdout.split('\n'):
        line = line.strip()
        if line.startswith('Domains:'):
            current_domains = line.replace('Domains:', '').strip()
        elif line.startswith('Expiry Date:') and current_domains:
            match = re.search(r'(\d{4}-\d{2}-\d{2})', line)
            days_match = re.search(r'(\d+)\s+day', line)
            if match:
                expiry_date = match.group(1)
                days_left = int(days_match.group(1)) if days_match else 0
                certs.append({
                    'domain': current_domains,
                    'expiry': expiry_date,
                    'days_left': days_left,
                })
            current_domains = None

    return certs


@_ttl_cache(30)
def get_services_status():
    """Get status of key services"""
    result = run_cmd(
        "systemctl list-units --type=service --state=active --no-legend 2>/dev/null | awk '{print $1}'"
    )
    active_services = result.stdout.strip().split('\n') if result.stdout else []

    default_services = CONFIG.get('services', ['nginx', 'php8.3-fpm', 'mariadb', 'fail2ban'])
    services = list(default_services)
    seen = set(default_services)

    for svc in active_services:
        svc = svc.strip().replace('.service', '')
        if not svc:
            continue
        if 'php' in svc and 'fpm' in svc and svc not in seen:
            services.append(svc)
            seen.add(svc)
        if svc in ('ufw', 'cron', 'ssh', 'certbot.timer') and svc not in seen:
            services.append(svc)
            seen.add(svc)

    # Deduplicate auto-discovered PHP-FPM versions (keep all configured ones)
    configured_set = set(default_services)
    final_services = []
    php_auto_found = False
    for svc in services:
        if 'php' in svc and 'fpm' in svc and svc not in configured_set:
            if php_auto_found:
                continue
            php_auto_found = True
        final_services.append(svc)

    result = run_cmd_safe(["systemctl", "is-active"] + final_services)
    statuses = result.stdout.strip().split('\n') if result.stdout else []

    svc_list = []
    for i, service in enumerate(final_services):
        status = statuses[i].strip() if i < len(statuses) else 'unknown'
        uptime = ''
        if status == 'active':
            up_result = run_cmd_safe(
                ["systemctl", "show", service, "--property=ActiveEnterTimestamp", "--value"]
            )
            if up_result.returncode == 0 and up_result.stdout.strip():
                try:
                    start_str = up_result.stdout.strip()
                    # Format: "Tue 2026-02-03 13:51:33 CET" - strip timezone
                    start_str = ' '.join(start_str.split()[:3])
                    start = datetime.strptime(start_str, '%a %Y-%m-%d %H:%M:%S')
                    delta = datetime.now() - start
                    days = delta.days
                    hours, remainder = divmod(delta.seconds, 3600)
                    minutes, _ = divmod(remainder, 60)
                    if days > 0:
                        uptime = f"{days}d {hours}h"
                    elif hours > 0:
                        uptime = f"{hours}h {minutes}m"
                    else:
                        uptime = f"{minutes}m"
                except (ValueError, IndexError):
                    uptime = '?'
        svc_list.append({
            'name': service,
            'status': status,
            'uptime': uptime,
        })

    return svc_list


BACKUP_STATUS_PATH = DATA_DIR / 'backup_status.json'


def _load_backup_status():
    """Load backup status history"""
    if BACKUP_STATUS_PATH.exists():
        try:
            return json.loads(BACKUP_STATUS_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {'history': [], 'last_success': None, 'last_failure': None}


def _save_backup_status(status):
    """Save backup status history"""
    _atomic_write_json(BACKUP_STATUS_PATH, status)


@_ttl_cache(60)
def get_backup_status():
    """Get backup status info"""
    backup_cfg = CONFIG.get('backup', {})
    log_path = backup_cfg.get('log_path', '/var/log/vps-backup.log')
    backup_dir = backup_cfg.get('backup_dir', '/var/backups/vps/')
    db_backup_dir = backup_cfg.get('db_backup_dir', '/var/backups/vps/databases/')

    data = {'log': '', 'size': '', 'db_backups': '', 'status': None, 'history': [],
            'backup_files': [], 'db_files': [], 'site_backups': []}

    result = run_cmd_safe(["tail", "-5", log_path])
    if result.returncode == 0:
        data['log'] = result.stdout.strip()

    result = run_cmd_safe(["du", "-sh", backup_dir])
    if result.returncode == 0:
        data['size'] = result.stdout.strip()

    result = run_cmd(f"ls -lt {shlex.quote(db_backup_dir)} 2>/dev/null | head -5")
    if result.returncode == 0:
        data['db_backups'] = result.stdout.strip()

    # List backup files with sizes for download
    for dir_path, key in [(backup_dir, 'backup_files'), (db_backup_dir, 'db_files')]:
        try:
            p = Path(dir_path)
            if p.is_dir():
                files = []
                for f in sorted(p.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
                    if f.is_file():
                        st = f.stat()
                        files.append({
                            'name': f.name,
                            'path': str(f),
                            'size': format_file_size(st.st_size),
                            'size_bytes': st.st_size,
                            'modified': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M'),
                        })
                data[key] = files[:20]
        except OSError:
            pass

    # List site backup directories with total sizes (single pass per dir)
    sites_dir = Path(backup_dir) / 'sites'
    try:
        if sites_dir.is_dir():
            for d in sorted(sites_dir.iterdir(), key=lambda x: x.name):
                if d.is_dir():
                    total_size = 0
                    latest_mtime = 0
                    for root, _dirs, files in os.walk(str(d)):
                        for fname in files:
                            try:
                                st = os.stat(os.path.join(root, fname))
                                total_size += st.st_size
                                if st.st_mtime > latest_mtime:
                                    latest_mtime = st.st_mtime
                            except OSError:
                                pass
                    data['site_backups'].append({
                        'name': d.name,
                        'path': str(d),
                        'size': format_file_size(total_size),
                        'size_bytes': total_size,
                        'modified': datetime.fromtimestamp(latest_mtime).strftime('%Y-%m-%d %H:%M') if latest_mtime else '-',
                    })
    except OSError:
        pass

    # Load tracked backup status
    status = _load_backup_status()
    data['status'] = status
    data['history'] = status.get('history', [])[-10:]

    # Parse transfer stats from last NAS pull
    data['nas_pull'] = None
    for entry in reversed(status.get('history', [])):
        if entry.get('status') == 'success' and 'NAS pull' in entry.get('details', ''):
            details = entry['details']
            pull_stats = {'timestamp': entry.get('timestamp', '')[:19]}
            # Parse "transferred: 3473931 bytes"
            m = re.search(r'transferred:\s*([\d,]+)\s*bytes', details)
            if m:
                raw = int(m.group(1).replace(',', ''))
                if raw >= 1048576:
                    pull_stats['transferred'] = f"{raw / 1048576:.1f} MB"
                elif raw >= 1024:
                    pull_stats['transferred'] = f"{raw / 1024:.1f} KB"
                else:
                    pull_stats['transferred'] = f"{raw} B"
            # Parse "speedup: 202.01"
            m = re.search(r'speedup:\s*([\d.]+)', details)
            if m:
                pull_stats['speedup'] = m.group(1)
            # Parse "6/6 checksums OK"
            m = re.search(r'(\d+/\d+)\s*checksums\s*OK', details)
            if m:
                pull_stats['checksums'] = m.group(1)
            # Parse "FAILED"
            m = re.search(r'(\d+)\s*FAILED', details)
            if m:
                pull_stats['checksums_failed'] = m.group(1)
            # Parse disk size "696M on disk"
            m = re.search(r'([\d.]+[KMGT]?)\s*on disk', details)
            if m:
                pull_stats['disk_size'] = m.group(1)
            data['nas_pull'] = pull_stats
            break

    # Parse log for success/failure if no webhook data yet
    if not data['history'] and data['log']:
        for line in data['log'].split('\n'):
            line_lower = line.lower()
            if 'completed' in line_lower or 'success' in line_lower:
                data['status']['last_success'] = line.strip()
            if 'error' in line_lower or 'failed' in line_lower:
                data['status']['last_failure'] = line.strip()

    return data


def check_backup_alerts():
    """Check backup status and return alerts"""
    alerts = []
    status = _load_backup_status()

    if status.get('last_failure'):
        entry = status['last_failure']
        # Only show failure alert if it's more recent than the last success
        show_failure = True
        if isinstance(entry, dict) and isinstance(status.get('last_success'), dict):
            fail_ts = entry.get('timestamp', '')
            success_ts = status['last_success'].get('timestamp', '')
            if success_ts > fail_ts:
                show_failure = False
        if show_failure:
            if isinstance(entry, dict):
                alerts.append({
                    'severity': 'error',
                    'message': f"Last backup failed: {entry.get('details', 'Unknown error')[:80]}",
                    'link': '/backup',
                    'key': 'backup_failed',
                })
            elif isinstance(entry, str):
                alerts.append({
                    'severity': 'error',
                    'message': f"Backup failure detected: {entry[:80]}",
                    'link': '/backup',
                    'key': 'backup_failed',
                })

    # Check if no successful backup in 48 hours
    last_success = status.get('last_success')
    if last_success and isinstance(last_success, dict):
        try:
            last_dt = datetime.fromisoformat(last_success.get('timestamp', ''))
            if (datetime.now() - last_dt).total_seconds() > 172800:  # 48h
                alerts.append({
                    'severity': 'warning',
                    'message': 'No successful backup in the last 48 hours',
                    'link': '/backup',
                    'key': 'backup_stale',
                })
        except (ValueError, TypeError):
            pass

    return alerts


def _seconds_to_human(seconds):
    """Convert seconds to human-readable duration"""
    try:
        s = int(seconds)
        if s == -1:
            return "Permanent"
        if s < 60:
            return f"{s} sec"
        if s < 3600:
            return f"{s // 60} min"
        if s < 86400:
            return f"{s // 3600}h {(s % 3600) // 60}m"
        return f"{s // 86400}d {(s % 86400) // 3600}h"
    except (ValueError, TypeError):
        return str(seconds)


def parse_ufw_rules(ufw_output):
    """Parse 'sudo ufw status numbered' output into a list of dicts"""
    rules = []
    for line in ufw_output.split('\n'):
        line = line.strip()
        # Match lines like: [ 1] 22/tcp                     ALLOW IN    Anywhere                   # comment
        match = re.match(
            r'\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)?\s*(.*)',
            line
        )
        if match:
            number = match.group(1)
            to = match.group(2).strip()
            action = match.group(3).strip()
            direction = (match.group(4) or '').strip()
            from_and_comment = match.group(5).strip() or 'Anywhere'
            comment = ''
            if '#' in from_and_comment:
                from_addr, comment = from_and_comment.split('#', 1)
                from_addr = from_addr.strip() or 'Anywhere'
                comment = comment.strip()
            else:
                from_addr = from_and_comment
            v6 = '(v6)' in to or '(v6)' in from_addr
            rules.append({
                'number': number,
                'to': to.replace('(v6)', '').strip(),
                'action': action,
                'direction': direction,
                'from_addr': from_addr.replace('(v6)', '').strip(),
                'v6': v6,
                'comment': comment,
            })
    return rules


@_ttl_cache(30)
def get_ssh_logs():
    """Get SSH log analysis: failed attempts, successful logins, top attackers, fail2ban actions"""
    data = {
        'failed_count': 0,
        'accepted_count': 0,
        'recent_failed': [],
        'recent_accepted': [],
        'top_attackers': [],
        'fail2ban_actions': [],
        'recent_entries': [],
    }

    # Count failed attempts today
    result = run_cmd("sudo grep -ci 'failed\\|invalid user\\|authentication failure' /var/log/auth.log 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip().isdigit():
        data['failed_count'] = int(result.stdout.strip())

    # Count accepted logins
    result = run_cmd("sudo grep -ci 'accepted' /var/log/auth.log 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip().isdigit():
        data['accepted_count'] = int(result.stdout.strip())

    # Recent failed attempts (last 30)
    result = run_cmd("sudo grep -i 'failed\\|invalid user\\|authentication failure' /var/log/auth.log 2>/dev/null | tail -30")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            entry = _parse_auth_log_line(line)
            data['recent_failed'].append(entry)

    # Recent accepted logins (last 20)
    result = run_cmd("sudo grep -i 'accepted' /var/log/auth.log 2>/dev/null | tail -20")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            entry = _parse_auth_log_line(line)
            data['recent_accepted'].append(entry)

    # Top attacking IPs (from failed attempts)
    result = run_cmd(
        "sudo grep -i 'failed\\|invalid user' /var/log/auth.log 2>/dev/null "
        "| grep -oP 'from \\K[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' "
        "| sort | uniq -c | sort -rn | head -20"
    )
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            parts = line.strip().split()
            if len(parts) >= 2:
                data['top_attackers'].append({
                    'ip': parts[1],
                    'count': int(parts[0]),
                })

    # Fail2ban actions (bans/unbans)
    result = run_cmd("sudo grep -i 'ban\\|unban' /var/log/fail2ban.log 2>/dev/null | tail -30")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            # Parse: 2026-03-10 12:34:56,789 fail2ban.actions [1234]: NOTICE [sshd] Ban 1.2.3.4
            ts_match = re.match(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
            timestamp = ts_match.group(1) if ts_match else ''
            action = 'ban' if re.search(r'\bBan\b', line) else 'unban' if re.search(r'\bUnban\b', line) else 'other'
            ip_match = re.search(r'(?:Ban|Unban|Found)\s+(\d+\.\d+\.\d+\.\d+)', line)
            ip = ip_match.group(1) if ip_match else ''
            jail_match = re.search(r'\[(\w+)\]\s+(?:Ban|Unban|Found)', line)
            jail = jail_match.group(1) if jail_match else ''
            data['fail2ban_actions'].append({
                'timestamp': timestamp,
                'action': action,
                'ip': ip,
                'jail': jail,
                'raw': line,
            })

    # Last 20 sshd entries (general)
    result = run_cmd("sudo grep 'sshd' /var/log/auth.log 2>/dev/null | tail -20")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if line:
                data['recent_entries'].append(_parse_auth_log_line(line))

    # Lookup country info for all IPs
    all_ips = set()
    for attacker in data['top_attackers']:
        if attacker.get('ip'):
            all_ips.add(attacker['ip'])
    for entry in data['fail2ban_actions']:
        if entry.get('ip'):
            all_ips.add(entry['ip'])
    for entry in data['recent_failed'] + data['recent_accepted'] + data['recent_entries']:
        if entry.get('ip'):
            all_ips.add(entry['ip'])
    country_map = lookup_ip_countries(list(all_ips))

    # Apply country data
    for attacker in data['top_attackers']:
        geo = country_map.get(attacker.get('ip'))
        if geo:
            attacker['country'] = geo['country']
            attacker['countryCode'] = geo['countryCode']
    for entry in data['fail2ban_actions']:
        geo = country_map.get(entry.get('ip'))
        if geo:
            entry['country'] = geo['country']
            entry['countryCode'] = geo['countryCode']
    for entry in data['recent_failed'] + data['recent_accepted'] + data['recent_entries']:
        geo = country_map.get(entry.get('ip'))
        if geo:
            entry['country'] = geo['country']
            entry['countryCode'] = geo['countryCode']

    return data


def _parse_auth_log_line(line):
    """Parse an auth.log line into structured data"""
    # Format: Mar 10 12:34:56 hostname sshd[1234]: message
    match = re.match(
        r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+\S+:\s+(.*)',
        line
    )
    if match:
        timestamp = match.group(1)
        message = match.group(2)
    else:
        timestamp = ''
        message = line

    # Determine level
    msg_lower = message.lower()
    if 'accepted' in msg_lower:
        level = 'accepted'
    elif 'failed' in msg_lower or 'invalid user' in msg_lower or 'authentication failure' in msg_lower:
        level = 'failed'
    elif 'disconnect' in msg_lower:
        level = 'disconnect'
    elif 'ban' in msg_lower:
        level = 'ban'
    else:
        level = 'info'

    # Extract IP
    ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
    ip = ip_match.group(1) if ip_match else ''

    return {
        'timestamp': timestamp,
        'level': level,
        'message': message[:200],
        'ip': ip,
        'raw': line,
    }


def get_firewall_security():
    """Get firewall and security info"""
    data = {
        'ufw': '', 'ufw_rules': [], 'fail2ban': '', 'banned': '', 'sessions': '', 'auth_log': '',
        'f2b_config': {}, 'jails': [],
    }

    result = run_cmd("sudo ufw status numbered 2>/dev/null")
    if result.returncode == 0:
        data['ufw'] = result.stdout.strip()
        data['ufw_rules'] = parse_ufw_rules(result.stdout)

    result = run_cmd("sudo fail2ban-client status sshd 2>/dev/null")
    if result.returncode == 0:
        data['fail2ban'] = result.stdout.strip()

    result = run_cmd("sudo fail2ban-client banned 2>/dev/null")
    if result.returncode == 0:
        data['banned'] = result.stdout.strip()

    result = run_cmd("who")
    if result.returncode == 0:
        data['sessions'] = result.stdout.strip()

    result = run_cmd("sudo grep 'sshd' /var/log/auth.log 2>/dev/null | tail -15")
    if result.returncode == 0:
        data['auth_log'] = result.stdout.strip()

    # Fail2ban config details
    f2b_config = {}
    for setting in ['bantime', 'findtime', 'maxretry']:
        result = run_cmd(f"sudo fail2ban-client get sshd {setting} 2>/dev/null")
        if result.returncode == 0:
            val = result.stdout.strip()
            if setting in ('bantime', 'findtime'):
                f2b_config[setting] = _seconds_to_human(val)
                f2b_config[f'{setting}_raw'] = val
            else:
                f2b_config[setting] = val
    f2b_config['permanent_bans'] = f2b_config.get('bantime_raw', '0') == '-1'
    data['f2b_config'] = f2b_config

    # All jails
    result = run_cmd("sudo fail2ban-client status 2>/dev/null")
    if result.returncode == 0:
        jail_match = re.search(r'Jail list:\s*(.+)', result.stdout)
        if jail_match:
            jail_names = [j.strip() for j in jail_match.group(1).split(',') if j.strip()]
            for jail_name in jail_names:
                jail_result = run_cmd(f"sudo fail2ban-client status {shlex.quote(jail_name)} 2>/dev/null")
                jail_info = {'name': jail_name, 'status': 'unknown', 'banned': 0, 'total_banned': 0}
                if jail_result.returncode == 0:
                    jail_info['status'] = 'active'
                    banned_match = re.search(r'Currently banned:\s*(\d+)', jail_result.stdout)
                    total_match = re.search(r'Total banned:\s*(\d+)', jail_result.stdout)
                    if banned_match:
                        jail_info['banned'] = int(banned_match.group(1))
                    if total_match:
                        jail_info['total_banned'] = int(total_match.group(1))
                data['jails'].append(jail_info)

    return data


@_ttl_cache(300)
def get_system_updates():
    """Get list of available updates, categorized"""
    result = run_cmd("apt list --upgradable 2>/dev/null", timeout=60)
    if result.returncode != 0:
        return []

    # Detect phased packages via simulated upgrade
    phased_packages = set()
    sim_result = run_cmd("apt -s upgrade 2>/dev/null", timeout=60)
    if sim_result.returncode == 0 and 'deferred due to phasing' in sim_result.stdout:
        in_phased = False
        for sim_line in sim_result.stdout.split('\n'):
            if 'deferred due to phasing' in sim_line:
                in_phased = True
                continue
            if in_phased:
                sim_line = sim_line.strip()
                if not sim_line or sim_line[0].isdigit():
                    break
                for pkg in sim_line.split():
                    phased_packages.add(pkg)

    updates = []
    for line in result.stdout.strip().split('\n'):
        line = line.strip()
        if line and 'Listing' not in line and line != '':
            # Parse: package/source version arch [upgradable from: old_version]
            parts = line.split('/')
            if len(parts) >= 2:
                name = parts[0]
                rest = '/'.join(parts[1:])
                version_match = re.search(r'\s(\S+)\s', rest)
                version = version_match.group(1) if version_match else rest.split()[0] if rest.split() else '?'

                # Categorize
                line_lower = line.lower()
                if 'esm-infra' in line_lower or 'esm-apps' in line_lower:
                    category = 'esm'
                elif name in phased_packages:
                    category = 'phased'
                elif 'security' in line_lower:
                    category = 'security'
                else:
                    category = 'regular'

                updates.append({
                    'package': name,
                    'version': version,
                    'security': category == 'security',
                    'category': category,
                    'raw': line,
                })

    return updates


def _parse_nginx_error_line(line):
    """Parse a single nginx error log line into structured data"""
    # Format: 2026/02/03 12:34:56 [error] 1234#0: *5678 message
    match = re.match(
        r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(.*)',
        line
    )
    if match:
        return {
            'timestamp': match.group(1),
            'level': match.group(2),
            'message': match.group(3)[:120],
            'raw': line,
        }
    return {'timestamp': '', 'level': 'unknown', 'message': line[:120], 'raw': line}


@_ttl_cache(30)
def get_nginx_logs():
    """Get nginx log information"""
    nginx_cfg = CONFIG.get('nginx', {})
    error_log = nginx_cfg.get('error_log', '/var/log/nginx/error.log')
    access_log = nginx_cfg.get('access_log', '/var/log/nginx/access.log')

    data = {'errors': [], 'per_site': [], 'access_summary': [], 'php_errors': []}

    # Nginx error log - parsed into structured entries
    result = run_cmd_safe(["sudo", "tail", "-20", error_log])
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                data['errors'].append(_parse_nginx_error_line(line.strip()))

    # Per-site errors: read each site's own error log
    sites = get_nginx_sites()
    for site in sites:
        site_error_log = site.get('error_log')
        if not site_error_log:
            continue
        site_name = site['domains'][0] if site.get('domains') else site.get('config', '?')
        result = run_cmd_safe(["sudo", "tail", "-50", site_error_log])
        if result.returncode != 0 or not result.stdout.strip():
            data['per_site'].append({
                'site': site_name,
                'count': 0,
                'last_ts': '',
                'last_msg': '',
                'log_path': site_error_log,
            })
            continue
        lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
        last_ts = ''
        last_msg = ''
        if lines:
            ts_match = re.match(r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})', lines[-1])
            if ts_match:
                last_ts = ts_match.group(1)
            msg_match = re.search(r'\[\w+\]\s+\d+#\d+:\s+\*\d+\s+(.*?)(?:,\s*client:|$)', lines[-1])
            if msg_match:
                last_msg = msg_match.group(1).strip()[:100]
        data['per_site'].append({
            'site': site_name,
            'count': len(lines),
            'last_ts': last_ts,
            'last_msg': last_msg,
            'log_path': site_error_log,
        })
    data['per_site'].sort(key=lambda x: x['count'], reverse=True)

    # Access log summary per site
    for site in sites:
        site_access_log = site.get('access_log')
        if not site_access_log:
            continue
        site_name = site['domains'][0] if site.get('domains') else site.get('config', '?')
        result = run_cmd(
            f"sudo awk '{{print $9}}' {shlex.quote(site_access_log)} 2>/dev/null | sort | uniq -c | sort -rn | head -10"
        )
        if result.returncode == 0 and result.stdout.strip():
            codes = []
            for line in result.stdout.strip().split('\n'):
                parts = line.strip().split()
                if len(parts) == 2:
                    codes.append({'code': parts[1], 'count': parts[0]})
            if codes:
                data['access_summary'].append({'site': site_name, 'codes': codes})

    # PHP-FPM error log
    result = run_cmd("sudo tail -20 /var/log/php*-fpm.log 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('==>'):
                data['php_errors'].append({
                    'message': line[:150],
                    'raw': line,
                })

    return data


@_ttl_cache(120)
def get_database_info():
    """Get MariaDB database info"""
    cmd = (
        'sudo mysql -e "'
        "SELECT table_schema AS db, "
        "ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS size_mb, "
        "COUNT(*) AS tables "
        "FROM information_schema.tables "
        "WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys') "
        "GROUP BY table_schema "
        'ORDER BY size_mb DESC;" 2>/dev/null'
    )
    result = run_cmd(cmd)
    if result.returncode != 0:
        return []

    databases = []
    lines = [l for l in result.stdout.strip().split('\n') if l.strip()]
    for line in lines[1:]:  # Skip header
        parts = line.split('\t')
        if len(parts) >= 3:
            databases.append({
                'name': parts[0].strip(),
                'size_mb': parts[1].strip(),
                'tables': parts[2].strip(),
            })

    return databases


def _cron_to_human(parts):
    """Convert cron schedule parts to human-readable string"""
    if len(parts) < 5:
        return ' '.join(parts)

    minute, hour, dom, month, dow = parts[:5]

    # Common patterns
    if minute == '*' and hour == '*':
        return "Every minute"
    if minute.startswith('*/'):
        return f"Every {minute[2:]} minutes"
    if hour.startswith('*/'):
        return f"Every {hour[2:]} hours"
    if dom == '*' and month == '*' and dow == '*':
        return f"Daily at {hour.zfill(2)}:{minute.zfill(2)}"
    if dom == '*' and month == '*' and dow != '*':
        days_map = {'0': 'Sun', '1': 'Mon', '2': 'Tue', '3': 'Wed', '4': 'Thu', '5': 'Fri', '6': 'Sat', '7': 'Sun'}
        day_names = ','.join(days_map.get(d.strip(), d.strip()) for d in dow.split(','))
        return f"{day_names} at {hour.zfill(2)}:{minute.zfill(2)}"
    if month == '*' and dow == '*':
        return f"Day {dom} at {hour.zfill(2)}:{minute.zfill(2)}"
    return f"{minute} {hour} {dom} {month} {dow}"


def _parse_systemd_timers(text):
    """Parse systemd list-timers output into structured data"""
    timers = []
    lines = text.strip().split('\n')
    if not lines:
        return timers

    # Find header line to get column positions
    header = None
    for line in lines:
        if 'NEXT' in line and 'UNIT' in line:
            header = line
            break

    if not header:
        return timers

    # Get column start positions from header
    try:
        col_next = header.index('NEXT')
        col_left = header.index('LEFT')
        col_last = header.index('LAST')
        col_unit = header.index('UNIT')
        col_activates = header.index('ACTIVATES')
    except ValueError:
        return timers

    for line in lines:
        if not line.strip() or line == header or 'timers listed' in line:
            continue
        if len(line) < col_activates:
            continue

        next_run = line[col_next:col_left].strip()
        left = line[col_left:col_last].strip()
        unit = line[col_unit:col_activates].strip()
        activates = line[col_activates:].strip()

        # Clean up "left" suffix from LEFT column
        if left.endswith(' left'):
            left = left[:-5]

        if unit.endswith('.timer'):
            timers.append({
                'unit': unit,
                'activates': activates,
                'next': next_run if next_run != '-' else '-',
                'left': left if left != '-' else '-',
            })
    return timers


@_ttl_cache(120)
def get_cronjobs():
    """Get cron and systemd timer info as structured data"""
    data = {'root': '', 'user': '', 'timers': '', 'root_jobs': [], 'user_jobs': [], 'timer_list': []}

    result = run_cmd("sudo crontab -l 2>/dev/null")
    if result.returncode == 0:
        data['root'] = result.stdout.strip()
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('MAILTO'):
                continue
            parts = line.split()
            if parts and '=' in parts[0]:
                continue
            if len(parts) >= 6:
                schedule_parts = parts[:5]
                command = ' '.join(parts[5:])
                data['root_jobs'].append({
                    'schedule': ' '.join(schedule_parts),
                    'human_schedule': _cron_to_human(schedule_parts),
                    'command': command,
                })

    result = run_cmd("crontab -l 2>/dev/null")
    if result.returncode == 0:
        data['user'] = result.stdout.strip()
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('MAILTO') or '=' in line.split()[0] if line.split() else True:
                continue
            parts = line.split()
            if len(parts) >= 6:
                schedule_parts = parts[:5]
                command = ' '.join(parts[5:])
                data['user_jobs'].append({
                    'schedule': ' '.join(schedule_parts),
                    'human_schedule': _cron_to_human(schedule_parts),
                    'command': command,
                })

    result = run_cmd("systemctl list-timers --no-pager 2>/dev/null")
    if result.returncode == 0:
        data['timers'] = result.stdout.strip()
        data['timer_list'] = _parse_systemd_timers(result.stdout)

    return data


def _parse_size_to_mb(size_str):
    """Parse human-readable size (e.g. '1.2G', '500M', '4.0K') to MB float"""
    size_str = size_str.strip()
    try:
        if size_str.endswith('G'):
            return float(size_str[:-1]) * 1024
        elif size_str.endswith('M'):
            return float(size_str[:-1])
        elif size_str.endswith('K'):
            return float(size_str[:-1]) / 1024
        elif size_str.endswith('T'):
            return float(size_str[:-1]) * 1024 * 1024
        else:
            return float(size_str) / (1024 * 1024)
    except (ValueError, IndexError):
        return 0.0


def get_disk_per_site():
    """Get disk usage per site"""
    result = run_cmd("du -sh /var/www/*/ 2>/dev/null | sort -rh")
    if result.returncode != 0 or not result.stdout.strip():
        return [], ''

    sites = []
    for line in result.stdout.strip().split('\n'):
        parts = line.split('\t')
        if len(parts) >= 2:
            size = parts[0].strip()
            path = parts[1].strip().rstrip('/')
            site_name = os.path.basename(path)
            sites.append({'site': site_name, 'size': size, 'size_mb': round(_parse_size_to_mb(size), 2)})

    total_result = run_cmd("du -sh /var/www/ 2>/dev/null")
    total = ''
    if total_result.returncode == 0 and total_result.stdout.strip():
        total = total_result.stdout.strip().split('\t')[0]

    return sites, total


def get_dashboard_alerts(data, services, pm2, ssl):
    """Generate dashboard alerts from existing data"""
    alerts = []
    thresholds = CONFIG.get('thresholds', {})

    if data:
        # Disk usage
        disk_pct = data.get('disk_pct', 0)
        disk_critical = thresholds.get('disk_critical', 95)
        disk_warning = thresholds.get('disk_warning', 80)
        if disk_pct > disk_critical:
            alerts.append({'severity': 'error', 'message': f"Disk space critical: {disk_pct}% used", 'link': '/disk', 'key': 'disk_critical'})
        elif disk_pct > disk_warning:
            alerts.append({'severity': 'warning', 'message': f"Disk space high: {disk_pct}% used", 'link': '/disk', 'key': 'disk_warning'})

        # Memory usage
        mem_pct = data.get('mem_pct', 0)
        mem_warning = thresholds.get('memory_warning', 85)
        if mem_pct > mem_warning:
            alerts.append({'severity': 'warning', 'message': f"RAM usage high: {mem_pct}%", 'link': None, 'key': 'ram_warning'})

        # Swap usage
        swap_pct = data.get('swap_pct', 0)
        swap_warning = thresholds.get('swap_warning', 50)
        if swap_pct > swap_warning:
            alerts.append({'severity': 'warning', 'message': f"Swap usage high: {swap_pct}%", 'link': None, 'key': 'swap_warning'})

        # Load average
        load_str = data.get('load', '')
        cpu_cores = data.get('cpu_cores', '1')
        try:
            load_1 = float(load_str.split('/')[0].strip())
            cores = int(cpu_cores)
            if load_1 > cores:
                alerts.append({'severity': 'warning', 'message': f"Load average high: {load_1:.2f} (> {cores} cores)", 'link': None, 'key': 'load_warning'})
        except (ValueError, IndexError):
            pass

    # Services down
    for svc in services:
        if svc['status'] != 'active':
            alerts.append({'severity': 'error', 'message': f"Service '{svc['name']}' is {svc['status']}", 'link': '/services', 'key': f"service_down_{svc['name']}"})

    # PM2 processes
    for p in pm2:
        if p['status'] != 'online':
            alerts.append({'severity': 'error', 'message': f"PM2 process '{p['name']}' is {p['status']}", 'link': '/pm2', 'key': f"pm2_offline_{p['name']}"})

    # SSL certificates
    ssl_critical = thresholds.get('ssl_critical_days', 3)
    ssl_warning = thresholds.get('ssl_warning_days', 14)
    for cert in ssl:
        days = cert.get('days_left', 999)
        domain = cert.get('domain', '?')
        if days < ssl_critical:
            alerts.append({'severity': 'error', 'message': f"SSL certificate '{domain}' expires in {days} days!", 'link': '/ssl', 'key': f"ssl_critical_{domain}"})
        elif days < ssl_warning:
            alerts.append({'severity': 'warning', 'message': f"SSL certificate '{domain}' expires in {days} days", 'link': '/ssl', 'key': f"ssl_warning_{domain}"})

    # Uptime: check for sites that are down
    try:
        uptime_history = json.loads(UPTIME_HISTORY_PATH.read_text()) if UPTIME_HISTORY_PATH.exists() else {}
        for domain, entries in uptime_history.items():
            if entries:
                last = entries[-1]
                if last.get('status', 0) == 0 or last.get('status', 200) >= 500:
                    alerts.append({'severity': 'error', 'message': f"Site '{domain}' is down", 'link': '/uptime', 'key': f"site_down_{domain}"})
    except (json.JSONDecodeError, OSError):
        pass

    # Quick updates check (fast, cached by apt)
    updates = get_system_updates()
    installable = [u for u in updates if u['category'] in ('security', 'regular')]
    sec_count = len([u for u in installable if u['category'] == 'security'])
    if installable:
        msg = f"{len(installable)} updates available"
        if sec_count > 0:
            msg += f" (including {sec_count} security)"
        alerts.append({'severity': 'warning', 'message': msg, 'link': '/updates', 'key': 'updates_available'})

    # Sort: error first, then warning, then info
    alerts.sort(key=lambda a: _SEVERITY_ORDER.get(a['severity'], 99))

    return alerts


@_ttl_cache(60)
def check_ddos_indicators():
    """Check for DDoS indicators and return alerts"""
    ddos_cfg = CONFIG.get('ddos_detection', {})
    if not ddos_cfg.get('enabled', True):
        return []

    alerts = []
    conn_threshold = ddos_cfg.get('connection_threshold', 100)
    syn_threshold = ddos_cfg.get('syn_threshold', 50)
    single_ip_threshold = ddos_cfg.get('single_ip_threshold', 50)

    # Total established connections
    result = run_cmd("ss -t state established 2>/dev/null | tail -n +2 | wc -l")
    if result.returncode == 0:
        try:
            total_conn = int(result.stdout.strip())
            if total_conn > conn_threshold:
                alerts.append({
                    'severity': 'warning',
                    'message': f"High connection count: {total_conn} established",
                    'link': '/firewall',
                    'key': 'high_connections',
                })
        except ValueError:
            pass

    # SYN_RECV count (SYN flood indicator)
    result = run_cmd("ss -t state syn-recv 2>/dev/null | tail -n +2 | wc -l")
    if result.returncode == 0:
        try:
            syn_count = int(result.stdout.strip())
            if syn_count > syn_threshold:
                alerts.append({
                    'severity': 'error',
                    'message': f"SYN flood indicator: {syn_count} SYN_RECV",
                    'link': '/firewall',
                    'key': 'syn_flood',
                })
        except ValueError:
            pass

    # Connections per IP (top offender)
    result = run_cmd(
        "ss -t state established 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -1"
    )
    if result.returncode == 0 and result.stdout.strip():
        parts = result.stdout.strip().split()
        if len(parts) >= 2:
            try:
                ip_count = int(parts[0])
                ip_addr = parts[1]
                if ip_count > single_ip_threshold:
                    alerts.append({
                        'severity': 'error',
                        'message': f"Possible DDoS: {ip_count} connections from {ip_addr}",
                        'link': '/firewall',
                        'key': f"ddos_single_ip_{ip_addr}",
                    })
            except ValueError:
                pass

    return alerts


def get_ddos_stats():
    """Get current connection stats for the firewall DDoS card"""
    stats = {'total_connections': 0, 'syn_recv': 0, 'top_ips': []}

    result = run_cmd("ss -t state established 2>/dev/null | tail -n +2 | wc -l")
    if result.returncode == 0:
        try:
            stats['total_connections'] = int(result.stdout.strip())
        except ValueError:
            pass

    result = run_cmd("ss -t state syn-recv 2>/dev/null | tail -n +2 | wc -l")
    if result.returncode == 0:
        try:
            stats['syn_recv'] = int(result.stdout.strip())
        except ValueError:
            pass

    result = run_cmd(
        "ss -t state established 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -5"
    )
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            parts = line.strip().split()
            if len(parts) >= 2:
                try:
                    stats['top_ips'].append({'count': int(parts[0]), 'ip': parts[1]})
                except ValueError:
                    pass

    ddos_cfg = CONFIG.get('ddos_detection', {})
    stats['conn_threshold'] = ddos_cfg.get('connection_threshold', 100)
    stats['syn_threshold'] = ddos_cfg.get('syn_threshold', 50)
    stats['ip_threshold'] = ddos_cfg.get('single_ip_threshold', 50)

    return stats


UPTIME_HISTORY_PATH = DATA_DIR / 'uptime_history.json'
_uptime_lock = threading.Lock()


@_ttl_cache(10)
def get_system_processes():
    """Get top 25 system processes sorted by memory usage"""
    result = run_cmd("ps aux --sort=-%mem | head -26", timeout=10)
    processes = []
    total = 0
    if result.returncode == 0:
        lines = result.stdout.strip().split('\n')
        for line in lines[1:]:  # skip header
            parts = line.split(None, 10)
            if len(parts) >= 11:
                processes.append({
                    'user': parts[0],
                    'pid': parts[1],
                    'cpu': float(parts[2]),
                    'mem': float(parts[3]),
                    'rss': int(parts[5]),
                    'stat': parts[7],
                    'start': parts[8],
                    'time': parts[9],
                    'command': parts[10],
                })
    count_result = run_cmd("ps aux | wc -l", timeout=5)
    if count_result.returncode == 0:
        try:
            total = int(count_result.stdout.strip()) - 1
        except ValueError:
            pass
    return {'processes': processes, 'total': total}


@_ttl_cache(30)
def get_network_info():
    """Get network interfaces, listening ports, and connection count"""
    interfaces = []
    result = run_cmd("ip -j addr show", timeout=10)
    if result.returncode == 0:
        try:
            ifaces = json.loads(result.stdout)
            for iface in ifaces:
                name = iface.get('ifname', '')
                if name == 'lo':
                    continue
                state = iface.get('operstate', 'UNKNOWN').lower()
                mac = iface.get('address', '')
                addrs = []
                for addr_info in iface.get('addr_info', []):
                    addrs.append(addr_info.get('local', ''))
                interfaces.append({
                    'name': name,
                    'state': state,
                    'mac': mac,
                    'addresses': addrs,
                    'ip': ', '.join(addrs) if addrs else '-',
                })
        except (json.JSONDecodeError, KeyError):
            pass

    ports = []
    result = run_cmd("ss -tlnp", timeout=10)
    if result.returncode == 0:
        lines = result.stdout.strip().split('\n')
        for line in lines[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 5:
                local = parts[3]
                process = ''
                if len(parts) >= 6:
                    m = re.search(r'users:\(\("([^"]+)"', parts[5] if len(parts) > 5 else '')
                    if m:
                        process = m.group(1)
                port = local.rsplit(':', 1)[-1] if ':' in local else local
                ports.append({
                    'local': local,
                    'port': port,
                    'state': parts[0],
                    'process': process,
                })

    conn_count = 0
    result = run_cmd("ss -t state established | wc -l", timeout=5)
    if result.returncode == 0:
        try:
            conn_count = max(0, int(result.stdout.strip()) - 1)
        except ValueError:
            pass

    return {'interfaces': interfaces, 'ports': ports, 'connections': conn_count}


@_ttl_cache(30)
def get_uptime_status():
    """Check HTTP status for all sites (HTTPS with HTTP fallback, HEAD with GET fallback)"""
    sites = get_sites()
    results = []
    for site in sites:
        domain = site['domains'][0] if site.get('domains') else None
        if not domain:
            continue

        result_entry = None
        # Try HTTPS first, then HTTP as fallback
        for scheme in ('https', 'http'):
            if result_entry:
                break
            # Try HEAD first, fall back to GET on 405
            for method in ('HEAD', 'GET'):
                try:
                    req = urllib.request.Request(f"{scheme}://{domain}", method=method)
                    start = time.time()
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        elapsed = (time.time() - start) * 1000
                        result_entry = {
                            'domain': domain,
                            'status_code': resp.status,
                            'response_ms': round(elapsed),
                            'is_up': True,
                        }
                        break
                except urllib.error.HTTPError as e:
                    if e.code == 405 and method == 'HEAD':
                        continue  # Try GET
                    # Got an HTTP response (even if error), site is reachable
                    result_entry = {
                        'domain': domain,
                        'status_code': e.code,
                        'response_ms': 0,
                        'is_up': e.code < 500,
                    }
                    break
                except Exception:
                    if scheme == 'https' and method == 'HEAD':
                        continue  # Try HTTPS GET first
                    if scheme == 'https':
                        break  # Fall through to HTTP
                    # Both schemes failed
                    pass

        if not result_entry:
            result_entry = {
                'domain': domain,
                'status_code': 0,
                'response_ms': 0,
                'is_up': False,
            }
        results.append(result_entry)
    return results


def check_uptime_all():
    """Check uptime for all sites and save to history file"""
    _invalidate_cache('get_uptime_status')
    results = get_uptime_status()
    now = datetime.now().isoformat()

    with _uptime_lock:
        try:
            history = json.loads(UPTIME_HISTORY_PATH.read_text()) if UPTIME_HISTORY_PATH.exists() else {}
        except (json.JSONDecodeError, OSError):
            history = {}

        for r in results:
            domain = r['domain']
            entry = {'timestamp': now, 'status': r['status_code'], 'response_ms': r['response_ms']}
            if domain not in history:
                history[domain] = []
            history[domain].append(entry)
            # Keep max 288 entries (24h at 5-min interval)
            history[domain] = history[domain][-288:]

        _atomic_write_json(UPTIME_HISTORY_PATH, history)

    return results


@_ttl_cache(120)
def get_php_info():
    """Get PHP versions, FPM pool status, and per-site PHP mapping"""
    versions = []
    result = run_cmd_safe(["ls", "/etc/php/"], timeout=5)
    if result.returncode == 0:
        ver_dirs = [v.strip() for v in result.stdout.strip().split('\n') if v.strip()]
        for ver in sorted(ver_dirs, reverse=True):
            if not re.match(r'^\d+\.\d+$', ver):
                continue
            fpm_result = run_cmd_safe(["systemctl", "is-active", f"php{ver}-fpm"], timeout=5)
            fpm_status = fpm_result.stdout.strip() if fpm_result.returncode == 0 else 'not installed'

            pool_config = {}
            pool_path = f"/etc/php/{ver}/fpm/pool.d/www.conf"
            pool_result = run_cmd_safe(["grep", "-E", "^(pm |pm\\.|memory_limit)", pool_path], timeout=5)
            if pool_result.returncode == 0:
                for line in pool_result.stdout.strip().split('\n'):
                    if '=' in line:
                        k, v = line.split('=', 1)
                        pool_config[k.strip()] = v.strip()

            # Installed extensions
            ext_result = run_cmd_safe(["php" + ver, "-m"], timeout=5)
            extensions = []
            if ext_result.returncode == 0:
                extensions = sorted([l.strip() for l in ext_result.stdout.strip().split('\n')
                                     if l.strip() and not l.strip().startswith('[')])

            versions.append({
                'version': ver,
                'fpm_status': fpm_status,
                'pm': pool_config.get('pm', '-'),
                'max_children': pool_config.get('pm.max_children', '-'),
                'memory_limit': pool_config.get('memory_limit', '-'),
                'extensions': extensions,
            })

    # Per-site PHP mapping from nginx configs
    site_mapping = []
    sites_dir = CONFIG['nginx'].get('sites_enabled', '/etc/nginx/sites-enabled/')
    result = run_cmd_safe(["grep", "-Rl", "fastcgi_pass", sites_dir], timeout=5)
    if result.returncode == 0:
        for config_path in result.stdout.strip().split('\n'):
            if not config_path.strip():
                continue
            real_path = os.path.realpath(config_path.strip())
            config_name = os.path.basename(config_path.strip())
            socket_result = run_cmd_safe(["grep", "-oP", "-m1", r"fastcgi_pass unix:\K[^;]+", real_path], timeout=5)
            socket_path = socket_result.stdout.strip() if socket_result.returncode == 0 else ''
            # Extract PHP version from socket path (e.g. /run/php/php8.3-fpm.sock)
            php_ver = '-'
            m = re.search(r'php(\d+\.\d+)', socket_path)
            if m:
                php_ver = m.group(1)
            site_mapping.append({
                'config': config_name,
                'php_version': php_ver,
                'socket': socket_path,
            })

    return {'versions': versions, 'site_mapping': site_mapping}


def get_dns_records(domain):
    """Get DNS records for a specific domain"""
    records = {}
    for rtype in ('A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS'):
        result = run_cmd_safe(["dig", "+short", rtype, domain], timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            values = [v.strip() for v in result.stdout.strip().split('\n') if v.strip()]
            if values:
                records[rtype] = values
    return records


@_ttl_cache(120)
def get_all_domains():
    """Get all known domains from web server sites"""
    sites = get_sites()
    domains = []
    for site in sites:
        for d in site.get('domains', []):
            if d not in domains:
                domains.append(d)
    return domains


def is_path_allowed(path):
    """Check if path is within allowed directories (whitelist approach).
    Uses realpath() to resolve symlinks and prevent symlink escapes.
    """
    allowed = CONFIG.get('file_browser', {}).get('allowed_paths', ['/var/www'])
    try:
        norm = os.path.realpath(path)
    except OSError:
        return False
    for a in allowed:
        try:
            real_a = os.path.realpath(a)
        except OSError:
            continue
        if norm == real_a or norm.startswith(real_a + '/'):
            return True
    return False


def format_file_size(size_bytes):
    """Format bytes to human readable"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

@app.route('/')
@login_required
def dashboard():
    data = get_server_overview()
    services = get_services_status()
    pm2 = get_pm2_processes()
    ssl = get_ssl_info()
    alerts = get_dashboard_alerts(data, services, pm2, ssl)
    # Add DDoS and backup alerts
    alerts.extend(check_ddos_indicators())
    alerts.extend(check_backup_alerts())
    # Re-sort
    alerts.sort(key=lambda a: _SEVERITY_ORDER.get(a['severity'], 99))
    dismissed = CONFIG.get('dismissed_alerts', [])
    alerts = [a for a in alerts if a.get('key') not in dismissed]
    return render_template('dashboard.html', data=data, services=services, pm2=pm2, ssl=ssl, alerts=alerts)


@app.route('/api/alerts/dismiss', methods=['POST'])
@login_required
def dismiss_alert():
    data = request.get_json() or {}
    key = data.get('key', '')
    if not key:
        return jsonify({'status': 'error', 'message': 'No alert key'}), 400
    dismissed = CONFIG.get('dismissed_alerts', [])
    if key not in dismissed:
        dismissed.append(key)
    CONFIG['dismissed_alerts'] = dismissed
    save_config(CONFIG)
    return jsonify({'status': 'ok'})


@app.route('/websites')
@login_required
def websites():
    sites = get_sites()
    return render_template('websites.html', sites=sites)


@app.route('/uptime')
@login_required
def uptime():
    status = get_uptime_status()
    total = len(status)
    up_count = sum(1 for s in status if s['is_up'])
    avg_response = round(sum(s['response_ms'] for s in status if s['is_up']) / up_count) if up_count else 0
    return render_template('uptime.html', status=status, total=total, up_count=up_count, avg_response=avg_response)


@app.route('/api/uptime/history')
@login_required
def uptime_history_api():
    with _uptime_lock:
        try:
            history = json.loads(UPTIME_HISTORY_PATH.read_text()) if UPTIME_HISTORY_PATH.exists() else {}
        except (json.JSONDecodeError, OSError):
            history = {}
    return jsonify(history)


@app.route('/pm2')
@login_required
def pm2():
    processes = get_pm2_processes()
    return render_template('pm2.html', processes=processes)


@app.route('/pm2/restart/<name>', methods=['POST'])
@login_required
def pm2_restart(name):
    if not is_safe_name(name):
        return jsonify({'status': 'error', 'message': 'Invalid process name'}), 400
    result = run_cmd_safe(["pm2", "restart", name])
    if result.returncode == 0:
        log_audit('pm2_restart', {'process': name})
        _invalidate_cache('get_pm2_processes')
        return jsonify({'status': 'ok', 'message': f"'{name}' restarted"})
    return jsonify({'status': 'error', 'message': f"Could not restart '{name}': {result.stderr}"}), 500


@app.route('/pm2/stop/<name>', methods=['POST'])
@login_required
def pm2_stop(name):
    if not is_safe_name(name):
        return jsonify({'status': 'error', 'message': 'Invalid process name'}), 400
    result = run_cmd_safe(["pm2", "stop", name])
    if result.returncode == 0:
        log_audit('pm2_stop', {'process': name})
        _invalidate_cache('get_pm2_processes')
        return jsonify({'status': 'ok', 'message': f"'{name}' stopped"})
    return jsonify({'status': 'error', 'message': f"Could not stop '{name}': {result.stderr}"}), 500


@app.route('/pm2/start/<name>', methods=['POST'])
@login_required
def pm2_start(name):
    if not is_safe_name(name):
        return jsonify({'status': 'error', 'message': 'Invalid process name'}), 400
    result = run_cmd_safe(["pm2", "start", name])
    if result.returncode == 0:
        log_audit('pm2_start', {'process': name})
        _invalidate_cache('get_pm2_processes')
        return jsonify({'status': 'ok', 'message': f"'{name}' started"})
    return jsonify({'status': 'error', 'message': f"Could not start '{name}': {result.stderr}"}), 500


@app.route('/pm2/logs/<name>')
@login_required
def pm2_logs(name):
    if not is_safe_name(name):
        return jsonify({'logs': 'Invalid process name'})
    result = run_cmd_safe(["pm2", "logs", name, "--lines", "50", "--nostream"])
    output = ''
    if result.stdout:
        output += result.stdout
    if result.stderr:
        output += result.stderr
    return jsonify({'logs': output})


@app.route('/ssl')
@login_required
def ssl():
    certs = get_ssl_info()
    return render_template('ssl.html', certs=certs)


@app.route('/api/ssl')
@login_required
def api_ssl():
    certs = get_ssl_info()
    return jsonify(certs)


@app.route('/ssl/renew', methods=['POST'])
@login_required
def ssl_renew():
    data = request.get_json() or {}
    domain = data.get('domain')

    if get_web_server() == 'caddy':
        # Caddy auto-manages SSL; reload to trigger renewal check
        result = run_cmd_safe(["sudo", "systemctl", "reload", "caddy"], timeout=30)
        if result.returncode == 0:
            _invalidate_cache('get_caddy_certificates')
            return jsonify({'status': 'ok', 'message': 'Caddy reloaded - certificates will auto-renew', 'output': ''})
        output = result.stderr or result.stdout or ''
        return jsonify({'status': 'error', 'message': 'Failed to reload Caddy', 'output': output}), 500

    # Nginx: certbot renewal
    if domain:
        if not is_safe_name(domain):
            return jsonify({'status': 'error', 'message': 'Invalid domain name'}), 400
        result = run_cmd_safe(
            ["sudo", "certbot", "renew", "--force-renewal", "--cert-name", domain],
            timeout=120
        )
    else:
        result = run_cmd_safe(
            ["sudo", "certbot", "renew", "--force-renewal"],
            timeout=120
        )
    output = result.stdout if result.stdout else result.stderr
    if result.returncode == 0:
        _invalidate_cache('get_ssl_certificates')
        return jsonify({'status': 'ok', 'message': 'Renewal successful', 'output': output})
    return jsonify({'status': 'error', 'message': 'Renewal failed', 'output': output}), 500


@app.route('/dns')
@login_required
def dns():
    domains = get_all_domains()
    return render_template('dns.html', domains=domains)


@app.route('/api/dns/lookup')
@login_required
def dns_lookup():
    domain = request.args.get('domain', '').strip()
    if not domain or not is_safe_name(domain):
        return jsonify({'status': 'error', 'message': 'Invalid domain'}), 400
    known = get_all_domains()
    if domain not in known:
        return jsonify({'status': 'error', 'message': 'Domain not found'}), 404
    records = get_dns_records(domain)
    return jsonify({'status': 'ok', 'records': records})


@app.route('/services')
@login_required
def services():
    svc_list = get_services_status()
    return render_template('services.html', services=svc_list)


@app.route('/services/<action>/<name>', methods=['POST'])
@login_required
def service_action(action, name):
    if action not in ('restart', 'stop', 'start'):
        return jsonify({'status': 'error', 'message': 'Invalid action'}), 400
    if not is_safe_name(name):
        return jsonify({'status': 'error', 'message': 'Invalid service name'}), 400
    result = run_cmd_safe(["sudo", "systemctl", action, name], timeout=30)
    if result.returncode == 0:
        log_audit(f'service_{action}', {'service': name})
        _invalidate_cache('get_services_status')
        return jsonify({'status': 'ok', 'message': f"'{name}' {action} successful"})
    return jsonify({'status': 'error', 'message': f"Could not {action} '{name}': {result.stderr}"}), 500


@app.route('/processes')
@login_required
def processes():
    sort = request.args.get('sort', 'mem')
    if sort not in ('mem', 'cpu'):
        sort = 'mem'
    data = get_system_processes()
    proc_list = data['processes']
    if sort == 'cpu':
        proc_list = sorted(proc_list, key=lambda p: p['cpu'], reverse=True)
    return render_template('processes.html', processes=proc_list, total=data['total'], sort=sort)


@app.route('/processes/kill/<pid>', methods=['POST'])
@login_required
def process_kill(pid):
    if not pid.isdigit():
        return jsonify({'status': 'error', 'message': 'Invalid PID'}), 400
    pid_int = int(pid)
    if pid_int <= 1 or pid_int == os.getpid():
        return jsonify({'status': 'error', 'message': 'Cannot kill this process'}), 403
    result = run_cmd_safe(["kill", "-15", pid])
    if result.returncode == 0:
        log_audit('process_kill', {'pid': pid})
        _invalidate_cache('get_system_processes')
        return jsonify({'status': 'ok', 'message': f"Signal sent to PID {pid}"})
    return jsonify({'status': 'error', 'message': f"Could not kill PID {pid}: {result.stderr}"}), 500


@app.route('/network')
@login_required
def network():
    data = get_network_info()
    return render_template('network.html', interfaces=data['interfaces'], ports=data['ports'], connections=data['connections'])


@app.route('/backup')
@login_required
def backup():
    data = get_backup_status()
    return render_template('backup.html', data=data)


@app.route('/api/backup/download')
@login_required
def backup_download():
    """Download a backup file (restricted to backup directories)"""
    path = request.args.get('path', '')
    if not path:
        return jsonify({'status': 'error', 'message': 'No path specified'}), 400

    real_path = os.path.realpath(path)
    backup_cfg = CONFIG.get('backup', {})
    backup_dir = os.path.realpath(backup_cfg.get('backup_dir') or '/var/backups/vps/')
    db_backup_dir = os.path.realpath(backup_cfg.get('db_backup_dir') or '/var/backups/vps/databases/')

    # Only allow paths within backup directories
    allowed = False
    for allowed_dir in (backup_dir, db_backup_dir):
        if real_path == allowed_dir or real_path.startswith(allowed_dir + '/'):
            allowed = True
            break

    if not allowed:
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    if os.path.isfile(real_path):
        return send_file(real_path, as_attachment=True)

    if os.path.isdir(real_path):
        # Write tar.gz to temp file instead of buffering in RAM
        import tarfile
        import tempfile
        dirname = os.path.basename(real_path)
        tmp = tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False)
        try:
            with tarfile.open(fileobj=tmp, mode='w:gz') as tar:
                tar.add(real_path, arcname=dirname)
            tmp.close()
            return send_file(tmp.name, as_attachment=True,
                             download_name=f"{dirname}.tar.gz",
                             mimetype='application/gzip')
        finally:
            # Flask sends the file, then we clean up
            @after_this_request
            def _cleanup(response):
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass
                return response

    return jsonify({'status': 'error', 'message': 'Not found'}), 404


@app.route('/ssh-logs')
@login_required
def ssh_logs_page():
    data = get_ssh_logs()
    return render_template('ssh_logs.html', data=data)


@app.route('/api/ssh-logs')
@login_required
def api_ssh_logs():
    """Get raw SSH log lines with optional filter"""
    try:
        lines = int(request.args.get('lines', 200))
    except (ValueError, TypeError):
        lines = 200
    lines = min(lines, 2000)
    filter_type = request.args.get('filter', 'all')

    if filter_type == 'failed':
        cmd = f"sudo grep -i 'failed\\|invalid user\\|authentication failure' /var/log/auth.log 2>/dev/null | tail -{lines}"
    elif filter_type == 'accepted':
        cmd = f"sudo grep -i 'accepted' /var/log/auth.log 2>/dev/null | tail -{lines}"
    elif filter_type == 'fail2ban':
        cmd = f"sudo grep -i 'fail2ban' /var/log/auth.log 2>/dev/null | tail -{lines}; sudo tail -{lines} /var/log/fail2ban.log 2>/dev/null"
    else:
        cmd = f"sudo grep 'sshd' /var/log/auth.log 2>/dev/null | tail -{lines}"

    result = run_cmd(cmd)
    if result.returncode == 0:
        return jsonify({'content': result.stdout.strip() or '(no matching log entries)'})
    return jsonify({'content': '(could not read log file)'}), 500


@app.route('/firewall')
@login_required
def firewall():
    data = get_firewall_security()
    data['ddos'] = get_ddos_stats()
    return render_template('firewall.html', data=data)


def _is_valid_ipv4(ip):
    """Validate an IPv4 address (without CIDR)"""
    return bool(re.match(
        r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$',
        ip
    ))


def _is_valid_ip_or_cidr(value):
    """Validate an IPv4 address or CIDR notation (e.g. 192.168.1.0/24)"""
    parts = value.split('/')
    if len(parts) == 1:
        return _is_valid_ipv4(parts[0])
    if len(parts) == 2:
        if not _is_valid_ipv4(parts[0]):
            return False
        try:
            prefix = int(parts[1])
            return 0 <= prefix <= 32
        except ValueError:
            return False
    return False


@app.route('/firewall/ban', methods=['POST'])
@login_required
def firewall_ban():
    """Permanently ban an IP via fail2ban + UFW"""
    data = request.get_json() or {}
    ip = data.get('ip', '').strip()
    jail = data.get('jail', 'sshd').strip()

    if not ip or not _is_valid_ipv4(ip):
        return jsonify({'status': 'error', 'message': 'Invalid IPv4 address'}), 400
    if not is_safe_name(jail):
        return jsonify({'status': 'error', 'message': 'Invalid jail name'}), 400

    # Ban in fail2ban
    result = run_cmd_safe(['sudo', 'fail2ban-client', 'set', jail, 'banip', ip], timeout=15)
    f2b_ok = result.returncode == 0
    f2b_msg = result.stdout.strip() or result.stderr.strip()

    # Add permanent UFW deny rule with timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
    ufw_result = run_cmd_safe(['sudo', 'ufw', 'deny', 'from', ip, 'comment', f'Banned via {jail} {timestamp}'], timeout=15)
    ufw_ok = ufw_result.returncode == 0
    ufw_msg = ufw_result.stdout.strip() or ufw_result.stderr.strip()

    if f2b_ok or ufw_ok:
        log_audit('firewall_ban', {'ip': ip, 'jail': jail})
    if f2b_ok and ufw_ok:
        return jsonify({'status': 'ok', 'message': f'{ip} banned in {jail} + UFW rule added'})
    elif f2b_ok:
        return jsonify({'status': 'ok', 'message': f'{ip} banned in {jail}, but UFW failed: {ufw_msg}'})
    elif ufw_ok:
        return jsonify({'status': 'ok', 'message': f'UFW rule added for {ip}, but fail2ban failed: {f2b_msg}'})
    return jsonify({'status': 'error', 'message': f'fail2ban: {f2b_msg}, UFW: {ufw_msg}'}), 500


@app.route('/firewall/unban', methods=['POST'])
@login_required
def firewall_unban():
    """Unban an IP from a fail2ban jail and remove UFW deny rule"""
    data = request.get_json() or {}
    ip = data.get('ip', '').strip()
    jail = data.get('jail', 'sshd').strip()

    if not ip or not _is_valid_ipv4(ip):
        return jsonify({'status': 'error', 'message': 'Invalid IPv4 address'}), 400
    if not is_safe_name(jail):
        return jsonify({'status': 'error', 'message': 'Invalid jail name'}), 400

    result = run_cmd_safe(['sudo', 'fail2ban-client', 'set', jail, 'unbanip', ip], timeout=15)
    f2b_ok = result.returncode == 0
    f2b_msg = result.stdout.strip() or result.stderr.strip()

    # Also remove UFW deny rule (matches the ban flow which adds both)
    ufw_result = run_cmd_safe(['sudo', 'ufw', 'delete', 'deny', 'from', ip], timeout=15)
    ufw_ok = ufw_result.returncode == 0

    if f2b_ok:
        log_audit('firewall_unban', {'ip': ip, 'jail': jail})
    if f2b_ok and ufw_ok:
        return jsonify({'status': 'ok', 'message': f'{ip} unbanned from {jail} + UFW rule removed'})
    elif f2b_ok:
        return jsonify({'status': 'ok', 'message': f'{ip} unbanned from {jail} (no UFW rule found or already removed)'})
    return jsonify({'status': 'error', 'message': f2b_msg or 'Unban failed'}), 500


@app.route('/firewall/whitelist', methods=['GET'])
@login_required
def firewall_whitelist_get():
    """Get the fail2ban ignoreip whitelist from jail.local"""
    try:
        result = run_cmd("sudo cat /etc/fail2ban/jail.local 2>/dev/null", timeout=10)
        if result.returncode != 0:
            return jsonify({'ips': []})

        for line in result.stdout.split('\n'):
            stripped = line.strip()
            if stripped.startswith('ignoreip'):
                # ignoreip = 127.0.0.1/8 ::1 10.0.0.0/24
                _, _, value = stripped.partition('=')
                ips = [v.strip() for v in value.strip().split() if v.strip()]
                return jsonify({'ips': ips})
        return jsonify({'ips': []})
    except Exception:
        return jsonify({'ips': []})


@app.route('/firewall/whitelist', methods=['POST'])
@login_required
def firewall_whitelist_set():
    """Update the fail2ban ignoreip whitelist in jail.local"""
    data = request.get_json() or {}
    ips = data.get('ips', [])

    if not isinstance(ips, list):
        return jsonify({'status': 'error', 'message': 'ips must be a list'}), 400

    # Validate each entry (allow IPv4, CIDR, and ::1 for IPv6 loopback)
    validated = []
    for entry in ips:
        entry = entry.strip()
        if not entry:
            continue
        if entry == '::1':
            validated.append(entry)
        elif _is_valid_ip_or_cidr(entry):
            validated.append(entry)
        else:
            return jsonify({'status': 'error', 'message': f'Invalid IP/CIDR: {entry}'}), 400

    ignoreip_line = 'ignoreip = ' + ' '.join(validated)

    # Read current jail.local
    result = run_cmd("sudo cat /etc/fail2ban/jail.local 2>/dev/null", timeout=10)
    if result.returncode == 0 and result.stdout.strip():
        lines = result.stdout.split('\n')
        updated = False
        new_lines = []
        for line in lines:
            if line.strip().startswith('ignoreip'):
                new_lines.append(ignoreip_line)
                updated = True
            else:
                new_lines.append(line)
        if not updated:
            # Insert ignoreip after [DEFAULT] section header
            final_lines = []
            inserted = False
            for line in new_lines:
                final_lines.append(line)
                if not inserted and line.strip() == '[DEFAULT]':
                    final_lines.append(ignoreip_line)
                    inserted = True
            if not inserted:
                final_lines.insert(0, '[DEFAULT]')
                final_lines.insert(1, ignoreip_line)
            new_lines = final_lines
        content = '\n'.join(new_lines)
    else:
        content = f'[DEFAULT]\n{ignoreip_line}\n'

    # Write via shell pipe with sudo tee
    write_result = run_cmd(
        f"echo {shlex.quote(content)} | sudo tee /etc/fail2ban/jail.local > /dev/null",
        timeout=10
    )
    if write_result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Failed to write jail.local'}), 500

    # Reload fail2ban
    reload_result = run_cmd_safe(['sudo', 'fail2ban-client', 'reload'], timeout=30)
    log_audit('firewall_whitelist', {'ips': validated})
    if reload_result.returncode == 0:
        return jsonify({'status': 'ok', 'message': f'Whitelist updated ({len(validated)} entries), fail2ban reloaded'})
    return jsonify({'status': 'ok', 'message': f'Whitelist updated but fail2ban reload failed: {reload_result.stderr.strip()}'})


@app.route('/api/firewall/ufw-rules')
@login_required
def api_ufw_rules():
    result = run_cmd("sudo ufw status numbered 2>/dev/null")
    if result.returncode == 0:
        return jsonify(parse_ufw_rules(result.stdout))
    return jsonify([])


@app.route('/firewall/ufw/add', methods=['POST'])
@login_required
def firewall_ufw_add():
    """Add a UFW rule"""
    data = request.get_json() or {}
    port = data.get('port', '').strip()
    proto = data.get('proto', 'tcp').strip().lower()
    action = data.get('action', 'allow').strip().lower()
    from_ip = data.get('from_ip', '').strip()

    # Validate action
    if action not in ('allow', 'deny'):
        return jsonify({'status': 'error', 'message': 'Action must be allow or deny'}), 400

    # Validate protocol
    if proto not in ('tcp', 'udp', 'any'):
        return jsonify({'status': 'error', 'message': 'Protocol must be tcp, udp, or any'}), 400

    # Validate port
    try:
        port_num = int(port)
        if not (1 <= port_num <= 65535):
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Port must be between 1 and 65535'}), 400

    # Build the command with comment + timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
    user_comment = data.get('comment', '').strip()
    rule_comment = f'{user_comment} ({timestamp})' if user_comment else f'Added {timestamp}'
    if from_ip and from_ip.lower() != 'anywhere':
        if not _is_valid_ip_or_cidr(from_ip):
            return jsonify({'status': 'error', 'message': 'Invalid source IP/CIDR'}), 400
        cmd = ['sudo', 'ufw', action, 'from', from_ip, 'to', 'any', 'port', port]
        if proto != 'any':
            cmd.extend(['proto', proto])
    else:
        if proto != 'any':
            cmd = ['sudo', 'ufw', action, f'{port}/{proto}']
        else:
            cmd = ['sudo', 'ufw', action, port]
    cmd.extend(['comment', rule_comment])

    result = run_cmd_safe(cmd, timeout=15)
    if result.returncode == 0:
        log_audit('ufw_add_rule', {'port': port, 'proto': proto, 'action': action, 'from': from_ip or 'anywhere'})
        return jsonify({'status': 'ok', 'message': f'UFW rule added: {action} {port}/{proto}'})
    return jsonify({'status': 'error', 'message': result.stderr.strip() or result.stdout.strip() or 'Failed to add rule'}), 500


@app.route('/firewall/ufw/delete', methods=['POST'])
@login_required
def firewall_ufw_delete():
    """Delete a UFW rule by number"""
    data = request.get_json() or {}
    rule_number = data.get('rule_number', '').strip()

    try:
        num = int(rule_number)
        if num < 1:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Invalid rule number'}), 400

    result = run_cmd_safe(['sudo', 'ufw', '--force', 'delete', str(num)], timeout=15)
    if result.returncode == 0:
        log_audit('ufw_delete_rule', {'rule_number': str(num)})
        return jsonify({'status': 'ok', 'message': f'UFW rule #{num} deleted'})
    return jsonify({'status': 'error', 'message': result.stderr.strip() or result.stdout.strip() or 'Failed to delete rule'}), 500


def lookup_ip_countries(ip_list):
    """Batch lookup country info for a list of IPs via ipwho.is (HTTPS)"""
    import urllib.request

    if not ip_list:
        return {}

    results = {}
    for ip in ip_list[:100]:  # Limit to 100 lookups
        try:
            req = urllib.request.Request(
                f'https://ipwho.is/{ip}?fields=ip,country,country_code',
                headers={'User-Agent': 'VPS-Manager'},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
            if data.get('country_code'):
                results[ip] = {
                    'country': data.get('country', ''),
                    'countryCode': data.get('country_code', ''),
                }
        except Exception:
            logger.debug('IP geo lookup failed for %s', ip, exc_info=True)

    return results


@app.route('/firewall/banned-ips')
@login_required
def firewall_banned_ips():
    """Get structured list of currently banned IPs per jail with timing info"""
    import sqlite3

    jails_data = []

    # Get list of active jails
    result = run_cmd("sudo fail2ban-client status 2>/dev/null", timeout=15)
    if result.returncode != 0:
        return jsonify([])

    jail_match = re.search(r'Jail list:\s*(.+)', result.stdout)
    if not jail_match:
        return jsonify([])

    jail_names = [j.strip() for j in jail_match.group(1).split(',') if j.strip()]

    # Read ban timing info from fail2ban SQLite database
    ban_info = {}
    db_path = '/var/lib/fail2ban/fail2ban.sqlite3'
    try:
        # Copy db to temp location (original is root-owned)
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix='.sqlite3', delete=False)
        tmp.close()
        cp_result = run_cmd_safe(['sudo', 'cp', db_path, tmp.name], timeout=5)
        chmod_result = run_cmd_safe(['sudo', 'chmod', '644', tmp.name], timeout=5)
        if cp_result.returncode == 0 and chmod_result.returncode == 0:
            conn = sqlite3.connect(tmp.name)
            now = int(time.time())
            rows = conn.execute(
                'SELECT jail, ip, timeofban, bantime, bancount FROM bans ORDER BY timeofban DESC'
            ).fetchall()
            conn.close()
            for jail, ip, timeofban, bantime, bancount in rows:
                key = f"{jail}:{ip}"
                if key not in ban_info:
                    ban_info[key] = {
                        'timeofban': timeofban,
                        'bantime': bantime,
                        'bancount': bancount,
                        'remaining': (timeofban + bantime) - now if bantime > 0 else -1,
                    }
        os.unlink(tmp.name)
    except Exception:
        logger.debug('Fail2ban parse failed', exc_info=True)

    for jail_name in jail_names:
        jail_result = run_cmd(f"sudo fail2ban-client status {shlex.quote(jail_name)} 2>/dev/null", timeout=10)
        if jail_result.returncode != 0:
            continue

        # Extract banned IP list
        ip_match = re.search(r'Banned IP list:\s*(.*)', jail_result.stdout)
        if ip_match:
            ip_str = ip_match.group(1).strip()
            ip_list = [ip.strip() for ip in ip_str.split() if ip.strip()] if ip_str else []
        else:
            ip_list = []

        ips_with_info = []
        for ip in ip_list:
            info = ban_info.get(f"{jail_name}:{ip}", {})
            entry = {'ip': ip}
            if info:
                entry['banned_at'] = datetime.fromtimestamp(info['timeofban']).strftime('%Y-%m-%d %H:%M:%S')
                entry['bancount'] = info.get('bancount', 1)
                if info['bantime'] < 0:
                    entry['duration'] = 'permanent'
                    entry['remaining'] = 'permanent'
                else:
                    entry['duration'] = info['bantime']
                    remaining = info['remaining']
                    entry['remaining'] = max(0, remaining)
            ips_with_info.append(entry)

        jails_data.append({'jail': jail_name, 'ips': ips_with_info})

    # Lookup country info for all banned IPs
    all_ips = []
    for jail_data in jails_data:
        for entry in jail_data['ips']:
            if entry['ip'] not in all_ips:
                all_ips.append(entry['ip'])

    country_map = lookup_ip_countries(all_ips)
    for jail_data in jails_data:
        for entry in jail_data['ips']:
            geo = country_map.get(entry['ip'])
            if geo:
                entry['country'] = geo['country']
                entry['countryCode'] = geo['countryCode']

    return jsonify(jails_data)


UPDATES_HISTORY_PATH = DATA_DIR / 'updates_history.json'
UPDATES_HISTORY_MAX = 100


def _save_update_history(source, status, details=''):
    """Save an update event to history (source: manual/unattended)"""
    entry = {
        'timestamp': datetime.now().isoformat(),
        'source': source,
        'status': status,
        'details': details,
    }
    try:
        history = json.loads(UPDATES_HISTORY_PATH.read_text()) if UPDATES_HISTORY_PATH.exists() else []
    except (json.JSONDecodeError, OSError):
        history = []
    history.append(entry)
    if len(history) > UPDATES_HISTORY_MAX:
        history = history[-UPDATES_HISTORY_MAX:]
    _atomic_write_json(UPDATES_HISTORY_PATH, history)


def _parse_unattended_upgrades_log():
    """Parse /var/log/unattended-upgrades/unattended-upgrades.log for recent activity"""
    log_path = '/var/log/unattended-upgrades/unattended-upgrades.log'
    entries = []
    # Only read last 500 lines instead of entire file to limit memory usage
    result = run_cmd_safe(['tail', '-500', log_path], timeout=5)
    if result.returncode != 0:
        return entries
    lines = result.stdout.split('\n')

    current_date = None
    current_packages = []
    for line in lines:
        line = line.strip()
        # Lines look like: 2025-01-15 06:25:04,123 INFO Packages that will be upgraded: pkg1 pkg2
        # or: 2025-01-15 06:25:30,456 INFO All upgrades installed
        if not line:
            continue
        # Extract date from log line
        if len(line) > 19 and line[4] == '-' and line[10] == ' ':
            date_str = line[:19]
            msg = line[24:] if len(line) > 24 else ''  # Skip past log level

            if 'INFO' in line and 'Packages that will be upgraded:' in line:
                parts = line.split('Packages that will be upgraded:')
                if len(parts) > 1:
                    current_packages = [p.strip() for p in parts[1].strip().split() if p.strip()]
                    current_date = date_str[:10]

            elif 'INFO' in line and 'All upgrades installed' in line:
                entries.append({
                    'timestamp': date_str.replace(',', '.'),
                    'source': 'unattended',
                    'status': 'success',
                    'details': f"{len(current_packages)} packages: {', '.join(current_packages[:10])}{'...' if len(current_packages) > 10 else ''}",
                })
                current_packages = []

            elif 'ERROR' in line or 'WARNING' in line:
                if 'dpkg' in line.lower() or 'upgrade' in line.lower() or 'fail' in line.lower():
                    entries.append({
                        'timestamp': date_str.replace(',', '.'),
                        'source': 'unattended',
                        'status': 'failure',
                        'details': msg[:150],
                    })

    return entries[-20:]  # Last 20 entries


@app.route('/api/updates/history')
@login_required
def updates_history():
    # Combine manual history with unattended-upgrades log
    try:
        manual = json.loads(UPDATES_HISTORY_PATH.read_text()) if UPDATES_HISTORY_PATH.exists() else []
    except (json.JSONDecodeError, OSError):
        manual = []

    unattended = _parse_unattended_upgrades_log()
    combined = manual + unattended
    combined.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return jsonify(combined[:50])


@app.route('/updates')
@login_required
def updates():
    update_list = get_system_updates()
    return render_template('updates.html', updates=update_list)


_apt_lock = threading.Lock()


@app.route('/updates/install', methods=['POST'])
@login_required
def install_updates():
    if not _apt_lock.acquire(blocking=False):
        return jsonify({'status': 'error', 'message': 'Another update operation is already running'}), 409
    try:
        run_cmd("sudo apt update 2>&1", timeout=120)
        result = run_cmd("sudo apt upgrade -y 2>&1", timeout=300)
        _invalidate_cache('get_system_updates')
        if result.returncode == 0:
            log_audit('system_updates_install', {'output': result.stdout[-200:]})
            _save_update_history('manual', 'success', result.stdout[-200:])
            return jsonify({'status': 'ok', 'message': 'Updates installed', 'output': result.stdout[-500:]})
        log_audit('system_updates_install_failed', {'error': result.stderr[-200:]})
        _save_update_history('manual', 'failure', result.stderr[-200:])
        return jsonify({'status': 'error', 'message': 'Installation error', 'output': result.stderr[-500:]}), 500
    finally:
        _apt_lock.release()


# ---------------------------------------------------------------------------
# VPS Manager self-update (GitHub releases)
# ---------------------------------------------------------------------------

@app.route('/api/update/check')
@login_required
def update_check():
    """Check GitHub for the latest release and compare with current version"""
    import urllib.request

    current = _get_current_version()
    url = 'https://api.github.com/repos/martijnrenkema/vps-manager/releases/latest'
    req = urllib.request.Request(url, headers={
        'User-Agent': 'VPS-Manager/' + current,
        'Accept': 'application/vnd.github.v3+json',
    })

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Could not reach GitHub: {e}'}), 502

    latest = data.get('tag_name', '').lstrip('v')
    if not latest:
        return jsonify({'status': 'error', 'message': 'No releases found'}), 404

    return jsonify({
        'current_version': current,
        'latest_version': latest,
        'update_available': latest != current,
        'release_notes': data.get('body', ''),
        'published_at': data.get('published_at', ''),
    })


@app.route('/api/update/install', methods=['POST'])
@login_required
def update_install():
    """Pull latest code from GitHub and restart the PM2 process"""
    if not _apt_lock.acquire(blocking=False):
        return jsonify({'status': 'error', 'message': 'Another update operation is already running'}), 409
    try:
        return _do_update_install()
    finally:
        _apt_lock.release()


def _do_update_install():
    current_before = _get_current_version()

    # Fetch and reset to origin/main
    result = run_cmd(
        f"git -C {APP_DIR} fetch origin main && git -C {APP_DIR} reset --hard origin/main",
        timeout=60
    )
    if result.returncode != 0:
        return jsonify({
            'status': 'error',
            'message': 'Git pull failed',
            'output': (result.stderr or result.stdout)[-500:],
        }), 500

    # Copy web/ files to app root (repo has files in web/ subfolder,
    # but PM2 runs from the repo root directory)
    copy_ok = True
    web_src = os.path.join(APP_DIR, 'web')
    if os.path.isdir(web_src):
        copy_result = run_cmd(
            f"cp -r {web_src}/app.py {web_src}/config.py {web_src}/VERSION "
            f"{web_src}/requirements.txt {web_src}/vps-backup.sh {APP_DIR}/ 2>&1 && "
            f"cp -r {web_src}/templates/* {APP_DIR}/templates/ 2>&1 && "
            f"cp -r {web_src}/static/* {APP_DIR}/static/ 2>&1",
            timeout=15
        )
        if copy_result.returncode != 0:
            copy_ok = False

    # Read the new version from the freshly copied VERSION file
    new_version = _get_current_version()

    # Restart PM2 process
    pm2_result = run_cmd_safe(["pm2", "restart", "vps-manager"], timeout=15)
    restart_ok = pm2_result.returncode == 0

    warnings = []
    if not copy_ok:
        warnings.append('file copy failed')
    if not restart_ok:
        warnings.append('restart pending')

    log_audit('self_update', {'from': current_before, 'to': new_version})
    _invalidate_cache('check_app_update_alert', 'get_pm2_processes')
    return jsonify({
        'status': 'ok' if copy_ok else 'warning',
        'message': 'Update installed' + (f' ({", ".join(warnings)})' if warnings else ''),
        'previous_version': current_before,
        'new_version': new_version,
        'restart': 'ok' if restart_ok else 'failed',
        'copy': 'ok' if copy_ok else 'failed',
        'output': result.stdout[-500:],
    })


def _delayed_restart(delay=1.5):
    """Restart PM2 process after a delay (so SSE response can flush)"""
    time.sleep(delay)
    run_cmd_safe(["pm2", "restart", "vps-manager"], timeout=15)


@app.route('/api/update/install-token', methods=['POST'])
@login_required
def update_install_token():
    """Generate a one-time token for the SSE update stream (CSRF-protected POST)"""
    import secrets
    token = secrets.token_urlsafe(32)
    session['update_stream_token'] = token
    return jsonify({'token': token})


@app.route('/api/update/install-stream')
@login_required
def update_install_stream():
    """SSE endpoint that streams update progress step by step (token-protected)"""
    token = request.args.get('token', '')
    expected = session.pop('update_stream_token', None)
    if not token or token != expected:
        def denied():
            yield f"data: {json.dumps({'type': 'error', 'message': 'Invalid or expired token'})}\n\n"
        return Response(denied(), mimetype='text/event-stream')

    if not _apt_lock.acquire(blocking=False):
        def error_stream():
            yield f"data: {json.dumps({'type': 'error', 'message': 'Another update operation is already running'})}\n\n"
        return Response(error_stream(), mimetype='text/event-stream')

    def generate():
        import json as _json

        def send_event(data):
            return f"data: {_json.dumps(data)}\n\n"

        steps = [
            'Downloading from GitHub',
            'Installing update files',
            'Checking dependencies',
            'Clearing cache',
            'Restarting application',
        ]
        current_before = _get_current_version()
        error_occurred = False

        # Step 1: git fetch
        yield send_event({'step': 1, 'name': steps[0], 'status': 'running', 'output': ''})
        result = run_cmd(f"git -C {APP_DIR} fetch origin main", timeout=60)
        if result.returncode != 0:
            yield send_event({'step': 1, 'name': steps[0], 'status': 'error', 'output': (result.stderr or result.stdout)[-300:]})
            for i in range(2, 6):
                yield send_event({'step': i, 'name': steps[i - 1], 'status': 'skipped', 'output': ''})
            yield send_event({'type': 'error', 'message': 'Git fetch failed'})
            return
        yield send_event({'step': 1, 'name': steps[0], 'status': 'done', 'output': result.stdout[-200:]})

        # Step 2: reset + copy files
        yield send_event({'step': 2, 'name': steps[1], 'status': 'running', 'output': ''})
        reset = run_cmd(f"git -C {APP_DIR} reset --hard origin/main", timeout=30)
        if reset.returncode != 0:
            yield send_event({'step': 2, 'name': steps[1], 'status': 'error', 'output': (reset.stderr or reset.stdout)[-300:]})
            error_occurred = True
        else:
            copy_output = ''
            web_src = os.path.join(APP_DIR, 'web')
            if os.path.isdir(web_src):
                copy_result = run_cmd(
                    f"cp -r {web_src}/app.py {web_src}/config.py {web_src}/VERSION "
                    f"{web_src}/requirements.txt {web_src}/vps-backup.sh {APP_DIR}/ 2>&1 && "
                    f"cp -r {web_src}/templates/* {APP_DIR}/templates/ 2>&1 && "
                    f"cp -r {web_src}/static/* {APP_DIR}/static/ 2>&1",
                    timeout=15
                )
                if copy_result.returncode != 0:
                    error_occurred = True
                    copy_output = copy_result.stderr or copy_result.stdout
                    yield send_event({'step': 2, 'name': steps[1], 'status': 'error', 'output': copy_output[-200:]})
                else:
                    yield send_event({'step': 2, 'name': steps[1], 'status': 'done', 'output': 'Files copied'})
            else:
                yield send_event({'step': 2, 'name': steps[1], 'status': 'done', 'output': 'No web/ subfolder, skipped copy'})

        # Step 3: pip install (check if requirements changed)
        yield send_event({'step': 3, 'name': steps[2], 'status': 'running', 'output': ''})
        pip_result = run_cmd(
            f"cd {APP_DIR} && venv/bin/pip install -r requirements.txt --quiet 2>&1",
            timeout=120
        )
        if pip_result.returncode != 0:
            yield send_event({'step': 3, 'name': steps[2], 'status': 'error', 'output': (pip_result.stderr or pip_result.stdout)[-200:]})
        else:
            output = pip_result.stdout.strip()
            yield send_event({'step': 3, 'name': steps[2], 'status': 'done', 'output': output[-200:] if output else 'All dependencies satisfied'})

        # Step 4: clear cache + read new version
        yield send_event({'step': 4, 'name': steps[3], 'status': 'running', 'output': ''})
        _invalidate_cache('check_app_update_alert', 'get_pm2_processes')
        new_version = _get_current_version()
        yield send_event({'step': 4, 'name': steps[3], 'status': 'done', 'output': f'v{current_before} → v{new_version}'})

        # Step 5: audit log + restart
        yield send_event({'step': 5, 'name': steps[4], 'status': 'running', 'output': ''})
        log_audit('self_update', {'from': current_before, 'to': new_version})
        _save_update_history('self-update', 'success' if not error_occurred else 'warning',
                             f'v{current_before} → v{new_version}')
        yield send_event({'step': 5, 'name': steps[4], 'status': 'done', 'output': 'Restarting...'})

        # Send complete event before restart
        yield send_event({'type': 'complete', 'previous_version': current_before, 'new_version': new_version})

        # Schedule delayed restart so the SSE response can flush
        t = threading.Thread(target=_delayed_restart, daemon=True)
        t.start()

    def generate_with_lock():
        try:
            yield from generate()
        finally:
            _apt_lock.release()

    return Response(
        generate_with_lock(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        }
    )


@app.route('/web-logs')
@app.route('/nginx-logs')
@login_required
def nginx_logs_page():
    ws = get_web_server()
    data = get_web_logs()
    template = 'caddy_logs.html' if ws == 'caddy' else 'nginx_logs.html'
    return render_template(template, data=data)


@app.route('/api/web-log')
@app.route('/api/nginx-log')
@login_required
def api_nginx_log():
    """Get content of a specific web server log file for a site"""
    site = request.args.get('site', '')
    log_type = request.args.get('type', 'error')  # 'error' or 'access'
    ws = get_web_server()
    try:
        lines = int(request.args.get('lines', 100))
    except (ValueError, TypeError):
        lines = 100
    lines = min(lines, 500)

    # Allowed log directories per web server
    allowed_log_dirs = ('/var/log/caddy/',) if ws == 'caddy' else ('/var/log/nginx/',)

    if site:
        # Find site-specific log path
        log_path = None
        for s in get_sites():
            if site in s.get('domains', []):
                log_path = s.get('access_log') if log_type == 'access' else s.get('error_log')
                break
        if log_path:
            real_log = os.path.realpath(log_path)
            if not any(real_log.startswith(d) for d in allowed_log_dirs):
                return jsonify({'status': 'error', 'message': 'Invalid log path'}), 400
            result = run_cmd_safe(["sudo", "tail", f"-{lines}", real_log])
            if result.returncode == 0:
                content = result.stdout.strip() if result.stdout.strip() else f'(no {log_type} logs for this site)'
                return jsonify({'content': content, 'site': site, 'type': log_type})
            return jsonify({'status': 'error', 'message': 'Could not read log file'}), 500
        # Fallback: filter global error log
        if ws == 'caddy':
            caddy_cfg = CONFIG.get('caddy', {})
            error_log = caddy_cfg.get('error_log', '/var/log/caddy/error.log')
        else:
            nginx_cfg = CONFIG.get('nginx', {})
            error_log = nginx_cfg.get('error_log', '/var/log/nginx/error.log')
        result = run_cmd_safe(["sudo", "tail", "-2000", error_log])
        if result.returncode == 0:
            filtered = [l for l in result.stdout.split('\n') if site in l]
            content = '\n'.join(filtered[-lines:]) if filtered else '(no errors for this site)'
            return jsonify({'content': content, 'site': site, 'type': log_type})
        return jsonify({'status': 'error', 'message': 'Could not read error log'}), 500
    # Legacy: read specific file by path
    log_file = request.args.get('file', '')
    if not log_file or '..' in log_file:
        return jsonify({'status': 'error', 'message': 'Invalid log file'}), 400
    real_log = os.path.realpath(log_file)
    if not any(real_log.startswith(d) for d in allowed_log_dirs):
        return jsonify({'status': 'error', 'message': 'Invalid log file'}), 400
    result = run_cmd_safe(["sudo", "tail", f"-{lines}", real_log])
    if result.returncode == 0:
        return jsonify({'content': result.stdout, 'file': os.path.basename(real_log)})
    return jsonify({'status': 'error', 'message': 'Could not read log file'}), 500


@app.route('/databases')
@login_required
def databases():
    db_list = get_database_info()
    return render_template('databases.html', databases=db_list, phpmyadmin_path=CONFIG.get('phpmyadmin_path', '/phpmyadmin/'))


@app.route('/php')
@login_required
def php():
    data = get_php_info()
    return render_template('php.html', versions=data['versions'], site_mapping=data['site_mapping'])


@app.route('/php/restart/<version>', methods=['POST'])
@login_required
def php_restart(version):
    if not re.match(r'^\d+\.\d+$', version):
        return jsonify({'status': 'error', 'message': 'Invalid PHP version'}), 400
    result = run_cmd_safe(["sudo", "systemctl", "restart", f"php{version}-fpm"], timeout=30)
    if result.returncode == 0:
        log_audit('php_fpm_restart', {'version': version})
        _invalidate_cache('get_php_info')
        return jsonify({'status': 'ok', 'message': f"PHP {version}-FPM restarted"})
    return jsonify({'status': 'error', 'message': f"Could not restart PHP {version}-FPM: {result.stderr}"}), 500


@app.route('/cronjobs')
@login_required
def cronjobs():
    return render_template('cronjobs.html')


@app.route('/disk')
@login_required
def disk():
    sites, total = get_disk_per_site()
    return render_template('disk.html', sites=sites, total=total)


@app.route('/terminal')
@login_required
def terminal():
    session.setdefault('terminal_cwd', '/')
    result = run_cmd("whoami", timeout=5)
    sys_user = result.stdout.strip() if result.returncode == 0 else 'user'
    result = run_cmd("hostname -s", timeout=5)
    sys_host = result.stdout.strip() if result.returncode == 0 else 'vps'
    return render_template('terminal.html', cwd=session['terminal_cwd'], sys_user=sys_user, sys_host=sys_host)


@app.route('/terminal/exec', methods=['POST'])
@login_required
def terminal_exec():
    data = request.get_json() or {}
    cmd = data.get('command', '').strip()
    cwd = session.get('terminal_cwd', '/')

    if not cmd:
        return jsonify({'stdout': '', 'stderr': 'No command specified', 'cwd': cwd})

    # Handle 'clear' locally (before validation)
    if cmd.strip() == 'clear':
        return jsonify({'stdout': '', 'stderr': '', 'cwd': cwd, 'clear': True})

    # Validate cwd is a real directory
    real_cwd = os.path.realpath(cwd)
    if not os.path.isdir(real_cwd):
        real_cwd = '/'

    # --- Allowlist: check every segment's first command ---
    # Block subshell escapes: backticks, $(...), $(( patterns
    if '`' in cmd or '$(' in cmd:
        log_audit('terminal_blocked', {'command': cmd[:200], 'reason': 'subshell escape'})
        return jsonify({'stdout': '', 'stderr': 'Blocked: subshell expressions not allowed', 'cwd': real_cwd})

    # Block all output redirection (>, >>) to prevent arbitrary file writes
    if '>' in cmd:
        log_audit('terminal_blocked', {'command': cmd[:200], 'reason': 'output redirection'})
        return jsonify({'stdout': '', 'stderr': 'Blocked: output redirection not allowed. Use the File Editor to write files.', 'cwd': real_cwd})

    # Split on all shell operators: |, &&, ||, ;
    pipe_segments = re.split(r'\|{1,2}|&&|;', cmd)
    for segment in pipe_segments:
        segment = segment.strip()
        if not segment:
            continue
        # Strip leading 'sudo' to check the actual command
        check = segment
        if check.startswith('sudo '):
            check = check[5:].strip()
        try:
            tokens = shlex.split(check)
        except ValueError:
            tokens = check.split()
        if not tokens:
            continue
        base_cmd = os.path.basename(tokens[0])
        if base_cmd not in TERMINAL_ALLOWED_COMMANDS:
            log_audit('terminal_blocked', {'command': cmd[:200], 'reason': f'not in allowlist: {base_cmd}'})
            return jsonify({'stdout': '', 'stderr': f'Blocked: command not allowed: {base_cmd}', 'cwd': real_cwd})

    # Block dangerous patterns (defense-in-depth, extra layer on top of allowlist)
    cmd_lower = cmd.lower()
    dangerous_strings = [
        'rm -rf /', 'rm -rf /*', 'rm -rf ~', 'rm -rf .', 'rm -rf *',
        'mkfs', 'dd if=', '> /dev/', 'chmod -r 777 /', 'chmod 777 /',
        ':(){ :|:& };:', '.(){.|.&};.',
        'shred', 'wipefs',
    ]
    dangerous_patterns = [
        r'\bpython[23]?\b.*-c\b',      # python -c 'os.system(...)'
        r'\bperl\b.*-e\b',             # perl -e 'system(...)'
        r'curl\b.*\|\s*\bsh\b',        # curl ... | sh
        r'wget\b.*\|\s*\bsh\b',        # wget ... | sh
        r'curl\b.*\|\s*\bbash\b',      # curl ... | bash
        r'wget\b.*\|\s*\bbash\b',      # wget ... | bash
        r'\beval\b',                    # eval
        r'>\s*/etc/',                   # write to /etc
        r'\bpasswd\b',                  # passwd changes
        r'\buserdel\b',                 # delete users
        r'\buseradd\b',                 # add users
        r'\bvisudo\b',                  # sudoers changes
        r'\bshutdown\b',               # shutdown
        r'\binit\s+[06]\b',            # init 0/6
    ]
    for pattern in dangerous_strings:
        if pattern in cmd_lower:
            log_audit('terminal_blocked', {'command': cmd[:200], 'reason': 'dangerous string'})
            return jsonify({'stdout': '', 'stderr': 'Blocked: dangerous command', 'cwd': real_cwd})
    for pattern in dangerous_patterns:
        if re.search(pattern, cmd_lower):
            log_audit('terminal_blocked', {'command': cmd[:200], 'reason': 'dangerous pattern'})
            return jsonify({'stdout': '', 'stderr': 'Blocked: dangerous command', 'cwd': real_cwd})

    # Run the command from the current working directory, then capture new cwd
    # This way cd, pushd, etc. all work naturally
    # cwd is shell-quoted to prevent injection through manipulated session values
    wrapped = f'cd {shlex.quote(real_cwd)} 2>/dev/null && {cmd} 2>&1; echo "---CWD---"; pwd'
    result = run_cmd(wrapped, timeout=30)

    output = result.stdout
    new_cwd = cwd

    # Extract the new cwd from the output
    if '---CWD---' in output:
        parts = output.rsplit('---CWD---', 1)
        output = parts[0].rstrip('\n')
        new_cwd = parts[1].strip()

    # Update session
    session['terminal_cwd'] = new_cwd

    return jsonify({
        'stdout': output,
        'stderr': '',
        'cwd': new_cwd,
    })


@app.route('/files')
@login_required
def files():
    return render_template('files.html')


@app.route('/files/list')
@login_required
def files_list():
    default_path = CONFIG.get('file_browser', {}).get('default_path', '/var/www')
    path = request.args.get('path', default_path)
    norm_path = os.path.abspath(path)

    if not os.path.isdir(norm_path):
        return jsonify({'status': 'error', 'message': 'Directory not found'}), 404

    if not is_path_allowed(norm_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    # Get owner/permissions of current directory
    dir_info = {}
    try:
        dir_stat = os.stat(norm_path)
        try:
            dir_info['owner'] = pwd.getpwuid(dir_stat.st_uid).pw_name
        except KeyError:
            dir_info['owner'] = str(dir_stat.st_uid)
        try:
            dir_info['group'] = grp.getgrgid(dir_stat.st_gid).gr_name
        except KeyError:
            dir_info['group'] = str(dir_stat.st_gid)
        dir_info['mode'] = oct(stat_module.S_IMODE(dir_stat.st_mode))
        dir_info['writable'] = os.access(norm_path, os.W_OK)
    except OSError:
        dir_info = {'owner': '?', 'group': '?', 'mode': '?', 'writable': False}

    items = []
    try:
        entries = sorted(os.listdir(norm_path))
    except PermissionError:
        # Fallback: use sudo find for directories we don't have read access to
        result = run_cmd_safe(['sudo', 'find', norm_path, '-maxdepth', '1', '-mindepth', '1',
                               '-printf', '%f\\t%y\\t%U\\t%s\\t%T@\\t%#m\\n'], timeout=10)
        if result.returncode != 0:
            return jsonify({'status': 'error', 'message': 'No read permissions on this directory'}), 403
        entries = None
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) < 6:
                continue
            fname, ftype, fowner, fsize, ftime, fmode = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
            is_dir = ftype == 'd'
            try:
                modified = datetime.fromtimestamp(float(ftime)).strftime('%Y-%m-%d %H:%M')
            except (ValueError, OSError):
                modified = '-'
            items.append({
                'name': fname,
                'type': 'dir' if is_dir else 'file',
                'size': '-' if is_dir else format_file_size(int(fsize)) if fsize.isdigit() else fsize,
                'modified': modified,
                'owner': fowner,
                'mode': fmode,
            })

    if entries is not None:
        for name in entries:
            full = os.path.join(norm_path, name)
            try:
                st = os.stat(full)
                is_dir = os.path.isdir(full)
                modified = datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M')
                try:
                    item_owner = pwd.getpwuid(st.st_uid).pw_name
                except KeyError:
                    item_owner = str(st.st_uid)
                items.append({
                    'name': name,
                    'type': 'dir' if is_dir else 'file',
                    'size': '-' if is_dir else format_file_size(st.st_size),
                    'modified': modified,
                    'owner': item_owner,
                    'mode': oct(stat_module.S_IMODE(st.st_mode)),
                })
            except (OSError, PermissionError):
                # Fallback: try lstat to determine type (works for symlinks where stat fails)
                item_type = 'unknown'
                try:
                    lst = os.lstat(full)
                    if stat_module.S_ISDIR(lst.st_mode):
                        item_type = 'dir'
                    elif stat_module.S_ISLNK(lst.st_mode):
                        item_type = 'dir' if os.path.isdir(full) else 'file'
                    else:
                        item_type = 'file'
                except OSError:
                    pass
                items.append({
                    'name': name,
                    'type': item_type,
                    'size': '-',
                    'modified': '-',
                    'owner': '?',
                    'mode': '?',
                })

    # Sort: dirs first, then files
    items.sort(key=lambda x: (0 if x['type'] == 'dir' else 1, x['name'].lower()))

    parent_path = os.path.dirname(norm_path)
    parent = parent_path if (norm_path != '/' and is_path_allowed(parent_path)) else None

    return jsonify({
        'path': norm_path,
        'parent': parent,
        'items': items,
        'dir_info': dir_info,
    })


@app.route('/files/mkdir', methods=['POST'])
@login_required
def files_mkdir():
    data = request.get_json() or {}
    path = data.get('path', '')
    name = data.get('name', '').strip()

    if not name or '/' in name or name.startswith('.'):
        return jsonify({'status': 'error', 'message': 'Invalid folder name'}), 400

    norm_path = os.path.abspath(os.path.join(path, name))
    if not is_path_allowed(norm_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    try:
        os.makedirs(norm_path, exist_ok=False)
        log_audit('file_mkdir', {'path': norm_path})
        return jsonify({'status': 'ok', 'message': f"Folder '{name}' created"})
    except FileExistsError:
        return jsonify({'status': 'error', 'message': 'Folder already exists'}), 400
    except OSError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/files/download')
@login_required
def files_download():
    path = request.args.get('path', '')
    norm_path = os.path.abspath(path)

    if not is_path_allowed(norm_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    if os.path.isfile(norm_path):
        return send_file(norm_path, as_attachment=True)

    if os.path.isdir(norm_path):
        import tarfile
        import tempfile
        dirname = os.path.basename(norm_path)
        tmp = tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False)
        try:
            with tarfile.open(fileobj=tmp, mode='w:gz') as tar:
                tar.add(norm_path, arcname=dirname)
            tmp.close()
            return send_file(tmp.name, as_attachment=True,
                             download_name=f"{dirname}.tar.gz",
                             mimetype='application/gzip')
        finally:
            @after_this_request
            def _cleanup(response):
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass
                return response

    return jsonify({'status': 'error', 'message': 'Not found'}), 404


@app.route('/files/upload', methods=['POST'])
@login_required
def files_upload():
    path = request.form.get('path', '/var/www')
    norm_path = os.path.abspath(path)

    if not is_path_allowed(norm_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    if not os.path.isdir(norm_path):
        return jsonify({'status': 'error', 'message': 'Directory not found'}), 404

    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file received'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file selected'}), 400

    filename = secure_filename(file.filename)
    if not filename:
        return jsonify({'status': 'error', 'message': 'Invalid filename'}), 400
    dest = os.path.join(norm_path, filename)

    try:
        file.save(dest)
        log_audit('file_upload', {'path': dest})
        return jsonify({'status': 'ok', 'message': f"'{filename}' uploaded"})
    except OSError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/files/delete', methods=['POST'])
@login_required
def files_delete():
    data = request.get_json() or {}
    path = data.get('path', '')
    norm_path = os.path.abspath(path)

    if not is_path_allowed(norm_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    if norm_path in ('/', '/var', '/var/www', '/etc', '/home', '/root'):
        return jsonify({'status': 'error', 'message': 'Cannot delete system directory'}), 403

    try:
        if os.path.isdir(norm_path):
            shutil.rmtree(norm_path)
            log_audit('file_delete', {'path': norm_path, 'type': 'dir'})
            return jsonify({'status': 'ok', 'message': 'Folder deleted'})
        elif os.path.isfile(norm_path):
            os.remove(norm_path)
            log_audit('file_delete', {'path': norm_path, 'type': 'file'})
            return jsonify({'status': 'ok', 'message': 'File deleted'})
        else:
            return jsonify({'status': 'error', 'message': 'Path not found'}), 404
    except OSError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/files/chown', methods=['POST'])
@login_required
def files_chown():
    """Change ownership of a file or directory"""
    data = request.get_json() or {}
    path = data.get('path', '')
    owner = data.get('owner', 'martijn')
    group = data.get('group', '')
    recursive = data.get('recursive', False)

    norm_path = os.path.abspath(path)
    if not is_path_allowed(norm_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    # Validate owner/group names
    if not re.match(r'^[a-zA-Z0-9._-]+$', owner):
        return jsonify({'status': 'error', 'message': 'Invalid owner name'}), 400
    if group and not re.match(r'^[a-zA-Z0-9._-]+$', group):
        return jsonify({'status': 'error', 'message': 'Invalid group name'}), 400

    ownership = f"{owner}:{group}" if group else owner
    cmd = ['sudo', 'chown']
    if recursive:
        cmd.append('-R')
    cmd.extend([ownership, norm_path])

    result = run_cmd_safe(cmd, timeout=30)
    if result.returncode == 0:
        log_audit('file_chown', {'path': norm_path, 'owner': ownership, 'recursive': recursive})
        label = 'recursively ' if recursive else ''
        return jsonify({'status': 'ok', 'message': f'Ownership {label}changed to {ownership}'})
    return jsonify({'status': 'error', 'message': result.stderr.strip() or 'chown failed'}), 500


@app.route('/files/chmod', methods=['POST'])
@login_required
def files_chmod():
    """Change permissions of a file or directory"""
    data = request.get_json() or {}
    path = data.get('path', '')
    mode = data.get('mode', '').strip()
    recursive = data.get('recursive', False)

    norm_path = os.path.abspath(path)
    if not is_path_allowed(norm_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    if not re.match(r'^[0-7]{3,4}$', mode):
        return jsonify({'status': 'error', 'message': 'Invalid mode (use octal like 755)'}), 400

    cmd = ['sudo', 'chmod']
    if recursive:
        cmd.append('-R')
    cmd.extend([mode, norm_path])

    result = run_cmd_safe(cmd, timeout=30)
    if result.returncode == 0:
        log_audit('file_chmod', {'path': norm_path, 'mode': mode, 'recursive': recursive})
        label = 'recursively ' if recursive else ''
        return jsonify({'status': 'ok', 'message': f'Permissions {label}changed to {mode}'})
    return jsonify({'status': 'error', 'message': result.stderr.strip() or 'chmod failed'}), 500


@app.route('/files/users')
@login_required
def files_users():
    """Get list of system users and groups relevant for web files"""
    users = []
    for name in ['martijn', 'www-data', 'root', 'nobody']:
        try:
            pwd.getpwnam(name)
            users.append(name)
        except KeyError:
            pass
    groups = []
    for name in ['martijn', 'www-data', 'root', 'nogroup']:
        try:
            grp.getgrnam(name)
            groups.append(name)
        except KeyError:
            pass
    return jsonify({'users': users, 'groups': groups})


# ---------------------------------------------------------------------------
# Push Notification routes
# ---------------------------------------------------------------------------

@app.route('/notifications')
@login_required
def notifications():
    return render_template('notifications.html')


@app.route('/api/push/vapid-key')
@login_required
def vapid_key():
    public_key, _ = _get_vapid_keys()
    return jsonify({'public_key': public_key})


@app.route('/api/push/subscribe', methods=['POST'])
@login_required
def push_subscribe():
    data = request.get_json() or {}
    if 'endpoint' not in data or 'keys' not in data:
        return jsonify({'status': 'error', 'message': 'Invalid subscription data'}), 400

    subs = _load_subscriptions()

    # Preserve existing preferences/label when re-subscribing same endpoint
    existing = next((s for s in subs if s.get('endpoint') == data['endpoint']), None)
    old_prefs = existing.get('preferences') if existing else None
    old_label = existing.get('label', '') if existing else ''

    subs = [s for s in subs if s.get('endpoint') != data['endpoint']]
    subs.append({
        'endpoint': data['endpoint'],
        'keys': data['keys'],
        'label': data.get('label') or old_label or '',
        'user_agent': request.headers.get('User-Agent', ''),
        'preferences': old_prefs or {
            'critical': True,
            'warnings': True,
            'updates': False,
            'security': True,
            'ddos': True,
            'backup': True,
        },
        'created': datetime.now().isoformat(),
    })
    _save_subscriptions(subs)
    return jsonify({'status': 'ok', 'message': 'Subscription registered'})


@app.route('/api/push/unsubscribe', methods=['POST'])
@login_required
def push_unsubscribe():
    data = request.get_json() or {}
    endpoint = data.get('endpoint')
    if not endpoint:
        return jsonify({'status': 'error', 'message': 'Missing endpoint'}), 400

    subs = _load_subscriptions()
    subs = [s for s in subs if s.get('endpoint') != endpoint]
    _save_subscriptions(subs)
    return jsonify({'status': 'ok', 'message': 'Unsubscribed'})


@app.route('/api/push/test', methods=['POST'])
@login_required
def push_test():
    data = request.get_json() or {}
    endpoint = data.get('endpoint')
    if not endpoint:
        return jsonify({'status': 'error', 'message': 'Missing endpoint'}), 400

    subs = _load_subscriptions()
    sub = next((s for s in subs if s.get('endpoint') == endpoint), None)
    if not sub:
        return jsonify({'status': 'error', 'message': 'Subscription not found'}), 404

    _, private_key_pem = _get_vapid_keys()
    payload = {
        'title': 'VPS Manager - Test',
        'body': 'Push notifications are working!',
        'tag': 'test',
        'url': '/notifications',
    }

    result = _send_push({'endpoint': sub['endpoint'], 'keys': sub['keys']}, payload, private_key_pem)
    if result is False:
        subs = [s for s in subs if s.get('endpoint') != endpoint]
        _save_subscriptions(subs)
        return jsonify({'status': 'error', 'message': 'Subscription expired'}), 410
    if result is None:
        return jsonify({'status': 'error', 'message': 'Push failed (transient error)'}), 502

    _add_notification_history(payload['title'], payload['body'], 'test')
    return jsonify({'status': 'ok', 'message': 'Test notification sent'})


@app.route('/api/push/preferences', methods=['GET', 'POST'])
@login_required
def push_preferences():
    if request.method == 'GET':
        endpoint = request.args.get('endpoint')
        if not endpoint:
            return jsonify({'status': 'error', 'message': 'Missing endpoint'}), 400

        subs = _load_subscriptions()
        sub = next((s for s in subs if s.get('endpoint') == endpoint), None)
        if not sub:
            return jsonify({'critical': True, 'warnings': True, 'updates': False, 'security': True, 'ddos': True, 'backup': True})

        return jsonify(sub.get('preferences', {
            'critical': True, 'warnings': True, 'updates': False, 'security': True, 'ddos': True, 'backup': True,
        }))

    # POST
    data = request.get_json() or {}
    endpoint = data.get('endpoint')
    if not endpoint:
        return jsonify({'status': 'error', 'message': 'Missing endpoint'}), 400

    subs = _load_subscriptions()
    for sub in subs:
        if sub.get('endpoint') == endpoint:
            sub['preferences'] = {
                'critical': bool(data.get('critical', True)),
                'warnings': bool(data.get('warnings', True)),
                'updates': bool(data.get('updates', False)),
                'security': bool(data.get('security', True)),
                'ddos': bool(data.get('ddos', True)),
                'backup': bool(data.get('backup', True)),
                'app_update': bool(data.get('app_update', True)),
            }
            break
    _save_subscriptions(subs)
    return jsonify({'status': 'ok', 'message': 'Preferences saved'})


@app.route('/api/push/subscriptions')
@login_required
def push_subscriptions_list():
    """Return all active subscriptions with metadata (endpoint masked)."""
    subs = _load_subscriptions()
    result = []
    for s in subs:
        ep = s.get('endpoint', '')
        # Mask endpoint for display: show provider + last 8 chars
        if 'mozilla.com' in ep or 'push.services.mozilla' in ep:
            provider = 'Firefox'
        elif 'fcm.googleapis.com' in ep:
            provider = 'Chrome/Edge'
        elif 'windows.com' in ep or 'wns' in ep:
            provider = 'Edge'
        else:
            provider = 'Unknown'
        masked = '...' + ep[-8:] if len(ep) > 8 else ep
        ua = s.get('user_agent', '')
        is_pwa = 'standalone' in ua or ('Mobile' not in ua and 'Android' not in ua and provider != 'Unknown')
        result.append({
            'endpoint': ep,
            'endpoint_short': masked,
            'provider': provider,
            'label': s.get('label', ''),
            'preferences': s.get('preferences', {}),
            'created': s.get('created', ''),
            'user_agent': ua[:120],
        })
    return jsonify(result)


@app.route('/api/push/subscriptions/label', methods=['POST'])
@login_required
def push_subscription_label():
    """Update the label for a subscription."""
    data = request.get_json() or {}
    endpoint = data.get('endpoint')
    label = data.get('label', '')
    if not endpoint:
        return jsonify({'status': 'error', 'message': 'Missing endpoint'}), 400

    subs = _load_subscriptions()
    for sub in subs:
        if sub.get('endpoint') == endpoint:
            sub['label'] = label[:50]
            break
    else:
        return jsonify({'status': 'error', 'message': 'Subscription not found'}), 404
    _save_subscriptions(subs)
    return jsonify({'status': 'ok', 'message': 'Label updated'})


@app.route('/api/push/subscriptions/delete', methods=['POST'])
@login_required
def push_subscription_delete():
    """Delete any subscription by endpoint."""
    data = request.get_json() or {}
    endpoint = data.get('endpoint')
    if not endpoint:
        return jsonify({'status': 'error', 'message': 'Missing endpoint'}), 400

    subs = _load_subscriptions()
    new_subs = [s for s in subs if s.get('endpoint') != endpoint]
    if len(new_subs) == len(subs):
        return jsonify({'status': 'error', 'message': 'Subscription not found'}), 404
    _save_subscriptions(new_subs)
    return jsonify({'status': 'ok', 'message': 'Subscription deleted'})


@app.route('/api/push/subscriptions/preferences', methods=['POST'])
@login_required
def push_subscription_preferences():
    """Update preferences for any subscription by endpoint."""
    data = request.get_json() or {}
    endpoint = data.get('endpoint')
    if not endpoint:
        return jsonify({'status': 'error', 'message': 'Missing endpoint'}), 400

    subs = _load_subscriptions()
    for sub in subs:
        if sub.get('endpoint') == endpoint:
            sub['preferences'] = {
                'critical': bool(data.get('critical', True)),
                'warnings': bool(data.get('warnings', True)),
                'updates': bool(data.get('updates', False)),
                'security': bool(data.get('security', True)),
                'ddos': bool(data.get('ddos', True)),
                'backup': bool(data.get('backup', True)),
                'app_update': bool(data.get('app_update', True)),
            }
            break
    else:
        return jsonify({'status': 'error', 'message': 'Subscription not found'}), 404
    _save_subscriptions(subs)
    return jsonify({'status': 'ok', 'message': 'Preferences saved'})


# ---------------------------------------------------------------------------
# Notification History routes
# ---------------------------------------------------------------------------

@app.route('/api/notifications/history')
@login_required
def notification_history():
    history = _load_notification_history()
    # Return newest first
    return jsonify(list(reversed(history)))


@app.route('/api/notifications/read', methods=['POST'])
@login_required
def notification_read():
    history = _load_notification_history()
    for item in history:
        item['read'] = True
    _save_notification_history(history)
    return jsonify({'status': 'ok', 'message': 'All notifications marked as read'})


@app.route('/api/notifications/clear', methods=['POST'])
@login_required
def notification_clear():
    """Clear all notification history and reset the notification log.

    This allows alerts to be sent again if they are still active.
    """
    _save_notification_history([])
    _save_notification_log({})
    return jsonify({'status': 'ok', 'message': 'Notifications cleared'})


@app.route('/api/notifications/dismiss', methods=['POST'])
@login_required
def notification_dismiss():
    """Dismiss (remove) a single notification by index."""
    data = request.get_json() or {}
    index = data.get('index')
    if index is None:
        return jsonify({'status': 'error', 'message': 'Missing index'}), 400

    try:
        index = int(index)
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Invalid index'}), 400

    history = _load_notification_history()
    # History is stored oldest-first; the API returns newest-first,
    # so the front-end index maps to reversed order.
    reversed_idx = len(history) - 1 - index
    if 0 <= reversed_idx < len(history):
        history.pop(reversed_idx)
        _save_notification_history(history)
        return jsonify({'status': 'ok', 'message': 'Notification dismissed'})
    return jsonify({'status': 'error', 'message': 'Invalid index'}), 400


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', config=CONFIG, has_2fa=HAS_2FA)


@app.route('/api/services/detect')
@login_required
def detect_services():
    """Auto-detect running services that are relevant to monitor"""
    result = run_cmd(
        "systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null",
        timeout=15
    )
    if result.returncode != 0:
        return jsonify([])

    # Known relevant service prefixes/names
    relevant = {
        'nginx', 'caddy', 'mariadb', 'mysql', 'mysqld', 'fail2ban', 'ufw', 'cron',
        'ssh', 'sshd', 'postfix', 'dovecot', 'redis', 'redis-server',
        'memcached', 'docker', 'containerd', 'certbot',
    }
    relevant_prefixes = ('php', 'pm2-', 'postgresql', 'mongo')

    detected = []
    for line in result.stdout.strip().split('\n'):
        parts = line.split()
        if not parts:
            continue
        svc = parts[0].replace('.service', '')
        if svc in relevant or any(svc.startswith(p) for p in relevant_prefixes):
            detected.append(svc)

    detected.sort()
    return jsonify(detected)


@app.route('/api/webserver/detect')
@login_required
def detect_webserver_route():
    """Auto-detect installed web server"""
    detected = detect_web_server()
    current = get_web_server()
    nginx = run_cmd_safe(['which', 'nginx'], timeout=5)
    caddy = run_cmd_safe(['which', 'caddy'], timeout=5)
    return jsonify({
        'detected': detected,
        'current': current,
        'nginx_installed': nginx.returncode == 0,
        'caddy_installed': caddy.returncode == 0,
    })


def validate_config(data):
    """Validate config values. Returns (is_valid, errors)"""
    errors = []

    if 'thresholds' in data:
        if not isinstance(data['thresholds'], dict):
            errors.append('thresholds must be an object')
        else:
            t = data['thresholds']
            for key in ('disk_warning', 'disk_critical', 'memory_warning', 'swap_warning'):
                if key in t:
                    if not isinstance(t[key], (int, float)) or t[key] < 1 or t[key] > 100:
                        errors.append(f'{key} must be between 1-100')
            for key in ('ssl_warning_days', 'ssl_critical_days'):
                if key in t:
                    if not isinstance(t[key], (int, float)) or t[key] < 1:
                        errors.append(f'{key} must be at least 1')

    if 'monitor_interval' in data:
        if not isinstance(data['monitor_interval'], int) or data['monitor_interval'] < 30:
            errors.append('monitor_interval must be at least 30 seconds')

    if 'notification_cooldown' in data:
        if not isinstance(data['notification_cooldown'], int) or data['notification_cooldown'] < 60:
            errors.append('notification_cooldown must be at least 60 seconds')

    if 'services' in data:
        if not isinstance(data['services'], list):
            errors.append('services must be a list')
        else:
            for s in data['services']:
                if not isinstance(s, str) or not re.match(r'^[a-zA-Z0-9._-]+$', s):
                    errors.append(f'Invalid service name: {s}')

    if 'file_browser' in data:
        fb = data['file_browser']
        if not isinstance(fb, dict):
            errors.append('file_browser must be an object')
        elif 'allowed_paths' in fb:
            if not isinstance(fb['allowed_paths'], list):
                errors.append('allowed_paths must be a list')
            else:
                for p in fb['allowed_paths']:
                    if not isinstance(p, str) or not p.startswith('/'):
                        errors.append(f'Allowed path must be an absolute path string: {p}')
                    elif len(p) < 4:
                        errors.append(f'Allowed path too short (min 4 chars): {p}')
                    else:
                        try:
                            resolved = os.path.realpath(p)
                        except OSError:
                            resolved = p
                        if resolved in FORBIDDEN_ALLOWED_PATHS:
                            errors.append(f'Forbidden allowed path (too broad): {p}')

    if 'ddos_detection' in data:
        if not isinstance(data['ddos_detection'], dict):
            errors.append('ddos_detection must be an object')
        else:
            dd = data['ddos_detection']
            for key in ('connection_threshold', 'syn_threshold', 'single_ip_threshold'):
                if key in dd and (not isinstance(dd[key], int) or dd[key] < 1):
                    errors.append(f'{key} must be a positive integer')

    if 'auth' in data:
        if not isinstance(data['auth'], dict):
            errors.append('auth must be an object')
        else:
            a = data['auth']
            if 'session_lifetime_hours' in a:
                v = a['session_lifetime_hours']
                if not isinstance(v, int) or v < 1 or v > 720:
                    errors.append('session_lifetime_hours must be between 1-720')

    if 'vapid_mailto' in data:
        if not isinstance(data['vapid_mailto'], str) or not data['vapid_mailto'].startswith('mailto:'):
            errors.append('vapid_mailto must start with mailto:')

    if 'backup' in data:
        if not isinstance(data['backup'], dict):
            errors.append('backup must be an object')
        else:
            for key in ('log_path', 'backup_dir', 'db_backup_dir'):
                if key in data['backup']:
                    v = data['backup'][key]
                    if not isinstance(v, str) or not v.startswith('/'):
                        errors.append(f'backup.{key} must be an absolute path')

    if 'web_server' in data:
        if data['web_server'] not in ('nginx', 'caddy'):
            errors.append('web_server must be "nginx" or "caddy"')

    if 'nginx' in data:
        if not isinstance(data['nginx'], dict):
            errors.append('nginx must be an object')
        else:
            for key in ('error_log', 'access_log'):
                if key in data['nginx']:
                    v = data['nginx'][key]
                    if not isinstance(v, str) or not v.startswith('/'):
                        errors.append(f'nginx.{key} must be an absolute path')
                    elif not v.startswith('/var/log/nginx/'):
                        errors.append(f'nginx.{key} must be under /var/log/nginx/')
            if 'sites_enabled' in data['nginx']:
                v = data['nginx']['sites_enabled']
                if not isinstance(v, str) or not v.startswith('/'):
                    errors.append('nginx.sites_enabled must be an absolute path')
                elif not v.startswith('/etc/nginx/'):
                    errors.append('nginx.sites_enabled must be under /etc/nginx/')

    if 'caddy' in data:
        if not isinstance(data['caddy'], dict):
            errors.append('caddy must be an object')
        else:
            for key in ('config_file', 'sites_dir'):
                if key in data['caddy']:
                    v = data['caddy'][key]
                    if not isinstance(v, str) or not v.startswith('/'):
                        errors.append(f'caddy.{key} must be an absolute path')
                    elif not v.startswith('/etc/caddy/'):
                        errors.append(f'caddy.{key} must be under /etc/caddy/')
            for key in ('access_log', 'error_log'):
                if key in data['caddy']:
                    v = data['caddy'][key]
                    if not isinstance(v, str) or not v.startswith('/'):
                        errors.append(f'caddy.{key} must be an absolute path')
                    elif not v.startswith('/var/log/caddy/'):
                        errors.append(f'caddy.{key} must be under /var/log/caddy/')
            if 'data_dir' in data['caddy']:
                v = data['caddy']['data_dir']
                if not isinstance(v, str) or not v.startswith('/'):
                    errors.append('caddy.data_dir must be an absolute path')
                elif not v.startswith('/var/lib/caddy/'):
                    errors.append('caddy.data_dir must be under /var/lib/caddy/')

    return (len(errors) == 0, errors)


@app.route('/api/config', methods=['POST'])
@login_required
def update_config():
    global CONFIG, MONITOR_INTERVAL
    data = request.get_json() or {}
    if not data:
        return jsonify({'status': 'error', 'message': 'No data received'}), 400

    # Validate config
    is_valid, errors = validate_config(data)
    if not is_valid:
        return jsonify({'status': 'error', 'message': 'Validation failed', 'errors': errors}), 400

    # Merge into config (only allow session_lifetime_hours from auth)
    with _config_runtime_lock:
        for key in data:
            if key == 'auth':
                if isinstance(data[key], dict) and 'session_lifetime_hours' in data[key]:
                    CONFIG['auth']['session_lifetime_hours'] = data[key]['session_lifetime_hours']
                continue
            if key in CONFIG and isinstance(CONFIG[key], dict) and isinstance(data[key], dict):
                CONFIG[key].update(data[key])
            else:
                CONFIG[key] = data[key]

        save_config(CONFIG)

    # Update runtime values
    MONITOR_INTERVAL = CONFIG.get('monitor_interval', 300)
    app.permanent_session_lifetime = timedelta(hours=CONFIG['auth'].get('session_lifetime_hours', 24))

    # Invalidate web server caches if web_server setting changed
    if 'web_server' in data:
        _invalidate_cache('get_nginx_sites', 'get_caddy_sites', 'get_nginx_logs',
                          'get_caddy_logs', 'get_ssl_certificates', 'get_caddy_certificates')

    log_audit('config_update', {'keys': list(data.keys())})
    return jsonify({'status': 'ok', 'message': 'Settings saved'})


@app.route('/settings/password', methods=['POST'])
@login_required
def change_password():
    global PASSWORD_HASH
    data = request.get_json() or {}
    current = data.get('current_password', '')
    new_pass = data.get('new_password', '')
    confirm = data.get('confirm_password', '')

    if not check_password_hash(PASSWORD_HASH, current):
        return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 400
    if len(new_pass) < 8:
        return jsonify({'status': 'error', 'message': 'New password must be at least 8 characters'}), 400
    if new_pass != confirm:
        return jsonify({'status': 'error', 'message': 'Passwords do not match'}), 400

    PASSWORD_HASH = generate_password_hash(new_pass)
    CONFIG['auth']['password_hash'] = PASSWORD_HASH
    save_config(CONFIG)

    # Remove generated password file if it exists
    _pw_file = DATA_DIR / '.generated_password'
    try:
        _pw_file.unlink(missing_ok=True)
    except OSError:
        pass

    log_audit('password_change')
    return jsonify({'status': 'ok', 'message': 'Password changed successfully'})


@app.route('/settings/2fa/enable', methods=['POST'])
@login_required
def enable_2fa():
    if not HAS_2FA:
        return jsonify({'status': 'error', 'message': 'pyotp/qrcode not installed'}), 500

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=USERNAME, issuer_name='VPS Manager')

    # Generate QR code as base64 PNG
    qr = qrcode.QRCode(version=1, box_size=6, border=2)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color='white', back_color='#0d1117')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    # Store secret temporarily in session for verification
    session['pending_totp_secret'] = secret

    return jsonify({
        'status': 'ok',
        'secret': secret,
        'qr_code': f'data:image/png;base64,{qr_b64}',
    })


@app.route('/settings/2fa/verify', methods=['POST'])
@login_required
def verify_2fa():
    if not HAS_2FA:
        return jsonify({'status': 'error', 'message': 'pyotp not installed'}), 500

    data = request.get_json() or {}
    code = data.get('code', '').strip()
    secret = session.get('pending_totp_secret')

    if not secret:
        return jsonify({'status': 'error', 'message': 'No pending 2FA setup'}), 400

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({'status': 'error', 'message': 'Invalid code, try again'}), 400

    # Save to config
    CONFIG['auth']['totp_secret'] = secret
    save_config(CONFIG)
    session.pop('pending_totp_secret', None)

    log_audit('2fa_enable')
    return jsonify({'status': 'ok', 'message': '2FA enabled successfully'})


@app.route('/settings/2fa/disable', methods=['POST'])
@login_required
def disable_2fa():
    data = request.get_json() or {}
    password = data.get('password', '')

    if not check_password_hash(PASSWORD_HASH, password):
        return jsonify({'status': 'error', 'message': 'Incorrect password'}), 400

    CONFIG['auth']['totp_secret'] = None
    save_config(CONFIG)

    log_audit('2fa_disable')
    return jsonify({'status': 'ok', 'message': '2FA disabled'})


@app.route('/api/backup/webhook', methods=['POST'])
@csrf.exempt
def backup_webhook():
    """Endpoint for backup scripts to report success/failure"""
    webhook_secret = CONFIG.get('backup', {}).get('webhook_secret', '')
    if not webhook_secret:
        return jsonify({'status': 'error', 'message': 'Webhook secret not configured'}), 403
    provided = request.headers.get('X-Webhook-Secret', '')
    if not provided or not hmac.compare_digest(provided, webhook_secret):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    data = request.get_json() or {}
    if 'status' not in data or data['status'] not in ('success', 'failure'):
        return jsonify({'status': 'error', 'message': 'Invalid data, status must be success or failure'}), 400

    # Sanitize details: strip HTML tags and limit length
    raw_details = data.get('details', '')
    clean_details = re.sub(r'<[^>]+>', '', str(raw_details))[:500]

    status_data = _load_backup_status()
    entry = {
        'status': data['status'],
        'details': clean_details,
        'timestamp': datetime.now().isoformat(),
    }

    history = status_data.get('history', [])
    history.append(entry)
    # Keep last 20 entries
    status_data['history'] = history[-20:]

    if data['status'] == 'success':
        status_data['last_success'] = entry
    else:
        status_data['last_failure'] = entry

    _save_backup_status(status_data)
    return jsonify({'status': 'ok', 'message': 'Backup status recorded'})


@app.route('/swap/clear', methods=['POST'])
@login_required
def swap_clear():
    # Check current swap and available RAM
    try:
        meminfo = {}
        with open('/proc/meminfo') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(':')] = int(parts[1])
        swap_used = meminfo.get('SwapTotal', 0) - meminfo.get('SwapFree', 0)
        mem_available = meminfo.get('MemAvailable', 0)
        if swap_used <= 0:
            return jsonify({'status': 'error', 'message': 'Swap is already empty'}), 400
        if swap_used > mem_available:
            swap_mb = swap_used // 1024
            avail_mb = mem_available // 1024
            return jsonify({'status': 'error', 'message': f'Not enough free RAM ({avail_mb}MB) to clear swap ({swap_mb}MB)'}), 400
    except (OSError, ValueError):
        return jsonify({'status': 'error', 'message': 'Could not read memory info'}), 500
    # Disable and re-enable swap
    result = run_cmd_safe(["sudo", "swapoff", "-a"], timeout=60)
    if result.returncode != 0:
        return jsonify({'status': 'error', 'message': f'swapoff failed: {result.stderr}'}), 500
    result = run_cmd_safe(["sudo", "swapon", "-a"], timeout=10)
    if result.returncode != 0:
        return jsonify({'status': 'error', 'message': f'swapon failed: {result.stderr}'}), 500
    log_audit('swap_clear', {'freed_mb': swap_used // 1024})
    _invalidate_cache('get_server_overview')
    return jsonify({'status': 'ok', 'message': f'Swap cleared ({swap_used // 1024}MB freed)'})


@app.route('/reboot', methods=['POST'])
@login_required
def reboot():
    log_audit('server_reboot')
    run_cmd("sudo reboot")
    return jsonify({'status': 'ok', 'message': 'Server is rebooting...'})


@app.route('/api/metrics')
@login_required
def api_metrics():
    """Return collected metrics (max 288 data points, 24h)"""
    with _metrics_lock:
        metrics = _load_metrics()
    return jsonify(metrics)


@app.route('/api/refresh/<section>')
@login_required
def api_refresh(section):
    """AJAX endpoint to refresh a specific section"""
    handlers = {
        'overview': get_server_overview,
        'websites': get_sites,
        'pm2': get_pm2_processes,
        'ssl': get_ssl_info,
        'services': get_services_status,
        'backup': get_backup_status,
        'firewall': get_firewall_security,
        'updates': get_system_updates,
        'nginx-logs': get_web_logs,
        'databases': get_database_info,
        'cronjobs': get_cronjobs,
    }

    if section == 'disk':
        sites, total = get_disk_per_site()
        return jsonify({'sites': sites, 'total': total})

    handler = handlers.get(section)
    if handler:
        return jsonify(handler())
    return jsonify({'status': 'error', 'message': 'Unknown section'}), 404


# ---------------------------------------------------------------------------
# Audit Log routes
# ---------------------------------------------------------------------------

@app.route('/audit')
@login_required
def audit():
    return render_template('audit.html')


@app.route('/api/audit')
@login_required
def api_audit():
    """JSON API for audit log with optional filters"""
    try:
        log = json.loads(AUDIT_LOG_PATH.read_text()) if AUDIT_LOG_PATH.exists() else []
    except (json.JSONDecodeError, OSError):
        log = []

    # Filter by action
    action_filter = request.args.get('action', '')
    if action_filter:
        log = [e for e in log if e.get('action') == action_filter]

    # Filter by date range
    date_from = request.args.get('from', '')
    date_to = request.args.get('to', '')
    if date_from:
        log = [e for e in log if e.get('timestamp', '') >= date_from]
    if date_to:
        log = [e for e in log if e.get('timestamp', '') <= date_to]

    # Return newest first
    return jsonify(list(reversed(log)))


@app.route('/api/audit/clear', methods=['POST'])
@login_required
def audit_clear():
    log_audit('audit_clear')
    _atomic_write_json(AUDIT_LOG_PATH, [])
    return jsonify({'status': 'ok', 'message': 'Audit log cleared'})


# ---------------------------------------------------------------------------
# File Editor routes
# ---------------------------------------------------------------------------

EDITABLE_EXTENSIONS = {
    '.conf', '.env', '.json', '.html', '.css', '.js', '.py', '.php', '.sh',
    '.txt', '.md', '.yml', '.yaml', '.xml', '.ini', '.cfg', '.log',
    '.htaccess', '.tsx', '.ts', '.jsx', '.sql', '.toml', '.svg',
}


@app.route('/files/read')
@login_required
def files_read():
    """Read file content for in-browser editing"""
    path = request.args.get('path', '')
    norm_path = os.path.abspath(path)

    if not is_path_allowed(norm_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    if not os.path.isfile(norm_path):
        return jsonify({'status': 'error', 'message': 'File not found'}), 404

    # Check file size (max 1MB)
    try:
        size = os.path.getsize(norm_path)
    except OSError:
        return jsonify({'status': 'error', 'message': 'Cannot read file'}), 500

    if size > 1024 * 1024:
        return jsonify({'status': 'error', 'message': 'File too large (max 1MB)'}), 400

    # Read and check for binary content
    try:
        with open(norm_path, 'rb') as f:
            raw = f.read()
        if b'\x00' in raw[:8192]:
            return jsonify({'status': 'error', 'message': 'Binary file cannot be edited'}), 400
        content = raw.decode('utf-8', errors='replace')
    except OSError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

    writable = os.access(norm_path, os.W_OK)
    return jsonify({'status': 'ok', 'content': content, 'writable': writable})


@app.route('/files/save', methods=['POST'])
@login_required
def files_save():
    """Save file content from in-browser editor"""
    data = request.get_json() or {}
    path = data.get('path', '')
    content = data.get('content', '')

    if not path:
        return jsonify({'status': 'error', 'message': 'No path specified'}), 400

    norm_path = os.path.abspath(path)

    if not is_path_allowed(norm_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    if not os.path.isfile(norm_path):
        return jsonify({'status': 'error', 'message': 'File not found'}), 404

    try:
        with open(norm_path, 'w', encoding='utf-8') as f:
            f.write(content)
        log_audit('file_save', {'path': norm_path})
        return jsonify({'status': 'ok', 'message': 'File saved'})
    except OSError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ---------------------------------------------------------------------------
# Cronjob Editor routes
# ---------------------------------------------------------------------------

def _parse_crontab_lines(text):
    """Parse crontab text, returning all lines and structured job list"""
    lines = text.split('\n')
    jobs = []
    job_idx = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        # Skip env var lines
        first_word = stripped.split()[0] if stripped.split() else ''
        if '=' in first_word:
            continue
        parts = stripped.split()
        if len(parts) >= 6:
            jobs.append({
                'index': job_idx,
                'line_num': i,
                'schedule': ' '.join(parts[:5]),
                'command': ' '.join(parts[5:]),
                'human_schedule': _cron_to_human(parts[:5]),
            })
            job_idx += 1
    return lines, jobs


_MONTH_NAMES = {'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
                 'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12}
_DOW_NAMES = {'sun': 0, 'mon': 1, 'tue': 2, 'wed': 3, 'thu': 4, 'fri': 5, 'sat': 6}


def _cron_value_to_int(val, names_map):
    """Convert a cron value (digit or name) to int. Returns None if invalid."""
    if val.isdigit():
        return int(val)
    return names_map.get(val.lower())


def _validate_cron_field(value, min_val, max_val, names_map=None):
    """Validate a single cron schedule field"""
    if value == '*':
        return True
    for part in value.split(','):
        part = part.strip()
        if '/' in part:
            base, step = part.split('/', 1)
            if not step.isdigit() or int(step) < 1:
                return False
            if base == '*':
                continue
            # Base can be a range (e.g. 1-10/2) or a single value
            if '-' in base:
                lo_s, hi_s = base.split('-', 1)
                lo = _cron_value_to_int(lo_s, names_map or {})
                hi = _cron_value_to_int(hi_s, names_map or {})
                if lo is None or hi is None:
                    return False
                if not (min_val <= lo <= max_val) or not (min_val <= hi <= max_val):
                    return False
            else:
                n = _cron_value_to_int(base, names_map or {})
                if n is None or not (min_val <= n <= max_val):
                    return False
        elif '-' in part:
            lo_s, hi_s = part.split('-', 1)
            lo = _cron_value_to_int(lo_s, names_map or {})
            hi = _cron_value_to_int(hi_s, names_map or {})
            if lo is None or hi is None:
                return False
            if not (min_val <= lo <= max_val) or not (min_val <= hi <= max_val):
                return False
        else:
            n = _cron_value_to_int(part, names_map or {})
            if n is None or not (min_val <= n <= max_val):
                return False
    return True


def _validate_cron_schedule(schedule):
    """Validate a full cron schedule string. Returns (is_valid, error_msg)"""
    parts = schedule.split()
    if len(parts) != 5:
        return False, 'Schedule must have 5 fields'
    limits = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
    names_maps = [None, None, None, _MONTH_NAMES, _DOW_NAMES]
    field_names = ['minute', 'hour', 'day of month', 'month', 'day of week']
    for i, (val, (lo, hi)) in enumerate(zip(parts, limits)):
        if not _validate_cron_field(val, lo, hi, names_maps[i]):
            return False, f'Invalid {field_names[i]}: {val}'
    return True, ''


@app.route('/api/cronjobs')
@login_required
def api_cronjobs():
    """JSON API for cronjob data"""
    data = get_cronjobs()
    return jsonify(data)


@app.route('/api/cronjobs/add', methods=['POST'])
@login_required
def cronjobs_add():
    """Add a new cron entry"""
    data = request.get_json() or {}
    schedule = data.get('schedule', '').strip()
    command = data.get('command', '').strip()
    cron_type = data.get('type', 'user')

    if not schedule or not command:
        return jsonify({'status': 'error', 'message': 'Schedule and command are required'}), 400

    is_valid, err = _validate_cron_schedule(schedule)
    if not is_valid:
        return jsonify({'status': 'error', 'message': err}), 400

    new_line = f'{schedule} {command}'

    if cron_type == 'root':
        result = run_cmd("sudo crontab -l 2>/dev/null")
        current = result.stdout if result.returncode == 0 else ''
    else:
        result = run_cmd("crontab -l 2>/dev/null")
        current = result.stdout if result.returncode == 0 else ''

    # Append new line
    if current and not current.endswith('\n'):
        current += '\n'
    current += new_line + '\n'

    if cron_type == 'root':
        write_result = run_cmd(f"printf %s {shlex.quote(current)} | sudo crontab -", timeout=10)
    else:
        write_result = run_cmd(f"printf %s {shlex.quote(current)} | crontab -", timeout=10)

    if write_result.returncode == 0:
        log_audit('cronjob_add', {'type': cron_type, 'schedule': schedule, 'command': command})
        return jsonify({'status': 'ok', 'message': 'Cronjob added'})
    return jsonify({'status': 'error', 'message': write_result.stderr.strip() or 'Failed to add cronjob'}), 500


@app.route('/api/cronjobs/edit', methods=['POST'])
@login_required
def cronjobs_edit():
    """Edit an existing cron entry by index"""
    data = request.get_json() or {}
    index = data.get('index')
    schedule = data.get('schedule', '').strip()
    command = data.get('command', '').strip()
    cron_type = data.get('type', 'user')

    if index is None or not schedule or not command:
        return jsonify({'status': 'error', 'message': 'Index, schedule, and command are required'}), 400

    is_valid, err = _validate_cron_schedule(schedule)
    if not is_valid:
        return jsonify({'status': 'error', 'message': err}), 400

    try:
        index = int(index)
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Invalid index'}), 400

    if cron_type == 'root':
        result = run_cmd("sudo crontab -l 2>/dev/null")
    else:
        result = run_cmd("crontab -l 2>/dev/null")

    if result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Could not read crontab'}), 500

    lines, jobs = _parse_crontab_lines(result.stdout)

    if index < 0 or index >= len(jobs):
        return jsonify({'status': 'error', 'message': 'Job index out of range'}), 400

    job = jobs[index]
    lines[job['line_num']] = f'{schedule} {command}'
    new_content = '\n'.join(lines)
    if not new_content.endswith('\n'):
        new_content += '\n'

    if cron_type == 'root':
        write_result = run_cmd(f"printf %s {shlex.quote(new_content)} | sudo crontab -", timeout=10)
    else:
        write_result = run_cmd(f"printf %s {shlex.quote(new_content)} | crontab -", timeout=10)

    if write_result.returncode == 0:
        log_audit('cronjob_edit', {'type': cron_type, 'index': index, 'schedule': schedule, 'command': command})
        return jsonify({'status': 'ok', 'message': 'Cronjob updated'})
    return jsonify({'status': 'error', 'message': write_result.stderr.strip() or 'Failed to edit cronjob'}), 500


@app.route('/api/cronjobs/delete', methods=['POST'])
@login_required
def cronjobs_delete():
    """Delete a cron entry by index"""
    data = request.get_json() or {}
    index = data.get('index')
    cron_type = data.get('type', 'user')

    if index is None:
        return jsonify({'status': 'error', 'message': 'Index is required'}), 400

    try:
        index = int(index)
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Invalid index'}), 400

    if cron_type == 'root':
        result = run_cmd("sudo crontab -l 2>/dev/null")
    else:
        result = run_cmd("crontab -l 2>/dev/null")

    if result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Could not read crontab'}), 500

    lines, jobs = _parse_crontab_lines(result.stdout)

    if index < 0 or index >= len(jobs):
        return jsonify({'status': 'error', 'message': 'Job index out of range'}), 400

    job = jobs[index]
    deleted_cmd = lines[job['line_num']]
    del lines[job['line_num']]
    new_content = '\n'.join(lines)
    if not new_content.endswith('\n'):
        new_content += '\n'

    if cron_type == 'root':
        write_result = run_cmd(f"printf %s {shlex.quote(new_content)} | sudo crontab -", timeout=10)
    else:
        write_result = run_cmd(f"printf %s {shlex.quote(new_content)} | crontab -", timeout=10)

    if write_result.returncode == 0:
        log_audit('cronjob_delete', {'type': cron_type, 'index': index, 'entry': deleted_cmd.strip()})
        return jsonify({'status': 'ok', 'message': 'Cronjob deleted'})
    return jsonify({'status': 'error', 'message': write_result.stderr.strip() or 'Failed to delete cronjob'}), 500


@app.route('/api/cronjobs/run', methods=['POST'])
@login_required
def cronjobs_run():
    """Run a cron job command immediately"""
    data = request.get_json() or {}
    index = data.get('index')
    cron_type = data.get('type', 'user')

    if index is None:
        return jsonify({'status': 'error', 'message': 'Index is required'}), 400

    try:
        index = int(index)
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Invalid index'}), 400

    if cron_type == 'root':
        result = run_cmd("sudo crontab -l 2>/dev/null")
    else:
        result = run_cmd("crontab -l 2>/dev/null")

    if result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Could not read crontab'}), 500

    lines, jobs = _parse_crontab_lines(result.stdout)

    if index < 0 or index >= len(jobs):
        return jsonify({'status': 'error', 'message': 'Job index out of range'}), 400

    job = jobs[index]
    command = job['command']

    if cron_type == 'root':
        run_result = run_cmd(f"sudo bash -c {shlex.quote(command)}", timeout=120)
    else:
        run_result = run_cmd(f"bash -c {shlex.quote(command)}", timeout=120)

    log_audit('cronjob_run', {'type': cron_type, 'command': command, 'exit_code': run_result.returncode})

    output = run_result.stdout.strip()
    errors = run_result.stderr.strip()

    if run_result.returncode == 0:
        return jsonify({
            'status': 'ok',
            'message': 'Cronjob executed successfully',
            'output': output[:2000] if output else '',
            'errors': errors[:2000] if errors else ''
        })
    return jsonify({
        'status': 'error',
        'message': f'Command exited with code {run_result.returncode}',
        'output': output[:2000] if output else '',
        'errors': errors[:2000] if errors else ''
    }), 200


# ---------------------------------------------------------------------------
# Nginx Config Editor routes
# ---------------------------------------------------------------------------

def list_nginx_configs():
    """List enabled + available site configs"""
    configs = {'enabled': [], 'available': []}

    result = run_cmd("sudo ls /etc/nginx/sites-enabled/ 2>/dev/null", timeout=10)
    if result.returncode == 0:
        configs['enabled'] = [n.strip() for n in result.stdout.strip().split('\n') if n.strip()]

    result = run_cmd("sudo ls /etc/nginx/sites-available/ 2>/dev/null", timeout=10)
    if result.returncode == 0:
        all_available = [n.strip() for n in result.stdout.strip().split('\n') if n.strip()]
        configs['available'] = [n for n in all_available if n not in configs['enabled']]

    return configs


def validate_nginx():
    """Run nginx -t, return (is_valid, output)"""
    result = run_cmd_safe(["sudo", "nginx", "-t"], timeout=15)
    output = (result.stderr or '') + (result.stdout or '')
    return result.returncode == 0, output.strip()


# ---------------------------------------------------------------------------
# Caddy backend functions
# ---------------------------------------------------------------------------

def _parse_caddyfile(content, sites_dir=None):
    """Parse a Caddyfile and extract site blocks.
    Returns list of dicts with keys: address, root, proxy, file_server, tls, log_output.
    """
    sites = []

    # Expand imports: if we see 'import sites/*' or 'import /path/to/dir/*', load those files
    expanded = content
    # Resolve relative imports against the Caddyfile's directory (not sites_dir)
    caddyfile_dir = os.path.dirname(sites_dir.rstrip('/')) if sites_dir else '/etc/caddy'

    import_pattern = re.compile(r'^\s*import\s+(\S+)\s*$', re.MULTILINE)
    for m in import_pattern.finditer(content):
        import_path = m.group(1)
        # Skip snippet imports (no path chars, no glob)
        if '/' not in import_path and '*' not in import_path:
            continue
        # Resolve relative paths against the Caddyfile's parent directory
        if not import_path.startswith('/'):
            import_path = os.path.join(caddyfile_dir, import_path)
        # Security: only expand paths within /etc/caddy/
        clean_path = import_path.replace('*', '').rstrip('/')
        if not _is_caddy_path_safe(clean_path if clean_path else caddyfile_dir):
            continue
        # Expand glob patterns
        if '*' in import_path:
            base_dir = os.path.dirname(import_path)  # e.g. /etc/caddy/sites from /etc/caddy/sites/*
            if not base_dir or not _is_caddy_path_safe(base_dir):
                continue
            result = run_cmd_safe(["sudo", "ls", base_dir], timeout=5)
            if result.returncode == 0:
                for fname in result.stdout.strip().split('\n'):
                    fname = fname.strip()
                    if fname and not fname.endswith('.disabled'):
                        fpath = os.path.join(base_dir, fname)
                        if not _is_caddy_path_safe(fpath):
                            continue
                        file_result = run_cmd_safe(["sudo", "cat", fpath], timeout=5)
                        if file_result.returncode == 0:
                            expanded += '\n' + file_result.stdout
        else:
            # Direct file import (no glob)
            if _is_caddy_path_safe(import_path):
                file_result = run_cmd_safe(["sudo", "cat", import_path], timeout=5)
                if file_result.returncode == 0:
                    expanded += '\n' + file_result.stdout

    # Parse site blocks: address { ... }
    # Simple brace-counting parser
    lines = expanded.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        # Skip comments, empty lines
        if not line or line.startswith('#'):
            i += 1
            continue
        # Skip snippet blocks: (name) { ... }
        if line.startswith('('):
            depth = 0
            # Count braces on current line; if none, look ahead for opening brace
            depth += lines[i].count('{') - lines[i].count('}')
            i += 1
            if depth == 0 and i < len(lines):
                # Opening brace might be on the next line
                depth += lines[i].count('{') - lines[i].count('}')
                i += 1
            while i < len(lines) and depth > 0:
                depth += lines[i].count('{') - lines[i].count('}')
                i += 1
            continue

        # Check for global options block
        if line == '{':
            depth = 1
            i += 1
            while i < len(lines) and depth > 0:
                depth += lines[i].count('{') - lines[i].count('}')
                i += 1
            continue

        # Check for site address (domain/host followed by { on same or next line)
        address = None
        if '{' in line:
            address = line.split('{')[0].strip()
        elif i + 1 < len(lines) and lines[i + 1].strip() == '{':
            address = line
        elif line and not line.startswith('}') and not any(line.startswith(d) for d in [
            'import', 'log', 'tls', 'root', 'reverse_proxy', 'file_server',
            'encode', 'header', 'handle', 'handle_path', 'route', 'respond', 'redir',
            'email', 'admin', 'auto_https', 'order', 'storage', 'acme_ca',
            'ocsp_stapling', 'grace_period', 'shutdown_delay', 'servers',
            'skip_install_trust', 'default_bind', 'default_sni',
            'php_fastcgi', 'basicauth', 'forward_auth', 'request_header',
            'try_files', 'rewrite', 'uri', 'method', 'bind', 'abort',
            'error', 'metrics', 'templates', 'push', 'vars', 'map',
            'invoke', 'skip_log', 'request_body',
        ]):
            # Likely a site address on its own line
            address = line

        if not address or address == '}':
            i += 1
            continue

        # Find the block content
        block_lines = []
        depth = 0
        # Find opening brace
        if '{' in lines[i]:
            depth = lines[i].count('{') - lines[i].count('}')
            i += 1
        else:
            i += 1
            if i < len(lines) and '{' in lines[i]:
                depth = lines[i].count('{') - lines[i].count('}')
                i += 1

        while i < len(lines) and depth > 0:
            block_lines.append(lines[i])
            depth += lines[i].count('{') - lines[i].count('}')
            i += 1

        # Parse block directives
        doc_root = None
        proxy = None
        file_server = False
        tls_mode = None
        log_output = None

        for bline in block_lines:
            bline = bline.strip()
            if bline.startswith('root'):
                parts = bline.split(None, 1)
                if len(parts) > 1:
                    # root can be 'root * /path' or 'root /path'
                    root_val = parts[1].rstrip()
                    if root_val.startswith('* '):
                        root_val = root_val[2:].strip()
                    doc_root = root_val
            elif bline.startswith('reverse_proxy'):
                parts = bline.split(None, 1)
                if len(parts) > 1:
                    proxy = parts[1].split('{')[0].strip()
            elif bline.startswith('file_server'):
                file_server = True
            elif bline.startswith('tls'):
                parts = bline.split(None, 1)
                tls_mode = parts[1].strip() if len(parts) > 1 else 'auto'
            elif bline.startswith('log'):
                # Look for output directive in nested block
                if '{' in bline:
                    pass  # handled below
            elif bline.startswith('output') and 'file' in bline:
                # output file /path/to/log
                parts = bline.split()
                for idx, p in enumerate(parts):
                    if p == 'file' and idx + 1 < len(parts):
                        log_output = parts[idx + 1]

        # Also scan for log output in block
        in_log = False
        for bline in block_lines:
            bline = bline.strip()
            if bline.startswith('log'):
                in_log = True
            elif in_log and bline.startswith('}'):
                in_log = False
            elif in_log and 'output' in bline and 'file' in bline:
                parts = bline.split()
                for idx, p in enumerate(parts):
                    if p == 'file' and idx + 1 < len(parts):
                        log_output = parts[idx + 1]

        # Clean up address: remove protocol prefixes for domain extraction
        clean_addr = address
        for prefix in ('https://', 'http://'):
            if clean_addr.startswith(prefix):
                clean_addr = clean_addr[len(prefix):]
        # Remove port if present
        domains = []
        for addr_part in clean_addr.split():
            addr_part = addr_part.strip(',')
            domain = addr_part.split(':')[0] if ':' in addr_part else addr_part
            if domain and domain not in ('localhost', '*', ':'):
                domains.append(domain)

        if domains:
            sites.append({
                'address': address,
                'domains': domains,
                'root': doc_root,
                'proxy': proxy,
                'file_server': file_server,
                'tls': tls_mode,
                'log_output': log_output,
            })

    return sites


def _ensure_caddy_site_logs(config_file):
    """Auto-add log blocks to Caddy site blocks that lack them.
    Modifies the Caddyfile in place. Returns True if changes were made."""
    result = run_cmd_safe(["sudo", "cat", config_file], timeout=5)
    if result.returncode != 0:
        return False

    lines = result.stdout.split('\n')
    new_lines = list(lines)
    insertions = []  # (line_index, domain) - collect first, insert later

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Skip empty, comments, snippets, global options
        if not line or line.startswith('#') or line.startswith('('):
            i += 1
            continue
        if line == '{':
            depth = 1
            i += 1
            while i < len(lines) and depth > 0:
                depth += lines[i].count('{') - lines[i].count('}')
                i += 1
            continue

        # Detect site address
        address = None
        if '{' in line:
            address = line.split('{')[0].strip()
        elif i + 1 < len(lines) and lines[i + 1].strip() == '{':
            address = line

        if not address or address == '}':
            i += 1
            continue

        # Find the block boundaries
        block_start = i
        depth = 0
        if '{' in lines[i]:
            depth = lines[i].count('{') - lines[i].count('}')
            i += 1
        else:
            i += 1
            if i < len(lines) and '{' in lines[i]:
                depth = lines[i].count('{') - lines[i].count('}')
                i += 1

        block_content_start = i
        while i < len(lines) and depth > 0:
            depth += lines[i].count('{') - lines[i].count('}')
            i += 1
        block_end = i  # line after closing brace

        # Check if this block has a log directive
        has_log = False
        for j in range(block_content_start, block_end):
            if lines[j].strip().startswith('log'):
                has_log = True
                break

        if has_log:
            continue

        # Extract domain for log filename
        clean_addr = address
        for prefix in ('https://', 'http://'):
            if clean_addr.startswith(prefix):
                clean_addr = clean_addr[len(prefix):]
        domain = clean_addr.split()[0].split(':')[0].strip(',') if clean_addr.split() else None
        if not domain or domain in ('localhost', '*', ':'):
            continue

        # Insert before the closing brace (block_end - 1)
        insertions.append((block_end - 1, domain))

    if not insertions:
        return False

    # Insert in reverse order so line indices stay valid
    for insert_idx, domain in reversed(insertions):
        safe_domain = re.sub(r'[^a-zA-Z0-9._-]', '', domain)
        log_block = [
            '    log {',
            f'        output file /var/log/caddy/{safe_domain}.log',
            '    }',
        ]
        for offset, log_line in enumerate(log_block):
            new_lines.insert(insert_idx, log_line)

    new_content = '\n'.join(new_lines)

    # Write via temp file
    safe_name = os.path.basename(config_file).replace('/', '')
    temp_path = str(DATA_DIR / f'caddy_autolog_{safe_name}')
    try:
        with open(temp_path, 'w') as f:
            f.write(new_content)
        cp_result = run_cmd_safe(["sudo", "cp", temp_path, config_file], timeout=5)
        if cp_result.returncode != 0:
            return False
    except OSError:
        return False
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass

    domains_added = [d for _, d in insertions]
    log_audit('caddy_auto_add_logs', {'config': os.path.basename(config_file), 'domains': domains_added})
    return True


@_ttl_cache(60)
def get_caddy_sites():
    """Get Caddy sites with HTTP status"""
    caddy_cfg = CONFIG.get('caddy', {})
    config_file = caddy_cfg.get('config_file', '/etc/caddy/Caddyfile')
    sites_dir = caddy_cfg.get('sites_dir', '/etc/caddy/sites/')

    result = run_cmd_safe(["sudo", "cat", config_file], timeout=10)
    if result.returncode != 0:
        return []

    # Auto-add log blocks to sites missing them (with backup/rollback)
    configs_modified = False
    modified_files = []  # [(path, backup_content), ...]

    def _try_add_logs(fpath):
        """Try to add logs, keeping backup for rollback"""
        backup = run_cmd_safe(["sudo", "cat", fpath], timeout=5)
        if backup.returncode != 0:
            return False
        if _ensure_caddy_site_logs(fpath):
            modified_files.append((fpath, backup.stdout))
            return True
        return False

    _try_add_logs(config_file)
    if sites_dir and _is_caddy_path_safe(sites_dir):
        ls_result = run_cmd_safe(["sudo", "ls", sites_dir], timeout=5)
        if ls_result.returncode == 0 and ls_result.stdout.strip():
            for fname in ls_result.stdout.strip().split('\n'):
                fname = fname.strip()
                if fname and not fname.endswith('.disabled'):
                    fpath = os.path.join(sites_dir, fname)
                    if _is_caddy_path_safe(fpath):
                        _try_add_logs(fpath)

    if modified_files:
        valid = run_cmd_safe(["sudo", "caddy", "validate", "--config", config_file], timeout=10)
        if valid.returncode == 0:
            run_cmd_safe(["sudo", "systemctl", "reload", "caddy"], timeout=10)
            configs_modified = True
        else:
            # Rollback all modified files
            logger.warning("Caddy config invalid after auto-adding logs, rolling back")
            for fpath, backup_content in modified_files:
                tmp = str(DATA_DIR / 'caddy_rollback_tmp')
                try:
                    with open(tmp, 'w') as f:
                        f.write(backup_content)
                    run_cmd_safe(["sudo", "cp", tmp, fpath], timeout=5)
                except OSError:
                    pass
                finally:
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass

    if configs_modified:
        # Re-read config after modifications
        result = run_cmd_safe(["sudo", "cat", config_file], timeout=10)
        if result.returncode != 0:
            return []

    parsed = _parse_caddyfile(result.stdout, sites_dir=sites_dir)
    sites = []

    for site in parsed:
        domains = site['domains']
        proxy = site.get('proxy')
        doc_root = site.get('root')
        log_output = site.get('log_output')

        # HTTP status check (same logic as nginx)
        http_result = run_cmd_safe(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-L",
             f"https://{domains[0]}", "--max-time", "5"],
            timeout=10
        )
        http_status = http_result.stdout.strip() if http_result.stdout else '---'
        if http_status == '000':
            http_result = run_cmd_safe(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-L",
                 f"http://{domains[0]}", "--max-time", "5"],
                timeout=10
            )
            http_status = http_result.stdout.strip() if http_result.stdout else '---'

        sites.append({
            'config': os.path.basename(config_file),
            'domains': domains,
            'domain': ', '.join(domains),
            'root': doc_root,
            'proxy': proxy,
            'type': 'proxy' if proxy else 'static',
            'location': proxy if proxy else (doc_root or 'n/a'),
            'http_status': http_status,
            'access_log': log_output,
            'error_log': log_output,  # Caddy uses single log file per site
        })

    return sites


def _parse_caddy_log_line(line):
    """Parse a single Caddy JSON log line into structured data"""
    try:
        entry = json.loads(line)
        ts = entry.get('ts', 0)
        if isinstance(ts, (int, float)):
            timestamp = datetime.fromtimestamp(ts).strftime('%Y/%m/%d %H:%M:%S')
        else:
            timestamp = str(ts)
        level = entry.get('level', 'unknown')
        msg = entry.get('msg', '')
        # For access logs, build a useful message
        req = entry.get('request', {})
        if req:
            method = req.get('method', '')
            uri = req.get('uri', '')
            host = req.get('host', '')
            status = entry.get('status', '')
            msg = f"{method} {host}{uri} -> {status}" if method else msg
        return {
            'timestamp': timestamp,
            'level': level,
            'message': str(msg)[:120],
            'raw': line,
        }
    except (json.JSONDecodeError, ValueError):
        return {'timestamp': '', 'level': 'unknown', 'message': line[:120], 'raw': line}


@_ttl_cache(30)
def get_caddy_logs():
    """Get Caddy log information"""
    caddy_cfg = CONFIG.get('caddy', {})
    error_log = caddy_cfg.get('error_log', '/var/log/caddy/error.log')
    access_log = caddy_cfg.get('access_log', '/var/log/caddy/access.log')

    data = {'errors': [], 'per_site': [], 'access_summary': [], 'php_errors': []}

    # Validate log paths
    if not _is_log_path_safe(error_log, 'caddy'):
        error_log = '/var/log/caddy/error.log'
    if not _is_log_path_safe(access_log, 'caddy'):
        access_log = '/var/log/caddy/access.log'

    # Caddy error log (JSON lines)
    result = run_cmd_safe(["sudo", "tail", "-20", error_log])
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                data['errors'].append(_parse_caddy_log_line(line.strip()))

    # Also try journalctl for Caddy logs if file doesn't exist
    if not data['errors']:
        result = run_cmd(
            "sudo journalctl -u caddy --no-pager -n 20 --output=cat 2>/dev/null",
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    data['errors'].append(_parse_caddy_log_line(line.strip()))

    # Per-site log info
    sites = get_caddy_sites()
    for site in sites:
        site_log = site.get('error_log')
        site_name = site['domains'][0] if site.get('domains') else '?'
        if not site_log or not _is_log_path_safe(site_log, 'caddy'):
            data['per_site'].append({
                'site': site_name,
                'count': 0,
                'last_ts': '',
                'last_msg': '',
                'log_path': site_log or '',
            })
            continue
        result = run_cmd_safe(["sudo", "tail", "-50", site_log])
        if result.returncode != 0 or not result.stdout.strip():
            data['per_site'].append({
                'site': site_name,
                'count': 0,
                'last_ts': '',
                'last_msg': '',
                'log_path': site_log,
            })
            continue
        lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
        error_lines = []
        for l in lines:
            try:
                entry = json.loads(l)
                if entry.get('level') in ('error', 'warn', 'fatal', 'panic'):
                    error_lines.append(l)
            except json.JSONDecodeError:
                if 'error' in l.lower() or 'warn' in l.lower():
                    error_lines.append(l)
        last_ts = ''
        last_msg = ''
        if error_lines:
            parsed = _parse_caddy_log_line(error_lines[-1])
            last_ts = parsed['timestamp']
            last_msg = parsed['message']
        data['per_site'].append({
            'site': site_name,
            'count': len(error_lines),
            'last_ts': last_ts,
            'last_msg': last_msg,
            'log_path': site_log,
        })
    data['per_site'].sort(key=lambda x: x['count'], reverse=True)

    # Access log summary: parse JSON access log for status codes per site
    for site in sites:
        site_log = site.get('access_log')
        site_name = site['domains'][0] if site.get('domains') else '?'
        if not site_log or not _is_log_path_safe(site_log, 'caddy'):
            continue
        result = run_cmd_safe(["sudo", "tail", "-500", site_log])
        if result.returncode != 0 or not result.stdout.strip():
            continue
        status_counts = {}
        for line in result.stdout.strip().split('\n'):
            try:
                entry = json.loads(line.strip())
                status = str(entry.get('status', ''))
                if status:
                    status_counts[status] = status_counts.get(status, 0) + 1
            except json.JSONDecodeError:
                continue
        if status_counts:
            codes = [{'code': k, 'count': str(v)} for k, v in
                     sorted(status_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
            data['access_summary'].append({'site': site_name, 'codes': codes})

    # PHP-FPM errors (same for both web servers)
    result = run_cmd("sudo tail -20 /var/log/php*-fpm.log 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('==>'):
                data['php_errors'].append({
                    'message': line[:150],
                    'raw': line,
                })

    return data


@_ttl_cache(120)
def get_caddy_certificates():
    """Get SSL certificate info from Caddy auto-HTTPS"""
    caddy_cfg = CONFIG.get('caddy', {})
    data_dir = caddy_cfg.get('data_dir', '/var/lib/caddy/.local/share/caddy/')
    cert_dir = os.path.join(data_dir, 'certificates')

    # Find all certificate files
    result = run_cmd_safe(
        ["sudo", "find", cert_dir, "-name", "*.crt"],
        timeout=10
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []

    certs = []
    seen_domains = set()
    for cert_path in result.stdout.strip().split('\n'):
        cert_path = cert_path.strip()
        if not cert_path:
            continue

        # Extract domain from path: .../certificates/acme-v02.../domain.com/domain.com.crt
        parts = cert_path.split('/')
        domain = None
        for idx, p in enumerate(parts):
            if p == 'certificates' and idx + 2 < len(parts):
                domain = parts[idx + 2]  # Skip the ACME provider dir
                break
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)

        # Read certificate expiry
        expiry_result = run_cmd_safe(
            ["sudo", "openssl", "x509", "-in", cert_path, "-enddate", "-noout"],
            timeout=5
        )
        if expiry_result.returncode != 0:
            continue

        # Parse: notAfter=Mar 15 12:00:00 2027 GMT
        expiry_str = expiry_result.stdout.strip().replace('notAfter=', '')
        try:
            expiry_dt = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
            days_left = (expiry_dt - datetime.now()).days
            expiry_date = expiry_dt.strftime('%Y-%m-%d')
        except ValueError:
            try:
                expiry_dt = datetime.strptime(expiry_str, '%b  %d %H:%M:%S %Y %Z')
                days_left = (expiry_dt - datetime.now()).days
                expiry_date = expiry_dt.strftime('%Y-%m-%d')
            except ValueError:
                continue

        certs.append({
            'domain': domain,
            'expiry': expiry_date,
            'days_left': days_left,
        })

    certs.sort(key=lambda x: x['days_left'])
    return certs


def list_caddy_configs():
    """List Caddy config files (main Caddyfile + site files)"""
    caddy_cfg = CONFIG.get('caddy', {})
    config_file = caddy_cfg.get('config_file', '/etc/caddy/Caddyfile')
    sites_dir = caddy_cfg.get('sites_dir', '/etc/caddy/sites/')

    configs = {'main': os.path.basename(config_file), 'sites': [], 'disabled': []}

    result = run_cmd_safe(["sudo", "ls", sites_dir], timeout=5)
    if result.returncode == 0 and result.stdout.strip():
        for name in result.stdout.strip().split('\n'):
            name = name.strip()
            if not name:
                continue
            if name.endswith('.disabled'):
                configs['disabled'].append(name)
            else:
                configs['sites'].append(name)

    return configs


def validate_caddy():
    """Run caddy validate, return (is_valid, output)"""
    caddy_cfg = CONFIG.get('caddy', {})
    config_file = caddy_cfg.get('config_file', '/etc/caddy/Caddyfile')
    result = run_cmd_safe(
        ["sudo", "caddy", "validate", "--config", config_file],
        timeout=15
    )
    output = (result.stderr or '') + (result.stdout or '')
    return result.returncode == 0, output.strip()


@app.route('/web-config')
@app.route('/nginx-config')
@login_required
def nginx_config():
    ws = get_web_server()
    selected = request.args.get('select', '')
    if ws == 'caddy':
        configs = list_caddy_configs()
        return render_template('caddy_config.html', configs=configs, selected=selected)
    configs = list_nginx_configs()
    return render_template('nginx_config.html', configs=configs, selected=selected)


@app.route('/api/nginx/config/read')
@login_required
def nginx_config_read():
    """Read an nginx config file"""
    name = request.args.get('name', '')
    config_type = request.args.get('type', 'enabled')

    if not name or not is_safe_name(name):
        return jsonify({'status': 'error', 'message': 'Invalid config name'}), 400

    if config_type not in ('enabled', 'available'):
        return jsonify({'status': 'error', 'message': 'Invalid type'}), 400

    path = f'/etc/nginx/sites-{config_type}/{name}'
    result = run_cmd(f"sudo cat {shlex.quote(path)}", timeout=10)
    if result.returncode == 0:
        return jsonify({'status': 'ok', 'content': result.stdout, 'name': name, 'type': config_type})
    return jsonify({'status': 'error', 'message': 'Could not read config'}), 500


@app.route('/api/nginx/config/save', methods=['POST'])
@login_required
def nginx_config_save():
    """Save nginx config with validation and reload"""
    data = request.get_json() or {}
    name = data.get('name', '')
    content = data.get('content', '')
    config_type = data.get('type', 'enabled')

    if not name or not is_safe_name(name):
        return jsonify({'status': 'error', 'message': 'Invalid config name'}), 400

    if config_type not in ('enabled', 'available'):
        return jsonify({'status': 'error', 'message': 'Invalid type'}), 400

    path = f'/etc/nginx/sites-{config_type}/{name}'

    # Backup current config
    run_cmd(f"sudo cp {shlex.quote(path)} {shlex.quote(path + '.backup')} 2>/dev/null", timeout=10)

    # Write content via temp file
    temp_path = str(DATA_DIR / f'nginx_temp_{name}')
    try:
        with open(temp_path, 'w') as f:
            f.write(content)
    except OSError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

    # Copy to nginx dir
    cp_result = run_cmd(f"sudo cp {shlex.quote(temp_path)} {shlex.quote(path)}", timeout=10)
    try:
        os.remove(temp_path)
    except OSError:
        pass

    if cp_result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Failed to write config'}), 500

    # Validate nginx config
    is_valid, output = validate_nginx()
    if not is_valid:
        # Restore backup
        run_cmd(f"sudo cp {shlex.quote(path + '.backup')} {shlex.quote(path)} 2>/dev/null", timeout=10)
        run_cmd(f"sudo rm -f {shlex.quote(path + '.backup')}", timeout=10)
        return jsonify({'status': 'error', 'message': 'Nginx config test failed', 'output': output}), 400

    # Reload nginx
    reload_result = run_cmd_safe(["sudo", "systemctl", "reload", "nginx"], timeout=15)
    # Clean up backup
    run_cmd(f"sudo rm -f {shlex.quote(path + '.backup')}", timeout=10)

    log_audit('nginx_config_save', {'name': name, 'type': config_type})
    _invalidate_cache('get_nginx_sites', 'get_nginx_logs')

    if reload_result.returncode == 0:
        return jsonify({'status': 'ok', 'message': 'Config saved and nginx reloaded'})
    return jsonify({'status': 'ok', 'message': 'Config saved but nginx reload failed'})


@app.route('/api/nginx/config/enable', methods=['POST'])
@login_required
def nginx_config_enable():
    """Enable a site by creating symlink"""
    data = request.get_json() or {}
    name = data.get('name', '')

    if not name or not is_safe_name(name):
        return jsonify({'status': 'error', 'message': 'Invalid config name'}), 400

    available = f'/etc/nginx/sites-available/{name}'
    enabled = f'/etc/nginx/sites-enabled/{name}'

    # Check if available exists
    check = run_cmd(f"sudo test -f {shlex.quote(available)} && echo ok", timeout=5)
    if 'ok' not in check.stdout:
        return jsonify({'status': 'error', 'message': 'Config not found in sites-available'}), 404

    result = run_cmd(f"sudo ln -sf {shlex.quote(available)} {shlex.quote(enabled)}", timeout=10)
    if result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Failed to create symlink'}), 500

    # Validate and reload
    is_valid, output = validate_nginx()
    if not is_valid:
        run_cmd(f"sudo rm -f {shlex.quote(enabled)}", timeout=10)
        return jsonify({'status': 'error', 'message': 'Nginx config test failed after enabling', 'output': output}), 400

    reload_result = run_cmd_safe(["sudo", "systemctl", "reload", "nginx"], timeout=15)
    if reload_result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Nginx reload failed after enabling', 'output': reload_result.stderr.strip()}), 500
    log_audit('nginx_config_enable', {'name': name})
    _invalidate_cache('get_nginx_sites', 'get_nginx_logs')
    return jsonify({'status': 'ok', 'message': f'{name} enabled and nginx reloaded'})


@app.route('/api/nginx/config/disable', methods=['POST'])
@login_required
def nginx_config_disable():
    """Disable a site by removing symlink from sites-enabled"""
    data = request.get_json() or {}
    name = data.get('name', '')

    if not name or not is_safe_name(name):
        return jsonify({'status': 'error', 'message': 'Invalid config name'}), 400

    enabled = f'/etc/nginx/sites-enabled/{name}'
    result = run_cmd(f"sudo rm -f {shlex.quote(enabled)}", timeout=10)
    if result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Failed to remove symlink'}), 500

    reload_result = run_cmd_safe(["sudo", "systemctl", "reload", "nginx"], timeout=15)
    if reload_result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Nginx reload failed after disabling', 'output': reload_result.stderr.strip()}), 500
    log_audit('nginx_config_disable', {'name': name})
    _invalidate_cache('get_nginx_sites', 'get_nginx_logs')
    return jsonify({'status': 'ok', 'message': f'{name} disabled and nginx reloaded'})


@app.route('/api/nginx/validate', methods=['POST'])
@login_required
def nginx_validate_route():
    """Test nginx configuration"""
    is_valid, output = validate_nginx()
    return jsonify({'status': 'ok' if is_valid else 'error', 'valid': is_valid, 'output': output})


@app.route('/api/webserver/validate', methods=['POST'])
@login_required
def webserver_validate_route():
    """Validate active web server configuration"""
    is_valid, output = validate_web_config()
    return jsonify({'status': 'ok' if is_valid else 'error', 'valid': is_valid, 'output': output})


# ---------------------------------------------------------------------------
# Caddy config editor routes
# ---------------------------------------------------------------------------

@app.route('/api/caddy/config/read')
@login_required
def caddy_config_read():
    """Read a Caddy config file"""
    name = request.args.get('name', '')
    config_type = request.args.get('type', 'main')

    if config_type not in ('main', 'site'):
        return jsonify({'status': 'error', 'message': 'Invalid type'}), 400

    caddy_cfg = CONFIG.get('caddy', {})
    config_file = caddy_cfg.get('config_file', '/etc/caddy/Caddyfile')
    sites_dir = caddy_cfg.get('sites_dir', '/etc/caddy/sites/')

    if config_type == 'main':
        path = config_file
    else:
        if not name or not is_safe_name(name):
            return jsonify({'status': 'error', 'message': 'Invalid config name'}), 400
        path = os.path.join(sites_dir, name)

    if not _is_caddy_path_safe(path):
        return jsonify({'status': 'error', 'message': 'Path not allowed'}), 403

    result = run_cmd_safe(["sudo", "cat", path], timeout=10)
    if result.returncode == 0:
        return jsonify({'status': 'ok', 'content': result.stdout, 'name': name or os.path.basename(config_file), 'type': config_type})
    return jsonify({'status': 'error', 'message': 'Could not read config'}), 500


@app.route('/api/caddy/config/save', methods=['POST'])
@login_required
def caddy_config_save():
    """Save Caddy config with validation and reload"""
    data = request.get_json() or {}
    name = data.get('name', '')
    content = data.get('content', '')
    config_type = data.get('type', 'main')

    if config_type not in ('main', 'site'):
        return jsonify({'status': 'error', 'message': 'Invalid type'}), 400

    caddy_cfg = CONFIG.get('caddy', {})
    config_file = caddy_cfg.get('config_file', '/etc/caddy/Caddyfile')
    sites_dir = caddy_cfg.get('sites_dir', '/etc/caddy/sites/')

    if config_type == 'main':
        path = config_file
    else:
        if not name or not is_safe_name(name):
            return jsonify({'status': 'error', 'message': 'Invalid config name'}), 400
        path = os.path.join(sites_dir, name)

    if not _is_caddy_path_safe(path):
        return jsonify({'status': 'error', 'message': 'Path not allowed'}), 403

    # Backup current config
    run_cmd(f"sudo cp {shlex.quote(path)} {shlex.quote(path + '.backup')} 2>/dev/null", timeout=10)

    # Write content via temp file
    safe_name = name if name and is_safe_name(name) else 'Caddyfile'
    temp_path = str(DATA_DIR / f'caddy_temp_{safe_name}')
    try:
        with open(temp_path, 'w') as f:
            f.write(content)
    except OSError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

    # Copy to caddy dir
    cp_result = run_cmd(f"sudo cp {shlex.quote(temp_path)} {shlex.quote(path)}", timeout=10)
    try:
        os.remove(temp_path)
    except OSError:
        pass

    if cp_result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Failed to write config'}), 500

    # Validate caddy config
    is_valid, output = validate_caddy()
    if not is_valid:
        # Restore backup
        run_cmd(f"sudo cp {shlex.quote(path + '.backup')} {shlex.quote(path)} 2>/dev/null", timeout=10)
        run_cmd(f"sudo rm -f {shlex.quote(path + '.backup')}", timeout=10)
        return jsonify({'status': 'error', 'message': 'Caddy config validation failed', 'output': output}), 400

    # Reload caddy
    reload_result = run_cmd_safe(["sudo", "systemctl", "reload", "caddy"], timeout=15)
    # Clean up backup
    run_cmd(f"sudo rm -f {shlex.quote(path + '.backup')}", timeout=10)

    log_audit('caddy_config_save', {'name': name or 'Caddyfile', 'type': config_type})
    _invalidate_cache('get_caddy_sites', 'get_caddy_logs', 'get_caddy_certificates')

    if reload_result.returncode == 0:
        return jsonify({'status': 'ok', 'message': 'Config saved and Caddy reloaded'})
    return jsonify({'status': 'ok', 'message': 'Config saved but Caddy reload failed'})


@app.route('/api/caddy/config/toggle', methods=['POST'])
@login_required
def caddy_config_toggle():
    """Enable/disable a Caddy site file by renaming with .disabled extension"""
    data = request.get_json() or {}
    name = data.get('name', '')
    action = data.get('action', '')  # 'enable' or 'disable'

    base_name = name.removesuffix('.disabled') if name else ''
    if not base_name or not is_safe_name(base_name):
        return jsonify({'status': 'error', 'message': 'Invalid config name'}), 400
    if action not in ('enable', 'disable'):
        return jsonify({'status': 'error', 'message': 'Invalid action'}), 400

    caddy_cfg = CONFIG.get('caddy', {})
    sites_dir = caddy_cfg.get('sites_dir', '/etc/caddy/sites/')

    if action == 'disable':
        old_path = os.path.join(sites_dir, name)
        new_path = os.path.join(sites_dir, name + '.disabled')
    else:
        old_path = os.path.join(sites_dir, name)
        new_path = os.path.join(sites_dir, name.removesuffix('.disabled'))

    if not _is_caddy_path_safe(old_path) or not _is_caddy_path_safe(new_path):
        return jsonify({'status': 'error', 'message': 'Path not allowed'}), 403

    result = run_cmd(f"sudo mv {shlex.quote(old_path)} {shlex.quote(new_path)}", timeout=10)
    if result.returncode != 0:
        return jsonify({'status': 'error', 'message': f'Failed to {action} config'}), 500

    # Validate and reload
    is_valid, output = validate_caddy()
    if not is_valid:
        # Revert
        run_cmd(f"sudo mv {shlex.quote(new_path)} {shlex.quote(old_path)}", timeout=10)
        return jsonify({'status': 'error', 'message': f'Caddy validation failed after {action}', 'output': output}), 400

    reload_result = run_cmd_safe(["sudo", "systemctl", "reload", "caddy"], timeout=15)
    log_audit(f'caddy_config_{action}', {'name': name})
    _invalidate_cache('get_caddy_sites', 'get_caddy_logs', 'get_caddy_certificates')

    if reload_result.returncode == 0:
        return jsonify({'status': 'ok', 'message': f'Site {action}d and Caddy reloaded'})
    return jsonify({'status': 'ok', 'message': f'Site {action}d but Caddy reload failed'})


@app.route('/api/caddy/validate', methods=['POST'])
@login_required
def caddy_validate_route():
    """Test Caddy configuration"""
    is_valid, output = validate_caddy()
    return jsonify({'status': 'ok' if is_valid else 'error', 'valid': is_valid, 'output': output})


@app.route('/api/caddy/debug')
@login_required
def caddy_debug():
    """Debug endpoint: show Caddyfile content and parsed sites"""
    caddy_cfg = CONFIG.get('caddy', {})
    config_file = caddy_cfg.get('config_file', '/etc/caddy/Caddyfile')
    sites_dir = caddy_cfg.get('sites_dir', '/etc/caddy/sites/')

    result = run_cmd_safe(["sudo", "cat", config_file], timeout=10)
    caddyfile_content = result.stdout if result.returncode == 0 else f'ERROR: {result.stderr}'

    # Check sites dir
    sites_dir_content = {}
    if _is_caddy_path_safe(sites_dir):
        ls_result = run_cmd_safe(["sudo", "ls", sites_dir], timeout=5)
        if ls_result.returncode == 0:
            for fname in ls_result.stdout.strip().split('\n'):
                if fname.strip():
                    fpath = os.path.join(sites_dir, fname.strip())
                    if _is_caddy_path_safe(fpath):
                        fr = run_cmd_safe(["sudo", "cat", fpath], timeout=5)
                        sites_dir_content[fname.strip()] = fr.stdout if fr.returncode == 0 else f'ERROR: {fr.stderr}'

    # Parse without auto-log injection
    parsed = _parse_caddyfile(result.stdout if result.returncode == 0 else '', sites_dir=sites_dir)

    return jsonify({
        'config_file': config_file,
        'sites_dir': sites_dir,
        'caddyfile_readable': result.returncode == 0,
        'caddyfile_lines': len(caddyfile_content.split('\n')) if result.returncode == 0 else 0,
        'caddyfile_content': caddyfile_content[:5000],
        'sites_dir_files': list(sites_dir_content.keys()),
        'parsed_sites': [{'address': s.get('address'), 'domains': s.get('domains'), 'has_log': s.get('log_output') is not None} for s in parsed],
        'parsed_count': len(parsed),
        'web_server_config': get_web_server(),
    })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # Start background push notification monitor
    monitor = threading.Thread(target=_monitor_loop, daemon=True)
    monitor.start()
    app.run(host='0.0.0.0', port=5050, debug=False)
