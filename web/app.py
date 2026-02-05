#!/usr/bin/env python3
"""
VPS Manager - Web Interface
Flask-based web dashboard for managing a VPS.
Runs locally on the VPS itself (subprocess.run instead of SSH).
"""

import os
import re
import io
import json
import shlex
import shutil
import subprocess
import threading
import time
import logging
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from pywebpush import webpush, WebPushException
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
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
    app.secret_key = _generated

app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB upload limit
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
    logging.warning(
        'WARNING: No password configured. Generated temporary password: %s  '
        'Set VPS_MANAGER_PASS env var or change password in settings.',
        _generated_pass
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

NOTIFICATION_COOLDOWN = CONFIG.get('notification_cooldown', 3600)
MONITOR_INTERVAL = CONFIG.get('monitor_interval', 300)
METRICS_PATH = DATA_DIR / 'metrics.json'
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
    SUBSCRIPTIONS_PATH.write_text(json.dumps(subs, indent=2))


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
    NOTIFICATION_LOG_PATH.write_text(json.dumps(log, indent=2))


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
    NOTIFICATION_HISTORY_PATH.write_text(json.dumps(history[-100:], indent=2))


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
    METRICS_PATH.write_text(json.dumps(metrics))


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
        try:
            # Collect metrics every cycle (independent of subscriptions)
            try:
                collect_metrics()
            except Exception as e:
                logger.warning(f"Metrics collection error: {e}")

            subs = _load_subscriptions()
            if not subs:
                time.sleep(MONITOR_INTERVAL)
                continue

            # Gather current state
            data = get_server_overview()
            services = get_services_status()
            pm2 = get_pm2_processes()
            ssl = get_ssl_certificates()
            alerts = get_dashboard_alerts(data, services, pm2, ssl)

            # Add DDoS alerts
            ddos_alerts = check_ddos_indicators()
            alerts.extend(ddos_alerts)

            # Add backup alerts
            backup_alerts = check_backup_alerts()
            alerts.extend(backup_alerts)

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

        except Exception as e:
            logger.warning(f"Monitor error: {e}")

        time.sleep(MONITOR_INTERVAL)

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


@app.context_processor
def inject_global_info():
    return {
        'server_ip': get_server_ip(),
        'global_hostname': get_server_hostname(),
        'global_uptime': get_server_uptime_short(),
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


# Login rate limiting: max 5 attempts per IP per 5 minutes
_login_attempts = {}  # {ip: [(timestamp, ...), ...]}
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW = 300  # seconds


def _is_rate_limited(ip):
    """Check if an IP has exceeded login attempt limits"""
    now = time.time()
    attempts = _login_attempts.get(ip, [])
    # Remove expired attempts
    attempts = [t for t in attempts if now - t < _LOGIN_WINDOW]
    _login_attempts[ip] = attempts
    return len(attempts) >= _LOGIN_MAX_ATTEMPTS


def _record_attempt(ip):
    """Record a failed login attempt"""
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
            return redirect(url_for('dashboard'))
        _record_attempt(client_ip)
        flash('Invalid username or password', 'danger')
    return render_template('login.html', show_2fa=show_2fa)


@app.route('/logout')
def logout():
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
    if len(mem_parts) >= 7:
        mem_total = int(mem_parts[1])
        mem_used = int(mem_parts[2])
        mem_available = int(mem_parts[6])
        mem_pct = round(mem_used / mem_total * 100) if mem_total else 0
        mem_total_gb = f"{mem_total / (1024**3):.1f}"
        mem_used_gb = f"{mem_used / (1024**3):.1f}"
        mem_avail_gb = f"{mem_available / (1024**3):.1f}"
    else:
        mem_total_gb = mem_used_gb = mem_avail_gb = "?"
        mem_pct = 0

    # Parse swap
    swap_parts = swap_line.split()
    swap_pct = 0
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

    # Parse disk
    disk_parts = disk_line.split()
    if len(disk_parts) >= 6:
        disk_size = disk_parts[1]
        disk_used = disk_parts[2]
        disk_avail = disk_parts[3]
        disk_pct_str = disk_parts[4]
        disk_pct = int(disk_pct_str.rstrip('%'))
    else:
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


def get_nginx_sites():
    """Get nginx sites with HTTP status"""
    sites_dir = CONFIG['nginx'].get('sites_enabled', '/etc/nginx/sites-enabled/')
    result = run_cmd(f"ls {sites_dir}")
    if result.returncode != 0:
        return []

    configs = [s.strip() for s in result.stdout.strip().split('\n')
               if s.strip() and s.strip() != 'default']
    sites = []

    for config in configs:
        info_result = run_cmd(
            f"grep -E 'server_name|root |proxy_pass' {sites_dir}{config} 2>/dev/null"
        )
        if info_result.returncode != 0:
            continue

        domains = []
        doc_root = None
        proxy = None

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

        # Deduplicate domains (certbot creates 2 server blocks per config)
        domains = list(dict.fromkeys(domains))

        if domains:
            # Check HTTP status for first domain
            http_result = run_cmd(
                f"curl -s -o /dev/null -w '%{{http_code}}' https://{domains[0]} --max-time 5",
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
            })

    return sites


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

    # Deduplicate php-fpm
    final_services = []
    php_found = False
    for svc in services:
        if 'php' in svc and 'fpm' in svc:
            if php_found:
                continue
            php_found = True
        final_services.append(svc)

    result = run_cmd(f"systemctl is-active {' '.join(final_services)}")
    statuses = result.stdout.strip().split('\n') if result.stdout else []

    svc_list = []
    for i, service in enumerate(final_services):
        status = statuses[i].strip() if i < len(statuses) else 'unknown'
        uptime = ''
        if status == 'active':
            up_result = run_cmd(
                f"systemctl show {service} --property=ActiveEnterTimestamp --value 2>/dev/null"
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
    BACKUP_STATUS_PATH.write_text(json.dumps(status, indent=2))


def get_backup_status():
    """Get backup status info"""
    backup_cfg = CONFIG.get('backup', {})
    log_path = backup_cfg.get('log_path', '/var/log/vps-backup.log')
    backup_dir = backup_cfg.get('backup_dir', '/var/backups/vps/')
    db_backup_dir = backup_cfg.get('db_backup_dir', '/var/backups/vps/databases/')

    data = {'log': '', 'size': '', 'db_backups': '', 'status': None, 'history': [],
            'backup_files': [], 'db_files': [], 'site_backups': []}

    result = run_cmd(f"tail -5 {log_path} 2>/dev/null")
    if result.returncode == 0:
        data['log'] = result.stdout.strip()

    result = run_cmd(f"du -sh {backup_dir} 2>/dev/null")
    if result.returncode == 0:
        data['size'] = result.stdout.strip()

    result = run_cmd(f"ls -lt {db_backup_dir} 2>/dev/null | head -5")
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

    # List site backup directories with total sizes
    sites_dir = Path(backup_dir) / 'sites'
    try:
        if sites_dir.is_dir():
            for d in sorted(sites_dir.iterdir(), key=lambda x: x.name):
                if d.is_dir():
                    total_size = sum(f.stat().st_size for f in d.rglob('*') if f.is_file())
                    latest_mtime = max((f.stat().st_mtime for f in d.rglob('*') if f.is_file()), default=0)
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


def get_firewall_security():
    """Get firewall and security info"""
    data = {
        'ufw': '', 'fail2ban': '', 'banned': '', 'sessions': '', 'auth_log': '',
        'f2b_config': {}, 'jails': [],
    }

    result = run_cmd("sudo ufw status numbered 2>/dev/null")
    if result.returncode == 0:
        data['ufw'] = result.stdout.strip()

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
                jail_result = run_cmd(f"sudo fail2ban-client status {jail_name} 2>/dev/null")
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


def get_nginx_logs():
    """Get nginx log information"""
    nginx_cfg = CONFIG.get('nginx', {})
    error_log = nginx_cfg.get('error_log', '/var/log/nginx/error.log')
    access_log = nginx_cfg.get('access_log', '/var/log/nginx/access.log')

    data = {'errors': [], 'per_site': [], 'access_summary': [], 'php_errors': []}

    # Nginx error log - parsed into structured entries
    result = run_cmd(f"sudo tail -20 {error_log} 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                data['errors'].append(_parse_nginx_error_line(line.strip()))

    # Per-site error logs
    result = run_cmd("ls /var/log/nginx/*error* 2>/dev/null")
    if result.returncode == 0 and result.stdout.strip():
        log_files = [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
        for log_file in log_files:
            name = os.path.basename(log_file)
            size_result = run_cmd(f"wc -l < {log_file} 2>/dev/null")
            line_count = size_result.stdout.strip() if size_result.returncode == 0 else '?'
            last_result = run_cmd(f"tail -1 {log_file} 2>/dev/null")
            last_line = last_result.stdout.strip()[:100] if last_result.stdout.strip() else 'empty'
            # Derive site name from log filename
            site = name.replace('-error.log', '').replace('.error.log', '').replace('error.log', 'global')
            data['per_site'].append({
                'name': name,
                'site': site,
                'path': log_file,
                'lines': line_count,
                'last': last_line,
            })

    # Access log summary
    result = run_cmd(
        f"sudo awk '{{print $9}}' {access_log} 2>/dev/null | sort | uniq -c | sort -rn | head -10"
    )
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            parts = line.strip().split()
            if len(parts) == 2:
                data['access_summary'].append({
                    'code': parts[1],
                    'count': parts[0],
                })

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
        return "Elke minuut"
    if minute.startswith('*/'):
        return f"Elke {minute[2:]} minuten"
    if hour.startswith('*/'):
        return f"Elke {hour[2:]} uur"
    if dom == '*' and month == '*' and dow == '*':
        return f"Dagelijks om {hour.zfill(2)}:{minute.zfill(2)}"
    if dom == '*' and month == '*' and dow != '*':
        days_map = {'0': 'zo', '1': 'ma', '2': 'di', '3': 'wo', '4': 'do', '5': 'vr', '6': 'za', '7': 'zo'}
        day_names = ','.join(days_map.get(d.strip(), d.strip()) for d in dow.split(','))
        return f"{day_names} om {hour.zfill(2)}:{minute.zfill(2)}"
    if month == '*' and dow == '*':
        return f"Dag {dom} om {hour.zfill(2)}:{minute.zfill(2)}"
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
    col_next = header.index('NEXT')
    col_left = header.index('LEFT')
    col_last = header.index('LAST')
    col_unit = header.index('UNIT')
    col_activates = header.index('ACTIVATES')

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
            sites.append({'site': site_name, 'size': size})

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
    severity_order = {'error': 0, 'warning': 1, 'info': 2}
    alerts.sort(key=lambda a: severity_order.get(a['severity'], 99))

    return alerts


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


def is_path_allowed(path):
    """Check if path is within allowed directories (whitelist approach)"""
    allowed = CONFIG.get('file_browser', {}).get('allowed_paths', ['/var/www'])
    real = os.path.realpath(path)
    for a in allowed:
        if real == a or real.startswith(a + '/'):
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
    ssl = get_ssl_certificates()
    alerts = get_dashboard_alerts(data, services, pm2, ssl)
    # Add DDoS and backup alerts
    alerts.extend(check_ddos_indicators())
    alerts.extend(check_backup_alerts())
    # Re-sort
    severity_order = {'error': 0, 'warning': 1, 'info': 2}
    alerts.sort(key=lambda a: severity_order.get(a['severity'], 99))
    return render_template('dashboard.html', data=data, services=services, pm2=pm2, ssl=ssl, alerts=alerts)


@app.route('/websites')
@login_required
def websites():
    sites = get_nginx_sites()
    return render_template('websites.html', sites=sites)


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
        return jsonify({'status': 'ok', 'message': f"'{name}' restarted"})
    return jsonify({'status': 'error', 'message': f"Could not restart '{name}': {result.stderr}"}), 500


@app.route('/pm2/stop/<name>', methods=['POST'])
@login_required
def pm2_stop(name):
    if not is_safe_name(name):
        return jsonify({'status': 'error', 'message': 'Invalid process name'}), 400
    result = run_cmd_safe(["pm2", "stop", name])
    if result.returncode == 0:
        return jsonify({'status': 'ok', 'message': f"'{name}' stopped"})
    return jsonify({'status': 'error', 'message': f"Could not stop '{name}': {result.stderr}"}), 500


@app.route('/pm2/start/<name>', methods=['POST'])
@login_required
def pm2_start(name):
    if not is_safe_name(name):
        return jsonify({'status': 'error', 'message': 'Invalid process name'}), 400
    result = run_cmd_safe(["pm2", "start", name])
    if result.returncode == 0:
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
    certs = get_ssl_certificates()
    return render_template('ssl.html', certs=certs)


@app.route('/ssl/renew', methods=['POST'])
@login_required
def ssl_renew():
    data = request.get_json() or {}
    domain = data.get('domain')
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
        return jsonify({'status': 'ok', 'message': 'Renewal successful', 'output': output})
    return jsonify({'status': 'error', 'message': 'Renewal failed', 'output': output}), 500


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
        return jsonify({'status': 'ok', 'message': f"'{name}' {action} successful"})
    return jsonify({'status': 'error', 'message': f"Could not {action} '{name}': {result.stderr}"}), 500


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
        return jsonify({'error': 'No path specified'}), 400

    real_path = os.path.realpath(path)
    backup_cfg = CONFIG.get('backup', {})
    backup_dir = os.path.realpath(backup_cfg.get('backup_dir', '/var/backups/vps/'))
    db_backup_dir = os.path.realpath(backup_cfg.get('db_backup_dir', '/var/backups/vps/databases/'))

    # Only allow paths within backup directories
    allowed = False
    for allowed_dir in (backup_dir, db_backup_dir):
        if real_path == allowed_dir or real_path.startswith(allowed_dir + '/'):
            allowed = True
            break

    if not allowed:
        return jsonify({'error': 'Access denied'}), 403

    if os.path.isfile(real_path):
        return send_file(real_path, as_attachment=True)

    if os.path.isdir(real_path):
        # Stream directory as tar.gz
        import tarfile
        buf = io.BytesIO()
        dirname = os.path.basename(real_path)
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            tar.add(real_path, arcname=dirname)
        buf.seek(0)
        return send_file(buf, as_attachment=True,
                         download_name=f"{dirname}.tar.gz",
                         mimetype='application/gzip')

    return jsonify({'error': 'Not found'}), 404


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

    # Add permanent UFW deny rule
    ufw_result = run_cmd_safe(['sudo', 'ufw', 'deny', 'from', ip], timeout=15)
    ufw_ok = ufw_result.returncode == 0
    ufw_msg = ufw_result.stdout.strip() or ufw_result.stderr.strip()

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
    """Unban an IP from a fail2ban jail"""
    data = request.get_json() or {}
    ip = data.get('ip', '').strip()
    jail = data.get('jail', 'sshd').strip()

    if not ip or not _is_valid_ipv4(ip):
        return jsonify({'status': 'error', 'message': 'Invalid IPv4 address'}), 400
    if not is_safe_name(jail):
        return jsonify({'status': 'error', 'message': 'Invalid jail name'}), 400

    result = run_cmd_safe(['sudo', 'fail2ban-client', 'set', jail, 'unbanip', ip], timeout=15)
    if result.returncode == 0:
        return jsonify({'status': 'ok', 'message': f'{ip} unbanned from {jail}'})
    return jsonify({'status': 'error', 'message': result.stderr.strip() or 'Unban failed'}), 500


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
    if reload_result.returncode == 0:
        return jsonify({'status': 'ok', 'message': f'Whitelist updated ({len(validated)} entries), fail2ban reloaded'})
    return jsonify({'status': 'ok', 'message': f'Whitelist updated but fail2ban reload failed: {reload_result.stderr.strip()}'})


@app.route('/firewall/banned-ips')
@login_required
def firewall_banned_ips():
    """Get structured list of currently banned IPs per jail"""
    jails_data = []

    # Get list of active jails
    result = run_cmd("sudo fail2ban-client status 2>/dev/null", timeout=15)
    if result.returncode != 0:
        return jsonify([])

    jail_match = re.search(r'Jail list:\s*(.+)', result.stdout)
    if not jail_match:
        return jsonify([])

    jail_names = [j.strip() for j in jail_match.group(1).split(',') if j.strip()]

    for jail_name in jail_names:
        jail_result = run_cmd(f"sudo fail2ban-client status {shlex.quote(jail_name)} 2>/dev/null", timeout=10)
        if jail_result.returncode != 0:
            continue

        # Extract banned IP list
        ip_match = re.search(r'Banned IP list:\s*(.*)', jail_result.stdout)
        if ip_match:
            ip_str = ip_match.group(1).strip()
            ips = [ip.strip() for ip in ip_str.split() if ip.strip()] if ip_str else []
        else:
            ips = []

        jails_data.append({'jail': jail_name, 'ips': ips})

    return jsonify(jails_data)


@app.route('/updates')
@login_required
def updates():
    update_list = get_system_updates()
    return render_template('updates.html', updates=update_list)


@app.route('/updates/install', methods=['POST'])
@login_required
def install_updates():
    result = run_cmd("sudo apt upgrade -y 2>&1", timeout=300)
    if result.returncode == 0:
        return jsonify({'status': 'ok', 'message': 'Updates installed', 'output': result.stdout[-500:]})
    return jsonify({'status': 'error', 'message': 'Installation error', 'output': result.stderr[-500:]}), 500


# ---------------------------------------------------------------------------
# VPS Manager self-update (GitHub releases)
# ---------------------------------------------------------------------------

VERSION_FILE = Path(__file__).parent / 'VERSION'
APP_DIR = '/var/www/vps.dmmusic.nl'


def _get_current_version():
    """Read current version from VERSION file"""
    try:
        return VERSION_FILE.read_text().strip()
    except (OSError, FileNotFoundError):
        return '0.0.0'


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

    # Read the new version from the freshly pulled VERSION file
    new_version = _get_current_version()

    # Restart PM2 process
    pm2_result = run_cmd_safe(["pm2", "restart", "vps-manager"], timeout=15)
    restart_ok = pm2_result.returncode == 0

    return jsonify({
        'status': 'ok',
        'message': 'Update installed' + (' - restart pending' if not restart_ok else ''),
        'previous_version': current_before,
        'new_version': new_version,
        'restart': 'ok' if restart_ok else 'failed',
        'output': result.stdout[-500:],
    })


@app.route('/nginx-logs')
@login_required
def nginx_logs_page():
    data = get_nginx_logs()
    return render_template('nginx_logs.html', data=data)


@app.route('/api/nginx-log')
@login_required
def api_nginx_log():
    """Get content of a specific nginx log file"""
    log_file = request.args.get('file', '')
    try:
        lines = int(request.args.get('lines', 50))
    except (ValueError, TypeError):
        lines = 50
    lines = min(lines, 200)
    # Only allow files in /var/log/nginx/ - resolve symlinks and validate
    if not log_file or '..' in log_file:
        return jsonify({'error': 'Invalid log file'}), 400
    real_log = os.path.realpath(log_file)
    if not real_log.startswith('/var/log/nginx/'):
        return jsonify({'error': 'Invalid log file'}), 400
    result = run_cmd_safe(["sudo", "tail", f"-{lines}", real_log])
    if result.returncode == 0:
        return jsonify({'content': result.stdout, 'file': os.path.basename(real_log)})
    return jsonify({'error': 'Could not read log file'}), 500


@app.route('/databases')
@login_required
def databases():
    db_list = get_database_info()
    return render_template('databases.html', databases=db_list, phpmyadmin_path=CONFIG.get('phpmyadmin_path', '/phpmyadmin/'))


@app.route('/cronjobs')
@login_required
def cronjobs():
    data = get_cronjobs()
    return render_template('cronjobs.html', data=data)


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

    # Validate cwd is a real directory
    real_cwd = os.path.realpath(cwd)
    if not os.path.isdir(real_cwd):
        real_cwd = '/'

    # Block dangerous patterns (defense-in-depth, not a security boundary)
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
            return jsonify({'stdout': '', 'stderr': 'Blocked: dangerous command', 'cwd': real_cwd})
    for pattern in dangerous_patterns:
        if re.search(pattern, cmd_lower):
            return jsonify({'stdout': '', 'stderr': 'Blocked: dangerous command', 'cwd': real_cwd})

    # Handle 'clear' locally
    if cmd == 'clear':
        return jsonify({'stdout': '', 'stderr': '', 'cwd': real_cwd, 'clear': True})

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
    real_path = os.path.realpath(path)

    if not os.path.isdir(real_path):
        return jsonify({'error': 'Directory not found'}), 404

    if not is_path_allowed(real_path):
        return jsonify({'error': 'Access denied'}), 403

    # Get owner/permissions of current directory
    import pwd
    import grp
    import stat as stat_module
    dir_info = {}
    try:
        dir_stat = os.stat(real_path)
        try:
            dir_info['owner'] = pwd.getpwuid(dir_stat.st_uid).pw_name
        except KeyError:
            dir_info['owner'] = str(dir_stat.st_uid)
        try:
            dir_info['group'] = grp.getgrgid(dir_stat.st_gid).gr_name
        except KeyError:
            dir_info['group'] = str(dir_stat.st_gid)
        dir_info['mode'] = oct(stat_module.S_IMODE(dir_stat.st_mode))
        dir_info['writable'] = os.access(real_path, os.W_OK)
    except OSError:
        dir_info = {'owner': '?', 'group': '?', 'mode': '?', 'writable': False}

    items = []
    try:
        for name in sorted(os.listdir(real_path)):
            full = os.path.join(real_path, name)
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
                items.append({
                    'name': name,
                    'type': 'unknown',
                    'size': '-',
                    'modified': '-',
                    'owner': '?',
                    'mode': '?',
                })
    except PermissionError:
        return jsonify({'error': 'No read permissions on this directory'}), 403

    # Sort: dirs first, then files
    items.sort(key=lambda x: (0 if x['type'] == 'dir' else 1, x['name'].lower()))

    parent_path = os.path.dirname(real_path)
    parent = parent_path if (real_path != '/' and is_path_allowed(parent_path)) else None

    return jsonify({
        'path': real_path,
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

    real_path = os.path.realpath(os.path.join(path, name))
    if not is_path_allowed(real_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    try:
        os.makedirs(real_path, exist_ok=False)
        return jsonify({'status': 'ok', 'message': f"Folder '{name}' created"})
    except FileExistsError:
        return jsonify({'status': 'error', 'message': 'Folder already exists'}), 400
    except OSError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/files/download')
@login_required
def files_download():
    path = request.args.get('path', '')
    real_path = os.path.realpath(path)

    if not os.path.isfile(real_path):
        return jsonify({'error': 'File not found'}), 404

    if not is_path_allowed(real_path):
        return jsonify({'error': 'Access denied'}), 403

    return send_file(real_path, as_attachment=True)


@app.route('/files/upload', methods=['POST'])
@login_required
def files_upload():
    path = request.form.get('path', '/var/www')
    real_path = os.path.realpath(path)

    if not os.path.isdir(real_path):
        return jsonify({'status': 'error', 'message': 'Directory not found'}), 404

    if not is_path_allowed(real_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file received'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file selected'}), 400

    filename = secure_filename(file.filename)
    dest = os.path.join(real_path, filename)

    try:
        file.save(dest)
        return jsonify({'status': 'ok', 'message': f"'{filename}' uploaded"})
    except OSError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/files/delete', methods=['POST'])
@login_required
def files_delete():
    data = request.get_json() or {}
    path = data.get('path', '')
    real_path = os.path.realpath(path)

    if not is_path_allowed(real_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    if real_path in ('/', '/var', '/var/www', '/etc', '/home', '/root'):
        return jsonify({'status': 'error', 'message': 'Cannot delete system directory'}), 403

    try:
        if os.path.isdir(real_path):
            shutil.rmtree(real_path)
            return jsonify({'status': 'ok', 'message': 'Folder deleted'})
        elif os.path.isfile(real_path):
            os.remove(real_path)
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

    real_path = os.path.realpath(path)
    if not is_path_allowed(real_path):
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
    cmd.extend([ownership, real_path])

    result = run_cmd_safe(cmd, timeout=30)
    if result.returncode == 0:
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

    real_path = os.path.realpath(path)
    if not is_path_allowed(real_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    if not re.match(r'^[0-7]{3,4}$', mode):
        return jsonify({'status': 'error', 'message': 'Invalid mode (use octal like 755)'}), 400

    cmd = ['sudo', 'chmod']
    if recursive:
        cmd.append('-R')
    cmd.extend([mode, real_path])

    result = run_cmd_safe(cmd, timeout=30)
    if result.returncode == 0:
        label = 'recursively ' if recursive else ''
        return jsonify({'status': 'ok', 'message': f'Permissions {label}changed to {mode}'})
    return jsonify({'status': 'error', 'message': result.stderr.strip() or 'chmod failed'}), 500


@app.route('/files/users')
@login_required
def files_users():
    """Get list of system users and groups relevant for web files"""
    import pwd
    import grp
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

    # Replace if same endpoint already exists
    subs = [s for s in subs if s.get('endpoint') != data['endpoint']]
    subs.append({
        'endpoint': data['endpoint'],
        'keys': data['keys'],
        'preferences': {
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
            }
            break
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

    history = _load_notification_history()
    # History is stored oldest-first; the API returns newest-first,
    # so the front-end index maps to reversed order.
    reversed_idx = len(history) - 1 - int(index)
    if 0 <= reversed_idx < len(history):
        history.pop(reversed_idx)
        _save_notification_history(history)
        return jsonify({'status': 'ok', 'message': 'Notification dismissed'})
    return jsonify({'status': 'error', 'message': 'Invalid index'}), 400


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', config=CONFIG, has_2fa=HAS_2FA)


@app.route('/api/config', methods=['POST'])
@login_required
def update_config():
    global CONFIG, NOTIFICATION_COOLDOWN, MONITOR_INTERVAL
    data = request.get_json() or {}
    if not data:
        return jsonify({'status': 'error', 'message': 'No data received'}), 400

    # Merge into config (don't overwrite auth section from here)
    for key in data:
        if key == 'auth':
            continue  # Auth is handled separately
        if key in CONFIG and isinstance(CONFIG[key], dict) and isinstance(data[key], dict):
            CONFIG[key].update(data[key])
        else:
            CONFIG[key] = data[key]

    save_config(CONFIG)

    # Update runtime values
    NOTIFICATION_COOLDOWN = CONFIG.get('notification_cooldown', 3600)
    MONITOR_INTERVAL = CONFIG.get('monitor_interval', 300)

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

    return jsonify({'status': 'ok', 'message': '2FA disabled'})


@app.route('/api/backup/webhook', methods=['POST'])
@csrf.exempt
def backup_webhook():
    """Endpoint for backup scripts to report success/failure"""
    webhook_secret = CONFIG.get('backup', {}).get('webhook_secret', '')
    if not webhook_secret:
        return jsonify({'status': 'error', 'message': 'Webhook secret not configured'}), 403
    provided = request.headers.get('X-Webhook-Secret', '')
    if not provided or provided != webhook_secret:
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


@app.route('/reboot', methods=['POST'])
@login_required
def reboot():
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
        'websites': get_nginx_sites,
        'pm2': get_pm2_processes,
        'ssl': get_ssl_certificates,
        'services': get_services_status,
        'backup': get_backup_status,
        'firewall': get_firewall_security,
        'updates': get_system_updates,
        'nginx-logs': get_nginx_logs,
        'databases': get_database_info,
        'cronjobs': get_cronjobs,
    }

    if section == 'disk':
        sites, total = get_disk_per_site()
        return jsonify({'sites': sites, 'total': total})

    handler = handlers.get(section)
    if handler:
        return jsonify(handler())
    return jsonify({'error': 'Unknown section'}), 404


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # Start background push notification monitor
    monitor = threading.Thread(target=_monitor_loop, daemon=True)
    monitor.start()
    app.run(host='0.0.0.0', port=5050, debug=False)
