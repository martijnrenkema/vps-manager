#!/usr/bin/env python3
"""
VPS Manager - Web Interface
Flask-based web dashboard for managing a VPS.
Runs locally on the VPS itself (subprocess.run instead of SSH).
"""

import concurrent.futures
from collections import Counter
import gc
import grp
import gzip
import hashlib
import html as html_mod
import os
import pwd
import queue
import re
import io
import json
import hmac
import ipaddress
import secrets
import shlex
import shutil
import signal
import smtplib
import ssl as ssl_mod  # alias: de view-functie ssl() overschaduwt de modulenaam
import stat as stat_module
import subprocess
import tempfile
import threading
import time
import logging
import math
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from pathlib import Path
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file, send_from_directory,
    after_this_request, Response
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf.csrf import CSRFProtect, CSRFError
from pywebpush import webpush, WebPushException
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import urllib.error
import urllib.parse
import urllib.request
import base64

try:
    import pyotp
    import qrcode
    HAS_2FA = True
except ImportError:
    HAS_2FA = False

from config import load_config, save_config

# Load .env file if it exists (before any os.environ.get calls)
_env_file = Path(__file__).parent / '.env'
if not _env_file.exists():
    _env_file = Path(__file__).parent.parent / '.env'  # flat deployment
if _env_file.exists():
    try:
        with open(_env_file) as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith('#') and '=' in _line:
                    _key, _val = _line.split('=', 1)
                    _val = _val.strip()
                    # PASS="x y" → x y (zoals shells en dotenv het lezen)
                    if len(_val) >= 2 and _val[0] == _val[-1] and _val[0] in '"\'':
                        _val = _val[1:-1]
                    if _key.strip() not in os.environ:  # Don't override existing env vars
                        os.environ[_key.strip()] = _val
    except OSError:
        pass

def _write_private_file(path, data):
    """Schrijf een geheim bestand dat vanaf het eerste moment 0600 is
    (write + chmod achteraf laat een venster met de umask-rechten, vaak 0644)."""
    path = Path(path)
    if isinstance(data, str):
        data = data.encode()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)  # ook als het bestand al bestond met ruimere rechten
        os.write(fd, data)
    finally:
        os.close(fd)


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
    _write_private_file(_secret_key_file, _generated)
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
# Standaard verloopt een CSRF-token na 1 uur, waardoor elke actie in een tab
# die langer openstaat faalt. Het token is al aan de sessie gebonden, dus
# laat het net zo lang leven als de sessie.
app.config['WTF_CSRF_TIME_LIMIT'] = None
csrf = CSRFProtect(app)

# App draait achter nginx op dezelfde host: vertrouw één proxy-hop zodat
# request.remote_addr de echte client-IP is (rate limiting + audit logs).
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Content-Security-Policy: alles (ook Chart.js en fonts) wordt lokaal geserveerd,
# dus geen externe bronnen. 'unsafe-inline' is nodig omdat de templates inline
# scripts/styles bevatten; de CSP is een tweede verdedigingslaag bovenop escHtml().
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


def _compute_asset_version():
    """Cache-buster voor static URLs: verandert bij elke wijziging in static/
    (ook bij een update naar een commit zonder versie-bump)."""
    h = hashlib.sha1()
    static_root = Path(app.static_folder)
    try:
        for f in sorted(static_root.rglob('*')):
            if f.is_file():
                st = f.stat()
                h.update(f'{f.relative_to(static_root)}:{st.st_size}:{int(st.st_mtime)}'.encode())
    except OSError:
        pass
    return h.hexdigest()[:10]


ASSET_VERSION = _compute_asset_version()
_GZIP_TYPES = ('text/html', 'text/css', 'application/javascript', 'text/javascript',
               'application/json', 'image/svg+xml', 'application/manifest+json')


@app.after_request
def _static_cache_and_compress(resp):
    # Geversioneerde static URLs (?v=) veranderen bij elke wijziging, dus de
    # browser mag ze onbeperkt cachen: geen revalidatie-requests meer die
    # waitress-threads bezetten bij elke paginawissel.
    if request.endpoint == 'static' and request.args.get('v') and resp.status_code == 200:
        resp.headers['Cache-Control'] = 'public, max-age=31536000, immutable'

    # Waitress comprimeert niet en de reverse proxy is niet altijd zo
    # ingesteld; HTML-pagina's met inline scripts zijn 50-100 KB.
    if (resp.status_code == 200
            and 'gzip' in request.headers.get('Accept-Encoding', '')
            and 'Content-Encoding' not in resp.headers
            and resp.mimetype in _GZIP_TYPES
            and (request.endpoint == 'static' or not resp.is_streamed)):
        resp.direct_passthrough = False
        data = resp.get_data()
        if len(data) >= 1024:
            resp.set_data(gzip.compress(data, compresslevel=5))
            resp.headers['Content-Encoding'] = 'gzip'
            if resp.headers.get('ETag'):
                # Gecomprimeerde representatie ≠ ongecomprimeerde
                etag, weak = resp.get_etag()
                if etag:
                    resp.set_etag(etag + '-gz', weak=weak)
        resp.vary.add('Accept-Encoding')
    return resp


@app.after_request
def _set_security_headers(resp):
    resp.headers.setdefault('Content-Security-Policy', _CSP)
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    # Alleen zinvol over HTTPS (browsers negeren hem over HTTP); geen
    # includeSubDomains omdat andere subdomeinen niet door deze app beheerd worden.
    resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000')
    return resp


@app.route('/health')
def health():
    """Unauthenticated liveness check for PM2/reverse proxy/uptime monitoring."""
    return jsonify({'status': 'ok'})


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
        _write_private_file(_pw_file, _generated_pass)
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
            f.flush()
            os.fsync(f.fileno())
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

# NB: commando's die zelf subprocessen kunnen starten of bestanden kunnen
# schrijven (awk/sed/find/xargs/tee/php/git/tar/zip/mysql) horen hier NIET in:
# in combinatie met sudo geven die een volledige root-shell.
TERMINAL_ALLOWED_COMMANDS = {
    # File system
    'ls', 'cat', 'head', 'tail', 'less', 'more', 'wc', 'file', 'stat',
    'locate', 'du', 'df', 'tree', 'readlink', 'realpath', 'basename',
    'dirname', 'pwd', 'cd', 'touch',
    # Text processing
    'grep', 'egrep', 'fgrep', 'sort', 'uniq', 'cut', 'tr',
    'diff', 'comm',
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
    'nginx', 'caddy', 'php8.3-fpm',
    # PM2
    'pm2',
    # Certificates
    'certbot',
    # Firewall
    'ufw', 'fail2ban-client',
    # Database
    'mysqldump',
    # Misc tools
    'date', 'cal', 'echo', 'printf', 'true', 'false', 'test',
    'gzip', 'gunzip', 'unzip', 'zcat',
    'md5sum', 'sha256sum', 'openssl',
    'crontab',
}

# Met sudo alleen commando's die niets kunnen schrijven of uitvoeren. Veel
# commando's in de allowlist hebben opties die als root bestanden schrijven
# of een ander programma starten (apt-get -o APT::Update::Pre-Invoke,
# certbot --pre-hook, sort -o, curl -o, openssl -out, unzip -d, ip netns
# exec, crontab <bestand>, systemctl link, dpkg -i, mount ...) en gaven zo
# alsnog een root-shell. Beheer via sudo loopt via de eigen pagina's.
TERMINAL_SUDO_READONLY = {
    'ls', 'cat', 'head', 'tail', 'wc', 'stat', 'du', 'df', 'readlink',
    'realpath', 'grep', 'egrep', 'fgrep', 'cut', 'tr', 'diff', 'comm',
    'lsof', 'ss', 'netstat', 'ps', 'journalctl', 'md5sum', 'sha256sum',
    'zcat', 'id', 'whoami', 'w', 'who', 'last', 'free', 'uptime', 'lsblk',
    'pwd',
}
# Opties die ook bij "alleen-lezen" commando's iets wijzigen of uitvoeren
TERMINAL_SUDO_BLOCKED_OPTIONS = {
    'journalctl': ('--vacuum', '--rotate', '--flush', '--sync', '--relinquish',
                   '--smart-relinquish', '--setup-keys', '--update-catalog'),
    'ss': ('--kill',),
    'systemctl': ('-H', '--host', '-M', '--machine'),
}
# Commando's die met sudo alleen met deze (alleen-lezen) subcommando's mogen
TERMINAL_SUDO_SUBCOMMANDS = {
    'systemctl': {'status', 'is-active', 'is-enabled', 'is-failed', 'list-units',
                  'list-unit-files', 'list-timers', 'show', 'cat'},
    'ufw': {'status'},
    'fail2ban-client': {'status', 'get', 'banned', 'ping', 'version'},
    'certbot': {'certificates'},
    'nginx': {'-t', '-T', '-v', '-V'},
    'crontab': {'-l'},
}


def _terminal_sudo_allowed(tokens):
    """tokens = het commando ná 'sudo'."""
    name, args = tokens[0], tokens[1:]
    for arg in args:
        if arg.startswith(TERMINAL_SUDO_BLOCKED_OPTIONS.get(name, ())):
            return False
        # ss -K / -tK (gecombineerde korte opties): sockets killen
        if name == 'ss' and arg.startswith('-') and not arg.startswith('--') and 'K' in arg:
            return False
    if name in TERMINAL_SUDO_READONLY:
        return True
    allowed_sub = TERMINAL_SUDO_SUBCOMMANDS.get(name)
    if not allowed_sub or not args or args[0] not in allowed_sub:
        return False
    if name in ('nginx', 'crontab', 'certbot'):
        return len(args) == 1
    return True


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


def log_audit(action, details=None, user=None, ip=None):
    """Log an action to the audit trail"""
    entry = {
        # Met UTC-offset, zodat de browser de juiste lokale tijd toont
        'timestamp': datetime.now().astimezone().isoformat(),
        'user': user or (session.get('username', 'system') if request else 'system'),
        'ip': ip or (request.remote_addr if request else '-'),
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
# Beschermt read-modify-write van subscriptions.json / notification_log.json /
# notification_history.json tegen races tussen monitor-thread en webrequests.
# RLock: de monitor roept binnen één cyclus meerdere helpers genest aan.
_notif_lock = threading.RLock()


# Per-thread vlag: de monitor-thread wil altijd verse data (alerts mogen niet
# op een verouderde snapshot gebaseerd zijn); webrequests mogen stale data
# krijgen terwijl er op de achtergrond ververst wordt.
_cache_tls = threading.local()
_cache_key_locks = {}
_cache_refreshing = set()
# Per functienaam opgehoogd bij _invalidate_cache: een berekening die vóór
# de invalidatie startte (bijv. een achtergrond-refresh tijdens een pm2
# restart) mag zijn inmiddels verouderde resultaat niet meer opslaan.
_cache_generation = {}


def _cache_key_lock(key):
    with _cache_lock:
        lock = _cache_key_locks.get(key)
        if lock is None:
            lock = _cache_key_locks[key] = threading.RLock()
        return lock


def _cache_compute(key, func, args, kwargs, ttl, max_age):
    """Bereken en sla op onder een per-key lock (single-flight).

    Wachtende threads die de lock daarna krijgen zien de verse entry en
    rekenen niet opnieuw.
    """
    with _cache_key_lock(key):
        with _cache_lock:
            entry = _cache_store.get(key)
            generation = _cache_generation.get(key[0], 0)
        if entry and time.time() - entry[1] < ttl:
            return entry[0]
        started = time.time()
        result = func(*args, **kwargs)
        with _cache_lock:
            if _cache_generation.get(key[0], 0) == generation:
                # (resultaat, tijdstip, max bewaarduur voor _sweep_caches)
                _cache_store[key] = (result, started, max_age)
        return result


def _cache_refresh_async(key, func, args, kwargs, ttl, max_age):
    with _cache_lock:
        if key in _cache_refreshing:
            return
        _cache_refreshing.add(key)

    def _run():
        try:
            _cache_compute(key, func, args, kwargs, ttl, max_age)
        except Exception:
            logger.warning('Background cache refresh of %s failed', func.__name__, exc_info=True)
        finally:
            with _cache_lock:
                _cache_refreshing.discard(key)

    threading.Thread(target=_run, daemon=True, name=f'cache-{func.__name__}').start()


def _ttl_cache(seconds, stale=None):
    """TTL cache decorator for expensive functions.

    - Binnen `seconds`: resultaat uit de cache.
    - Met `stale`: tot `stale` seconden oud wordt het oude resultaat meteen
      teruggegeven en op de achtergrond ververst (stale-while-revalidate),
      zodat een pagina nooit op bijv. `apt` of `certbot` hoeft te wachten.
    - Gelijktijdige aanroepen voor dezelfde key rekenen maar één keer
      (single-flight), in plaats van allemaal hetzelfde trage commando te
      starten zodra de cache verloopt.
    """
    max_age = max(seconds, stale or 0)

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Key op functienaam én argumenten: anders zou een gedecoreerde
            # functie met verschillende args hetzelfde (verkeerde) resultaat
            # uit de cache krijgen.
            try:
                key = (func.__name__, args, tuple(sorted(kwargs.items())))
                hash(key)
            except TypeError:
                # Niet-hashbare args: cache deze aanroep niet
                return func(*args, **kwargs)
            with _cache_lock:
                entry = _cache_store.get(key)
            if entry:
                age = time.time() - entry[1]
                if age < seconds:
                    return entry[0]
                if (stale and age < stale
                        and not getattr(_cache_tls, 'require_fresh', False)):
                    _cache_refresh_async(key, func, args, kwargs, seconds, max_age)
                    return entry[0]
            return _cache_compute(key, func, args, kwargs, seconds, max_age)
        return wrapper
    return decorator


def _invalidate_cache(*func_names):
    """Invalidate cached results for given function names.

    Keys zijn tuples (func_name, args, kwargs), dus verwijder elke entry
    waarvan het eerste element matcht.
    """
    names = set(func_names)
    with _cache_lock:
        for name in names:
            _cache_generation[name] = _cache_generation.get(name, 0) + 1
        for key in [k for k in _cache_store if isinstance(k, tuple) and k[0] in names]:
            _cache_store.pop(key, None)


def _sweep_caches():
    """Drop expired cache entries so long-lived caches don't grow unbounded.

    _ttl_cache en _ip_country_cache verwijderen verlopen entries alleen bij
    een nieuwe hit op dezelfde key; keys die nooit terugkomen (bijv. unieke
    IP's uit SSH-logs) blijven anders voor altijd staan.
    """
    now = time.time()
    with _cache_lock:
        for key in [k for k, (_, ts, max_age) in _cache_store.items() if now - ts > max_age]:
            _cache_store.pop(key, None)
            # De per-key lock alleen weggooien als niemand hem vasthoudt: een
            # lopende synchrone berekening zou anders een tweede, parallelle
            # berekening (apt, du) naast zich krijgen.
            lock = _cache_key_locks.get(key)
            if lock is not None and key not in _cache_refreshing and lock.acquire(blocking=False):
                try:
                    _cache_key_locks.pop(key, None)
                finally:
                    lock.release()
    with _ip_country_cache_lock:
        for ip in [ip for ip, (_, ts) in _ip_country_cache.items()
                   if now - ts > _IP_COUNTRY_TTL]:
            _ip_country_cache.pop(ip, None)


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
    _write_private_file(VAPID_PRIVATE_KEY_PATH, pem)
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
            history = json.loads(NOTIFICATION_HISTORY_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            return []
        # Entries van vóór de stabiele id's krijgen een deterministische id
        # (zelfde id bij elke load, ook zonder tussentijdse save).
        for item in history:
            if isinstance(item, dict) and not item.get('id'):
                raw = f"{item.get('timestamp')}|{item.get('title')}|{item.get('body')}"
                item['id'] = hashlib.sha1(raw.encode('utf-8', 'replace')).hexdigest()[:12]
        return history
    return []


def _save_notification_history(history):
    """Save notification history (max 100 entries)"""
    _atomic_write_json(NOTIFICATION_HISTORY_PATH, history[-100:])


def _add_notification_history(title, body, category):
    """Add an entry to notification history, deduplicating active alerts.

    If an unread entry with the same category and body already exists,
    update its timestamp instead of creating a duplicate.
    """
    with _notif_lock:
        history = _load_notification_history()

        # Check for existing unread entry with same category + body
        for item in history:
            if not item.get('read') and item.get('category') == category and item.get('body') == body:
                item['timestamp'] = datetime.now().astimezone().isoformat()
                item['count'] = item.get('count', 1) + 1
                _save_notification_history(history)
                return

        history.append({
            'id': secrets.token_hex(6),
            'timestamp': datetime.now().astimezone().isoformat(),
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
            # Zonder timeout kan één hangend push-endpoint de monitor (die
            # _notif_lock vasthoudt) en daarmee alle notificatie-routes blokkeren.
            timeout=10,
        )
        return True
    except WebPushException as e:
        # NB: een requests.Response met status >= 400 is falsy, dus expliciet
        # op None checken — anders werden verlopen subscriptions nooit opgeruimd.
        if e.response is not None and e.response.status_code in (404, 410):
            return False  # Subscription expired, should be removed
        logger.warning(f"Push failed: {e}")
        return None  # Transient error, keep subscription
    except Exception as e:
        # Connection errors, timeouts, DNS failures etc. must not break the
        # whole monitor loop or leave one broken subscription blocking the rest.
        logger.warning(f"Push failed (transient): {e}")
        return None


def _classify_alert(alert):
    """Classify an alert into a notification category"""
    msg = alert.get('message', '').lower()
    severity = alert.get('severity', '')
    key = alert.get('key', '')

    # Eerst op key: berichten bevatten door de gebruiker gekozen namen, dus
    # "PM2 process 'backup-worker' is stopped" zou op tekst als 'backup'
    # geclassificeerd worden (en bij uitgeschakelde backup-meldingen nooit
    # aankomen).
    if key == 'app_update_available':
        return 'app_update'
    if key in ('high_connections', 'syn_flood') or key.startswith('ddos_'):
        return 'ddos'
    if key.startswith('backup_'):
        return 'backup'
    if key in ('updates_available', 'reboot_required'):
        return 'updates'
    if key.startswith(('service_down_', 'pm2_offline_', 'site_down_', 'ssl_', 'disk_',
                       'ram_', 'swap_', 'load_', 'auto_heal_')):
        return 'critical' if severity == 'error' else 'warnings'

    # Onbekende key: val terug op de tekst-heuristiek
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
    # Harde bovengrens voor het kortste interval (30 s); de 24h-grens
    # hierboven is leidend. Met een vaste 288 besloegen de "24h"-grafieken en
    # de disk-forecast bij een kort interval maar een paar uur.
    metrics = metrics[-2880:]
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


# Auto-heal: restart-pogingen per service (in-memory; een herstart van de
# app reset de teller, dat is acceptabel voor een daglimiet).
_auto_heal_attempts = {}  # {service: [timestamp, ...]}
_auto_heal_lock = threading.Lock()


# Services die de beheerder via de UI heeft gestopt: auto-heal mag die niet
# weer starten (bijv. mariadb gestopt voor onderhoud) tot ze weer actief zijn.
# Persistent zodat een herstart van de app de intentie niet vergeet.
_MANUALLY_STOPPED_PATH = DATA_DIR / 'manually_stopped_services.json'
_manually_stopped_lock = threading.Lock()


def _load_manually_stopped():
    try:
        return set(json.loads(_MANUALLY_STOPPED_PATH.read_text()))
    except (OSError, ValueError, TypeError):
        return set()


def _set_manually_stopped(name, stopped):
    with _manually_stopped_lock:
        names = _load_manually_stopped()
        if stopped:
            names.add(name)
        else:
            names.discard(name)
        _atomic_write_json(_MANUALLY_STOPPED_PATH, sorted(names))


def _auto_heal_services(services):
    """Restart services that are down, when auto-heal is enabled.

    Returns a list of alert dicts describing what happened, so the caller
    can feed them into the normal notification pipeline. Capped per service
    per 24h: a crash-looping service moet een mens wakker maken, niet
    eindeloos herstart worden.
    """
    cfg = CONFIG.get('auto_heal', {})
    if not cfg.get('enabled', False):
        return []
    try:
        max_per_day = int(cfg.get('max_restarts_per_day', 3))
    except (ValueError, TypeError):
        max_per_day = 3

    alerts = []
    now = time.time()
    healed_any = False

    manually_stopped = _load_manually_stopped()
    # Weer actief (via SSH gestart, reboot): de "bewust gestopt"-markering
    # vervalt, zodat een latere crash wél weer hersteld wordt.
    for svc in services:
        if svc.get('status') == 'active' and svc.get('name') in manually_stopped:
            _set_manually_stopped(svc['name'], False)
            manually_stopped.discard(svc['name'])
    for svc in services:
        # Alleen echt gestopte/gecrashte units; 'activating'/'reloading' zijn
        # tussenstanden die een herstart juist zou verstoren.
        if svc.get('status') not in ('failed', 'inactive'):
            continue
        name = svc.get('name', '')
        if not name or not is_safe_name(name) or name in manually_stopped:
            continue

        with _auto_heal_lock:
            attempts = [t for t in _auto_heal_attempts.get(name, []) if now - t < 86400]
            if len(attempts) >= max_per_day:
                _auto_heal_attempts[name] = attempts
                alerts.append({
                    'severity': 'error',
                    'message': f"Auto-heal gave up on '{name}': still down after {max_per_day} restarts in 24h",
                    'link': '/services',
                    'key': f'auto_heal_gaveup_{name}',
                })
                continue
            attempts.append(now)
            _auto_heal_attempts[name] = attempts
            attempt_no = len(attempts)

        result = run_cmd_safe(['sudo', 'systemctl', 'restart', name], timeout=60)
        if result.returncode == 0:
            healed_any = True
            log_audit('auto_heal_restart', {'service': name, 'attempt': attempt_no})
            logger.info(f"Auto-heal: restarted '{name}' (attempt {attempt_no}/{max_per_day} today)")
            alerts.append({
                'severity': 'info',
                'message': f"Service '{name}' was down and has been automatically restarted (attempt {attempt_no}/{max_per_day} today)",
                'link': '/services',
                'key': f'auto_heal_ok_{name}',
            })
        else:
            err = (result.stderr or result.stdout or 'unknown error').strip()[:120]
            log_audit('auto_heal_restart_failed', {'service': name, 'error': err})
            logger.warning(f"Auto-heal: could not restart '{name}': {err}")
            alerts.append({
                'severity': 'error',
                'message': f"Auto-heal could not restart '{name}': {err}",
                'link': '/services',
                'key': f'auto_heal_fail_{name}',
            })

    if healed_any:
        _invalidate_cache('get_services_status')
    return alerts


def _monitor_sleep_seconds(elapsed=0):
    """Begrensd: een onzinnige monitor_interval mag de thread niet laten
    crashen (OverflowError) of eindeloos laten slapen."""
    try:
        interval = min(max(int(MONITOR_INTERVAL), 30), 86400)
    except (TypeError, ValueError, OverflowError):
        interval = 300
    return max(10, interval - elapsed)


def _monitor_loop():
    """Background thread: check alerts and send push notifications"""
    # Alerts moeten op actuele data gebaseerd zijn, nooit op een stale
    # cache-entry (zie _ttl_cache).
    _cache_tls.require_fresh = True
    # Wait for app to fully start
    time.sleep(30)
    logger.info("Push notification monitor started")

    first_cycle = True
    while True:
        cycle_start = time.time()
        try:
            # Collect metrics every cycle (independent of subscriptions)
            try:
                collect_metrics()
            except Exception as e:
                logger.warning(f"Metrics collection error: {e}")

            # Ruim verlopen cache-entries op (begrenst geheugengebruik)
            try:
                _sweep_caches()
            except Exception as e:
                logger.warning(f"Cache sweep error: {e}")

            # Check uptime for all sites and save history
            try:
                check_uptime_all()
            except Exception as e:
                logger.warning(f"Uptime check error: {e}")

            subs = _load_subscriptions()
            email_prefs_any = any(CONFIG.get('email_notifications', {}).values())
            auto_heal_enabled = CONFIG.get('auto_heal', {}).get('enabled', False)
            if not subs and not email_prefs_any and not auto_heal_enabled:
                time.sleep(_monitor_sleep_seconds())
                continue

            services = get_services_status()

            # Self-healing: probeer gefaalde services te herstarten vóórdat de
            # alerts worden opgebouwd, zodat een geslaagde heal een
            # heal-notificatie geeft in plaats van een "service down"-alert.
            heal_alerts = []
            try:
                heal_alerts = _auto_heal_services(services)
                if any(a['key'].startswith('auto_heal_ok_') for a in heal_alerts):
                    services = get_services_status()
            except Exception as e:
                logger.warning(f"Auto-heal error: {e}")

            if not subs and not email_prefs_any:
                time.sleep(_monitor_sleep_seconds())
                continue

            # Gather current state - free intermediate data after building alerts
            data = get_server_overview()
            pm2 = get_pm2_processes()
            ssl = get_ssl_info()
            alerts = get_dashboard_alerts(data, services, pm2, ssl)
            alerts.extend(heal_alerts)
            del data, services, pm2, ssl

            # Add DDoS alerts
            alerts.extend(check_ddos_indicators())

            # Add backup alerts
            alerts.extend(check_backup_alerts())

            # Add app update alert
            alerts.extend(check_app_update_alert())

            private_key_pem = None
            if subs:
                _, private_key_pem = _get_vapid_keys()
            with _notif_lock:
                notif_log = _load_notification_log()
                now = time.time()
                log_changed = False

                # Build set of current alert keys so we can detect resolved alerts
                current_alert_keys = set()
                # Safety net: dedupe by (category, message) within this cycle so
                # two alerts that resolve to identical text — e.g. via different
                # `key` fields — can never produce two identical notifications.
                sent_push_msgs = set()
                sent_email_msgs = set()

                # cooldown wordt ook in de resolved-cleanup verderop gebruikt, dus
                # vóór `if alerts:` toekennen — anders crasht een alert-loze cyclus.
                cooldown = CONFIG.get('notification_cooldown', 3600)

                if alerts:

                    # Update categories ('updates', 'app_update') are gated to fire
                    # at most once per day, after a configured time-of-day. This
                    # avoids being woken up at 03:00 when apt or GitHub publishes
                    # a new package, and prevents new updates trickling in
                    # throughout the day from each producing their own notification.
                    updates_time_str = CONFIG.get('updates_notification_time', '08:00')
                    try:
                        _uh, _um = updates_time_str.split(':')
                        updates_hour, updates_min = int(_uh), int(_um)
                    except (ValueError, AttributeError):
                        updates_hour, updates_min = 8, 0
                    now_dt = datetime.now()
                    today_str = now_dt.strftime('%Y-%m-%d')
                    updates_window_open = (now_dt.hour, now_dt.minute) >= (updates_hour, updates_min)

                    def _is_update_cat(cat):
                        return cat in ('updates', 'app_update')

                    # On first cycle after (re)start, seed the notification
                    # log with all current alerts so we don't spam every
                    # existing alert as if it's new.
                    # Migration safety: on first cycle after restart, if any
                    # update-category alert is already known to notif_log (i.e.
                    # the user has been notified about it before) but no daily
                    # marker exists yet, stamp the marker so we don't re-fire
                    # right after an upgrade to a version that introduced the gate.
                    if first_cycle and notif_log:
                        for alert in alerts:
                            category = _classify_alert(alert)
                            if not _is_update_cat(category):
                                continue
                            alert_key = f"{category}:{alert.get('key', alert['message'][:80])}"
                            if alert_key in notif_log and f"_daily_push:{alert_key}" not in notif_log:
                                notif_log[f"_daily_push:{alert_key}"] = today_str
                                log_changed = True
                            if f"email:{alert_key}" in notif_log and f"_daily_email:{alert_key}" not in notif_log:
                                notif_log[f"_daily_email:{alert_key}"] = today_str
                                log_changed = True

                    if first_cycle and not notif_log:
                        email_prefs = CONFIG.get('email_notifications', {})
                        for alert in alerts:
                            category = _classify_alert(alert)
                            alert_key = f"{category}:{alert.get('key', alert['message'][:80])}"
                            current_alert_keys.add(alert_key)
                            entry = {'ts': now, 'message': alert['message']}
                            notif_log[alert_key] = entry
                            if email_prefs.get(category, False):
                                notif_log[f"email:{alert_key}"] = entry
                            # Also seed daily markers so a mid-day restart doesn't
                            # re-trigger an update notification once the window opens.
                            if _is_update_cat(category):
                                notif_log[f"_daily_push:{alert_key}"] = today_str
                                if email_prefs.get(category, False):
                                    notif_log[f"_daily_email:{alert_key}"] = today_str
                        log_changed = True
                        logger.info(f"First cycle: seeded {len(current_alert_keys)} alerts into notification log (no notifications sent)")
                        first_cycle = False
                        if log_changed:
                            _save_notification_log(notif_log)
                        # Niets versturen deze cyclus: maak de alert-lijst leeg zodat
                        # de verstuur-loop hieronder niets doet, maar val wél door
                        # naar de cleanup en de sleep onderaan de while-loop. Een
                        # `continue` zou die sleep overslaan en direct een tweede
                        # volledige monitoringcyclus starten.
                        alerts = []

                    for alert in alerts:
                        category = _classify_alert(alert)
                        alert_key = f"{category}:{alert.get('key', alert['message'][:80])}"
                        current_alert_keys.add(alert_key)
                        msg_dedup = (category, alert['message'])

                        # --- Push notifications ---
                        log_entry = notif_log.get(alert_key)
                        should_push = bool(subs and private_key_pem)

                        if _is_update_cat(category):
                            # Daily gate: skip until configured time, and at most
                            # one push per category per day. Multiple update alerts
                            # in the same day collapse into a single morning ping.
                            # Per alert-key: updates_available en reboot_required
                            # delen de categorie, dus een gate per categorie liet
                            # "reboot required" nooit door.
                            daily_push_key = f"_daily_push:{alert_key}"
                            last_push_date = notif_log.get(daily_push_key)
                            if not updates_window_open or last_push_date == today_str:
                                should_push = False
                        else:
                            if isinstance(log_entry, dict):
                                if log_entry.get('message') == alert['message']:
                                    should_push = False
                                elif now - log_entry.get('ts', 0) < cooldown:
                                    should_push = False
                            elif isinstance(log_entry, (int, float)):
                                notif_log[alert_key] = {'ts': log_entry, 'message': alert['message']}
                                log_changed = True
                                should_push = False

                        if should_push and msg_dedup in sent_push_msgs:
                            should_push = False

                        if should_push:
                            payload = {
                                'title': 'VPS Manager',
                                'body': alert['message'],
                                'tag': category,
                                'url': alert.get('link') or '/',
                            }

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

                            if expired:
                                # Herlaad en filter op endpoint: `subs` is aan het
                                # begin van de cyclus geladen, een subscribe/
                                # unsubscribe via de UI sindsdien zou anders
                                # overschreven worden.
                                dead = {subs[i]['endpoint'] for i in expired}
                                with _notif_lock:
                                    current_subs = _load_subscriptions()
                                    _save_subscriptions([s for s in current_subs
                                                         if s.get('endpoint') not in dead])
                                subs = [s for s in subs if s['endpoint'] not in dead]

                            if sent_count > 0:
                                notif_log[alert_key] = {'ts': now, 'message': alert['message']}
                                if _is_update_cat(category):
                                    # Re-evaluate the date at stamp time so a cycle
                                    # that crosses midnight stamps the correct day.
                                    notif_log[f"_daily_push:{alert_key}"] = datetime.now().strftime('%Y-%m-%d')
                                log_changed = True
                                sent_push_msgs.add(msg_dedup)
                                # Flush immediately after every successful push so a
                                # later transient error in the same cycle can't cause
                                # this alert to be re-pushed next cycle.
                                try:
                                    _save_notification_log(notif_log)
                                except Exception:
                                    logger.warning("Failed to flush notification log after push", exc_info=True)
                                logger.info(f"Push sent: {alert['message']} → {sent_count} subscriber(s)")

                                _add_notification_history(
                                    payload['title'],
                                    payload['body'],
                                    category,
                                )

                        # --- Email notifications ---
                        email_prefs = CONFIG.get('email_notifications', {})
                        if email_prefs.get(category, False):
                            email_key = f"email:{alert_key}"
                            email_entry = notif_log.get(email_key)
                            should_email = True

                            if _is_update_cat(category):
                                daily_email_key = f"_daily_email:{alert_key}"
                                last_email_date = notif_log.get(daily_email_key)
                                if not updates_window_open or last_email_date == today_str:
                                    should_email = False
                            else:
                                if isinstance(email_entry, dict):
                                    if email_entry.get('message') == alert['message']:
                                        should_email = False
                                    elif now - email_entry.get('ts', 0) < cooldown:
                                        should_email = False
                                elif isinstance(email_entry, (int, float)):
                                    notif_log[email_key] = {'ts': email_entry, 'message': alert['message']}
                                    log_changed = True
                                    should_email = False

                            if should_email and msg_dedup in sent_email_msgs:
                                should_email = False

                            if should_email:
                                ok, err = send_notification_email(category, alert)
                                if ok:
                                    notif_log[email_key] = {'ts': now, 'message': alert['message']}
                                    if _is_update_cat(category):
                                        notif_log[f"_daily_email:{alert_key}"] = datetime.now().strftime('%Y-%m-%d')
                                    log_changed = True
                                    sent_email_msgs.add(msg_dedup)
                                    # Flush to disk immediately so a second process
                                    # (e.g. duplicate PM2 app, stale thread) reading
                                    # notif_log on its own cycle sees this send and
                                    # won't also send the same email.
                                    try:
                                        _save_notification_log(notif_log)
                                    except Exception:
                                        logger.warning("Failed to flush notification log after email send", exc_info=True)
                                    logger.info(f"Email notification sent: {alert['message']}")

                                    _add_notification_history(
                                        'VPS Manager (email)',
                                        alert['message'],
                                        category,
                                    )
                                else:
                                    logger.warning(f"Email notification failed: {err}")

                # Remove log entries for alerts that have resolved AND whose
                # cooldown has expired.  Keeping resolved entries until the
                # cooldown window passes prevents flapping alerts (values
                # oscillating around a threshold) from bypassing the dedup
                # and sending duplicate notifications every few minutes.
                resolved_keys = []
                for k in notif_log:
                    # Daily marker keys are not tied to a specific alert; they
                    # carry a date string (YYYY-MM-DD) instead of a ts dict and
                    # are managed separately below.
                    if k.startswith('_daily_push:') or k.startswith('_daily_email:'):
                        continue
                    check_key = k[6:] if k.startswith('email:') else k
                    if check_key not in current_alert_keys:
                        entry = notif_log[k]
                        ts = entry.get('ts', 0) if isinstance(entry, dict) else entry
                        if now - ts >= cooldown:
                            resolved_keys.append(k)
                for k in resolved_keys:
                    del notif_log[k]
                    log_changed = True

                # Clean entries older than 7 days as a safety net. Daily markers
                # are kept regardless (they're tiny strings) so a stamp from
                # yesterday still gates today's send if the gate hasn't fired yet.
                cleaned = {}
                for k, v in notif_log.items():
                    if k.startswith('_daily_push:') or k.startswith('_daily_email:'):
                        cleaned[k] = v
                        continue
                    ts = v.get('ts', 0) if isinstance(v, dict) else v
                    if now - ts < 604800:
                        cleaned[k] = v
                if len(cleaned) != len(notif_log) or log_changed:
                    _save_notification_log(cleaned)

            # Pas na een geslaagde cyclus: faalde de eerste cyclus vóór het
            # seeden, dan zou de volgende anders alle bestaande alerts pushen.
            first_cycle = False
        except Exception:
            logger.warning("Monitor error", exc_info=True)

        gc.collect()
        elapsed = time.time() - cycle_start
        time.sleep(_monitor_sleep_seconds(elapsed))

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
_Q_APP_DIR = shlex.quote(APP_DIR)  # voor shell-strings (pad met spaties)


def _get_current_version():
    """Read current version from VERSION file"""
    try:
        return VERSION_FILE.read_text().strip()
    except (OSError, FileNotFoundError):
        return '0.0.0'


def _version_tuple(v):
    """'1.10.2' → (1, 10, 2); niet-numerieke delen tellen als 0."""
    parts = []
    for p in str(v).lstrip('v').split('.'):
        m = re.match(r'\d+', p)
        parts.append(int(m.group()) if m else 0)
    return tuple(parts)


def _is_newer_version(latest, current):
    # Met `!=` gaf een lokaal nieuwere versie (bijv. na een handmatige pull
    # van main) ten onrechte "update beschikbaar" — en een downgrade-knop.
    return bool(latest) and _version_tuple(latest) > _version_tuple(current)


@_ttl_cache(300)
def _fetch_latest_release():
    """Latest GitHub release (gedeeld door het dashboard-alert en /updates).

    Gooit een exceptie bij een fout, zodat mislukte checks niet gecachet worden.
    """
    req = urllib.request.Request(
        'https://api.github.com/repos/martijnrenkema/vps-manager/releases/latest',
        headers={
            'User-Agent': 'VPS-Manager/' + _get_current_version(),
            'Accept': 'application/vnd.github.v3+json',
        })
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


@_ttl_cache(3600, stale=86400)
def check_app_update_alert():
    """Check GitHub for a new VPS Manager release and return an alert if available"""
    current = _get_current_version()
    try:
        data = _fetch_latest_release()
    except Exception:
        logger.debug('GitHub API check failed', exc_info=True)
        return []

    latest = data.get('tag_name', '').lstrip('v')
    if _is_newer_version(latest, current):
        return [{
            'severity': 'info',
            'message': f"VPS Manager update available: v{current} → v{latest}",
            'link': '/updates',
            'key': 'app_update_available',
        }]
    return []


@_ttl_cache(600, stale=3600)
def get_available_features():
    """Detect which optional features/services are installed on the server"""
    features = {}
    checks = {
        'php': 'which php 2>/dev/null || ls /usr/sbin/php-fpm* 2>/dev/null',
        'mysql': 'which mysql 2>/dev/null || which mariadb 2>/dev/null',
        'pm2': 'which pm2 2>/dev/null',
    }
    for feature, cmd in checks.items():
        result = run_cmd(cmd, timeout=5)
        features[feature] = result.returncode == 0 and bool(result.stdout.strip())
    return features


def _peek_cache(func_name, *args, **kwargs):
    """Return a _ttl_cache'd result only if it is already in the cache.

    Never calls the getter (no subprocess, no background refresh), so it is
    safe to use on every page render. Returns None when the entry is missing
    or older than its max age.
    """
    key = (func_name, args, tuple(sorted(kwargs.items())))
    with _cache_lock:
        entry = _cache_store.get(key)
    if not entry:
        return None
    result, ts, max_age = entry
    if time.time() - ts > max_age:
        return None
    return result


def get_sidebar_hints():
    """Small status hints for the sidebar (e.g. "PM2 1 err", "SSL 9d").

    Built exclusively from data other pages already put in the cache; unknown
    values are simply omitted. Each hint: {'text', 'tone' ('err'|'warn'|''), 'title'}.
    """
    hints = {}
    try:
        pm2 = _peek_cache('get_pm2_processes')
        if isinstance(pm2, list) and pm2:
            errored = [p for p in pm2 if p.get('status') in ('errored', 'error')]
            down = [p for p in pm2 if p.get('status') not in ('online', 'launching')]
            if errored:
                hints['pm2'] = {'text': f"{len(errored)} err", 'tone': 'err',
                                'title': f"{len(errored)} process(es) errored"}
            elif down:
                hints['pm2'] = {'text': f"{len(down)} off", 'tone': 'warn',
                                'title': f"{len(down)} process(es) not online"}

        services = _peek_cache('get_services_status')
        if isinstance(services, list) and services:
            down = [s for s in services if s.get('status') != 'active']
            if down:
                hints['services'] = {'text': f"{len(down)} off", 'tone': 'err',
                                     'title': f"{len(down)} service(s) not running"}

        cert_getter = 'get_caddy_certificates' if CONFIG.get('web_server') == 'caddy' else 'get_ssl_certificates'
        certs = _peek_cache(cert_getter)
        if isinstance(certs, list):
            days = [c.get('days_left') for c in certs if isinstance(c.get('days_left'), int)]
            if days:
                soonest = min(days)
                thr = CONFIG.get('thresholds', {})
                if soonest <= 30:
                    tone = ('err' if soonest <= thr.get('ssl_critical_days', 3)
                            else 'warn' if soonest <= thr.get('ssl_warning_days', 14) else '')
                    hints['ssl'] = {'text': f"{max(soonest, 0)}d", 'tone': tone,
                                    'title': 'Days until the first certificate expires'}

        updates = _peek_cache('get_system_updates')
        if isinstance(updates, list):
            installable = [u for u in updates if u.get('category') in ('security', 'regular')]
            if installable:
                sec = sum(1 for u in installable if u.get('category') == 'security')
                hints['updates'] = {'text': str(len(installable)), 'tone': 'warn' if sec else '',
                                    'title': f"{len(installable)} updates available"
                                             + (f", {sec} security" if sec else '')}
    except Exception:
        logger.debug('Sidebar hints failed', exc_info=True)
    return hints


@app.context_processor
def inject_global_info():
    features = get_available_features()
    return {
        'nav_hints': get_sidebar_hints(),
        'server_ip': get_server_ip(),
        'global_hostname': get_server_hostname(),
        'global_uptime': get_server_uptime_short(),
        'app_version': _get_current_version(),
        'asset_v': ASSET_VERSION,
        'web_server': get_web_server(),
        'has_php': features.get('php', False),
        'has_mysql': features.get('mysql', False),
        'has_pm2': features.get('pm2', False),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _CmdFailed:
    """Resultaat-object met dezelfde velden als CompletedProcess."""
    def __init__(self, stderr, returncode=1):
        self.stdout = ''
        self.stderr = stderr
        self.returncode = returncode


_DEFAULT_MAX_OUTPUT = 64 * 1024 * 1024


def _run(args, shell, timeout, input=None, max_output=_DEFAULT_MAX_OUTPUT):
    """subprocess.run met een paar verbeteringen:

    - Eigen process group + killpg bij timeout: met shell=True doodt
      subprocess.run anders alleen de shell en blijven pipeline-kinderen
      (grep/awk over grote logs, `ping`, `tail -f`) als wees doordraaien.
    - Een ontbrekend binary (FileNotFoundError) of andere OSError geeft een
      mislukt resultaat i.p.v. een 500.
    - Output wordt als UTF-8 met errors='replace' gedecodeerd: één niet-UTF-8
      byte (binair bestand, vreemde bestandsnaam) gaf anders een
      UnicodeDecodeError → 500.
    - Output is begrensd (max_output per stream): `cat /dev/zero` in de
      terminal kon anders gigabytes in het geheugen van de app laten lopen.
    """
    try:
        proc = subprocess.Popen(
            args, shell=shell, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
    except OSError as e:
        return _CmdFailed(str(e), returncode=127)

    def _kill_group():
        # Eerst SIGTERM: sudo geeft die door aan zijn (root-)kind, SIGKILL
        # niet. Daarna pas SIGKILL voor wat nog leeft.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(proc.pid, sig)
            except OSError:
                pass
            try:
                proc.wait(timeout=2)
                return
            except subprocess.TimeoutExpired:
                continue

    overflow = threading.Event()
    chunks = {'out': [], 'err': []}

    def _reader(stream, key):
        kept = 0
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                if kept < max_output:
                    chunks[key].append(chunk[:max_output - kept])
                    kept += len(chunk)
                if kept >= max_output and not overflow.is_set():
                    overflow.set()
                    _kill_group()
        except (OSError, ValueError):
            pass

    readers = [threading.Thread(target=_reader, args=(proc.stdout, 'out'), daemon=True),
               threading.Thread(target=_reader, args=(proc.stderr, 'err'), daemon=True)]
    for t in readers:
        t.start()
    if input is not None:
        try:
            proc.stdin.write(input.encode('utf-8') if isinstance(input, str) else input)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group()
    for t in readers:
        t.join(timeout=5)

    def _decode(key):
        return b''.join(chunks[key]).decode('utf-8', errors='replace').replace('\r\n', '\n')

    if timed_out:
        failed = _CmdFailed('Command timed out')
        failed.partial_stdout = _decode('out')
        return failed
    stderr = _decode('err')
    if overflow.is_set():
        stderr += f'\n[output truncated at {max_output // 1024} KB]'
    return subprocess.CompletedProcess(args, proc.returncode, _decode('out'), stderr)


def run_cmd(cmd, timeout=30, max_output=_DEFAULT_MAX_OUTPUT):
    """Run a shell command locally on the VPS (only for hardcoded commands)"""
    return _run(cmd, True, timeout, max_output=max_output)


def run_cmd_safe(args, timeout=30, input=None):
    """Run a command with argument list (no shell injection possible)"""
    return _run(args, False, timeout, input=input)


def _json_body():
    """JSON-body als dict; een array/string/ongeldige body wordt {} i.p.v.
    een AttributeError (500) bij de eerste .get()."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _json_str(data, key, default=''):
    """String-veld uit een JSON-body; getallen worden tekst, andere types
    (lijst, object, null) de default — i.p.v. een AttributeError → 500."""
    value = data.get(key, default) if isinstance(data, dict) else default
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        value = default
    return str(value).strip()


def is_safe_name(name):
    """Validate that a name only contains safe characters (alphanumeric, dot, dash, underscore).

    Geen leidende '-' (zou als optie aan systemctl/certbot/pm2 doorgegeven
    worden) of '.' ('.', '..' als padcomponent), en \\Z i.p.v. $ zodat een
    afsluitende newline niet door de check glipt.
    """
    return isinstance(name, str) and bool(re.match(r'[a-zA-Z0-9_][a-zA-Z0-9._-]*\Z', name))


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


def _rate_limit_key(ip):
    """IPv6 per /64 bucketen: één client beschikt meestal over een hele /64
    en kon anders per adres opnieuw 5 pogingen doen."""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return str(ip)
    if addr.version == 6:
        if addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f'{addr}/64', strict=False))
    return str(addr)


def _is_rate_limited(ip):
    """Check if an IP has exceeded login attempt limits"""
    ip = _rate_limit_key(ip)
    with _login_attempts_lock:
        now = time.time()
        attempts = _login_attempts.get(ip, [])
        # Remove expired attempts for this IP
        attempts = [t for t in attempts if now - t < _LOGIN_WINDOW]
        _login_attempts[ip] = attempts
        _cleanup_login_attempts()
        return len(attempts) >= _LOGIN_MAX_ATTEMPTS


_failed_login_audit_times = []


def _audit_failed_login_allowed(limit=30, window=600):
    now = time.time()
    with _login_attempts_lock:
        _failed_login_audit_times[:] = [t for t in _failed_login_audit_times if now - t < window]
        if len(_failed_login_audit_times) >= limit:
            return False
        _failed_login_audit_times.append(now)
        return True


def _record_attempt(ip):
    """Record a failed login attempt"""
    ip = _rate_limit_key(ip)
    with _login_attempts_lock:
        _login_attempts.setdefault(ip, []).append(time.time())


# TOTP replay protection: accept each time step at most once, so an
# intercepted/observed code cannot be reused within its validity window.
# In-memory is sufficient: after a restart the window has almost always
# passed, and the trade-off avoids disk writes on every login.
_totp_last_counter = 0
_totp_counter_lock = threading.Lock()


def _verify_totp(secret, code):
    """Verify a TOTP code with valid_window=1, rejecting reused time steps."""
    global _totp_last_counter
    if not code:
        return False
    totp = pyotp.TOTP(secret)
    now = time.time()
    for offset in (0, -1, 1):
        step_time = now + offset * totp.interval
        # Vergelijk op bytes: compare_digest gooit een TypeError (→ HTTP 500)
        # op str-input met niet-ASCII tekens uit het formulier.
        if hmac.compare_digest(totp.at(step_time).encode(), code.encode('utf-8')):
            counter = int(step_time) // totp.interval
            with _totp_counter_lock:
                if counter <= _totp_last_counter:
                    return False  # code (or an older one) was already used
                _totp_last_counter = counter
            return True
    return False


# Email 2FA code store (single-user app, one code at a time)
_email_2fa_code = {}  # {'code': str, 'expires': float, 'attempts': int, 'last_sent': float}
_email_2fa_lock = threading.Lock()
_EMAIL_CODE_LIFETIME = 600  # 10 minutes
_EMAIL_CODE_MAX_ATTEMPTS = 5
_EMAIL_RESEND_COOLDOWN = 60  # seconds between resends


def _generate_email_code():
    """Generate a 6-digit code and store it with expiry"""
    code = str(secrets.SystemRandom().randint(100000, 999999))
    with _email_2fa_lock:
        _email_2fa_code.clear()
        _email_2fa_code.update({
            'code': code,
            'expires': time.time() + _EMAIL_CODE_LIFETIME,
            'attempts': 0,
            'last_sent': time.time(),
        })
    return code


def _verify_email_code(submitted_code):
    """Verify email 2FA code. Returns (success, error_message)"""
    with _email_2fa_lock:
        if not _email_2fa_code:
            return False, 'No code pending, request a new one'
        if time.time() > _email_2fa_code['expires']:
            _email_2fa_code.clear()
            return False, 'Code expired, request a new one'
        _email_2fa_code['attempts'] += 1
        if _email_2fa_code['attempts'] > _EMAIL_CODE_MAX_ATTEMPTS:
            _email_2fa_code.clear()
            return False, 'Too many attempts, request a new code'
        # Vergelijk op bytes: compare_digest gooit een TypeError (→ HTTP 500)
        # op str-input met niet-ASCII tekens uit het formulier.
        if hmac.compare_digest(submitted_code.encode('utf-8'), _email_2fa_code['code'].encode()):
            _email_2fa_code.clear()
            return True, ''
        return False, 'Invalid code'


def _smtp_tls_context(host, verify=True):
    """TLS-context voor SMTP. Zonder expliciete context verifieert smtplib het
    servercertificaat niet, waardoor een MITM het SMTP-wachtwoord en de
    2FA-codes kan onderscheppen. Uitzondering: een lokale relay op loopback
    (vaak met een self-signed snakeoil-certificaat) — daar is geen netwerkpad
    om te onderscheppen."""
    ctx = ssl_mod.create_default_context()
    # verify=False: expliciete keuze in de SMTP-instellingen voor een eigen
    # mailserver met self-signed certificaat.
    if not verify or host in ('localhost', '127.0.0.1', '::1'):
        ctx.check_hostname = False
        ctx.verify_mode = ssl_mod.CERT_NONE
    return ctx


def send_email(subject, body_text, body_html=None, to=None):
    """Send email using configured SMTP settings. Returns (success, error_msg)."""
    smtp_cfg = CONFIG.get('smtp', {})
    host = smtp_cfg.get('host', '')
    if not host:
        return False, 'SMTP not configured'

    port = smtp_cfg.get('port', 587)
    username = smtp_cfg.get('username', '')
    password = smtp_cfg.get('password', '')
    encryption = smtp_cfg.get('encryption', 'starttls')
    from_addr = smtp_cfg.get('from_address', '')
    to_addr = to or CONFIG.get('auth', {}).get('tfa_email', '')

    if not from_addr:
        return False, 'From address not configured'
    if not to_addr:
        return False, 'Recipient address not set'

    from_name = smtp_cfg.get('from_name', '')

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = formataddr((from_name, from_addr)) if from_name else from_addr
    msg['To'] = to_addr
    msg.attach(MIMEText(body_text, 'plain'))
    if body_html:
        msg.attach(MIMEText(body_html, 'html'))

    server = None
    try:
        if encryption == 'ssl':
            server = smtplib.SMTP_SSL(host, port, timeout=10, context=_smtp_tls_context(host, smtp_cfg.get('verify_tls', True)))
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            if encryption == 'starttls':
                server.starttls(context=_smtp_tls_context(host, smtp_cfg.get('verify_tls', True)))
        if username and password:
            server.login(username, password)
        server.sendmail(from_addr, [to_addr], msg.as_string())
        return True, ''
    except ssl_mod.SSLCertVerificationError as e:
        return False, (f'TLS certificate verification failed ({e.verify_message or e}). '
                       "For your own mail server with a self-signed certificate, turn off "
                       "'Verify TLS certificate' in the SMTP settings.")
    except Exception as e:
        return False, str(e)
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass


def _send_2fa_code_email(code):
    """Send the 2FA verification code via email"""
    subject = f'VPS Manager - Login Code: {code}'
    body_text = f'Your VPS Manager verification code is {code}\n\nThis code expires in 10 minutes.'
    body_html = f'''<div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:20px">
<h2 style="color:#e6edf3;margin:0 0 16px">VPS Manager</h2>
<p style="color:#8b949e;margin:0 0 20px">Your login verification code:</p>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;text-align:center;margin:0 0 20px">
<span style="font-size:32px;font-weight:700;letter-spacing:8px;color:#58a6ff">{code}</span>
</div>
<p style="color:#8b949e;font-size:13px;margin:0">This code expires in 10 minutes.</p>
</div>'''
    return send_email(subject, body_text, body_html)


def _get_notification_email():
    """Resolve the target email address for notification emails."""
    addr = CONFIG.get('notification_email', '')
    if addr:
        return addr
    addr = CONFIG.get('auth', {}).get('tfa_email', '')
    if addr:
        return addr
    return CONFIG.get('smtp', {}).get('from_address', '')


def send_notification_email(category, alert):
    """Send an HTML notification email for a server alert."""
    to_addr = _get_notification_email()
    if not to_addr:
        return False, 'No notification email configured'

    category_names = {
        'critical': 'Critical Error',
        'warnings': 'Warning',
        'updates': 'System Updates',
        'security': 'Security',
        'ddos': 'DDoS Detection',
        'backup': 'Backup',
        'app_update': 'App Update',
    }
    cat_label = category_names.get(category, category.title())
    severity = alert.get('severity', 'warning')
    message = alert.get('message', '')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    subject = f'VPS Manager - {cat_label}: {message[:80]}'
    body_text = f'{cat_label}\n\n{message}\n\nTime: {timestamp}'

    safe_msg = html_mod.escape(message)
    severity_color = '#f85149' if severity == 'error' else '#d29922'
    body_html = f'''<div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:20px">
<h2 style="color:#e6edf3;margin:0 0 16px">VPS Manager</h2>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:0 0 16px">
<div style="font-size:12px;color:{severity_color};text-transform:uppercase;font-weight:600;margin:0 0 8px">{cat_label}</div>
<div style="font-size:15px;color:#e6edf3;margin:0 0 12px">{safe_msg}</div>
<div style="font-size:12px;color:#8b949e">{timestamp}</div>
</div>
</div>'''

    return send_email(subject, body_text, body_html, to=to_addr)


def _session_epoch():
    return CONFIG['auth'].get('session_epoch', 0)


def _session_epoch_valid():
    """Sessies zijn signed cookies; zonder server-side teller blijft een
    gestolen cookie geldig tot hij verloopt, ook na een wachtwoordwijziging.
    De epoch in de config wordt opgehoogd bij wachtwoord-/2FA-wijzigingen,
    waarmee alle andere sessies ongeldig worden."""
    return session.get('epoch', 0) == _session_epoch()


def _bump_session_epoch():
    """Invalideer alle andere sessies; de huidige sessie blijft geldig."""
    with _config_runtime_lock:
        CONFIG['auth']['session_epoch'] = _session_epoch() + 1
        save_config(CONFIG)
    session['epoch'] = _session_epoch()


def _start_session(username, method):
    # Verse sessie tegen session fixation
    session.clear()
    session.permanent = True
    session['logged_in'] = True
    session['username'] = username
    session['epoch'] = _session_epoch()
    log_audit('login', {'method': method})
    return redirect(url_for('dashboard'))


# Een half afgeronde 2FA-login (wachtwoord ok, code nog niet) is maar
# beperkt geldig: anders kan een achtergelaten cookie later zonder
# wachtwoord afgemaakt worden.
_2FA_PENDING_LIFETIME = 600


def _wants_json():
    """True voor fetch/XHR-aanroepen: die kunnen niets met een redirect naar
    de HTML-loginpagina (fetch volgt hem en de JSON-parse faalt dan met een
    misleidende "Connection error")."""
    return (request.path.startswith('/api/')
            or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
            or 'X-CSRFToken' in request.headers
            or request.is_json)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in') or not _session_epoch_valid():
            # Alleen een ingelogde sessie met een verouderde epoch opruimen.
            # Een niet-ingelogde sessie niet aanraken: een poll uit een oude
            # tab zou anders de cookie (CSRF-token, half afgeronde 2FA) van de
            # tab waarin net wordt ingelogd wissen.
            if session.get('logged_in'):
                for k in ('logged_in', 'username', 'epoch'):
                    session.pop(k, None)
            if _wants_json():
                return jsonify({'status': 'error',
                                'message': 'Session expired, please log in again',
                                'login_url': url_for('login')}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


@app.errorhandler(CSRFError)
def _handle_csrf_error(e):
    # Het CSRF-token hoort bij de sessie: is die verlopen, dan is "log opnieuw
    # in" de juiste melding, niet "token verlopen".
    if not session.get('logged_in') and _wants_json():
        return jsonify({'status': 'error',
                        'message': 'Session expired, please log in again',
                        'login_url': url_for('login')}), 401
    if _wants_json():
        return jsonify({'status': 'error',
                        'message': 'Security token expired, reload the page',
                        'csrf_expired': True}), 400
    flash('Your session expired, please try again.', 'danger')
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    ref = request.referrer or ''
    if ref and urllib.parse.urlparse(ref).netloc == request.host:
        return redirect(ref)
    return redirect(url_for('dashboard'))


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    show_2fa = False
    tfa_method = None
    if request.method == 'POST':
        client_ip = request.remote_addr

        # Rate limiting check
        if _is_rate_limited(client_ip):
            flash('Too many login attempts. Try again later.', 'danger')
            return render_template('login.html', show_2fa=False)

        username = request.form.get('username', '')
        password = request.form.get('password', '')
        totp_code = request.form.get('totp_code', '').strip()
        email_code = request.form.get('email_code', '').strip()

        # Determine active 2FA method (backward compat: totp_secret without tfa_method)
        active_tfa = CONFIG['auth'].get('tfa_method')
        if not active_tfa and CONFIG['auth'].get('totp_secret') and HAS_2FA:
            active_tfa = 'totp'

        # If we're in 2FA step, credentials are stored in session
        if session.get('2fa_pending') and (
                time.time() - session.get('2fa_started', 0) > _2FA_PENDING_LIFETIME
                or session.get('2fa_epoch', 0) != _session_epoch()):
            session.clear()
            flash('Login expired, please sign in again', 'danger')
            return render_template('login.html', show_2fa=False)

        if session.get('2fa_pending'):
            username = session.get('2fa_username', '')
            method = session.get('2fa_method', 'totp')

            if method == 'totp':
                totp_secret = CONFIG['auth'].get('totp_secret')
                if totp_secret and HAS_2FA and totp_code:
                    if _verify_totp(totp_secret, totp_code):
                        return _start_session(username, '2fa_totp')
                _record_attempt(client_ip)
                flash('Invalid 2FA code', 'danger')
                return render_template('login.html', show_2fa=True, tfa_method='totp')

            elif method == 'email':
                if email_code:
                    ok, err = _verify_email_code(email_code)
                    if ok:
                        return _start_session(username, '2fa_email')
                    _record_attempt(client_ip)
                    flash(err, 'danger')
                    return render_template('login.html', show_2fa=True, tfa_method='email')
                _record_attempt(client_ip)
                flash('Enter the verification code', 'danger')
                return render_template('login.html', show_2fa=True, tfa_method='email')

        # Beide checks altijd uitvoeren (geen short-circuit) zodat de
        # responstijd niet verraadt of de username bestond. Vergelijk op bytes:
        # compare_digest gooit een TypeError op str met niet-ASCII tekens.
        user_ok = hmac.compare_digest(username.encode('utf-8'), USERNAME.encode('utf-8'))
        pass_ok = check_password_hash(PASSWORD_HASH, password)
        if user_ok and pass_ok:
            if active_tfa in ('totp', 'email'):
                if active_tfa == 'email':
                    # Hergebruik een nog geldige, recent verstuurde code: anders
                    # kan iedereen met het wachtwoord de eigenaar met mails
                    # bestoken en diens openstaande code steeds ongeldig maken.
                    with _email_2fa_lock:
                        recent = (_email_2fa_code
                                  and time.time() - _email_2fa_code.get('last_sent', 0) < _EMAIL_RESEND_COOLDOWN
                                  and time.time() < _email_2fa_code.get('expires', 0))
                    if not recent:
                        code = _generate_email_code()
                        ok, err = _send_2fa_code_email(code)
                        if not ok:
                            app.logger.error('Email 2FA send failed: %s', err)
                            flash('Could not send verification email. Check SMTP settings on the server.', 'danger')
                            return render_template('login.html', show_2fa=False)
                session['2fa_pending'] = True
                session['2fa_username'] = username
                session['2fa_method'] = active_tfa
                session['2fa_started'] = time.time()
                session['2fa_epoch'] = _session_epoch()
                return render_template('login.html', show_2fa=True, tfa_method=active_tfa)

            return _start_session(username, 'password')
        _record_attempt(client_ip)
        # Begrens de lengte: de gebruikersnaam komt ongeauthenticeerd binnen
        # en zou anders de audit log onbeperkt kunnen laten groeien. Bij een
        # golf mislukte logins (veel IP's) alleen nog naar de applicatielog,
        # zodat echte beheeracties niet uit de audit trail (max 1000) vallen.
        if _audit_failed_login_allowed():
            log_audit('login_failed', {'username': username[:64]})
        else:
            logger.warning('Failed login from %s (audit entry suppressed: too many failures)', client_ip)
        flash('Invalid username or password', 'danger')
    return render_template('login.html', show_2fa=show_2fa, tfa_method=tfa_method)


@app.route('/settings/2fa/send-code', methods=['POST'])
def resend_2fa_code():
    """Resend email 2FA code during login (no login_required, but needs 2fa_pending)"""
    if not session.get('2fa_pending') or session.get('2fa_method') != 'email':
        return jsonify({'status': 'error', 'message': 'No email 2FA pending'}), 400
    # Zelfde geldigheid als in login(): anders kan een oude pending-cookie
    # (ook na een wachtwoordwijziging) de eigenaar nog uren met mails bestoken.
    if (time.time() - session.get('2fa_started', 0) > _2FA_PENDING_LIFETIME
            or session.get('2fa_epoch', 0) != _session_epoch()):
        session.clear()
        return jsonify({'status': 'error', 'message': 'Login expired, please sign in again'}), 400

    with _email_2fa_lock:
        last_sent = _email_2fa_code.get('last_sent', 0)
        if time.time() - last_sent < _EMAIL_RESEND_COOLDOWN:
            remaining = int(_EMAIL_RESEND_COOLDOWN - (time.time() - last_sent))
            return jsonify({'status': 'error', 'message': f'Wait {remaining}s before resending'}), 429
        # Generate code inside lock to prevent TOCTOU race
        code = str(secrets.SystemRandom().randint(100000, 999999))
        _email_2fa_code.clear()
        _email_2fa_code.update({
            'code': code,
            'expires': time.time() + _EMAIL_CODE_LIFETIME,
            'attempts': 0,
            'last_sent': time.time(),
        })

    ok, err = _send_2fa_code_email(code)
    if not ok:
        return jsonify({'status': 'error', 'message': 'Could not send email'}), 500
    return jsonify({'status': 'ok', 'message': 'Code sent'})


@app.route('/logout', methods=['POST'])
def logout():
    # POST + CSRF zodat een force-logout via <img src> / cross-site GET niet werkt.
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
    # ';' i.p.v. '&&': één falend onderdeel (bijv. geen PRETTY_NAME) mag niet
    # de hele overview — en daarmee de disk/RAM/load-alerts — laten wegvallen.
    cmd = (
        "hostname; echo '---SEP---'; "
        "cat /proc/uptime; echo '---SEP---'; "
        "cat /proc/cpuinfo | grep 'model name' | head -1; echo '---SEP---'; "
        "nproc; echo '---SEP---'; "
        "free -b | grep Mem; echo '---SEP---'; "
        "free -b | grep Swap; echo '---SEP---'; "
        "df -h / | tail -1; echo '---SEP---'; "
        "cat /etc/os-release | grep PRETTY_NAME; echo '---SEP---'; "
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


def _nginx_parse(content):
    """Minimal nginx config parser (directives + blocks, comment/quote aware).

    Returns (directives, blocks). Elke directive is een dict met name, args,
    depth, parents (tuple van omsluitende blocknamen), server (index van het
    omsluitende top-level server-block of None), line en end_line (0-based).
    Blocks hebben daarnaast brace_line/brace_col (positie van de '{').
    Commentaar ('# ...' aan het begin van een token) wordt genegeerd, dus een
    uitgecommentarieerde '# access_log ...' telt niet mee, en '${var}' wordt
    niet als block-opening gezien.
    """
    directives = []
    blocks = []
    stack = []
    tokens = []
    word = []
    stmt_line = None
    line = 0
    col = 0
    server_count = 0
    i = 0
    n = len(content)

    def _flush():
        if word:
            tokens.append(''.join(word))
            word.clear()

    def _current_server():
        for b in stack:
            if b['server'] is not None:
                return b['server']
        return None

    while i < n:
        ch = content[i]
        if ch in ' \t\r\n':
            _flush()
            if ch == '\n':
                line += 1
                col = 0
            else:
                col += 1
            i += 1
            continue
        if ch == '#' and not word:
            while i < n and content[i] != '\n':
                i += 1
            continue
        if stmt_line is None and not tokens and not word:
            stmt_line = line
        if ch in '"\'' and not word:
            quote = ch
            i += 1
            col += 1
            buf = []
            while i < n and content[i] != quote:
                if content[i] == '\\' and i + 1 < n:
                    buf.append(content[i + 1])
                    i += 2
                    col += 2
                    continue
                if content[i] == '\n':
                    line += 1
                    col = 0
                else:
                    col += 1
                buf.append(content[i])
                i += 1
            tokens.append(''.join(buf))
            i += 1
            col += 1
            continue
        if ch == '$' and i + 1 < n and content[i + 1] == '{':
            end = content.find('}', i)
            if end == -1 or '\n' in content[i:end]:
                end = i + 1
            word.append(content[i:end + 1])
            col += end + 1 - i
            i = end + 1
            continue
        if ch == ';':
            _flush()
            if tokens:
                directives.append({
                    'name': tokens[0],
                    'args': tokens[1:],
                    'depth': len(stack),
                    'parents': tuple(b['name'] for b in stack),
                    'server': _current_server(),
                    'line': stmt_line if stmt_line is not None else line,
                    'end_line': line,
                })
            tokens = []
            stmt_line = None
        elif ch == '{':
            _flush()
            name = tokens[0] if tokens else ''
            parents = tuple(b['name'] for b in stack)
            server_idx = None
            if name == 'server' and _current_server() is None and 'upstream' not in parents:
                server_idx = server_count
                server_count += 1
            block = {
                'name': name,
                'args': tokens[1:],
                'depth': len(stack),
                'parents': parents,
                'server': server_idx if server_idx is not None else _current_server(),
                'line': stmt_line if stmt_line is not None else line,
                'brace_line': line,
                'brace_col': col,
            }
            blocks.append(block)
            stack.append(block)
            tokens = []
            stmt_line = None
        elif ch == '}':
            _flush()
            tokens = []
            stmt_line = None
            if stack:
                stack.pop()
        else:
            word.append(ch)
        i += 1
        col += 1

    return directives, blocks


def _nginx_site_log_paths(content):
    """(access_log, error_log) paden uit een nginx site-config, of None.

    'access_log off' telt niet als logpad (exact argument, geen substring:
    een pad als /var/log/nginx/coffee-access.log is gewoon een logpad).
    """
    access_log_path = None
    error_log_path = None
    directives, _ = _nginx_parse(content)
    for d in directives:
        if not d['args']:
            continue
        if d['name'] == 'access_log' and d['args'][0] != 'off':
            access_log_path = d['args'][0]
        elif d['name'] == 'error_log':
            error_log_path = d['args'][0]
    return access_log_path, error_log_path


def _nginx_add_site_logs(content, domain):
    """Return content with access_log/error_log added to the main server block,
    or None when nothing needs to change (or no safe insert point exists).

    Het doel-block is het eerste top-level server-block dat content serveert
    (root/*_pass), bij voorkeur met het domein in server_name; anders het
    eerste server-block. Alleen directives op server-niveau tellen: een
    expliciete 'access_log off' op server-niveau wordt gerespecteerd.
    De regels worden direct na 'server {' ingevoegd, dus altijd op
    server-niveau en nooit binnen een location-block.
    """
    safe_domain = re.sub(r'[^a-zA-Z0-9._-]', '', domain or '')
    if not safe_domain:
        return None
    directives, blocks = _nginx_parse(content)
    servers = [b for b in blocks if b['name'] == 'server' and b['server'] is not None
               and 'server' not in b['parents']]
    if not servers:
        return None

    serving_names = ('root', 'proxy_pass', 'fastcgi_pass', 'uwsgi_pass', 'grpc_pass', 'scgi_pass')

    def _serves(srv):
        return any(d['server'] == srv['server'] and d['name'] in serving_names for d in directives)

    def _has_domain(srv):
        return any(d['server'] == srv['server'] and d['name'] == 'server_name' and domain in d['args']
                   for d in directives)

    candidates = [s for s in servers if _serves(s)] or servers
    target = next((s for s in candidates if _has_domain(s)), candidates[0])

    level = [d for d in directives
             if d['server'] == target['server'] and d['depth'] == target['depth'] + 1]
    has_access_log = any(d['name'] == 'access_log' for d in level)
    has_error_log = any(d['name'] == 'error_log' for d in level)
    if has_access_log and has_error_log:
        return None

    lines = content.split('\n')
    brace_line = target['brace_line']
    if brace_line >= len(lines):
        return None
    rest = lines[brace_line][target['brace_col'] + 1:].strip()
    if rest and not rest.startswith('#'):
        # 'server { listen 80; ... }' op één regel: geen veilige invoegplek
        return None

    indent = None
    for d in level:
        if d['line'] > brace_line:
            src = lines[d['line']]
            indent = src[:len(src) - len(src.lstrip())]
            break
    if not indent:
        base = lines[target['line']]
        indent = base[:len(base) - len(base.lstrip())] + '    '

    new_lines = []
    if not has_access_log:
        new_lines.append(f'{indent}access_log /var/log/nginx/{safe_domain}-access.log;')
    if not has_error_log:
        new_lines.append(f'{indent}error_log /var/log/nginx/{safe_domain}-error.log;')
    lines[brace_line + 1:brace_line + 1] = new_lines
    return '\n'.join(lines)


# Auto-log toevoegen gebeurt hooguit één keer per bestand per versie (mtime)
# per proces. Zonder deze rem herschreef elke cache-ronde (pagina of monitor)
# de live config en herlaadde de webserver, ook als het de vorige keer faalde.
_autolog_attempted = set()
_autolog_lock = threading.Lock()


def _autolog_key(path):
    try:
        return (path, os.stat(path).st_mtime_ns)
    except OSError:
        return (path, None)


def _autolog_should_attempt(path):
    """True als voor deze versie van het bestand nog geen poging is gedaan."""
    key = _autolog_key(path)
    with _autolog_lock:
        if key in _autolog_attempted:
            return False
        _autolog_attempted.add(key)
    return True


def _autolog_mark_done(path):
    """Markeer de huidige versie (na een eigen schrijfactie) als afgehandeld."""
    with _autolog_lock:
        _autolog_attempted.add(_autolog_key(path))


def _ensure_nginx_site_logs(config_path, domain):
    """Auto-add access_log and error_log directives to an nginx config that lacks them.

    Idempotent en niet-lussend: één poging per bestandsversie per proces,
    schrijven/valideren/herladen via _sudo_write_validated (met rollback),
    en alleen een audit-entry als er daadwerkelijk iets is gewijzigd.
    Returns True if the config was modified."""
    if not _autolog_should_attempt(config_path):
        return False
    # Lezen-aanpassen-schrijven onder dezelfde lock als een save uit de UI;
    # anders kon een tussentijdse edit overschreven worden.
    with _webconfig_write_lock:
        result = run_cmd_safe(["sudo", "cat", config_path], timeout=5)
        if result.returncode != 0:
            return False

        new_content = _nginx_add_site_logs(result.stdout, domain)
        if new_content is None:
            return False

        res = _sudo_write_validated(config_path, new_content, validate_nginx,
                                    lambda: run_cmd_safe(["sudo", "systemctl", "reload", "nginx"], timeout=15))
    _autolog_mark_done(config_path)
    if not res['written']:
        logger.warning("Auto-adding nginx logs to %s failed (%s): %s",
                       config_path, res['stage'], res['output'] or res['message'])
        return False
    if not res['ok']:
        logger.warning("Nginx reload failed after auto-adding logs to %s: %s", config_path, res['output'])

    log_audit('nginx_auto_add_logs', {'config': os.path.basename(config_path), 'domain': domain})
    return True


def _check_http_status(domain):
    """HTTP status for one domain: HTTPS with HTTP fallback, follows redirects."""
    status = '---'
    for scheme in ('https', 'http'):
        result = run_cmd_safe(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-L",
             f"{scheme}://{domain}", "--max-time", "5"],
            timeout=10
        )
        status = result.stdout.strip() if result.stdout else '---'
        if status != '000':
            return status
    return status


def _check_http_statuses(domains):
    """Check HTTP status for multiple domains in parallel.

    Serieel kan dit bij N sites tot N×10s duren; parallel is de duurste
    site bepalend in plaats van de som.
    """
    statuses = {}
    unique = list(dict.fromkeys(domains))
    if not unique:
        return statuses
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(unique))) as pool:
        futures = {pool.submit(_check_http_status, d): d for d in unique}
        for fut in concurrent.futures.as_completed(futures):
            try:
                statuses[futures[fut]] = fut.result()
            except Exception:
                statuses[futures[fut]] = '---'
    return statuses


def _read_nginx_site_config(config_path):
    """Lees een nginx site-config (zonder sudo als het bestand leesbaar is)."""
    try:
        with open(config_path, encoding='utf-8', errors='replace') as f:
            return f.read()
    except OSError:
        pass
    result = run_cmd_safe(["sudo", "cat", config_path], timeout=5)
    return result.stdout if result.returncode == 0 else None


@_ttl_cache(60, stale=900)
def get_nginx_sites():
    """Get nginx sites with HTTP status"""
    sites_dir = CONFIG['nginx'].get('sites_enabled', '/etc/nginx/sites-enabled/')
    result = run_cmd_safe(["ls", sites_dir])
    if result.returncode != 0:
        return []

    configs = [s.strip() for s in result.stdout.strip().split('\n')
               if s.strip() and s.strip() != 'default']
    sites = []

    for config in configs:
        config_path = os.path.join(sites_dir, config)
        content = _read_nginx_site_config(config_path)
        if content is None:
            continue

        domains = []
        doc_root = None
        proxy = None

        # Echte directive-parsing: uitgecommentarieerde regels tellen niet mee
        directives, _ = _nginx_parse(content)
        for d in directives:
            if d['name'] == 'server_name':
                for name in d['args']:
                    name = name.strip()
                    if name and name != '_' and name != 'localhost':
                        domains.append(name)
            elif d['name'] == 'root' and d['args']:
                doc_root = d['args'][0]
            elif d['name'] == 'proxy_pass' and d['args']:
                proxy = d['args'][0]
        access_log_path, error_log_path = _nginx_site_log_paths(content)

        # Deduplicate domains (certbot creates 2 server blocks per config)
        domains = list(dict.fromkeys(domains))

        if domains:
            # Auto-add log directives if missing (één poging per bestandsversie,
            # valideert en herlaadt zelf; zie _ensure_nginx_site_logs)
            if not access_log_path or not error_log_path:
                if _ensure_nginx_site_logs(config_path, domains[0]):
                    updated = _read_nginx_site_config(config_path)
                    if updated is not None:
                        access_log_path, error_log_path = _nginx_site_log_paths(updated)

            sites.append({
                'config': config,
                'domains': domains,
                'domain': ', '.join(domains),
                'root': doc_root,
                'proxy': proxy,
                'type': 'proxy' if proxy else 'static',
                'location': proxy if proxy else (doc_root or 'n/a'),
                'http_status': '---',
                'access_log': access_log_path,
                'error_log': error_log_path,
            })

    # Check HTTP status for all sites in parallel (first domain per site)
    statuses = _check_http_statuses([s['domains'][0] for s in sites if s['domains']])
    for s in sites:
        if s['domains']:
            s['http_status'] = statuses.get(s['domains'][0], '---')

    return sites


@_ttl_cache(30)
def get_pm2_processes():
    """Get PM2 process list as structured data"""
    result = run_cmd("pm2 jlist")
    if result.returncode != 0 or not result.stdout.strip():
        return []

    # pm2 print soms waarschuwingen op stdout vóór/na de JSON ("In-memory
    # PM2 is out-of-date", "[PM2] Spawning PM2 daemon"); dan faalde json.loads
    # op het geheel en werd PM2-monitoring stil blind. Zoek de JSON-array.
    out = result.stdout
    processes = None
    decoder = json.JSONDecoder()
    idx = out.find('[')
    while idx != -1:
        try:
            parsed, _ = decoder.raw_decode(out, idx)
            if isinstance(parsed, list) and all(isinstance(x, dict) for x in parsed):
                processes = parsed
                break
        except json.JSONDecodeError:
            pass  # bijv. "[PM2] Spawning ..."
        idx = out.find('[', idx + 1)
    if not isinstance(processes, list):
        logger.warning('Could not parse `pm2 jlist` output: %s', out[:200])
        return []

    try:
        pm2_list = []
        for p in processes:
            if not isinstance(p, dict):
                continue
            env = p.get('pm2_env') or {}
            monit = p.get('monit') or {}
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
    except (KeyError, TypeError, AttributeError):
        logger.warning('Unexpected `pm2 jlist` structure', exc_info=True)
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


@_ttl_cache(600, stale=21600)
def get_ssl_certificates():
    """Get SSL certificate info"""
    result = run_cmd("sudo certbot certificates 2>/dev/null", timeout=15)
    if result.returncode != 0:
        return []

    # Per lineage parsen (Certificate Name → Domains → Expiry Date). Dagen
    # zelf uitrekenen uit de datum: "(INVALID: EXPIRED)" en test-certificaten
    # hebben geen "N days" en werden anders "0 dagen".
    lineages = []
    current = None
    for line in result.stdout.split('\n'):
        line = line.strip()
        if line.startswith('Certificate Name:'):
            current = {'name': line.split(':', 1)[1].strip()}
            lineages.append(current)
        elif current is not None and line.startswith('Domains:'):
            current['domains'] = line.split(':', 1)[1].strip()
        elif current is not None and line.startswith('Expiry Date:'):
            m = re.search(r'(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}:\d{2}))?', line)
            if m:
                current['expiry'] = m.group(1)
                try:
                    exp = datetime.strptime(f"{m.group(1)} {m.group(2) or '00:00:00'}", '%Y-%m-%d %H:%M:%S')
                    current['days_left'] = (exp - datetime.now(timezone.utc).replace(tzinfo=None)).days
                except ValueError:
                    days_match = re.search(r'(\d+)\s+day', line)
                    current['days_left'] = int(days_match.group(1)) if days_match else 0
                current['invalid'] = 'INVALID' in line
                current['test_cert'] = 'TEST_CERT' in line

    # Dubbele lineages (example.com-0001) met dezelfde domeinen: alleen de
    # langst geldige telt; het oude, ongebruikte certificaat gaf anders een
    # permanente "verloopt"-alert.
    best = {}
    for lin in lineages:
        if not lin.get('domains') or 'expiry' not in lin or lin.get('test_cert'):
            continue
        key = ' '.join(sorted(lin['domains'].split()))
        if key not in best or lin['days_left'] > best[key]['days_left']:
            best[key] = lin
    certs = [{'domain': lin['domains'], 'expiry': lin['expiry'], 'days_left': lin['days_left'],
              'name': lin['name']} for lin in best.values()]
    certs.sort(key=lambda c: c['days_left'])
    return certs


@_ttl_cache(30)
def get_services_status():
    """Get status of key services (only shows installed services)"""
    result = run_cmd(
        "systemctl list-units --type=service --state=active --no-legend 2>/dev/null | awk '{print $1}'"
    )
    active_services = result.stdout.strip().split('\n') if result.stdout else []

    # Get all known unit files to determine which services are actually installed
    unit_result = run_cmd(
        "systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}'"
    )
    installed_units = set()
    if unit_result.returncode == 0:
        for u in unit_result.stdout.strip().split('\n'):
            installed_units.add(u.strip().replace('.service', ''))

    default_services = CONFIG.get('services', ['nginx', 'php8.3-fpm', 'mariadb', 'fail2ban'])
    # Filter default services to only those actually installed
    services = [s for s in default_services if s in installed_units]
    seen = set(services)

    for svc in active_services:
        svc = svc.strip().replace('.service', '')
        if not svc:
            continue
        if 'php' in svc and 'fpm' in svc and svc not in seen:
            services.append(svc)
            seen.add(svc)
        if svc in ('ufw', 'cron', 'ssh') and svc not in seen:
            services.append(svc)
            seen.add(svc)

    # Deduplicate auto-discovered PHP-FPM versions
    final_services = []
    php_auto_found = False
    configured_set = set(s for s in default_services if s in installed_units)
    for svc in services:
        if 'php' in svc and 'fpm' in svc and svc not in configured_set:
            if php_auto_found:
                continue
            php_auto_found = True
        final_services.append(svc)

    result = run_cmd_safe(["systemctl", "is-active"] + final_services)
    statuses = result.stdout.strip().split('\n') if result.stdout else []

    # Eén `systemctl show` voor alle actieve services i.p.v. één per service.
    # Monotone timestamp (µs sinds boot) i.p.v. ActiveEnterTimestamp: die
    # laatste is locale-afhankelijk ("di 2026-02-03 ...") en brak strptime.
    active_names = [svc for i, svc in enumerate(final_services)
                    if i < len(statuses) and statuses[i].strip() == 'active']
    started_mono = {}
    if active_names:
        show = run_cmd_safe(["systemctl", "show", "-p", "Id", "-p", "ActiveEnterTimestampMonotonic"]
                            + active_names)
        for block, name in zip(show.stdout.strip().split('\n\n'), active_names):
            props = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
            try:
                started_mono[name] = int(props.get('ActiveEnterTimestampMonotonic', '0')) / 1e6
            except ValueError:
                pass
    try:
        with open('/proc/uptime') as f:
            boot_uptime = float(f.read().split()[0])
    except (OSError, ValueError, IndexError):
        boot_uptime = None

    svc_list = []
    for i, service in enumerate(final_services):
        status = statuses[i].strip() if i < len(statuses) else 'unknown'
        uptime = ''
        if status == 'active':
            started = started_mono.get(service)
            if started and boot_uptime is not None and boot_uptime >= started:
                secs = int(boot_uptime - started)
                days, rem = divmod(secs, 86400)
                hours, rem = divmod(rem, 3600)
                minutes = rem // 60
                if days > 0:
                    uptime = f"{days}d {hours}h"
                elif hours > 0:
                    uptime = f"{hours}h {minutes}m"
                else:
                    uptime = f"{minutes}m"
            else:
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


@_ttl_cache(300, stale=21600)
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


_AUTH_LOG_TAIL_BYTES = 20_000_000
# Regels van het sshd-proces zelf (ook sshd-session[..] sinds OpenSSH 9.8).
# Een losse 'sshd'-match ving ook de sudo-logregels van de app zelf
# ("COMMAND=/usr/bin/fail2ban-client status sshd").
_SSHD_LINE_RE = re.compile(r'\bsshd(?:-session)?\[\d+\]:')
_SSHD_GREP = r"grep -E 'sshd(-session)?\[[0-9]+\]:'"


def _tail_file_lines(path, max_bytes):
    """Laatste max_bytes van een (root-only) logbestand als regels.

    Een eventueel afgekapte eerste regel wordt weggelaten."""
    result = run_cmd_safe(['sudo', 'tail', '-c', str(max_bytes), path], timeout=20)
    if result.returncode != 0 or not result.stdout:
        return []
    lines = result.stdout.split('\n')
    if len(result.stdout) >= max_bytes - 1 and len(lines) > 1:
        lines = lines[1:]
    return [line for line in lines if line.strip()]


def _extract_log_ip(line):
    """IPv4- of IPv6-adres na 'from' in een auth.log-regel, of ''."""
    m = re.search(r'from\s+([0-9a-fA-F:.]+[0-9a-fA-F])', line)
    if m and _is_valid_ip(m.group(1)):
        return m.group(1)
    return ''


@_ttl_cache(60, stale=600)
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

    # Eén pass in Python over het staartstuk van auth.log, i.p.v. zeven
    # volledige grep-scans: auth.log is op een server onder brute-force al
    # snel honderden MB's. De tellingen gelden daarmee voor het recente deel
    # van de log (laatste ~20 MB).
    auth_lines = _tail_file_lines('/var/log/auth.log', _AUTH_LOG_TAIL_BYTES)
    failed_re = re.compile(r'failed|invalid user|authentication failure', re.I)
    attacker_re = re.compile(r'failed|invalid user', re.I)
    failed, accepted, sshd_lines = [], [], []
    attackers = Counter()
    for line in auth_lines:
        if failed_re.search(line):
            failed.append(line)
            if attacker_re.search(line):
                ip = _extract_log_ip(line)
                if ip:
                    attackers[ip] += 1
        if 'accepted' in line.lower():
            accepted.append(line)
        if _SSHD_LINE_RE.search(line):
            sshd_lines.append(line)

    data['failed_count'] = len(failed)
    data['accepted_count'] = len(accepted)
    data['recent_failed'] = [_parse_auth_log_line(line) for line in failed[-30:]]
    data['recent_accepted'] = [_parse_auth_log_line(line) for line in accepted[-20:]]
    data['recent_entries'] = [_parse_auth_log_line(line) for line in sshd_lines[-20:]]
    data['top_attackers'] = [{'ip': ip, 'count': c} for ip, c in attackers.most_common(20)]

    # Fail2ban actions (bans/unbans)
    # Alleen echte Ban/Unban-acties; 'ban' case-insensitive matchte ook de
    # "fail2ban."-loggerprefix van elke regel.
    ban_re = re.compile(r'\b(?:Ban|Unban)\b')
    f2b_lines = [line for line in _tail_file_lines('/var/log/fail2ban.log', 2_000_000)
                 if ban_re.search(line)][-30:]
    for line in f2b_lines:
        line = line.strip()
        if not line:
            continue
        # Parse: 2026-03-10 12:34:56,789 fail2ban.actions [1234]: NOTICE [sshd] Ban 1.2.3.4
        ts_match = re.match(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
        timestamp = ts_match.group(1) if ts_match else ''
        action = 'ban' if re.search(r'\bBan\b', line) else 'unban' if re.search(r'\bUnban\b', line) else 'other'
        ip_match = re.search(r'(?:Ban|Unban|Found)\s+([0-9a-fA-F:.]+)', line)
        ip = ip_match.group(1) if ip_match and _is_valid_ip(ip_match.group(1)) else ''
        jail_match = re.search(r'\[([\w-]+)\]\s+(?:Ban|Unban|Found)', line)
        jail = jail_match.group(1) if jail_match else ''
        data['fail2ban_actions'].append({
            'timestamp': timestamp,
            'action': action,
            'ip': ip,
            'jail': jail,
            'raw': line,
        })

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
    # Twee formaten:
    #  - legacy BSD syslog:  Mar 10 12:34:56 hostname sshd[1234]: message
    #  - rsyslog ISO8601 (Ubuntu 24.04 default):
    #      2026-03-10T12:34:56.789012+00:00 hostname sshd[1234]: message
    match = re.match(
        r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+\S+:\s+(.*)',
        line
    )
    if not match:
        match = re.match(
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)\s+\S+\s+\S+:\s+(.*)',
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

    # Extract IP (IPv4 en IPv6)
    ip = _extract_log_ip(line)

    return {
        'timestamp': timestamp,
        'level': level,
        'message': message[:200],
        'ip': ip,
        'raw': line,
    }


def _run_cmds_parallel(cmds, timeout=30):
    """Voer onafhankelijke shell-commando's parallel uit: {naam: cmd} →
    {naam: resultaat}. fail2ban-client en ufw zijn Python-tools met elk
    ~0.2-0.4 s opstarttijd; serieel telt dat snel op tot seconden."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(cmds)))) as ex:
        futures = {name: ex.submit(run_cmd, cmd, timeout) for name, cmd in cmds.items()}
        return {name: f.result() for name, f in futures.items()}


@_ttl_cache(30)
def get_firewall_security():
    """Get firewall and security info"""
    data = {
        'ufw': '', 'ufw_rules': [], 'fail2ban': '', 'banned': '', 'sessions': '', 'auth_log': '',
        'f2b_config': {}, 'jails': [],
    }

    r = _run_cmds_parallel({
        'ufw': "sudo ufw status numbered 2>/dev/null",
        'sshd': "sudo fail2ban-client status sshd 2>/dev/null",
        'banned': "sudo fail2ban-client banned 2>/dev/null",
        'who': "who",
        # Alleen het staartstuk: auth.log is op een aangevallen server al
        # snel honderden MB's en een volledige grep kostte seconden.
        'auth': f"sudo tail -n 5000 /var/log/auth.log 2>/dev/null | {_SSHD_GREP} | tail -15",
        'bantime': "sudo fail2ban-client get sshd bantime 2>/dev/null",
        'findtime': "sudo fail2ban-client get sshd findtime 2>/dev/null",
        'maxretry': "sudo fail2ban-client get sshd maxretry 2>/dev/null",
        'jails': "sudo fail2ban-client status 2>/dev/null",
    })

    if r['ufw'].returncode == 0:
        data['ufw'] = r['ufw'].stdout.strip()
        data['ufw_rules'] = parse_ufw_rules(r['ufw'].stdout)
    if r['sshd'].returncode == 0:
        data['fail2ban'] = r['sshd'].stdout.strip()
    if r['banned'].returncode == 0:
        data['banned'] = r['banned'].stdout.strip()
    if r['who'].returncode == 0:
        data['sessions'] = r['who'].stdout.strip()
    if r['auth'].returncode == 0:
        data['auth_log'] = r['auth'].stdout.strip()

    # Fail2ban config details
    f2b_config = {}
    for setting in ['bantime', 'findtime', 'maxretry']:
        result = r[setting]
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
    if r['jails'].returncode == 0:
        jail_match = re.search(r'Jail list:\s*(.+)', r['jails'].stdout)
        if jail_match:
            jail_names = [j.strip() for j in jail_match.group(1).split(',') if j.strip()]
            # sshd-status hebben we al; de rest parallel
            jail_results = _run_cmds_parallel({
                name: f"sudo fail2ban-client status {shlex.quote(name)} 2>/dev/null"
                for name in jail_names if name != 'sshd'
            }) if jail_names else {}
            if 'sshd' in jail_names:
                jail_results['sshd'] = r['sshd']
            for jail_name in jail_names:
                jail_result = jail_results[jail_name]
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


@_ttl_cache(1800, stale=86400)
def get_system_updates():
    """Get list of available updates, categorized"""
    # LC_ALL=C: de parsers hieronder zoeken op Engelse apt-teksten
    result = run_cmd("LC_ALL=C apt list --upgradable 2>/dev/null", timeout=60)
    if result.returncode != 0:
        return []

    # Detect phased packages via simulated upgrade. Koptekst verschilt per
    # apt-versie: "...have been kept back / deferred due to phasing:" (oud)
    # of "Not upgrading yet due to phasing:" (apt >= 2.9). De pakketlijst
    # staat ingesprongen eronder; de eerste niet-ingesprongen regel is de
    # volgende sectie (bijv. "The following packages will be upgraded:").
    phased_packages = set()
    sim_result = run_cmd("LC_ALL=C apt -s upgrade 2>/dev/null", timeout=60)
    if sim_result.returncode == 0 and 'due to phasing' in sim_result.stdout:
        in_phased = False
        for sim_line in sim_result.stdout.split('\n'):
            if 'due to phasing' in sim_line:
                in_phased = True
                continue
            if in_phased:
                if not sim_line.startswith((' ', '\t')) or not sim_line.strip():
                    break
                phased_packages.update(sim_line.split())

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


@_ttl_cache(60, stale=600)
def get_nginx_logs():
    """Get nginx log information"""
    nginx_cfg = CONFIG.get('nginx', {})
    error_log = nginx_cfg.get('error_log', '/var/log/nginx/error.log')

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
        # Alleen de laatste 10k requests: awk+sort over een access log van
        # enkele GB's kostte per site seconden (de caddy-variant deed dit al zo).
        result = run_cmd(
            f"sudo tail -n 10000 {shlex.quote(site_access_log)} 2>/dev/null "
            f"| awk '{{print $9}}' | sort | uniq -c | sort -rn | head -10"
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


@_ttl_cache(300, stale=3600)
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


_CRON_SPECIALS = {
    '@reboot': 'At boot', '@yearly': 'Yearly', '@annually': 'Yearly',
    '@monthly': 'Monthly', '@weekly': 'Weekly', '@daily': 'Daily',
    '@midnight': 'Daily', '@hourly': 'Hourly',
}


def _cron_to_human(parts):
    """Convert cron schedule parts to human-readable string"""
    if len(parts) == 1 and parts[0].lower() in _CRON_SPECIALS:
        return _CRON_SPECIALS[parts[0].lower()]
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

    # Zelfde parser als de edit/delete/run-endpoints, zodat de index die de
    # UI meestuurt naar dezelfde regel wijst.
    root_text, _ = _read_crontab('root')
    if root_text:
        data['root'] = root_text.strip()
        data['root_jobs'] = _parse_crontab_lines(root_text)[1]

    user_text, _ = _read_crontab('user')
    # Skip user crontab section if it's identical to root (app running as root)
    if user_text and user_text.strip() != data['root']:
        data['user'] = user_text.strip()
        data['user_jobs'] = _parse_crontab_lines(user_text)[1]

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


def _human_kb(kb):
    """KB → du -h-achtige notatie (4.0K, 512M, 1.2G)."""
    size = float(kb)
    for unit in ('K', 'M', 'G', 'T'):
        if size < 1024 or unit == 'T':
            return f"{size:.1f}{unit}" if size < 10 else f"{size:.0f}{unit}"
        size /= 1024


# du loopt de hele /var/www-boom af (seconden tot tientallen seconden bij
# grote sites); de grootte verandert traag, dus ruim cachen.
@_ttl_cache(900, stale=21600)
def get_disk_per_site():
    """Get disk usage per site"""
    # Eén scan met -k i.p.v. -h: het totaal is dan de som, zonder de hele
    # boom een tweede keer met `du -sh /var/www/` af te lopen.
    result = run_cmd("du -sk /var/www/*/ 2>/dev/null", timeout=120)
    if not result.stdout.strip():
        return [], ''

    sites = []
    total_kb = 0
    for line in result.stdout.strip().split('\n'):
        parts = line.split('\t')
        if len(parts) >= 2:
            try:
                kb = int(parts[0].strip())
            except ValueError:
                continue
            total_kb += kb
            path = parts[1].strip().rstrip('/')
            sites.append({'site': os.path.basename(path), 'size': _human_kb(kb),
                          'size_mb': round(kb / 1024, 2)})
    sites.sort(key=lambda x: x['size_mb'], reverse=True)
    return sites, _human_kb(total_kb) if sites else ''


def predict_disk_full_days():
    """Estimate the number of days until / is full, based on a linear fit
    over the collected metrics history.

    Returns None when there is not enough data (< ~2h of points or < 6h
    time span), when disk usage is not growing, or when growth is too slow
    to produce a meaningful forecast (< 0.1%/day would extrapolate noise).
    """
    metrics = _load_metrics()
    pts = [(m['ts'], m['disk']) for m in metrics
           if isinstance(m.get('ts'), (int, float)) and isinstance(m.get('disk'), (int, float))]
    if len(pts) < 24:
        return None
    span = pts[-1][0] - pts[0][0]
    if span < 6 * 3600:
        return None

    # Least-squares linear fit: disk% = slope * t + b
    n = len(pts)
    t0 = pts[0][0]
    xs = [t - t0 for t, _ in pts]
    ys = [d for _, d in pts]
    sx = sum(xs)
    sy = sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    denom = n * sxx - sx * sx
    if denom == 0:
        return None
    slope = (n * sxy - sx * sy) / denom  # %/second
    slope_per_day = slope * 86400
    if slope_per_day < 0.1:
        return None

    remaining = 100 - ys[-1]
    if remaining <= 0:
        return 0.0
    return remaining / slope_per_day


def compute_health_score(alerts):
    """Compute an overall server health score (0-100) from active alerts.

    Alerts al bevatten de individuele problemen (services down, disk,
    SSL, updates, ...), dus de score weegt alleen de alerts zelf — anders
    zou bijv. een kapotte service dubbel tellen.
    """
    score = 100
    for a in alerts:
        sev = a.get('severity')
        if sev == 'error':
            score -= 15
        elif sev == 'warning':
            score -= 5
        else:
            score -= 1
    score = max(0, min(100, score))
    if score >= 90:
        label, color = 'Excellent', 'green'
    elif score >= 75:
        label, color = 'Good', 'green'
    elif score >= 50:
        label, color = 'Fair', 'yellow'
    else:
        label, color = 'Needs attention', 'red'
    return {'score': score, 'label': label, 'color': color}


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
        if days < 0:
            alerts.append({'severity': 'error', 'message': f"SSL certificate '{domain}' has expired!", 'link': '/ssl', 'key': f"ssl_critical_{domain}"})
        elif days < ssl_critical:
            alerts.append({'severity': 'error', 'message': f"SSL certificate '{domain}' expires in {days} days!", 'link': '/ssl', 'key': f"ssl_critical_{domain}"})
        elif days < ssl_warning:
            alerts.append({'severity': 'warning', 'message': f"SSL certificate '{domain}' expires in {days} days", 'link': '/ssl', 'key': f"ssl_warning_{domain}"})

    # Uptime: require two consecutive failed checks before alerting so
    # slow-starting sites after a VPS reboot don't fire false positives.
    try:
        uptime_history = json.loads(UPTIME_HISTORY_PATH.read_text()) if UPTIME_HISTORY_PATH.exists() else {}
        for domain, entries in uptime_history.items():
            if len(entries) >= 2:
                def _is_down(e):
                    s = e.get('status', 0)
                    return s == 0 or s >= 500
                if _is_down(entries[-1]) and _is_down(entries[-2]):
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

    # Reboot required (e.g. kernel/libc updates installed but not active yet)
    if os.path.exists('/var/run/reboot-required'):
        alerts.append({
            'severity': 'warning',
            'message': 'Server reboot required to finish installed updates',
            'link': '/updates',
            'key': 'reboot_required',
        })

    # Predictive disk-full warning based on the metrics growth trend
    try:
        days = predict_disk_full_days()
        if days is not None and days <= 14:
            alerts.append({
                'severity': 'error' if days <= 3 else 'warning',
                'message': f"Disk / is projected to be full in ~{max(days, 0):.0f} days at the current growth rate",
                'link': '/disk',
                'key': 'disk_forecast',
            })
    except Exception:
        logger.debug('Disk forecast failed', exc_info=True)

    # Sort: error first, then warning, then info
    alerts.sort(key=lambda a: _SEVERITY_ORDER.get(a['severity'], 99))

    return alerts


def _established_remote_peers():
    """Peer-IP's van alle established TCP-verbindingen, zonder loopback.

    Returns None als `ss` niet werkt. IPv4-mapped IPv6 (::ffff:1.2.3.4)
    wordt genormaliseerd naar het IPv4-adres.
    """
    result = run_cmd_safe(['ss', '-tn', 'state', 'established'], timeout=10)
    if result.returncode != 0:
        return None
    peers = []
    for line in result.stdout.splitlines():
        cols = line.split()
        # Met een state-filter laat ss de State-kolom weg:
        # Recv-Q Send-Q Local:Port Peer:Port
        if len(cols) < 4 or not cols[0].isdigit():
            continue  # header
        addr = cols[3].rsplit(':', 1)[0].strip('[]')
        addr = addr.split('%', 1)[0]  # zone-id (fe80::1%eth0)
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if getattr(ip, 'ipv4_mapped', None):
            ip = ip.ipv4_mapped
        if ip.is_loopback:
            continue
        peers.append(str(ip))
    return peers


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

    # Established connections, zonder loopback: nginx→PM2/PHP-FPM/redis
    # keepalives geven anders tientallen tot honderden verbindingen vanaf
    # 127.0.0.1 en daarmee een vals "Possible DDoS"-alarm.
    peers = _established_remote_peers()
    if peers is not None:
        total_conn = len(peers)
        if total_conn > conn_threshold:
            alerts.append({
                'severity': 'warning',
                'message': f"High connection count: {total_conn} established",
                'link': '/firewall',
                'key': 'high_connections',
            })

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
    if peers:
        ip_addr, ip_count = Counter(peers).most_common(1)[0]
        if ip_count > single_ip_threshold:
            alerts.append({
                'severity': 'error',
                'message': f"Possible DDoS: {ip_count} connections from {ip_addr}",
                'link': '/firewall',
                'key': f"ddos_single_ip_{ip_addr}",
            })

    return alerts


def get_ddos_stats():
    """Get current connection stats for the firewall DDoS card"""
    stats = {'total_connections': 0, 'syn_recv': 0, 'top_ips': []}

    # Zelfde telling als check_ddos_indicators (zonder loopback), zodat de
    # kaart en de alerts dezelfde cijfers tonen.
    peers = _established_remote_peers() or []
    stats['total_connections'] = len(peers)
    stats['top_ips'] = [{'count': c, 'ip': ip} for ip, c in Counter(peers).most_common(5)]

    result = run_cmd("ss -t state syn-recv 2>/dev/null | tail -n +2 | wc -l")
    if result.returncode == 0:
        try:
            stats['syn_recv'] = int(result.stdout.strip())
        except ValueError:
            pass

    ddos_cfg = CONFIG.get('ddos_detection', {})
    stats['conn_threshold'] = ddos_cfg.get('connection_threshold', 100)
    stats['syn_threshold'] = ddos_cfg.get('syn_threshold', 50)
    stats['ip_threshold'] = ddos_cfg.get('single_ip_threshold', 50)

    return stats


# ---------------------------------------------------------------------------
# Security audit
# ---------------------------------------------------------------------------

def _audit_check(key, label, status, details='', recommendation=''):
    """One security audit result. status: ok | warn | fail | info"""
    return {
        'key': key,
        'label': label,
        'status': status,
        'details': details,
        'recommendation': recommendation,
    }


# Poorten die publiek open horen te staan; al het andere is reden voor review.
_EXPECTED_PUBLIC_PORTS = {'22', '80', '443'}


@_ttl_cache(600, stale=3600)
def get_security_audit():
    """Run a set of hardening checks and return them with a score.

    Alle checks zijn read-only; de audit past zelf niets aan.
    """
    checks = []

    # --- SSH daemon hardening (effective config via sshd -T) ---
    sshd_cfg = {}
    result = run_cmd("sudo sshd -T 2>/dev/null", timeout=10)
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.split('\n'):
            parts = line.split(None, 1)
            if len(parts) == 2:
                sshd_cfg[parts[0].lower()] = parts[1].strip().lower()

    if sshd_cfg:
        v = sshd_cfg.get('permitrootlogin', 'unknown')
        if v in ('no', 'prohibit-password', 'without-password'):
            checks.append(_audit_check('ssh_root_login', 'SSH root login', 'ok',
                                       f'PermitRootLogin is {v}'))
        else:
            checks.append(_audit_check('ssh_root_login', 'SSH root login', 'fail',
                                       f'PermitRootLogin is {v}',
                                       'Set "PermitRootLogin no" (or prohibit-password) in /etc/ssh/sshd_config'))

        v = sshd_cfg.get('passwordauthentication', 'unknown')
        if v == 'no':
            checks.append(_audit_check('ssh_password_auth', 'SSH password authentication', 'ok',
                                       'Only key-based login is allowed'))
        else:
            checks.append(_audit_check('ssh_password_auth', 'SSH password authentication', 'warn',
                                       f'PasswordAuthentication is {v}',
                                       'Use SSH keys and set "PasswordAuthentication no" to stop brute-force attempts'))

        port = sshd_cfg.get('port', '22')
        checks.append(_audit_check('ssh_port', 'SSH port', 'info', f'sshd listens on port {port}'))
    else:
        checks.append(_audit_check('ssh_config', 'SSH configuration', 'info',
                                   'Could not read the effective sshd configuration (sudo sshd -T failed)'))

    # --- Firewall ---
    result = run_cmd("sudo ufw status 2>/dev/null", timeout=10)
    if result.returncode == 0 and 'Status: active' in result.stdout:
        checks.append(_audit_check('ufw', 'UFW firewall', 'ok', 'Firewall is active'))
    elif result.returncode == 0 and 'inactive' in result.stdout:
        checks.append(_audit_check('ufw', 'UFW firewall', 'fail', 'UFW is installed but inactive',
                                   'Enable it with "sudo ufw enable" (allow SSH first!)'))
    else:
        checks.append(_audit_check('ufw', 'UFW firewall', 'warn', 'UFW status could not be determined',
                                   'Install and enable UFW, or verify another firewall is active'))

    # --- fail2ban ---
    result = run_cmd_safe(['systemctl', 'is-active', 'fail2ban'], timeout=5)
    if result.stdout.strip() == 'active':
        checks.append(_audit_check('fail2ban', 'fail2ban intrusion prevention', 'ok', 'fail2ban is running'))
    else:
        checks.append(_audit_check('fail2ban', 'fail2ban intrusion prevention', 'warn',
                                   'fail2ban is not active',
                                   'Install/start fail2ban to automatically ban brute-force attackers'))

    # --- Automatic security updates ---
    result = run_cmd_safe(['apt-config', 'dump', 'APT::Periodic::Unattended-Upgrade'], timeout=5)
    if result.returncode == 0 and '"1"' in result.stdout:
        checks.append(_audit_check('unattended', 'Automatic security updates', 'ok',
                                   'unattended-upgrades is enabled'))
    else:
        checks.append(_audit_check('unattended', 'Automatic security updates', 'warn',
                                   'unattended-upgrades appears to be disabled',
                                   'Run "sudo dpkg-reconfigure unattended-upgrades" to enable automatic security patches'))

    # --- Pending security updates ---
    try:
        sec_updates = [u for u in get_system_updates() if u['category'] == 'security']
    except Exception:
        sec_updates = []
    if sec_updates:
        checks.append(_audit_check('security_updates', 'Pending security updates', 'warn',
                                   f'{len(sec_updates)} security update(s) waiting',
                                   'Install them from the Updates page'))
    else:
        checks.append(_audit_check('security_updates', 'Pending security updates', 'ok',
                                   'No security updates pending'))

    # --- Reboot required ---
    if os.path.exists('/var/run/reboot-required'):
        checks.append(_audit_check('reboot', 'Pending reboot', 'warn',
                                   'A reboot is required to activate installed updates (e.g. kernel)',
                                   'Reboot the server at a convenient moment'))
    else:
        checks.append(_audit_check('reboot', 'Pending reboot', 'ok', 'No reboot required'))

    # --- Dashboard 2FA ---
    auth_cfg = CONFIG.get('auth', {})
    if auth_cfg.get('tfa_method') or auth_cfg.get('totp_secret'):
        checks.append(_audit_check('tfa', 'Dashboard two-factor authentication', 'ok', '2FA is enabled'))
    else:
        checks.append(_audit_check('tfa', 'Dashboard two-factor authentication', 'warn',
                                   '2FA is not enabled for this dashboard',
                                   'Enable TOTP or email 2FA in Settings'))

    # --- SMTP certificate verification ---
    smtp_cfg = CONFIG.get('smtp', {})
    if smtp_cfg.get('host') and smtp_cfg.get('encryption', 'starttls') != 'none':
        if smtp_cfg.get('verify_tls', True):
            checks.append(_audit_check('smtp_tls', 'SMTP certificate verification', 'ok',
                                       'The mail server certificate is verified'))
        else:
            checks.append(_audit_check('smtp_tls', 'SMTP certificate verification', 'warn',
                                       'The mail server certificate is not verified, so the SMTP password '
                                       'and email 2FA codes could be intercepted',
                                       'Enable "Verify TLS certificate" in Settings → SMTP and send a test '
                                       'email (keep it off only for your own mail server with a '
                                       'self-signed certificate)'))

    # --- Backup freshness ---
    backup_status = _load_backup_status()
    last_success = backup_status.get('last_success')
    if isinstance(last_success, dict):
        try:
            last_dt = datetime.fromisoformat(last_success.get('timestamp', ''))
            age_h = (datetime.now() - last_dt).total_seconds() / 3600
            if age_h <= 48:
                checks.append(_audit_check('backup', 'Recent backup', 'ok',
                                           f'Last successful backup {age_h:.0f}h ago'))
            else:
                checks.append(_audit_check('backup', 'Recent backup', 'warn',
                                           f'Last successful backup was {age_h / 24:.0f} days ago',
                                           'Check the backup page and cron schedule'))
        except (ValueError, TypeError):
            checks.append(_audit_check('backup', 'Recent backup', 'info', 'Backup status could not be parsed'))
    else:
        checks.append(_audit_check('backup', 'Recent backup', 'info',
                                   'No backup reports received yet',
                                   'Configure the backup script and webhook secret'))

    # --- Publicly listening ports ---
    try:
        net = get_network_info()
        public_ports = {}
        for p in net.get('ports', []):
            local = p.get('local', '')
            addr = local.rsplit(':', 1)[0] if ':' in local else local
            if addr in ('0.0.0.0', '[::]', '*', '::'):
                public_ports.setdefault(p.get('port', '?'), p.get('process') or '?')
        # Een verplaatste SSH-poort (sshd -T) is verwacht, niet "onverwacht"
        expected = set(_EXPECTED_PUBLIC_PORTS) | {p for p in sshd_cfg.get('port', '').split() if p.isdigit()}
        unexpected = {port: proc for port, proc in public_ports.items()
                      if port not in expected}
        if unexpected:
            listing = ', '.join(f"{port} ({proc})" for port, proc in sorted(unexpected.items()))
            checks.append(_audit_check('public_ports', 'Publicly listening ports', 'warn',
                                       f'Unexpected public ports: {listing}',
                                       'Bind internal services to 127.0.0.1 or restrict them with UFW'))
        else:
            checks.append(_audit_check('public_ports', 'Publicly listening ports', 'ok',
                                       'Only standard ports (SSH/HTTP/HTTPS) are publicly reachable'))
    except Exception:
        logger.debug('Public port check failed', exc_info=True)
        checks.append(_audit_check('public_ports', 'Publicly listening ports', 'info',
                                   'Could not determine listening ports'))

    # Score: percentage of scored checks that pass (info doesn't count)
    scored = [c for c in checks if c['status'] in ('ok', 'warn', 'fail')]
    ok_count = len([c for c in scored if c['status'] == 'ok'])
    # 'warn' telt half mee: het is een aanbeveling, geen acuut gat
    warn_count = len([c for c in scored if c['status'] == 'warn'])
    score = round((ok_count + warn_count * 0.5) / len(scored) * 100) if scored else 0

    order = {'fail': 0, 'warn': 1, 'ok': 2, 'info': 3}
    checks.sort(key=lambda c: order.get(c['status'], 9))

    return {
        'checks': checks,
        'score': score,
        'summary': {
            'ok': ok_count,
            'warn': warn_count,
            'fail': len([c for c in scored if c['status'] == 'fail']),
            'info': len([c for c in checks if c['status'] == 'info']),
        },
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }


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


def _check_site_uptime(domain):
    """HTTPS met HTTP-fallback, HEAD met GET-fallback."""
    for scheme in ('https', 'http'):
        # Try HEAD first, fall back to GET on 405
        for method in ('HEAD', 'GET'):
            try:
                req = urllib.request.Request(f"{scheme}://{domain}", method=method)
                start = time.time()
                with urllib.request.urlopen(req, timeout=5) as resp:
                    elapsed = (time.time() - start) * 1000
                    return {
                        'domain': domain,
                        'status_code': resp.status,
                        'response_ms': round(elapsed),
                        'is_up': True,
                    }
            except urllib.error.HTTPError as e:
                if e.code == 405 and method == 'HEAD':
                    continue  # Try GET
                # Got an HTTP response (even if error), site is reachable
                return {
                    'domain': domain,
                    'status_code': e.code,
                    'response_ms': 0,
                    'is_up': e.code < 500,
                }
            except Exception:
                if method == 'HEAD':
                    continue  # Try GET before giving up on this scheme
                break  # Fall through to the next scheme
    return {'domain': domain, 'status_code': 0, 'response_ms': 0, 'is_up': False}


@_ttl_cache(60, stale=600)
def get_uptime_status():
    """Check HTTP status for all sites (HTTPS with HTTP fallback, HEAD with GET fallback)"""
    domains = []
    for site in get_sites():
        # Eerste echte hostnaam: wildcard/regex-servernames (*.x, .x, ~^...)
        # zijn niet op te vragen en telden anders elke cyclus als "down".
        domain = next((d for d in site.get('domains') or []
                       if d and not d.startswith(('*', '.', '~')) and _HOSTNAME_RE.match(d)), None)
        if domain and domain not in domains:
            domains.append(domain)
    if not domains:
        return []
    # Parallel: één onbereikbare site kost tot 4 × 5 s; serieel liep dat bij
    # een paar kapotte sites op tot minuten (en blokkeerde de monitor).
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(domains))) as ex:
        return list(ex.map(_check_site_uptime, domains))


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
            # Laatste 24 uur (timestamps zijn lokale ISO-strings: vergelijkbaar),
            # met een harde bovengrens voor het kortste monitor-interval
            cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
            history[domain] = [e for e in history[domain] if e.get('timestamp', '') >= cutoff][-2880:]

        # Verwijderde/uitgeschakelde sites opruimen: hun laatste "down"-checks
        # gaven anders een permanente "Site is down"-alert.
        current = {r['domain'] for r in results}
        if results:
            for domain in [d for d in history if d not in current]:
                del history[domain]

        _atomic_write_json(UPTIME_HISTORY_PATH, history)

    return results


@_ttl_cache(600, stale=21600)
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
            # is-active geeft exit != 0 voor inactive/failed; de tekst op stdout
            # is dan nog steeds de status. Alleen "unknown"/leeg = niet geïnstalleerd.
            fpm_status = fpm_result.stdout.strip() or 'not installed'
            if fpm_status == 'unknown':
                fpm_status = 'not installed'

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
            # Niet-uitgecommentarieerde regel (de default-site heeft vaak een
            # "# fastcgi_pass unix:..."-voorbeeld)
            socket_result = run_cmd_safe(["grep", "-oP", "-m1", r"^\s*fastcgi_pass\s+unix:\K[^;]+", real_path], timeout=5)
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


@_ttl_cache(300, stale=3600)
def get_all_domains():
    """Get all known domains from web server sites"""
    sites = get_sites()
    domains = []
    for site in sites:
        for d in site.get('domains', []):
            if d not in domains:
                domains.append(d)
    return domains


_PROTECTED_DIRS = tuple(sorted({
    os.path.realpath(APP_DIR),
    os.path.realpath(os.path.dirname(os.path.abspath(__file__))),
    os.path.realpath(DATA_DIR),
}))


def is_path_allowed(path):
    """Check if path is within allowed directories (whitelist approach).
    Uses realpath() to resolve symlinks and prevent symlink escapes.
    """
    allowed = CONFIG.get('file_browser', {}).get('allowed_paths', ['/var/www'])
    try:
        norm = os.path.realpath(path)
    except OSError:
        return False
    # De manager zelf staat vaak onder /var/www (README-installatie); zonder
    # deze uitzondering waren data/.secret_key, config.json (TOTP-secret,
    # SMTP-wachtwoord) en .env via de file browser te downloaden en app.py
    # te overschrijven.
    for protected in _PROTECTED_DIRS:
        if norm == protected or norm.startswith(protected + '/'):
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
# PWA: serve service worker + manifest from root so the SW can claim scope '/'.
# Flask's static handler doesn't set Service-Worker-Allowed, which caused
# Chrome to silently reject the registration and blocked PWA install on Android.
# ---------------------------------------------------------------------------

@app.route('/sw.js')
def service_worker():
    response = send_from_directory(app.static_folder, 'sw.js', mimetype='application/javascript')
    response.headers['Service-Worker-Allowed'] = '/'
    response.headers['Cache-Control'] = 'no-cache'
    return response


@app.route('/manifest.json')
def pwa_manifest():
    response = send_from_directory(app.static_folder, 'manifest.json', mimetype='application/manifest+json')
    response.headers['Cache-Control'] = 'no-cache'
    return response


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

_dashboard_pool = concurrent.futures.ThreadPoolExecutor(max_workers=6, thread_name_prefix='dashboard')


@app.route('/')
@login_required
def dashboard():
    # De collectors zijn onafhankelijk en vooral wachten op subprocessen:
    # parallel ophalen maakt een koude dashboard-load zo traag als de
    # traagste in plaats van de som.
    futures = {name: _dashboard_pool.submit(fn) for name, fn in (
        ('data', get_server_overview), ('services', get_services_status),
        ('pm2', get_pm2_processes), ('ssl', get_ssl_info),
        ('ddos', check_ddos_indicators), ('backup', check_backup_alerts),
    )}
    res = {name: f.result() for name, f in futures.items()}
    data, services, pm2, ssl = res['data'], res['services'], res['pm2'], res['ssl']
    alerts = get_dashboard_alerts(data, services, pm2, ssl)
    # Add DDoS and backup alerts
    alerts.extend(res['ddos'])
    alerts.extend(res['backup'])
    # Re-sort
    alerts.sort(key=lambda a: _SEVERITY_ORDER.get(a['severity'], 99))
    # Een weggeklikte alert blijft alleen weg zolang hij actief is: keys zijn
    # stabiel (service_down_nginx), dus anders verborg één dismiss elke
    # volgende storing van die service voorgoed — ook in de health score.
    active_keys = {a.get('key') for a in alerts}
    with _config_runtime_lock:
        dismissed = [k for k in CONFIG.get('dismissed_alerts', []) if k in active_keys]
        if dismissed != CONFIG.get('dismissed_alerts', []):
            CONFIG['dismissed_alerts'] = dismissed
            save_config(CONFIG)
    alerts = [a for a in alerts if a.get('key') not in dismissed]
    health = compute_health_score(alerts)
    return render_template('dashboard.html', data=data, services=services, pm2=pm2, ssl=ssl,
                           alerts=alerts, health=health, thresholds=CONFIG.get('thresholds', {}))


@app.route('/api/alerts/dismiss', methods=['POST'])
@login_required
def dismiss_alert():
    data = request.get_json(silent=True)
    key = data.get('key', '') if isinstance(data, dict) else ''
    if not key or not isinstance(key, str) or len(key) > 200:
        return jsonify({'status': 'error', 'message': 'No alert key'}), 400
    with _config_runtime_lock:
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
    data = _json_body()
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
        # Zonder --force-renewal: certbot vernieuwt dan alleen certificaten
        # die bijna verlopen. Alles geforceerd vernieuwen raakt snel de Let's
        # Encrypt duplicate-certificate rate limit.
        result = run_cmd_safe(
            ["sudo", "certbot", "renew"],
            timeout=300
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
        _set_manually_stopped(name, action == 'stop')
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
    # isascii: isdigit() accepteert ook '²', waarna int() een 500 gaf
    if not (pid.isascii() and pid.isdigit()):
        return jsonify({'status': 'error', 'message': 'Invalid PID'}), 400
    pid_int = int(pid)
    # Ook niet de parent (PM2-daemon): dan valt het dashboard zelf weg
    if pid_int <= 1 or pid_int in (os.getpid(), os.getppid()):
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

    is_file = os.path.isfile(real_path)
    is_dir = os.path.isdir(real_path)
    if not is_file and not is_dir:
        # os.path.isfile is False als de app de map niet mag lezen; laat sudo
        # het dan bepalen.
        probe = run_cmd_safe(['sudo', 'test', '-d', real_path], timeout=5)
        if probe.returncode == 0:
            is_dir = True
        elif run_cmd_safe(['sudo', 'test', '-f', real_path], timeout=5).returncode == 0:
            is_file = True
    if not is_file and not is_dir:
        return jsonify({'status': 'error', 'message': 'Not found'}), 404

    # Backups zijn (bewust) niet world-readable: vps-backup.sh zet site-
    # bestanden op 640. Draait de app niet als root, dan eerst zelf proberen
    # en anders via sudo naar een tijdelijk bestand van de app kopiëren/tarren.
    name = os.path.basename(real_path)
    tmp = tempfile.NamedTemporaryFile(suffix='.tar.gz' if is_dir else '.download', delete=False)
    tmp.close()

    @after_this_request
    def _cleanup(response):
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        return response

    if is_file:
        try:
            with open(real_path, 'rb'):
                pass
            os.unlink(tmp.name)
            return send_file(real_path, as_attachment=True)
        except PermissionError:
            # cp naar een bestaand doel behoudt de eigenaar (de app)
            result = run_cmd_safe(['sudo', 'cp', '--', real_path, tmp.name], timeout=600)
            if result.returncode != 0:
                return jsonify({'status': 'error', 'message': 'Could not read backup file'}), 500
            return send_file(tmp.name, as_attachment=True, download_name=name)

    import tarfile
    try:
        with tarfile.open(tmp.name, mode='w:gz') as tar:
            tar.add(real_path, arcname=name)
    except PermissionError:
        result = run_cmd_safe(['sudo', 'tar', '-czf', tmp.name, '-C', os.path.dirname(real_path), '--', name],
                              timeout=1800)
        if result.returncode != 0:
            return jsonify({'status': 'error', 'message': 'Could not archive backup directory'}), 500
    return send_file(tmp.name, as_attachment=True, download_name=f"{name}.tar.gz",
                     mimetype='application/gzip')


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
    lines = max(1, min(lines, 2000))
    filter_type = request.args.get('filter', 'all')

    # Alleen het staartstuk van auth.log doorzoeken (kan honderden MB's zijn)
    auth_tail = f"sudo tail -c {_AUTH_LOG_TAIL_BYTES} /var/log/auth.log 2>/dev/null"
    if filter_type == 'failed':
        cmd = f"{auth_tail} | grep -ai 'failed\\|invalid user\\|authentication failure' | tail -{lines}"
    elif filter_type == 'accepted':
        cmd = f"{auth_tail} | grep -ai 'accepted' | tail -{lines}"
    elif filter_type == 'fail2ban':
        cmd = f"{auth_tail} | grep -ai 'fail2ban' | tail -{lines}; sudo tail -{lines} /var/log/fail2ban.log 2>/dev/null"
    else:
        cmd = f"{auth_tail} | {_SSHD_GREP} -a | tail -{lines}"

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


@app.route('/security')
@login_required
def security_audit_page():
    data = get_security_audit()
    return render_template('security.html', data=data,
                           auto_heal=CONFIG.get('auto_heal', {}))


@app.route('/api/security/audit')
@login_required
def api_security_audit():
    if request.args.get('refresh'):
        _invalidate_cache('get_security_audit', 'get_system_updates', 'get_network_info')
    return jsonify(get_security_audit())


def _is_valid_ipv4(ip):
    """Validate an IPv4 address (without CIDR)"""
    return bool(re.match(
        r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$',
        ip
    ))


def _is_valid_ip(ip):
    """Validate an IPv4 or IPv6 address (without CIDR).

    fail2ban bant ook IPv6-adressen (bijv. via de sshd-jail), dus ban/unban
    vanuit de UI moet die ook accepteren — anders zijn IPv6-bans onbeheerbaar.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _is_valid_ip_or_cidr(value):
    """Validate an IPv4/IPv6 address or CIDR (e.g. 192.168.1.0/24, 2001:db8::/32).

    fail2ban's ignoreip en ufw ondersteunen beide IPv6, dus de whitelist
    en UFW-regels moeten dat ook accepteren.
    """
    try:
        if '/' in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@app.route('/firewall/ban', methods=['POST'])
@login_required
def firewall_ban():
    """Permanently ban an IP via fail2ban + UFW"""
    data = _json_body()
    ip = _json_str(data, 'ip', '')
    jail = _json_str(data, 'jail', 'sshd')

    if not ip or not _is_valid_ip(ip):
        return jsonify({'status': 'error', 'message': 'Invalid IP address'}), 400
    if not is_safe_name(jail):
        return jsonify({'status': 'error', 'message': 'Invalid jail name'}), 400

    # Ban in fail2ban
    result = run_cmd_safe(['sudo', 'fail2ban-client', 'set', jail, 'banip', ip], timeout=15)
    _invalidate_cache('get_banned_ips', 'get_firewall_security')
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
    data = _json_body()
    ip = _json_str(data, 'ip', '')
    jail = _json_str(data, 'jail', 'sshd')

    if not ip or not _is_valid_ip(ip):
        return jsonify({'status': 'error', 'message': 'Invalid IP address'}), 400
    if not is_safe_name(jail):
        return jsonify({'status': 'error', 'message': 'Invalid jail name'}), 400

    result = run_cmd_safe(['sudo', 'fail2ban-client', 'set', jail, 'unbanip', ip], timeout=15)
    _invalidate_cache('get_banned_ips', 'get_firewall_security')
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


JAIL_LOCAL_PATH = '/etc/fail2ban/jail.local'
_HOSTNAME_RE = re.compile(r'\A(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
                          r'(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z')
_IGNOREIP_RE = re.compile(r'^ignoreip\s*[=:]\s*(.*)$')


def _find_ignoreip_blocks(lines):
    """Alle `ignoreip`-regels (incl. ingesprongen vervolgregels) per sectie.

    Returns lijst van (section, start, end, values)."""
    blocks = []
    section = None
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            section = stripped[1:-1].strip()
        elif section and not line[:1].isspace():
            m = _IGNOREIP_RE.match(stripped)
            if m:
                values = m.group(1).split()
                end = i + 1
                while end < len(lines) and lines[end][:1].isspace() and lines[end].strip():
                    values.extend(lines[end].split())
                    end += 1
                blocks.append((section, i, end, [v for v in values if not v.startswith('#')]))
                i = end
                continue
        i += 1
    return blocks


def _find_default_ignoreip(lines):
    """De lijst die de UI toont: [DEFAULT], of anders de eerste jail
    (sshd bij voorkeur) die een eigen ignoreip heeft."""
    blocks = _find_ignoreip_blocks(lines)
    for wanted in ('DEFAULT', 'sshd'):
        for b in blocks:
            if b[0] == wanted:
                return b[1], b[2], b[3]
    return (blocks[0][1], blocks[0][2], blocks[0][3]) if blocks else None


def _read_jail_local():
    """Returns (text, error). Een ontbrekend bestand is geen fout."""
    result = run_cmd_safe(['sudo', 'cat', JAIL_LOCAL_PATH], timeout=10)
    if result.returncode == 0:
        return result.stdout, None
    if 'no such file' in (result.stderr or '').lower():
        return '', None
    return None, (result.stderr or '').strip() or 'Could not read jail.local'


@app.route('/firewall/whitelist', methods=['GET'])
@login_required
def firewall_whitelist_get():
    """Get the fail2ban ignoreip whitelist from jail.local"""
    text, err = _read_jail_local()
    if text is None:
        # Niet stil een lege lijst tonen: opslaan zou dan de bestaande
        # whitelist (incl. 127.0.0.1 en het eigen IP) vervangen.
        return jsonify({'status': 'error', 'message': f'Could not read jail.local: {err}'}), 500
    found = _find_default_ignoreip(text.split('\n'))
    return jsonify({'ips': found[2] if found else []})


@app.route('/firewall/whitelist', methods=['POST'])
@login_required
def firewall_whitelist_set():
    """Update the fail2ban ignoreip whitelist in jail.local"""
    data = request.get_json(silent=True) or {}
    ips = data.get('ips', [])

    if not isinstance(ips, list):
        return jsonify({'status': 'error', 'message': 'ips must be a list'}), 400

    validated = []
    for entry in ips:
        if not isinstance(entry, str):
            return jsonify({'status': 'error', 'message': 'Invalid IP/CIDR entry'}), 400
        entry = entry.strip()
        if not entry:
            continue
        # fail2ban accepteert ook hostnamen in ignoreip
        if entry == '::1' or _is_valid_ip_or_cidr(entry) or _HOSTNAME_RE.match(entry):
            validated.append(entry)
        else:
            return jsonify({'status': 'error', 'message': f'Invalid IP/CIDR: {entry}'}), 400

    ignoreip_line = 'ignoreip = ' + ' '.join(validated)

    # Bij een leesfout (sudo, timeout) afbreken: voorheen werd jail.local dan
    # vervangen door alleen [DEFAULT] + ignoreip, waarmee alle jails verdwenen.
    text, err = _read_jail_local()
    if text is None:
        return jsonify({'status': 'error', 'message': f'Could not read jail.local: {err}'}), 500

    lines = text.split('\n') if text else []
    # De UI beheert één lijst: vervang elke ignoreip-regel (DEFAULT én
    # jail-overrides, zoals v1.10 deed — anders overschrijft bijv. een
    # [sshd]-ignoreip de nieuwe lijst en lijkt opslaan te werken zonder
    # effect). Regels die naar DEFAULT verwijzen (%(...)s) blijven staan.
    blocks = [b for b in _find_ignoreip_blocks(lines) if '%(' not in ' '.join(b[3])]
    for section, start_i, end_i, _ in reversed(blocks):
        lines[start_i:end_i] = [ignoreip_line]
    if not blocks:
        idx = next((i for i, line in enumerate(lines) if line.strip() == '[DEFAULT]'), None)
        if idx is None:
            lines[0:0] = ['[DEFAULT]', ignoreip_line, '']
        else:
            lines.insert(idx + 1, ignoreip_line)
    content = '\n'.join(lines)
    if not content.endswith('\n'):
        content += '\n'

    # Via stdin i.p.v. `echo ... | sudo tee`: dash's echo interpreteert
    # backslashes (\b, \c, ...) en beschadigde daarmee regexes in jail.local.
    write_result = run_cmd_safe(['sudo', 'tee', JAIL_LOCAL_PATH], timeout=10, input=content)
    if write_result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Failed to write jail.local'}), 500

    # Reload fail2ban
    reload_result = run_cmd_safe(['sudo', 'fail2ban-client', 'reload'], timeout=30)
    _invalidate_cache('get_firewall_security')
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
    data = _json_body()
    port = _json_str(data, 'port', '')
    proto = _json_str(data, 'proto', 'tcp').lower()
    action = _json_str(data, 'action', 'allow').lower()
    from_ip = _json_str(data, 'from_ip', '')

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
    # int() accepteert ook '22_0' en ' 22'; geef ufw de genormaliseerde waarde
    port = str(port_num)

    # Build the command with comment + timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
    user_comment = _json_str(data, 'comment', '')
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
        _invalidate_cache('get_firewall_security')
        log_audit('ufw_add_rule', {'port': port, 'proto': proto, 'action': action, 'from': from_ip or 'anywhere'})
        return jsonify({'status': 'ok', 'message': f'UFW rule added: {action} {port}/{proto}'})
    return jsonify({'status': 'error', 'message': result.stderr.strip() or result.stdout.strip() or 'Failed to add rule'}), 500


@app.route('/firewall/ufw/delete', methods=['POST'])
@login_required
def firewall_ufw_delete():
    """Delete a UFW rule by number"""
    data = _json_body()
    rule_number = _json_str(data, 'rule_number', '')

    try:
        num = int(rule_number)
        if num < 1:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Invalid rule number'}), 400

    # Regelnummers verschuiven zodra fail2ban of een andere actie regels
    # toevoegt/verwijdert; controleer dat regel N nog de regel is die de
    # gebruiker zag, anders kan bijv. de SSH-allow-regel verdwijnen.
    expected = data.get('expected')
    if isinstance(expected, dict):
        current = run_cmd_safe(['sudo', 'ufw', 'status', 'numbered'], timeout=15)
        rule = next((r for r in parse_ufw_rules(current.stdout) if r['number'] == str(num)), None)
        fields = ('to', 'action', 'from_addr', 'v6')
        if rule is None or any(str(rule.get(f)) != str(expected.get(f)) for f in fields if f in expected):
            return jsonify({'status': 'error',
                            'message': 'The firewall rules changed since the list was loaded. '
                                       'The list has been refreshed, please try again.'}), 409

    result = run_cmd_safe(['sudo', 'ufw', '--force', 'delete', str(num)], timeout=15)
    if result.returncode == 0:
        _invalidate_cache('get_firewall_security')
        log_audit('ufw_delete_rule', {'rule_number': str(num)})
        return jsonify({'status': 'ok', 'message': f'UFW rule #{num} deleted'})
    return jsonify({'status': 'error', 'message': result.stderr.strip() or result.stdout.strip() or 'Failed to delete rule'}), 500


# IP→country cache: geo data is effectively static, so cache for a day to
# avoid re-querying the external API on every firewall/SSH-logs page load.
_ip_country_cache = {}
_ip_country_cache_lock = threading.Lock()
_IP_COUNTRY_TTL = 86400  # 24h


def _lookup_single_ip_country(ip):
    """Look up one IP via ipwho.is. Returns (ip, info_or_None)."""
    try:
        req = urllib.request.Request(
            f'https://ipwho.is/{ip}?fields=ip,country,country_code',
            headers={'User-Agent': 'VPS-Manager'},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        if data.get('country_code'):
            return ip, {
                'country': data.get('country', ''),
                'countryCode': data.get('country_code', ''),
            }
    except Exception:
        logger.debug('IP geo lookup failed for %s', ip, exc_info=True)
    return ip, None


def lookup_ip_countries(ip_list):
    """Batch lookup country info for a list of IPs via ipwho.is (HTTPS).

    Cached per IP (24h) and parallelised with a hard overall deadline so a
    busy attack day can't turn this into a multi-minute blocking call.
    """
    if not ip_list:
        return {}

    results = {}
    now = time.time()
    to_fetch = []
    with _ip_country_cache_lock:
        for ip in dict.fromkeys(ip_list):  # de-dupe, preserve order
            cached = _ip_country_cache.get(ip)
            if cached and now - cached[1] < _IP_COUNTRY_TTL:
                if cached[0]:
                    results[ip] = cached[0]
            else:
                to_fetch.append(ip)

    if not to_fetch:
        return results

    to_fetch = to_fetch[:100]  # hard cap on outbound lookups
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=10)
    try:
        futures = [ex.submit(_lookup_single_ip_country, ip) for ip in to_fetch]
        for fut in concurrent.futures.as_completed(futures, timeout=10):
            try:
                ip, info = fut.result()
            except Exception:
                continue
            with _ip_country_cache_lock:
                _ip_country_cache[ip] = (info, time.time())
            if info:
                results[ip] = info
    except concurrent.futures.TimeoutError:
        logger.debug('IP geo lookup deadline reached; returning partial results')
    finally:
        # Cancel nog niet gestarte taken zodat de deadline echt hard is en we
        # niet alsnog op trage urllib-calls wachten bij shutdown.
        ex.shutdown(wait=False, cancel_futures=True)

    return results


@app.route('/firewall/banned-ips')
@login_required
def firewall_banned_ips():
    """Get structured list of currently banned IPs per jail with timing info"""
    return jsonify(get_banned_ips())


# De firewall-pagina pollt dit; zonder cache kostte elke poll J+1
# fail2ban-client aanroepen, een kopie van de fail2ban-database en geo-lookups.
@_ttl_cache(30)
def get_banned_ips():
    import sqlite3

    jails_data = []

    # Get list of active jails
    result = run_cmd("sudo fail2ban-client status 2>/dev/null", timeout=15)
    if result.returncode != 0:
        return []

    jail_match = re.search(r'Jail list:\s*(.+)', result.stdout)
    if not jail_match:
        return []

    jail_names = [j.strip() for j in jail_match.group(1).split(',') if j.strip()]

    # Read ban timing info from fail2ban SQLite database
    ban_info = {}
    db_path = '/var/lib/fail2ban/fail2ban.sqlite3'
    tmp_name = None
    try:
        # Copy db to temp location (original is root-owned)
        tmp = tempfile.NamedTemporaryFile(suffix='.sqlite3', delete=False)
        tmp.close()
        tmp_name = tmp.name
        cp_result = run_cmd_safe(['sudo', 'cp', db_path, tmp_name], timeout=5)
        chmod_result = run_cmd_safe(['sudo', 'chmod', '644', tmp_name], timeout=5)
        if cp_result.returncode == 0 and chmod_result.returncode == 0:
            now = int(time.time())
            conn = sqlite3.connect(tmp_name)
            try:
                # Alleen nog actieve bans; de tabel bevat de volledige historie
                rows = conn.execute(
                    'SELECT jail, ip, timeofban, bantime, bancount FROM bans '
                    'WHERE bantime < 0 OR timeofban + bantime > ? ORDER BY timeofban DESC',
                    (now,)
                ).fetchall()
            finally:
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
    except Exception:
        logger.debug('Fail2ban parse failed', exc_info=True)
    finally:
        if tmp_name:
            # Root-owned kopie: unlink mag (eigen tmp-dir entry), maar vang fouten af
            try:
                os.unlink(tmp_name)
            except OSError:
                run_cmd_safe(['sudo', 'rm', '-f', tmp_name], timeout=5)

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

    return jails_data


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
        run_cmd("sudo apt-get update 2>&1", timeout=180)
        # Non-interactief: stdin is /dev/null, dus een conffile-vraag van dpkg
        # liet de upgrade anders mislukken. Bestaande configs blijven staan
        # (confold), nieuwe defaults worden overgenomen waar niets gewijzigd is.
        # Ruime timeout: een SIGTERM midden in dpkg laat "dpkg was interrupted"
        # achter.
        result = run_cmd(
            "sudo env DEBIAN_FRONTEND=noninteractive apt-get -y "
            "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "
            "upgrade 2>&1",
            timeout=1800)
        _invalidate_cache('get_system_updates', 'get_security_audit')
        # 2>&1: alle output staat in stdout (stderr was altijd leeg, waardoor
        # een fout zonder uitleg gemeld werd)
        output = result.stdout or result.stderr
        if result.returncode == 0:
            log_audit('system_updates_install', {'output': output[-200:]})
            _save_update_history('manual', 'success', output[-200:])
            return jsonify({'status': 'ok', 'message': 'Updates installed', 'output': output[-500:]})
        log_audit('system_updates_install_failed', {'error': output[-200:]})
        _save_update_history('manual', 'failure', output[-200:])
        return jsonify({'status': 'error', 'message': 'Installation error', 'output': output[-500:]}), 500
    finally:
        _apt_lock.release()


# ---------------------------------------------------------------------------
# VPS Manager self-update (GitHub releases)
# ---------------------------------------------------------------------------

@app.route('/api/update/check')
@login_required
def update_check():
    """Check GitHub for the latest release and compare with current version"""
    current = _get_current_version()
    try:
        data = _fetch_latest_release()
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Could not reach GitHub: {e}'}), 502

    latest = data.get('tag_name', '').lstrip('v')
    if not latest:
        return jsonify({'status': 'error', 'message': 'No releases found'}), 404

    return jsonify({
        'current_version': current,
        'latest_version': latest,
        'update_available': _is_newer_version(latest, current),
        'release_notes': data.get('body', ''),
        'published_at': data.get('published_at', ''),
    })


GITHUB_REPO_URL = 'https://github.com/martijnrenkema/vps-manager.git'


def _ensure_env_file():
    """Ensure .env file exists in APP_DIR with current runtime settings.
    Preserves custom port and credentials across updates."""
    env_path = os.path.join(APP_DIR, '.env')
    existing = {}
    if os.path.exists(env_path):
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        existing[key.strip()] = val.strip()
        except OSError:
            pass

    # Collect current env vars that should persist
    env_vars = {
        'VPS_MANAGER_PORT': os.environ.get('VPS_MANAGER_PORT', ''),
        'VPS_MANAGER_USER': os.environ.get('VPS_MANAGER_USER', ''),
        'VPS_MANAGER_PASS': os.environ.get('VPS_MANAGER_PASS', ''),
        'VPS_MANAGER_DIR': os.environ.get('VPS_MANAGER_DIR', ''),
        'VPS_MANAGER_SECRET': os.environ.get('VPS_MANAGER_SECRET', ''),
    }

    # Merge: keep existing values, only add new ones that are set
    changed = False
    for key, val in env_vars.items():
        if val and key not in existing:
            existing[key] = val
            changed = True

    if not existing:
        return  # Nothing to write

    if changed or not os.path.exists(env_path):
        try:
            lines = ['# VPS Manager environment (auto-generated, persists across updates)\n']
            lines += [f'{key}={val}\n' for key, val in sorted(existing.items()) if val]
            # Direct 0600 (bevat wachtwoord en secret key)
            _write_private_file(env_path, ''.join(lines))
        except OSError:
            pass


def _ensure_git_repo():
    """Ensure APP_DIR is a git repository. Initializes if needed.
    Returns (success, message)."""
    git_dir = os.path.join(APP_DIR, '.git')
    if os.path.isdir(git_dir):
        # Verify remote exists
        result = run_cmd(f"git -C {_Q_APP_DIR} remote get-url origin 2>/dev/null", timeout=5)
        if result.returncode == 0:
            return True, 'Git repo OK'
        # Remote missing, add it
        run_cmd(f"git -C {_Q_APP_DIR} remote add origin {GITHUB_REPO_URL} 2>/dev/null", timeout=5)
        return True, 'Added remote origin'

    # No .git directory - initialize
    init = run_cmd(f"git -C {_Q_APP_DIR} init", timeout=10)
    if init.returncode != 0:
        return False, f'git init failed: {init.stderr}'
    remote = run_cmd(f"git -C {_Q_APP_DIR} remote add origin {GITHUB_REPO_URL}", timeout=5)
    if remote.returncode != 0:
        return False, f'git remote add failed: {remote.stderr}'
    return True, 'Initialized git repo'


@app.route('/api/update/install', methods=['POST'])
@login_required
def update_install():
    """Pull latest code from GitHub and restart the PM2 process"""
    if not _apt_lock.acquire(blocking=False):
        # De SSE-updatestream start zijn worker direct; valt de stream daarna
        # weg, dan probeert de UI deze route als fallback. Meld dan dat de
        # update al loopt i.p.v. een kale fout.
        return jsonify({'status': 'error', 'running': True,
                        'message': 'An update is already running in the background'}), 409
    try:
        return _do_update_install()
    finally:
        _apt_lock.release()


def _copy_update_files():
    """Copy freshly pulled web/ files into the app root.

    Each step runs independently so a single missing/failed file doesn't
    silently skip the templates/static copies (which an &&-chain would).
    Returns (ok, output_string).
    """
    web_src = os.path.join(APP_DIR, 'web')
    if not os.path.isdir(web_src):
        return True, 'No web/ subfolder, skipped copy'

    failures = []
    outputs = []
    top_files = ['app.py', 'config.py', 'VERSION', 'requirements.txt',
                 'vps-backup.sh', 'nas-pull-backup.sh', 'update-watchdog.sh']
    for fname in top_files:
        src = os.path.join(web_src, fname)
        if not os.path.exists(src):
            continue
        r = run_cmd(f"cp {shlex.quote(src)} {shlex.quote(APP_DIR + '/')} 2>&1", timeout=15)
        if r.returncode != 0:
            failures.append(fname)
            outputs.append((r.stderr or r.stdout).strip())

    for subdir in ('templates', 'static'):
        src_dir = os.path.join(web_src, subdir)
        if not os.path.isdir(src_dir):
            continue
        r = run_cmd(
            f"cp -r {shlex.quote(src_dir)}/. {shlex.quote(os.path.join(APP_DIR, subdir))}/ 2>&1",
            timeout=15
        )
        if r.returncode != 0:
            failures.append(subdir + '/')
            outputs.append((r.stderr or r.stdout).strip())

    if failures:
        return False, 'Failed to copy: ' + ', '.join(failures) + '\n' + '\n'.join(outputs)
    return True, 'Files copied'


def _do_update_install():
    current_before = _get_current_version()

    # Preserve runtime settings before update
    _ensure_env_file()

    # Ensure git repo is initialized
    git_ok, git_msg = _ensure_git_repo()
    if not git_ok:
        return jsonify({'status': 'error', 'message': f'Git setup failed: {git_msg}'}), 500

    # Onthoud de huidige commit voor de rollback-watchdog
    prev_rev = run_cmd(f"git -C {_Q_APP_DIR} rev-parse HEAD", timeout=10)
    prev_commit = prev_rev.stdout.strip() if prev_rev.returncode == 0 else ''

    # Fetch and reset to origin/main
    result = run_cmd(
        f"git -C {_Q_APP_DIR} fetch origin main && git -C {_Q_APP_DIR} reset --hard origin/main",
        timeout=60
    )
    if result.returncode != 0:
        return jsonify({
            'status': 'error',
            'message': 'Git pull failed',
            'output': (result.stderr or result.stdout)[-500:],
        }), 500

    # Copy web/ files to app root (repo has files in web/ subfolder,
    # but PM2 runs from the repo root directory). Abort BEFORE restarting
    # if the copy failed — never restart on a half-applied update.
    copy_ok, copy_msg = _copy_update_files()
    if not copy_ok:
        rb_ok, _ = _rollback_update(prev_commit)
        return jsonify({
            'status': 'error',
            'message': 'Update aborted: file copy failed (not restarted, '
                       + ('previous version restored)' if rb_ok else 'ROLLBACK FAILED — check the server)'),
            'output': copy_msg[-500:],
        }), 500

    # Install dependencies (requirements may have changed)
    pip_result = run_cmd(
        f"cd {_Q_APP_DIR} && venv/bin/pip install -r requirements.txt --quiet 2>&1",
        timeout=120
    )
    if pip_result.returncode != 0:
        rb_ok, _ = _rollback_update(prev_commit)
        return jsonify({
            'status': 'error',
            'message': 'Update aborted: pip install failed (not restarted, '
                       + ('previous version restored)' if rb_ok else 'ROLLBACK FAILED — check the server)'),
            'output': (pip_result.stderr or pip_result.stdout)[-500:],
        }), 500

    # Read the new version from the freshly copied VERSION file
    new_version = _get_current_version()

    log_audit('self_update', {'from': current_before, 'to': new_version})
    _invalidate_cache('check_app_update_alert', 'get_pm2_processes')

    # Arm de rollback-watchdog en herstart via een delayed thread zodat dit
    # response kan flushen voordat PM2 dit proces killt en respawnt.
    _spawn_update_watchdog(prev_commit)
    threading.Thread(target=_delayed_restart, daemon=True).start()

    return jsonify({
        'status': 'ok',
        'message': 'Update installed, restarting',
        'previous_version': current_before,
        'new_version': new_version,
        'restart': 'pending',
        'copy': 'ok',
        'output': result.stdout[-500:],
    })


def _rollback_update(prev_commit):
    """Zet een half toegepaste update terug (git reset + bestanden kopiëren),
    zoals update-watchdog.sh doet. Zonder dit bleef na een mislukte copy of
    pip install de nieuwe code op schijf staan: het draaiende oude proces
    serveerde nieuwe templates/JS, en de volgende herstart laadde nieuwe code
    zonder dependencies en zonder rollback-watchdog."""
    if not prev_commit:
        return False, 'no previous commit known'
    reset = run_cmd(f"git -C {_Q_APP_DIR} reset --hard {shlex.quote(prev_commit)}", timeout=60)
    if reset.returncode != 0:
        return False, (reset.stderr or reset.stdout)[-300:]
    ok, msg = _copy_update_files()
    return ok, msg


def _delayed_restart(delay=1.5):
    """Restart PM2 process after a delay (so SSE response can flush)"""
    time.sleep(delay)
    run_cmd_safe(["pm2", "restart", "vps-manager"], timeout=15)


def _spawn_update_watchdog(prev_commit):
    """Start a detached watchdog that rolls back if the updated app
    never becomes healthy after the restart.

    setsid + achtergrond-& zorgt dat de watchdog in een eigen sessie draait
    en de PM2-restart van dit proces overleeft. Faalt de healthcheck, dan
    reset de watchdog naar prev_commit en herstart opnieuw — zo kan een
    kapotte release het dashboard nooit permanent onbereikbaar maken.
    """
    if not prev_commit:
        return False
    script = os.path.join(APP_DIR, 'web', 'update-watchdog.sh')
    if not os.path.isfile(script):
        script = os.path.join(APP_DIR, 'update-watchdog.sh')
    if not os.path.isfile(script):
        return False
    port = os.environ.get('VPS_MANAGER_PORT', '5050')
    log_path = str(DATA_DIR / 'update-watchdog.log')
    marker = str(DATA_DIR / '.update_rollback')
    args = ' '.join(shlex.quote(a) for a in
                    [script, APP_DIR, prev_commit, port, log_path, marker])
    # >/dev/null zodat de gespawnde watchdog onze pipes niet openhoudt
    result = run_cmd(f"setsid nohup bash {args} >/dev/null 2>&1 &", timeout=10)
    return result.returncode == 0


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

        # Preserve runtime settings before update
        _ensure_env_file()

        # Step 1: ensure git repo + fetch
        yield send_event({'step': 1, 'name': steps[0], 'status': 'running', 'output': ''})
        git_ok, git_msg = _ensure_git_repo()
        if not git_ok:
            yield send_event({'step': 1, 'name': steps[0], 'status': 'error', 'output': git_msg})
            for i in range(2, 6):
                yield send_event({'step': i, 'name': steps[i - 1], 'status': 'skipped', 'output': ''})
            yield send_event({'type': 'error', 'message': f'Git setup failed: {git_msg}'})
            return
        result = run_cmd(f"git -C {_Q_APP_DIR} fetch origin main", timeout=60)
        if result.returncode != 0:
            yield send_event({'step': 1, 'name': steps[0], 'status': 'error', 'output': (result.stderr or result.stdout)[-300:]})
            for i in range(2, 6):
                yield send_event({'step': i, 'name': steps[i - 1], 'status': 'skipped', 'output': ''})
            yield send_event({'type': 'error', 'message': 'Git fetch failed'})
            return
        yield send_event({'step': 1, 'name': steps[0], 'status': 'done', 'output': result.stdout[-200:]})

        # Onthoud de huidige commit zodat de watchdog kan terugrollen als de
        # nieuwe versie na de herstart niet gezond wordt.
        prev_rev = run_cmd(f"git -C {_Q_APP_DIR} rev-parse HEAD", timeout=10)
        prev_commit = prev_rev.stdout.strip() if prev_rev.returncode == 0 else ''

        # Step 2: reset + copy files
        yield send_event({'step': 2, 'name': steps[1], 'status': 'running', 'output': ''})
        reset = run_cmd(f"git -C {_Q_APP_DIR} reset --hard origin/main", timeout=30)
        if reset.returncode != 0:
            yield send_event({'step': 2, 'name': steps[1], 'status': 'error', 'output': (reset.stderr or reset.stdout)[-300:]})
            error_occurred = True
        else:
            copy_ok, copy_msg = _copy_update_files()
            if not copy_ok:
                error_occurred = True
                yield send_event({'step': 2, 'name': steps[1], 'status': 'error', 'output': copy_msg[-200:]})
            else:
                yield send_event({'step': 2, 'name': steps[1], 'status': 'done', 'output': copy_msg})

        # Abort before touching dependencies or restarting: a failed reset/copy
        # means a half-applied update, so we must not restart on top of it.
        if error_occurred:
            for i in range(3, 6):
                yield send_event({'step': i, 'name': steps[i - 1], 'status': 'skipped', 'output': ''})
            rb_ok, _ = _rollback_update(prev_commit)
            _save_update_history('self-update', 'error', 'Update aborted before restart'
                                 + ('; previous version restored' if rb_ok else '; rollback failed'))
            yield send_event({'type': 'error', 'message': 'Update aborted: install step failed (not restarted)'})
            return

        # Step 3: pip install (check if requirements changed)
        yield send_event({'step': 3, 'name': steps[2], 'status': 'running', 'output': ''})
        pip_result = run_cmd(
            f"cd {_Q_APP_DIR} && venv/bin/pip install -r requirements.txt --quiet 2>&1",
            timeout=120
        )
        if pip_result.returncode != 0:
            yield send_event({'step': 3, 'name': steps[2], 'status': 'error', 'output': (pip_result.stderr or pip_result.stdout)[-200:]})
            for i in range(4, 6):
                yield send_event({'step': i, 'name': steps[i - 1], 'status': 'skipped', 'output': ''})
            rb_ok, _ = _rollback_update(prev_commit)
            _save_update_history('self-update', 'error', 'pip install failed before restart'
                                 + ('; previous version restored' if rb_ok else '; rollback failed'))
            yield send_event({'type': 'error', 'message': 'Update aborted: pip install failed (not restarted). New code may need its dependencies.'})
            return
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
        log_audit('self_update', {'from': current_before, 'to': new_version}, user=actor, ip=actor_ip)
        _save_update_history('self-update', 'success' if not error_occurred else 'warning',
                             f'v{current_before} → v{new_version}')
        watchdog_armed = _spawn_update_watchdog(prev_commit)
        restart_msg = 'Restarting... (auto-rollback armed)' if watchdog_armed else 'Restarting...'
        yield send_event({'step': 5, 'name': steps[4], 'status': 'done', 'output': restart_msg})

        # Send complete event before restart
        yield send_event({'type': 'complete', 'previous_version': current_before, 'new_version': new_version})

        # Schedule delayed restart so the SSE response can flush
        t = threading.Thread(target=_delayed_restart, daemon=True)
        t.start()

    # De update draait in een eigen thread; de SSE-stream leest alleen de
    # voortgang uit een queue. Liep hij in de response-generator, dan brak
    # een gesloten tab (ClientDisconnected bij de volgende yield) de update
    # halverwege af: bestanden al gereset, maar geen herstart en geen
    # rollback-watchdog.
    if not _apt_lock.acquire(blocking=False):
        def busy():
            yield f"data: {json.dumps({'type': 'error', 'message': 'Another update operation is already running'})}\n\n"
        return Response(busy(), mimetype='text/event-stream')

    events = queue.Queue()
    # De worker draait buiten de request-context; zonder dit logde de audit
    # trail de update als gebruiker "system".
    actor, actor_ip = session.get('username', 'admin'), request.remote_addr

    def worker():
        try:
            for ev in generate():
                events.put(ev)
        except Exception:
            logger.exception('Self-update failed')
            events.put(f"data: {json.dumps({'type': 'error', 'message': 'Update failed unexpectedly, see server log'})}\n\n")
        finally:
            _apt_lock.release()
            events.put(None)

    threading.Thread(target=worker, daemon=True, name='self-update').start()

    def generate_with_lock():
        while True:
            try:
                ev = events.get(timeout=15)
            except queue.Empty:
                # SSE-comment als keepalive, zodat proxies de stream niet sluiten
                # tijdens een lange pip install
                yield ": keepalive\n\n"
                continue
            if ev is None:
                return
            yield ev

    # NB: geen 'Connection: keep-alive' header — dat is een hop-by-hop
    # header die WSGI-apps niet mogen zetten (PEP 3333). Waitress handhaaft
    # dat met een AssertionError, waardoor deze stream sinds de overstap
    # naar waitress altijd direct crashte (HTTP 500, geen enkel event) en
    # de in-app updater "niets deed".
    return Response(
        generate_with_lock(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
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
    lines = max(1, min(lines, 500))

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
    data = _json_body()
    cmd = _json_str(data, 'command', '')
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
    # Block subshell escapes: backticks, $(...), process substitution <(...)
    if '`' in cmd or '$(' in cmd or '<(' in cmd:
        log_audit('terminal_blocked', {'command': cmd[:200], 'reason': 'subshell escape'})
        return jsonify({'stdout': '', 'stderr': 'Blocked: subshell expressions not allowed', 'cwd': real_cwd})

    # Block newlines: alleen het eerste segment zou anders gecheckt worden
    if '\n' in cmd or '\r' in cmd:
        log_audit('terminal_blocked', {'command': cmd[:200], 'reason': 'newline'})
        return jsonify({'stdout': '', 'stderr': 'Blocked: multi-line commands not allowed', 'cwd': real_cwd})

    # Block all output redirection (>, >>) to prevent arbitrary file writes
    if '>' in cmd:
        log_audit('terminal_blocked', {'command': cmd[:200], 'reason': 'output redirection'})
        return jsonify({'stdout': '', 'stderr': 'Blocked: output redirection not allowed. Use the File Editor to write files.', 'cwd': real_cwd})

    # Split on all shell operators: |, ||, &, &&, ;
    pipe_segments = re.split(r'\|{1,2}|&{1,2}|;', cmd)
    for segment in pipe_segments:
        segment = segment.strip()
        if not segment:
            continue
        # Strip leading 'sudo' to check the actual command
        check = segment
        uses_sudo = check.startswith('sudo ') or check == 'sudo'
        if uses_sudo:
            check = check[5:].strip()
            # Geen sudo-flags (-u, -i, -s, ...): direct na sudo moet het
            # commando zelf staan, anders is de allowlist-check omzeilbaar
            if check.startswith('-'):
                log_audit('terminal_blocked', {'command': cmd[:200], 'reason': 'sudo flags'})
                return jsonify({'stdout': '', 'stderr': 'Blocked: sudo flags not allowed', 'cwd': real_cwd})
        try:
            tokens = shlex.split(check)
        except ValueError:
            tokens = check.split()
        if not tokens:
            continue
        base_cmd = os.path.basename(tokens[0])
        # Alleen kale commandonamen: met een pad zou /var/www/x/ls (een
        # geüpload binary met een toegestane naam) de allowlist passeren.
        if '/' in tokens[0]:
            log_audit('terminal_blocked', {'command': cmd[:200], 'reason': 'path in command name'})
            return jsonify({'stdout': '', 'stderr': 'Blocked: use the command name without a path', 'cwd': real_cwd})
        if base_cmd not in TERMINAL_ALLOWED_COMMANDS:
            log_audit('terminal_blocked', {'command': cmd[:200], 'reason': f'not in allowlist: {base_cmd}'})
            return jsonify({'stdout': '', 'stderr': f'Blocked: command not allowed: {base_cmd}', 'cwd': real_cwd})
        if uses_sudo and not _terminal_sudo_allowed(tokens):
            log_audit('terminal_blocked', {'command': cmd[:200], 'reason': f'sudo not allowed for: {base_cmd}'})
            return jsonify({'stdout': '', 'stderr': f'Blocked: sudo is only allowed for read-only commands '
                                                     f'(e.g. sudo cat, sudo systemctl status). Use the {base_cmd} page instead.',
                            'cwd': real_cwd})

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
    wrapped = f'cd {shlex.quote(real_cwd)} 2>/dev/null && {{ {cmd} ; }} 2>&1; echo "---CWD---"; pwd'
    result = run_cmd(wrapped, timeout=30, max_output=1024 * 1024)

    new_cwd = cwd
    if isinstance(result, _CmdFailed):
        # Timeout: toon wat er al was plus een duidelijke melding i.p.v. niets
        return jsonify({
            'stdout': getattr(result, 'partial_stdout', '').rstrip('\n'),
            'stderr': 'Command timed out after 30 seconds (use the dedicated pages for long-running tasks)',
            'cwd': new_cwd,
        })
    output = result.stdout
    if result.stderr and 'output truncated' in result.stderr:
        output += '\n[output truncated at 1 MB]'

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
    # realpath (niet abspath): check en daadwerkelijke toegang moeten op
    # hetzelfde geresolvede pad gebeuren, anders kan een symlink-wissel
    # tussen check en gebruik buiten de toegestane mappen komen.
    norm_path = os.path.realpath(path)

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
    data = _json_body()
    path = _json_str(data, 'path', '')
    name = _json_str(data, 'name', '')

    if not name or '/' in name or name.startswith('.'):
        return jsonify({'status': 'error', 'message': 'Invalid folder name'}), 400

    norm_path = os.path.realpath(os.path.join(path, name))
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
    norm_path = os.path.realpath(path)

    if not is_path_allowed(norm_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    if os.path.isfile(norm_path):
        if not os.access(norm_path, os.R_OK):
            return jsonify({'status': 'error', 'message': 'File is not readable by the app'}), 403
        return send_file(norm_path, as_attachment=True)

    if os.path.isdir(norm_path):
        import tarfile
        import tempfile
        dirname = os.path.basename(norm_path)
        tmp = tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False)
        try:
            try:
                with tarfile.open(fileobj=tmp, mode='w:gz') as tar:
                    tar.add(norm_path, arcname=dirname)
            except OSError as e:
                tmp.close()
                return jsonify({'status': 'error',
                                'message': f'Cannot archive this folder: {e.strerror or e}'}), 403
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
    norm_path = os.path.realpath(path)

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
    # Volg geen symlink op de doelnaam: een (bijv. door een gecompromitteerde
    # site geplaatste) symlink zou de upload buiten de toegestane paden laten
    # schrijven.
    if os.path.islink(dest):
        return jsonify({'status': 'error', 'message': 'Refusing to overwrite a symlink'}), 403

    try:
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'wb') as out:
            file.save(out)
        log_audit('file_upload', {'path': dest})
        return jsonify({'status': 'ok', 'message': f"'{filename}' uploaded"})
    except OSError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/files/delete', methods=['POST'])
@login_required
def files_delete():
    data = _json_body()
    path = _json_str(data, 'path', '')
    norm_path = os.path.abspath(path)

    # Symlinks: verwijder de link zelf (nooit het doel), mits de link
    # zelf in een toegestane map staat. realpath zou hier juist het doel
    # verwijderen en rmtree weigert symlinks.
    if os.path.islink(norm_path):
        if not is_path_allowed(os.path.dirname(norm_path)):
            return jsonify({'status': 'error', 'message': 'Access denied'}), 403
        try:
            os.remove(norm_path)
            log_audit('file_delete', {'path': norm_path, 'type': 'symlink'})
            return jsonify({'status': 'ok', 'message': 'Symlink deleted'})
        except OSError as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    norm_path = os.path.realpath(path)
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
    data = _json_body()
    path = _json_str(data, 'path', '')
    owner = _json_str(data, 'owner', 'www-data')
    group = _json_str(data, 'group', '')
    recursive = data.get('recursive', False)

    norm_path = os.path.realpath(path)
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
    data = _json_body()
    path = _json_str(data, 'path', '')
    mode = _json_str(data, 'mode', '')
    recursive = data.get('recursive', False)

    norm_path = os.path.realpath(path)
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
    """Get list of system users and groups relevant for web files.

    Dynamisch i.p.v. hardcoded namen: root, de web-user en alle reguliere
    accounts (uid/gid 1000-65533) plus nobody/nogroup.
    """
    users = set()
    groups = set()
    try:
        for p in pwd.getpwall():
            if p.pw_uid == 0 or p.pw_name in ('www-data', 'nobody') or 1000 <= p.pw_uid < 65534:
                users.add(p.pw_name)
        for g in grp.getgrall():
            if g.gr_gid == 0 or g.gr_name in ('www-data', 'nogroup') or 1000 <= g.gr_gid < 65534:
                groups.add(g.gr_name)
    except OSError:
        users.update(['www-data', 'root'])
        groups.update(['www-data', 'root'])
    return jsonify({'users': sorted(users), 'groups': sorted(groups)})


# ---------------------------------------------------------------------------
# Push Notification routes
# ---------------------------------------------------------------------------

@app.route('/notifications')
@login_required
def notifications():
    smtp_configured = bool(CONFIG.get('smtp', {}).get('host', ''))
    return render_template('notifications.html', smtp_configured=smtp_configured)


@app.route('/api/push/vapid-key')
@login_required
def vapid_key():
    public_key, _ = _get_vapid_keys()
    return jsonify({'public_key': public_key})


@app.route('/api/push/subscribe', methods=['POST'])
@login_required
def push_subscribe():
    data = _json_body()
    if 'endpoint' not in data or 'keys' not in data:
        return jsonify({'status': 'error', 'message': 'Invalid subscription data'}), 400

    with _notif_lock:
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
                'app_update': True,
            },
            'created': datetime.now().isoformat(),
        })
        _save_subscriptions(subs)
    return jsonify({'status': 'ok', 'message': 'Subscription registered'})


@app.route('/api/push/unsubscribe', methods=['POST'])
@login_required
def push_unsubscribe():
    data = _json_body()
    endpoint = data.get('endpoint')
    if not endpoint:
        return jsonify({'status': 'error', 'message': 'Missing endpoint'}), 400

    with _notif_lock:
        subs = _load_subscriptions()
        subs = [s for s in subs if s.get('endpoint') != endpoint]
        _save_subscriptions(subs)
    return jsonify({'status': 'ok', 'message': 'Unsubscribed'})


@app.route('/api/push/test', methods=['POST'])
@login_required
def push_test():
    data = _json_body()
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
        with _notif_lock:
            subs = [s for s in _load_subscriptions() if s.get('endpoint') != endpoint]
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
            return jsonify({'critical': True, 'warnings': True, 'updates': False, 'security': True, 'ddos': True, 'backup': True, 'app_update': True})

        return jsonify(sub.get('preferences', {
            'critical': True, 'warnings': True, 'updates': False, 'security': True, 'ddos': True, 'backup': True, 'app_update': True,
        }))

    # POST
    data = _json_body()
    endpoint = data.get('endpoint')
    if not endpoint:
        return jsonify({'status': 'error', 'message': 'Missing endpoint'}), 400

    with _notif_lock:
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
    data = _json_body()
    endpoint = data.get('endpoint')
    label = data.get('label', '')
    if not endpoint:
        return jsonify({'status': 'error', 'message': 'Missing endpoint'}), 400

    with _notif_lock:
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
    data = _json_body()
    endpoint = data.get('endpoint')
    if not endpoint:
        return jsonify({'status': 'error', 'message': 'Missing endpoint'}), 400

    with _notif_lock:
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
    data = _json_body()
    endpoint = data.get('endpoint')
    if not endpoint:
        return jsonify({'status': 'error', 'message': 'Missing endpoint'}), 400

    with _notif_lock:
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


@app.route('/api/notifications/unread-count')
@login_required
def notification_unread_count():
    """Goedkoop alternatief voor de volledige history bij elke page load."""
    history = _load_notification_history()
    return jsonify({'unread': sum(1 for h in history if not h.get('read'))})


@app.route('/api/notifications/read', methods=['POST'])
@login_required
def notification_read():
    with _notif_lock:
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
    with _notif_lock:
        _save_notification_history([])
        _save_notification_log({})
    return jsonify({'status': 'ok', 'message': 'Notifications cleared'})


@app.route('/api/notifications/dismiss', methods=['POST'])
@login_required
def notification_dismiss():
    """Dismiss (remove) a single notification by id (or legacy index).

    Op id, niet op positie: de monitor voegt tussendoor entries toe en na
    elke dismiss verschuiven de posities, waardoor een index-dismiss de
    verkeerde notificatie kon verwijderen.
    """
    data = _json_body()
    notif_id = data.get('id')
    if notif_id is not None:
        with _notif_lock:
            history = _load_notification_history()
            remaining = [h for h in history if h.get('id') != str(notif_id)]
            if len(remaining) == len(history):
                return jsonify({'status': 'error', 'message': 'Notification not found'}), 404
            _save_notification_history(remaining)
        return jsonify({'status': 'ok', 'message': 'Notification dismissed'})

    index = data.get('index')
    if index is None:
        return jsonify({'status': 'error', 'message': 'Missing id'}), 400

    try:
        index = int(index)
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Invalid index'}), 400

    with _notif_lock:
        history = _load_notification_history()
        # History is stored oldest-first; the API returns newest-first,
        # so the front-end index maps to reversed order.
        reversed_idx = len(history) - 1 - index
        if 0 <= reversed_idx < len(history):
            history.pop(reversed_idx)
            _save_notification_history(history)
            return jsonify({'status': 'ok', 'message': 'Notification dismissed'})
    return jsonify({'status': 'error', 'message': 'Invalid index'}), 400


@app.route('/api/notifications/email-preferences', methods=['GET', 'POST'])
@login_required
def email_notification_preferences():
    """Get or save email notification preferences (global, not per-device)."""
    if request.method == 'GET':
        prefs = CONFIG.get('email_notifications', {})
        smtp_configured = bool(CONFIG.get('smtp', {}).get('host', ''))
        return jsonify({
            'preferences': prefs,
            'smtp_configured': smtp_configured,
            'notification_email': _get_notification_email(),
        })

    data = _json_body()
    categories = ['critical', 'warnings', 'updates', 'security', 'ddos', 'backup', 'app_update']
    prefs = {}
    for cat in categories:
        prefs[cat] = bool(data.get(cat, False))

    with _config_runtime_lock:
        CONFIG['email_notifications'] = prefs
        if 'notification_email' in data:
            CONFIG['notification_email'] = str(data['notification_email']).strip()
        save_config(CONFIG)
    log_audit('email_notification_prefs_saved')
    return jsonify({'status': 'ok', 'message': 'Email notification preferences saved'})


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


# Top-level keys die via /api/config gezet mogen worden. SMTP, wachtwoord en
# 2FA hebben eigen endpoints; een onbekende key (of een string waar een object
# hoort, bijv. {"smtp": "x"}) zou anders elke CONFIG.get(key, {}).get(...)
# laten crashen.
_CONFIG_EDITABLE_KEYS = {
    'web_server', 'thresholds', 'monitor_interval', 'notification_cooldown',
    'updates_notification_time', 'auth', 'ddos_detection', 'services',
    'phpmyadmin_path', 'file_browser', 'backup', 'nginx', 'caddy',
    'vapid_mailto', 'auto_heal',
}


# Systeemmappen die (inclusief alles eronder) nooit als backup- of browse-map
# ingesteld mogen worden; /api/backup/download en de file browser serveren
# alles onder zo'n map.
_FORBIDDEN_DIR_PREFIXES = ('/etc', '/root', '/proc', '/sys', '/dev', '/boot', '/run',
                           '/usr', '/bin', '/sbin', '/lib', '/lib64', '/var/lib')


def _is_forbidden_dir(p, prefixes=_FORBIDDEN_DIR_PREFIXES):
    try:
        resolved = os.path.realpath(p)
    except OSError:
        resolved = os.path.normpath(p)
    if resolved.rstrip('/') in FORBIDDEN_ALLOWED_PATHS or resolved == '/' or len(resolved) < 4:
        return True
    for root in tuple(prefixes) + _PROTECTED_DIRS:
        if resolved == root or resolved.startswith(root + '/'):
            return True
    return False


def _is_number(v):
    """int/float, geen bool, geen NaN/inf (Flask's JSON-parser accepteert NaN)."""
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _under(path, root):
    """Genormaliseerd pad onder root? (/etc/nginx/../../var/www faalt)."""
    norm = os.path.normpath(path)
    return norm == root.rstrip('/') or norm.startswith(root.rstrip('/') + '/')


def validate_config(data):
    """Validate config values. Returns (is_valid, errors)"""
    errors = []
    if not isinstance(data, dict):
        return False, ['Config must be an object']

    for key in data:
        if key not in _CONFIG_EDITABLE_KEYS:
            errors.append(f'Unknown or read-only setting: {key}')
        elif isinstance(CONFIG.get(key), dict) and not isinstance(data[key], dict):
            errors.append(f'{key} must be an object')
    if errors:
        return False, errors

    if 'thresholds' in data:
        if not isinstance(data['thresholds'], dict):
            errors.append('thresholds must be an object')
        else:
            t = data['thresholds']
            for key in ('disk_warning', 'disk_critical', 'memory_warning', 'swap_warning'):
                if key in t:
                    if not _is_number(t[key]) or t[key] < 1 or t[key] > 100:
                        errors.append(f'{key} must be between 1-100')
            for key in ('ssl_warning_days', 'ssl_critical_days'):
                if key in t:
                    if not _is_number(t[key]) or t[key] < 1 or t[key] > 365:
                        errors.append(f'{key} must be between 1-365')
            merged = {**CONFIG.get('thresholds', {}), **t}
            try:
                if merged['disk_warning'] >= merged['disk_critical']:
                    errors.append('disk_warning must be lower than disk_critical')
                if merged['ssl_critical_days'] >= merged['ssl_warning_days']:
                    errors.append('ssl_critical_days must be lower than ssl_warning_days')
            except (KeyError, TypeError):
                pass

    # Bovengrens: een enorme waarde liet time.sleep() een OverflowError geven
    # buiten de try, waarmee de monitor-thread voorgoed stopte.
    if 'monitor_interval' in data:
        v = data['monitor_interval']
        if not isinstance(v, int) or isinstance(v, bool) or not (30 <= v <= 86400):
            errors.append('monitor_interval must be between 30 and 86400 seconds')

    if 'notification_cooldown' in data:
        v = data['notification_cooldown']
        if not isinstance(v, int) or isinstance(v, bool) or not (60 <= v <= 7 * 86400):
            errors.append('notification_cooldown must be between 60 seconds and 7 days')

    if 'updates_notification_time' in data:
        v = data['updates_notification_time']
        if not isinstance(v, str) or not re.match(r'\A([01]\d|2[0-3]):[0-5]\d\Z', v):
            errors.append('updates_notification_time must be in HH:MM format (24h)')

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
                        if resolved in FORBIDDEN_ALLOWED_PATHS or _is_forbidden_dir(
                                p, ('/root', '/proc', '/sys', '/dev', '/boot', '/run')):
                            errors.append(f'Forbidden allowed path (too broad or sensitive): {p}')

    if 'ddos_detection' in data:
        if not isinstance(data['ddos_detection'], dict):
            errors.append('ddos_detection must be an object')
        else:
            dd = data['ddos_detection']
            for key in ('connection_threshold', 'syn_threshold', 'single_ip_threshold'):
                if key in dd and (not isinstance(dd[key], int) or isinstance(dd[key], bool) or dd[key] < 1):
                    errors.append(f'{key} must be a positive integer')
            if 'enabled' in dd and not isinstance(dd['enabled'], bool):
                errors.append('ddos_detection.enabled must be a boolean')

    if 'auto_heal' in data:
        if not isinstance(data['auto_heal'], dict):
            errors.append('auto_heal must be an object')
        else:
            ah = data['auto_heal']
            if 'enabled' in ah and not isinstance(ah['enabled'], bool):
                errors.append('auto_heal.enabled must be a boolean')
            if 'max_restarts_per_day' in ah:
                v = ah['max_restarts_per_day']
                if not isinstance(v, int) or not (1 <= v <= 20):
                    errors.append('auto_heal.max_restarts_per_day must be between 1-20')

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
                    elif key != 'log_path' and _is_forbidden_dir(v):
                        # /api/backup/download serveert alles onder backup_dir
                        errors.append(f'backup.{key} is too broad: {v}')
            if 'webhook_secret' in data['backup'] and not isinstance(data['backup']['webhook_secret'], str):
                errors.append('backup.webhook_secret must be a string')

    if 'phpmyadmin_path' in data and not isinstance(data['phpmyadmin_path'], str):
        errors.append('phpmyadmin_path must be a string')

    if isinstance(data.get('file_browser'), dict) and 'default_path' in data['file_browser']:
        v = data['file_browser']['default_path']
        if not isinstance(v, str) or not v.startswith('/'):
            errors.append('file_browser.default_path must be an absolute path')

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
                    elif not _under(v, '/var/log/nginx/'):
                        errors.append(f'nginx.{key} must be under /var/log/nginx/')
            if 'sites_enabled' in data['nginx']:
                v = data['nginx']['sites_enabled']
                if not isinstance(v, str) or not v.startswith('/'):
                    errors.append('nginx.sites_enabled must be an absolute path')
                elif not _under(v, '/etc/nginx/'):
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
                    elif not _under(v, '/etc/caddy/'):
                        errors.append(f'caddy.{key} must be under /etc/caddy/')
            for key in ('access_log', 'error_log'):
                if key in data['caddy']:
                    v = data['caddy'][key]
                    if not isinstance(v, str) or not v.startswith('/'):
                        errors.append(f'caddy.{key} must be an absolute path')
                    elif not _under(v, '/var/log/caddy/'):
                        errors.append(f'caddy.{key} must be under /var/log/caddy/')
            if 'data_dir' in data['caddy']:
                v = data['caddy']['data_dir']
                if not isinstance(v, str) or not v.startswith('/'):
                    errors.append('caddy.data_dir must be an absolute path')
                elif not _under(v, '/var/lib/caddy/'):
                    errors.append('caddy.data_dir must be under /var/lib/caddy/')

    return (len(errors) == 0, errors)


@app.route('/api/config', methods=['POST'])
@login_required
def update_config():
    # CONFIG wordt alleen in-place gemuteerd, dus geen global nodig
    global MONITOR_INTERVAL
    data = _json_body()
    if not data:
        return jsonify({'status': 'error', 'message': 'No data received'}), 400

    # Validate config
    is_valid, errors = validate_config(data)
    if not is_valid:
        return jsonify({'status': 'error', 'message': 'Validation failed', 'errors': errors}), 400

    # Het webhook-secret wordt niet meer naar de browser gestuurd; een leeg
    # veld betekent "ongewijzigd laten".
    if isinstance(data.get('backup'), dict) and data['backup'].get('webhook_secret') == '':
        data['backup'].pop('webhook_secret')

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
    data = _json_body()
    current = data.get('current_password', '')
    new_pass = data.get('new_password', '')
    confirm = data.get('confirm_password', '')

    if not check_password_hash(PASSWORD_HASH, current):
        return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 400
    if len(new_pass) < 8:
        return jsonify({'status': 'error', 'message': 'New password must be at least 8 characters'}), 400
    if new_pass != confirm:
        return jsonify({'status': 'error', 'message': 'Passwords do not match'}), 400

    with _config_runtime_lock:
        PASSWORD_HASH = generate_password_hash(new_pass)
        CONFIG['auth']['password_hash'] = PASSWORD_HASH
        save_config(CONFIG)

    # Remove generated password file if it exists
    _pw_file = DATA_DIR / '.generated_password'
    try:
        _pw_file.unlink(missing_ok=True)
    except OSError:
        pass

    _bump_session_epoch()
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

    data = _json_body()
    code = _json_str(data, 'code', '')
    secret = session.get('pending_totp_secret')

    if not secret:
        return jsonify({'status': 'error', 'message': 'No pending 2FA setup'}), 400

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({'status': 'error', 'message': 'Invalid code, try again'}), 400

    # Save to config
    with _config_runtime_lock:
        CONFIG['auth']['totp_secret'] = secret
        CONFIG['auth']['tfa_method'] = 'totp'
        CONFIG['auth']['tfa_email'] = None
        save_config(CONFIG)
    session.pop('pending_totp_secret', None)
    _bump_session_epoch()

    log_audit('2fa_enable', {'method': 'totp'})
    return jsonify({'status': 'ok', 'message': '2FA enabled successfully'})


@app.route('/settings/2fa/disable', methods=['POST'])
@login_required
def disable_2fa():
    data = _json_body()
    password = data.get('password', '')

    if not check_password_hash(PASSWORD_HASH, password):
        return jsonify({'status': 'error', 'message': 'Incorrect password'}), 400

    with _config_runtime_lock:
        CONFIG['auth']['totp_secret'] = None
        CONFIG['auth']['tfa_method'] = None
        CONFIG['auth']['tfa_email'] = None
        save_config(CONFIG)
    _bump_session_epoch()

    log_audit('2fa_disable')
    return jsonify({'status': 'ok', 'message': '2FA disabled'})


@app.route('/settings/2fa/email/enable', methods=['POST'])
@login_required
def enable_email_2fa():
    """Start email 2FA setup: send verification code to provided email"""
    smtp_host = CONFIG.get('smtp', {}).get('host', '')
    if not smtp_host:
        return jsonify({'status': 'error', 'message': 'Configure SMTP settings first'}), 400

    data = _json_body()
    email = _json_str(data, 'email', '')
    if not email or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({'status': 'error', 'message': 'Invalid email address'}), 400

    code = _generate_email_code()
    ok, err = send_email(
        'VPS Manager - Verify Email 2FA',
        f'Your verification code is: {code}\n\nThis code expires in 10 minutes.',
        f'''<div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:20px">
<h2 style="color:#e6edf3;margin:0 0 16px">VPS Manager</h2>
<p style="color:#8b949e;margin:0 0 20px">Verify your email for 2FA:</p>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;text-align:center;margin:0 0 20px">
<span style="font-size:32px;font-weight:700;letter-spacing:8px;color:#58a6ff">{code}</span>
</div>
<p style="color:#8b949e;font-size:13px;margin:0">This code expires in 10 minutes.</p>
</div>''',
        to=email,
    )
    if not ok:
        return jsonify({'status': 'error', 'message': f'Could not send email: {err}'}), 500

    session['pending_tfa_email'] = email
    return jsonify({'status': 'ok', 'message': f'Verification code sent to {email}'})


@app.route('/settings/2fa/email/verify', methods=['POST'])
@login_required
def verify_email_2fa():
    """Verify email 2FA setup code and enable email 2FA"""
    data = _json_body()
    code = _json_str(data, 'code', '')
    pending_email = session.get('pending_tfa_email')

    if not pending_email:
        return jsonify({'status': 'error', 'message': 'No pending email 2FA setup'}), 400

    ok, err = _verify_email_code(code)
    if not ok:
        return jsonify({'status': 'error', 'message': err}), 400

    with _config_runtime_lock:
        CONFIG['auth']['tfa_method'] = 'email'
        CONFIG['auth']['tfa_email'] = pending_email
        CONFIG['auth']['totp_secret'] = None
        save_config(CONFIG)
    session.pop('pending_tfa_email', None)
    _bump_session_epoch()

    log_audit('2fa_enable', {'method': 'email', 'email': pending_email})
    return jsonify({'status': 'ok', 'message': 'Email 2FA enabled successfully'})


@app.route('/api/smtp/save', methods=['POST'])
@login_required
def save_smtp_settings():
    """Save SMTP configuration"""
    data = _json_body()

    host = str(data.get('host', '')).strip()
    port = data.get('port', 587)
    username = str(data.get('username', '')).strip()
    password = data.get('password', '')
    encryption = str(data.get('encryption', 'starttls')).strip()
    from_name = str(data.get('from_name', '')).strip()
    from_address = str(data.get('from_address', '')).strip()

    if not isinstance(port, int) or port < 1 or port > 65535:
        return jsonify({'status': 'error', 'message': 'Port must be between 1-65535'}), 400
    if encryption not in ('starttls', 'ssl', 'none'):
        return jsonify({'status': 'error', 'message': 'Invalid encryption type'}), 400

    if not isinstance(password, str):
        return jsonify({'status': 'error', 'message': 'Invalid password'}), 400
    # Keep existing password if not provided — maar niet bij een andere host
    # of gebruiker: anders stuurt "Test" het opgeslagen wachtwoord naar een
    # willekeurige (bijv. door een aanvaller ingevulde) server.
    if not password:
        current = CONFIG.get('smtp', {})
        if current.get('password') and (host != current.get('host') or username != current.get('username')):
            return jsonify({'status': 'error',
                            'message': 'Enter the SMTP password again when changing the host or username'}), 400
        password = current.get('password', '')

    verify_tls = data.get('verify_tls', CONFIG.get('smtp', {}).get('verify_tls', True))
    if not isinstance(verify_tls, bool):
        return jsonify({'status': 'error', 'message': 'verify_tls must be true or false'}), 400

    with _config_runtime_lock:
        CONFIG['smtp'] = {
            'verify_tls': verify_tls,
            'host': host,
            'port': port,
            'username': username,
            'password': password,
            'encryption': encryption,
            'from_name': from_name,
            'from_address': from_address,
        }

        # Save notification recipient if provided
        if 'notification_email' in data:
            CONFIG['notification_email'] = str(data['notification_email']).strip()

        save_config(CONFIG)
    log_audit('smtp_settings_saved')
    return jsonify({'status': 'ok', 'message': 'SMTP settings saved'})


@app.route('/api/smtp/test', methods=['POST'])
@login_required
def test_smtp():
    """Send a test email to verify SMTP settings"""
    data = _json_body()
    recipient = _json_str(data, 'recipient', '')
    if not recipient:
        recipient = CONFIG.get('smtp', {}).get('from_address', '')
    if not recipient:
        return jsonify({'status': 'error', 'message': 'No recipient specified'}), 400

    ok, err = send_email(
        'VPS Manager - Test Email',
        'This is a test email from VPS Manager. Your SMTP settings are working correctly.',
        '<div style="font-family:sans-serif;padding:20px"><h2 style="color:#e6edf3">VPS Manager</h2><p style="color:#8b949e">Your SMTP settings are working correctly.</p></div>',
        to=recipient,
    )
    if ok:
        return jsonify({'status': 'ok', 'message': f'Test email sent to {recipient}'})
    return jsonify({'status': 'error', 'message': f'Failed: {err}'}), 500


@app.route('/api/backup/webhook', methods=['POST'])
@csrf.exempt
def backup_webhook():
    """Endpoint for backup scripts to report success/failure"""
    webhook_secret = CONFIG.get('backup', {}).get('webhook_secret', '')
    if not webhook_secret:
        return jsonify({'status': 'error', 'message': 'Webhook secret not configured'}), 403
    provided = request.headers.get('X-Webhook-Secret', '')
    # Op bytes vergelijken: compare_digest gooit een TypeError (→ 500) op
    # str met niet-ASCII tekens in de header.
    if not provided or not hmac.compare_digest(provided.encode('utf-8', 'replace'),
                                               str(webhook_secret).encode('utf-8')):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get('status') not in ('success', 'failure'):
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
    _invalidate_cache('get_backup_status')
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
    # Disable and re-enable swap. Een paar GB swap leegmaken duurt makkelijk
    # langer dan een minuut; swapon moet altijd volgen, ook als swapoff faalt
    # of time-out gaat — anders blijft de server zonder swap tot een reboot.
    off = run_cmd_safe(["sudo", "swapoff", "-a"], timeout=600)
    on = run_cmd_safe(["sudo", "swapon", "-a"], timeout=30)
    if off.returncode != 0:
        return jsonify({'status': 'error', 'message': f'swapoff failed: {off.stderr}'}), 500
    if on.returncode != 0:
        return jsonify({'status': 'error', 'message': f'swapon failed: {on.stderr}'}), 500
    log_audit('swap_clear', {'freed_mb': swap_used // 1024})
    _invalidate_cache('get_server_overview')
    return jsonify({'status': 'ok', 'message': f'Swap cleared ({swap_used // 1024}MB freed)'})


@app.route('/reboot', methods=['POST'])
@login_required
def reboot():
    result = run_cmd_safe(["sudo", "reboot"], timeout=30)
    if result.returncode != 0:
        log_audit('server_reboot_failed', {'error': (result.stderr or '')[:200]})
        return jsonify({'status': 'error',
                        'message': f"Reboot failed: {(result.stderr or 'unknown error').strip()[:200]}"}), 500
    log_audit('server_reboot')
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
        'security': get_security_audit,
    }

    # Een expliciete refresh wil geen stale cache-entry (zie _ttl_cache);
    # de vlag is thread-local en waitress hergebruikt threads, dus altijd resetten.
    _cache_tls.require_fresh = True
    try:
        if section == 'disk':
            sites, total = get_disk_per_site()
            return jsonify({'sites': sites, 'total': total})

        handler = handlers.get(section)
        if handler:
            return jsonify(handler())
    finally:
        _cache_tls.require_fresh = False
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
    # Eerst leegmaken, dan loggen: andersom werd ook het "cleared"-record
    # direct weer gewist en was niet meer te zien dat de log geleegd is.
    with _audit_lock:
        _atomic_write_json(AUDIT_LOG_PATH, [])
    log_audit('audit_clear')
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
    norm_path = os.path.realpath(path)

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

    # Read and check for binary content. O_NOFOLLOW + fstat + begrensde read:
    # een bestand dat na de checks door een symlink (bijv. naar /dev/zero)
    # vervangen wordt, kan zo niet alsnog onbeperkt ingelezen worden.
    try:
        fd = os.open(norm_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            if not stat_module.S_ISREG(os.fstat(f.fileno()).st_mode):
                return jsonify({'status': 'error', 'message': 'Not a regular file'}), 400
            raw = f.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            return jsonify({'status': 'error', 'message': 'File too large (max 1MB)'}), 400
        if b'\x00' in raw[:8192]:
            return jsonify({'status': 'error', 'message': 'Binary file cannot be edited'}), 400
    except OSError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

    writable = os.access(norm_path, os.W_OK)
    try:
        content = raw.decode('utf-8')
        notice = ''
    except UnicodeDecodeError:
        # Opslaan zou de niet-UTF-8 bytes als U+FFFD terugschrijven en het
        # bestand beschadigen: alleen-lezen tonen.
        content = raw.decode('utf-8', errors='replace')
        writable = False
        notice = 'File is not UTF-8 encoded; opened read-only to avoid corrupting it'
    return jsonify({'status': 'ok', 'content': content, 'writable': writable, 'notice': notice})


@app.route('/files/save', methods=['POST'])
@login_required
def files_save():
    """Save file content from in-browser editor"""
    data = _json_body()
    path = _json_str(data, 'path', '')
    content = data.get('content', '')

    if not path or not isinstance(path, str):
        return jsonify({'status': 'error', 'message': 'No path specified'}), 400
    # open('w') kapt het bestand al af vóór write(); een niet-string content
    # zou het bestand dus leeg achterlaten.
    if not isinstance(content, str):
        return jsonify({'status': 'error', 'message': 'Invalid content'}), 400

    norm_path = os.path.realpath(path)

    if not is_path_allowed(norm_path):
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403

    if not os.path.isfile(norm_path):
        return jsonify({'status': 'error', 'message': 'File not found'}), 404

    try:
        # In-place (behoudt eigenaar/rechten), maar zonder een symlink te volgen
        # die na de checks op de plek van het bestand gezet is.
        fd = os.open(norm_path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
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
        if parts[0].startswith('@') and len(parts) >= 2:
            schedule_parts, command_parts = parts[:1], parts[1:]
        elif len(parts) >= 6:
            schedule_parts, command_parts = parts[:5], parts[5:]
        else:
            continue
        jobs.append({
            'index': job_idx,
            'line_num': i,
            'schedule': ' '.join(schedule_parts),
            'command': ' '.join(command_parts),
            'human_schedule': _cron_to_human(schedule_parts),
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
    if len(parts) == 1 and parts[0].lower() in _CRON_SPECIALS:
        return True, ''
    if len(parts) != 5:
        return False, 'Schedule must have 5 fields (or @daily, @reboot, ...)'
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


def _read_crontab(cron_type):
    """Lees de crontab. Returns (text, error); een lege crontab is geen fout.

    Voorheen werd elke fout van `crontab -l` als "lege crontab" behandeld,
    waarna add de bestaande crontab overschreef met alleen de nieuwe regel.
    """
    cmd = ['sudo', 'crontab', '-l'] if cron_type == 'root' else ['crontab', '-l']
    result = run_cmd_safe(cmd, timeout=10)
    if result.returncode == 0:
        return result.stdout, None
    if 'no crontab for' in (result.stderr or '').lower():
        return '', None
    return None, (result.stderr or '').strip() or 'Could not read crontab'


def _write_crontab(cron_type, content):
    if content and not content.endswith('\n'):
        content += '\n'
    prefix = 'sudo crontab -' if cron_type == 'root' else 'crontab -'
    result = run_cmd(f"printf %s {shlex.quote(content)} | {prefix}", timeout=10)
    _invalidate_cache('get_cronjobs')
    return result


def _cron_request():
    """Parse type/index/expected uit een cron-request en zoek de job op.

    Returns (cron_type, lines, job, error_response). Als de client
    `expected` meestuurt en de job op die index is inmiddels een andere
    (crontab extern gewijzigd), dan 409 in plaats van de verkeerde regel te
    bewerken, verwijderen of als root uit te voeren.
    """
    data = request.get_json(silent=True) or {}
    cron_type = data.get('type', 'user')
    if cron_type not in ('user', 'root'):
        return None, None, None, (jsonify({'status': 'error', 'message': 'Invalid crontab type'}), 400)
    try:
        index = int(data.get('index'))
    except (ValueError, TypeError):
        return None, None, None, (jsonify({'status': 'error', 'message': 'Invalid index'}), 400)

    text, err = _read_crontab(cron_type)
    if text is None:
        return None, None, None, (jsonify({'status': 'error', 'message': err}), 500)
    lines, jobs = _parse_crontab_lines(text)
    if index < 0 or index >= len(jobs):
        return None, None, None, (jsonify({'status': 'error', 'message': 'Job index out of range, reload the page'}), 409)
    job = jobs[index]

    expected = data.get('expected')
    if isinstance(expected, dict):
        if (str(expected.get('schedule', '')).split() != job['schedule'].split()
                or str(expected.get('command', '')).split() != job['command'].split()):
            return None, None, None, (jsonify({
                'status': 'error',
                'message': 'The crontab changed since the page was loaded. The list has been refreshed, please try again.',
            }), 409)
    return cron_type, lines, job, None


def _cron_input(data):
    schedule = data.get('schedule')
    command = data.get('command')
    schedule = schedule.strip() if isinstance(schedule, str) else ''
    command = command.strip() if isinstance(command, str) else ''
    if '\n' in command or '\r' in command:
        return schedule, command, 'Command must be a single line'
    if not schedule or not command:
        return schedule, command, 'Schedule and command are required'
    ok, err = _validate_cron_schedule(schedule)
    return schedule, command, (None if ok else err)


@app.route('/api/cronjobs/add', methods=['POST'])
@login_required
def cronjobs_add():
    """Add a new cron entry"""
    data = request.get_json(silent=True) or {}
    cron_type = data.get('type', 'user')
    if cron_type not in ('user', 'root'):
        return jsonify({'status': 'error', 'message': 'Invalid crontab type'}), 400
    schedule, command, err = _cron_input(data)
    if err:
        return jsonify({'status': 'error', 'message': err}), 400

    current, err = _read_crontab(cron_type)
    if current is None:
        return jsonify({'status': 'error', 'message': err}), 500

    if current and not current.endswith('\n'):
        current += '\n'
    current += f'{schedule} {command}\n'

    write_result = _write_crontab(cron_type, current)
    if write_result.returncode == 0:
        log_audit('cronjob_add', {'type': cron_type, 'schedule': schedule, 'command': command})
        return jsonify({'status': 'ok', 'message': 'Cronjob added'})
    return jsonify({'status': 'error', 'message': write_result.stderr.strip() or 'Failed to add cronjob'}), 500


@app.route('/api/cronjobs/edit', methods=['POST'])
@login_required
def cronjobs_edit():
    """Edit an existing cron entry by index"""
    schedule, command, err = _cron_input(request.get_json(silent=True) or {})
    if err:
        return jsonify({'status': 'error', 'message': err}), 400
    cron_type, lines, job, error = _cron_request()
    if error:
        return error

    lines[job['line_num']] = f'{schedule} {command}'
    write_result = _write_crontab(cron_type, '\n'.join(lines))
    if write_result.returncode == 0:
        log_audit('cronjob_edit', {'type': cron_type, 'index': job['index'], 'schedule': schedule, 'command': command})
        return jsonify({'status': 'ok', 'message': 'Cronjob updated'})
    return jsonify({'status': 'error', 'message': write_result.stderr.strip() or 'Failed to edit cronjob'}), 500


@app.route('/api/cronjobs/delete', methods=['POST'])
@login_required
def cronjobs_delete():
    """Delete a cron entry by index"""
    cron_type, lines, job, error = _cron_request()
    if error:
        return error

    deleted_cmd = lines[job['line_num']]
    del lines[job['line_num']]
    write_result = _write_crontab(cron_type, '\n'.join(lines))
    if write_result.returncode == 0:
        log_audit('cronjob_delete', {'type': cron_type, 'index': job['index'], 'entry': deleted_cmd.strip()})
        return jsonify({'status': 'ok', 'message': 'Cronjob deleted'})
    return jsonify({'status': 'error', 'message': write_result.stderr.strip() or 'Failed to delete cronjob'}), 500


@app.route('/api/cronjobs/run', methods=['POST'])
@login_required
def cronjobs_run():
    """Run a cron job command immediately"""
    cron_type, _lines, job, error = _cron_request()
    if error:
        return error
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

_CADDY_GLOB_CHARS = '*?['
_CADDY_LOG_RE = re.compile(r'^\s*log(\s|\{|$)')


def _caddy_strip_comment(line):
    """Strip a Caddyfile comment ('#' at the start of a token)."""
    m = re.search(r'(^|\s)#', line)
    return line[:m.start()] if m else line


def _caddy_brace_delta(line):
    code = _caddy_strip_comment(line)
    return code.count('{') - code.count('}')


def _caddy_skip_block(lines, i):
    """Skip the block starting at lines[i] (brace on that line or the next).

    Telt accolades tot het block sluit, dus geneste blocks (header { },
    @matcher { }, handle { }) horen bij het block. Returns de index van de
    regel na de sluitende accolade.
    """
    code = _caddy_strip_comment(lines[i])
    depth = code.count('{') - code.count('}')
    i += 1
    if '{' not in code and i < len(lines) and lines[i].strip().startswith('{'):
        depth += _caddy_brace_delta(lines[i])
        i += 1
    while i < len(lines) and depth > 0:
        depth += _caddy_brace_delta(lines[i])
        i += 1
    return i


def _caddy_import_specs(content, caddyfile_dir):
    """File imports of a Caddyfile within /etc/caddy/.

    Returns [(base_dir, pattern)] for glob imports and [(path, None)] for
    single-file imports. Relatieve paden worden, net als in Caddy, opgelost
    tegen de map van de Caddyfile.
    """
    specs = []
    for m in re.finditer(r'^\s*import\s+(\S+)\s*$', content, re.MULTILINE):
        import_path = m.group(1)
        # Skip snippet imports (no path chars, no glob)
        if '/' not in import_path and not any(c in import_path for c in _CADDY_GLOB_CHARS):
            continue
        if not import_path.startswith('/'):
            import_path = os.path.join(caddyfile_dir, import_path)
        import_path = os.path.normpath(import_path)
        base_dir, pattern = os.path.split(import_path)
        if any(c in pattern for c in _CADDY_GLOB_CHARS):
            # Caddy staat maar één wildcard toe; een glob in de map zelf niet ondersteund
            if any(c in base_dir for c in _CADDY_GLOB_CHARS):
                continue
            if not _is_caddy_path_safe(os.path.join(base_dir, '_')):
                continue
            specs.append((base_dir, pattern))
        elif _is_caddy_path_safe(import_path):
            specs.append((import_path, None))
    return specs


def _caddy_glob_match(pattern, fname):
    """Match a file name like Caddy's import glob does.

    fnmatch op de basename; verborgen bestanden worden overgeslagen als het
    patroon met '*' begint (Caddy doet dat ook). Let op: 'sites/*' matcht dus
    ook 'foo.disabled'.
    """
    import fnmatch
    if pattern.startswith('*') and fname.startswith('.'):
        return False
    return fnmatch.fnmatchcase(fname, pattern)


def _caddy_import_files(content, caddyfile_dir):
    """Paths of the files a Caddyfile imports (glob-aware, only within /etc/caddy/)."""
    files = []
    for base, pattern in _caddy_import_specs(content, caddyfile_dir):
        if pattern is None:
            files.append(base)
            continue
        result = run_cmd_safe(["sudo", "ls", base], timeout=5)
        if result.returncode != 0:
            continue
        for fname in result.stdout.split('\n'):
            fname = fname.strip()
            if not fname or not _caddy_glob_match(pattern, fname):
                continue
            fpath = os.path.join(base, fname)
            if _is_caddy_path_safe(fpath):
                files.append(fpath)
    return list(dict.fromkeys(files))


def _parse_caddyfile(content, sites_dir=None, config_file=None):
    """Parse a Caddyfile and extract site blocks.
    Returns list of dicts with keys: address, root, proxy, file_server, tls, log_output.
    """
    sites = []

    # Expand file imports ('import sites/*', 'import sites/*.caddy', 'import /etc/caddy/x'):
    # alleen de bestanden die het glob-patroon matcht, zoals Caddy zelf ook doet.
    expanded = content
    # Resolve relative imports against the Caddyfile's directory (not sites_dir)
    if config_file:
        caddyfile_dir = os.path.dirname(config_file)
    else:
        caddyfile_dir = os.path.dirname(sites_dir.rstrip('/')) if sites_dir else '/etc/caddy'

    for fpath in _caddy_import_files(content, caddyfile_dir):
        file_result = run_cmd_safe(["sudo", "cat", fpath], timeout=5)
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
        # Skip snippet blocks: (name) { ... }, inclusief geneste blocks
        if line.startswith('('):
            i = _caddy_skip_block(lines, i)
            continue

        # Check for global options block
        if line == '{':
            i = _caddy_skip_block(lines, i)
            continue

        # Check for site address (domain/host followed by { on same or next line)
        address = None
        if '{' in line:
            address = line.split('{')[0].strip()
        elif i + 1 < len(lines) and lines[i + 1].strip() == '{':
            address = line
        elif (line and not line.startswith('}') and not line.startswith('/')
              and not any(line.startswith(d) for d in [
            'import', 'log', 'tls', 'root', 'reverse_proxy', 'file_server',
            'encode', 'header', 'handle', 'handle_path', 'route', 'respond', 'redir',
            'email', 'admin', 'auto_https', 'order', 'storage', 'acme_ca',
            'ocsp_stapling', 'grace_period', 'shutdown_delay', 'servers',
            'skip_install_trust', 'default_bind', 'default_sni',
            'php_fastcgi', 'basicauth', 'forward_auth', 'request_header',
            'try_files', 'rewrite', 'uri', 'method', 'bind', 'abort',
            'error', 'metrics', 'templates', 'push', 'vars', 'map',
            'invoke', 'skip_log', 'request_body',
            'output', 'file', 'format', 'level', 'include', 'exclude',
            'roll_size', 'roll_keep', 'roll_keep_for', 'roll_local_time',
        ])):
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
            depth = _caddy_brace_delta(lines[i])
            i += 1
        else:
            i += 1
            if i < len(lines) and '{' in lines[i]:
                depth = _caddy_brace_delta(lines[i])
                i += 1

        while i < len(lines) and depth > 0:
            block_lines.append(lines[i])
            depth += _caddy_brace_delta(lines[i])
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
        # Remove port if present, validate as domain name
        domains = []
        for addr_part in clean_addr.split():
            addr_part = addr_part.strip(',')
            domain = addr_part.split(':')[0] if ':' in addr_part else addr_part
            if not domain or domain in ('localhost', '*', ':'):
                continue
            # Must look like a domain (contain a dot) or be a port-only address
            if '.' not in domain and not domain.startswith(':'):
                continue
            # Skip paths and non-domain strings
            if '/' in domain or domain.startswith('/'):
                continue
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


def _caddy_log_snippets(content):
    """Names of snippets in content whose body contains a log directive."""
    names = set()
    lines = content.split('\n')
    i = 0
    while i < len(lines):
        m = re.match(r'^\s*\(([^)\s]+)\)', lines[i])
        if m:
            end = _caddy_skip_block(lines, i)
            if any(_CADDY_LOG_RE.match(_caddy_strip_comment(bl)) for bl in lines[i + 1:end]):
                names.add(m.group(1))
            i = end
            continue
        i += 1
    return names


def _caddy_add_site_logs(content, log_snippets=()):
    """Add a log block to site blocks without one.

    Returns (new_content, [domains]) or (None, []) when nothing changes.
    Snippets '(name) { ... }' worden in hun geheel overgeslagen (incl. geneste
    header/@matcher/handle-blocks), net als het globale options-block. Een
    site die een snippet met log importeert telt als 'heeft log'.
    """
    lines = content.split('\n')
    log_snippets = set(log_snippets) | _caddy_log_snippets(content)
    insertions = []  # (close_line_index, domain, indent)

    i = 0
    while i < len(lines):
        line = _caddy_strip_comment(lines[i]).strip()
        if not line:
            i += 1
            continue
        # Snippet of global options block: hele block overslaan
        if line.startswith('(') or line == '{':
            i = _caddy_skip_block(lines, i)
            continue

        # Detect site address
        address = None
        if '{' in line:
            address = line.split('{')[0].strip()
        elif i + 1 < len(lines) and lines[i + 1].strip() == '{':
            address = line

        if not address or address.startswith('}'):
            i += 1
            continue

        header = i
        end = _caddy_skip_block(lines, i)
        close = end - 1
        i = end
        # Alleen invoegen als de sluitende '}' op een eigen regel staat
        if close <= header or _caddy_strip_comment(lines[close]).strip() != '}':
            continue

        body = [_caddy_strip_comment(bl) for bl in lines[header + 1:close]]
        has_log = any(_CADDY_LOG_RE.match(bl) for bl in body)
        if not has_log:
            for bl in body:
                m = re.match(r'^\s*import\s+(\S+)', bl)
                if m and m.group(1) in log_snippets:
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
        safe_domain = re.sub(r'[^a-zA-Z0-9._-]', '', domain)
        if not safe_domain:
            continue
        head = lines[header]
        indent = head[:len(head) - len(head.lstrip())] + '    '
        insertions.append((close, safe_domain, indent))

    if not insertions:
        return None, []

    # Insert in reverse order so line indices stay valid
    for close, safe_domain, indent in reversed(insertions):
        lines[close:close] = [
            f'{indent}log {{',
            f'{indent}    output file /var/log/caddy/{safe_domain}.log',
            f'{indent}}}',
        ]
    return '\n'.join(lines), [d for _, d, _ in insertions]


def _ensure_caddy_site_logs(config_file, log_snippets=()):
    """Auto-add log blocks to Caddy site blocks that lack them.

    Eén poging per bestandsversie per proces; schrijven, valideren en
    herladen via _sudo_write_validated (rollback bij ongeldige config) en
    alleen een audit-entry als er echt iets is gewijzigd.
    Returns True if changes were made."""
    if not _autolog_should_attempt(config_file):
        return False
    # Lezen-aanpassen-schrijven onder dezelfde lock als een save uit de UI;
    # anders kon een tussentijdse edit overschreven worden.
    with _webconfig_write_lock:
        result = run_cmd_safe(["sudo", "cat", config_file], timeout=5)
        if result.returncode != 0:
            return False

        new_content, domains_added = _caddy_add_site_logs(result.stdout, log_snippets)
        if new_content is None:
            return False

        res = _sudo_write_validated(config_file, new_content, validate_caddy,
                                    lambda: run_cmd_safe(["sudo", "systemctl", "reload", "caddy"], timeout=15))
    _autolog_mark_done(config_file)
    if not res['written']:
        logger.warning("Auto-adding Caddy logs to %s failed (%s), rolled back: %s",
                       config_file, res['stage'], res['output'] or res['message'])
        return False
    if not res['ok']:
        logger.warning("Caddy reload failed after auto-adding logs to %s: %s", config_file, res['output'])

    log_audit('caddy_auto_add_logs', {'config': os.path.basename(config_file), 'domains': domains_added})
    return True


@_ttl_cache(60, stale=900)
def get_caddy_sites():
    """Get Caddy sites with HTTP status"""
    caddy_cfg = CONFIG.get('caddy', {})
    config_file = caddy_cfg.get('config_file', '/etc/caddy/Caddyfile')
    sites_dir = caddy_cfg.get('sites_dir', '/etc/caddy/sites/')

    result = run_cmd_safe(["sudo", "cat", config_file], timeout=10)
    if result.returncode != 0:
        return []

    # Auto-add log blocks to sites missing them: alleen bestanden die Caddy
    # daadwerkelijk importeert, één poging per bestandsversie per proces
    # (valideert, herlaadt en rolt zelf terug; zie _ensure_caddy_site_logs).
    log_snippets = _caddy_log_snippets(result.stdout)
    configs_modified = False
    for fpath in [config_file] + _caddy_import_files(result.stdout, os.path.dirname(config_file)):
        if _ensure_caddy_site_logs(fpath, log_snippets):
            configs_modified = True

    if configs_modified:
        # Re-read config after modifications
        result = run_cmd_safe(["sudo", "cat", config_file], timeout=10)
        if result.returncode != 0:
            return []

    parsed = _parse_caddyfile(result.stdout, sites_dir=sites_dir, config_file=config_file)
    sites = []

    for site in parsed:
        domains = site['domains']
        proxy = site.get('proxy')
        doc_root = site.get('root')
        log_output = site.get('log_output')

        sites.append({
            'config': os.path.basename(config_file),
            'domains': domains,
            'domain': ', '.join(domains),
            'root': doc_root,
            'proxy': proxy,
            'type': 'proxy' if proxy else 'static',
            'location': proxy if proxy else (doc_root or 'n/a'),
            'http_status': '---',
            'access_log': log_output,
            'error_log': log_output,  # Caddy uses single log file per site
        })

    # Check HTTP status for all sites in parallel (same logic as nginx)
    statuses = _check_http_statuses([s['domains'][0] for s in sites if s['domains']])
    for s in sites:
        if s['domains']:
            s['http_status'] = statuses.get(s['domains'][0], '---')

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
    except (json.JSONDecodeError, ValueError, AttributeError, TypeError, OverflowError, OSError):
        return {'timestamp': '', 'level': 'unknown', 'message': line[:120], 'raw': line}


@_ttl_cache(60, stale=600)
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
                if not isinstance(entry, dict):
                    raise ValueError('not a JSON object')
                if entry.get('level') in ('error', 'warn', 'fatal', 'panic'):
                    error_lines.append(l)
            except (json.JSONDecodeError, ValueError):
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
                if not isinstance(entry, dict):
                    continue
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


@_ttl_cache(600, stale=21600)
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

        # Parse: notAfter=Mar 15 12:00:00 2027 GMT. openssl geeft altijd GMT/UTC;
        # behandel de tijd expliciet als UTC en vergelijk met now(UTC) zodat een
        # naive/lokale-tijd-mismatch de dag-grens niet kan laten omklappen.
        expiry_str = expiry_result.stdout.strip().replace('notAfter=', '')
        expiry_str = re.sub(r'\s+(GMT|UTC)$', '', expiry_str).strip()
        expiry_dt = None
        for fmt in ('%b %d %H:%M:%S %Y', '%b  %d %H:%M:%S %Y'):
            try:
                expiry_dt = datetime.strptime(expiry_str, fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
        if expiry_dt is None:
            continue
        days_left = (expiry_dt - datetime.now(timezone.utc)).days
        expiry_date = expiry_dt.strftime('%Y-%m-%d')

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


# Serialiseert schrijf-/valideer-/reload-cycli van webserverconfigs, zodat
# twee gelijktijdige saves (of een save en de auto-log-toevoeging) elkaars
# validatie of rollback niet doorkruisen.
_webconfig_write_lock = threading.RLock()
# Backups staan bewust buiten /etc/nginx en /etc/caddy: een '<naam>.backup'
# in sites-enabled/ of sites/ wordt door 'include sites-enabled/*' resp.
# 'import sites/*' meegeladen (dubbele server/site-definities).
CONFIG_BACKUP_DIR = DATA_DIR / 'config-backups'


def _sudo_run(args, data=None, timeout=15):
    """Run a command with bytes stdin/stdout; returns None on timeout/OS error."""
    try:
        return subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None


def _sudo_write_validated(path, content, validate_fn, reload_fn):
    """Write a root-owned web server config, validate it and reload.

    - Het vorige bestand gaat naar DATA_DIR/config-backups/ (nooit naast de
      config in een include-map) en blijft in het geheugen voor rollback.
    - Schrijven via 'sudo tee', zodat eigenaar/rechten van een bestaand bestand
      behouden blijven en een symlink (sites-enabled -> sites-available)
      gevolgd wordt.
    - Validatie mislukt: vorige inhoud terugzetten, of een nieuw aangemaakt
      bestand weer verwijderen.
    - Reload mislukt: gemeld als fout (de geldige nieuwe config blijft staan).

    Returns dict: ok, written (nieuwe inhoud staat op schijf), stage
    ('write' | 'validate' | 'reload' | None), message, output, code.
    """
    data = content.encode('utf-8') if isinstance(content, str) else content

    def _fail(stage, message, output='', code=500, written=False):
        return {'ok': False, 'written': written, 'stage': stage,
                'message': message, 'output': output, 'code': code}

    with _webconfig_write_lock:
        link = _sudo_run(["sudo", "test", "-L", path], timeout=5)
        exists = _sudo_run(["sudo", "test", "-e", path], timeout=5)
        if link is None or exists is None:
            return _fail('write', 'Could not check config path')
        existed = exists.returncode == 0
        if link.returncode == 0 and not existed:
            return _fail('write', 'Config path is a dangling symlink', code=409)

        old = None
        backup_path = None
        if existed:
            read = _sudo_run(["sudo", "cat", path], timeout=10)
            if read is None or read.returncode != 0:
                return _fail('write', 'Could not read current config for backup')
            old = read.stdout
            backup_path = CONFIG_BACKUP_DIR / (path.strip('/').replace('/', '_') + '.bak')
            try:
                CONFIG_BACKUP_DIR.mkdir(mode=0o700, exist_ok=True)
                fd = os.open(str(backup_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, 'wb') as f:
                    f.write(old)
            except OSError as e:
                return _fail('write', f'Could not write backup: {e}')

        def _restore():
            if existed:
                r = _sudo_run(["sudo", "tee", path], data=old, timeout=15)
            else:
                r = _sudo_run(["sudo", "rm", "-f", path], timeout=10)
            return r is not None and r.returncode == 0

        def _restore_note():
            if _restore():
                return 'previous version restored' if existed else 'new file removed'
            if existed:
                return f'RESTORE FAILED, previous version saved at {backup_path}'
            return f'could not remove new file {path}'

        write = _sudo_run(["sudo", "tee", path], data=data, timeout=15)
        if write is None or write.returncode != 0:
            # tee kan het bestand al afgekapt hebben: altijd terugzetten
            err = (write.stderr.decode('utf-8', 'replace').strip() if write is not None else 'timeout')
            return _fail('write', f'Failed to write config ({_restore_note()})', err)

        is_valid, output = validate_fn()
        if not is_valid:
            return _fail('validate', f'Config test failed ({_restore_note()})', output, code=400)

        reload_result = reload_fn()
        if reload_result.returncode != 0:
            return _fail('reload', 'Config saved and valid, but reload failed',
                         (reload_result.stderr or '').strip(), written=True)

    return {'ok': True, 'written': True, 'stage': None, 'message': '', 'output': '', 'code': 200}


@app.route('/api/nginx/config/save', methods=['POST'])
@login_required
def nginx_config_save():
    """Save nginx config with validation and reload"""
    data = _json_body()
    name = _json_str(data, 'name', '')
    content = data.get('content', '')
    if not isinstance(content, str):
        return jsonify({'status': 'error', 'message': 'Invalid content'}), 400
    config_type = data.get('type', 'enabled')

    if not name or not is_safe_name(name):
        return jsonify({'status': 'error', 'message': 'Invalid config name'}), 400

    if config_type not in ('enabled', 'available'):
        return jsonify({'status': 'error', 'message': 'Invalid type'}), 400

    path = f'/etc/nginx/sites-{config_type}/{name}'

    res = _sudo_write_validated(
        path, content, validate_nginx,
        lambda: run_cmd_safe(["sudo", "systemctl", "reload", "nginx"], timeout=15))

    if res['written']:
        log_audit('nginx_config_save', {'name': name, 'type': config_type})
        _invalidate_cache('get_nginx_sites', 'get_nginx_logs', 'get_all_domains', 'get_uptime_status')

    if res['ok']:
        return jsonify({'status': 'ok', 'message': 'Config saved and nginx reloaded'})
    if res['stage'] == 'validate':
        return jsonify({'status': 'error', 'message': f"Nginx {res['message']}", 'output': res['output']}), 400
    if res['stage'] == 'reload':
        return jsonify({'status': 'error', 'message': 'Config saved but nginx reload failed',
                        'output': res['output']}), 500
    return jsonify({'status': 'error', 'message': res['message'], 'output': res['output']}), res['code']


@app.route('/api/nginx/config/enable', methods=['POST'])
@login_required
def nginx_config_enable():
    """Enable a site by creating symlink"""
    data = _json_body()
    name = _json_str(data, 'name', '')

    if not name or not is_safe_name(name):
        return jsonify({'status': 'error', 'message': 'Invalid config name'}), 400

    available = f'/etc/nginx/sites-available/{name}'
    enabled = f'/etc/nginx/sites-enabled/{name}'

    # Check if available exists
    check = run_cmd_safe(["sudo", "test", "-f", available], timeout=5)
    if check.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Config not found in sites-available'}), 404

    # Nooit iets in sites-enabled overschrijven: een regulier bestand daar
    # heeft mogelijk geen kopie in sites-available.
    if run_cmd_safe(["sudo", "test", "-L", enabled], timeout=5).returncode == 0:
        try:
            target = os.path.realpath(enabled)
        except OSError:
            target = None
        if target == os.path.realpath(available):
            return jsonify({'status': 'ok', 'message': f'{name} is already enabled'})
        return jsonify({'status': 'error', 'message':
                        f'sites-enabled/{name} is a symlink to another file; remove it first'}), 409
    if run_cmd_safe(["sudo", "test", "-e", enabled], timeout=5).returncode == 0:
        return jsonify({'status': 'error', 'message':
                        f'sites-enabled/{name} is a regular file, not a symlink; refusing to overwrite it'}), 409

    result = run_cmd_safe(["sudo", "ln", "-s", available, enabled], timeout=10)
    if result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Failed to create symlink',
                        'output': (result.stderr or '').strip()}), 500

    # Validate and reload
    is_valid, output = validate_nginx()
    if not is_valid:
        # Alleen de symlink die deze aanroep zelf heeft aangemaakt verwijderen
        run_cmd_safe(["sudo", "rm", "-f", enabled], timeout=10)
        return jsonify({'status': 'error', 'message': 'Nginx config test failed after enabling', 'output': output}), 400

    reload_result = run_cmd_safe(["sudo", "systemctl", "reload", "nginx"], timeout=15)
    log_audit('nginx_config_enable', {'name': name})
    _invalidate_cache('get_nginx_sites', 'get_nginx_logs', 'get_all_domains', 'get_uptime_status')
    if reload_result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Nginx reload failed after enabling', 'output': reload_result.stderr.strip()}), 500
    return jsonify({'status': 'ok', 'message': f'{name} enabled and nginx reloaded'})


@app.route('/api/nginx/config/disable', methods=['POST'])
@login_required
def nginx_config_disable():
    """Disable a site by removing symlink from sites-enabled"""
    data = _json_body()
    name = _json_str(data, 'name', '')

    if not name or not is_safe_name(name):
        return jsonify({'status': 'error', 'message': 'Invalid config name'}), 400

    enabled = f'/etc/nginx/sites-enabled/{name}'

    # Alleen symlinks verwijderen: een regulier bestand in sites-enabled heeft
    # mogelijk geen kopie in sites-available en zou dan verloren gaan.
    if run_cmd_safe(["sudo", "test", "-L", enabled], timeout=5).returncode != 0:
        if run_cmd_safe(["sudo", "test", "-e", enabled], timeout=5).returncode == 0:
            return jsonify({'status': 'error', 'message':
                            f'sites-enabled/{name} is a regular file, not a symlink; move it to '
                            'sites-available and enable it from there before disabling'}), 409
        return jsonify({'status': 'error', 'message': f'{name} is not enabled'}), 404

    try:
        link_target = os.readlink(enabled)
    except OSError:
        link_target = None

    result = run_cmd_safe(["sudo", "rm", "-f", enabled], timeout=10)
    if result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Failed to remove symlink'}), 500

    is_valid, output = validate_nginx()
    if not is_valid:
        # Bijv. een upstream uit deze site die elders gebruikt wordt: link terugzetten
        if link_target:
            run_cmd_safe(["sudo", "ln", "-s", link_target, enabled], timeout=10)
        return jsonify({'status': 'error', 'message': 'Nginx config test failed after disabling'
                        + ('; symlink restored' if link_target else ''), 'output': output}), 400

    reload_result = run_cmd_safe(["sudo", "systemctl", "reload", "nginx"], timeout=15)
    log_audit('nginx_config_disable', {'name': name})
    _invalidate_cache('get_nginx_sites', 'get_nginx_logs', 'get_all_domains', 'get_uptime_status')
    if reload_result.returncode != 0:
        return jsonify({'status': 'error', 'message': 'Nginx reload failed after disabling', 'output': reload_result.stderr.strip()}), 500
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


def _caddy_site_import_patterns(sites_dir):
    """Import patterns (basenames) with which the main Caddyfile loads files from sites_dir.

    Returns None als de Caddyfile niet leesbaar is. Een enkel bestand-import
    levert de exacte bestandsnaam op (matcht dan alleen zichzelf).
    """
    caddy_cfg = CONFIG.get('caddy', {})
    config_file = caddy_cfg.get('config_file', '/etc/caddy/Caddyfile')
    result = run_cmd_safe(["sudo", "cat", config_file], timeout=10)
    if result.returncode != 0:
        return None
    target = os.path.realpath(sites_dir.rstrip('/'))
    patterns = []
    for base, pattern in _caddy_import_specs(result.stdout, os.path.dirname(config_file)):
        if pattern is None:
            base, pattern = os.path.split(base)
        if os.path.realpath(base) == target:
            patterns.append(pattern)
    return patterns


@app.route('/api/caddy/config/save', methods=['POST'])
@login_required
def caddy_config_save():
    """Save Caddy config with validation and reload"""
    data = _json_body()
    name = _json_str(data, 'name', '')
    content = data.get('content', '')
    if not isinstance(content, str):
        return jsonify({'status': 'error', 'message': 'Invalid content'}), 400
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

    res = _sudo_write_validated(
        path, content, validate_caddy,
        lambda: run_cmd_safe(["sudo", "systemctl", "reload", "caddy"], timeout=15))

    if res['written']:
        log_audit('caddy_config_save', {'name': name or 'Caddyfile', 'type': config_type})
        _invalidate_cache('get_caddy_sites', 'get_caddy_logs', 'get_caddy_certificates', 'get_all_domains', 'get_uptime_status')

    if res['ok']:
        return jsonify({'status': 'ok', 'message': 'Config saved and Caddy reloaded'})
    if res['stage'] == 'validate':
        return jsonify({'status': 'error', 'message': f"Caddy {res['message']}", 'output': res['output']}), 400
    if res['stage'] == 'reload':
        return jsonify({'status': 'error', 'message': 'Config saved but Caddy reload failed',
                        'output': res['output']}), 500
    return jsonify({'status': 'error', 'message': res['message'], 'output': res['output']}), res['code']


@app.route('/api/caddy/config/toggle', methods=['POST'])
@login_required
def caddy_config_toggle():
    """Enable/disable a Caddy site file by renaming with .disabled extension"""
    data = _json_body()
    name = _json_str(data, 'name', '')
    action = data.get('action', '')  # 'enable' or 'disable'

    base_name = name.removesuffix('.disabled') if name else ''
    if not base_name or not is_safe_name(base_name):
        return jsonify({'status': 'error', 'message': 'Invalid config name'}), 400
    if action not in ('enable', 'disable'):
        return jsonify({'status': 'error', 'message': 'Invalid action'}), 400
    if (action == 'disable') == name.endswith('.disabled'):
        return jsonify({'status': 'error', 'message': f'{name} is already {action}d'}), 400

    caddy_cfg = CONFIG.get('caddy', {})
    sites_dir = caddy_cfg.get('sites_dir', '/etc/caddy/sites/')

    old_path = os.path.join(sites_dir, name)
    if action == 'disable':
        new_path = os.path.join(sites_dir, name + '.disabled')
    else:
        new_path = os.path.join(sites_dir, base_name)

    if not _is_caddy_path_safe(old_path) or not _is_caddy_path_safe(new_path):
        return jsonify({'status': 'error', 'message': 'Path not allowed'}), 403

    # Caddy's import-glob bepaalt of '.disabled' echt uitschakelt: 'import sites/*'
    # laadt ook 'foo.disabled', dan zou de UI 'disabled' tonen terwijl de site live blijft.
    warning = ''
    patterns = _caddy_site_import_patterns(sites_dir)
    if patterns is not None:
        new_name = os.path.basename(new_path)
        loaded = any(_caddy_glob_match(p, new_name) for p in patterns)
        if action == 'disable' and loaded:
            shown = ', '.join(f"'{p}'" for p in patterns)
            return jsonify({'status': 'error', 'message':
                            f'Cannot disable {name}: the Caddyfile imports {shown} from the sites directory, '
                            f'which also loads {new_name}, so the site would stay active. Use an import pattern '
                            "that skips .disabled files (e.g. 'import sites/*.caddy' with site files named "
                            '*.caddy), or remove the site file.'}), 409
        if action == 'enable' and not loaded:
            warning = ' (warning: the Caddyfile does not import this file, so the site is not active)'

    if run_cmd_safe(["sudo", "test", "-e", new_path], timeout=5).returncode == 0:
        return jsonify({'status': 'error', 'message':
                        f'{os.path.basename(new_path)} already exists; refusing to overwrite it'}), 409

    result = run_cmd_safe(["sudo", "mv", old_path, new_path], timeout=10)
    if result.returncode != 0:
        return jsonify({'status': 'error', 'message': f'Failed to {action} config'}), 500

    # Validate and reload
    is_valid, output = validate_caddy()
    if not is_valid:
        # Revert
        run_cmd_safe(["sudo", "mv", new_path, old_path], timeout=10)
        return jsonify({'status': 'error', 'message': f'Caddy validation failed after {action}', 'output': output}), 400

    reload_result = run_cmd_safe(["sudo", "systemctl", "reload", "caddy"], timeout=15)
    log_audit(f'caddy_config_{action}', {'name': name})
    _invalidate_cache('get_caddy_sites', 'get_caddy_logs', 'get_caddy_certificates', 'get_all_domains', 'get_uptime_status')

    if reload_result.returncode != 0:
        return jsonify({'status': 'error', 'message': f'Site {action}d but Caddy reload failed{warning}',
                        'output': (reload_result.stderr or '').strip()}), 500
    return jsonify({'status': 'ok', 'message': f'Site {action}d and Caddy reloaded{warning}'})


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

    # Meld het als de update-watchdog een mislukte update heeft teruggerold
    _rollback_marker = DATA_DIR / '.update_rollback'
    if _rollback_marker.exists():
        try:
            _rollback_detail = _rollback_marker.read_text().strip()
        except OSError:
            _rollback_detail = ''
        logger.error("Previous update failed and was rolled back: %s", _rollback_detail)
        try:
            log_audit('self_update_rollback', {'detail': _rollback_detail})
            _add_notification_history(
                'VPS Manager',
                'Update failed its health check and was automatically rolled back to the previous version',
                'app_update')
        except Exception:
            logger.exception("Could not record rollback notification")
        try:
            _rollback_marker.unlink()
        except OSError:
            pass

    # Start background push notification monitor
    monitor = threading.Thread(target=_monitor_loop, daemon=True)
    monitor.start()

    # Vul de trage caches (apt, certbot, HTTP-checks) op de achtergrond, zodat
    # de eerste dashboard-load na een (her)start er niet op hoeft te wachten.
    def _warm_caches():
        for fn in (get_available_features, get_system_updates, get_ssl_info,
                   get_sites, check_app_update_alert):
            try:
                fn()
            except Exception:
                logger.debug('Cache warm-up of %s failed', fn.__name__, exc_info=True)
    threading.Thread(target=_warm_caches, daemon=True, name='cache-warmup').start()
    port = int(os.environ.get('VPS_MANAGER_PORT', 5050))
    # Bind standaard op loopback: nginx proxyt lokaal naar deze poort, dus de
    # server hoeft niet extern bereikbaar te zijn. Override met
    # VPS_MANAGER_HOST=0.0.0.0 alleen als je bewust direct wilt exposen.
    host = os.environ.get('VPS_MANAGER_HOST', '127.0.0.1')
    try:
        from waitress import serve
    except ImportError:
        # Waitress hoort via requirements.txt geïnstalleerd te zijn; liever
        # draaien op de dev-server dan helemaal niet opstarten (bijv. na een
        # handmatige git pull zonder pip install).
        logging.warning('waitress not installed, falling back to the Flask dev server')
        app.run(host=host, port=port, debug=False)
    else:
        logger.info("Serving with waitress on %s:%s", host, port)
        # send_bytes=1: SSE-events (update-voortgang) moeten per event
        # doorgestuurd worden, niet gebufferd tot de standaard 18KB.
        # 16 threads: trage requests (apt, certbot, SSE-updatestream) mogen
        # niet de hele app laten wachten, ook niet op static files.
        serve(app, host=host, port=port, threads=16, send_bytes=1)
