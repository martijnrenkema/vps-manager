# VPS Manager

Management tool for Ubuntu VPS servers. Includes a CLI tool for local terminal management and a web dashboard that runs on the VPS itself.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-Web_Dashboard-green)
![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04_LTS-orange)
![License](https://img.shields.io/badge/License-MIT-green)

## Features

### Web Dashboard

- **Server Overview** - CPU, RAM, disk, swap, load average, uptime
- **Service Monitoring** - Nginx, PHP-FPM, MariaDB, Fail2ban status with auto-restart
- **Website Management** - All hosted sites with HTTP status checks
- **SSL Certificates** - Expiry dates, warnings, and auto-renewal status
- **PM2 Processes** - Node.js process management (restart, stop, logs)
- **System Updates** - Categorized updates (security, regular, phased, ESM) with one-click install
- **Firewall & Security** - UFW rules, Fail2ban config, jail status, banned IPs
- **DDoS Detection** - Connection monitoring, SYN flood detection, per-IP thresholds
- **Nginx Logs** - Expandable error entries, per-site logs, PHP-FPM errors
- **MariaDB Databases** - Database sizes, table counts, phpMyAdmin link
- **File Browser** - Browse, upload, download, edit files on the server
- **Web Terminal** - Browser-based command execution
- **Cron & Timers** - Crontab and systemd timers with human-readable schedules
- **Backup Monitoring** - Status tracking, history timeline, webhook endpoint
- **Push Notifications** - Web Push alerts for critical events, configurable categories
- **2FA Authentication** - TOTP two-factor auth with QR code setup
- **Settings Panel** - All configuration via web UI, password management

### CLI Tool

- **Interactive Menu** - Full-featured terminal UI with colored output
- **Quick Commands** - `--status`, `--sites`, `--ssl`, `--services`, `--firewall`, etc.
- **Site Deployment** - Deploy static sites and Node.js apps via rsync
- **Server Reboot** - Safe reboot with confirmation

## Quick Start

### Web Dashboard

```bash
# Clone repository
git clone https://github.com/martijnrenkema/vps-manager.git
cd vps-manager

# Upload to VPS
rsync -avz --exclude='venv/' --exclude='data/' --exclude='__pycache__/' \
  web/ your-vps:/var/www/vps-manager/

# On VPS: setup
cd /var/www/vps-manager
python3 -m venv venv
venv/bin/pip install -r requirements.txt

# Set credentials
export VPS_MANAGER_USER=admin
export VPS_MANAGER_PASS=your-secure-password

# Run with PM2
pm2 start "cd /var/www/vps-manager && venv/bin/python app.py" \
  --name vps-manager
pm2 save
```

### CLI Tool

```bash
# Interactive mode
python3 vps-manager.py

# Quick status check
python3 vps-manager.py --status

# All info at once
python3 vps-manager.py --all
```

## CLI Usage

```
python3 vps-manager.py              # Interactive menu
python3 vps-manager.py --status     # Server overview
python3 vps-manager.py --sites      # Websites + HTTP check
python3 vps-manager.py --pm2        # PM2 processes
python3 vps-manager.py --ssl        # SSL certificates
python3 vps-manager.py --services   # Service status
python3 vps-manager.py --backup     # Backup status
python3 vps-manager.py --deploy SITE  # Deploy site
python3 vps-manager.py --firewall   # Firewall & security
python3 vps-manager.py --reboot     # Server reboot
python3 vps-manager.py --all        # Everything at once
```

## Project Structure

```
├── vps-manager.py          # CLI tool (runs from local machine via SSH)
├── web/
│   ├── app.py              # Flask web dashboard (runs on VPS)
│   ├── config.py           # Configuration loader with defaults
│   ├── requirements.txt    # Python dependencies
│   ├── static/
│   │   ├── style.css       # Dark theme stylesheet
│   │   ├── sw.js           # Service worker (push notifications)
│   │   ├── manifest.json   # PWA manifest
│   │   └── *.png           # App icons
│   └── templates/
│       ├── base.html       # Layout with sidebar navigation
│       ├── login.html      # Login + 2FA
│       ├── dashboard.html  # Server overview
│       ├── services.html   # Service monitoring
│       ├── websites.html   # Hosted sites
│       ├── ssl.html        # SSL certificates
│       ├── pm2.html        # PM2 processes
│       ├── updates.html    # System updates
│       ├── firewall.html   # Firewall & security
│       ├── nginx_logs.html # Log viewer
│       ├── databases.html  # MariaDB databases
│       ├── files.html      # File browser
│       ├── terminal.html   # Web terminal
│       ├── cronjobs.html   # Cron & timers
│       ├── disk.html       # Disk usage
│       ├── backup.html     # Backup status
│       ├── notifications.html # Push notification settings
│       ├── settings.html   # Configuration panel
│       └── icons.html      # SVG icon macros
└── CLAUDE.md               # AI assistant context
```

## Configuration

The web dashboard uses `web/data/config.json` for all settings. On first run, defaults are used. Configuration can be changed via the Settings page or by editing the JSON file directly.

### Authentication

Set credentials via environment variables (recommended) or config:

```bash
export VPS_MANAGER_USER=admin
export VPS_MANAGER_PASS=your-password
```

### Monitored Services

Default: `nginx`, `php8.3-fpm`, `mariadb`, `fail2ban`. Configurable in settings.

### Alert Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Disk usage | 80% | 95% |
| Memory usage | 85% | - |
| Swap usage | 50% | - |
| SSL expiry | 14 days | 3 days |

### Push Notifications

Web Push notifications with configurable categories:

| Category | Default | Triggers |
|----------|---------|----------|
| Critical Errors | On | Services down, disk >95%, SSL expired |
| Warnings | On | Disk >80%, RAM >85%, high load |
| Security | On | Fail2ban bans, suspicious SSH activity |
| DDoS Detection | On | High connections, SYN floods |
| Backup | On | Backup failures, no backup in 48h |
| System Updates | Off | Available package updates |

## Dependencies

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [pywebpush](https://github.com/web-push-libs/pywebpush) - Web Push notifications
- [cryptography](https://cryptography.io/) - VAPID key generation
- [pyotp](https://github.com/pyauth/pyotp) - TOTP two-factor authentication
- [qrcode](https://github.com/lincolnloop/python-qrcode) - QR code generation for 2FA setup

## Nginx Configuration

Example Nginx reverse proxy config for the web dashboard:

```nginx
server {
    server_name vps.example.com;

    location / {
        proxy_pass http://127.0.0.1:5050;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    listen 443 ssl;
    ssl_certificate /etc/letsencrypt/live/vps.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vps.example.com/privkey.pem;
}
```

## License

MIT License - feel free to use and modify.
