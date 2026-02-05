# v1.2.0

## New Features

### Audit Log
Full audit trail for all actions performed in the dashboard. Every login, config change, service restart, firewall action, and file edit is logged with timestamp, user, IP address, and details.
- View and filter the audit log from the sidebar
- Automatic rotation (max 1000 entries)
- Clear log via the UI

### File Editor
In-browser file editing for all files within allowed paths. Accessible from the file browser by clicking any text file.
- Syntax-aware editing with monospace font
- Binary file detection (prevents editing non-text files)
- File size limit (1MB) to prevent browser hangs
- Read-only mode for files without write permissions

### Cronjob Editor
Full CRUD management for cron jobs, both user and root crontabs.
- Add, edit, and delete cron entries via the UI
- Human-readable schedule descriptions (e.g. "Dagelijks om 03:00")
- Schedule validation with support for ranges (`1-10`), steps (`*/5`), range+step combos (`1-10/2`), and named values (`mon`, `jan`)
- Systemd timers overview

### Nginx Config Editor
Manage Nginx site configurations directly from the dashboard.
- Read and edit config files in `/etc/nginx/sites-available/`
- Enable/disable sites (symlink management)
- Built-in `nginx -t` validation before saving or enabling
- Nginx reload with return code verification

### Push Notifications for App Updates
The monitoring loop now checks GitHub for new VPS Manager releases and sends a push notification when an update is available.

## Improvements

- **Firewall**: Unban now also removes the corresponding UFW deny rule (matching the ban flow)
- **Firewall**: Removed duplicate banned IPs card from the dashboard
- **Config validation**: All nested config objects (`thresholds`, `ddos_detection`, `file_browser`, `services`) are type-checked before saving

## Security Fixes

- **File routes**: Permission check (`is_path_allowed`) now runs before file existence check, preventing information disclosure about files outside allowed paths
- **Nginx reload**: Return code of `systemctl reload nginx` is now checked in enable/disable routes — no more silent failures
- **Cron validator**: Fixed rejection of valid cron syntax (range+step like `1-10/2`, named values like `mon`, `jan`)
- **Config validation**: Added `isinstance` checks for all nested objects to prevent 500 errors on malformed input
- **Backup download**: Handles explicit `null` values in config for backup directories without crashing
- **Banned IPs**: SQLite temp file `chmod` return code is now checked before opening the database

## Audit Trail Coverage

Actions logged: `login`, `login_failed`, `logout`, `pm2_restart`, `pm2_stop`, `pm2_start`, `service_restart`, `service_start`, `service_stop`, `firewall_ban`, `firewall_unban`, `nginx_config_enable`, `nginx_config_disable`, `nginx_config_save`, `cronjob_add`, `cronjob_edit`, `cronjob_delete`, `file_save`, `config_update`
