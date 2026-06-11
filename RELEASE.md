# v1.9.0 — Production Server, Update Rollback & Bug Fixes

This release moves the dashboard to a production WSGI server, makes self-updates safe to fail, and fixes a series of bugs found during a full code audit.

## Highlights

### Production WSGI server
The app now serves via [waitress](https://docs.pylonsproject.org/projects/waitress/) instead of the Flask development server. Waitress is installed automatically through `requirements.txt` during the update; if it is somehow missing the app falls back to the dev server rather than failing to start. Update progress (SSE) streams per event.

### Self-update rollback watchdog
Updates installed from the Updates page are now guarded end-to-end:
- The updater already aborted **before** restarting if the download, file copy or `pip install` failed.
- New: right before restarting, it arms a detached watchdog that polls the new `/health` endpoint. If the freshly updated app never becomes healthy, the watchdog automatically rolls back to the previous commit, restarts, and the app records an audit entry plus a notification.

A broken release can no longer leave the dashboard unreachable.

### Manager state is now part of the backup
`vps-backup.sh` includes the manager's `data/` directory (settings, 2FA secret, session key, VAPID keys) as a separate tarball in `configs/`. Previously this data was in no backup at all — a disk failure meant a 2FA lockout and losing every push subscription.

## Security
- **TOTP replay protection** — each 2FA time step is accepted at most once; an observed code cannot be reused within its validity window
- **Session fixation protection** — the session is fully regenerated on every successful login
- **HSTS** — `Strict-Transport-Security` header added
- **File browser symlink handling** — all file routes resolve symlinks consistently for both the permission check and the actual access; deleting a symlink removes the link itself (deleting a directory symlink previously errored)

## Bug fixes
- A corrupt `config.json` is now logged and preserved as `config.json.corrupt` instead of being silently replaced with defaults
- `json_escape` in `nas-pull-backup.sh` escapes newlines/control characters, so failure reports containing rsync output no longer produce invalid JSON (which silently dropped exactly the error reports that mattered)
- `find | while` pipe subshells in `vps-backup.sh` hid copy errors from `set -e`/the ERR trap; the backup could report success on partial failure
- Firewall whitelist and UFW rule validation now accept IPv6 addresses and CIDR
- UFW table refresh errors show feedback instead of failing silently
- Login page uses the locally vendored Inter font (Google Fonts reference removed)

## Performance
- Per-site HTTP status checks (Nginx and Caddy) run in parallel instead of sequentially — with many sites, page load drops from the sum of all checks to the slowest single check
- Expired TTL/IP-geolocation cache entries are swept periodically instead of accumulating indefinitely

## Operations
- New unauthenticated `GET /health` endpoint for uptime monitoring, PM2 health checks and reverse proxy checks
- `requirements.txt` now pins bounded version ranges
- New CI workflow: syntax checks, critical lint and shell checks on every push
- Logrotate config shipped in `deploy/`
- Releases are now created automatically when a `v*` tag is pushed

## For existing backup script users
The backup scripts no longer contain environment-specific defaults (paths, usernames, hostnames). If you reinstall `vps-backup.sh` or `nas-pull-backup.sh`, set your own values in `.backup_env` — see the README ("Backup Monitoring") for a full example. Your currently installed scripts keep working unchanged.

## Updating
Go to **Updates** in the sidebar and click install, or update manually:

```bash
cd /var/www/vps-manager
git fetch origin && git reset --hard origin/main
venv/bin/pip install -r requirements.txt
pm2 restart vps-manager
```
