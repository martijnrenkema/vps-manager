# v2.3.0 — New Look & Quieter Alerts

VPS Manager now has the same look as muxdeck and the regiekamer. It no longer sends alerts for services that automatic updates restart on purpose. This release also fixes a set of bugs from a new review round.

## Upgrading

Update in the app as usual. After the update:

- **Reload any open VPS Manager tab** to get the new style everywhere.
- **Backup scripts changed.** If you use `vps-backup.sh` or `nas-pull-backup.sh`, copy the new versions to where your cron jobs run them (see the README). The old scripts keep working, but they lack the fixes below.

## What's new

**New look.** The interface uses the palette of muxdeck and the regiekamer:

- Slate neutrals, flat panels with a thin edge, and 8px corners.
- Teal as the one accent, for links, focus and primary buttons.
- Status colours keep one meaning each: green is fine, amber needs attention, red is wrong.
- The sidebar marks the current page with a teal bar, and group headers are small caps.
- Usage bars are teal until they cross a threshold, and large figures are lighter.
- The light theme follows the same palette.

**System fonts.** IBM Plex is replaced by the system font stack, the same one muxdeck uses. Pages no longer download web fonts.

**No more false alerts during updates.** Automatic updates (unattended-upgrades with needrestart) restart every service that uses an updated library. fail2ban can take over a minute to stop, and a monitor check in that window sent an e-mail like "Service 'fail2ban' is deactivating". Now:

- Service and PM2 alerts are held, and self-healing waits, while apt, dpkg, unattended-upgrade or needrestart runs.
- A service in the middle of a restart (`activating`, `deactivating`) gets up to 150 seconds to finish before it counts as down.
- Anything still down after the update is reported on the next check, as before.
- If the package manager hangs for more than an hour, alerts are no longer held.

**Backup: extra SQLite databases and config files.** List them in `.backup_env` (absolute paths, separated by spaces) to back up apps that live outside `/var/www`:

```bash
EXTRA_SQLITE_DBS="/opt/bugsink/data/db.sqlite3"
EXTRA_CONFIG_PATHS="/opt/bugsink/bugsink_conf.py"
```

Each database is snapshotted safely while the app runs and checked with `PRAGMA integrity_check`. A failed backup now starts its alert with the reason (`Backup incomplete: ...`), so you can see it in the notification itself.

## Fixes

- **Updates history missed automatic upgrades.** The unattended-upgrades log is only readable by root and group `adm`, so the history never showed them.
- **Backup page looked empty** when the backup log, `databases/` or `configs/` were root-only. You got no latest log, "No backup directory found" and no database dumps in the download list.
- **False SSL expiry alert on Caddy.** An older certificate from another issuer (for example staging, or the ZeroSSL fallback) could count instead of the valid one.
- **fail2ban whitelist could be wiped** by a save request without a valid list of IPs. Such requests are now rejected.
- **Template units** such as `postgresql@16-main` could not be saved in Settings, restarted from the Services page or restarted by self-healing.
- **NAS pull**: the VPS backup directory can be set with `REMOTE_DIR` in the NAS `.backup_env`.
- **Cronjobs**: Escape on the save confirmation also closed the edit dialog and lost your input.
- **Notifications**: e-mail preferences were not saved when this device's push subscription no longer existed on the server.
