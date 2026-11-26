# v2.3.2 — Quieter Alerts and Separate Backup Status

Fewer false notifications, and a failed backup can no longer hide behind a successful NAS pull.

## Upgrading

Update in the app as usual. Then, if you use the backup scripts:

- **Reinstall the backup scripts** to get the new SQLite handling and the `source` field: `sudo install -m 750 web/vps-backup.sh /usr/local/bin/vps-backup.sh` on the server, and copy `web/nas-pull-backup.sh` to your NAS. Old copies keep working; their reports are assigned by their text.
- **`EXTRA_SQLITE_DBS` backups get new file names** that keep the full file name (`opt_app_data_db.sqlite3_DATE.sqlite.gz` instead of `opt_app_data_db_DATE.sqlite.gz`). Old files expire through retention as usual.
- **Optional: rotate the PM2 logs.** See `deploy/logrotate-vps-manager-pm2` and the Backup setup section in the README.

Backup alerts get new keys per source. An alert that is active during the upgrade may be sent once more, and a dismissed backup alert may come back once.

## What's new

**Quieter alerts.**
- The load alert uses the 15-minute average instead of the 1-minute one, so short peaks from cron jobs or backups no longer send a notification.
- Load, RAM and swap alerts are no longer re-sent every time their number changes.
- The app's own update check no longer delays alerts, and "self-healing gave up" is not re-sent after a long update.

**Separate backup status.**
- The VPS backup and the NAS pull each have their own last success and failure, on the Backup page, in the alerts and in the security audit.
- Webhook updates are locked and written atomically.

**Safer SQLite backups.**
- Databases under `/var/www` are snapshotted as their owner, with an integrity check, so no root-owned `-wal`/`-shm` files are left behind.
- Relative `EXTRA_*` paths are rejected with a warning.
- `db.sqlite` and `db.sqlite3` in one folder no longer overwrite each other.

**For other setups.**
- The nginx pages use the Sites enabled / Sites available directories from Settings.
- SSH logs fall back to the systemd journal when there is no `auth.log` (Debian 12).
- The SSL warning colours agree on the boundary day everywhere.
