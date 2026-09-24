# v2.0.1 — Backup Script Fixes

A small release that fixes two problems in the backup script. The dashboard itself is unchanged. The README now has new screenshots of the v2.0 design.

![VPS Manager v2 dashboard](https://raw.githubusercontent.com/martijnrenkema/vps-manager/v2.0.1/docs/screenshots/dashboard-dark.png)

## Upgrading

Update in the app as usual (**Updates → Install update**). The backup script is installed separately, so **reinstall it by hand** afterwards:

```bash
sudo install -m 750 /var/www/vps-manager/vps-backup.sh /usr/local/bin/vps-backup.sh
```

Use your own path if the manager is not in `/var/www/vps-manager`, and check the note below.

**Did you edit `/usr/local/bin/vps-backup.sh` yourself?** For example, to change the default paths or the read user. Reinstalling overwrites those edits. Move them to `.backup_env` first (`BACKUP_READ_USER`, `SKIP_DIRS`, `MANAGER_DATA_DIR`, `BACKUP_DIR`, …). Otherwise the defaults come back, and a NAS that pulls as a non-root user can no longer read the backups.

**Manager installed somewhere other than `/var/www/vps-manager`?** The script looks for `.backup_env` in that default location. Pass the real path in `/etc/cron.d/vps-backup`, and set the matching directories in `.backup_env`:

```bash
0 3 * * * root BACKUP_ENV=/var/www/vps.example.com/data/.backup_env /usr/local/bin/vps-backup.sh
```
```bash
# .backup_env
SKIP_DIRS="html vps.example.com"
MANAGER_DATA_DIR=/var/www/vps.example.com/data
```

Run `sudo /usr/local/bin/vps-backup.sh` once afterwards (with `BACKUP_ENV=...` if needed) and check the backup status on the Backups page.

## Fixes

- **Settings in `.backup_env` were applied too late.** Some values were computed from the defaults before `.backup_env` was read. As a result:
  - With your own `SKIP_DIRS`, the `.env` and `wp-config.php` copies still came from the skipped directories.
  - With your own `BACKUP_DIR`, the checksum manifest and lock file were still written to `/var/backups/vps`.
- **Database users and grants are backed up again.** Before, a restore brought back every table but no database user or permission, so no site could connect to its database. The script now also writes `databases/_grants_DATE.sql.gz`. This uses MariaDB's `mysqldump --system=users`. On MySQL the script logs a warning and the backup continues.

To restore the users and grants after the databases:

```bash
zcat _grants_DATE.sql.gz | sudo mysql --force
```

`--force` is needed because the dump also contains accounts that already exist on a fresh server, such as `root`. Those lines fail harmlessly and the rest is still applied.
