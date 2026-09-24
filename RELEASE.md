# v2.0.2 — NAS Pull Script Fix

A small fix for the NAS pull script. The dashboard and the VPS backup script are unchanged.

## Upgrading

Update in the app as usual. On the NAS, replace the pull script with the new `nas-pull-backup.sh`. Keep the file name your scheduled task uses, for example:

```bash
cp nas-pull-backup.sh /volume1/Backup/vps/pull-backup.sh
```

Nothing changes if you use the default `LOCAL_DIR` (`/volume1/Backup/vps`).

## Fix

- **`LOCAL_DIR` in the NAS `.backup_env` was only half applied.** The script worked out the data folder, snapshot folder, log and lock file from the default `/volume1/Backup/vps` before it read `.backup_env`. With your own `LOCAL_DIR` in that file, the pull still went into the default location. `.backup_env` is now read first, the same fix `vps-backup.sh` got in v2.0.1.
  - The script still looks for `.backup_env` itself in `/volume1/Backup/vps/`, or in `$LOCAL_DIR/` when `LOCAL_DIR` is set in the scheduled task's environment. If you keep it anywhere else, add `BACKUP_ENV=/path/to/.backup_env` to the task's command.
