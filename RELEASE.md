# v2.0.0 — New Design, Much Faster, Security & Reliability Overhaul

A major release: a redesigned interface with dark and light themes, pages that load in milliseconds instead of seconds, and fixes for dozens of bugs and security issues found in three rounds of code review, regression testing and a full upgrade simulation.

## Upgrading from v1.10.x

The in-app updater handles this release like any other. Open **Updates**, click **Install update** and the page reloads by itself. The upgrade was tested end to end from v1.10.2, through both the progress stream and the fallback install. If the new version doesn't come up healthy, the rollback watchdog restores v1.10.x automatically.

**What carries over automatically:**
- You stay logged in.
- Settings, 2FA, push subscriptions and history are kept.
- Tabs left open keep working.

**Steps to do by hand after updating:**
- **Reinstall the backup script** if you use it. It is installed separately, so the in-app update does not replace it:
  ```bash
  sudo install -m 750 /var/www/vps-manager/vps-backup.sh /usr/local/bin/vps-backup.sh
  ```
  On the NAS, copy the new `nas-pull-backup.sh` as well.
- **Optional:** delete the leftover font file `static/vendor/fonts/inter-latin.woff2`.

**Changes you may notice:**
- **Email TLS certificates are now checked** on new installs. Your existing SMTP setup keeps its current behaviour, and the Security Audit suggests turning the check on under **Settings → SMTP → Verify TLS certificate**.
  - If you use email 2FA, press **Test** first. With a self-signed mail server, leave the check off, or you will no longer receive login codes.
- **Changing your password or 2FA now logs out every other session**, including the installed app on your phone.
- **`sudo` in the web terminal only allows read-only commands**, such as `sudo cat` and `sudo systemctl status`. Several allowed commands could previously be used to get a root shell. Manage services, the firewall, updates and cron from their own pages.
- **The file browser no longer opens the VPS Manager folder itself.** That folder holds the session key, `config.json` and `.env`.
- **Settings are validated more strictly.** Backup folders inside system directories (`/etc`, `/root`, `/var/lib`, …) or inside the manager's own folder are refused. Existing values keep working; you only get an error when you change one of them.
- **A dismissed dashboard alert now comes back if the problem returns.** Before, dismissing "nginx is down" hid every future nginx outage.
- **Alerts are categorised by their type instead of their text.** For example, "High connection count" now falls under DDoS. Right after updating you may get one notification for an alert that is newly in a category you have turned on. "Server reboot required" is now sent on its own instead of being swallowed by the daily updates notification.
- **Installing system updates** from the Updates page now runs non-interactively and keeps your existing config files.
- **Caddy:** disabling a site is refused when your Caddyfile uses `import sites/*`, because Caddy loads `.disabled` files with that pattern too. Use `import sites/*.caddy` or similar.

## What's new

- **New design.** A calmer interface that uses colour only for status. There are dark and light themes: it follows your system setting, or you pick one with the toggle.
  - Sidebar status hints show problems at a glance, e.g. `PM2 1 err`, `SSL 9d`, `Services 1 off`.
  - New dashboard: a "Needs attention" list with the health score, one resources panel with 1h/6h/24h ranges, and tables where problems are listed first.
  - Self-hosted IBM Plex fonts; no external resources at all.
- **Much faster.** Slow checks (apt, certbot, HTTP checks, log scans, disk usage) are cached and refreshed in the background, so pages no longer wait for them. The dashboard loads its data in parallel.
  - Log pages read only the most recent part of large logs.
  - Static files are cached by the browser and responses are compressed.
- **Safer actions.**
  - Every Stop action asks for confirmation.
  - Reboot and Clear swap moved into a **Server actions** menu.
  - Cron and firewall edits check that nothing changed in the meantime, so they never hit the wrong line or rule.
  - Config editors can no longer save an empty or wrong file.
- **Sessions are revoked** when you change your password or 2FA.
- **Failed self-updates roll back** to the previous version instead of leaving a half-installed update.

## Notable fixes

- **Push notifications:** expired push subscriptions were never cleaned up.
- **nginx configs:** a config could keep growing with duplicate `access_log` lines, and saving could fail with "duplicate default server".
- **Backups:**
  - The backup script deleted the copies of `wp-config.php`/`.env` in the same run that created them.
  - Backup files are no longer readable by every local user.
- **Command palette:** pressing Enter ran Reboot without confirmation.
- **Dashboard and monitoring:**
  - Security updates could be hidden as "phased".
  - DDoS alerts fired for local (loopback) connections.
  - PM2 monitoring went blind when pm2 printed a warning.
- **Many HTTP 500 errors** on unusual input, binary output or non-UTF-8 logs are gone.

The full list of findings and fixes is in `ANALYSIS-2.0.0.md` in the repository.
