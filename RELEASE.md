# v2.2.0 — Calmer Pages & Bug Fix Round

This release makes the busiest pages easier to read and fixes a long list of bugs found in a full review of the app, including a few security issues that a logged-in user could trigger.

## Upgrading

Update in the app as usual. After the update:

- **Reload any open VPS Manager tab** (especially Firewall and Cronjobs). A page loaded before the update may refuse the first delete or edit with "changed since the page was loaded".
- **Backup scripts changed.** If you use `vps-backup.sh` or `nas-pull-backup.sh`, copy the new versions to where your cron jobs run them (see the README).
- **You may get a few notifications right after the update** for alerts that were already active. See "Missed alerts after a restart" below.

## What's new

**Collapsible sections.** Advanced and rarely used parts are folded away by default, so each page starts with what you look at most:

- **Settings**: thresholds, web server and monitored services stay open; monitor timing, session, DDoS detection, phpMyAdmin and all path settings are collapsed. 2FA and e-mail collapse once they are set up. If a field is invalid, its section opens by itself.
- **Firewall**: rules, fail2ban status and banned IPs stay open; add rule, jail configuration, DDoS detection, SSH sessions, ban form and whitelist are collapsed.
- **Backup**: the download tables now come directly under the health card; NAS pull details, run history and the raw log are collapsed.
- Also on SSH logs, Updates, PHP, Cronjobs, Notifications, Network and Security audit.

Headers show a short status ("No attack detected", "2FA active"), and each section remembers whether you left it open.

## Fixes

### Monitoring and alerts

- **Missed alerts after a restart.** When the notification log was empty, the first monitor run after every start marked all active alerts as "already sent". A service that failed to start after a reboot was then never reported.
- **Stopped services vanished from the list.** Auto-discovered services (PHP-FPM versions not in your config, ssh, cron, ufw) disappeared when they went down, with no alert and no self-healing. Template instances such as `postgresql@16-main` can now be monitored.
- **Stopping a slow service** (e.g. MariaDB) from the Services page could be undone by self-healing.
- Checks no longer depend on the system language (UFW status, memory and swap).
- A failed `apt` or disk measurement is no longer shown as "no updates" or an empty list.

### Backup

- **The Backup page stayed green** after a failed run if an earlier run had succeeded.
- **The webhook example** was missing the required `X-Webhook-Secret` header.
- **NAS pull failed every day** for sites that contain `.tmp` files.
- A file that disappears during the VPS backup no longer aborts the whole run.

### Security

- **fail2ban whitelist**: an entry could carry line breaks into `jail.local`.
- **File browser and backup download**: downloading, recursively changing or deleting a folder that contains the VPS Manager installation no longer exposes or touches its own config and secrets. The backup directory and log path settings are validated more strictly.
- **Terminal**: `sudo` commands no longer accept quotes, `$`, backslashes or braces. This also blocks a few harmless forms such as `sudo grep "two words" file`; run those without quotes or use the matching page.
- **Top attacking IPs** could be spoofed through the username of an SSH login attempt, which put an arbitrary address next to a Ban button.

### Firewall

- The lock-out confirmation now also appears when you delete an SSH rule limited to your own address, or deny the SSH port for a network that includes it.
- A `22/udp` rule no longer counts as an SSH rule. Rules with logging are read correctly.
- Unban reports a partial result instead of an error when only the UFW rule was removed.

### Other

- **Updates**: "Check" now really checks instead of reloading the cached list, and the page refreshes after an install.
- **Cronjobs**: commands keep their exact whitespace, "Run now" follows cron's `%` rules, and the dialog keeps what you typed when saving fails.
- **Caddy**: sites with a placeholder address (`{$DOMAIN}`) no longer produce phantom sites or misplaced log blocks, and the Config link opens the file the site is defined in.
- **SSL**: the page uses your configured warning thresholds, like the dashboard. "Renew All" is now "Renew Due", which is what it does.
- **Files**: a second upload no longer cancels the first; the permissions dialog works for files owned by system users.
- Stop/Start buttons follow the new state, audit log filters cover their whole category, and several errors on malformed input are gone.
