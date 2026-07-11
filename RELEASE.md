# v1.10.0 — Security Audit, Self-Healing Services & Smarter Alerts

This release makes the dashboard proactive: it audits the server's hardening, can heal failed services on its own, and warns about problems before they happen — plus a round of bug fixes from a full code review.

## Highlights

### Security Audit page
A new **Security Audit** page (sidebar → Security) runs nine read-only hardening checks and scores the result:

- SSH: root login and password authentication (from the effective `sshd -T` config)
- UFW firewall active
- fail2ban running
- Automatic security updates (unattended-upgrades) enabled
- Pending security updates
- Pending reboot (kernel/libc updates waiting for a restart)
- Two-factor authentication enabled on the dashboard itself
- Backup freshness (last successful backup within 48h)
- Unexpected publicly listening ports (anything other than SSH/HTTP/HTTPS bound to 0.0.0.0)

Every finding comes with a concrete recommendation. Failures sort to the top, and a *Re-run audit* button refreshes all checks on demand. The audit never changes anything — it only reports.

### Self-healing services (opt-in)
When enabled, the monitor automatically restarts a monitored service that goes down, capped per service per 24 hours (default 3×). Each restart is recorded in the audit log and sent as a notification; a service that keeps failing triggers a "gave up" alert so a human takes over instead of an endless restart loop. Configure it on the Security Audit page. Disabled by default.

### Predictive disk-full alert
The monitor already collects disk usage every 5 minutes; a linear fit over that history now projects when `/` will be full. You get a warning when that is within 14 days and an error within 3 days — before the disk actually fills up, not after. Slow growth (< 0.1%/day) and short histories deliberately produce no forecast, so noise is never extrapolated.

### Health score
The dashboard shows an overall health score (0–100) computed from the active alerts — errors weigh heaviest — with a color-coded label, so one glance tells you whether anything needs attention.

## New
- **Reboot-required alert** — when `/var/run/reboot-required` exists (e.g. after a kernel update), the dashboard shows an alert and the daily update notification includes it
- `GET /api/security/audit` endpoint and `security` section for `/api/refresh/`

## Bug fixes
- **Dashboard restart button never worked** — it called `/service/<name>/restart` while the route is `/services/restart/<name>`; every click was a silent 404
- **Monitor loop skipped its pause after the first cycle** — after seeding existing alerts at startup, `continue` bypassed the pacing sleep and immediately started a second full monitoring cycle
- **IPv6 addresses could not be banned/unbanned** — fail2ban bans IPv6 too, but the firewall ban/unban endpoints only accepted IPv4, making those bans unmanageable from the UI
- **HTTP 500 on non-ASCII 2FA codes** — `hmac.compare_digest` raises `TypeError` on non-ASCII strings; TOTP and email code verification now compare bytes and correctly answer "Invalid code"
- **Websites page could crash on a config edge case** — an nginx `access_log`/`error_log` directive without a value caused an `IndexError` that broke the whole site list
- **Saving push preferences for an unknown device reported success** — now returns 404, consistent with the per-device endpoint

## Updating
Go to **Updates** in the sidebar and click install, or update manually:

```bash
cd /var/www/vps-manager
git fetch origin && git reset --hard origin/main
venv/bin/pip install -r requirements.txt
pm2 restart vps-manager
```
