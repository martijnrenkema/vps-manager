# v1.10.1 — Critical Fix: In-App Updater Broken Since v1.9.0

## ⚠️ One-time manual update required

**The in-app updater in v1.9.0 and v1.10.0 is broken** — clicking *Install update* fails immediately and nothing installs. To get this fix you must update **manually once**:

```bash
cd /var/www/vps-manager
git fetch origin && git reset --hard origin/main
venv/bin/pip install -r requirements.txt
pm2 restart vps-manager
```

From this version on, in-app updates work again.

## What was broken

The self-update progress stream set a `Connection: keep-alive` response header. That is a hop-by-hop header that WSGI applications are not allowed to set (PEP 3333). The Flask dev server tolerated it, but **waitress — the production server introduced in v1.9.0 — rejects it with an error before a single byte is sent**. The result: clicking *Install update* made the progress stream fail instantly with HTTP 500, the page showed nothing (or briefly "Connection lost"), and no update was installed.

## Fixes
- **Removed the hop-by-hop `Connection` header** from the update progress stream; the in-app updater works under waitress again
- **Update lock could leak** — if the stream failed before starting, the update lock was never released, so every retry (including apt updates from the dashboard) reported "Another update operation is already running" until a restart. The lock is now acquired inside the stream and always released
- **Silent failure in the update UI** — if fetching the one-time stream token failed (e.g. expired session), the progress stepper appeared and then nothing happened, with no error. It now shows a clear error message

## Included from v1.10.0

If you are coming from v1.9.0, this update also brings everything from v1.10.0:

- **Security Audit page** — nine read-only hardening checks (SSH root login & password auth, UFW, fail2ban, unattended-upgrades, pending security updates, pending reboot, dashboard 2FA, backup freshness, unexpected public ports) with a score and concrete recommendations
- **Self-healing services (opt-in)** — the monitor automatically restarts a down service (capped per service per 24h) with audit logging and notifications
- **Predictive disk-full alert** — warns when `/` is projected to be full within 14 days based on the metrics growth trend
- **Reboot-required alert** and a **health score (0–100)** on the dashboard
- **Bug fixes** — dashboard restart button 404'd, monitor loop skipped its pause after the first cycle, IPv6 bans unmanageable, HTTP 500 on non-ASCII 2FA codes, websites page crash on an nginx log directive without a value, push preferences for an unknown device reported success

See the [v1.10.0 release notes](https://github.com/martijnrenkema/vps-manager/releases/tag/v1.10.0) for details.
