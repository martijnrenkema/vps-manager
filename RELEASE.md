# v1.10.2 — Update Button Fallback

## ⚠️ Coming from v1.9.0 or v1.10.0? One manual update required

The in-app updater in v1.9.0 and v1.10.0 is broken — clicking *Install update* fails immediately and nothing installs (see the [v1.10.1 release notes](https://github.com/martijnrenkema/vps-manager/releases/tag/v1.10.1)). To get out of that state, run this single line on your server (adjust the path if you installed elsewhere):

```bash
cd /var/www/vps-manager && git fetch origin && git reset --hard origin/main && venv/bin/pip install -r requirements.txt && pm2 restart vps-manager
```

That is the last manual update you will ever need — from this version on the button also has a safety net.

## What's new

- **The update button now falls back automatically** — if the live progress stream fails before delivering a single event (exactly what happened in v1.9.0/v1.10.0), the UI no longer gives up: it automatically installs the update through the plain install endpoint instead. You lose the step-by-step progress display in that case, but the update installs and the page reloads by itself. A future bug in the progress stream can therefore no longer strand anyone on an old version.

## Included from v1.10.1

- Fixed the in-app updater under waitress (hop-by-hop `Connection` header)
- Update lock no longer leaks when the stream fails to start
- Clear error message when the update token request fails

## Included from v1.10.0

- **Security Audit page** — nine read-only hardening checks with a score and recommendations
- **Self-healing services (opt-in)**, **predictive disk-full alert**, **reboot-required alert** and a **health score** on the dashboard
- Assorted bug fixes — see the [v1.10.0 release notes](https://github.com/martijnrenkema/vps-manager/releases/tag/v1.10.0)
