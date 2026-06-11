#!/bin/bash
# =============================================================================
# Update watchdog
# Spawned (detached) by the in-app updater right before it restarts the app.
# Polls the /health endpoint; if the freshly updated app never becomes
# healthy, rolls back to the previous git commit and restarts again.
#
# Args: APP_DIR PREV_COMMIT PORT LOG_FILE MARKER_FILE
# =============================================================================
set -u

APP_DIR="${1:?usage: update-watchdog.sh APP_DIR PREV_COMMIT [PORT] [LOG] [MARKER]}"
PREV_COMMIT="${2:?missing previous commit}"
PORT="${3:-5050}"
LOG="${4:-/tmp/vps-manager-watchdog.log}"
MARKER="${5:-}"

HEALTH_URL="http://127.0.0.1:${PORT}/health"

# Overridable for testing; production defaults wait ~70s total
BOOT_WAIT="${WATCHDOG_BOOT_WAIT:-10}"
RETRIES="${WATCHDOG_RETRIES:-12}"
INTERVAL="${WATCHDOG_INTERVAL:-5}"

log() { echo "$(date '+%F %T'): watchdog: $*" >> "$LOG"; }

log "armed - will roll back to ${PREV_COMMIT:0:10} if $HEALTH_URL stays down"

# Give PM2 time to restart the app before the first probe
sleep "$BOOT_WAIT"

for _ in $(seq 1 "$RETRIES"); do
    if curl -sf --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then
        log "update OK - app is healthy"
        exit 0
    fi
    sleep "$INTERVAL"
done

log "app not healthy after update - rolling back to $PREV_COMMIT"

cd "$APP_DIR" || { log "rollback FAILED: cannot cd to $APP_DIR"; exit 1; }

if ! git reset --hard "$PREV_COMMIT" >> "$LOG" 2>&1; then
    log "rollback FAILED: git reset error"
    exit 1
fi

# Same copy step as the updater: repo has files in web/, PM2 runs from root
if [ -d web ]; then
    for f in app.py config.py VERSION requirements.txt \
             vps-backup.sh nas-pull-backup.sh update-watchdog.sh; do
        [ -f "web/$f" ] && cp "web/$f" ./ 2>>"$LOG"
    done
    [ -d web/templates ] && cp -r web/templates/. templates/ 2>>"$LOG"
    [ -d web/static ] && cp -r web/static/. static/ 2>>"$LOG"
fi

# Marker zodat de app de rollback kan melden (audit log + notificatie)
if [ -n "$MARKER" ]; then
    echo "rolled back to $PREV_COMMIT at $(date -Is)" > "$MARKER" 2>>"$LOG" || true
fi

pm2 restart vps-manager >> "$LOG" 2>&1
log "rollback complete - previous version restarted"
