#!/bin/bash
# =============================================================================
# Update watchdog
# Spawned (detached) by the in-app updater right before it restarts the app.
# Polls the /health endpoint; if the freshly updated app never becomes
# healthy, rolls back to the previous git commit and restarts again.
#
# Args: APP_DIR PREV_COMMIT PORT LOG_FILE MARKER_FILE
# Env:  VPS_MANAGER_HOST / VPS_MANAGER_PORT (same as the app) pick the address
#       that is probed; PORT (arg 3) takes precedence over VPS_MANAGER_PORT.
# =============================================================================
set -u

APP_DIR="${1:?usage: update-watchdog.sh APP_DIR PREV_COMMIT [PORT] [LOG] [MARKER]}"
PREV_COMMIT="${2:?missing previous commit}"
PORT="${3:-${VPS_MANAGER_PORT:-5050}}"
LOG="${4:-/tmp/vps-manager-watchdog.log}"
MARKER="${5:-}"

# Probe the address the app actually binds to. A wildcard/empty bind is
# reachable on loopback; a specific IP (VPS_MANAGER_HOST=10.0.0.5) is not,
# and probing 127.0.0.1 there caused a false rollback of a healthy update.
PROBE_HOST="${VPS_MANAGER_HOST:-127.0.0.1}"
case "$PROBE_HOST" in
    ""|0.0.0.0|"*") PROBE_HOST="127.0.0.1" ;;
    ::|"[::]") PROBE_HOST="[::1]" ;;
    \[*) ;;
    *:*) PROBE_HOST="[$PROBE_HOST]" ;;   # bare IPv6 literal needs brackets
esac
HEALTH_URL="http://${PROBE_HOST}:${PORT}/health"

# Overridable for testing; production defaults wait ~70s total
BOOT_WAIT="${WATCHDOG_BOOT_WAIT:-10}"
RETRIES="${WATCHDOG_RETRIES:-12}"
INTERVAL="${WATCHDOG_INTERVAL:-5}"

log() { echo "$(date '+%F %T'): watchdog: $*" >> "$LOG"; }

# One watchdog at a time: two updates in quick succession would otherwise run
# two watchdogs that each reset to a different commit. A later watchdog waits
# for the earlier one and then judges the app state it left behind.
LOCK_BASE="$(dirname "${MARKER:-$LOG}")/.update-watchdog"
LOCK_WAIT=$(( BOOT_WAIT + RETRIES * (INTERVAL + 3) * 2 + 120 ))
if command -v flock >/dev/null 2>&1; then
    exec 8>"$LOCK_BASE.lock"
    if ! flock -w "$LOCK_WAIT" 8; then
        log "another watchdog still running after ${LOCK_WAIT}s - giving up"
        exit 1
    fi
else
    waited=0
    until mkdir "$LOCK_BASE.lockdir" 2>/dev/null; do
        holder=$(cat "$LOCK_BASE.lockdir/pid" 2>/dev/null)
        if [ -n "$holder" ] && ! kill -0 "$holder" 2>/dev/null; then
            rm -rf "$LOCK_BASE.lockdir"   # stale lock of a dead watchdog
            continue
        fi
        if [ "$waited" -ge "$LOCK_WAIT" ]; then
            log "another watchdog still running after ${LOCK_WAIT}s - giving up"
            exit 1
        fi
        sleep 2
        waited=$((waited + 2))
    done
    echo $$ > "$LOCK_BASE.lockdir/pid"
    trap 'rm -rf "$LOCK_BASE.lockdir"' EXIT
fi

wait_healthy() {
    local _
    for _ in $(seq 1 "$RETRIES"); do
        if curl -sf --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then
            return 0
        fi
        sleep "$INTERVAL"
    done
    return 1
}

log "armed - will roll back to ${PREV_COMMIT:0:10} if $HEALTH_URL stays down"

# Give PM2 time to restart the app before the first probe
sleep "$BOOT_WAIT"

if wait_healthy; then
    log "update OK - app is healthy"
    exit 0
fi

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

# Marker zodat de app de rollback kan melden (audit log + notificatie).
# Must exist before the restart: the app reads and removes it at startup.
if [ -n "$MARKER" ]; then
    echo "rolled back to $PREV_COMMIT at $(date -Is)" > "$MARKER" 2>>"$LOG" || true
fi

# 8>&- : if pm2 has to (re)spawn its daemon, it must not inherit the lock fd
if ! pm2 restart vps-manager >> "$LOG" 2>&1 8>&-; then
    log "rollback: pm2 restart failed"
fi

sleep "$BOOT_WAIT"
if wait_healthy; then
    log "rollback complete - previous version restarted and healthy"
    # Marker is normally consumed by the restarted app already; only annotate
    # it if it is still there.
    if [ -n "$MARKER" ] && [ -f "$MARKER" ]; then
        echo "health check after rollback: OK" >> "$MARKER" 2>>"$LOG" || true
    fi
    exit 0
fi

log "rollback FAILED health check - $HEALTH_URL still down after restoring $PREV_COMMIT, manual action needed"
# Appending (re)creates the marker if the app consumed it before dying, so the
# next successful start still reports that the rollback did not recover.
if [ -n "$MARKER" ]; then
    echo "health check after rollback FAILED at $(date -Is) - manual action needed" >> "$MARKER" 2>>"$LOG" || true
fi
exit 1
