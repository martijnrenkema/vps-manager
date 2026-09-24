#!/bin/bash
# =============================================================================
# NAS Pull Backup Script
# Pulls /var/backups/vps from the VPS to Synology NAS storage, verifies the
# checksum manifest, and keeps dated hard-link snapshots for point-in-time restore.
# Runs daily via Synology Task Scheduler: /bin/bash /volume1/Backup/vps/pull-backup.sh
# =============================================================================

set -Eeuo pipefail
umask 027

# Load overrides first: DATA_DIR, SNAPSHOT_DIR, LOG and LOCK_FILE are derived
# from LOCAL_DIR, so a LOCAL_DIR set in $BACKUP_ENV must be known before those
# are computed. The env file itself defaults to the default LOCAL_DIR.
BACKUP_ENV="${BACKUP_ENV:-${LOCAL_DIR:-/volume1/Backup/vps}/.backup_env}"
if [ -f "$BACKUP_ENV" ]; then
    # shellcheck disable=SC1090
    source "$BACKUP_ENV"
fi

# Connection/location settings: configure these in $BACKUP_ENV (see README)
# so the script itself stays generic.
VPS="${VPS:-backup@your-vps-hostname}"
SSH_PORT="${SSH_PORT:-22}"
LOCAL_DIR="${LOCAL_DIR:-/volume1/Backup/vps}"
DATA_DIR="$LOCAL_DIR/data"
SNAPSHOT_DIR="$LOCAL_DIR/snapshots"
LOG="${LOG:-$LOCAL_DIR/backup.log}"
WEBHOOK_URL="${WEBHOOK_URL:-https://your-dashboard-domain/api/backup/webhook}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
# Always keep at least this many of the newest snapshots, regardless of age
KEEP_MIN_SNAPSHOTS="${KEEP_MIN_SNAPSHOTS:-3}"
# Report failure when the newest VPS checksum manifest is older than this
# (the VPS backup stopped running); the pull itself still verifies/snapshots.
# 8 days tolerates a weekly VPS backup; set 2 for a daily one. 0 disables.
MAX_BACKUP_AGE_DAYS="${MAX_BACKUP_AGE_DAYS:-8}"
LOCK_FILE="$LOCAL_DIR/.pull-backup.lock"

WEBHOOK_SECRET="${WEBHOOK_SECRET:-}"

mkdir -p "$DATA_DIR" "$SNAPSHOT_DIR" "$(dirname "$LOG")"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    msg="NAS pull skipped - previous run still active"
    echo "$(date): $msg" >> "$LOG"
    exit 1
fi

json_escape() {
    # Also escape newlines/tabs/CR: multi-line details (e.g. rsync output on
    # failure) would otherwise break the JSON, losing exactly the error
    # reports that matter most. awk instead of python: Synology lacks python3.
    printf '%s' "$1" | awk '
        {
            line = $0
            gsub(/\\/, "\\\\", line)
            gsub(/"/, "\\\"", line)
            gsub(/\t/, "\\t", line)
            gsub(/\r/, "\\r", line)
            out = out (NR > 1 ? "\\n" : "") line
        }
        END { printf "%s", out }
    '
}

webhook_secret_config() {
    # curl config syntax: a quoted value, with \ and " escaped; newlines dropped
    local v
    v=$(printf '%s' "$WEBHOOK_SECRET" | tr -d '\r\n')
    v=${v//\\/\\\\}
    v=${v//\"/\\\"}
    printf 'header = "X-Webhook-Secret: %s"\n' "$v"
}

report_status() {
    local status="$1"
    local details="$2"
    [ -n "$WEBHOOK_SECRET" ] || return 0
    local escaped
    escaped=$(json_escape "$details")
    # The secret goes to curl as a config file on stdin (-K -), not as a
    # command-line argument, where every local user could read it in `ps`.
    # -K - works on all curl versions (unlike -H @file, which needs >= 7.55).
    webhook_secret_config | curl -s -K - -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "{\"status\": \"$status\", \"details\": \"$escaped\"}" > /dev/null 2>&1 || true
}

fail() {
    local msg="$1"
    echo "$(date): $msg" >> "$LOG"
    report_status "failure" "$msg"
    exit 1
}

report_failure() {
    fail "NAS pull failed at line $1: $2"
}
trap 'report_failure $LINENO "$BASH_COMMAND"' ERR

echo "$(date): Start backup pull" >> "$LOG"

RSYNC_OUTPUT_FILE="$LOCAL_DIR/.rsync-output.$$"
VERIFY_OUTPUT_FILE="$LOCAL_DIR/.verify-output.$$"
trap 'rm -f "$RSYNC_OUTPUT_FILE" "$VERIFY_OUTPUT_FILE"' EXIT

trap - ERR
set +e
rsync -avz --delete --delay-updates --stats \
    --exclude='.vps-backup.lock' \
    --exclude='*.tmp' \
    -e "ssh -p $SSH_PORT -o BatchMode=yes -o ConnectTimeout=30" \
    "$VPS:/var/backups/vps/" "$DATA_DIR/" > "$RSYNC_OUTPUT_FILE" 2>&1
RSYNC_EXIT=$?
set -e
trap 'report_failure $LINENO "$BASH_COMMAND"' ERR

cat "$RSYNC_OUTPUT_FILE" >> "$LOG"

if [ "$RSYNC_EXIT" -ne 0 ]; then
    fail "NAS pull failed - rsync exit code: $RSYNC_EXIT"
fi

TOTAL_SIZE=$(du -sh "$DATA_DIR/" | cut -f1)
TRANSFERRED=$(awk -F: '/Total transferred file size/ {gsub(/^[ \t]+| bytes|,/,"",$2); print $2}' "$RSYNC_OUTPUT_FILE" | tail -1)
SPEEDUP=$(awk '/speedup is/ {print $NF}' "$RSYNC_OUTPUT_FILE" | tail -1)

LATEST_CHECKSUM=$(ls -t "$DATA_DIR"/checksums_*.sha256 2>/dev/null | head -1 || true)
[ -n "$LATEST_CHECKSUM" ] || fail "NAS pull failed - no checksum file found"

pushd "$DATA_DIR" > /dev/null
trap - ERR
set +e
sha256sum -c "$(basename "$LATEST_CHECKSUM")" > "$VERIFY_OUTPUT_FILE" 2>&1
VERIFY_EXIT=$?
set -e
trap 'report_failure $LINENO "$BASH_COMMAND"' ERR

TOTAL=$(wc -l < "$(basename "$LATEST_CHECKSUM")")
FAILED=$(grep -c "FAILED" "$VERIFY_OUTPUT_FILE" || true)
PASSED=$((TOTAL - FAILED))
popd > /dev/null

if [ "$VERIFY_EXIT" -ne 0 ]; then
    tail -40 "$VERIFY_OUTPUT_FILE" >> "$LOG"
    fail "NAS pull failed - checksum verification failed: $PASSED/$TOTAL OK, $FAILED FAILED"
fi

CHECKSUM_RESULT="$TOTAL/$TOTAL checksums OK"

SNAPSHOT_NAME=$(date +%Y%m%d)
SNAPSHOT_PATH="$SNAPSHOT_DIR/$SNAPSHOT_NAME"
# Leftovers of interrupted runs (any date)
find "$SNAPSHOT_DIR" -maxdepth 1 -mindepth 1 -type d -name '*.tmp' -exec rm -rf {} +
rm -rf "$SNAPSHOT_PATH"
cp -al "$DATA_DIR" "$SNAPSHOT_PATH.tmp"
mv "$SNAPSHOT_PATH.tmp" "$SNAPSHOT_PATH"
# cp -al keeps DATA_DIR's mtime, which rsync -a copies from the VPS directory.
# Without this touch a snapshot's age is the age of the VPS data, so when the
# VPS backup stopped for > RETENTION_DAYS every snapshot was pruned at once.
touch "$SNAPSHOT_PATH"

# Prune by age, but never the KEEP_MIN_SNAPSHOTS newest (names are YYYYMMDD,
# so glob order is chronological; iterate newest first).
snapshots=( "$SNAPSHOT_DIR"/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9] )
kept=0
for (( i = ${#snapshots[@]} - 1; i >= 0; i-- )); do
    snap="${snapshots[$i]}"
    [ -d "$snap" ] || continue
    kept=$((kept + 1))
    [ "$kept" -le "$KEEP_MIN_SNAPSHOTS" ] && continue
    if [ -n "$(find "$snap" -maxdepth 0 -mtime +"$RETENTION_DAYS")" ]; then
        rm -rf "$snap"
    fi
done

SNAPSHOT_COUNT=$(find "$SNAPSHOT_DIR" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)
message="NAS pull completed - $TOTAL_SIZE on disk - transferred: ${TRANSFERRED:-unknown} bytes - speedup: ${SPEEDUP:-n/a} - $CHECKSUM_RESULT - snapshots: $SNAPSHOT_COUNT"

# A verified but old manifest means the VPS backup itself stopped running:
# don't report that as a healthy backup. MAX_BACKUP_AGE_DAYS=0 disables this.
if [ "$MAX_BACKUP_AGE_DAYS" -gt 0 ] && [ -n "$(find "$LATEST_CHECKSUM" -maxdepth 0 -mtime +"$((MAX_BACKUP_AGE_DAYS - 1))")" ]; then
    fail "NAS pull OK but VPS backup is stale - newest manifest $(basename "$LATEST_CHECKSUM") is older than $MAX_BACKUP_AGE_DAYS days - $message"
fi
echo "$(date): $message" >> "$LOG"
report_status "success" "$message"
