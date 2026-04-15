#!/bin/bash
# =============================================================================
# NAS Pull Backup Script
# Pulls /var/backups/vps from the VPS to Synology NAS storage, verifies the
# checksum manifest, and keeps dated hard-link snapshots for point-in-time restore.
# Runs daily via Synology Task Scheduler: /bin/bash /volume1/Backup/vps/pull-backup.sh
# =============================================================================

set -Eeuo pipefail
umask 027

VPS="${VPS:-martijn@212.227.135.150}"
SSH_PORT="${SSH_PORT:-2222}"
LOCAL_DIR="${LOCAL_DIR:-/volume1/Backup/vps}"
DATA_DIR="$LOCAL_DIR/data"
SNAPSHOT_DIR="$LOCAL_DIR/snapshots"
LOG="${LOG:-$LOCAL_DIR/backup.log}"
WEBHOOK_URL="${WEBHOOK_URL:-https://vps.dmmusic.nl/api/backup/webhook}"
BACKUP_ENV="${BACKUP_ENV:-$LOCAL_DIR/.backup_env}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
LOCK_FILE="$LOCAL_DIR/.pull-backup.lock"

WEBHOOK_SECRET="${WEBHOOK_SECRET:-}"
if [ -f "$BACKUP_ENV" ]; then
    # shellcheck disable=SC1090
    source "$BACKUP_ENV"
fi
WEBHOOK_SECRET="${WEBHOOK_SECRET:-}"

mkdir -p "$DATA_DIR" "$SNAPSHOT_DIR" "$(dirname "$LOG")"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    msg="NAS pull skipped - previous run still active"
    echo "$(date): $msg" >> "$LOG"
    exit 1
fi

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

report_status() {
    local status="$1"
    local details="$2"
    [ -n "$WEBHOOK_SECRET" ] || return 0
    local escaped
    escaped=$(json_escape "$details")
    curl -s -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -H "X-Webhook-Secret: $WEBHOOK_SECRET" \
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
rm -rf "$SNAPSHOT_PATH.tmp"
rm -rf "$SNAPSHOT_PATH"
cp -al "$DATA_DIR" "$SNAPSHOT_PATH.tmp"
mv "$SNAPSHOT_PATH.tmp" "$SNAPSHOT_PATH"
find "$SNAPSHOT_DIR" -maxdepth 1 -mindepth 1 -type d -mtime +"$RETENTION_DAYS" -exec rm -rf {} +

SNAPSHOT_COUNT=$(find "$SNAPSHOT_DIR" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)
message="NAS pull completed - $TOTAL_SIZE on disk - transferred: ${TRANSFERRED:-unknown} bytes - speedup: ${SPEEDUP:-n/a} - $CHECKSUM_RESULT - snapshots: $SNAPSHOT_COUNT"
echo "$(date): $message" >> "$LOG"
report_status "success" "$message"
