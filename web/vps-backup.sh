#!/bin/bash
# =============================================================================
# VPS Backup Script
# Backs up restorable VPS data: site content, databases, web/server config,
# cron/systemd metadata, and checksums for NAS verification.
# Runs daily via cron: 0 3 * * * root /usr/local/bin/vps-backup.sh
# =============================================================================

set -Eeuo pipefail
umask 027

BACKUP_DIR="${BACKUP_DIR:-/var/backups/vps}"
DATE=$(date +%Y%m%d)
RETENTION_DAYS="${RETENTION_DAYS:-7}"
CHECKSUM_FILE="$BACKUP_DIR/checksums_$DATE.sha256"
LOG="${LOG:-/var/log/vps-backup.log}"
WEBHOOK_URL="${WEBHOOK_URL:-http://127.0.0.1:5050/api/backup/webhook}"
BACKUP_ENV="${BACKUP_ENV:-/var/www/vps.dmmusic.nl/data/.backup_env}"
WWW_DIR="${WWW_DIR:-/var/www}"
LOCK_FILE="$BACKUP_DIR/.vps-backup.lock"
BACKUP_READ_USER="${BACKUP_READ_USER:-martijn}"

# Directories in /var/www that are not backup targets.
# vps.dmmusic.nl is redeployable from git and contains the manager itself.
SKIP_DIRS="${SKIP_DIRS:-html vps.dmmusic.nl}"
SKIP_CONFIG_DIRS="${SKIP_CONFIG_DIRS:-$SKIP_DIRS}"

WEBHOOK_SECRET="${WEBHOOK_SECRET:-}"
if [ -f "$BACKUP_ENV" ]; then
    # shellcheck disable=SC1090
    source "$BACKUP_ENV"
fi
WEBHOOK_SECRET="${WEBHOOK_SECRET:-}"

mkdir -p "$BACKUP_DIR/databases" "$BACKUP_DIR/configs" "$BACKUP_DIR/sites" "$(dirname "$LOG")"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "$(date): Backup already running, exiting" >> "$LOG"
    exit 1
fi

json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()))'
}

report_status() {
    local status="$1"
    local details="$2"
    [ -n "$WEBHOOK_SECRET" ] || return 0
    local escaped
    escaped=$(printf '%s' "$details" | json_escape)
    curl -s -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -H "X-Webhook-Secret: $WEBHOOK_SECRET" \
        -d "{\"status\": \"$status\", \"details\": $escaped}" > /dev/null 2>&1 || true
}

report_failure() {
    local err_msg="Backup failed at line $1: $2"
    echo "$(date): $err_msg" >> "$LOG"
    report_status "failure" "$err_msg"
}
trap 'report_failure $LINENO "$BASH_COMMAND"' ERR

is_listed() {
    local needle="$1"
    local item
    for item in $2; do
        [ "$item" = "$needle" ] && return 0
    done
    return 1
}

safe_rsync() {
    rsync -a --delete --delete-excluded \
        --exclude='.git/' \
        --exclude='.hg/' \
        --exclude='.svn/' \
        --exclude='.claude/' \
        --exclude='__pycache__/' \
        --exclude='*.pyc' \
        --exclude='.DS_Store' \
        --exclude='._*' \
        --exclude='node_modules/' \
        --exclude='venv/' \
        --exclude='.venv/' \
        --exclude='env/' \
        --exclude='.cache/' \
        --exclude='cache/' \
        --exclude='*.log' \
        "$@"
}

# =============================================================================
# DATABASES - MariaDB and SQLite data
# =============================================================================
SYSTEM_DBS="information_schema|performance_schema|mysql|sys"
DATABASES=$(mysql -N -e "SHOW DATABASES" 2>/dev/null | grep -Ev "^($SYSTEM_DBS)$" || true)
DB_COUNT=0

dump_mariadb() {
    local db="$1"
    local tmp="$2"

    if mysqldump --single-transaction --quick --max-allowed-packet=512M "$db" | gzip -c > "$tmp"; then
        return 0
    fi

    rm -f "$tmp"
    mysqldump --single-transaction --quick --skip-extended-insert --max-allowed-packet=512M "$db" | gzip -c > "$tmp"
}

while IFS= read -r db; do
    [ -n "$db" ] || continue
    tmp="$BACKUP_DIR/databases/${db}_$DATE.sql.gz.tmp"
    dest="$BACKUP_DIR/databases/${db}_$DATE.sql.gz"
    dump_mariadb "$db" "$tmp"
    mv "$tmp" "$dest"
    DB_COUNT=$((DB_COUNT + 1))
done <<< "$DATABASES"

# Auto-detect SQLite databases in /var/www. Exclude dependencies and skipped apps.
while IFS= read -r -d '' dbfile; do
    relative="${dbfile#$WWW_DIR/}"
    sitename="${relative%%/*}"
    is_listed "$sitename" "$SKIP_DIRS" && continue

    safename=$(printf '%s' "$relative" | sed 's|/|_|g; s|\.db$||')
    dest="$BACKUP_DIR/databases/${safename}_$DATE.db"
    tmp="$dest.tmp"
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$dbfile" ".backup '$tmp'" 2>/dev/null || cp -p "$dbfile" "$tmp"
    else
        cp -p "$dbfile" "$tmp"
    fi
    mv "$tmp" "$dest"
done < <(find "$WWW_DIR" -maxdepth 5 -name "*.db" -type f \
    ! -path "*/node_modules/*" ! -path "*/venv/*" ! -path "*/.venv/*" 2>/dev/null -print0)

find "$BACKUP_DIR/databases" -type f -mtime +"$RETENTION_DAYS" -delete

# =============================================================================
# CONFIGS - webserver, TLS, env files, WordPress config, cron/system metadata
# =============================================================================
if [ -d /etc/nginx ]; then
    tar czf "$BACKUP_DIR/configs/nginx_$DATE.tar.gz" -C /etc/nginx sites-available/ conf.d/ 2>/dev/null || true
fi
if [ -d /etc/caddy ]; then
    tar czf "$BACKUP_DIR/configs/caddy_$DATE.tar.gz" -C /etc caddy/ 2>/dev/null || true
fi
if [ -d /etc/letsencrypt ]; then
    tar czf "$BACKUP_DIR/configs/letsencrypt_$DATE.tar.gz" -C /etc letsencrypt/ 2>/dev/null || true
fi

tar czf "$BACKUP_DIR/configs/system_$DATE.tar.gz" \
    --ignore-failed-read \
    /etc/cron.d /etc/crontab /etc/systemd/system /etc/php /etc/mysql \
    /etc/fail2ban /etc/ufw /etc/ssh/sshd_config /home/martijn/.pm2/dump.pm2 \
    2>/dev/null || true

find "$WWW_DIR" -maxdepth 2 -name ".env" -type f 2>/dev/null | while read -r envfile; do
    sitename=$(basename "$(dirname "$envfile")")
    is_listed "$sitename" "$SKIP_CONFIG_DIRS" && continue
    cp -p "$envfile" "$BACKUP_DIR/configs/${sitename}-env_$DATE"
done

find "$WWW_DIR" -maxdepth 2 -name "wp-config.php" -type f 2>/dev/null | while read -r wpconfig; do
    sitename=$(basename "$(dirname "$wpconfig")")
    is_listed "$sitename" "$SKIP_CONFIG_DIRS" && continue
    cp -p "$wpconfig" "$BACKUP_DIR/configs/${sitename}-wp-config_$DATE.php"
done

find "$BACKUP_DIR/configs" -type f -mtime +"$RETENTION_DAYS" -delete

# =============================================================================
# SITES - restorable site data without dependencies, caches, or manager source
# =============================================================================
for skip in $SKIP_DIRS; do
    case "$skip" in
        ""|*/*|.|..) ;;
        *) rm -rf "$BACKUP_DIR/sites/$skip" ;;
    esac
done

for sitedir in "$WWW_DIR"/*/; do
    [ -d "$sitedir" ] || continue
    sitename=$(basename "$sitedir")
    is_listed "$sitename" "$SKIP_DIRS" && continue

    destdir="$BACKUP_DIR/sites/$sitename"
    mkdir -p "$destdir"

    if [ -f "$sitedir/wp-config.php" ]; then
        for subdir in uploads themes plugins; do
            if [ -d "$sitedir/wp-content/$subdir" ]; then
                safe_rsync "$sitedir/wp-content/$subdir/" "$destdir/wp-content-$subdir/"
            fi
        done
        safe_rsync \
            --exclude='wp-admin/' --exclude='wp-includes/' \
            --exclude='wp-content/' --exclude='wp-*.php' \
            --exclude='index.php' --exclude='license.txt' \
            --exclude='readme.html' --exclude='xmlrpc.php' \
            "$sitedir" "$destdir/custom/"
    elif [ -f "$sitedir/package.json" ]; then
        safe_rsync \
            --exclude='.next/' \
            --exclude='dist/' \
            --exclude='build/' \
            --exclude='coverage/' \
            --exclude='certificates/' \
            --exclude='backups/' \
            "$sitedir" "$destdir/"
    else
        safe_rsync "$sitedir" "$destdir/"
    fi
done

# =============================================================================
# MANIFEST, CHECKSUMS & PERMISSIONS
# =============================================================================
find "$BACKUP_DIR" -maxdepth 1 -name "checksums_*.sha256" -mtime +"$RETENTION_DAYS" -delete

MANIFEST_FILE="$BACKUP_DIR/configs/manifest_$DATE.txt"
{
    echo "date=$DATE"
    echo "generated_at=$(date -Is)"
    echo "backup_dir=$BACKUP_DIR"
    echo "skip_dirs=$SKIP_DIRS"
    echo
    echo "[sites]"
    find "$BACKUP_DIR/sites" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null | sort
    echo
    echo "[databases]"
    printf '%s\n' "$DATABASES" | sed '/^$/d' | sort
} > "$MANIFEST_FILE"

cd "$BACKUP_DIR"
tmp_checksum="$CHECKSUM_FILE.tmp"
: > "$tmp_checksum"
for f in databases/*_"$DATE".* configs/*_"$DATE".*; do
    [ -f "$f" ] && sha256sum "$f" >> "$tmp_checksum"
done
find sites -type f -print0 2>/dev/null | sort -z | xargs -0r sha256sum >> "$tmp_checksum"
mv "$tmp_checksum" "$CHECKSUM_FILE"

find "$BACKUP_DIR" -type d -exec chmod 755 {} \;
find "$BACKUP_DIR/sites" -type f -exec chmod 644 {} \;
if id -u "$BACKUP_READ_USER" >/dev/null 2>&1; then
    chown -R "$BACKUP_READ_USER:$BACKUP_READ_USER" "$BACKUP_DIR/databases" "$BACKUP_DIR/configs" 2>/dev/null || true
    chown "$BACKUP_READ_USER:$BACKUP_READ_USER" "$CHECKSUM_FILE" 2>/dev/null || true
fi
find "$BACKUP_DIR/databases" "$BACKUP_DIR/configs" -type d -exec chmod 750 {} \; 2>/dev/null || true
find "$BACKUP_DIR/databases" "$BACKUP_DIR/configs" -type f -exec chmod 640 {} \; 2>/dev/null || true
chmod 644 "$CHECKSUM_FILE"

CHECKSUM_COUNT=$(wc -l < "$CHECKSUM_FILE")
BACKUP_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)
SITE_COUNT=$(find "$BACKUP_DIR/sites" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)

message="Backup completed - $SITE_COUNT sites, $DB_COUNT MariaDB databases - $BACKUP_SIZE on disk - $CHECKSUM_COUNT checksums"
echo "$(date): $message" >> "$LOG"
report_status "success" "$message"
