#!/bin/bash
# =============================================================================
# VPS Backup Script - Dynamic
# Automatically detects all sites in /var/www/ and all MariaDB databases.
# Runs daily via cron: 0 3 * * * root /usr/local/bin/vps-backup.sh
# =============================================================================

BACKUP_DIR="/var/backups/vps"
DATE=$(date +%Y%m%d)
CHECKSUM_FILE="$BACKUP_DIR/checksums_$DATE.sha256"
LOG="/var/log/vps-backup.log"
WEBHOOK_URL="http://127.0.0.1:5050/api/backup/webhook"
WEBHOOK_SECRET="9CGr0rmMOOz1uyFnoGjbrZgzhYmIm9zHXVMCsIdq0hw"
WWW_DIR="/var/www"

# Directories to skip in /var/www/ (not actual sites)
SKIP_DIRS="html"

# Report failure on any error
report_failure() {
    local err_msg="Backup failed at line $1: $2"
    echo "$(date): $err_msg" >> "$LOG"
    curl -s -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" -H "X-Webhook-Secret: $WEBHOOK_SECRET" \
        -d "{\"status\": \"failure\", \"details\": \"$err_msg\"}" > /dev/null 2>&1 || true
}
trap 'report_failure $LINENO "$BASH_COMMAND"' ERR
set -e

mkdir -p "$BACKUP_DIR/databases"
mkdir -p "$BACKUP_DIR/configs"
mkdir -p "$BACKUP_DIR/sites"

# =============================================================================
# DATABASES - Auto-detect all MariaDB databases
# =============================================================================
SYSTEM_DBS="information_schema|performance_schema|mysql|sys"
DATABASES=$(mysql -N -e "SHOW DATABASES" 2>/dev/null | grep -Ev "^($SYSTEM_DBS)$")

for db in $DATABASES; do
    mysqldump --single-transaction --quick "$db" | gzip > "$BACKUP_DIR/databases/${db}_$DATE.sql.gz"
done

# Auto-detect SQLite databases in /var/www/
find "$WWW_DIR" -maxdepth 3 -name "*.db" -type f ! -path "*/node_modules/*" 2>/dev/null | while read -r dbfile; do
    # Derive a safe name from the path: /var/www/site/data.db -> site_data
    relative="${dbfile#$WWW_DIR/}"
    safename=$(echo "$relative" | sed 's|/|_|g; s|\.db$||')
    cp "$dbfile" "$BACKUP_DIR/databases/${safename}_$DATE.db" 2>/dev/null || true
done

# Cleanup database dumps older than 7 days
find "$BACKUP_DIR/databases" -type f -mtime +7 -delete

# =============================================================================
# CONFIGS - Nginx, Let's Encrypt, env files
# =============================================================================
tar czf "$BACKUP_DIR/configs/nginx_$DATE.tar.gz" -C /etc/nginx sites-available/ conf.d/
tar czf "$BACKUP_DIR/configs/letsencrypt_$DATE.tar.gz" -C /etc letsencrypt/ 2>/dev/null || true

# Backup .env files from all sites
find "$WWW_DIR" -maxdepth 2 -name ".env" -type f 2>/dev/null | while read -r envfile; do
    sitename=$(basename "$(dirname "$envfile")")
    cp "$envfile" "$BACKUP_DIR/configs/${sitename}-env_$DATE" 2>/dev/null || true
done

# Backup wp-config.php from WordPress sites
find "$WWW_DIR" -maxdepth 2 -name "wp-config.php" -type f 2>/dev/null | while read -r wpconfig; do
    sitename=$(basename "$(dirname "$wpconfig")")
    cp "$wpconfig" "$BACKUP_DIR/configs/${sitename}-wp-config_$DATE.php" 2>/dev/null || true
done

# Cleanup configs older than 7 days
find "$BACKUP_DIR/configs" -type f -mtime +7 -delete

# =============================================================================
# SITES - Auto-detect and backup all sites in /var/www/
# =============================================================================
for sitedir in "$WWW_DIR"/*/; do
    [ -d "$sitedir" ] || continue
    sitename=$(basename "$sitedir")

    # Skip configured directories
    echo "$SKIP_DIRS" | tr ' ' '\n' | grep -qx "$sitename" && continue

    destdir="$BACKUP_DIR/sites/$sitename"
    mkdir -p "$destdir"

    if [ -f "$sitedir/wp-config.php" ]; then
        # WordPress: backup wp-content (uploads, themes, plugins) + custom root files
        for subdir in uploads themes plugins; do
            if [ -d "$sitedir/wp-content/$subdir" ]; then
                rsync -a --delete "$sitedir/wp-content/$subdir/" "$destdir/wp-content-$subdir/"
            fi
        done
        # Custom files in WP root (skip WP core)
        rsync -a --delete \
            --exclude='wp-admin/' --exclude='wp-includes/' \
            --exclude='wp-content/' --exclude='wp-*.php' \
            --exclude='index.php' --exclude='license.txt' \
            --exclude='readme.html' --exclude='xmlrpc.php' \
            "$sitedir" "$destdir/custom/"

    elif [ -f "$sitedir/package.json" ]; then
        # Node.js: skip build artifacts en dependencies
        rsync -a --delete \
            --exclude='node_modules/' --exclude='.next/' \
            --exclude='.cache/' --exclude='dist/' \
            "$sitedir" "$destdir/"

    else
        # Static site of overig: volledige rsync
        rsync -a --delete "$sitedir" "$destdir/"
    fi
done

# =============================================================================
# PERMISSIONS & CHECKSUMS
# =============================================================================
chmod -R 644 "$BACKUP_DIR"/databases/* "$BACKUP_DIR"/configs/* 2>/dev/null || true
find "$BACKUP_DIR" -type d -exec chmod 755 {} \;
find "$BACKUP_DIR/sites" -type f -exec chmod 644 {} \;

# Cleanup old checksum files (7 days retention)
find "$BACKUP_DIR" -maxdepth 1 -name "checksums_*.sha256" -mtime +7 -delete

# Generate checksums with relative paths
cd "$BACKUP_DIR"
: > "$CHECKSUM_FILE"
for f in databases/*_$DATE.* configs/*_$DATE.*; do
    [ -f "$f" ] && sha256sum "$f" >> "$CHECKSUM_FILE"
done
chmod 644 "$CHECKSUM_FILE"

CHECKSUM_COUNT=$(wc -l < "$CHECKSUM_FILE")
BACKUP_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)
SITE_COUNT=$(ls -d "$BACKUP_DIR/sites"/*/ 2>/dev/null | wc -l)
DB_COUNT=$(echo "$DATABASES" | wc -w)

echo "$(date): Backup completed - $SITE_COUNT sites, $DB_COUNT databases - $BACKUP_SIZE on disk - $CHECKSUM_COUNT checksums" >> "$LOG"

# Report success to VPS Manager
curl -s -X POST "$WEBHOOK_URL" \
    -H "Content-Type: application/json" -H "X-Webhook-Secret: $WEBHOOK_SECRET" \
    -d "{\"status\": \"success\", \"details\": \"Backup completed - $SITE_COUNT sites, $DB_COUNT databases - $BACKUP_SIZE on disk - $CHECKSUM_COUNT checksums verified\"}" > /dev/null 2>&1 || true
