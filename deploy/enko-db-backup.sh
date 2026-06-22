#!/usr/bin/env bash
# Enko PostgreSQL daily backup script
# Installed to: /usr/local/bin/enko-db-backup.sh
set -euo pipefail

BACKUP_DIR="/opt/enko/backups"
DB_NAME="enko"
DB_USER="enko"
KEEP_DAYS=7

mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/enko_${TIMESTAMP}.sql.gz"

echo "[enko-backup] Starting backup at $(date)"
pg_dump -U "$DB_USER" "$DB_NAME" | gzip > "$BACKUP_FILE"
chmod 600 "$BACKUP_FILE"
echo "[enko-backup] Backup saved: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"

# Rotate: remove backups older than KEEP_DAYS
find "$BACKUP_DIR" -name "enko_*.sql.gz" -mtime +${KEEP_DAYS} -delete
echo "[enko-backup] Rotated backups older than ${KEEP_DAYS} days"
echo "[enko-backup] Done at $(date)"
