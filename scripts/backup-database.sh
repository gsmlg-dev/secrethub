#!/usr/bin/env bash
# SecretHub Database Backup Script
# Purpose: Automated daily database backup with S3 upload
# Usage: ./backup-database.sh
# Recommended: Run via cron daily at 2 AM

set -euo pipefail

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/var/backups/secrethub}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
S3_BUCKET="${AWS_S3_BACKUP_BUCKET:-secrethub-backups}"
S3_PREFIX="${S3_PREFIX:-database-backups}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
DATE=$(date +%Y%m%d)

# Logging
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

log_error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2
}

# Create backup directory if not exists
mkdir -p "$BACKUP_DIR"

# Backup filename
BACKUP_FILE="secrethub-${TIMESTAMP}.sql"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_FILE}"

# Check DATABASE_URL is set
if [ -z "${DATABASE_URL:-}" ]; then
    log_error "DATABASE_URL environment variable not set"
    exit 1
fi

log "Starting database backup..."
log "Backup file: $BACKUP_PATH"

# Perform backup
if pg_dump "$DATABASE_URL" \
    --format=plain \
    --no-owner \
    --no-privileges \
    --verbose \
    --file="$BACKUP_PATH" 2>&1 | grep -v "^-- "; then
    log "Database backup completed successfully"
else
    log_error "Database backup failed"
    exit 1
fi

# Check backup file size
BACKUP_SIZE=$(du -h "$BACKUP_PATH" | cut -f1)
log "Backup size: $BACKUP_SIZE"

# Compress backup
log "Compressing backup..."
gzip "$BACKUP_PATH"
BACKUP_PATH="${BACKUP_PATH}.gz"

COMPRESSED_SIZE=$(du -h "$BACKUP_PATH" | cut -f1)
log "Compressed size: $COMPRESSED_SIZE"

# Upload to S3
log "Uploading to S3..."
S3_KEY="${S3_PREFIX}/${DATE}/${BACKUP_FILE}.gz"

if aws s3 cp "$BACKUP_PATH" "s3://${S3_BUCKET}/${S3_KEY}" \
    --server-side-encryption AES256 \
    --storage-class STANDARD_IA \
    --metadata "backup-date=${TIMESTAMP},backup-type=full,retention-days=${RETENTION_DAYS}"; then
    log "Backup uploaded to S3: s3://${S3_BUCKET}/${S3_KEY}"
else
    log_error "S3 upload failed"
    exit 1
fi

# Clean up old local backups
log "Cleaning up old local backups (retention: ${RETENTION_DAYS} days)..."
find "$BACKUP_DIR" -name "secrethub-*.sql.gz" -mtime +${RETENTION_DAYS} -delete
LOCAL_COUNT=$(find "$BACKUP_DIR" -name "secrethub-*.sql.gz" | wc -l)
log "Local backups remaining: $LOCAL_COUNT"

# Apply S3 lifecycle policy (if not already set)
cat > /tmp/s3-lifecycle-policy.json <<EOF
{
    "Rules": [
        {
            "Id": "TransitionToGlacier",
            "Status": "Enabled",
            "Prefix": "${S3_PREFIX}/",
            "Transitions": [
                {
                    "Days": 90,
                    "StorageClass": "GLACIER"
                }
            ],
            "Expiration": {
                "Days": 2555
            }
        }
    ]
}
EOF

aws s3api put-bucket-lifecycle-configuration \
    --bucket "$S3_BUCKET" \
    --lifecycle-configuration file:///tmp/s3-lifecycle-policy.json \
    2>/dev/null || log "Note: Could not set S3 lifecycle policy (may already exist)"

rm /tmp/s3-lifecycle-policy.json

# Create backup manifest
cat > "${BACKUP_DIR}/latest-backup.json" <<EOF
{
    "timestamp": "${TIMESTAMP}",
    "date": "${DATE}",
    "backup_file": "${BACKUP_FILE}.gz",
    "s3_location": "s3://${S3_BUCKET}/${S3_KEY}",
    "size_original": "${BACKUP_SIZE}",
    "size_compressed": "${COMPRESSED_SIZE}",
    "retention_days": ${RETENTION_DAYS}
}
EOF

log "Backup manifest created: ${BACKUP_DIR}/latest-backup.json"

# Send notification (if configured)
if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
    curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d "{
            \"text\": \"✅ SecretHub database backup completed\",
            \"attachments\": [{
                \"color\": \"good\",
                \"fields\": [
                    {\"title\": \"Timestamp\", \"value\": \"${TIMESTAMP}\", \"short\": true},
                    {\"title\": \"Size\", \"value\": \"${COMPRESSED_SIZE}\", \"short\": true},
                    {\"title\": \"S3 Location\", \"value\": \"s3://${S3_BUCKET}/${S3_KEY}\"}
                ]
            }]
        }" 2>/dev/null || log "Note: Slack notification failed (webhook may not be configured)"
fi

log "Backup completed successfully!"
log "S3 Location: s3://${S3_BUCKET}/${S3_KEY}"
log "Local Copy: $BACKUP_PATH"

exit 0
