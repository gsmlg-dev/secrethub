#!/usr/bin/env bash
# SecretHub Database Restore Script
# Purpose: Restore database from backup (local or S3)
# Usage: ./restore-database.sh [backup-file-or-s3-url]

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging
log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

log_success() {
    echo -e "${GREEN}✅ $*${NC}"
}

log_error() {
    echo -e "${RED}❌ $*${NC}" >&2
}

log_warning() {
    echo -e "${YELLOW}⚠️  $*${NC}"
}

# Usage
usage() {
    cat <<EOF
Usage: $0 [OPTIONS] <backup-source>

Restore SecretHub database from backup.

OPTIONS:
    -h, --help              Show this help message
    -t, --target URL        Target database URL (default: DATABASE_URL env var)
    -y, --yes               Skip confirmation prompt
    --no-verify             Skip backup verification

BACKUP SOURCE:
    Local file:             /path/to/backup.sql.gz
    S3 URL:                 s3://bucket/path/to/backup.sql.gz
    Latest from S3:         latest

EXAMPLES:
    # Restore from local file
    $0 /var/backups/secrethub/secrethub-20250101-120000.sql.gz

    # Restore from S3
    $0 s3://secrethub-backups/database-backups/20250101/secrethub-20250101-120000.sql.gz

    # Restore latest backup from S3
    $0 latest

    # Restore to specific database
    $0 --target postgresql://user:pass@localhost/secrethub_restored backup.sql.gz

EOF
    exit 1
}

# Parse arguments
TARGET_DB=""
SKIP_CONFIRMATION=false
VERIFY_BACKUP=true

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -t|--target)
            TARGET_DB="$2"
            shift 2
            ;;
        -y|--yes)
            SKIP_CONFIRMATION=true
            shift
            ;;
        --no-verify)
            VERIFY_BACKUP=false
            shift
            ;;
        *)
            BACKUP_SOURCE="$1"
            shift
            ;;
    esac
done

# Check backup source provided
if [ -z "${BACKUP_SOURCE:-}" ]; then
    log_error "No backup source specified"
    usage
fi

# Set target database
if [ -z "$TARGET_DB" ]; then
    if [ -z "${DATABASE_URL:-}" ]; then
        log_error "Target database not specified and DATABASE_URL not set"
        exit 1
    fi
    TARGET_DB="$DATABASE_URL"
fi

log "Restore Configuration:"
log "  Backup Source: $BACKUP_SOURCE"
log "  Target Database: $TARGET_DB"
log "  Verification: $([ "$VERIFY_BACKUP" = true ] && echo 'Enabled' || echo 'Disabled')"

# Create temp directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Download/prepare backup file
BACKUP_FILE=""

if [ "$BACKUP_SOURCE" = "latest" ]; then
    log "Fetching latest backup from S3..."
    S3_BUCKET="${AWS_S3_BACKUP_BUCKET:-secrethub-backups}"
    LATEST_BACKUP=$(aws s3 ls "s3://${S3_BUCKET}/database-backups/" --recursive | \
        grep '\.sql\.gz$' | \
        sort | \
        tail -n 1 | \
        awk '{print $4}')

    if [ -z "$LATEST_BACKUP" ]; then
        log_error "No backups found in S3"
        exit 1
    fi

    log "Latest backup: s3://${S3_BUCKET}/${LATEST_BACKUP}"
    BACKUP_SOURCE="s3://${S3_BUCKET}/${LATEST_BACKUP}"
fi

if [[ "$BACKUP_SOURCE" == s3://* ]]; then
    log "Downloading backup from S3..."
    BACKUP_FILE="${TEMP_DIR}/backup.sql.gz"

    if ! aws s3 cp "$BACKUP_SOURCE" "$BACKUP_FILE"; then
        log_error "Failed to download backup from S3"
        exit 1
    fi

    log_success "Backup downloaded to $BACKUP_FILE"
elif [ -f "$BACKUP_SOURCE" ]; then
    log "Using local backup file..."
    BACKUP_FILE="$BACKUP_SOURCE"
else
    log_error "Backup source not found: $BACKUP_SOURCE"
    exit 1
fi

# Get backup info
BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
log "Backup size: $BACKUP_SIZE"

# Verify backup integrity
if [ "$VERIFY_BACKUP" = true ]; then
    log "Verifying backup integrity..."

    if gunzip -t "$BACKUP_FILE" 2>/dev/null; then
        log_success "Backup file integrity verified"
    else
        log_error "Backup file appears to be corrupted"
        exit 1
    fi

    # Check if it's a valid SQL dump
    if gunzip -c "$BACKUP_FILE" | head -n 20 | grep -q "PostgreSQL database dump"; then
        log_success "Backup is a valid PostgreSQL dump"
    else
        log_warning "Backup may not be a valid PostgreSQL dump"
    fi
fi

# Extract database name from URL
DB_NAME=$(echo "$TARGET_DB" | sed 's/.*\/\([^?]*\).*/\1/')
log "Target database name: $DB_NAME"

# Confirmation prompt
if [ "$SKIP_CONFIRMATION" = false ]; then
    log_warning "⚠️  WARNING: This will OVERWRITE the database: $DB_NAME"
    log_warning "All existing data will be LOST!"
    echo ""
    read -p "Are you sure you want to continue? (type 'yes' to confirm): " CONFIRM

    if [ "$CONFIRM" != "yes" ]; then
        log "Restore cancelled by user"
        exit 0
    fi
fi

# Start restore
log "Starting database restore..."
START_TIME=$(date +%s)

# Step 1: Create pre-restore backup (safety)
log "Creating safety backup of current database..."
SAFETY_BACKUP="${TEMP_DIR}/pre-restore-backup-$(date +%Y%m%d-%H%M%S).sql.gz"
if pg_dump "$TARGET_DB" | gzip > "$SAFETY_BACKUP" 2>/dev/null; then
    log_success "Safety backup created: $SAFETY_BACKUP"
else
    log_warning "Could not create safety backup (database may be empty)"
fi

# Step 2: Terminate existing connections
log "Terminating existing database connections..."
psql "$TARGET_DB" <<EOF 2>/dev/null || true
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = current_database()
  AND pid <> pg_backend_pid();
EOF

# Step 3: Drop existing schema
log "Dropping existing schema..."
psql "$TARGET_DB" -c "DROP SCHEMA IF EXISTS public CASCADE;" 2>/dev/null || true
psql "$TARGET_DB" -c "DROP SCHEMA IF EXISTS audit CASCADE;" 2>/dev/null || true

# Step 4: Recreate schemas
log "Recreating schemas..."
psql "$TARGET_DB" -c "CREATE SCHEMA public;"
psql "$TARGET_DB" -c "CREATE SCHEMA audit;"

# Step 5: Restore from backup
log "Restoring database from backup..."
if gunzip -c "$BACKUP_FILE" | psql "$TARGET_DB" 2>&1 | grep -v "^SET$" | grep -v "^--"; then
    log_success "Database restore completed"
else
    log_error "Database restore failed"

    # Attempt to restore from safety backup
    if [ -f "$SAFETY_BACKUP" ]; then
        log_warning "Attempting to restore from safety backup..."
        gunzip -c "$SAFETY_BACKUP" | psql "$TARGET_DB" 2>/dev/null || true
    fi

    exit 1
fi

# Step 6: Verify restore
log "Verifying restore..."

# Check table count
TABLE_COUNT=$(psql "$TARGET_DB" -t -c "
    SELECT count(*)
    FROM information_schema.tables
    WHERE table_schema = 'public';
" | xargs)

log "Tables restored: $TABLE_COUNT"

# Check data in key tables
if [ "$TABLE_COUNT" -gt 0 ]; then
    SECRET_COUNT=$(psql "$TARGET_DB" -t -c "SELECT count(*) FROM secrets;" 2>/dev/null | xargs || echo "0")
    POLICY_COUNT=$(psql "$TARGET_DB" -t -c "SELECT count(*) FROM policies;" 2>/dev/null | xargs || echo "0")
    AUDIT_COUNT=$(psql "$TARGET_DB" -t -c "SELECT count(*) FROM audit.events;" 2>/dev/null | xargs || echo "0")

    log "Secrets: $SECRET_COUNT"
    log "Policies: $POLICY_COUNT"
    log "Audit Events: $AUDIT_COUNT"
else
    log_warning "No tables found in database"
fi

# Calculate duration
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

log_success "Database restore completed successfully!"
log "Duration: ${DURATION}s"
log ""
log "Next steps:"
log "1. Verify application connectivity"
log "2. Unseal vault (if sealed)"
log "3. Reconnect agents"
log "4. Verify audit log integrity"

# Save restore report
REPORT_FILE="${TEMP_DIR}/restore-report-$(date +%Y%m%d-%H%M%S).txt"
cat > "$REPORT_FILE" <<EOF
SecretHub Database Restore Report
==================================

Date: $(date -Iseconds)
Backup Source: $BACKUP_SOURCE
Target Database: $DB_NAME
Backup Size: $BACKUP_SIZE
Duration: ${DURATION}s

Tables Restored: $TABLE_COUNT
Secrets: $SECRET_COUNT
Policies: $POLICY_COUNT
Audit Events: $AUDIT_COUNT

Status: SUCCESS

Safety Backup: $SAFETY_BACKUP
(Keep this file until you've verified the restore is successful)
EOF

cat "$REPORT_FILE"
log ""
log "Restore report saved to: $REPORT_FILE"

exit 0
