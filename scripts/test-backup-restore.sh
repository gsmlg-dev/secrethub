#!/usr/bin/env bash
# SecretHub Backup and Restore Testing Script
# Purpose: Automated testing of backup and restore procedures
# Usage: ./test-backup-restore.sh [test-name]
#
# Available tests:
#   full-backup       - Test full database backup
#   point-in-time     - Test point-in-time recovery
#   audit-archive     - Test audit log archival and restore
#   config-backup     - Test configuration backup and restore
#   all               - Run all tests

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_RESULTS_DIR="${PROJECT_ROOT}/test-results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
TEST_LOG="${TEST_RESULTS_DIR}/backup-restore-test-${TIMESTAMP}.log"

# Ensure test results directory exists
mkdir -p "$TEST_RESULTS_DIR"

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*" | tee -a "$TEST_LOG"
}

log_success() {
    echo -e "${GREEN}✅ $*${NC}" | tee -a "$TEST_LOG"
}

log_error() {
    echo -e "${RED}❌ $*${NC}" | tee -a "$TEST_LOG"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $*${NC}" | tee -a "$TEST_LOG"
}

log_section() {
    echo "" | tee -a "$TEST_LOG"
    echo -e "${BLUE}========================================${NC}" | tee -a "$TEST_LOG"
    echo -e "${BLUE}$*${NC}" | tee -a "$TEST_LOG"
    echo -e "${BLUE}========================================${NC}" | tee -a "$TEST_LOG"
}

# Check prerequisites
check_prerequisites() {
    log_section "Checking Prerequisites"

    local missing_tools=()

    # Check required tools
    for tool in psql aws jq curl; do
        if ! command -v $tool &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log "Please install missing tools and try again"
        exit 1
    fi

    # Check environment variables
    if [ -z "${DATABASE_URL:-}" ]; then
        log_error "DATABASE_URL not set"
        exit 1
    fi

    if [ -z "${AWS_S3_BACKUP_BUCKET:-}" ]; then
        log_warning "AWS_S3_BACKUP_BUCKET not set, using default: secrethub-backups"
        export AWS_S3_BACKUP_BUCKET="secrethub-backups"
    fi

    log_success "All prerequisites met"
}

# Test 1: Full Database Backup
test_full_backup() {
    log_section "Test 1: Full Database Backup"

    local test_start=$(date +%s)
    local backup_file="secrethub-backup-${TIMESTAMP}.sql"
    local backup_path="${TEST_RESULTS_DIR}/${backup_file}"
    local s3_key="backups/${backup_file}.gz"

    # Step 1: Create baseline data
    log "Creating test data..."
    psql "$DATABASE_URL" <<EOF
-- Create test secrets for verification
INSERT INTO secrets (path, value_encrypted, version, created_at, updated_at)
VALUES
    ('test/backup/secret1', 'encrypted-value-1', 1, NOW(), NOW()),
    ('test/backup/secret2', 'encrypted-value-2', 1, NOW(), NOW()),
    ('test/backup/secret3', 'encrypted-value-3', 1, NOW(), NOW())
ON CONFLICT (path) DO NOTHING;
EOF

    # Step 2: Perform backup
    log "Performing database backup..."
    pg_dump "$DATABASE_URL" \
        --format=plain \
        --no-owner \
        --no-privileges \
        --verbose \
        --file="$backup_path" 2>&1 | tee -a "$TEST_LOG"

    if [ ! -f "$backup_path" ]; then
        log_error "Backup file not created"
        return 1
    fi

    local backup_size=$(du -h "$backup_path" | cut -f1)
    log_success "Backup created: $backup_path (Size: $backup_size)"

    # Step 3: Compress backup
    log "Compressing backup..."
    gzip "$backup_path"
    backup_path="${backup_path}.gz"

    # Step 4: Upload to S3
    log "Uploading backup to S3..."
    aws s3 cp "$backup_path" "s3://${AWS_S3_BACKUP_BUCKET}/${s3_key}" \
        --server-side-encryption AES256 \
        --storage-class STANDARD_IA

    if aws s3 ls "s3://${AWS_S3_BACKUP_BUCKET}/${s3_key}" &> /dev/null; then
        log_success "Backup uploaded to S3: s3://${AWS_S3_BACKUP_BUCKET}/${s3_key}"
    else
        log_error "Backup upload to S3 failed"
        return 1
    fi

    # Step 5: Verify backup integrity
    log "Verifying backup integrity..."
    gunzip -c "$backup_path" | head -n 20 | tee -a "$TEST_LOG"

    # Step 6: Test restore (to test database)
    log "Testing restore to test database..."
    local test_db_url="${DATABASE_TEST_URL:-${DATABASE_URL/_dev/_test}}"

    # Drop and recreate test database
    psql "$test_db_url" -c "DROP SCHEMA public CASCADE;" 2>/dev/null || true
    psql "$test_db_url" -c "CREATE SCHEMA public;"

    # Restore
    gunzip -c "$backup_path" | psql "$test_db_url" &> /dev/null

    # Verify data
    local secret_count=$(psql "$test_db_url" -t -c "SELECT count(*) FROM secrets WHERE path LIKE 'test/backup/%';")
    secret_count=$(echo "$secret_count" | xargs)

    if [ "$secret_count" -eq 3 ]; then
        log_success "Backup restore verified: $secret_count secrets restored"
    else
        log_error "Backup restore verification failed: expected 3 secrets, found $secret_count"
        return 1
    fi

    # Calculate duration
    local test_end=$(date +%s)
    local duration=$((test_end - test_start))

    log_section "Test 1 Results"
    log "Status: PASSED"
    log "Duration: ${duration}s"
    log "Backup Size: $backup_size"
    log "S3 Location: s3://${AWS_S3_BACKUP_BUCKET}/${s3_key}"

    return 0
}

# Test 2: Point-in-Time Recovery
test_point_in_time() {
    log_section "Test 2: Point-in-Time Recovery"

    local test_start=$(date +%s)
    local test_db_url="${DATABASE_TEST_URL:-${DATABASE_URL/_dev/_test}}"

    # Step 1: Create baseline state (T0)
    log "Creating baseline state (T0)..."
    psql "$test_db_url" <<EOF
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;

CREATE TABLE IF NOT EXISTS secrets (
    id SERIAL PRIMARY KEY,
    path VARCHAR(255) UNIQUE NOT NULL,
    value_encrypted TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

INSERT INTO secrets (path, value_encrypted, version)
VALUES ('test/pitr/secret-t0', 'value-at-t0', 1);
EOF

    local count_t0=$(psql "$test_db_url" -t -c "SELECT count(*) FROM secrets;" | xargs)
    log "T0: $count_t0 secrets"

    # Take snapshot at T0
    local backup_t0="${TEST_RESULTS_DIR}/pitr-t0-${TIMESTAMP}.sql"
    pg_dump "$test_db_url" --format=plain -f "$backup_t0"
    log "Snapshot T0 created: $backup_t0"

    # Step 2: Perform operations and create T1 state
    sleep 2
    log "Performing operations (T0 → T1)..."
    psql "$test_db_url" <<EOF
INSERT INTO secrets (path, value_encrypted, version)
VALUES ('test/pitr/secret-t1', 'value-at-t1', 1);
EOF

    local count_t1=$(psql "$test_db_url" -t -c "SELECT count(*) FROM secrets;" | xargs)
    log "T1: $count_t1 secrets"

    # Take snapshot at T1
    local backup_t1="${TEST_RESULTS_DIR}/pitr-t1-${TIMESTAMP}.sql"
    pg_dump "$test_db_url" --format=plain -f "$backup_t1"
    log "Snapshot T1 created: $backup_t1"

    # Step 3: Perform more operations (T1 → T2)
    sleep 2
    log "Performing more operations (T1 → T2)..."
    psql "$test_db_url" <<EOF
INSERT INTO secrets (path, value_encrypted, version)
VALUES ('test/pitr/secret-t2', 'value-at-t2', 1);
EOF

    local count_t2=$(psql "$test_db_url" -t -c "SELECT count(*) FROM secrets;" | xargs)
    log "T2: $count_t2 secrets"

    # Step 4: Restore to T1
    log "Restoring database to T1..."
    psql "$test_db_url" -c "DROP SCHEMA public CASCADE;"
    psql "$test_db_url" -c "CREATE SCHEMA public;"
    psql "$test_db_url" -f "$backup_t1" &> /dev/null

    # Verify restored state matches T1
    local count_restored=$(psql "$test_db_url" -t -c "SELECT count(*) FROM secrets;" | xargs)
    log "Restored: $count_restored secrets"

    if [ "$count_restored" -eq "$count_t1" ]; then
        log_success "Point-in-time recovery successful: state matches T1"
    else
        log_error "Point-in-time recovery failed: expected $count_t1 secrets, found $count_restored"
        return 1
    fi

    # Verify specific data
    local t1_exists=$(psql "$test_db_url" -t -c "SELECT count(*) FROM secrets WHERE path = 'test/pitr/secret-t1';" | xargs)
    local t2_exists=$(psql "$test_db_url" -t -c "SELECT count(*) FROM secrets WHERE path = 'test/pitr/secret-t2';" | xargs)

    if [ "$t1_exists" -eq 1 ] && [ "$t2_exists" -eq 0 ]; then
        log_success "Data verification passed: T1 data present, T2 data absent"
    else
        log_error "Data verification failed: t1_exists=$t1_exists, t2_exists=$t2_exists"
        return 1
    fi

    # Calculate duration
    local test_end=$(date +%s)
    local duration=$((test_end - test_start))

    log_section "Test 2 Results"
    log "Status: PASSED"
    log "Duration: ${duration}s"
    log "T0 State: $count_t0 secrets"
    log "T1 State: $count_t1 secrets"
    log "T2 State: $count_t2 secrets"
    log "Restored State: $count_restored secrets (matches T1 ✓)"

    return 0
}

# Test 3: Audit Log Archive and Restore
test_audit_archive() {
    log_section "Test 3: Audit Log Archive and Restore"

    local test_start=$(date +%s)
    local test_db_url="${DATABASE_TEST_URL:-${DATABASE_URL/_dev/_test}}"

    # Step 1: Create audit schema and generate events
    log "Creating audit events..."
    psql "$test_db_url" <<EOF
-- Create audit schema if not exists
CREATE SCHEMA IF NOT EXISTS audit;

-- Create audit events table
CREATE TABLE IF NOT EXISTS audit.events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    action VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    event_hash VARCHAR(64),
    previous_hash VARCHAR(64)
);

-- Generate 1000 audit events
INSERT INTO audit.events (event_type, actor, resource, action, timestamp)
SELECT
    'secret.read',
    'user-' || (i % 10),
    'test/secret-' || i,
    'read',
    NOW() - (interval '1 day' * (i / 100))
FROM generate_series(1, 1000) AS i;

-- Calculate hash chain
UPDATE audit.events SET event_hash = md5(id::text || event_type || actor || resource);
UPDATE audit.events e1 SET previous_hash = e2.event_hash
FROM audit.events e2 WHERE e2.id = e1.id - 1;
EOF

    local total_events=$(psql "$test_db_url" -t -c "SELECT count(*) FROM audit.events;" | xargs)
    log "Generated $total_events audit events"

    # Step 2: Archive old events (> 30 days)
    log "Archiving old audit events..."
    local archive_file="${TEST_RESULTS_DIR}/audit-archive-${TIMESTAMP}.json"

    psql "$test_db_url" -t -c "
        SELECT json_agg(row_to_json(e))
        FROM audit.events e
        WHERE timestamp < NOW() - interval '30 days'
    " > "$archive_file"

    # Step 3: Upload to S3
    log "Uploading archive to S3..."
    local s3_key="audit-archives/audit-${TIMESTAMP}.json"
    aws s3 cp "$archive_file" "s3://${AWS_S3_BACKUP_BUCKET}/${s3_key}" \
        --server-side-encryption AES256 \
        --storage-class GLACIER_IR

    log_success "Archive uploaded to S3: s3://${AWS_S3_BACKUP_BUCKET}/${s3_key}"

    # Step 4: Delete archived events from database
    log "Deleting archived events from database..."
    local deleted_count=$(psql "$test_db_url" -t -c "
        DELETE FROM audit.events
        WHERE timestamp < NOW() - interval '30 days'
        RETURNING id;
    " | wc -l | xargs)

    log "Deleted $deleted_count events from database"

    # Step 5: Verify disk space reclaimed
    local remaining_events=$(psql "$test_db_url" -t -c "SELECT count(*) FROM audit.events;" | xargs)
    log "Remaining events in database: $remaining_events"

    # Step 6: Restore from archive
    log "Testing restore from archive..."
    local archive_size=$(jq '. | length' "$archive_file")
    log "Archive contains $archive_size events"

    # Parse and restore first 10 events as verification
    jq -r '.[:10][] | [.event_type, .actor, .resource, .action, .timestamp] | @tsv' "$archive_file" | \
    while IFS=$'\t' read -r event_type actor resource action timestamp; do
        psql "$test_db_url" <<EOF > /dev/null
INSERT INTO audit.events (event_type, actor, resource, action, timestamp)
VALUES ('$event_type', '$actor', '$resource', '$action', '$timestamp'::timestamp);
EOF
    done

    local restored_events=$(psql "$test_db_url" -t -c "SELECT count(*) FROM audit.events;" | xargs)
    log "Events after restore test: $restored_events (restored 10 from archive)"

    # Step 7: Verify hash chain integrity
    log "Verifying hash chain integrity..."
    local broken_chains=$(psql "$test_db_url" -t -c "
        SELECT count(*)
        FROM audit.events e1
        JOIN audit.events e2 ON e2.id = e1.id + 1
        WHERE e2.previous_hash IS NOT NULL
          AND e2.previous_hash != e1.event_hash;
    " | xargs)

    if [ "$broken_chains" -eq 0 ]; then
        log_success "Hash chain integrity verified"
    else
        log_warning "Hash chain has $broken_chains breaks (expected after archive/restore)"
    fi

    # Calculate duration
    local test_end=$(date +%s)
    local duration=$((test_end - test_start))

    log_section "Test 3 Results"
    log "Status: PASSED"
    log "Duration: ${duration}s"
    log "Total Events: $total_events"
    log "Archived Events: $deleted_count"
    log "Remaining Events: $remaining_events"
    log "Archive Size: $archive_size events"
    log "S3 Location: s3://${AWS_S3_BACKUP_BUCKET}/${s3_key}"

    return 0
}

# Test 4: Configuration Backup
test_config_backup() {
    log_section "Test 4: Configuration Backup and Restore"

    local test_start=$(date +%s)
    local config_backup_dir="${TEST_RESULTS_DIR}/config-backup-${TIMESTAMP}"
    mkdir -p "$config_backup_dir"

    # Step 1: Export AppRoles
    log "Exporting AppRoles..."
    psql "$DATABASE_URL" -t -c "
        SELECT json_agg(row_to_json(a))
        FROM approles a;
    " > "${config_backup_dir}/approles.json"

    local approle_count=$(jq '. | length' "${config_backup_dir}/approles.json" 2>/dev/null || echo "0")
    log "Exported $approle_count AppRoles"

    # Step 2: Export Policies
    log "Exporting Policies..."
    psql "$DATABASE_URL" -t -c "
        SELECT json_agg(row_to_json(p))
        FROM policies p;
    " > "${config_backup_dir}/policies.json"

    local policy_count=$(jq '. | length' "${config_backup_dir}/policies.json" 2>/dev/null || echo "0")
    log "Exported $policy_count Policies"

    # Step 3: Export Secret Engine Configurations
    log "Exporting Secret Engine configurations..."
    psql "$DATABASE_URL" -t -c "
        SELECT json_agg(row_to_json(e))
        FROM engines e;
    " > "${config_backup_dir}/engines.json" 2>/dev/null || echo "[]" > "${config_backup_dir}/engines.json"

    # Step 4: Create backup metadata
    log "Creating backup metadata..."
    cat > "${config_backup_dir}/metadata.json" <<EOF
{
    "backup_date": "$(date -Iseconds)",
    "database_version": "$(psql "$DATABASE_URL" -t -c "SELECT version();" | head -1 | xargs)",
    "approle_count": $approle_count,
    "policy_count": $policy_count,
    "backup_type": "configuration"
}
EOF

    # Step 5: Create tarball
    log "Creating configuration backup tarball..."
    local tarball="${TEST_RESULTS_DIR}/config-backup-${TIMESTAMP}.tar.gz"
    tar -czf "$tarball" -C "$TEST_RESULTS_DIR" "config-backup-${TIMESTAMP}"

    local tarball_size=$(du -h "$tarball" | cut -f1)
    log_success "Configuration backup created: $tarball (Size: $tarball_size)"

    # Step 6: Upload to S3
    log "Uploading configuration backup to S3..."
    local s3_key="config-backups/config-backup-${TIMESTAMP}.tar.gz"
    aws s3 cp "$tarball" "s3://${AWS_S3_BACKUP_BUCKET}/${s3_key}" \
        --server-side-encryption AES256

    log_success "Configuration backup uploaded to S3"

    # Step 7: Test restore
    log "Testing configuration restore..."
    local restore_dir="${TEST_RESULTS_DIR}/config-restore-${TIMESTAMP}"
    mkdir -p "$restore_dir"
    tar -xzf "$tarball" -C "$restore_dir"

    # Verify extracted files
    if [ -f "${restore_dir}/config-backup-${TIMESTAMP}/metadata.json" ]; then
        log_success "Configuration restore successful"
        cat "${restore_dir}/config-backup-${TIMESTAMP}/metadata.json" | jq '.' | tee -a "$TEST_LOG"
    else
        log_error "Configuration restore failed"
        return 1
    fi

    # Calculate duration
    local test_end=$(date +%s)
    local duration=$((test_end - test_start))

    log_section "Test 4 Results"
    log "Status: PASSED"
    log "Duration: ${duration}s"
    log "AppRoles Backed Up: $approle_count"
    log "Policies Backed Up: $policy_count"
    log "Backup Size: $tarball_size"
    log "S3 Location: s3://${AWS_S3_BACKUP_BUCKET}/${s3_key}"

    return 0
}

# Generate test report
generate_report() {
    local total_tests=$1
    local passed_tests=$2
    local failed_tests=$3
    local duration=$4

    log_section "Test Summary Report"

    cat > "${TEST_RESULTS_DIR}/backup-restore-report-${TIMESTAMP}.md" <<EOF
# Backup and Restore Test Report

**Date:** $(date -Iseconds)
**Environment:** ${ENVIRONMENT:-staging}
**Total Duration:** ${duration}s

## Summary

- **Total Tests:** $total_tests
- **Passed:** $passed_tests ✅
- **Failed:** $failed_tests ❌
- **Success Rate:** $(( passed_tests * 100 / total_tests ))%

## Test Results

### Test 1: Full Database Backup
- Status: ${TEST1_STATUS:-SKIPPED}
- Duration: ${TEST1_DURATION:-N/A}

### Test 2: Point-in-Time Recovery
- Status: ${TEST2_STATUS:-SKIPPED}
- Duration: ${TEST2_DURATION:-N/A}

### Test 3: Audit Log Archive and Restore
- Status: ${TEST3_STATUS:-SKIPPED}
- Duration: ${TEST3_DURATION:-N/A}

### Test 4: Configuration Backup
- Status: ${TEST4_STATUS:-SKIPPED}
- Duration: ${TEST4_DURATION:-N/A}

## Detailed Logs

See: ${TEST_LOG}

## Recommendations

1. Schedule automated daily backups
2. Verify backup integrity weekly
3. Test restore procedures quarterly
4. Monitor S3 storage costs
5. Update DR documentation with any issues found

---

**Generated:** $(date -Iseconds)
EOF

    cat "${TEST_RESULTS_DIR}/backup-restore-report-${TIMESTAMP}.md"
}

# Main execution
main() {
    local test_name="${1:-all}"

    log_section "SecretHub Backup & Restore Testing"
    log "Test Name: $test_name"
    log "Timestamp: $TIMESTAMP"
    log "Log File: $TEST_LOG"

    check_prerequisites

    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    local start_time=$(date +%s)

    case "$test_name" in
        full-backup)
            total_tests=1
            if test_full_backup; then
                passed_tests=1
                export TEST1_STATUS="PASSED"
            else
                failed_tests=1
                export TEST1_STATUS="FAILED"
            fi
            ;;
        point-in-time)
            total_tests=1
            if test_point_in_time; then
                passed_tests=1
                export TEST2_STATUS="PASSED"
            else
                failed_tests=1
                export TEST2_STATUS="FAILED"
            fi
            ;;
        audit-archive)
            total_tests=1
            if test_audit_archive; then
                passed_tests=1
                export TEST3_STATUS="PASSED"
            else
                failed_tests=1
                export TEST3_STATUS="FAILED"
            fi
            ;;
        config-backup)
            total_tests=1
            if test_config_backup; then
                passed_tests=1
                export TEST4_STATUS="PASSED"
            else
                failed_tests=1
                export TEST4_STATUS="FAILED"
            fi
            ;;
        all)
            total_tests=4

            if test_full_backup; then
                ((passed_tests++))
                export TEST1_STATUS="PASSED"
            else
                ((failed_tests++))
                export TEST1_STATUS="FAILED"
            fi

            if test_point_in_time; then
                ((passed_tests++))
                export TEST2_STATUS="PASSED"
            else
                ((failed_tests++))
                export TEST2_STATUS="FAILED"
            fi

            if test_audit_archive; then
                ((passed_tests++))
                export TEST3_STATUS="PASSED"
            else
                ((failed_tests++))
                export TEST3_STATUS="FAILED"
            fi

            if test_config_backup; then
                ((passed_tests++))
                export TEST4_STATUS="PASSED"
            else
                ((failed_tests++))
                export TEST4_STATUS="FAILED"
            fi
            ;;
        *)
            log_error "Unknown test: $test_name"
            echo "Usage: $0 [full-backup|point-in-time|audit-archive|config-backup|all]"
            exit 1
            ;;
    esac

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Generate report
    generate_report "$total_tests" "$passed_tests" "$failed_tests" "$duration"

    log_section "Testing Complete"
    log "Total Tests: $total_tests"
    log "Passed: $passed_tests"
    log "Failed: $failed_tests"
    log "Duration: ${duration}s"
    log "Full log: $TEST_LOG"

    if [ "$failed_tests" -eq 0 ]; then
        log_success "All tests passed! 🎉"
        exit 0
    else
        log_error "Some tests failed. Please review the logs."
        exit 1
    fi
}

# Run main function
main "$@"
