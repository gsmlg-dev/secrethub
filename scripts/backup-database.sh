#!/usr/bin/env bash
# DATABASE_URL + BACKUP_DIR select the operator's local destination; S3 is optional.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 -B "$SCRIPT_DIR/database-backup.py" backup "$@"
