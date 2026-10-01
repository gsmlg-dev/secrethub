#!/usr/bin/env bash
# Restore only a versioned manifest to an explicitly selected empty target.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 -B "$SCRIPT_DIR/database-backup.py" restore "$@"
