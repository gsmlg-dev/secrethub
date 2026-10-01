#!/usr/bin/env bash
# Scoped tests use fake tools by default; real database fixtures require explicit opt-in.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 -B -m unittest discover -s "$SCRIPT_DIR/tests" -p 'test_backup_restore.py' "$@"
