#!/usr/bin/env bash

# Quality Check Script
# Runs all quality checks that GitHub Actions will run
# Usage: ./scripts/quality-check.sh

set -e  # Exit on error

echo "════════════════════════════════════════════════════════════════"
echo "  SecretHub Quality Check"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track failures
FAILED=0

run_check() {
    local name=$1
    shift
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Running: $name"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if "$@"; then
        echo -e "${GREEN}✓ $name passed${NC}"
    else
        echo -e "${RED}✗ $name failed${NC}"
        FAILED=$((FAILED + 1))
    fi
    echo ""
}

# 1. Format Check
run_check "Format Check" mix format --check-formatted

# 2. Compilation with warnings as errors
run_check "Compilation (warnings as errors)" mix compile --warnings-as-errors

# 3. Credo (strict mode)
run_check "Credo (strict)" mix credo --strict

# 4. Dialyzer
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Running: Dialyzer (this may take a while...)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if mix dialyzer --halt-exit-status; then
    echo -e "${GREEN}✓ Dialyzer passed${NC}"
else
    echo -e "${RED}✗ Dialyzer failed${NC}"
    FAILED=$((FAILED + 1))
fi
echo ""

# 5. Tests (optional - can be slow)
if [ "$SKIP_TESTS" != "1" ]; then
    run_check "Tests" mix test
else
    echo -e "${YELLOW}⊘ Tests skipped (set SKIP_TESTS=0 to run)${NC}"
    echo ""
fi

# Summary
echo "════════════════════════════════════════════════════════════════"
echo "  Summary"
echo "════════════════════════════════════════════════════════════════"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Your code is ready to be committed and pushed."
    exit 0
else
    echo -e "${RED}✗ $FAILED check(s) failed${NC}"
    echo ""
    echo "Please fix the errors above before committing."
    exit 1
fi
