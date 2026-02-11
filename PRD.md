#!/bin/bash
# SecretHub E2E Testing Execution Script
# This script invokes Claude Code to perform comprehensive E2E testing

set -e

echo "🔐 SecretHub E2E Testing with Claude Code"
echo "=========================================="
echo ""

# Check if Claude Code is installed
if ! command -v claude-code &> /dev/null; then
    echo "❌ Error: claude-code not found"
    echo "Please install Claude Code first"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "devenv.nix" ]; then
    echo "❌ Error: Not in SecretHub project root"
    echo "Please run this script from the secrethub/ directory"
    exit 1
fi

# Create results directory
mkdir -p test-results
mkdir -p test-results/screenshots
mkdir -p test-results/logs

echo "📋 Invoking Claude Code with E2E Testing PRD..."
echo ""

# Execute Claude Code with the PRD
claude-code <<'EOF'
You are tasked with performing comprehensive End-to-End testing of the SecretHub WebSocket implementation following the PDCA (Plan-Do-Check-Act) methodology.

**Primary Objective:** Validate, debug, and fix the WebSocket communication between SecretHub Core and Agent.

## YOUR INSTRUCTIONS:

### PLAN Phase (10 minutes)

1. Review the current codebase structure:
   - apps/secrethub_web/lib/secrethub_web/channels/
   - apps/secrethub_agent/lib/secrethub_agent/
   - config/dev.exs

2. Identify all components that need testing:
   - Phoenix Socket configuration
   - Phoenix Channel implementation
   - Agent WebSocket client
   - Database integration
   - Configuration files

3. Design test scenarios (document your plan):
   - Connection establishment
   - Message request/reply
   - Error handling
   - Concurrent requests
   - Connection recovery

### DO Phase (30-60 minutes)

**Step 1: Start Environment**
```bash
# Start devenv services
devenv up

# Wait for PostgreSQL
until psql -U secrethub -d secrethub_dev -c "SELECT 1" > /dev/null 2>&1; do
  sleep 2
done

# Setup database
cd apps/secrethub_core
mix ecto.create || echo "Database exists"
mix ecto.migrate
cd ../..
```

**Step 2: Compile Everything**
```bash
mix deps.get
mix compile 2>&1 | tee test-results/logs/compile.log

# Document any compilation errors
```

**Step 3: Start Phoenix Server**
```bash
cd apps/secrethub_web
mix phx.server > ../../test-results/logs/server.log 2>&1 &
SERVER_PID=$!
echo $SERVER_PID > ../../test-results/server.pid

# Wait for server
sleep 5

# Test server is responding
curl -f http://localhost:4000 && echo "✅ Server is running" || echo "❌ Server failed to start"
```

**Step 4: Test Agent Connection**
```bash
cd apps/secrethub_agent

# Start agent and test connection
iex -S mix <<'IEXEOF'
# Wait for connection
Process.sleep(3000)

# Test static secret request
case SecretHub.Agent.Connection.get_static_secret("test.secret") do
  {:ok, response} -> 
    IO.puts("✅ SECRET REQUEST SUCCESS")
    IO.inspect(response)
  {:error, reason} -> 
    IO.puts("❌ SECRET REQUEST FAILED")
    IO.inspect(reason)
end

# Exit
System.halt(0)
IEXEOF
```

**Step 5: Run Automated Tests**
```bash
# Run all tests
mix test 2>&1 | tee test-results/logs/test-results.log

# Check exit code
if [ $? -eq 0 ]; then
  echo "✅ All tests passed"
else
  echo "❌ Tests failed - analyzing..."
fi
```

**Step 6: Database Validation**
```bash
psql -U secrethub -d secrethub_dev <<DBEOF
-- Check tables exist
\dt

-- Check for any data
SELECT 'Secrets count:' as info, COUNT(*) FROM secrets WHERE EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'secrets');
SELECT 'Audit logs count:' as info, COUNT(*) FROM audit_logs WHERE EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_logs');

-- Show any errors
SELECT * FROM pg_stat_activity WHERE state = 'idle in transaction';

\q
DBEOF
```

### CHECK Phase (20 minutes)

Review all results and categorize issues:

1. **Critical Issues** (system doesn't work at all):
   - Server won't start
   - Agent can't connect
   - Database errors

2. **High Priority Issues** (features don't work):
   - Requests fail
   - Responses malformed
   - Timeouts

3. **Medium Issues** (degraded experience):
   - Slow responses
   - Missing error handling
   - Poor logging

4. **Low Issues** (cosmetic):
   - Typos in logs
   - Code style

Document each issue found:
```markdown
## Bug Report

### Bug #1: [Title]
**Severity:** Critical/High/Medium/Low
**File:** path/to/file.ex:line
**Error:** [paste error message]
**Fix needed:** [what to change]
```

### ACT Phase (60-120 minutes)

**Fix each bug in order of severity:**

For CRITICAL bugs:
1. Identify root cause by examining:
   - Error messages
   - Stack traces
   - Log files
   - Code at error location

2. Implement fix:
   - Modify code
   - Add missing functions
   - Fix configuration
   - Update dependencies

3. Test fix immediately:
   - Restart affected service
   - Re-run specific test
   - Verify fix works

4. Continue to next critical bug

For HIGH PRIORITY bugs:
- Follow same process after all critical bugs fixed

**Common Fixes You'll Likely Need:**

**Fix 1: Socket not registered**
```elixir
# In apps/secrethub_web/lib/secrethub_web/endpoint.ex
# Add BEFORE the plug definitions:

socket "/agent/socket", SecretHub.Web.AgentSocket,
  websocket: true,
  longpoll: false
```

**Fix 2: Missing Channel module**
```elixir
# Create apps/secrethub_web/lib/secrethub_web/channels/agent_channel.ex
defmodule SecretHub.Web.AgentChannel do
  use Phoenix.Channel
  require Logger

  @impl true
  def join("agent:" <> _agent_id, _payload, socket) do
    {:ok, socket}
  end

  @impl true
  def handle_in("secrets:get_static", %{"path" => path}, socket) do
    response = %{value: "mock_secret", version: 1}
    {:reply, {:ok, response}, socket}
  end
end
```

**Fix 3: Connection GenServer issues**
```elixir
# In apps/secrethub_agent/lib/secrethub_agent/connection.ex
# Ensure handle_info for :connect is present
# Ensure Channel.join is called correctly
# Ensure Channel.push uses correct format
```

**Fix 4: Missing dependency**
```elixir
# In apps/secrethub_agent/mix.exs
defp deps do
  [
    {:phoenix_socket_client, "~> 0.5"},
    {:jason, "~> 1.4"}
  ]
end
```

After each fix:
```bash
# Recompile
mix compile

# Restart server
kill $SERVER_PID
cd apps/secrethub_web
mix phx.server &
SERVER_PID=$!

# Re-test
# ... repeat tests ...
```

### FINAL VALIDATION

When you believe all critical and high issues are fixed:

1. Run complete test suite:
```bash
mix test --trace
```

2. Manual E2E test:
```bash
# Start fresh
devenv down
devenv up
mix ecto.reset
mix phx.server &

# Test agent connection
cd apps/secrethub_agent
iex -S mix
# In IEx:
SecretHub.Agent.Connection.get_static_secret("final.test")
```

3. Let system run for 5 minutes, monitor for:
   - Memory leaks
   - Connection drops
   - Error logs

### DELIVERABLES

Provide at the end:

1. **test-results/summary.md** with:
   - Total bugs found: X
   - Critical bugs fixed: Y
   - High priority bugs fixed: Z
   - Tests passing: A/B
   - System status: ✅ Working / ⚠️ Degraded / ❌ Broken

2. **test-results/bugs-found.md** with all bugs documented

3. **test-results/fixes-applied.md** with all code changes

4. **test-results/remaining-issues.md** with any unfixed issues

5. Git diff of all changes:
```bash
git diff > test-results/all-changes.diff
```

## IMPORTANT NOTES:

- If you encounter a bug you cannot fix, document it thoroughly and move to next
- Prioritize getting the basic flow working over perfection
- Use mock/stub implementations where needed
- Add extensive logging for debugging
- Every fix should have a comment explaining WHY
- Test after EACH fix, not at the end

## SUCCESS CRITERIA:

✅ Phoenix server starts without errors
✅ Agent connects to server successfully  
✅ Agent can request a secret and get response
✅ Response is properly formatted
✅ Connection stays alive for 5+ minutes
✅ At least 80% of tests pass
✅ Zero critical bugs remaining

You have access to:
- File system (read/write all project files)
- Shell execution (run any bash commands)
- Database access (psql commands)

**Begin the PDCA cycle now. Be thorough and systematic. Good luck!**
EOF

echo ""
echo "✅ Claude Code execution complete!"
echo ""
echo "📊 Results available in test-results/"
echo ""
echo "To review:"
echo "  cat test-results/summary.md"
echo "  cat test-results/bugs-found.md"
echo "  cat test-results/logs/*.log"
echo ""
