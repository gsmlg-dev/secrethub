# PRD: SecretHub Comprehensive Test Plan

## Product Overview

SecretHub is an enterprise M2M secrets management platform built with Elixir/Phoenix. It consists of:

- **SecretHub Core**: Central Phoenix service managing PKI, policies, secret engines, and audit logging
- **SecretHub Agent**: Local daemon for secure secret delivery via Unix Domain Sockets
- **Communication**: Persistent mTLS WebSocket connections between Core and Agents

This PRD defines the test plan for validating all SecretHub functionality. The goal is to run the existing test suite, identify failures, fix them, and add missing test coverage for critical gaps.

## Development Environment

- **Framework**: Elixir umbrella app (Phoenix 1.8, Ecto, Oban)
- **Database**: PostgreSQL 16 via Unix domain socket (managed by devenv)
- **Dev shell**: `devenv shell` activates the environment (or direnv auto-activates)
- **DB setup**: Run `db-setup` (alias for create + migrate + seed)
- **Server**: Run `server` (alias for `mix phx.server` on port 4664)
- **Test command**: `mix test`
- **Quality checks**: `mix format --check-formatted && mix credo --strict`

### Important Environment Notes

- PostgreSQL connects via Unix socket at `$DEVENV_STATE/postgres`, NOT TCP
- Test database: `secrethub_test` (user: `secrethub`, password: `secrethub_dev_password`)
- Ecto SQL Sandbox is used for test isolation
- `SealState` GenServer is NOT auto-started in test env — tests must use `start_supervised/1`

## Objectives

### Primary: Fix All Failing Tests

1. Run `mix test` and capture all failures
2. Categorize failures by root cause (compilation errors, missing modules, DB issues, logic bugs)
3. Fix each failure, prioritizing by dependency order (compilation > DB > logic)
4. Achieve 100% pass rate on the existing test suite

### Secondary: Add Missing Test Coverage for Critical Security Gaps

After all existing tests pass, add tests for these known gaps:

1. **Authentication route coverage** — Several API routes lack authentication plugs
2. **Policy condition evaluation** — Time-of-day, IP range, max_ttl conditions untested
3. **Audit log concurrent inserts** — Race condition retry logic needs coverage
4. **Real PKI cert issuance** — Currently returns mock PEM instead of CA-signed certs

### Tertiary: Code Quality

1. All code passes `mix format --check-formatted`
2. All code passes `mix credo --strict`
3. No compiler warnings (`--warnings-as-errors`)

## Architecture Reference

### Umbrella App Structure

```
apps/
  secrethub_core/       # Core business logic, DB migrations, all Ecto schemas
  secrethub_web/        # Phoenix web interface & REST API (namespace: SecretHub.Web)
  secrethub_agent/      # Agent daemon (bootstrap, WebSocket, cache)
  secrethub_shared/     # Shared Ecto schemas and protocols
  secrethub_cli/        # CLI tool (escript)
```

### Key Module Namespaces

- `SecretHub.Core.Auth.AppRole` — AppRole authentication (role_id/secret_id login)
- `SecretHub.Core.Vault.SealState` — Vault seal/unseal state machine (GenServer)
- `SecretHub.Core.Secrets` — Secret CRUD with encryption and versioning
- `SecretHub.Core.Policies` — Policy engine with glob matching and conditions
- `SecretHub.Core.Audit` — Tamper-evident audit logging with hash chain (SHA-256 + HMAC)
- `SecretHub.Core.PKI.CA` — Certificate Authority (Root CA, Intermediate CA, CSR signing)
- `SecretHub.Core.Agents` — Agent registration, bootstrap, lifecycle
- `SecretHub.Core.LeaseManager` — Dynamic secret lease lifecycle
- `SecretHub.Core.Engines.Dynamic.*` — PostgreSQL, Redis, AWS STS credential generation
- `SecretHub.Web.Endpoint` — Phoenix endpoint (port 4664)
- `SecretHub.Web.Router` — All API routes
- `SecretHub.Agent.Bootstrap` — AppRole-based agent bootstrap flow
- `SecretHub.Agent.Connection` — WebSocket client with reconnect backoff
- `SecretHub.Agent.EndpointManager` — HA endpoint management with health checks
- `SecretHub.Agent.Cache` — Local secret cache with TTL

### REST API Routes

- `/v1/sys/*` — System operations (init, seal/unseal, health) — no auth required
- `/v1/auth/approle/*` — AppRole authentication and management
- `/v1/secrets/*` — Secret read/write operations
- `/v1/secrets/dynamic/*` — Dynamic credential generation
- `/v1/sys/leases/*` — Lease management
- `/v1/pki/*` — PKI and certificate operations
- `/v1/apps/*` — Application registration and management
- `/admin/*` — LiveView admin dashboard
- `/admin/api/*` — Admin JSON API endpoints

### Database Conventions

- Primary keys: `:binary_id` (UUID)
- `Repo.get_by` with `:binary_id` fields will crash on non-UUID input — validate with `Ecto.UUID.cast/1` first
- `validate_required` rejects empty strings — test data generators must produce non-empty values
- Partitioned tables rename constraints per-partition — `unique_constraint` with parent table name won't match
- ConnCase tests need explicit Ecto Sandbox setup or they fail with `DBConnection.OwnershipError`

## Test Inventory

### Existing Test Files

**Core unit tests:**
- `apps/secrethub_core/test/secrethub_core/vault/seal_state_test.exs`
- `apps/secrethub_core/test/secrethub_core/cluster_state_test.exs`
- `apps/secrethub_core/test/secrethub_core/engines/dynamic/postgresql_test.exs`
- `apps/secrethub_core/test/secrethub_core/lease_manager_test.exs`
- `apps/secrethub_core/test/secrethub_core/pki/ca_test.exs`

**Web tests:**
- `apps/secrethub_web/test/secrethub_web_web/controllers/error_html_test.exs`
- `apps/secrethub_web/test/secrethub_web_web/controllers/error_json_test.exs`
- `apps/secrethub_web/test/secrethub_web_web/controllers/page_controller_test.exs`
- `apps/secrethub_web/test/secrethub_web/channels/agent_channel_test.exs`
- `apps/secrethub_web/test/secrethub_web_web/channels/agent_channel_test.exs`
- `apps/secrethub_web/test/secrethub_web_web/plugs/verify_client_certificate_test.exs`
- `apps/secrethub_web/test/secrethub_web_web/live/cluster_status_live_test.exs`

**E2E tests:**
- `apps/secrethub_web/test/secrethub_web_web/controllers/vault_unsealing_e2e_test.exs`
- `apps/secrethub_web/test/secrethub_web_web/controllers/secret_management_e2e_test.exs`
- `apps/secrethub_web/test/secrethub_web_web/controllers/agent_registration_e2e_test.exs`
- `apps/secrethub_web/test/secrethub_web_web/controllers/access_control_e2e_test.exs`
- `apps/secrethub_web/test/secrethub_web_web/controllers/audit_trail_e2e_test.exs`
- `apps/secrethub_web/test/secrethub_web_web/controllers/pki_lifecycle_e2e_test.exs`
- `apps/secrethub_web/test/secrethub_web_web/controllers/app_management_e2e_test.exs`
- `apps/secrethub_web/test/secrethub_web_web/controllers/system_health_e2e_test.exs`

**Agent tests:**
- `apps/secrethub_agent/test/secrethub_agent/bootstrap_test.exs`
- `apps/secrethub_agent/test/secrethub_agent/lease_renewer_test.exs`
- `apps/secrethub_agent/test/secrethub_agent/connection_test.exs`

**CLI tests:**
- `apps/secrethub_cli/test/secrethub_cli_test.exs`
- `apps/secrethub_cli/test/secrethub_cli/output_test.exs`
- `apps/secrethub_cli/test/secrethub_cli/auth_test.exs`
- `apps/secrethub_cli/test/secrethub_cli/config_test.exs`
- `apps/secrethub_cli/test/secrethub_cli/commands/*_test.exs`

**Shared tests:**
- `apps/secrethub_shared/test/secrethub_shared/crypto/encryption_test.exs`
- `apps/secrethub_shared/test/secrethub_shared/crypto/shamir_test.exs`

**Performance tests:**
- `test/performance/agent_load_test.exs`

## Execution Plan

### Phase 1: Environment Setup and Baseline

1. Ensure devenv is active and PostgreSQL is running
2. Run `mix deps.get` to fetch dependencies
3. Run `mix compile --warnings-as-errors 2>&1` — capture and fix any compilation errors
4. Run `db-setup` or `mix ecto.create && mix ecto.migrate` for test database
5. Run `MIX_ENV=test mix ecto.create && MIX_ENV=test mix ecto.migrate`
6. Run `mix test 2>&1` — capture full output as the baseline

### Phase 2: Fix Compilation Errors

If Phase 1 reveals compilation errors:
1. Fix missing module references
2. Fix function arity mismatches
3. Fix missing dependency declarations in umbrella app mix.exs files
4. Re-run `mix compile --warnings-as-errors` until clean

### Phase 3: Fix Test Failures

For each failing test, categorize and fix:

**Category A — Test setup issues:**
- Missing Ecto Sandbox setup in test modules
- SealState not started (needs `start_supervised`)
- Missing test helper imports

**Category B — Missing implementations:**
- Functions referenced in tests but not yet implemented
- Stub implementations that need to be completed

**Category C — Logic bugs:**
- Incorrect return values
- Race conditions
- Constraint violations

**Category D — Test bugs:**
- Tests asserting wrong values
- Tests using incorrect API (e.g., `json_response/2` with list of status codes)
- Tests with wrong channel topics or module names

Fix order: A -> B -> C -> D (dependencies flow downward)

### Phase 4: Add Critical Missing Tests

After all existing tests pass, add tests for these priority gaps:

#### P0 — Authentication Route Coverage

Test that protected API routes return 401 without a valid token:
- `POST /v1/secrets/dynamic/:role` without auth token
- `GET /v1/sys/leases/` without auth token
- `POST /v1/sys/leases/renew` without auth token
- `POST /v1/pki/ca/root/generate` without auth token
- `POST /v1/apps` without auth token

If routes are missing auth plugs, add the appropriate plug pipeline.

#### P0 — AppRole Security

- Token with wrong endpoint returns error
- Expired token returns error
- Non-UUID role_id input returns auth error (not 500 CastError)
- Login with wrong secret_id returns identical error message as wrong role_id (no enumeration)

#### P1 — Policy Condition Evaluation

- Time-of-day condition: access within allowed window succeeds
- Time-of-day condition: access outside window denied
- IP range condition: source IP in CIDR succeeds
- IP range condition: source IP not in CIDR denied
- max_ttl condition: TTL within limit succeeds
- max_ttl condition: TTL above limit denied

#### P1 — Audit Log Concurrent Inserts

- 10 concurrent `log_event/1` calls all succeed (no lost writes)
- After concurrent inserts, sequence numbers have no gaps
- After concurrent inserts, `verify_chain/0` returns `{:ok, :valid}`
- Retry logic handles `Ecto.ConstraintError` correctly

#### P1 — Agent Connection Resilience

- Reconnect interval grows with retry count (exponential backoff)
- Reconnect interval is capped at 60 seconds
- Successful connect resets retry counter
- Jitter is applied to backoff (no thundering herd)

### Phase 5: Quality Checks

1. Run `mix format` to auto-format all code
2. Run `mix credo --strict` and fix any issues
3. Run `mix compile --warnings-as-errors` and fix any warnings
4. Final `mix test` to confirm everything still passes

## Success Criteria

| Criterion | Target |
|-----------|--------|
| Existing test suite | 100% pass rate |
| New P0 security tests | All passing |
| New P1 tests | All passing |
| `mix format --check-formatted` | Clean |
| `mix credo --strict` | Clean |
| `mix compile --warnings-as-errors` | Clean |
| No tests with `async: true` touching shared GenServer state | 0 violations |

## Known Pitfalls (Read Before Starting)

These are lessons learned from previous test runs — avoid repeating these mistakes:

1. **Ecto.Query.CastError on non-UUID**: `Repo.get_by(Schema, id: "not-a-uuid")` crashes. Always validate with `Ecto.UUID.cast/1` before querying `:binary_id` fields.

2. **validate_required rejects ""**: When generating test data, use `"test_value_#{System.unique_integer()}"` not `""`.

3. **Partitioned table constraints**: PostgreSQL renames constraints on partitioned tables (e.g., `audit_logs_y2026m02_pkey`). Ecto `unique_constraint(name: "audit_logs_pkey")` won't match. Use `rescue Ecto.ConstraintError` instead.

4. **ConnCase needs Sandbox**: Every test module using `ConnCase` needs:
   ```elixir
   setup do
     :ok = Ecto.Adapters.SQL.Sandbox.checkout(SecretHub.Core.Repo)
   end
   ```

5. **SealState in tests**: The GenServer isn't auto-started in test env. Use:
   ```elixir
   setup do
     {:ok, _pid} = start_supervised(SecretHub.Core.Vault.SealState)
     :ok
   end
   ```

6. **json_response/2 quirk**: `Phoenix.ConnTest.json_response(conn, [200, 201])` doesn't work. Assert status separately then decode body.

7. **Channel topics**: Must match exactly. The implementation uses `"agent:lobby"` not `"agent:<agent_id>"`.

8. **Mox setup**: Requires `Application.ensure_all_started(:mox)` in `test_helper.exs`.

9. **Audit log race conditions**: Concurrent inserts collide on `(sequence_number, timestamp)`. The fix uses retry logic — rescue `Ecto.ConstraintError` and retry up to 3 times.

10. **Phoenix.Token signing**: Requires the Endpoint to be started. In tests, ensure `SecretHub.Web.Endpoint` is in the application supervision tree or started manually.

## Deliverables

After all phases complete:

1. All existing tests passing with `mix test`
2. New test files for P0 and P1 gaps
3. Any bug fixes applied to source code
4. Clean `mix format` and `mix credo --strict`
5. Git diff summary of all changes made
