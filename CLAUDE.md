# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SecretHub is an enterprise-grade Machine-to-Machine secrets management platform built with Elixir. It provides centralized secrets storage, dynamic credential generation, automatic rotation, and mTLS-based secure communication between core services and agents.

**Architecture:** Two-tier system
- **SecretHub Core**: Central Phoenix-based service managing PKI, policies, secret engines, and audit logging
- **SecretHub Agent**: Local daemon deployed alongside applications for secure secret delivery via Unix Domain Sockets
- **Communication**: Persistent mTLS WebSocket connections between Core and Agents

## Development Environment

This project uses **devenv** (devenv.sh) with Nix for reproducible development environments. PostgreSQL and Prometheus are automatically managed by devenv.

### Initial Setup

```bash
devenv shell          # Enter devenv shell (or use direnv for automatic activation)
db-setup              # Create database, run migrations, seed data
assets-install        # Install frontend dependencies (Bun + Tailwind)
```

### Essential Commands

```bash
# Development
server                # Start Phoenix server (http://localhost:4664)
console               # Start IEx shell with application loaded

# Database
db-setup              # Create database and run migrations + seeds
db-reset              # Drop, recreate, migrate, and seed database
db-migrate            # Run pending migrations only

# Testing
mix test                                    # Run all tests
mix test apps/secrethub_core/test/          # Test specific app
mix test path/to/test_file.exs              # Run single test file
mix test path/to/test_file.exs:42           # Run single test at line
test-watch                                  # Watch mode for tests

# Code Quality
mix format                                  # Format code
mix credo --strict                          # Linter
mix dialyzer                                # Static type analysis
quality                                     # Run format check + credo + dialyzer
./scripts/quality-check.sh                  # Full CI checks locally (includes tests)
SKIP_TESTS=1 ./scripts/quality-check.sh     # CI checks without tests

# Database Migrations (always from secrethub_core)
cd apps/secrethub_core && mix ecto.gen.migration create_table_name
cd apps/secrethub_core && mix ecto.migrate
cd apps/secrethub_core && mix ecto.rollback
```

## Project Structure (Umbrella App)

Elixir umbrella project with 5 apps sharing `mix.lock`, `deps/`, and `_build/` at the root. Configuration is centralized in `/config/*.exs`.

```
apps/
  secrethub_core/       Core business logic (auth, engines, PKI, policies, audit, crypto)
                        All database migrations live in priv/repo/migrations/
  secrethub_web/        Phoenix web interface & REST API
                        Source: lib/secret_hub/web/ (namespace: SecretHub.Web)
  secrethub_agent/      Agent daemon (bootstrap, WebSocket connection, cache, sinker)
  secrethub_shared/     Shared Ecto schemas and communication protocols
  secrethub_cli/        CLI tool (escript, built with `mix escript.build`)
```

### Key Module Namespaces

- `SecretHub.Core.*` - Core business logic (auth, engines, PKI, etc.)
- `SecretHub.Web.*` - Phoenix web layer (endpoint: `SecretHub.Web.Endpoint`)
- `SecretHub.Agent.*` - Agent daemon modules
- `SecretHub.Shared.*` - Shared schemas and protocols
- `SecretHub.CLI` - CLI escript entry point

**Important:** The web app's namespace is `SecretHub.Web` (configured in `config.exs`), and source lives at `apps/secrethub_web/lib/secret_hub/web/` - not `lib/secrethub_web_web/` as Phoenix typically generates.

## Architecture Concepts

### Database (PostgreSQL 16)
- **Connection**: Unix domain socket at `$DEVENV_STATE/postgres` (no TCP port exposed)
- **Dev database**: `secrethub_dev` (user: `secrethub`, password: `secrethub_dev_password`)
- **Test database**: `secrethub_test` (same credentials)
- **Extensions**: `uuid-ossp`, `pgcrypto`
- **Schemas**: Default schema + `audit` schema for audit logs
- All migrations must be created in `apps/secrethub_core/`

### Frontend Assets
- **Bun** for JavaScript bundling (not npm/esbuild)
- **Tailwind CSS v4.1.7** (installed globally via bun, path: `$HOME/.bun/bin/tailwindcss`)
- **DaisyUI** for UI components, **Heroicons** for icons
- Phoenix LiveView for interactive admin dashboard components

### Authentication & Security
- mTLS between Core and Agents; PKI engine manages internal CA
- Agent bootstrap: AppRole auth (RoleID/SecretID) -> CSR -> Certificate issuance -> mTLS WebSocket
- Applications connect to local Agent via Unix Domain Sockets

### Background Jobs
- **Oban** for persistent background tasks (secret rotation, lease cleanup)
- New background jobs must integrate with Oban configuration

### Audit Logging
- All operations must be logged to the audit subsystem
- Hash chain implementation (SHA-256 + HMAC) for tamper-evident logs

### Secret Engines
Located in `apps/secrethub_core/lib/secrethub_core/engines/`:
- **Dynamic engines**: Generate temporary credentials (PostgreSQL, Redis, AWS STS) - integrate with Lease Manager
- **Static engines**: Rotate long-lived credentials - integrate with Oban scheduler

### REST API Routes
- `/v1/sys/*` - System operations (init, seal/unseal, health) - no auth required
- `/v1/auth/approle/*` - AppRole authentication and management
- `/v1/secrets/*` - Secret read/write operations
- `/v1/secrets/dynamic/*` - Dynamic credential generation
- `/v1/sys/leases/*` - Lease management
- `/v1/pki/*` - PKI and certificate operations
- `/v1/apps/*` - Application registration and management
- `/admin/*` - LiveView admin dashboard (session-based auth)
- `/dev/dashboard` - Phoenix LiveDashboard (dev only)
- `/dev/mailbox` - Swoosh email preview (dev only)

## CI/CD

**CI Workflow** (`ci.yml`) - 4 parallel jobs on every push: compile (`--warnings-as-errors`), format check, credo (strict), dialyzer.

**Test Workflow** (`test.yml`) - On push to main/develop and PRs: full test suite with PostgreSQL 16 + Redis 7 services.

**Release Workflow** (`release.yml`) - On version tags (`v*.*.*`): builds tar.gz releases + multi-arch Docker images, publishes to `ghcr.io/gsmlg-dev/secrethub/{core,agent}`.

CI environment: Elixir 1.18, OTP 28. Caches: deps (keyed by `mix.lock`), dialyzer PLT.

## Deployment

Two release configurations in root `mix.exs`:
1. **secrethub_core**: `secrethub_core` + `secrethub_web` + `secrethub_shared`
2. **secrethub_agent**: `secrethub_agent` + `secrethub_shared`

Infrastructure code in `/infrastructure/` (Helm charts, Kubernetes manifests, Prometheus configs).

## Commit Convention

```
type(scope): subject
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Scopes: `core`, `web`, `agent`, `shared`, `cli`, `infra`
