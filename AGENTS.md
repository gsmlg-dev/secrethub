# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SecretHub is an enterprise-grade Machine-to-Machine secrets management platform built with Elixir. It provides centralized secrets storage, dynamic credential generation, automatic rotation, and mTLS-based secure communication between core services and agents.

**Architecture:** Two-tier system
- **SecretHub Core**: Central Phoenix-based service managing PKI, policies, secret engines, and audit logging
- **SecretHub Agent**: Local daemon deployed alongside applications for secure secret delivery via Unix Domain Sockets
- **Communication**: Persistent mTLS WebSocket connections between Core and Agents

## Development Environment

This project uses **devenv** (devenv.sh) with Nix for reproducible development environments. PostgreSQL is automatically managed by devenv.

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

# Testing (devenv sets MIX_ENV=dev, so use test-all or prefix with MIX_ENV=test)
test-all                                    # Run all tests (sets MIX_ENV=test)
test-all apps/secrethub_core/test/          # Test specific app
test-all path/to/test_file.exs              # Run single test file
test-all path/to/test_file.exs:42           # Run single test at line
test-watch                                  # Watch mode for tests

# Code Quality
mix format                                  # Format code
mix credo --strict                          # Linter
mix dialyzer                                # Static type analysis
quality                                     # Run format check + credo + dialyzer (devenv script)
./scripts/quality-check.sh                  # Full CI checks locally (format + compile --warnings-as-errors + credo + dialyzer + tests)
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
- **`@duskmoon-dev/core`** — TailwindCSS plugin (CSS/design tokens only)
- **`phoenix_duskmoon`** — Phoenix component module (Elixir/HEEx components, `dm_*` prefix)
- **Heroicons** for icons
- Phoenix LiveView for interactive admin dashboard components

#### UI Constraints
- **Do not** vendor or copy component internals — consume via the package APIs only
- **Do not** override `@duskmoon-dev/core` design tokens locally; propose upstream changes instead
- **Do not** patch `phoenix_duskmoon` component logic inline; wrap or compose instead
- Upstream bugs/gaps → file GitHub issue with label `internal request` in the correct repo:
  - CSS/token/plugin → `duskmoon-dev/duskmoonui`
  - Web component/element → `duskmoon-dev/duskmoon-elements`
  - Phoenix component → `duskmoon-dev/phoenix-duskmoon-ui`

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

Infrastructure code in `/infrastructure/` (PostgreSQL init scripts).

## Commit Convention

```
type(scope): subject
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Scopes: `core`, `web`, `agent`, `shared`, `cli`, `infra`

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **secrethub** (2648 symbols, 2701 relationships, 1 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> If any GitNexus tool warns the index is stale, run `npx gitnexus analyze` in terminal first.

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `gitnexus_impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `gitnexus_detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `gitnexus_query({query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `gitnexus_context({name: "symbolName"})`.

## Never Do

- NEVER edit a function, class, or method without first running `gitnexus_impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `gitnexus_rename` which understands the call graph.
- NEVER commit changes without running `gitnexus_detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/secrethub/context` | Codebase overview, check index freshness |
| `gitnexus://repo/secrethub/clusters` | All functional areas |
| `gitnexus://repo/secrethub/processes` | All execution flows |
| `gitnexus://repo/secrethub/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
