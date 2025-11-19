# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SecretHub is an enterprise-grade Machine-to-Machine secrets management platform built with Elixir. It provides centralized secrets storage, dynamic credential generation, automatic rotation, and mTLS-based secure communication between core services and agents.

**Architecture:** Two-tier system
- **SecretHub Core**: Central Phoenix-based service managing PKI, policies, secret engines, and audit logging
- **SecretHub Agent**: Local daemon deployed alongside applications for secure secret delivery via Unix Domain Sockets
- **Communication**: Persistent mTLS WebSocket connections between Core and Agents

**Current Status:** Week 1 - Initial project setup complete, database schema design in progress

## Development Environment

This project uses **devenv** (devenv.sh) with Nix for reproducible development environments. All services (PostgreSQL, Redis, Prometheus) are automatically managed.

### Initial Setup

```bash
# Enter devenv shell (or use direnv for automatic activation)
devenv shell

# Initialize database
db-setup

# Install frontend dependencies (using Bun, not npm)
assets-install
```

### Essential Commands

**Development:**
```bash
server          # Start Phoenix server (http://localhost:4000)
console         # Start IEx shell with application loaded
iex -S mix      # Alternative way to start console
```

**Database:**
```bash
db-setup        # Create database and run migrations
db-reset        # Drop, recreate, migrate, and seed database
db-migrate      # Run pending migrations only
```

**Frontend (uses Bun, not npm):**
```bash
assets-install  # Install dependencies with Bun
assets-build    # Build assets with Bun
```

**Testing:**
```bash
mix test                              # Run all tests
mix test apps/secrethub_core/test/... # Test specific app
mix coveralls.html                     # Generate coverage report
test-watch                             # Watch mode for tests
mix test.watch                        # Alternative watch mode
```

**Code Quality:**
```bash
mix format              # Format code
mix credo --strict      # Run linter
mix dialyzer            # Static analysis
quality                 # Run all quality checks (format, credo, dialyzer)
./scripts/quality-check.sh  # Run all CI checks locally (format, compile, credo, dialyzer, tests)
```

**Database Migrations:**
```bash
# Generate new migration (run from app directory)
cd apps/secrethub_core
mix ecto.gen.migration create_table_name

# Run migrations from specific app
cd apps/secrethub_core && mix ecto.migrate

# Rollback migration
cd apps/secrethub_core && mix ecto.rollback
```

## Project Structure (Umbrella App)

This is an Elixir umbrella project with multiple apps:

```
apps/
├── secrethub_core/      # Core business logic
│   ├── lib/secrethub_core/
│   │   ├── auth/        # Authentication backends (AppRole, K8s SA)
│   │   ├── engines/     # Secret engines (Static, Dynamic PostgreSQL, Redis, AWS)
│   │   ├── pki/         # PKI & certificate management (CA, CRL, OCSP)
│   │   ├── policies/    # Policy engine for authorization
│   │   ├── audit/       # Audit logging with hash chains
│   │   └── crypto/      # Encryption & unsealing
│   └── priv/repo/migrations/  # Database migrations live here
│
├── secrethub_web/       # Phoenix web interface & API
│   ├── lib/secrethub_web_web/
│   │   ├── controllers/ # REST API endpoints
│   │   ├── live/        # LiveView components for UI
│   │   └── channels/    # WebSocket channels for Agent communication
│   └── assets/          # Frontend (Tailwind + esbuild, managed by Bun)
│
├── secrethub_agent/     # Agent daemon (deployed with applications)
│   ├── lib/secrethub_agent/
│   │   ├── bootstrap.ex   # Bootstrap & authentication flow
│   │   ├── connection.ex  # WebSocket client to Core
│   │   ├── cache.ex       # Local secret caching
│   │   ├── template.ex    # Template rendering engine
│   │   └── sinker.ex      # File writer for secrets
│
└── secrethub_shared/    # Shared code (schemas, protocols)
    └── lib/secrethub_shared/
        ├── schemas/     # Ecto schemas shared across apps
        └── protocols/   # Communication protocols
```

## Key Architecture Concepts

### Umbrella App Structure
- All apps share the same `mix.lock`, `deps/`, and `_build/` directories at the umbrella root
- Database operations are in `secrethub_core` - migrations must be run from that app's directory
- Configuration is centralized in `/config/*.exs`

### Database (PostgreSQL 16)
- **Connection:** Unix domain socket at `$DEVENV_STATE/postgres` (no TCP port exposed)
- **Main database:** `secrethub_dev` (user: `secrethub`, password: `secrethub_dev_password`)
- **Test database:** `secrethub_test`
- **Extensions enabled:** `uuid-ossp`, `pgcrypto`
- **Schemas:** Default schema + `audit` schema for audit logs
- All migrations are in `apps/secrethub_core/priv/repo/migrations/`
- **Security:** Unix sockets provide better security (no network exposure) and performance (no TCP overhead)

### Frontend Assets
- **Uses Bun, not npm** - Always use `assets-install`, never `npm install`
- Tailwind CSS v4.1.7 for styling
- esbuild v0.25.4 for JavaScript bundling
- Phoenix LiveView for interactive components
- DaisyUI for UI components (pre-configured)
- Heroicons for icons (optimized version)

### Authentication & Security
- mTLS everywhere between Core and Agents
- PKI engine manages internal Certificate Authority
- Agent bootstrap uses "secret zero" (RoleID/SecretID) to obtain client certificates
- Applications connect to local Agent via Unix Domain Sockets with mTLS

### Background Jobs
- Oban for persistent background tasks (primarily static secret rotation)
- Ensure Oban is properly configured when adding new background jobs

### Audit Logging
- All operations must be logged to the audit subsystem
- Hash chain implementation for tamper-evident logs
- Multi-tier storage strategy (hot/warm/cold)

## Development Guidelines

### Testing Approach
- Write tests alongside new features
- Use ExUnit for all testing
- Test coverage tracked with ExCoveralls
- Run `mix test` from umbrella root to test all apps
- For focused testing, cd into specific app directory

### Code Style
- Pre-commit hooks enforce: formatting, Credo linting, and compilation checks
- Run `mix format` before committing
- Run `quality` script to ensure all checks pass
- Use `mix compile --warnings-as-errors` to treat warnings as errors
- Pre-commit hooks are configured in `devenv.nix` and run automatically

### Database Changes
- Always create migrations in `apps/secrethub_core/`
- Use descriptive migration names
- Test migrations up and down: `mix ecto.migrate` / `mix ecto.rollback`
- PostgreSQL uses Unix domain sockets in devenv (no TCP port, enhanced security)

### Adding New Secret Engines
Secret engines live in `apps/secrethub_core/lib/secrethub_core/engines/`:
- **Dynamic engines**: Generate temporary credentials (e.g., PostgreSQL, Redis, AWS)
- **Static engines**: Rotate long-lived credentials in external systems
- Must integrate with Lease Manager for dynamic secrets
- Must integrate with Oban scheduler for static secret rotation

### Working with Agents
- Agent code is in `apps/secrethub_agent/`
- Agents maintain persistent WebSocket connections to Core
- Local caching strategy is critical for resilience
- Template rendering allows secret injection into config files

## Environment Variables

Default development environment variables are set in `devenv.nix`:

```bash
# Database (using Unix domain socket for security and performance)
DATABASE_URL=postgresql://secrethub:secrethub_dev_password@/secrethub_dev?host=$DEVENV_STATE/postgres
DATABASE_TEST_URL=postgresql://secrethub:secrethub_dev_password@/secrethub_test?host=$DEVENV_STATE/postgres
MIX_ENV=dev
SECRET_KEY_BASE=dev-secret-key-base-change-in-production
PHX_HOST=localhost
PHX_PORT=4000
ELIXIR_ERL_OPTIONS=+sbwt none +sbwtdcpu none +sbwtdio none
```

Production deployments require:
- `SECRET_KEY_BASE` (generate with `mix phx.gen.secret`)
- `DATABASE_URL` for production database
- Proper mTLS certificates for Core-Agent communication

### devenv Scripts
The project includes convenient scripts in devenv.nix:
- `db-setup`, `db-reset`, `db-migrate` - Database operations
- `assets-install`, `assets-build` - Frontend asset management
- `server`, `console` - Development operations
- `test-all`, `test-watch` - Testing operations
- `format`, `lint`, `quality` - Code quality checks
- `gen-secret` - Generate Phoenix secrets

## Development Services

devenv automatically manages these services:
- **PostgreSQL 16**: Unix domain socket at `$DEVENV_STATE/postgres` (databases: `secrethub_dev`, `secrethub_test`)
- **Prometheus**: `localhost:9090` (metrics collection)

**Note:** PostgreSQL uses Unix domain sockets for better security and performance. No TCP port is exposed.

## CI/CD and GitHub Actions

The project uses GitHub Actions for continuous integration and testing. See `.github/workflows/` for workflow definitions.

### Workflows

**CI Workflow** (`ci.yml`) - Runs on every push with 4 parallel jobs:
1. **Compile**: Code compilation with `--warnings-as-errors`
2. **Format**: Code formatting check
3. **Credo**: Strict mode linting
4. **Dialyzer**: Static type analysis

All jobs run in parallel for fastest feedback (~5 min vs ~15 min sequential).

**Test Workflow** (`test.yml`) - Runs on push to main/develop and PRs:
- Sets up PostgreSQL 16 and Redis 7 services
- Runs full test suite with `mix test`
- Generates coverage reports
- Uploads coverage artifacts

### Local CI Checks

Before pushing code, run all CI checks locally:

```bash
# Run all quality checks (same as CI)
./scripts/quality-check.sh

# Skip tests for faster feedback
SKIP_TESTS=1 ./scripts/quality-check.sh

# Individual checks
mix format --check-formatted  # Format check
mix compile --warnings-as-errors  # Compilation
mix credo --strict  # Linting
mix dialyzer  # Static analysis
mix test  # Tests
```

### CI Environment

GitHub Actions runs with:
- **Elixir**: 1.18
- **OTP**: 28
- **PostgreSQL**: 16 (service container)
- **Redis**: 7 (service container)

All workflows use caching to speed up builds:
- Dependencies cache (keyed by `mix.lock`)
- Dialyzer PLT cache (keyed by `mix.lock`)

See `.github/workflows/README.md` for detailed CI/CD documentation.

## Deployment

The project has two separate release configurations in `mix.exs`:

1. **secrethub_core**: Includes `secrethub_core`, `secrethub_web`, and `secrethub_shared`
2. **secrethub_agent**: Includes `secrethub_agent` and `secrethub_shared`

Both releases:
- Include executables for Unix only
- Use standard `:assemble, :tar` steps

Infrastructure code is in `/infrastructure/`:
- Docker configs in `infrastructure/docker/`
- Terraform modules in `infrastructure/terraform/`
- Kubernetes manifests in `infrastructure/kubernetes/`

### Asset Build Configuration
- **esbuild**: v0.25.4, bundles JavaScript to `priv/static/assets/js/`
- **Tailwind CSS**: v4.1.7, compiles to `priv/static/assets/css/app.css`
- Assets are managed through mix aliases: `assets.setup`, `assets.build`, `assets.deploy`

## Team & Development Process

Development team includes AI assistants with specific responsibilities:
- **Claude**: Architecture, Security, Documentation
- **Kimi K2**: Core Backend, Database
- **GLM-4.6**: Agent, OTP, GenServers

**Commit Message Convention:**
```
type(scope): subject

body

footer
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Example:
```
feat(core): implement AppRole authentication backend

- Add RoleID/SecretID generation
- Implement token validation
- Add integration tests

Closes #123
```
