# AGENTS.md

This file provides guidance to coding agents when working with code in this repository.

## Project Overview

SecretHub is a Machine-to-Machine secrets management platform built with Elixir for the owner's own systems. It provides centralized secrets storage, dynamic credential generation, automatic rotation, and mTLS-based secure communication between core services and agents.

### Design Principles

- **Personal system use:** SecretHub Core serves the owner's own infrastructure. Core does not require an application user system; do not introduce user accounts, registration, password login, or user management into Core or its management UI.
- **Human app is separate:** `secrethub_human` owns its own accounts, devices, sessions, and client-encrypted vault data (Bitwarden-compatible + native APIs) in a separate database. It reaches Core only through the public `SecretHub.Access` boundary and never adds a Core admin login. Keep Human identity out of Core. See `apps/secrethub_human/README.md`.
- **Management UI authentication:** The management/admin UI runs behind Caddy with mandatory mTLS client certificate verification. Caddy provides the authentication boundary; do not add application-level admin login, session authentication, or another authentication layer. The UI must remain accessible only through this protected proxy.
- **Machine security:** These UI principles do not remove Core-Agent mTLS, agent enrollment, machine identity, secret access policies, or API authentication requirements.

**Architecture:** Two-tier system
- **SecretHub Core**: Central Phoenix-based service managing PKI, policies, secret engines, and audit logging
- **SecretHub Agent**: Local daemon deployed alongside applications for secure secret delivery via Unix Domain Sockets
- **Communication**: Persistent mTLS WebSocket connections between Core and Agents

## Development Environment

This project uses **devenv** (devenv.sh) with Nix for reproducible development environments. PostgreSQL is automatically managed by devenv.

### Initial Setup

```bash
devenv shell          # Enter devenv shell (or use direnv for automatic activation)
assets-install        # Install frontend dependencies (mix npm.install)
devenv processes up   # Start postgres, core, agent in dependency order
```

Core waits for PostgreSQL readiness, initializes missing databases, applies Core migrations, and starts Phoenix. Agent starts after Core's liveness endpoint responds. Startup preserves existing data and does not run seeds. First boot still requires Vault initialization/unsealing, CA setup, and operator approval in `/admin/pending-agents`.

Use `devenv processes up -d` for background startup. After process configuration changes, stop the old manager with `devenv processes down` and run `devenv processes up` again; PostgreSQL data and Agent certificate material persist.

### Essential Commands

```bash
# Development
devenv processes up   # Start postgres, core, agent (Core HTTP: localhost:4664)
devenv processes list # Show process status
devenv processes down # Stop processes without removing persistent state
mix phx.server        # Start Phoenix server only (PostgreSQL must already be running)
console               # Start IEx shell with application loaded
mix agent.run         # Run a local agent against Core (see Trusted Agent Connection below)

# Database
db-setup              # Optional setup + Core seeds (Core + Human repos); may modify existing data
db-reset              # Drop, recreate, migrate both repos, and seed Core
db-migrate            # Run pending Core + Human migrations only
db-clean              # Remove stale postgres lock files after unclean shutdown

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

# Database Migrations (two repos; generate in the owning app)
cd apps/secrethub_core && mix ecto.gen.migration create_table_name    # Core repo
cd apps/secrethub_human && mix ecto.gen.migration create_table_name   # Human repo
mix ecto.migrate -r SecretHub.Core.Repo     # or -r SecretHub.Human.Repo
mix ecto.rollback -r SecretHub.Core.Repo
```

## Project Structure (Umbrella App)

Elixir umbrella project with 7 apps sharing `mix.lock`, `deps/`, and `_build/` at the root. Configuration is centralized in `/config/*.exs` (`core_runtime.exs` and `agent_runtime.exs` are the release runtime configs).

```
apps/
  secrethub_core/       Core business logic (auth, engines, PKI/ACME, policies, audit, crypto,
                        Styx workers). Core migrations live in priv/repo/migrations/
  secrethub_web/        Phoenix web interface & REST API
                        Source: lib/secret_hub/web/ (namespace: SecretHub.Web)
  secrethub_human/      Human-facing vault: accounts, encrypted items, organizations,
                        attachments, Bitwarden-compatible + native APIs, own Repo/Endpoint/Styx.
                        Migrations live in priv/repo/migrations/
  secrethub_agent/      Agent daemon (bootstrap, enrollment, mTLS connection, cache, sinker,
                        templates, UDS server, lease renewal)
  secrethub_shared/     Shared Ecto schemas, crypto, runtime config, and communication protocols
  secrethub_cli/        CLI tool (escript `secrethub`, built with `mix escript.build`)
  x509/                 In-tree copy of the `x509` Hex package (certificates, CSRs, CRLs)
```

Other top-level directories: `caddy-secrethub-pki/` (Go Caddy module that verifies management-UI client certificates against SecretHub PKI), `rel/` (release overlays), `scripts/` (quality, backup, PKI/ACME verification), `test/performance/`, `docs/` (architecture, ops, ADRs in `docs/adr/`).

### Key Module Namespaces

- `SecretHub.Core.*` - Core business logic (auth, engines, PKI, etc.)
- `SecretHub.Access` - Public Core boundary used by the Human app
- `SecretHub.Web.*` - Phoenix web layer (endpoint: `SecretHub.Web.Endpoint`)
- `SecretHub.Human.*` / `SecretHub.HumanWeb.*` - Human app and its endpoint (`SecretHub.HumanWeb.Endpoint`)
- `SecretHub.Agent.*` - Agent daemon modules
- `SecretHub.Shared.*` - Shared schemas and protocols
- `SecretHub.CLI` - CLI escript entry point

**Important:** The web app's namespace is `SecretHub.Web` (configured in `config.exs`), and source lives at `apps/secrethub_web/lib/secret_hub/web/` - not `lib/secrethub_web_web/` as Phoenix typically generates.

## Architecture Concepts

### Database (PostgreSQL 16)
- **Connection**: Unix domain socket at `$DEVENV_STATE/postgres` (no TCP port exposed)
- **Core databases**: `secrethub_dev` / `secrethub_test` (user: `secrethub`, password: `secrethub_dev_password`) via `SecretHub.Core.Repo`
- **Human databases**: `secrethub_human_dev` / `secrethub_human_test` (same credentials) via `SecretHub.Human.Repo`
- **Extensions**: `uuid-ossp`, `pgcrypto`
- **Schemas**: Default schema + `audit` schema for audit logs (Core)
- Core migrations go in `apps/secrethub_core/`; Human migrations go in `apps/secrethub_human/`

### Runtime Roles
`SECRETHUB_ROLE` selects what a node runs: `all` (default outside prod; Core + Human), `core` (default in prod), `human`, or `agent` (see `SecretHub.Human.RuntimeRole`). The devenv `core` process sets `SECRETHUB_ROLE=core`, so Human is not started there; the Human endpoint uses `HUMAN_ENDPOINT_PORT` (dev: `4666`).

### Frontend Assets
- **DuskmoonBundler** builds JavaScript and Tailwind CSS v4 with a named `secrethub_web` profile and serves development modules with HMR
- Install workspace dependencies from the umbrella root with `assets-install` (`mix npm.install`); commit the generated `package-lock.json` and use `mix npm.ci` for frozen installs
- Build assets with `assets-build` (`mix duskmoon_bundler.build secrethub_web --tailwind`); production builds then run `mix phx.digest --no-compile`
- `duskmoon_bundler_runtime` resolves production manifests inside the installed web OTP app; the development/build toolchain is excluded from releases
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
- Management/admin UI authentication is enforced by Caddy mTLS; no additional application-level admin authentication is required (see Design Principles).
- mTLS between Core and Agents; PKI engine manages internal CA
- Applications connect to local Agent via Unix Domain Sockets

### Trusted Agent Connection
Full design in `docs/agents/trusted-agent-connection.md` (supersedes older AppRole runtime docs). Key rules:
- **Runtime identity is the Core-issued client certificate only.** AppRole, pending tokens, and approval state are enrollment mechanisms — they never authorize runtime secret access.
- Agent runtime uses a dedicated mTLS listener, separate from the normal web/API endpoint.
- First-boot enrollment flow: discover host identity (SSH host key) -> create pending enrollment via Core API -> operator approves in `/admin/pending-agents` -> submit CSR -> receive certificate -> connect over mTLS and join `agent:runtime` -> finalize.
- The startup coordinator (`SecretHub.Agent.RuntimeBootstrapper`) owns material loading, enrollment, runtime startup, finalization, and renewal scheduling; `SecretHub.Agent.Connection` is only the low-level socket client.
- Local dev: `devenv processes up` starts a standalone Agent using `mix agent.run`. Enrollment HTTPS and runtime WSS share the Agent listener at `SECRET_HUB_AGENT_ENDPOINT_HOST`/`SECRET_HUB_AGENT_ENDPOINT_PORT` (defaults `localhost:4665`). Inside the managed Agent process, unset `SECRET_HUB_AGENT_CORE_URL` defaults to `https://<endpoint-host>:<endpoint-port>` and `SECRET_HUB_AGENT_ENROLLMENT_CA_PATH` to the generated dev CA (`/tmp/secrethub/agent_endpoint/ca-cert.pem`); unset `SECRET_HUB_AGENT_STATE_DIR` defaults to `$DEVENV_STATE/secrethub-agent`, and unset `SECRET_HUB_AGENT_SOCKET_PATH` defaults to `<state-dir>/agent.sock`. Explicit environment values are preserved. Direct `mix agent.run` falls back to `https://localhost:4665` and the `priv/cert` state directory unless overridden; `SECRET_HUB_AGENT_APPROVAL_TIMEOUT_MS` bounds the approval wait (default: infinite). `SECRET_HUB_AGENT_HOST_KEY_PATH` can select an existing RSA/ECDSA SSH host key; otherwise a development RSA key is generated and persisted. First enrollment requires operator approval; subsequent starts reuse certificate material and reconnect.

### Background Jobs
- **Styx** for persistent background tasks (secret rotation, audit archival, hash-chain verification, CRL refresh, ACME, Human lease monitoring/attachment cleanup). Oban is no longer used.
- Two instances: `SecretHub.Core.Styx` (workers in `apps/secrethub_core/lib/secrethub_core/workers/` and `pki/acme/`) and `SecretHub.Human.Styx` (cron entries in `config/config.exs`)
- New background jobs must integrate with the Core or Human Styx instance

### Audit Logging
- All operations must be logged to the audit subsystem
- Hash chain implementation (SHA-256 + HMAC) for tamper-evident logs

### Secret Engines
- **Dynamic engines** (`apps/secrethub_core/lib/secrethub_core/engines/dynamic/`): Generate temporary credentials (PostgreSQL, Redis, AWS STS) - integrate with `SecretHub.Core.LeaseManager`
- **Static secrets** (`SecretHub.Core.Secrets`): Long-lived credentials rotated by `workers/rotation_scheduler.ex` + `rotation_worker.ex` on Styx

### REST API Routes (Core, `apps/secrethub_web/lib/secret_hub/web/router.ex`)
- `/v1/sys/*` - Health, seal-status (public); init, seal/unseal, management readiness (admin pipeline)
- `/v1/auth/approle/*` - AppRole login/renew (rate-limited) and role management (admin)
- `/v1/auth/cli-access` - CLI access requests and polling
- `/v1/secret/data/*path`, `/v1/secret/metadata/*path` - Static secret read/write (vault token)
- `/v1/secrets/dynamic/:role` - Dynamic credential generation
- `/v1/sys/leases/*` - Lease renew/revoke/list
- `/v1/agent/enrollments/*`, `/v1/agent/certificate/renew` - Agent enrollment and certificate renewal
- `/v1/pki/*` - CA and certificate operations; `/v1/pki/app/*` app cert issue/renew; `/v1/pki/client-auth/*` management client-certificate authority
- `/v1/apps/*` - Application registration and management
- `/vault/*` - Vault init/unseal/recovery LiveViews
- `/admin/*`, `/admin/api/*` - LiveView admin dashboard and its JSON API (protected by Caddy mTLS; no additional application-level authentication)
- `/dev/dashboard`, `/dev/mailbox` - LiveDashboard and Swoosh preview (dev only, `:dev_routes`)

Human routes live on the separate `SecretHub.HumanWeb.Endpoint`: Bitwarden-compatible `/identity`, `/api`, `/notifications`, and native `/human/*` (browser UI at `/human/ui`).

## CI/CD

**CI Workflow** (`ci.yml`) - 4 parallel jobs on every push: compile (`--warnings-as-errors`), format check, credo (strict), dialyzer.

**Test Workflow** (`test.yml`) - On push to main/develop and PRs: full test suite with PostgreSQL 16 + Redis 7 services.

**E2E Workflow** (`e2e.yml`) - On push to main/develop and PRs to main: end-to-end tests.

**Release Workflow** (`release.yml`) - On version tags (`v*.*.*`, e.g. `1.2.3` or `1.2.3-rc1`): builds tar.gz releases + multi-arch Docker images (`core`, `core-standalone`, `agent`), published under `ghcr.io/gsmlg-dev/secrethub/`.

**Claude Workflow** (`claude.yml`) - Claude Code GitHub integration.

CI environment: Elixir 1.18, OTP 28. Caches: deps (keyed by `mix.lock`), dialyzer PLT.

## Deployment

Two release configurations in root `mix.exs`:
1. **secrethub_core**: `secrethub_core` + `secrethub_web` + `secrethub_shared` + `secrethub_human` (runtime config `config/core_runtime.exs`; role chosen by `SECRETHUB_ROLE`)
2. **secrethub_agent**: `secrethub_agent` + `secrethub_shared` (runtime config `config/agent_runtime.exs`; Unix + Windows launchers, custom SSH helper and `config` commands patched in `mix.exs`)

Dockerfiles: `Dockerfile.core`, `Dockerfile.core-standalone`, `Dockerfile.agent`. Infrastructure code in `/infrastructure/` (PostgreSQL init scripts). Version lives in root `mix.exs` (`project[:version]`).

## Commit Convention

```
type(scope): subject
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Scopes: `core`, `web`, `human`, `agent`, `shared`, `cli`, `infra`, `release`

## Agent skills

### Issue tracker

Issues and PRDs are tracked in GitHub Issues for `gsmlg-dev/secrethub`. Agent-targeted issues, PRDs, implementation requests, and handoffs must include an `## Agent skills` section with explicit skill links in the body. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the default Matt Pocock skills triage label vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

This repo uses a single-context domain documentation layout. See `docs/agents/domain.md`.

