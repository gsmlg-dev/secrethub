# Human Vault Milestone 0 Implementation Report

## Scope

This report covers only Milestone 0 and section 20 of `docs/subsystem/human-vault.md`.
The implementation establishes an optional Human application, independent Repo and JSON
Endpoint, runtime/release wiring, and boundary tests. It does not implement any Human vault
domain behavior.

## Changed files

### Human application and web surface

- `apps/secrethub_human/mix.exs`
- `apps/secrethub_human/lib/secrethub_human.ex`
- `apps/secrethub_human/lib/secrethub_human/application.ex`
- `apps/secrethub_human/lib/secrethub_human/release.ex`
- `apps/secrethub_human/lib/secrethub_human/repo.ex`
- `apps/secrethub_human/lib/secrethub_human/runtime_role.ex`
- `apps/secrethub_human/lib/secrethub_human_web.ex`
- `apps/secrethub_human/lib/secrethub_human_web/endpoint.ex`
- `apps/secrethub_human/lib/secrethub_human_web/router.ex`
- `apps/secrethub_human/lib/secrethub_human_web/controllers/error_json.ex`
- `apps/secrethub_human/lib/secrethub_human_web/controllers/health_controller.ex`
- `apps/secrethub_human/lib/secrethub_human_web/controllers/page_controller.ex`
- `apps/secrethub_human/priv/repo/migrations/.gitkeep`

### Data, configuration, and release wiring

- `config/config.exs`
- `config/dev.exs`
- `config/test.exs`
- `config/prod.exs`
- `config/runtime.exs`
- `mix.exs`
- `devenv.nix`
- `.github/workflows/release.yml`

### Documentation and tests

- `apps/secrethub_human/README.md`
- `apps/secrethub_human/test/test_helper.exs`
- `apps/secrethub_human/test/support/conn_case.ex`
- `apps/secrethub_human/test/secrethub_human/application_test.exs`
- `apps/secrethub_human/test/secrethub_human/repo_boundary_test.exs`
- `apps/secrethub_human/test/secrethub_human/runtime_role_test.exs`
- `apps/secrethub_human/test/secrethub_human/runtime_config_integration_test.exs`
- `apps/secrethub_human/test/secrethub_human_web/controllers/root_controller_test.exs`
- `apps/secrethub_human/test/secrethub_human_web/endpoint_isolation_test.exs`
- `docs/superpowers/plans/2026-08-11-human-vault-milestone-0.md`
- `docs/subsystem/human-vault-milestone-0-report.md`

## Decisions

- Human domain and HTTP code live in one OTP application, `secrethub_human`, under the
  `SecretHub.Human` and `SecretHub.HumanWeb` namespaces.
- The production dependency direction is one-way: Human may depend on Core's public
  boundary, while Core has no dependency on Human. The Web dependency in the Human Mix
  project is test-only and `runtime: false` so simultaneous endpoint behavior can be tested.
- Human owns `SecretHub.Human.Repo`, dedicated development and test databases, its own
  production URL and pool configuration, and its own release migration helper. It never
  uses `SecretHub.Core.Repo` or Core schemas.
- Human exposes only JSON `GET /` and `GET /health`. The established ports are Core HTTP
  `4664`, trusted Agent mTLS `4665`, and Human HTTP `4666`.
- `SECRETHUB_ROLE` defaults to `core` in production for backward-compatible Core-only
  operation and to `all` in development/test. `all` and `human` enable Human; `core` and
  `agent` disable it. At this milestone, the role gates only Human, not existing Core/Web.
- The Human application remains a member of the combined Core release. When disabled, its
  application supervisor starts with an empty child list, so the Human Repo, PubSub, and
  Endpoint do not start.
- The combined `secrethub_core` release contains `secrethub_human` as a permanent
  application; this is release composition and does not introduce a reverse OTP dependency.
- No Human domain migration or table exists yet. The migration directory intentionally
  contains only `.gitkeep`, and the independent Human migration listing is empty.

## Verification

All Mix commands used these environment values:

```sh
PGHOST=/home/gao/Workspace/gsmlg-dev/secrethub/.devenv/state/postgres
PGPORT=5433
MIX_DEPS_PATH=/home/gao/Workspace/gsmlg-dev/secrethub/deps
MIX_BUILD_PATH=/home/gao/Workspace/gsmlg-dev/secrethub/_build
```

`unbuffer` was unavailable, so long-running Mix commands used `stdbuf -oL -eL`.

### Format and compilation

```sh
mix format
MIX_ENV=test mix compile --warnings-as-errors
```

Both commands exited 0. Compilation produced no warnings.

### Independent Human database and migrations

```sh
MIX_ENV=test mix ecto.create -r SecretHub.Human.Repo
MIX_ENV=test mix ecto.migrate -r SecretHub.Human.Repo
MIX_ENV=test mix ecto.migrations -r SecretHub.Human.Repo
```

All three commands exited 0. The database already existed, migration reported
`Migrations already up`, and the listing identified `SecretHub.Human.Repo` with no migration
entries, matching the deliberate no-schema Milestone 0 state.

### Runtime configuration integration

```sh
MIX_ENV=test mix test \
  apps/secrethub_human/test/secrethub_human/runtime_config_integration_test.exs
```

Result: 5 tests, 0 failures. Each case evaluates `config/runtime.exs` with
`Config.Reader.read!/2` in an isolated `elixir` OS subprocess. The subprocess receives only
inert Core/Human values, emits only selected non-secret configuration facts, and confirms no
SecretHub application started. The cases prove:

- production with `SECRETHUB_ROLE` unset defaults to Core, applies `enabled: false`, and does
  not require any `HUMAN_*` variable;
- production `all` applies `enabled: true`, the default Human port `4666`,
  `HUMAN_DB_POOL_SIZE=17`, `check_origin: :conn`, and independent Repo/Endpoint secrets;
- the enabled Human Endpoint has `server: true` only when `PHX_SERVER` is present;
- production `all` without `HUMAN_DATABASE_URL` fails with the explicit missing-variable
  message; and
- an invalid role fails with the accepted role list.

The test does not connect to PostgreSQL, bind an endpoint, mutate the ExUnit VM environment,
or use a fixed temporary directory.

### Scoped tests

```sh
MIX_ENV=test mix test apps/secrethub_human/test
MIX_ENV=test mix test apps/secrethub_core/test/secrethub_core/application_test.exs
MIX_ENV=test mix test \
  apps/secrethub_web/test/secrethub_web_web/controllers/page_controller_test.exs
```

Results:

- Human: 25 tests, 0 failures. This includes the real simultaneous-listener coverage for
  Core and Human plus the subprocess runtime configuration coverage.
- Core application: 6 tests, 0 failures.
- Web root page: 1 test, 0 failures.

No unrelated full test suite was run, in accordance with the Milestone 0 scope.

### Production release assembly

```sh
release_root=$(mktemp -d)
MIX_ENV=prod mix release secrethub_core --overwrite --path "$release_root/release"
rel_file=$(find "$release_root/release/releases" -type f \
  -name secrethub_core.rel -print -quit)
rg -n 'secrethub_(core|web|shared|human)' "$rel_file"
```

The release assembled successfully at `/tmp/tmp.DtvzYI7m1D/release`. Inspection of
`releases/1.0.0-rc9/secrethub_core.rel` showed:

```text
{secrethub_core,"1.0.0-rc9",permanent},
{secrethub_web,"1.0.0-rc9",permanent},
{secrethub_shared,"1.0.0-rc9",permanent},
{secrethub_human,"1.0.0-rc9",permanent},
```

Assembly emitted the existing production safety warning that `:audit_hmac_secret` still
uses its default development value. It did not prevent compilation or release creation; no
release was started, so no database or Endpoint connection was attempted.

### Static finish gates

```sh
mix format --check-formatted
mix credo --strict
git diff --check
git status --short --branch
nix-instantiate --parse devenv.nix
```

All executable gates exited 0. Credo ran 61 checks on the new source file and found no
issues. Nix parsing was available and passed. At the report-writing checkpoint, Git status
contained only the new runtime integration test and this report on
`codex/human-vault-m0`.

## Remaining work and non-goals

Milestones 1–7 remain unimplemented: human identities/accounts and sessions, personal vault
storage, Bitwarden-compatible sync and APIs, dynamic-secret references and the Core access
facade, in-memory reveal/lease handling, approvals and renewals, organizations and shared
collections, attachments, and extended vault item types.

The milestone also does not add persistent credential storage, direct Human access to Core
tables, cross-context Ecto associations, shared Core/Human encryption keys, or any of the
first-release non-goals listed in the subsystem plan.
