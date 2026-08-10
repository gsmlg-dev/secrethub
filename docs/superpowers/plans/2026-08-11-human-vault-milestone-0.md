# Human Vault Milestone 0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the optional `secrethub_human` umbrella application with an independent Repo, PubSub, Phoenix Endpoint, minimal routes, release wiring, and proof that it can run beside the existing Core Web endpoint.

**Architecture:** `secrethub_human` is one OTP/Phoenix application that owns both the `SecretHub.Human` domain namespace and `SecretHub.HumanWeb` HTTP namespace. Its supervision tree is runtime-gated and starts only its Repo, PubSub, and Endpoint; its dependency on Core remains one-way and does not access Core schemas or Repo. Development and test use dedicated Human databases, while production reads Human configuration only when `SECRETHUB_ROLE` is `all` or `human`.

**Tech Stack:** Elixir 1.18, OTP 28, Phoenix 1.8, Bandit, Ecto SQL/Postgrex, ExUnit, PostgreSQL 16.

---

### Task 1: Bootstrap the optional Human OTP application

**Files:**
- Create: `apps/secrethub_human/mix.exs`
- Create: `apps/secrethub_human/lib/secrethub_human.ex`
- Create: `apps/secrethub_human/lib/secrethub_human/application.ex`
- Create: `apps/secrethub_human/test/test_helper.exs`
- Create: `apps/secrethub_human/test/secrethub_human/application_test.exs`

- [ ] **Step 1: Add only the compile/test scaffold**

Create the child Mix project at version `1.0.0-rc9`, Elixir `~> 1.18`, with application callback `SecretHub.Human.Application`. Declare direct dependencies on `phoenix`, `phoenix_ecto`, `ecto_sql`, `postgrex`, `bandit`, `jason`, and one-way `secrethub_core`; add `secrethub_web` only as a `:test`, `runtime: false` dependency for simultaneous endpoint tests.

Create `SecretHub.Human.Application` with a temporary `children/1` that returns `[]` and starts `SecretHub.Human.Supervisor`. This is scaffold only; the next step defines behavior before implementing it.

- [ ] **Step 2: Write the failing supervision and dependency tests**

```elixir
defmodule SecretHub.Human.ApplicationTest do
  use ExUnit.Case, async: true

  alias SecretHub.Human.Application

  test "enabled subsystem owns only its Repo, PubSub, and Endpoint" do
    assert [
             SecretHub.Human.Repo,
             {Phoenix.PubSub, [name: SecretHub.Human.PubSub]},
             SecretHub.HumanWeb.Endpoint
           ] = Application.children(enabled: true)
  end

  test "disabled subsystem starts no children" do
    assert Application.children(enabled: false) == []
  end

  test "Core has no reverse dependency on Human" do
    assert {:ok, applications} = :application.get_key(:secrethub_core, :applications)
    refute :secrethub_human in applications
  end
end
```

- [ ] **Step 3: Run the test and verify RED**

Run:

```sh
MIX_ENV=test mix test apps/secrethub_human/test/secrethub_human/application_test.exs
```

Expected: the enabled-child assertion fails because the scaffold returns no children.

- [ ] **Step 4: Implement the minimum runtime gate and child list**

`children/1` must use the explicit `:enabled` option when present and otherwise read `Application.get_env(:secrethub_human, :enabled, true)`. When enabled, return exactly Repo, named PubSub, and Endpoint in that dependency order. `config_change/3` delegates to `SecretHub.HumanWeb.Endpoint.config_change/2`.

- [ ] **Step 5: Run the focused test and verify GREEN**

Run the command from Step 3. Expected: 3 tests, 0 failures.

- [ ] **Step 6: Commit**

```sh
git add apps/secrethub_human/mix.exs apps/secrethub_human/lib/secrethub_human.ex apps/secrethub_human/lib/secrethub_human/application.ex apps/secrethub_human/test/test_helper.exs apps/secrethub_human/test/secrethub_human/application_test.exs
git commit -m "feat(human): bootstrap optional application"
```

### Task 2: Add the independent Human Repo and migration boundary

**Files:**
- Create: `apps/secrethub_human/lib/secrethub_human/repo.ex`
- Create: `apps/secrethub_human/lib/secrethub_human/release.ex`
- Create: `apps/secrethub_human/priv/repo/migrations/.gitkeep`
- Create: `apps/secrethub_human/test/secrethub_human/repo_boundary_test.exs`
- Modify: `config/config.exs`
- Modify: `config/dev.exs`
- Modify: `config/test.exs`
- Modify: `config/prod.exs`

- [ ] **Step 1: Write the failing Repo-boundary test**

```elixir
defmodule SecretHub.Human.RepoBoundaryTest do
  use ExUnit.Case, async: true

  test "Human owns a separate Ecto Repo" do
    assert Application.fetch_env!(:secrethub_human, :ecto_repos) == [SecretHub.Human.Repo]
    assert SecretHub.Human.Repo.__adapter__() == Ecto.Adapters.Postgres
    refute SecretHub.Human.Repo in Application.fetch_env!(:secrethub_core, :ecto_repos)
  end

  test "Human migrations resolve under the Human application" do
    assert Application.app_dir(:secrethub_human, "priv/repo/migrations") =~
             "/secrethub_human/priv/repo/migrations"
  end
end
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```sh
MIX_ENV=test mix test apps/secrethub_human/test/secrethub_human/repo_boundary_test.exs
```

Expected: failure because the Repo/config do not exist.

- [ ] **Step 3: Implement Repo ownership and environment config**

Create `SecretHub.Human.Repo` using `otp_app: :secrethub_human` and `Ecto.Adapters.Postgres`. Register only that Repo under `config :secrethub_human, ecto_repos: [...]`.

In development, reuse the existing socket/credential resolution but default the Human database to `secrethub_human_dev`; allow `HUMAN_DATABASE_URL` to override it. In tests, reuse the Core test connection host/credentials while changing only the database to `secrethub_human_test#{MIX_TEST_PARTITION}` and retaining `Ecto.Adapters.SQL.Sandbox`. In production, give the Human Repo the same pool safety defaults as Core without sharing its URL.

- [ ] **Step 4: Add the independent release migration helper**

```elixir
defmodule SecretHub.Human.Release do
  @app :secrethub_human

  def migrate do
    Application.load(@app)

    for repo <- Application.fetch_env!(@app, :ecto_repos) do
      {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :up, all: true))
    end
  end

  def rollback(repo, version) do
    Application.load(@app)
    {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :down, to: version))
  end
end
```

- [ ] **Step 5: Create and migrate the dedicated test database**

Run:

```sh
MIX_ENV=test mix ecto.create -r SecretHub.Human.Repo
MIX_ENV=test mix ecto.migrate -r SecretHub.Human.Repo
MIX_ENV=test mix ecto.migrations -r SecretHub.Human.Repo
```

Expected: Human test database creation succeeds (or reports already created), migration succeeds, and the Human migration list is current and independent.

- [ ] **Step 6: Run the focused tests and verify GREEN**

Run both Human test files. Expected: 5 tests, 0 failures.

- [ ] **Step 7: Commit**

```sh
git add apps/secrethub_human/lib/secrethub_human/repo.ex apps/secrethub_human/lib/secrethub_human/release.ex apps/secrethub_human/priv/repo/migrations/.gitkeep apps/secrethub_human/test/secrethub_human/repo_boundary_test.exs config/config.exs config/dev.exs config/test.exs config/prod.exs
git commit -m "feat(human): add independent repository"
```

### Task 3: Add the independent Phoenix Endpoint and prove simultaneous listeners

**Files:**
- Create: `apps/secrethub_human/lib/secrethub_human_web.ex`
- Create: `apps/secrethub_human/lib/secrethub_human_web/endpoint.ex`
- Create: `apps/secrethub_human/lib/secrethub_human_web/router.ex`
- Create: `apps/secrethub_human/lib/secrethub_human_web/controllers/error_json.ex`
- Create: `apps/secrethub_human/lib/secrethub_human_web/controllers/page_controller.ex`
- Create: `apps/secrethub_human/lib/secrethub_human_web/controllers/health_controller.ex`
- Create: `apps/secrethub_human/test/support/conn_case.ex`
- Create: `apps/secrethub_human/test/secrethub_human_web/controllers/root_controller_test.exs`
- Create: `apps/secrethub_human/test/secrethub_human_web/endpoint_isolation_test.exs`
- Modify: `config/config.exs`
- Modify: `config/dev.exs`
- Modify: `config/test.exs`

- [ ] **Step 1: Add the framework scaffold with an empty Router**

Create the conventional `SecretHub.HumanWeb` `:controller` and `:router` macros, JSON error renderer, minimal Endpoint plugs (`RequestId`, `Telemetry`, parsers, method override, HEAD, Router), and an empty API pipeline/router. Configure Bandit, `SecretHub.Human.PubSub`, Human render errors, dev port `4666`, and test port `4667` with `server: false`.

- [ ] **Step 2: Write the failing route tests**

```elixir
defmodule SecretHub.HumanWeb.RootControllerTest do
  use SecretHub.HumanWeb.ConnCase, async: true

  test "GET / identifies the Human service", %{conn: conn} do
    assert %{"service" => "secrethub_human"} = conn |> get("/") |> json_response(200)
  end

  test "GET /health reports liveness", %{conn: conn} do
    assert %{"service" => "secrethub_human", "status" => "ok"} =
             conn |> get("/health") |> json_response(200)
  end
end
```

- [ ] **Step 3: Run the tests and verify RED**

Expected: both tests receive 404 because the Router has no routes.

- [ ] **Step 4: Implement only the two JSON controllers and routes**

Add `GET /` → `PageController.index/2` and `GET /health` → `HealthController.show/2` under the JSON API pipeline. Do not add sessions, LiveView, assets, sockets, domain APIs, or Bitwarden routes.

- [ ] **Step 5: Run the route tests and verify GREEN**

Expected: 2 tests, 0 failures.

- [ ] **Step 6: Write and run the real-listener test**

Start temporary Bandit child specs for `SecretHub.Web.Endpoint` and `SecretHub.HumanWeb.Endpoint`, each on `{127, 0, 0, 1}` port `0`. Use `ThousandIsland.listener_info/1` on each returned supervisor pid to obtain ports; assert the ports differ. Use `:httpc` to assert existing Core `GET /` and Human `GET /` plus `GET /health` return success. This test must start `:inets` and use unique temporary child IDs.

Run it before finalizing the helper. Expected initial RED is the Human request failing until its endpoint/router/config is complete; final expected result is 1 test, 0 failures.

- [ ] **Step 7: Commit**

```sh
git add apps/secrethub_human/lib/secrethub_human_web.ex apps/secrethub_human/lib/secrethub_human_web apps/secrethub_human/test/support apps/secrethub_human/test/secrethub_human_web config/config.exs config/dev.exs config/test.exs
git commit -m "feat(human): add independent endpoint"
```

### Task 4: Wire runtime roles, release startup, local databases, CI versioning, and docs

**Files:**
- Modify: `config/runtime.exs`
- Modify: `mix.exs`
- Modify: `devenv.nix`
- Modify: `.github/workflows/release.yml`
- Create: `apps/secrethub_human/README.md`
- Create: `apps/secrethub_human/test/secrethub_human/runtime_config_test.exs`

- [ ] **Step 1: Write the failing runtime-role contract test**

Test that the default non-production role is `all`, production defaults to `core`, only `all|human` enable Human, and invalid roles return an explicit error. Put this pure behavior in `SecretHub.Human.RuntimeRole` so runtime enablement is testable without mutating application environment. Release membership is verified by assembling and inspecting the release in Task 5 instead of exposing deployment configuration through production code.

- [ ] **Step 2: Run the focused test and verify RED**

Expected: failure because `RuntimeRole` does not exist.

- [ ] **Step 3: Implement runtime role and production-only requirements**

`config/runtime.exs` must derive the default role (`core` in prod, `all` otherwise), reject values outside `all|core|human|agent`, and configure `:secrethub_human, enabled:` from `RuntimeRole.human_enabled?/1`. Only when Human is enabled in production may it require `HUMAN_DATABASE_URL` and `HUMAN_SECRET_KEY_BASE`; configure `HUMAN_ENDPOINT_HOST` and `HUMAN_ENDPOINT_PORT` (default `4666`). `PHX_SERVER` enables the Human server only when the subsystem is enabled.

- [ ] **Step 4: Add Human to the existing combined Core release without reverse dependencies**

Keep the Core/Web/Shared entries unchanged and append `secrethub_human: :permanent`. Do not add Human modules or dependencies to Core or Web application code.

- [ ] **Step 5: Provision dedicated local databases and preserve CI release versioning**

Add `secrethub_human_dev` and `secrethub_human_test` to devenv PostgreSQL initialization and `db-init`; make `db-setup`, `db-reset`, and `db-migrate` target both Repos explicitly while Core seeds remain Core-only. Add `apps/secrethub_human/mix.exs` to the release workflow's `version_files` list. The existing root CI `mix ecto.create`/`mix ecto.migrate` already recurse across umbrella apps, so do not add redundant workflow steps.

- [ ] **Step 6: Document the boundary and operations**

Document:

- Core endpoint `4664`, trusted Agent endpoint `4665`, Human endpoint `4666`.
- `HUMAN_DATABASE_URL`, `HUMAN_ENDPOINT_HOST`, `HUMAN_ENDPOINT_PORT`, `HUMAN_SECRET_KEY_BASE`, and `SECRETHUB_ROLE` behavior.
- Human → public Core boundary and the prohibition on Human access to Core Repo/schemas.
- Independent create/migrate/release-migrate commands.
- Milestone 0 scope and explicit deferral of accounts, vault items, dynamic reveals, organizations, and Bitwarden APIs.

- [ ] **Step 7: Run the focused tests and verify GREEN**

Run all Human tests plus the existing Core application and Web root tests. Expected: all pass.

- [ ] **Step 8: Commit**

```sh
git add config/runtime.exs mix.exs devenv.nix .github/workflows/release.yml apps/secrethub_human/README.md apps/secrethub_human/lib/secrethub_human/runtime_role.ex apps/secrethub_human/test/secrethub_human/runtime_config_test.exs
git commit -m "feat(human): wire runtime and release"
```

### Task 5: Milestone 0 verification and implementation report

**Files:**
- Create: `docs/subsystem/human-vault-milestone-0-report.md`
- Modify only files already in this plan if verification exposes an in-scope defect.

- [ ] **Step 1: Format and compile**

```sh
mix format
MIX_ENV=test mix compile --warnings-as-errors
```

Expected: exit 0 with no project warnings.

- [ ] **Step 2: Verify Human migrations independently**

```sh
MIX_ENV=test mix ecto.create -r SecretHub.Human.Repo
MIX_ENV=test mix ecto.migrate -r SecretHub.Human.Repo
MIX_ENV=test mix ecto.migrations -r SecretHub.Human.Repo
```

Expected: all commands exit 0 and report the Human Repo independently.

- [ ] **Step 3: Run scoped and regression tests**

```sh
MIX_ENV=test mix test apps/secrethub_human/test
MIX_ENV=test mix test apps/secrethub_core/test/secrethub_core/application_test.exs
MIX_ENV=test mix test apps/secrethub_web/test/secrethub_web_web/controllers/page_controller_test.exs
```

Expected: 0 failures.

- [ ] **Step 4: Verify release assembly**

```sh
MIX_ENV=prod mix release secrethub_core --overwrite --path /tmp/secrethub-human-m0-release
```

Expected: release assembles successfully and contains `secrethub_human` in `releases/*/secrethub_core.rel`.

- [ ] **Step 5: Run static finish gates**

```sh
mix format --check-formatted
mix credo --strict
git diff --check
git status --short --branch
```

Expected: format, Credo, and diff checks exit 0; status lists only Milestone 0 files.

- [ ] **Step 6: Write the implementation report**

Record changed files by concern, selected decisions, exact verification evidence, environmental caveats, and remaining Milestones 1–7. Do not claim those later milestones are implemented.

- [ ] **Step 7: Commit**

```sh
git add docs/subsystem/human-vault-milestone-0-report.md
git commit -m "docs(human): report milestone zero"
```

---

## Self-review

- Milestone coverage: Tasks 1–4 cover every item in `human-vault.md` section 20; Task 5 verifies every Milestone 0 acceptance criterion.
- Scope: no accounts, vault schemas, Bitwarden routes, Core Access facade, RevealStore, LeaseMonitor, organizations, or credential persistence are introduced.
- Boundary: no Core or Web production file imports or depends on Human; the explicit release application list is deployment composition, not an OTP dependency.
- Database: Repo config, migration path, local provisioning, and release migration helper are separate from Core.
- Completeness: every implementation step names its concrete behavior and verification command.
