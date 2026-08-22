# Release Runtime Configuration Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Core and Agent explicit release-specific runtime files while preventing the CLI escript from embedding Core runtime requirements and preserving direct production debugging from source.

**Architecture:** `config/core_runtime.exs` becomes the canonical Core/Web/Human runtime file, while the default `config/runtime.exs` delegates to it for source-based production commands. Agent retains its dedicated runtime file. CLI moves to an app-local config directory with an empty runtime file so Mix cannot embed the root Core configuration.

**Tech Stack:** Elixir 1.18, Mix releases, Mix escripts, ExUnit, GitHub Actions YAML, Docker

---

### Task 1: Make Core release runtime selection explicit

**Files:**
- Create: `apps/secrethub_core/test/secrethub_core/release_runtime_config_test.exs`
- Create: `config/core_runtime.exs` from the current `config/runtime.exs`
- Modify: `config/runtime.exs`
- Modify: `mix.exs:160-181`
- Modify: `apps/secrethub_web/test/secrethub_web_web/runtime_config_integration_test.exs:8`
- Modify: `apps/secrethub_human/test/secrethub_human/runtime_config_integration_test.exs:7`

- [ ] **Step 1: Write failing release-wiring tests**

```elixir
defmodule SecretHub.Core.ReleaseRuntimeConfigTest do
  use ExUnit.Case, async: true

  @project_root Path.expand("../../../..", __DIR__)

  test "OTP releases select dedicated runtime config files" do
    releases = SecretHub.MixProject.project() |> Keyword.fetch!(:releases)

    assert "config/core_runtime.exs" ==
             releases
             |> Keyword.fetch!(:secrethub_core)
             |> Keyword.fetch!(:runtime_config_path)

    assert "config/agent_runtime.exs" ==
             releases
             |> Keyword.fetch!(:secrethub_agent)
             |> Keyword.fetch!(:runtime_config_path)
  end

  test "default runtime entrypoint delegates to Core runtime config" do
    assert "import Config\n\nCode.eval_file(Path.join(__DIR__, \"core_runtime.exs\"))\n" ==
             File.read!(Path.join(@project_root, "config/runtime.exs"))
  end
end
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```bash
MIX_ENV=test MIX_DEPS_PATH=/home/gao/Workspace/gsmlg-dev/secrethub/deps \
  mix test apps/secrethub_core/test/secrethub_core/release_runtime_config_test.exs
```

Expected: FAIL because Core has no `:runtime_config_path` and `config/runtime.exs` still contains the full Core configuration.

- [ ] **Step 3: Split the canonical Core runtime file**

Move the complete existing contents of `config/runtime.exs` to `config/core_runtime.exs` without changing runtime behavior. Replace `config/runtime.exs` with:

```elixir
import Config

Code.eval_file(Path.join(__DIR__, "core_runtime.exs"))
```

Runtime config evaluation disables `import_config/1`, so the compatibility entrypoint
evaluates the canonical file in the same config process instead.

Add the explicit Core path in `mix.exs`:

```elixir
secrethub_core: [
  applications: [
    secrethub_core: :permanent,
    secrethub_web: :permanent,
    secrethub_shared: :permanent,
    secrethub_human: :permanent
  ],
  runtime_config_path: "config/core_runtime.exs",
  include_executables_for: [:unix],
  steps: [:assemble, :tar]
],
```

Update both existing runtime integration test attributes:

```elixir
@runtime_config Path.join(@project_root, "config/core_runtime.exs")
```

- [ ] **Step 4: Run Core/Web/Human runtime tests and verify GREEN**

Run:

```bash
MIX_ENV=test MIX_DEPS_PATH=/home/gao/Workspace/gsmlg-dev/secrethub/deps \
  mix test \
    apps/secrethub_core/test/secrethub_core/release_runtime_config_test.exs \
    apps/secrethub_web/test/secrethub_web_web/runtime_config_integration_test.exs \
    apps/secrethub_human/test/secrethub_human/runtime_config_integration_test.exs
```

Expected: `0 failures`; existing Web and Human runtime assertions remain unchanged.

- [ ] **Step 5: Commit the Core runtime split**

```bash
git add mix.exs config/runtime.exs config/core_runtime.exs \
  apps/secrethub_core/test/secrethub_core/release_runtime_config_test.exs \
  apps/secrethub_web/test/secrethub_web_web/runtime_config_integration_test.exs \
  apps/secrethub_human/test/secrethub_human/runtime_config_integration_test.exs
git commit -m "fix(core): isolate release runtime config"
```

### Task 2: Isolate CLI escript configuration

**Files:**
- Create: `apps/secrethub_cli/test/secrethub_cli/runtime_config_isolation_test.exs`
- Create: `apps/secrethub_cli/config/config.exs`
- Create: `apps/secrethub_cli/config/runtime.exs`
- Modify: `apps/secrethub_cli/mix.exs:62-94`

- [ ] **Step 1: Write a failing CLI config-path test**

```elixir
defmodule SecretHub.CLI.RuntimeConfigIsolationTest do
  use ExUnit.Case, async: true

  @cli_root Path.expand("../..", __DIR__)

  test "CLI uses an app-local config and runtime file" do
    project = SecretHub.CLI.MixProject.project()

    assert Path.join(@cli_root, "config/config.exs") ==
             Path.expand(Keyword.fetch!(project, :config_path), @cli_root)

    assert File.regular?(Path.join(@cli_root, "config/runtime.exs"))
    assert "config" in project |> Keyword.fetch!(:package) |> Keyword.fetch!(:files)
  end
end
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```bash
MIX_ENV=test MIX_DEPS_PATH=/home/gao/Workspace/gsmlg-dev/secrethub/deps \
  mix test apps/secrethub_cli/test/secrethub_cli/runtime_config_isolation_test.exs
```

Expected: FAIL because CLI points at `../../config/config.exs`, has no local runtime file, and excludes `config` from package files.

- [ ] **Step 3: Add the minimal CLI-only config**

Create both CLI config files with:

```elixir
import Config
```

Add `"config"` to `package.files` and change the umbrella config path:

```elixir
defp umbrella_paths do
  if File.exists?(Path.expand("../../mix.exs", __DIR__)) do
    [
      build_path: "../../_build",
      config_path: "config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock"
    ]
  else
    []
  end
end
```

- [ ] **Step 4: Run the CLI test and artifact smoke**

Run:

```bash
MIX_ENV=test MIX_DEPS_PATH=/home/gao/Workspace/gsmlg-dev/secrethub/deps \
  mix test apps/secrethub_cli/test/secrethub_cli/runtime_config_isolation_test.exs
cd apps/secrethub_cli
MIX_ENV=prod MIX_DEPS_PATH=/home/gao/Workspace/gsmlg-dev/secrethub/deps \
  mix escript.build --force
/usr/bin/env -i PATH="$PATH" HOME="$HOME" LANG=C.UTF-8 ./secrethub version
```

Expected: test and build pass; CLI exits `0` without requesting Core/Human modules or Core variables.

- [ ] **Step 5: Remove only the generated escript and commit CLI isolation**

```bash
rm apps/secrethub_cli/secrethub
git add apps/secrethub_cli/mix.exs apps/secrethub_cli/config \
  apps/secrethub_cli/test/secrethub_cli/runtime_config_isolation_test.exs
git commit -m "fix(cli): isolate escript runtime config"
```

### Task 3: Characterize Agent runtime isolation and clean build inputs

**Files:**
- Create: `apps/secrethub_agent/test/secrethub_agent/runtime_config_integration_test.exs`
- Modify: `Dockerfile.agent:36-43`
- Modify: `.github/workflows/release.yml:319-338`
- Modify: `.github/workflows/release.yml:393-403`
- Modify: `docs/deploy.md:21`

- [ ] **Step 1: Add a hermetic Agent runtime regression test**

```elixir
defmodule SecretHub.Agent.RuntimeConfigIntegrationTest do
  use ExUnit.Case, async: true

  @project_root Path.expand("../../../..", __DIR__)
  @runtime_config Path.join(@project_root, "config/agent_runtime.exs")
  @result_prefix "SECRET_HUB_AGENT_RUNTIME_CONFIG="

  @probe """
  config = Config.Reader.read!(#{inspect(@runtime_config)}, env: :prod)
  payload = %{
    agent: Keyword.fetch!(config, :secrethub_agent),
    core?: Keyword.has_key?(config, :secrethub_core),
    human?: Keyword.has_key?(config, :secrethub_human),
    web?: Keyword.has_key?(config, :secrethub_web)
  }
  IO.puts(#{inspect(@result_prefix)} <> Base.encode64(:erlang.term_to_binary(payload)))
  """

  test "standalone Agent config requires only a non-empty Core URL" do
    assert %{
             agent: [core_url: "https://core.example.test"],
             core?: false,
             human?: false,
             web?: false
           } = read_runtime_config("https://core.example.test")
  end

  test "standalone Agent config rejects a missing or blank Core URL" do
    for core_url <- [nil, ""] do
      {output, status} = run_runtime_config(core_url)
      assert status != 0
      assert output =~ "environment variable SECRET_HUB_AGENT_CORE_URL is missing"
    end
  end

  defp read_runtime_config(core_url) do
    {output, status} = run_runtime_config(core_url)
    assert status == 0, output
    assert [_, encoded] = String.split(output, @result_prefix, parts: 2)
    assert {:ok, payload} = encoded |> String.trim() |> Base.decode64()
    :erlang.binary_to_term(payload, [:safe])
  end

  defp run_runtime_config(core_url) do
    runtime_env =
      [{"PATH", System.fetch_env!("PATH")}, {"SECRET_HUB_AGENT_CORE_URL", core_url}]
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Enum.map(fn {key, value} -> "#{key}=#{value}" end)

    System.cmd(
      System.find_executable("env"),
      ["-i" | runtime_env] ++
        [System.find_executable("elixir"), "--erl", "+S 2:2", "-e", @probe],
      cd: @project_root,
      stderr_to_stdout: true
    )
  end
end
```

- [ ] **Step 2: Run the Agent regression test**

Run:

```bash
MIX_ENV=test MIX_DEPS_PATH=/home/gao/Workspace/gsmlg-dev/secrethub/deps \
  mix test apps/secrethub_agent/test/secrethub_agent/runtime_config_integration_test.exs
```

Expected: `2 tests, 0 failures`, characterizing the existing Agent contract.

- [ ] **Step 3: Remove Core placeholders from Agent-only builds**

Change `Dockerfile.agent` to:

```dockerfile
# Build OTP release for agent
RUN mix release secrethub_agent
```

In `.github/workflows/release.yml`, remove Core-variable environment blocks from Agent compile/release steps and remove the corresponding FreeBSD exports. Do not change Core jobs or global placeholder definitions.

Update `docs/deploy.md`:

```markdown
Core and Agent are separate OTP releases. Core uses `config/core_runtime.exs` in packaged releases, while `config/runtime.exs` preserves direct production execution from source. The standalone Agent release uses `config/agent_runtime.exs` and requires only `SECRET_HUB_AGENT_CORE_URL` at boot. CLI builds use an app-local empty runtime config and do not require Core runtime variables.
```

- [ ] **Step 4: Verify Agent-only inputs and commit**

Run:

```bash
rg -n "DATABASE_URL|SECRET_KEY_BASE|SECRET_HUB_CLUSTER_NODE_ID" Dockerfile.agent
sed -n '280,410p' .github/workflows/release.yml
```

Expected: no Dockerfile matches; Agent workflow jobs contain no Core placeholder variables.

Then:

```bash
git add apps/secrethub_agent/test/secrethub_agent/runtime_config_integration_test.exs \
  Dockerfile.agent .github/workflows/release.yml docs/deploy.md
git commit -m "fix(agent): remove Core runtime build inputs"
```

### Task 4: Verify source and packaged runtime behavior

**Files:**
- Verify all files changed in Tasks 1-3

- [ ] **Step 1: Format Elixir files and check the diff**

Run:

```bash
mix format \
  mix.exs \
  config/runtime.exs \
  config/core_runtime.exs \
  apps/secrethub_cli/mix.exs \
  apps/secrethub_cli/config/config.exs \
  apps/secrethub_cli/config/runtime.exs \
  apps/secrethub_core/test/secrethub_core/release_runtime_config_test.exs \
  apps/secrethub_cli/test/secrethub_cli/runtime_config_isolation_test.exs \
  apps/secrethub_agent/test/secrethub_agent/runtime_config_integration_test.exs \
  apps/secrethub_web/test/secrethub_web_web/runtime_config_integration_test.exs \
  apps/secrethub_human/test/secrethub_human/runtime_config_integration_test.exs
git diff --check
```

Expected: formatter exits `0`; `git diff --check` emits no output.

- [ ] **Step 2: Run all scoped regression tests**

```bash
MIX_ENV=test MIX_DEPS_PATH=/home/gao/Workspace/gsmlg-dev/secrethub/deps \
  mix test \
    apps/secrethub_core/test/secrethub_core/release_runtime_config_test.exs \
    apps/secrethub_web/test/secrethub_web_web/runtime_config_integration_test.exs \
    apps/secrethub_human/test/secrethub_human/runtime_config_integration_test.exs \
    apps/secrethub_agent/test/secrethub_agent/runtime_config_integration_test.exs \
    apps/secrethub_cli/test/secrethub_cli/runtime_config_isolation_test.exs
```

Expected: all selected tests pass with `0 failures`.

- [ ] **Step 3: Prove direct production Core compatibility**

Run:

```bash
/usr/bin/env -i \
  PATH="$PATH" \
  DATABASE_URL=ecto://core:core@localhost/secrethub_runtime_probe \
  SECRET_KEY_BASE=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  SECRET_HUB_CLUSTER_NODE_ID=runtime-probe \
  SECRETHUB_ROLE=core \
  elixir --erl "+S 2:2" \
    -pa _build/test/lib/secrethub_human/ebin \
    -e 'config = Config.Reader.read!("config/runtime.exs", env: :prod); IO.inspect(Keyword.has_key?(config, :secrethub_core))'
```

Expected: the returned config contains `:secrethub_core` and exits `0`.

- [ ] **Step 4: Assemble both releases with isolated inputs**

```bash
MIX_ENV=prod MIX_DEPS_PATH=/home/gao/Workspace/gsmlg-dev/secrethub/deps \
  DATABASE_URL=ecto://core:core@localhost/secrethub_release_probe \
  SECRET_KEY_BASE=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  SECRET_HUB_CLUSTER_NODE_ID=release-probe \
  mix release secrethub_core --overwrite

/usr/bin/env -i PATH="$PATH" HOME="$HOME" MIX_ENV=prod \
  MIX_DEPS_PATH=/home/gao/Workspace/gsmlg-dev/secrethub/deps \
  mix release secrethub_agent --overwrite
```

Expected: both releases assemble; Agent receives none of the Core runtime variables.

- [ ] **Step 5: Inspect generated runtime files**

```bash
cmp config/core_runtime.exs _build/prod/rel/secrethub_core/releases/1.0.0-rc10/runtime.exs
cmp config/agent_runtime.exs _build/prod/rel/secrethub_agent/releases/1.0.0-rc10/runtime.exs
```

Expected: both comparisons exit `0`.

- [ ] **Step 6: Rebuild and invoke CLI under a scrubbed environment**

Run:

```bash
cd apps/secrethub_cli
MIX_ENV=prod MIX_DEPS_PATH=/home/gao/Workspace/gsmlg-dev/secrethub/deps \
  mix escript.build --force
/usr/bin/env -i PATH="$PATH" HOME="$HOME" LANG=C.UTF-8 ./secrethub version
cd ../..
rm apps/secrethub_cli/secrethub
```

Expected: exit `0` with the CLI version and no Core runtime error; only the generated escript is removed afterward.

- [ ] **Step 7: Review final status**

```bash
git status --short
git diff --check
```

Expected: only intentional source changes are committed; ignored build and release artifacts are not staged.
