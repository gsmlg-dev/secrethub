# Release Runtime Configuration Isolation

## Problem

SecretHub has two OTP releases with different runtime requirements. The Core release needs database, endpoint, cluster, and optional Human Vault settings. The Agent release only needs the Core URL. The CLI is an escript rather than an OTP release, but its umbrella build currently points at the root config directory, causing the Core runtime configuration to be embedded in the CLI.

The runtime boundary must be explicit so Agent and CLI artifacts never require Core database or Phoenix settings.

## Decisions

- Keep the existing `secrethub_core` and `secrethub_agent` OTP releases. Do not create a CLI OTP release.
- Make `config/core_runtime.exs` the canonical runtime configuration for the Core release and its bundled Web and Human applications.
- Keep `config/agent_runtime.exs` as the canonical Agent release runtime configuration.
- Keep `config/runtime.exs` as a compatibility entrypoint that evaluates `core_runtime.exs` in the same config process. This preserves direct production debugging with commands such as `MIX_ENV=prod mix phx.server`.
- Give the CLI an app-local config directory containing its own compile config and an empty runtime config. The CLI will continue to obtain operational settings from command-line flags and its local TOML configuration.
- Remove Core-only placeholder environment variables from Agent build paths once tests prove that Agent assembly is isolated.

## Configuration Flow

### Core release

The root release definition explicitly sets `runtime_config_path: "config/core_runtime.exs"`. Release assembly copies that file into the Core artifact as `runtime.exs`. The file retains the current Core, Web, Agent endpoint, admin endpoint, and optional Human runtime behavior without semantic changes.

### Direct production execution

Mix continues to discover `config/runtime.exs` for source-based production commands. Runtime config evaluation disables `import_config/1`, so that file uses `Code.eval_file(Path.join(__DIR__, "core_runtime.exs"))` to evaluate the canonical Core file in the same config process. Direct execution therefore uses the same canonical Core configuration without duplicating it.

### Agent release

The Agent release continues to set `runtime_config_path: "config/agent_runtime.exs"`. Its runtime file requires a non-empty `SECRET_HUB_AGENT_CORE_URL` and configures only `:secrethub_agent`.

### CLI escript

The CLI Mix project uses `apps/secrethub_cli/config/config.exs` instead of the umbrella root config. Its sibling `runtime.exs` contains no runtime settings. Because Mix embeds the runtime file adjacent to the CLI config path, the escript no longer embeds or evaluates Core runtime configuration.

## Build Integration

Agent-specific sections of `Dockerfile.agent` and `.github/workflows/release.yml` will stop supplying `DATABASE_URL`, `SECRET_KEY_BASE`, and `SECRET_HUB_CLUSTER_NODE_ID` placeholders. Core build paths retain their existing variables because Core asset and release tasks still use Core runtime configuration.

No unrelated Docker Compose cleanup, release restructuring, deployment, push, or PR creation is included.

## Verification

- Update existing Web and Human runtime integration tests to read `config/core_runtime.exs`.
- Add a hermetic Agent runtime test that evaluates `config/agent_runtime.exs` with only an allowlisted environment. It must accept a valid Core URL, reject missing or blank URLs, and emit no Core, Web, or Human configuration.
- Add release/config wiring assertions for the explicit Core and Agent paths and the CLI-local config path.
- Build and run the CLI escript under a scrubbed environment without Core, database, cluster, Phoenix, or Human variables.
- Assemble both OTP releases and confirm each generated artifact contains its selected runtime configuration.
- Run formatting and `git diff --check` over the scoped changes.

## Success Criteria

- Core release boot and direct `MIX_ENV=prod` source debugging use the same canonical Core runtime settings.
- Agent release assembly and evaluation require no Core database, endpoint secret, cluster identity, or Human settings.
- CLI invocation requires no Core runtime modules or environment variables.
- Existing Core/Web/Human runtime behavior remains covered and unchanged.
