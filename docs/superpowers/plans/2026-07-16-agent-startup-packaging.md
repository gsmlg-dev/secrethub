# Agent Startup and Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a clean standalone Agent release deterministically enroll, persist its trusted identity, connect to Core, expose a correctly permissioned UDS, and report real liveness/readiness in native and container deployments.

**Architecture:** Resolve all Agent runtime settings once, pass them explicitly down the supervision tree, and let RuntimeBootstrapper decide whether persisted trusted material or first-boot enrollment is required before attempting host-key discovery. Production first boot consumes an externally provisioned owner-only SSH identity; only the explicit development task may generate one. Socket group ID is an explicit release application setting (not a fifth path/URL environment alias) and is shared with application containers.

**Tech Stack:** Elixir/OTP releases and supervision, POSIX file/UDS permissions, Docker multi-stage builds, Docker Compose, ExUnit, devenv.

---

## Required runtime settings

The standalone release owns these names:

```text
SECRET_HUB_AGENT_CORE_URL
SECRET_HUB_AGENT_STATE_DIR
SECRET_HUB_AGENT_HOST_KEY_PATH
SECRET_HUB_AGENT_SOCKET_PATH
```

Precedence is environment, release application config, documented production default. There must be one resolver, not separate defaults in Application, RuntimeBootstrapper, Enrollment, HostKey, IdentityStore, and UDSServer.

## Task 1: Add one typed Agent runtime configuration boundary

**Files:**

- Create: `apps/secrethub_agent/lib/secrethub_agent/runtime_config.ex`
- Create: `apps/secrethub_agent/test/secrethub_agent/runtime_config_test.exs`
- Modify: `config/agent_runtime.exs`
- Modify: `config/test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/application.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/application_test.exs`

- [ ] Write table-driven tests for env → app config → default precedence for all four settings, blank-value rejection, URL validation, and absolute path validation. Add a required numeric `:socket_group_id` release application setting resolved by the POSIX adapter; it is not inferred from a username or socket path.
- [ ] Assert production defaults are state `/var/lib/secrethub-agent`, host key `/run/secrets/secrethub-agent-host-key`, and socket `/var/run/secrethub/agent.sock`; Core URL has no unsafe production default.
- [ ] Run `devenv shell -- test-all apps/secrethub_agent/test/secrethub_agent/runtime_config_test.exs apps/secrethub_agent/test/secrethub_agent/application_test.exs`; expect missing-module/config propagation failures.
- [ ] Implement `%SecretHub.Agent.RuntimeConfig{core_url, state_dir, host_key_path, socket_path, socket_group_id}` and `load!/1`; normalize once without reading mutable environment after boot.
- [ ] Make `config/agent_runtime.exs` populate all four app values without importing Core database/Phoenix secrets.
- [ ] Pass the struct's fields explicitly to EndpointManager, RuntimeBootstrapper, LeaseRenewer, and UDSServer; remove their divergent path defaults as each consumer is touched.
- [ ] Rerun focused tests and commit with `fix(agent): centralize standalone runtime config`.

## Task 2: Enforce externally provisioned host-key security

**Files:**

- Modify: `apps/secrethub_agent/lib/secrethub_agent/host_key.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/host_key_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/enrollment.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/enrollment_test.exs`
- Modify: `mix.exs`

- [ ] Add tests using temporary RSA and ECDSA SSH private keys for regular-file acceptance, symlink rejection, group/world permission rejection, wrong owner rejection, encrypted-key failure, unsupported curve, and public fingerprint stability.
- [ ] Add a test proving release enrollment never searches `/etc/ssh` or generates a fallback key when the configured path is absent.
- [ ] Run the HostKey/Enrollment tests and capture current discovery/fallback failures.
- [ ] Change `HostKey.discover/1` production behavior to require exactly `host_key_path`; call `File.lstat/1`, reject symlinks/nonregular files, require owner UID equals the runtime UID reported by an injectable Linux/POSIX file-security adapter, and require mode `0600` or stricter.
- [ ] Derive the OpenSSH public key and canonical SSH fingerprint in memory; never copy, rewrite, or log the private key.
- [ ] Keep key generation only in `mix agent.run`'s explicitly named development state directory and label it development-only in output.
- [ ] Make Enrollment accept the validated `%HostKey{}` from RuntimeBootstrapper instead of rediscovering it.
- [ ] Rerun focused tests and commit with `fix(agent): require provisioned enrollment host key`.

## Task 3: Prefer valid persisted runtime material before enrollment identity

**Files:**

- Modify: `apps/secrethub_agent/lib/secrethub_agent/runtime_bootstrapper.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/identity_store.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/enrollment.ex`
- Create: `apps/secrethub_core/priv/repo/migrations/20260716000050_add_agent_enrollment_idempotency.exs`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/agent_enrollment.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/agents/enrollment.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs`
- Modify: `apps/secrethub_web/lib/secret_hub/web/controllers/agent_enrollment_controller.ex`
- Modify: `apps/secrethub_web/test/secrethub_web_web/controllers/agent_enrollment_controller_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/runtime_bootstrapper_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/identity_store_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/enrollment_test.exs`

- [ ] Add startup matrix tests: valid persisted cert + missing host key boots; empty state + missing host key fails clearly; incomplete state resumes enrollment; valid state + changed host key still runs but reports enrollment-identity drift; expired/revoked state never silently enrolls.
- [ ] Add lost-create-response and concurrency tests: before the first request the Agent atomically persists a random enrollment request ID and 32-byte pending token; retrying the same normalized host payload/request ID/token returns the same Core row, while changed payload/host/token conflicts or fails authentication. Two concurrent first boots using the same host fingerprint but different request IDs/tokens produce exactly one nonterminal enrollment and one `ENROLLMENT_IN_PROGRESS` result.
- [ ] Add tests for owner-only state directory/files, symlinked state component rejection, partial-write recovery, and canonical fingerprint derivation from stored certificate.
- [ ] Run the three focused files and capture failures.
- [ ] Make `plan_start(state_dir)` inspect and validate fully committed runtime material before reading the enrollment host key.
- [ ] Return explicit plans `{:runtime, material}`, `{:resume_enrollment, pending}`, `{:first_enrollment, :host_key_required}`, or `{:error, :re_enrollment_required}`; do not hide state corruption as first boot.
- [ ] Persist enrollment pending token/idempotency key before network submission; resume the single nonterminal enrollment for the same fingerprint rather than create duplicates.
- [ ] Add nullable request ID/payload-hash columns, unique request-ID replay protection, and a partial unique index on canonical SSH host-key fingerprint for statuses `pending_registered`, `approved_waiting_for_csr`, `csr_submitted`, `certificate_issued`, `connect_info_delivered`, `trusted_connecting`, and `trusted_connected`. Preflight and explicitly resolve any legacy duplicate before creating the index.
- [ ] Core acquires a transaction-scoped advisory lock keyed by the canonical host fingerprint before lookup/insert. It first verifies exact request ID, pending-token hash, normalized payload, and fingerprint for an idempotent replay; a different request for an existing nonterminal fingerprint returns `ENROLLMENT_IN_PROGRESS` without revealing or replacing that row. The partial unique index is the final race guard.
- [ ] Use atomic write → fsync file → rename → fsync directory for trusted material and require directory `0700`, private files `0600`, public certificate/metadata at most `0640`.
- [ ] Rerun focused tests and commit with `fix(agent): resume persisted runtime identity safely`.

## Task 4: Secure UDS creation and expose real health

**Files:**

- Create: `apps/secrethub_agent/lib/secrethub_agent/health.ex`
- Create: `apps/secrethub_agent/test/secrethub_agent/health_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/uds_server.ex`
- Create: `apps/secrethub_agent/test/secrethub_agent/uds_server_lifecycle_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/runtime_bootstrapper.ex`

- [ ] Add tests that reject a symlink socket path, unlink only a stale socket owned by the runtime UID, create the parent directory as `0750`, set the socket to `0660`, and clean it on normal termination.
- [ ] Add liveness/readiness tests: a pre-authentication newline-delimited `health` action returns only liveness, identity-material readiness, and Core-connection readiness; liveness requires a responsive UDS, while full readiness requires valid loaded identity and an accepted normal runtime channel. Enrollment waiting is live but not ready.
- [ ] Run the new focused tests and expect failure against pid/file-based assumptions.
- [ ] Make UDSServer prepare and verify the socket directory/path before listen, enforce the Agent runtime UID plus explicitly configured application group, set directory/socket permissions after bind, and refuse an existing group/world-writable directory or world-accessible socket rather than weakening it.
- [ ] Implement `Health.status/0` returning sanitized `%{live: boolean, identity_ready: boolean, core_ready: boolean}` plus `Health.probe/2` and `Health.exit_status/1`; the release health command must use a bounded real UDS `health` request, not merely inspect a process or pid file.
- [ ] Have RuntimeBootstrapper publish phase changes only through an owned state query/subscription, not process-dictionary or log scraping.
- [ ] Rerun focused tests and commit with `feat(agent): report trusted runtime readiness`.

## Task 5: Fix the root standalone Agent image

**Files:**

- Modify: `Dockerfile.agent`
- Delete: `apps/secrethub_agent/Dockerfile` after all references use `Dockerfile.agent`
- Create: `scripts/test-agent-image.sh`
- Modify: `.dockerignore`
- Modify: release workflow files found by `rg -l 'Dockerfile.agent|secrethub_agent/Dockerfile' .github/workflows`

- [ ] Add a smoke assertion that the image builds the umbrella `secrethub_agent` release from the repository root and contains `/app/bin/secrethub_agent` plus the correct release applications.
- [ ] Run `docker build -f Dockerfile.agent -t secrethub-agent:plan-test .`; record current failures/incorrect dummy Core runtime requirements if reproduced.
- [ ] Keep only the root-context Dockerfile; build with `MIX_ENV=prod` and `mix release secrethub_agent`, relying on `runtime_config_path: "config/agent_runtime.exs"` rather than Core `runtime.exs` or dummy `DATABASE_URL`/`SECRET_KEY_BASE`.
- [ ] Create UID/GID 1002, container state `/app/state`, socket directory `/var/run/secrethub`, and read-only secret mount point `/run/secrets` with ownership/modes compatible with the non-root runtime. Set `SECRET_HUB_AGENT_STATE_DIR=/app/state`; the native release may retain `/var/lib/secrethub-agent` as its documented default.
- [ ] Set only documented Agent env names; remove `AGENT_ID`, `CORE_URL`, and pid-file health assumptions.
- [ ] Use a healthcheck invoking `bin/secrethub_agent eval 'SecretHub.Agent.Health.exit_status(:live)'`; that function must complete a bounded UDS liveness probe. Preserve an adequate startup period for operator approval and keep full readiness as a separate operator probe.
- [ ] Run `scripts/test-agent-image.sh`; verify image user, paths, runtime config, liveness/readiness, and absence of Core database configuration.
- [ ] Commit with `fix(infra): build deployable standalone agent image`.

## Task 6: Repair Compose clean boot and persistent mounts

**Files:**

- Modify: `docker-compose.yml`
- Modify: `Dockerfile.core`
- Create: `scripts/test-compose-agent.sh`
- Create: `docker-compose.smoke.yml`
- Create: `configs/agent/README.md` if the directory is intended to remain tracked
- Modify: `docs/deploy.md`
- Modify: `docs/quickstart.md`

- [ ] Add a Compose assertion checking Core uses root `Dockerfile.core`, Agent uses `Dockerfile.agent`, exact env names, persistent writable state, shared UDS directory, read-only owner-readable host key, and application consumers receive `group_add` for the configured numeric socket GID.
- [ ] Run `docker compose config`; expect current `CORE_URL`/`AGENT_SOCKET_PATH` and invalid healthcheck to fail the assertion.
- [ ] Change Agent configuration to `SECRET_HUB_AGENT_CORE_URL`, `SECRET_HUB_AGENT_STATE_DIR`, `SECRET_HUB_AGENT_HOST_KEY_PATH`, and `SECRET_HUB_AGENT_SOCKET_PATH`.
- [ ] Configure Core with `PHX_SERVER=true`, `PORT=4664`, `SECRET_HUB_AGENT_ENDPOINT_SERVER=true`, trusted endpoint port `4665`, and mounted endpoint certificate/key/client-CA paths. Publish 4664 and 4665 and use the real `/v1/sys/health/live` endpoint.
- [ ] Mount persistent state at `/app/state`, socket directory at `/var/run/secrethub`, and a dedicated Agent identity at `/run/secrets/secrethub-agent-host-key:ro`; do not mount a root-only host SSH key.
- [ ] Make application-side consumers share only the socket directory; do not expose Agent state or identity key to Core/application containers.
- [ ] Document how to provision UID-1002-owned key/state/socket paths and how enrollment approval affects readiness.
- [ ] Implement a disposable smoke override/script that provisions an ephemeral development CA/server material plus Agent host key, seeds/initializes the disposable Core consistently, runs `docker compose build` and `docker compose up`, approves the one pending Agent through Core, and asserts accepted mTLS runtime join plus a bounded UDS health probe. Always tear down volumes in an `EXIT` trap.
- [ ] Run `docker compose config` and `scripts/test-compose-agent.sh`; syntax-only validation is insufficient. Commit with `fix(infra): wire persistent agent identity and socket`.

## Task 7: Verify the standalone release and native first boot

**Files:**

- Modify: `apps/secrethub_web/test/e2e/core_agent_flow_test.exs`
- Modify: `docs/agents/trusted-agent-connection.md`

- [ ] Build with `devenv shell -- env MIX_ENV=prod mix release secrethub_agent --overwrite`.
- [ ] Run `SECRET_HUB_AGENT_CORE_URL=https://core.invalid _build/prod/rel/secrethub_agent/bin/secrethub_agent eval 'Application.load(:secrethub_agent)'`; require exit 0 without `DATABASE_URL` or Phoenix secrets.
- [ ] Change and verify `mix agent.run` alone uses the approved `http://localhost:4664` development Core endpoint, generates only its explicitly named local-development host key, and enables the existing explicit insecure-enrollment allowance only for that development task.
- [ ] Add E2E coverage for empty-state first boot, pending approval, restart while pending, completed runtime join, restart with host key temporarily absent, writable UDS, and readiness changes.
- [ ] Run `devenv shell -- test-all apps/secrethub_agent/test/secrethub_agent/application_test.exs apps/secrethub_agent/test/secrethub_agent/runtime_config_test.exs apps/secrethub_agent/test/secrethub_agent/host_key_test.exs apps/secrethub_agent/test/secrethub_agent/identity_store_test.exs apps/secrethub_agent/test/secrethub_agent/runtime_bootstrapper_test.exs apps/secrethub_agent/test/secrethub_agent/uds_server_lifecycle_test.exs apps/secrethub_agent/test/secrethub_agent/health_test.exs`.
- [ ] Run the clean-boot E2E case and `git diff --check`; require no production fallback identity and no private-key material in logs.
- [ ] Commit with `test(agent): verify clean standalone first boot`.
