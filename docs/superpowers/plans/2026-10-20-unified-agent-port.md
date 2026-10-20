# Unified Agent Port Implementation Plan

> **For agentic workers:** Use `subagent-driven-development` with explicit file ownership. Tasks 1 and 2 can proceed in parallel after the baseline build; Task 3 integrates them and Task 4 reviews the result.

**Goal:** Serve enrollment and trusted Agent runtime on one TLS port while retaining the management listener.

**Architecture:** Mount the existing machine HTTP route set on `AgentEndpoint` alongside the trusted WebSocket. TLS verifies presented client certificates but allows an absent certificate for bootstrap; runtime authorization continues to require the actual issued Agent certificate. Remove the separate supervised machine listener and update scoped configuration, preflight, and deployment examples.

**Tech Stack:** Elixir 1.18, OTP 28 TLS, Phoenix/Bandit, ExUnit, isolated PostgreSQL fixture.

## Task 1: Agent endpoint and actual TLS behavior

**Ownership:** Worker: `apps/secrethub_web/lib/secret_hub/web/agent_endpoint.ex`, `agent_endpoint_manager.ex`, and new focused endpoint/manager tests. Parent owns configuration and documentation.

- [ ] Write a failing focused test proving that `POST /v1/agent/enrollments` reaches the existing enrollment controller through `AgentEndpoint`; retain a missing-client-certificate WebSocket rejection case.
- [ ] Add actual loopback TLS tests using generated CA/server/client certificates and one ephemeral listener. Check no-client enrollment, invalid presented client, untrusted server, hostname mismatch, and runtime upgrade rejection without a machine certificate.
- [ ] Run those scoped tests against the baseline; record the expected missing-route/TLS behavior failures before implementing.
- [ ] Add the existing machine parser/NoStore/Head pipeline and `MachineRouter` to `AgentEndpoint`, preserving the trusted socket.
- [ ] In development listener configuration use `verify: :verify_peer, fail_if_no_peer_cert: false`; prefer configured TLS material before attempting development issuance.
- [ ] Verify approved certificate runtime admission and revoked/wrong-type identity rejection with the existing scoped trusted-channel tests; add real TLS/runtime cases where required for the new boundary.

## Task 2: Two-listener configuration and preflight

**Ownership:** Parent: `config/core_runtime.exs` relevant listener lines only, `apps/secrethub_web/lib/secrethub_web/application.ex`, `apps/secrethub_core/lib/secrethub_core/preflight.ex` listener helper only, and focused listener configuration tests.

- [ ] Update focused preflight tests first: enabling Agent HTTPS requires readable cert/key/CA, `verify_peer`, and `fail_if_no_peer_cert: false`. Missing material and `verify_none` must fail. Run to observe the changed contract fail.
- [ ] Remove `MachineEndpoint` from supervision and configuration-change forwarding. Forward config changes to `AgentEndpoint` only if it is running.
- [ ] Configure the production Agent listener with `fail_if_no_peer_cert: false`. Disable the retained compatibility machine endpoint configuration and remove its independent port from active-listener collision checks. Preserve excluded configuration verbatim.
- [ ] Update the listener preflight helper and retain disabled-listener behavior. Add a narrow runtime block regression without evaluating excluded runtime configuration.
- [ ] Run only focused listener/preflight tests and inspect changed hunks.

## Task 3: Integration and deployment examples

**Ownership:** Parent: relevant Agent defaults/examples in `config/dev.exs`, `devenv.nix`, `flake.nix`, `nix/tests/agent-module.nix`, `rel/agent/overlays/config/agent.example.toml`, `docs/deployment/agent-deployment-guide.md`, `docs/deployment/nixos-agent.md`, and the machine/agent listener paragraph in `docs/security/runtime-contract.md`.

- [ ] Update enrollment URLs to HTTPS on the same Agent host/port as runtime. Retain `enrollment_ca_path` with peer/name verification.
- [ ] Document existing Core TLS environment settings, the two-port layout, operator approval, fresh-development CA setup, and preserved enrolled identity state.
- [ ] Run focused tests with `ERL_FLAGS='+S 4:4' MIX_ENV=test` against the owned socket-only PostgreSQL fixture. Run enrollment service/controller and trusted socket/channel regressions, plus new TLS/listener tests.
- [ ] Format only explicitly changed safe files. For mixed runtime files, inspect only scoped changed hunks and leave excluded settings unchanged. Compile own applications with warnings as errors after dependency compilation.

## Task 4: Independent review and completion

- [ ] Request independent spec-compliance review of the written design and scoped diff.
- [ ] Resolve concrete findings, then request code-quality/security review of the resulting implementation and evidence.
- [ ] Rerun checks justified by any fixes. Record test counts, exact commands, TLS evidence, and limitations in `docs/testing/unified-agent-port-evidence.md`.
- [ ] Verify root checkout and unrelated work remain intact. Stop only owned test fixtures. Leave the result reviewable on `codex/unified-agent-port`; do not release or deploy.
