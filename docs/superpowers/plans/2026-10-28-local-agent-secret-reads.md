# Local Agent Secret Reads Implementation Plan

> **For agentic workers:** Use subagent-driven-development or executing-plans to implement the bounded tasks below. Work in the existing checkout; coordinate shared builds and database checks. Commit/publication/deployment are outside scope.

**Goal:** `secrethub secret get PATH` reads from the local Agent without application credentials, using an optional socket override and Agent policies.

**Architecture:** A distinct negotiated `local_socket_read_v1` capability and `secret:read_local` runtime operation separate local Agent authorization from application-certificate reads. Core revalidates mTLS-derived Agent identity, policies, Vault state and cached revisions; audit preserves Agent association without inventing an application.

**Tech Stack:** Existing Elixir/Phoenix umbrella, PostgreSQL disposable runtime fixtures, newline JSON Unix sockets, existing audit journal.

**Delivery amendment, 2026-10-28:** after implementation verification, the owner
requested conventional commits, push, and the next release. Publication is now
authorized through the existing release workflow; production deployment,
service restarts, and live database changes remain outside scope. The source
verification below records the completed implementation phase before this
separate delivery request.

## Agent skills

- [scoped-prd-execution](/home/gao/.agents/skills/scoped-prd-execution/SKILL.md): enforce the approved scope and delivery boundary.
- [test-driven-development](/home/gao/.agents/skills/test-driven-development/SKILL.md): demonstrate the missing behavior before implementing.
- [subagent-driven-development](/home/gao/.agents/skills/subagent-driven-development/SKILL.md): bounded ownership and independent reviews.
- [verification-before-completion](/home/gao/.agents/skills/verification-before-completion/SKILL.md): qualify the combined checkout.

## Task 1: Core local authorization and trusted channel

**Files:** `apps/secrethub_core/lib/secrethub_core/{authorization_versions,runtime_principal,runtime_authorization,upgrade_gates}.ex`, `apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex`, and their focused test files.

- [x] Add regressions for Agent-only static authorization, denial/revocation/seal, exact cached revision, audit attribution and floor-2 compatibility; run them before implementation.
- [x] Add Agent-only identity resolution and authorization locking alongside the application path. Require the typed authorization gate, current Agent/certificate state and the existing Agent policy evaluator.
- [x] Negotiate `local_socket_read_v1`; implement the separate channel operation with a bounded payload whitelist and current socket identity only.

```elixir
# New runtime payload, with identity obtained solely from socket assigns:
%{"path" => path, "known_revision" => revision,
  "audit_request_id" => request_id, "audit_attempt_id" => attempt_id}
```

- [x] Preserve existing application/legacy behavior and durable floor. Reuse Vault, managed-certificate, version/revision and checked audit conditions; local observations use null application identity.
- [x] Run focused Core authorization/locking and trusted channel tests with the existing disposable database fixtures.

## Task 2: CLI default socket and credential-free local client

**Files:** `apps/secrethub_cli/lib/secrethub_cli.ex`, `lib/secrethub_cli/{agent_client,commands/secret_commands}.ex`, CLI tests and socket fixture under `apps/secrethub_cli/`.

- [x] Add failing real-socket tests for direct `get_secret` without certificate/key files, default socket selection and override, no login or HTTP fallback, invalid credential pairs and structured values.
- [x] Select the socket using the explicit flag, then `SECRET_HUB_AGENT_SOCKET_PATH`, then `/var/run/secrethub/agent.sock`. Use direct local `get_secret` when neither credential option is supplied; a complete pair retains application proof and partial/invalid pairs fail.
- [x] Preserve an explicit Core read via `--server URL`; reject conflicting Core/Agent selectors. Existing update/create operations remain Core API operations.

```sh
secrethub secret get prod.db.password --format json
secrethub secret get prod.db.password --agent-socket /run/secrethub-agent/agent.sock
secrethub secret get prod.db.password --server https://core.example.com
```

- [x] Update CLI help and run focused CLI client/command/parser regressions.

## Task 3: Agent UDS, negotiated runtime and cache

**Files:** `apps/secrethub_agent/lib/secrethub_agent/{uds_server,connection,cache}.ex`, associated Agent UDS/runtime tests.

- [x] Add failing real-UDS tests for credential-free local reads, explicit app-auth mode isolation, capability errors, cache reauthorization/denial/outage and local audit attribution.
- [x] Expose `Connection.get_static_secret_local(server, path, revision, correlation, timeout)` forwarding `secret:read_local` only on a connected runtime with negotiated capability.
- [x] Keep new connections eligible for local reads; once application authentication starts, keep that connection in the application mode. Do not let pending/failed proof fall back to local reads.
- [x] Use a distinct local cache key while reusing existing exact-revision response validation and checked journal delivery. Preserve socket `0600`, framing and resource limits.
- [x] Restore a restarted UDS server from the current connected runtime through asynchronous synchronization; never persist or infer capability from an old floor.
- [x] Run Agent UDS, connection, cache and authentication regressions.

## Task 4: Integration, documentation and review

**Files:** Agent and CLI READMEs, `docs/{deploy,README}.md`, Agent deployment guide and current security/runtime docs; an appropriate focused transport integration fixture/test.

- [x] Exercise a credential-free CLI client through the actual UDS server and trusted Core local operation, proving Agent policies and floor 2 behavior. Use only disposable databases/processes created by the tests.
- [x] Document default socket/override, socket permissions, startup environment injection, explicit Core reads, application-mode compatibility and update/SDK limits. Reconcile ADR 0001's application-only assumption without rewriting historical evidence.
- [x] Review spec compliance, then code quality; fix findings and rerun affected checks.
- [x] Run focused combined tests, formatting, compile verification and integrated diff/scope review. Record exact outcomes and unexecuted criteria below.

## Verification evidence

Verified on 2026-10-28 in the existing `main` checkout, starting from
`1ec476e32f051dbd4151e005a73f08984e40d6f2`. No commit, push, release,
deployment, shared/live database migration, auth-floor activation or running
service restart was performed. Tests used disposable runtime databases and
processes created by their fixtures. The pre-existing untracked
`secrethub-access-audit-plan.md` was left untouched.

| Check | Result |
| --- | --- |
| CLI client, transport selectors, commands and parser | PASS: 89 tests, 0 failures |
| Core runtime authorization, application compatibility and locking | PASS: 38 tests, 0 failures after the final helper extraction; includes expired/revoked Agent identity, policy denial, sealed Vault and checked audit persistence |
| Agent UDS, protocol, auth and cache | PASS: 50 tests, 0 failures; includes real socket permission/framing/auth isolation, local cache denial/outage and UDS-only restart |
| Additional live-runtime synchronization regression | PASS: final tagged protocol run executed 2 cases, 0 failures, including the newly added connected/disconnected synchronization case |
| Existing Agent connection, SSH connection, audit Journal and Reporter | PASS: 41 tests, 0 failures, including the SSL client-certificate handshake |
| Trusted local channel and transport integration | PASS: final tagged channel run executed 4 cases, 0 failures (25 discovered, 21 excluded) |
| Formatting / compilation | PASS: all 20 changed Elixir source/test files formatted; compilation with warnings as errors passed |
| Strict Credo on all 11 changed production modules | BASELINE FAIL: exit 26, 32 existing findings (16 design, 15 refactoring, 1 warning); HEAD source comparison had 33 (17/15/1). All new local-read findings were removed; no checks or thresholds were weakened |
| Documentation links / diff scope | PASS: 14 local links in the new guide/design/plan resolve; final diff/scope checks passed |
| Spec compliance and code quality review | PASS after fixing UDS restart synchronization; helper extraction reviewed without further findings |

The integration uses the real CLI Agent client and Unix socket server, a test
bridge for runtime transport, and the production trusted channel callbacks on a
certificate-derived Phoenix test socket. It exercises fresh and exact-revision
cached reads at floor 2 under `single_operator`, then denies the cached read
after deleting the Agent grant. It uploads Agent audit observations through the
trusted channel, queries and rebuilds their projections, verifies null application
identity and zero application totals, and verifies the audit chain. This is
source integration evidence, not a deployed WebSocket or release-artifact test.

Reproducible focused checks (from the repository root unless noted):

```sh
MIX_ENV=test mix test --no-start \
  apps/secrethub_agent/test/secrethub_agent/uds_server_test.exs \
  apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs \
  apps/secrethub_agent/test/secrethub_agent/uds_auth_test.exs \
  apps/secrethub_agent/test/secrethub_agent/cache_security_test.exs

MIX_ENV=test mix test \
  apps/secrethub_core/test/secrethub_core/runtime_authorization_test.exs --timeout 180000

MIX_ENV=test mix test \
  apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs \
  apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs \
  --only local_socket_read --timeout 180000
```

The CLI app-local test invocation needs its existing umbrella sibling's X509
fixture module on the code path; no production dependency was added:

```sh
# From apps/secrethub_cli:
MIX_ENV=test mix run --no-start -e '
Code.prepend_path(Path.expand("../../_build/test/lib/x509/ebin"))
Mix.Task.run("test", [
  "test/secrethub_cli/agent_client_test.exs",
  "test/secrethub_cli/commands/secret_get_transport_test.exs",
  "test/secrethub_cli/commands/secret_commands_test.exs",
  "test/secrethub_cli_test.exs"
])'
```

The additional Agent checks start only the required dependency applications:

```sh
MIX_ENV=test mix run --no-start -e '
Enum.each([:ssl, :telemetry, :phoenix_socket_client], fn app ->
  {:ok, _} = Application.ensure_all_started(app)
end)
Mix.Task.run("test", [
  "apps/secrethub_agent/test/secrethub_agent/connection_test.exs",
  "apps/secrethub_agent/test/secrethub_agent/ssh/connection_test.exs",
  "apps/secrethub_agent/test/secrethub_agent/access_audit_journal_test.exs",
  "apps/secrethub_agent/test/secrethub_agent/access_audit_reporter_test.exs"
])'
```

Expected RED evidence: Core initially had 7 missing-principal-API failures;
CLI had 9 intended missing-behavior failures plus 4 X509 fixture load-path
failures; the corrected Agent setup had 8 missing local-operation/configuration
failures. The UDS-only restart regression separately failed before synchronization
was added. The initial Agent attempt could not reach UDS assertions until the
fixture explicitly started telemetry; those setup failures were not treated as
feature RED evidence.

An earlier broader channel attempt during RED used previously built code and
observed old audit/floor assertion failures (`audit_unavailable` / `UNAVAILABLE`)
and 60-second per-case fixture migration timeouts; it was aborted. Those old
assertions were preserved. The new local channel cases clone a migrated disposable
template and retain all their assertions. Full-suite Test/E2E, Dialyzer and release
artifact qualification are NOT RUN for this change, and the earlier broad channel
attempt is not claimed green. Historical release evidence does not qualify this
new mode. SDK packages, Agent writes and subscriptions remain outside this slice.
