# Unified Agent listener validation

Date: 2026-10-20 (Asia/Shanghai). Implementation branch:
`codex/unified-agent-port`, based on `d6d3307fe8631bcdae0318a97d8711957bec58a0`.

## Result

The management service retains its existing listener. Agent enrollment HTTPS,
existing machine token/proof HTTP APIs, and trusted runtime WSS share the Agent
TLS listener, normally 4665. `MachineEndpoint` is absent from web supervision
and its retained production configuration has `server: false, http: false`;
the retired machine enable setting cannot create a 4668 listener. Agent HTTPS
does not enable a second plaintext listener.

TLS verifies any presented client certificate but allows an absent certificate
for initial enrollment. Runtime admission still requires the real TLS peer
certificate and the unchanged Core verifier and runtime authorization gates.
No management authentication code or runtime identity protocol was changed.

## Scoped automated checks

An independent worktree used its own dependency/build directories and an owned
PostgreSQL cluster with a Unix socket only, at
`/tmp/secrethub-unified-port-6crdrfza/socket`. No existing database or live service
was used. Test TLS listeners used ephemeral loopback ports and were closed after
each test.

The consolidated command passed **126 tests, 0 failures**:

```sh
ERL_FLAGS='+S 4:4' MIX_ENV=test \
PGHOST=/tmp/secrethub-unified-port-6crdrfza/socket PGUSER=secrethub \
DATABASE_TEST_URL='postgresql://secrethub@/secrethub_test?host=/tmp/secrethub-unified-port-6crdrfza/socket' \
mix test \
  apps/secrethub_agent/test/secrethub_agent/enrollment_test.exs \
  apps/secrethub_agent/test/secrethub_agent/trusted_connection_test.exs \
  apps/secrethub_agent/test/secrethub_agent/runtime_bootstrapper_test.exs \
  apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs \
  apps/secrethub_core/test/secrethub_core/preflight_listener_test.exs \
  apps/secrethub_core/test/secrethub_core/agent_listener_runtime_config_test.exs \
  apps/secrethub_web/test/secrethub_web_web/controllers/agent_enrollment_controller_test.exs \
  apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs \
  apps/secrethub_web/test/secrethub_web/unified_agent_endpoint_test.exs \
  apps/secrethub_web/test/secrethub_web/unified_agent_tls_test.exs \
  apps/secrethub_web/test/secrethub_web/unified_agent_supervision_test.exs
```

| Group | Tests | Result |
| --- | ---: | --- |
| Agent enrollment, saved trust, bootstrap coordinator | 28 | PASS |
| Core enrollment, listener configuration, listener preflight | 59 | PASS |
| Web enrollment/runtime, unified HTTPS/WSS, supervision | 39 | PASS |

The new tests were observed failing before the corresponding implementation:
the initial web suite had 5 failures in 12 tests, listener configuration and
supervision had 3 failures in 5 tests, and revised preflight had 3 failures in
10 tests. The permissive-verification-callback regression and disabled explicit
HTTPS edge were also observed failing before correction.

## Actual TLS and authorization evidence

- TLS 1.2 and 1.3 accept certificate-free enrollment HTTPS; a real enrollment
  request returns 201. Invalid JSON payloads reach the existing controller.
- Wrong pending tokens return 401. An unapproved CSR returns 400. After operator
  approval, incorrect SSH proof returns 400 and records `invalid_signature`.
  Existing Core enrollment tests cover successful proof and issuance.
- A certificate-free WSS request returns 403 even with forged identity claims.
  A valid eligible Agent TLS peer obtains WSS 101 and an accepted
  `agent:runtime` join; claimed Agent IDs do not replace that peer identity.
- Revoked and wrong-type identities cannot upgrade runtime even when their
  certificate chain passes TLS validation. An unknown presented client
  certificate is rejected at TLS under both protocol versions.
- Server trust rejects an unknown CA and an incorrect expected hostname.
- Existing machine bearer authorization remains required. Application bootstrap
  requires its existing token/proof payload. The enrollment rate limit returns
  429 on request 31. NoStore and HEAD behavior are retained.
- Management, init, and unseal routes are absent on the Agent endpoint. These
  checks do not invoke the management endpoint.
- Explicit server TLS starts in development without an active signing CA;
  incomplete material, plaintext HTTP, disabled peer verification, mandatory
  pre-enrollment client certificates, and custom verification callbacks are
  rejected by the relevant configuration/preflight checks.
- Replacing generated development paths with explicit material takes
  precedence. Retained generated material still consults the active CA.

## Build, defaults, and review

Own application compilation with `mix compile --warnings-as-errors` passed.
Explicit safe changed files passed `mix format --check-formatted`; mixed runtime
configuration and endpoint socket settings were not passed to the formatter.
All three changed Nix files passed `nix-instantiate --parse`. The shipped Agent
TOML parsed with HTTPS port 4665 and its required settings.

Agent-only development configuration was evaluated for default/custom listener
addresses and explicit URL/CA settings. The managed Agent shell defaults were
executed for eight override cases: default URL, custom host/port, remote URL
without a CA override, remote URL/custom CA, default URL/custom CA, empty CA,
empty URL, and both empty. An explicit remote URL without a CA override retains
system trust; a managed default local URL receives the generated development CA.

Independent spec-compliance and code-quality/security reviews passed with no
actionable findings. Scoped Credo checked eight explicitly selected safe files
with no issues. After the final alias-only lint corrections, the affected web
endpoint/TLS/supervision tests passed again: **21 tests, 0 failures**. Compilation
and scoped formatting checks also passed after those corrections.

Local execution logs use the `/tmp/secrethub-unified-port-` prefix, including
`final-tests.log`, `final-compile.log`, `format.log`, and `credo.log`.

## Limits

This is local source and loopback TLS qualification. Production DNS, firewall,
server material, network listener state, installed release artifacts, and a
complete production first-enrollment session were not tested. No release,
deployment, live restart, or Vault mutation was performed. Full umbrella CI,
Dialyzer, and Nix VM/build checks were not run.

Actual development CA rotation and listener replacement were not exercised;
classification and active-CA consultation were tested. Fresh development still
requires Vault/CA setup and a Core restart before generated TLS can serve
enrollment. Existing saved Agent identities and connect-info are preserved.

The existing channel regression fixture emits migration-module redefinition
warnings and a sandbox connection-shutdown message; the scoped suite exits
successfully. Initial disposable test-database setup required both Core and
Human fixture migrations before umbrella applications could start.
