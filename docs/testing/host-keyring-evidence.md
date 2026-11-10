# Host keyring verification evidence

Feature: Agent-scoped host credentials (`host_credentials_v1`). Design:
[subsystem](../subsystem/host-keyring.md); operations:
[user guide](../user-guides/host-keyring.md).

Baseline commit `4ea82e2` plus the uncommitted host keyring change set.
Recorded 2026-11-09.

## Environment

| Item | Version |
| --- | --- |
| OS | Linux 6.18 (NixOS host), x86_64 |
| Elixir / OTP | 1.18.5 / 28 |
| PostgreSQL | 16.15, disposable cluster on a private socket (`/tmp`), never the shared dev database |
| Git | 2.54.0 |
| Docker | 29.7.2 daemon, `registry:2` with htpasswd auth |
| Python / keyring | 3.13.15 / 25.7.0 |
| systemd (VM) | 258.3 from the flake's pinned nixpkgs `release-25.11` |

## Reproduce

```sh
# Disposable PostgreSQL 16 (any empty cluster with a superuser `secrethub`)
export PGHOST=/path/to/socket-dir MIX_ENV=test

# Unit, database and protocol tests
mix test apps/secrethub_shared/test/secrethub_shared/host_credentials_test.exs \
         apps/secrethub_core/test/secrethub_core/host_credentials_test.exs \
         apps/secrethub_agent/test/secrethub_agent/host_credentials_test.exs \
         apps/secrethub_cli/test/secrethub_cli/host_credential_adapters_test.exs
mix test apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs \
         --exclude host_keyring_consumers --exclude host_keyring_docker --timeout 600000

# Real consumers: build installed artifacts, then run the tagged tests
scripts/host-keyring/build-local.sh /tmp/hk-artifacts
export SECRETHUB_HOST_KEYRING_BIN=/tmp/hk-artifacts/bin
export SECRETHUB_HOST_KEYRING_PYTHON=<python with keyring installed>
export SECRETHUB_HOST_KEYRING_HTPASSWD=<bcrypt htpasswd file: hkuser / hk-password>
mix test apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs \
         --only host_keyring_consumers --only host_keyring_docker --timeout 900000

# Native launcher, Python backend, packaging and systemd
make -C native/secrethub-exec test
nix build .#python-keyrings-secrethub .#secrethub-exec .#secrethub-cli
nix build .#checks.x86_64-linux.host-keyring-systemd
```

The real-consumer tests run a real Agent UDS server and local API against the
real trusted Core channel and database in one BEAM; a test relay replaces only
the Agent's websocket client. Channel transport itself is covered by the
channel tests.

## Results

| Area (plan §9) | Evidence | Result |
| --- | --- | --- |
| Core ownership | Core: Agent B cannot read, erase or list Agent A's entry by entry ID or selector; its own store creates a separate entry | pass |
| Operation grants | Core: `read` + `credential_read` on `host-credentials.**` cannot put/delete/list; collection create grant cannot overwrite an entry | pass |
| Owned lifecycle | Core: create, get, identical no-op, update, list without values, stale-value erase refused, erase, idempotent absent | pass |
| Reference lifecycle | Core: erase disables; repeated erase; source survives; store and rotation do not reactivate; explicit enable; source deletion + same-path recreation unavailable until rebind | pass |
| Managed store | Core: identical store audited no-op; replacement and disabled store `READ_ONLY`; source read grant required | pass |
| Current authorization | Core: exact-revision `not_modified` still denied after explicit deny, refused when sealed, and refused with `audit_unavailable` (as are fresh reads and stores) when Core audit persistence is unavailable; revoked Agent refused. Agent: with the audit journal unavailable, a cached value is not released and Core is not called (`AUDIT_UNAVAILABLE`). Agent: cached value released only on matching Core confirmation; denial invalidates; channel E2E: cached read then policy removal → `FORBIDDEN` | pass |
| Concurrency | Agent: slow (1.5 s) request does not delay another client (<1 s); request IDs preserved; write timeout → `UNCONFIRMED`. Core: writers serialize on the global authorization epoch | pass |
| Git | Real `git credential approve/fill/reject`; authenticated HTTP clone through `git http-backend` with Basic auth; miss → clone fails without prompt; server rejection erases stale password; stale reject does not erase newer value; path and port scope; Agent denial → `quit=true`, exit 1 | pass |
| Docker | Real `docker login --password-stdin`, `push`, `rmi`, authenticated `pull`, `logout` against disposable `registry:2`; config contains no secret; after logout `get` → `credentials not found in native keychain`, `list` excludes it, pull fails | pass |
| Execution | `secrethub exec` via installed wrapper: exact values incl. space/newline, stdin passes, exit status 7, outer shell PID equals target PID; missing credential → exit 1, target not started. Native launcher suite: 83 tests incl. SIGTERM/SIGHUP/SIGINT/SIGQUIT during resolution (launcher dies by the same signal, resolver receives it, no orphan, target not started), malformed output, collisions | pass |
| Reference management API | `HostCredentialControllerTest` (3 tests): CSRF required; bind/list/disable/enable/rebind over `/admin/api` return metadata only and append `host_credential.reference_*` audit events; unknown Agent/binding 404, Agent-owned source 422, duplicate identity 409 | pass |
| Agent websocket client | `connection_protocol_test.exs` (16 tests, 3 consecutive runs): credential pushes run in a supervised task; replies from a replaced channel become `:not_connected`; push timeout → `:timeout`; unnegotiated → `INCOMPATIBLE_VERSION`; capability follows Core acceptance | pass |
| systemd | NixOS VM: static `User=` and `DynamicUser=` services receive only their configured credential with exact bytes; denial and stopped provider prevent the next activation; `ExecStartPre=` success then main-process denial does not start the target (provider saw ≥2 acquisitions); empty EOF refused by the main launcher; canary absent from unit text; per-user Agent (`userAgent.enable`) boots under a lingering user manager with its own generated ECDSA key (`bob 600`), state under `~/.local/state/secrethub-agent`, private `$XDG_RUNTIME_DIR/secrethub` socket unreadable by other users, and the session variable pointing at it, while the system Agent is unaffected | pass |
| Rotation | Channel E2E: helper get after update returns the new value; systemd values are activation snapshots (documented) | pass |
| Compatibility | Existing Agent (351), CLI (299), Shared, channel suites pass; unnegotiated capability → `INCOMPATIBLE_VERSION`; app auth-v2 connection refused for credential actions; audit v1 vocabulary unchanged and cannot carry v2 operations; Core ingests Agent v2 events. Rollback (Agent): v2 events quarantined as `unsupported_schema` survive a journal restart, a full quarantine refuses new deliveries with `AUDIT_UNAVAILABLE` without calling Core, and explicit replay restores the identical events | pass |
| Python | Real `keyring` API with `PYTHON_KEYRING_BACKEND`: set/get/delete, `get_credential(service, None)`, empty value, non-ASCII; 22 backend tests (also in the Nix sandbox) | pass |
| Packaging | `nix build .#secrethub-exec` (runs the 75 launcher tests), `.#python-keyrings-secrethub` (22 tests in the sandbox), `.#secrethub-cli` (escript interpreter pinned to the Erlang store path; wrappers for `secrethub`, `secrethub-exec`, Git and Docker helpers). Installed helpers run from `/tmp` under `env -i` (no PATH, no locale) with protocol-only stdout | pass |
| No secrets in evidence | Canary values absent from audit log rows, observations, Agent WAL/events, unit text | pass |

Final regression run (after all changes, against the disposable cluster over
TCP): Core 933 tests, 0 failures (4 skipped); Web 461 tests, 0 failures (54
excluded by tag, including the real-consumer tests run separately above).

Earlier regression suites: Web 458 tests pass (54 excluded tags), Agent 351, CLI 299,
Shared 125 + 7 new. Core 932 tests: failures in a run concurrent with Dialyzer
and Nix builds were pool/GenServer timeouts and a stale shared test schema; on
re-run after migrating the test database, 73 of the 74 affected tests pass. The
remaining `PostgreSQLTest` dynamic-engine test needs a TCP PostgreSQL; with the
disposable cluster also listening on `127.0.0.1:55432` and `DATABASE_URL` set,
it passes (10 tests, 0 failures). `UDSServerTest` failed once in an early run;
afterwards it passed 10/10 on the change set and 10/10 on an untracked copy of
the baseline commit (`git archive HEAD`), so the failure was not reproduced.

Static checks: `mix compile --warnings-as-errors` clean; `mix format
--check-formatted` clean; `mix credo --strict` introduces no findings relative
to the baseline for every changed file; Dialyzer reports nothing for
application code (only ExUnit test-support noise when run under
`MIX_ENV=test`).

## Plan coverage

| Plan item | Delivered | Evidence |
| --- | --- | --- |
| §1.1 Agent credential API get/put/delete/list | Shared contract, Core facade, channel, Agent `credential_*` | Core/Agent/channel tests |
| §1.2 `git-credential-secrethub` | CLI adapter + wrapper | real Git rows |
| §1.3 `docker-credential-secrethub` | CLI adapter + wrapper | real Docker row |
| §1.4 `secrethub exec` | resolver + native launcher | Execution row |
| §1.5 systemd with different service users | provider sockets, NixOS options, main launcher | VM test |
| §1.6 `keyrings.secrethub` | `integrations/python-keyring` | Python row |
| §1.7 packaging, NixOS, docs, verification | flake packages/options, guides, this file | Packaging row |
| P1 Core model and policy | migration, bindings, typed grants, serialization | Core rows |
| P2 runtime and audit | `host_credentials_v1`, schema v2, cache revisions, old-peer refusal | Compatibility row |
| P3 Git and Docker | real clients and fixtures | Git/Docker rows |
| P4 process execution | exec, stdio/signal/exit | Execution row |
| P5 systemd and NixOS | VM activation, restart refusal, pre-start then main denial | systemd row |
| P6 generic keyring | real `keyring` API | Python row |
| P7 integration and handoff | guides, evidence, release notes | this file; remaining gates below |

## Found and fixed during verification

* The CLI's Agent client used a socket receive buffer smaller than the 64 KiB
  frame limit, so long response lines were split; it now sets `buffer`.
* `keyring.get_credential(service, None)` needed generic lookups without an
  account; generic lookups now resolve a unique match like Git.
* The flake's pinned Mix dependency hash was stale relative to `mix.lock`
  before this change (all Mix packages failed to build); it was updated.

## Remaining gates

* **Platform scope:** the host keyring is qualified for Linux/NixOS only; the
  `v1.0.0-rc.30` macOS archives below are not a supported target. The final
  Linux-only configuration ran in release `v1.0.0-rc.31`
  ([run 42760081873](https://github.com/gsmlg-dev/secrethub/actions/runs/42760081873)):
  `build-host-keyring-tools` succeeded for `linux-amd64` and `linux-arm64`
  (launcher suite, archive install and helper smoke test) and published only
  `secrethub-host-tools-v1.0.0-rc.31-linux-{amd64,arm64}.tar.gz`.
* **Release workflow:** release `v1.0.0-rc.30`
  ([run 42638094843](https://github.com/gsmlg-dev/secrethub/actions/runs/42638094843))
  ran `build-host-keyring-tools` on all four targets and published
  `secrethub-host-tools-v1.0.0-rc.30-{linux,macos}-{amd64,arm64}.tar.gz`.
  Each job built the escript and launcher, ran the launcher's subprocess suite
  (Linux 83/83; macOS arm64 and amd64 75/75), installed the archive and smoke
  tested the helpers (Git hard failure without an Agent, `secrethub version`).
  On macOS the SIGINT/SIGQUIT forwarding cases are skipped because the system
  `env` lacks `--default-signal`; SIGTERM forwarding and the other cases run.
  Real Git/Docker/Python consumers against a live Agent were exercised on
  Linux only.
* **Live deployment:** no host was deployed and no real credential was used.
* **Existing slow fixtures:** some pre-existing channel tests migrate a fresh
  database and exceed ExUnit's default 60 s timeout on a loaded machine; they
  pass with `--timeout 600000`.
