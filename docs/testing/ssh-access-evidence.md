# SSH access implementation evidence

## Current qualification (2026-10-20)

**Verdict: confidentiality and Linux x86_64 runtime qualification PASS.** The
broader plan still has lint debt and unexecuted target-runtime checks below;
these results do not establish deployment or aarch64/NixOS runtime acceptance.

The Agent now requires `phoenix_socket_client ~> 0.8.7`, consuming the published
fix for [upstream #108](https://github.com/gsmlg-dev/phoenix_socket_client/issues/108).
The lockfile resolves `http_web_socket`, `http_core` and `http_runtime` 0.21.14,
including the upstream transport confidentiality fix. No dependency internals,
logger filters or alternate transports were patched locally.

| Check | Current result |
| --- | --- |
| Original redaction diagnostic before update | RED: exit 1 with 0.8.5; both status and telemetry exposed the sentinel. `/tmp/secrethub-ssh-release-redaction-before.log`. |
| Same diagnostic after update | PASS: exit 0, both exposure flags false. `/tmp/secrethub-ssh-release-redaction-after.log`. |
| Normal application-started scoped suite | PASS: 98 tests, 0 failures, seed `364646`. `/tmp/secrethub-ssh-release-normal-tests.log`. |
| Core-only scoped suite | PASS: 98 tests, 0 failures, seed `180419`. `/tmp/secrethub-ssh-release-core-only-tests.log`. |
| Production compile / Agent assembly | PASS: `mix compile --warnings-as-errors`, rebuilt native Agent and own-app version verification. |
| Minimal-environment packaged helpers | RED/GREEN: removing the consumer's supplied PATH reproduced `dirname: command not found`; the release assembly now supplies trusted system utility paths for only the two public SSH commands before launcher utilities run. Both helpers, lookup reasons, peer checks and error exits pass with `env -i` and no supplied PATH. `/tmp/secrethub-ssh-release-minimal-env-before.log`, `/tmp/secrethub-ssh-release-minimal-env-after.log`. |
| Release packaging regressions | PASS: 10 tests, `/tmp/secrethub-ssh-release-packaging-fixed.log`. |
| Changed helper type analysis | PASS: helper and its SSH dependencies, 0 Dialyzer warnings. `/tmp/secrethub-ssh-release-helper-dialyzer.log`. This is not an umbrella-wide Dialyzer claim. |
| Actual Core / Agent / OpenSSH | PASS: 1 test, 0 failures, seed `291716`, 34.5 seconds. `/tmp/secrethub-ssh-release-openssh-final.log`. |

Both source users successfully authenticate with the real mTLS runtime and the
packaged helpers. The same run verifies wrong-user/reverse denial, group removal
and batch revocation, explicit deny override, wrong host keys, alternate local
authorized-key files and user CAs, cross-UID signing isolation and inaccessible
sockets. The nobody client uses its actual primary group and supplementary
fixture membership, as required by OpenSSH's subprocess privilege handling.
Test setup reuses already running PubSub/Endpoint services while retaining the
original assertions in both startup modes.

Native qualification artifact:
`/tmp/secrethub-ssh-release-agent/secrethub_agent-1.0.0-rc.18.tar.gz`, SHA256
`fcdaae3951a0de3e48a4f2a0505761a94b05ad17775a6b9a0c009b62c291132c`.
This is a local prepublication build; the release workflow assigns the next
version and builds published archives from its immutable release commit.
Independent review found no blockers in the dependency minimum, helper-only
launcher environment or application-started test setup. Existing 18-file lint
findings and unexecuted target-runtime checks remain recorded below. Test-only
channel teardown may log an unregister error after ConnectionManager stops;
the runtime assertions pass. No live services or databases were changed.

## Historical qualification (2026-10-19)

The following sections preserve the original results and blockers as recorded
before the current update; the upstream and real-login status above supersedes
their historical verdict.

Date: 2026-10-19. Branch: `codex/ssh-access`, isolated worktree `.trees/ssh-access`,
based on design commit `396b744a0250c37fa3a5c2fc0494186046115765`.

**Verdict: INCOMPLETE / BLOCKED_UPSTREAM.** This is a local implementation and
qualification record, not deployment or release acceptance. SSH stays opt-in and
disabled by default. During qualification, no changes were published, merged or
applied to running Core, Agent or system sshd services.

## Main integration and release gate

On 2026-10-19, the implementation through `d5ed92d` was fast-forwarded into
`main`, and the clean `.trees/ssh-access` worktree and branch were removed.
Upstream #108 remains open; GitHub and Hex both still publish 0.8.5 as the latest
dependency version. Release publication remains **BLOCKED_UPSTREAM** under the
repository blocker policy. No release workflow was dispatched or version bumped;
the latest published SecretHub version is still `v1.0.0-rc.18` and predates this
integration. The qualification results below have not been rerun during this
merge and do not establish release acceptance.

## Blocking dependency

[phoenix_socket_client#108](https://github.com/gsmlg-dev/phoenix_socket_client/issues/108)
is an open Bug with `internal request`, severity **blocker**. The pinned version
is 0.8.5. Its Socket process retains raw private-key responses in unredacted
`pending_decodes`; channel reply telemetry also includes the complete private
response. The application-level status redaction cannot protect these dependency
processes. No dependency patch or alternate-transport workaround was introduced.

The deterministic, key-free diagnostic is:

```sh
MIX_ENV=test ERL_FLAGS='+S 4:4' \
  mix run --no-start scripts/ssh/transport_redaction_probe.exs
```

Observed exit **1**:

```text
socket_status_exposes_private_material=true
reply_telemetry_exposes_private_material=true
BLOCKED_UPSTREAM: private SSH responses require upstream redaction
```

This executes the production receive/decode callback and installs its exact
returned pending state in the real Socket process for deterministic status
inspection, then exercises the production reply telemetry callback. It uses a
sentinel rather than a private key. A TODO at the SSH channel callsite preserves
the upstream dependency. Signing confidentiality and final SSH acceptance stop
until an upstream fix is consumed and verified.

## Source and package checks

| Check | Result and boundary |
| --- | --- |
| Shared key/profile regressions | PASS: 11 tests. Independent OpenSSH Ed25519/RSA imports/signatures; public-header mismatch; strict profiles and unrelated-host exclusion. |
| Agent SSH/config/protocol regressions | PASS: 62 tests. Kernel UID, unsupported mutations, bounded framing/RPCs, outages/restarts, delayed generation, full path/peer integrity, helper errors and configuration. |
| Core SSH regressions | PASS: 15 tests. Dedicated disposable PostgreSQL; atomic/stale batches, directed groups/denies, encrypted identities, endpoint rotation, current credentials/audit/seal and bracketed nondefault-port lookups. |
| Management/channel regressions | PASS: 10 tests. Public matrix/forms, preview/confirm, private import removal, missing capabilities and current certificate authorization. |
| Combined final source regressions | PASS: **98 tests, 0 failures**, seed `265771`, exit 0, log `/tmp/secrethub-ssh-consolidated-final.log`. |
| Formatting / incremental compile | PASS: explicit SSH source/integration file list formatted; `mix compile --warnings-as-errors` exit 0 after the scoped suite. Migration-module reload warnings in the combined test fixture do not appear in the incremental compile. |
| Agent production compile | PASS: fresh standalone production compile with `--warnings-as-errors`. |
| Packaged public helpers | PASS: real `nobody` UID 65534 under minimal environment; both commands, all lookup reasons, positive/empty-deny/error output, peer-counterfeit rejection, no readable private TOML/cookie or release writes. Injected public lookup fixture; does not prove Core authorization. |
| New Agent SSH module Credo | PASS: all eight modules, repository checks, strict mode. |
| Wider explicit 18-file Credo | FAIL: 1 logger metadata warning, 23 complexity/nesting findings and 16 alias suggestions across new SSH code and touched integration modules. No lint checks disabled to hide this result. |
| NixOS module evaluation | PASS: evaluated configuration/assertions for separate groups/directories, source accounts, nobody lookup access and DynamicUser/private state. Evaluation does not prove a running NixOS service. |
| Full Nix build | BLOCKED_ENV: unavailable closure, upstream Savannah HTTP 502 / SourceForge timeout; owned build canceled. |
| Linux x86_64 native package | Public-helper consumer PASS; complete signing/login acceptance remains blocked. |
| Linux aarch64 native package / NixOS runtime | NOT RUN. No qualified target execution environment. |
| Live deployment | NOT RUN. No deployment or live service restart authorized. |

The consolidated run uses a disposable local PostgreSQL supplied through
`PGHOST`, `PGPORT` and `PGUSER`; it starts only Core to avoid unrelated umbrella
application startup:

```sh
MIX_ENV=test ERL_FLAGS='+S 4:4' \
  mix do run --no-start scripts/ssh/test_boot.exs, test --no-start \
  apps/secrethub_shared/test/secrethub_shared/ssh/ \
  apps/secrethub_core/test/secrethub_core/ssh/ \
  apps/secrethub_agent/test/secrethub_agent/ssh/ \
  apps/secrethub_agent/test/secrethub_agent/config_test.exs \
  apps/secrethub_agent/test/secrethub_agent/config_cli_test.exs \
  apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs \
  apps/secrethub_web/test/secrethub_web/channels/ssh_runtime_channel_test.exs \
  apps/secrethub_web/test/secrethub_web/live/ssh_access_live_test.exs
```

Final Nix evaluation returned
`/nix/store/8vwmrmbv8nhjn1pcsfgh8zbsfzrx2x1i-secrethub-agent-module-check.drv`
with `nix eval --offline --raw '.#checks.x86_64-linux.agent-module.drvPath'`.

The final native Agent archive is
`/tmp/secrethub-ssh-agent-final-release/secrethub_agent-1.0.0-rc.18.tar.gz`.
SHA256: `91bc30dd6f9fc15cbc45da51a3169c38171f2feb160b93e5053f2cb7ce57c62e`.
Its 17 production/release/Nix/key source files match the checked manifest
`/tmp/secrethub-ssh-agent-product-manifest.txt` (SHA256
`863f80865a5d4a22779b071caf5fc5fa999fad72fbe7d5cf9b08f75d373eed51`).
These are local review artifacts, not published release assets.

Public consumer command, using the matching OTP toolchain and passwordless sudo
for an owned `/run` fixture and the nobody process:

```sh
ERL_FLAGS='+S 4:4' elixir \
  -pa '/tmp/secrethub-ssh-agent-final-release/lib/*/ebin' \
  scripts/ssh/agent_release_consumer.exs /tmp/secrethub-ssh-agent-final-release
```

## Actual Core / Agent / OpenSSH attempt

`scripts/ssh/qualify_openssh.exs` starts the real Core runtime endpoint, two
certificate-authenticated Agent Connections (one in an isolated BEAM), separate
Unix sockets, two disposable target accounts and owned loopback sshd processes.
It uses the packaged release helpers. It never reloads the system sshd.

Last run: **1 test, 1 failure**, seed `626104`, exit **2**, log
`/tmp/secrethub-ssh-astra-round2.log`, Linux x86_64, OpenSSH 10.5p1.

Completed assertions:

- Both real mTLS runtime connections and public inventory exchange.
- Isolated sshd startup and effective exclusion of local key files and alternate
  trusted user-certificate CAs.
- Real `ssh-add -l`, `-L`, `-T`; the second source UID sees only its identity and
  cannot sign with the first user's key; an inaccessible signing socket denies it.
- Effective strict client host checking, DNS trust disabled and both alternate
  known-host files set to `/dev/null`.

The first login failed because OpenSSH supplied `%H` as `[127.0.0.1]:port` during
`ORDER`; Core expected a bare alias. A subsequent scoped regression reproduced
this failure, and the public lookup now parses bracketed DNS/IPv4/IPv6 tokens,
requiring the embedded port to equal `%p`. The complete real login harness was
**not rerun** after the upstream confidentiality blocker was confirmed. The
failed attempt also predates the final helper path-integrity artifact.

Successful two-user login, reverse/wrong-user denial, actual wrong-host-key
rejection, alternate local-key/CA login rejection and batch revocation are
**NOT RUN to completion**. Configuration assertions and unit tests do not stand
in for those actual login outcomes. All attempted fixture directories, accounts,
groups, isolated nodes and owned sshd processes were cleaned up.

## Reviews and continuation

Independent specification review found malformed-key success exits and overly
broad client host matching. Both were fixed with regressions and re-reviewed.
Independent security review found replaceable socket ancestors. Full-chain
validation, root-anchored delegation, peer UID and inode/snapshot checks fixed
that P1; the reviewer confirmed it resolved. Old asynchronous runtime responses
now require the same channel, monitor generation, capability and connection.
Both reviews preserve overall acceptance as blocked by upstream #108.

Local implementation commits: `4aa2f7a` (shared keys/profiles), `1ca5cf8` (Core
policy/storage), `311607b` (Agent/configuration/Nix), `ba87d58` (management and
trusted channel). These were local at qualification time and were subsequently
included in the main integration described above.

The management checkbox workaround is tracked by
[phoenix-duskmoon-ui#205](https://github.com/duskmoon-dev/phoenix-duskmoon-ui/issues/205),
severity needed. Native selection controls carry TODO/WORKAROUND references;
dependency internals were not copied or changed.

To resume: consume the upstream confidentiality fix, make the sentinel diagnostic
pass, resolve remaining in-scope lint findings, rebuild matching artifacts, rerun
the complete SSH login harness, and qualify the target architectures/NixOS
runtime. Follow the [operational guide](../deployment/ssh-access-management.md)
when preparing a separately authorized deployment.
