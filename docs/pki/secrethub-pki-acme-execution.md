# ACME execution evidence

Started 2026-10-22 (Asia/Shanghai) from `395f14c87c71c40d4041c35e897d4f1b2481d4d5`.
The planning baseline remains an ancestor; no reset was performed. The intervening
commits update dependencies, document the unrelated Gaoxy blocker, and add the PKI
goal/design/plan. Unrelated `secrethub-access-audit-plan.md` is preserved in the
original checkout. Implementation uses `.trees/codex-pki-acme` on `codex/pki-acme`.

## Execution checklist

- [x] Read goal, design, implementation plan, repository instructions and release workflow.
- [x] Confirm current Core lacks supervised Oban and historical-only secret snapshots.
- [x] Separate protocol/trust and DNS adapter ownership from coordinator persistence/publication.
- [x] Default public trust and separate staging issuance profile.
- [x] Dedicated schemas, constraints, encrypted keys and provider references.
- [x] Named Core Oban, reconciliation and feature controls.
- [x] ACME protocol, certificate validation, ARI and fallback renewal.
- [x] Cloudflare and Route 53 adapters, delegation and authoritative propagation.
- [x] Durable issuance, cancellation, revocation and cleanup.
- [x] Atomic owned secret publication, exact-version delivery and retention gates.
- [x] Management UI/API and explicit private exports.
- [x] Deterministic protocol/provider/durability/publication tests and Pebble lifecycle.
- [x] Offline assembled release and scoped regressions/quality checks.
- [x] Operational documentation and source implementation commits.
- [x] Documentation commit, verified branch push and [pull request #18](https://github.com/gsmlg-dev/secrethub/pull/18).
- [ ] Mandatory branch CI/Test/E2E gates.
- [ ] Publish and verify the next release after mandatory gates pass.

## Dependency decision

Use the narrow native adapter over directly declared Req, JOSE, OTP/X509.
The required persisted-URL recovery, injectable explicit trust and RFC 9773 ARI
are the selection criteria; adopting an ACME library alone does not satisfy them.
Resolved additions: CAStore 1.0.22, JOSE 1.11.12, aws_signature 0.4.3.
Existing locked versions: Req 0.7.5, Oban 2.24.2, IDNA 7.1.0, X509 umbrella 0.9.2.
Core also explicitly packages `inets` for HTTP-date parsing and `xmerl` for Route
53 XML. The account/leaf keys remain caller-owned; no external ACME executable
is part of the runtime.

## Delivered capabilities

| Area | Result |
| --- | --- |
| Trust | Packaged CAStore catalogue, actual-byte hash/provenance, offline PEM export; separate pinned staging-chain trust |
| Protocol | Native ACME v2, verified transport, caller-owned keys/CSR, URL recovery, bounded nonce retries, certificate validation and ARI |
| Providers | Real Cloudflare and Route 53 HTTP adapters, scoped credential references/session tokens, explicit zones/delegation and authoritative TXT checks |
| Durability | Named Core Oban, bounded claims, persisted intent/receipts, cancellation/uncertainty, reconciliation, independent cleanup and revocation |
| Publication | Atomic encrypted static output/history with immutable certificate-version links, audit rollback, replay and retention protection |
| Delivery | Current and historical quarantine gates, exact fetched-version validation during concurrent publication, cache revision/revalidation |
| Management | Private views/API for configuration, progress, versions, recovery and no-store exports; existing Caddy mTLS/CSRF boundary |

The execution follows the design. Important implementation decisions are a
native adapter rather than patched ACME dependencies; explicit AWS environment
credentials or encrypted references rather than implicit cloud-role discovery;
and a pinned PostgreSQL session advisory lock for bounded provider mutations,
never for propagation waits. Route 53 ambiguous ownership remains an unresolved
cleanup obligation rather than permission to delete someone else's TXT value.

Review added regressions for pending/processing challenge polling, lost challenge
acknowledgment, exhausted nonce retries, stale revocation failures, due-work
starvation, account registration visibility and reads racing publication.

## Upgrade and rollout

Apply these Core migrations using the normal release migration command before
starting the upgraded service:

- `20261022000001_install_core_oban`: Oban schema version 14.
- `20261022000002_create_managed_acme`: dedicated ACME domain tables, immutable
  material/ownership constraints and referenced-history retention guards.

They were applied only to disposable local test databases. Existing development
and production services/databases were not restarted or migrated. Retention
guards require an intentional coordinated rollback; do not remove ACME history
to run an older binary.

The supported Core profile enables `public_trust` and `acme`. No issuance/DNS
effects occur without explicitly configured resources. Set
`SECRET_HUB_ACME_ENABLED=false` to stop new issuance/publication; leave old
credential references and outbound access available for cleanup/revocation.
Vault unsealing is required for account, leaf-key and credential operations.

See [operator procedures](managed-public-certificates.md), the
[deployment guide](../deploy.md), and the [changelog](../../CHANGELOG.md).

## Automated evidence

Commands run from the implementation worktree. Database-backed commands use only
the disposable PostgreSQL socket `/tmp/secrethub-acme-pg`, port `55439`, user
`secrethub`, with `SECRETHUB_ROLE=core MIX_ENV=test`, `ERL_FLAGS='+S 8:8'`, and
`MIX_DEPS_PATH=/home/gao/Workspace/gsmlg-dev/secrethub/deps`.

| Gate | Observed result |
| --- | --- |
| Combined feature qualification | PASS: 96 Core tests, 0 failures, 2 optional Pebble skips; 14 Web management tests, 0 failures (`/tmp/secrethub-acme-feature-release-final.log`) |
| Touched internal CA/app/client-auth/ingress/secret/runtime authorization regressions | PASS: 181 Core tests and 5 Web tests, 0 failures; the final feature suite additionally covers exact-snapshot reads racing publication (`/tmp/secrethub-acme-regressions.log`) |
| Actual named Core Oban execution and restart recovery | PASS: 1 test, 0 failures, using the configured PostgreSQL notifier (`/tmp/secrethub-acme-runtime-postgres-notifier.log`) |
| Standalone native ACME/Pebble lifecycle | PASS: 22 tests, 0 failures; issuance, replacement, ARI, revocation and TXT cleanup |
| Durable real Pebble lifecycle | PASS: 1 selected lifecycle (10 tests, 0 failures, 9 excluded); three publications, two renewals, ARI, exact material, revocation and TXT cleanup; recovered after three injected badNonce responses (`/tmp/secrethub-acme-durable-pebble-acceptance.log`) |
| Scoped authoritative DNS test fixture | PASS: 4 Python tests, including real loopback UDP/TCP framing, source identity and authoritative scope |
| Assembled production Core release | PASS: built locally at `/tmp/secrethub-acme-core-release`; offline/read-only probe passes before Repo/Vault startup |
| Scoped formatting | PASS: 65 changed/new Elixir/HEEx paths, excluding whole-file inspection of configuration outside the feature boundary |
| Scoped strict Credo | PASS: 47 new feature files, 650 modules/functions; final Workflow nonce changes also rechecked (`/tmp/secrethub-acme-final-credo.log`, `/tmp/secrethub-acme-final-nonce-credo.log`) |
| Final compile | PASS: warnings-as-errors compile, exit 0 (`/tmp/secrethub-acme-final-compile.log`) |
| CI recovery, protocol | PASS: 22 tests, 0 failures, 1 optional Pebble skip after the documented empty CSR subject type correction (`/tmp/secrethub-acme-protocol-dialyzer-fix.log`) |
| CI recovery, DNS providers | PASS: 28 tests, 0 failures; includes red/green malformed Cloudflare JSON regression, preserved borrowed records and bounded CNAME traversal (`/tmp/secrethub-dns-dialyzer-green.log`) |
| CI recovery, DNS claim persistence | PASS: 9 tests, 0 failures (`/tmp/secrethub-acme-dns-claim-dialyzer-fix.log`) |
| CI recovery, Core supervision | PASS: 6 tests, 0 failures with named Oban represented in the expected runtime children (`/tmp/secrethub-acme-supervision-regression.log`) |
| CI recovery, historical audit migrations | PASS: both affected tests selected and passed individually; 13 and 5 other tests excluded, respectively. Explicit audit migration lists preserve their original rollback/chain/retention assertions and the ACME rollback guard (`/tmp/secrethub-acme-audit-migration-regression.log`, `/tmp/secrethub-acme-audit-retention-regression.log`) |

The source passed these local feature checks, with the focused CI recovery
checks run after their respective corrections. Interrupted or contending
database runs are not counted as pass evidence. Mandatory remote branch checks
are a separate release gate, recorded below.

The release probe uses `scripts/verify-pki-trust-release.exs` with an unshared
network and read-only filesystem. It verifies actual packaged PEM bytes and
root fingerprints, packaged notices/staging profile, and the runtime HTTP-date
parser without starting Core services. The local artifact still uses the
existing `1.0.0-rc.21` version; it is qualification evidence, not a new published
release.

Actual packaged-byte evidence from the final assembled release:

| Material | Count/version | SHA-256 |
| --- | --- | --- |
| Core qualification archive, rebuilt with CI recovery source | `1.0.0-rc.21` | `b9c7267ebf43d02445f8a573629d1629a7d934f304bca2e0881741d41d1ae6cb` |
| Mozilla-derived PEM | CAStore `1.0.22`, 118 roots | `53652180bc53975a475f0b1574571426dc4ba27d7e08e04550dab69fb7537c25` |
| Separate staging PEM | 2 roots | `969992085e88a152ab64584b798d446e10f6de0ba084929c9ea3fa17c8ee3101` |

The archive was built with `MIX_ENV=prod SECRETHUB_ROLE=core`, isolated
`MIX_BUILD_PATH=/tmp/secrethub-acme-release-build`, and
`mix release secrethub_core --path /tmp/secrethub-acme-core-release --overwrite`.
The probe ran in a `bwrap` sandbox with a read-only root and unshared network;
Repo and Vault remained absent before and after it. Evidence logs:
`/tmp/secrethub-acme-release-recovery-build.log` and
`/tmp/secrethub-acme-release-recovery-offline-probe.log`.

Reproducible ACME qualification:

```sh
# With the disposable PostgreSQL environment above:
mix test apps/secrethub_core/test/secrethub_core/pki/acme/ \
  apps/secrethub_core/test/secrethub_core/pki/dns/ \
  apps/secrethub_core/test/secrethub_core/pki/managed_certificates_test.exs

# Start only owned, ephemeral Pebble/DNS processes and remove them on exit:
SECRETHUB_PEBBLE_TOOLS=/tmp/secrethub-acme-tools \
  scripts/test-pki-acme-pebble.sh
SECRETHUB_PEBBLE_TOOLS=/tmp/secrethub-acme-tools \
  SECRETHUB_PEBBLE_RUN_SCRIPT=scripts/test-pki-acme-workflow.exs \
  scripts/test-pki-acme-pebble.sh

python3 scripts/test_pki_acme_authoritative_dns.py
```

The two Pebble commands share fixed loopback ports and must run sequentially.
The harness pins Pebble v2.10.1 and uses independently injected TLS/issuance
roots, never a public CA or live DNS-provider account.

## Delivery gates

The starting commit's Test and E2E workflows passed. Its CI workflow
[39648764278](https://github.com/gsmlg-dev/secrethub/actions/runs/39648764278)
failed Dialyzer before implementation; the preceding commit has the same failed
gate. Do not treat this baseline failure as permission to bypass the final
branch's mandatory checks. Do not expand this feature into unrelated repairs.

The existing release workflow takes `version` and `git-rev`, pushes its own
version bump, and publishes archives/OCI/Hex/tag/release. The latest verified
release before implementation is `v1.0.0-rc.21`. No manual version bump or
release dispatch is appropriate before mandatory gates pass. Final commit,
push/PR, branch checks and release status are recorded in the delivery result.

## Delivery result

Source implementation is committed locally in reviewable slices:

- `363af5d`: packaged public trust and native ACME protocol.
- `6d27ce4`: ownership-safe Cloudflare and Route 53 DNS-01 providers.
- `444660a`: managed certificate schemas, ownership and history.
- `e68fe68`: durable Core jobs and atomic secret publication.
- `bb9a3cf`: private ACME management and exact exports.
- `8acf7e5`: operator/deployment/changelog and qualification documentation.
- `190cdf4`: corrected CSR contract, bounded DNS types/error handling, claim
  persistence simplification and explicit analysis dependencies.
- `bb2c0ca`: historical audit migration selection, Core supervision expectation
  and delivery evidence.

The branch is pushed to `origin/codex/pki-acme` and attached to
[draft PR #18](https://github.com/gsmlg-dev/secrethub/pull/18). The initial
documentation head `8acf7e588703570e0885b2d98cfac910386f4d3d` was independently
verified with `git ls-remote`; subsequent corrections are appended without
rewriting history. The final integration correction selects the intended older
audit migrations in their tests and accounts for Core Oban in the supervision
expectation. It does not weaken the ACME migration's retention safeguard.
Runtime restart qualification also keeps the configured PostgreSQL notifier.
Its previous test-only process-group notifier override raced a shared scope
during restart in the full suite; removing that override exercises the supported
Core runtime and passes the focused restart regression.

### Required remote gates

| Source head | Workflow | Observed result |
| --- | --- | --- |
| `8acf7e5` | [Test 39660989876](https://github.com/gsmlg-dev/secrethub/actions/runs/39660989876) | FAIL: three feature-induced integration expectations; corrected and passed in the focused supervision/audit regressions above |
| `190cdf4` | [CI 39662584759](https://github.com/gsmlg-dev/secrethub/actions/runs/39662584759) | Compile, Format, Credo and Caddy Go PASS; Dialyzer FAIL with exactly the 12 pre-existing unignored warning locations/kinds and zero new locations |
| `190cdf4` | [E2E 39662593501](https://github.com/gsmlg-dev/secrethub/actions/runs/39662593501) | PASS |
| `bb2c0ca` | [CI 39663769116](https://github.com/gsmlg-dev/secrethub/actions/runs/39663769116) | Compile, Format, Credo and Caddy Go PASS; Dialyzer has exactly the same 12 baseline warning locations/kinds |
| `bb2c0ca` | [E2E 39663769182](https://github.com/gsmlg-dev/secrethub/actions/runs/39663769182) | PASS: 11 E2E and 38 CLI socket tests, 0 failures |
| `bb2c0ca` | [Test 39663769535](https://github.com/gsmlg-dev/secrethub/actions/runs/39663769535) | Earlier three integration regressions passed; one restart test failed on its process-group override, corrected as described above |

The 12 remaining Dialyzer warnings are in management ingress URI types, Agent
UDS cache contracts/patterns, AuthorizationVersions and Human backend/lease
monitor code. Comparing warning locations and kinds against starting-head
[CI 39648764278](https://github.com/gsmlg-dev/secrethub/actions/runs/39648764278)
produces equal sets, with no new warnings. Recovery evidence:
`/tmp/secrethub-acme-ci-recovery.log` and
`/tmp/secrethub-acme-ci-baseline.log`. No broad warning suppression or unrelated
runtime repair was introduced.

The full Test workflow is rerun after the integration corrections. The
[PR checks](https://github.com/gsmlg-dev/secrethub/pull/18/checks) and PR
description hold the final-head workflow results; the source and qualification
evidence above remain tied to the revisions that actually ran them.

Release status: **BLOCKED by the required baseline Dialyzer gate**. The PR stays
draft and unmerged. No new version, tag, release, image or Hex package has been
published. The last verified published release is
[v1.0.0-rc.21](https://github.com/gsmlg-dev/secrethub/releases/tag/v1.0.0-rc.21).

Remaining delivery steps: repair those baseline warnings in a separately scoped
change, integrate/requalify the PR through all required checks, then run the
existing release workflow and verify its archives, image manifests, Hex package
and tag. If `v1.0.0-rc.21` is still latest, the next dispatch after those gates is:

```sh
gh workflow run release.yml --repo gsmlg-dev/secrethub --ref main \
  -f version=1.0.0-rc.22 -f git-rev=main
```

Recheck the latest version and integrated commit immediately before dispatch.
Release remains distinct from production deployment or application adoption.

## Operational evidence

Live Let's Encrypt staging through Cloudflare: NOT RUN (no authorized test zone/credentials supplied).
Live Let's Encrypt staging through Route 53: NOT RUN (no authorized test zone/credentials supplied).
No production certificate or live DNS mutation is part of qualification.
