# Prelaunch implementation evidence

Date: 2026-10-01. Baseline: `c7cb03083f98a7d461120013bf7b3b5933ffafaa`.
Implementation branch: `codex/prelaunch-wp1`, isolated under
`.trees/codex/prelaunch-wp1`. Original checkout edits remain preserved.
The operator-provided `secrethub-prelaunch-plan.en.md` is authoritative.

**The complete plan is not accepted.** No production deployment, publication,
credential rotation, persistent-data reset or live Caddy change occurred. Source
verification and provisional artifact checks below are scoped evidence.

| Package | Implemented and verified evidence | Outstanding acceptance |
| --- | --- | --- |
| WP1 | v4 GF(256) sharing, uniform coefficients, strict/canonical envelopes, independent vectors: 49 tests passed. Separate wrapping/data keys, authenticated generation-bound envelope, durable singleton creation, conservative loading/recovery, restart sealed and manual seal no-op. Combined Vault/audit checks: 128 tests, zero failures, two pre-existing skips. | Final frozen artifact, compatibility and full restore checks |
| WP2 | Private transport-peer management boundary before HTTP/socket dispatch, no second login/allowlist, CSRF/exact Origin/no-store and separate machine route set. Combined Web regression suite: 115 tests, zero failures. | Final image and actual deployment-network boundary |
| WP3 | Separate runtime-only Core/Agent inputs, historical audit keyring, disabled distribution, redacted preflight, accurate readiness/required CRL worker and restricted features. Runtime/preflight focused tests passed. Pinned/nonroot OCI builds and frozen Bun lock install. | Corrected asset manifest and final rebuilt images; runtime-key artifact gate |
| WP4 | Agent/CLI proof authentication source implementation and Core policy/revision/floor work are underway. Agent/CLI focused checks have passed for completed slices. | Complete Core/channel validation, concurrent read/revoke behavior, actual static and PKI consumers, outage/reconnect/revocation measurements |
| WP5 | Manifest/checksum backups, optional existing S3, transactional empty-target restore. Ten contract tests passed; two real PG16 tests additionally passed under isolated opt-in. Separate two S3 mocked checks passed. | Full service/consumer restore, old DB versus newer security history, complete operational monitoring acceptance |
| WP6 | Artifact harness underway. Provisional Core/Agent images built, empty candidate explicitly migrated, real nonroot Core started outside checkout. | All G01–G20 tied to a frozen source and exact final image identifiers |

## Review repairs

Legacy PKI used a known development encryption key in some historical paths.
Even a decryptable matching certificate/private-key pair cannot prove a legacy
Vault key's provenance. Explicit recovery now accepts only trustworthy existing
Secret/SecretVersion ciphertext and blocks certificate-only recovery. A real
fallback-certificate regression failed before this repair and passed afterwards.

Initialization and legacy replacement append their audit event inside the
persistence transaction; an audit failure rolls back. Unseal exposes the verified
key only after successful auditing. Four review regressions (provenance plus
initialize/recover/unseal audit failure) failed before repair and passed after it.
The final combined suite completed with 128 tests, zero failures and two existing
skips. Independent review covered the original implementation; independent
re-review of these repairs remains pending.

## Provisional artifact observations

The provisional Core runs as UID 1001 with runtime file inputs and an isolated
PostgreSQL 16 database. Its missing-input start exits nonzero with bounded input
names. Through isolated existing-mechanism Caddy mTLS, HTTP and a mounted LiveView
worked without a second login. Missing client certificates, cross-origin
mutations, missing CSRF and untrusted WebSocket Origins were rejected. A separate
machine listener cannot reach management; an outside network namespace cannot
reach the private management bind.

Two simultaneous protected initialize calls yielded one success and one
rejection with one durable configuration. Repeated initialization rejected.
A restart returned sealed state; correct shares recovered pre-restart static
ciphertext under the original Vault identity. Manual seal retained its no-op
behavior. Private fixture shares and raw responses are excluded from reports.

These observations belong to a provisional image, not the later source or a
final candidate. In particular, that image predates the management-readiness
route and corrected assets. The initial image missed its asset manifest because
recursive `mix phx.digest` received an ineffective root-relative path; the
Dockerfile now uses `mix phx.digest --no-compile`. Rebuild/verification remains
required. No provisional gate is automatically transferred to a rebuilt image.
Release distribution is disabled, so `rpc` is unavailable; harness fixture
introspection uses a separate Core-only release `eval`, not the live key state.

## Restore and test limitations

Real PostgreSQL 16 backup/restore fixtures verified old rows, nonempty-target
refusal and rollback after an injected late import failure. One isolated database
restore measured 82.108 seconds; that is not full application recovery time or
an accepted RTO. The default backup test invocation runs ten mocked-tool checks
and skips the two explicit real-database cases.

An older dynamic PostgreSQL integration fixture targets a hardcoded/unqualified
local database outside the isolated partition contract and failed PostgreSQL
password authentication. That fixture and service were left untouched; its result
is not claimed green. Dynamic lifecycle remains outside the enabled scope.

Remaining work is consumer authorization/integration, final-image qualification,
full restore/security-history reconciliation, G01–G20 evidence and runbook
verification. [Launch operations](launch-operations.md) is the authoritative
operations procedure; production cutover remains the operator's responsibility.
