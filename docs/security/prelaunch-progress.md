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
skips. Independent read-only re-review of these repairs passed with no remaining
blocking finding; the reviewer separately ran four signing-key tests. This
review does not replace artifact, compatibility or restore acceptance.

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

## Latest consumer and redaction checks

Agent/CLI proof, identity, floor and cache regressions passed for completed
source slices (59 Agent tests and 38 CLI tests before the final lint-only refresh).
An independent Python/OpenSSL application exercised the actual Agent UDS with
isolated Core responses: initial/update private atomic file readback succeeded;
denial and outage preserved the file; stdout excluded values (13 tests, no
failures in that focused socket suite). These remain source fixtures.

Core authorization now has 25 focused tests with one remaining failure; actual
independent-connection concurrency, revocation and floor-race cases passed.
The outstanding query casts `text[]` against a `varchar[]` policy column.
A one-line matching-type patch is prepared but unapplied. The recovery
specialist exhausted its two-round developer limit and explicitly requires
operator authorization for another round. The permission question is pending;
this restriction is not an application security-design gate.

The actual channel suite passed 15 of 16 tests using real independent database
connections; its remaining legacy-read failure reaches that same Core query.
It was not weakened or skipped. No Core authorization commit or final source
freeze is claimed yet.

Four new redaction regressions failed before the fix: secret/changeset inspection,
JSON encoding/decoding errors and low-level encryption exception detail. Secret
fields now redact inspection and error helpers return bounded strings. Final
focused evidence is 36 Shared tests plus two Core tests, all passing.
`go test -mod=readonly ./...` passed for the local Caddy consumer module and its
new executable entrypoint. Full image-level PKI enforcement remains pending.

## Later provisional artifact checks

The corrected Core assets were verified in image `ab0e6cbc24ae`, which passed
selected G01–G10 and G20 artifact checks. These results do not transfer to later
images. A real endpoint-enrollment failure exposed reversed runtime configuration
lookups in `AgentEndpointManager`; four focused tests passed after the correction
in `2f36fb9`. The resulting Core image `43715c4edce1` enrolled the fixture Agent
over its dedicated mTLS runtime listener.

The Agent container probe now uses the required UDS request envelope. Updated
image `13cc6bd2aa1e` became healthy with its preexisting certificate, key, CA and
authorization-floor digests preserved. The stronger G11 lifecycle run against
Core `43715c4edce1` and Agent `13cc6bd2aa1e` passed in 62.215 seconds. Enrollment
IDs are captured before both restarts and checked after each; fresh heartbeats
must follow restart completion. A copied damaged identity fails its identity
preflight check and startup while all other checks pass. Independent review
cleared the helper and probe. The earlier weaker G11 report is superseded;
neither report establishes static delivery or full recovery.

Actual Caddy consumer checks passed for valid/missing/unrelated certificates,
revocation and CRL refresh using the Agent artifact's headless bundle manager.
Revocation denied a fresh handshake within 11.531 seconds and a request on an
already-open connection within 11.541 seconds. Caddy disabled session tickets;
the attempted prior-session reuse used a fresh handshake, so resumed-session
enforcement is not claimed. Old/corrupt bundle replay preserved monotonic state.
Enrolled WebSocket delivery, disconnect/lag, consumer corruption and G17 remain
unaccepted.

A fresh independent PostgreSQL cluster restored the pre-revocation backup in
3.11 seconds. An isolated Core artifact manually unsealed and verified the old
static secret, audit chain and both runtime and Client Auth PKI keys in a further
15.767 seconds. These are partial G16 checks, not full service/consumer RTO.
The restored authority remains at generation/CRL 1 while retained consumer
history is newer; reconciliation and identity/consumer recovery remain required.

All these images and reports are provisional, built before a final source
freeze. Full G01–G20 acceptance against immutable final artifacts remains open.
