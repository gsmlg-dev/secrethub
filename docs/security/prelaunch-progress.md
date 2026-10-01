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

G19 subsequently passed on Core image `43715c4edce1` with a deliberate VM failure
in a separate isolated release process holding private fixture shares and a
plaintext sentinel. The exact image's `ERL_CRASH_DUMP=/dev/null` default was
verified and inherited without override. The process failed as intended,
retained no VM dump, and its captured diagnostics and current Core logs contained
no known fixture material or private-key/credential-URL markers. The live Core
was not faulted. This remains artifact-specific provisional evidence.

The reusable restricted recovery helper then passed selected checks in 11.929
seconds against the retained older restored database and Core image
`ab0e6cbc24ae`. It stopped the CRL refresher before unseal, verified no serving
apps/listeners, recovered the static secret, verified historical audit signatures
and proved the Client Auth key matched its CA. Vault/PKI inventory and historical
audit rows remained identical. Generation/CRL 1 stayed unchanged, with no
revocations added or removed. Supplied newer consumer counters remain explicitly
unverified in this helper; G16/G17 remain partial and the recovery hold stays on.

The enrolled Agent PKI run passed issuance/trust and revocation after a deliberate
disconnect, preserving its identity. Fresh handshakes denied the revoked fixture
within 21.485 seconds; an already-open request returned 403 within 21.503 seconds.
The later forced CRL refresh did not reach the Agent within the selected
120-second fixture bound (Core generation 5, Agent 4). G14 therefore failed.
Diagnosis found that the socket library's default channel sends bare payloads
while Agent Connection expects event envelopes. A public channel adapter fix and
new-image validation are pending; neither the bound nor trust state was reset.

The adapter fix in `4cdf41c` preserves runtime event envelopes and existing
request-reply correlation through the library's public API. Its focused
regressions failed before the fix and passed afterward; the combined Connection
suite passed 16 tests, with scoped format and warnings-as-errors compilation
checks. Independent review cleared it. Rebuilt artifact validation remains open;
two builds encountered Hex registry/tarball timeouts. The Agent dependency fetch
now uses documented concurrency/timeout settings; validation has not been
weakened.

The actual older-database trust rehearsal passed selected G17 checks in 54.54
seconds using Core `43715c4edce1`, Agent `13cc6bd2aa1e` and the exact Caddy
consumer. It exported the restored generation/CRL 1 while sealed with its worker
stopped and no listeners. The artifact manager retained generation/CRL 5 and
rejected the older signed bundle without changing its trust watermark/current
bundle. Independently read Caddy watermarks advanced monotonically from 4 to the
already retained 5. The revoked leaf was denied and the unrevoked control
allowed, with expiry, CA signatures and revocation membership checked. Restored
Vault/PKI/audit inventory remained unchanged. G17 stays partial: authoritative
reconciliation and full service reopen remain unexecuted, with recovery held.

The push-fix Agent image `3b95f124b819` (source label
`b9580e18eac15017a6576494d0e815908857c5be`, explicitly dirty/provisional)
replaced only the owned fixture Agent, preserving exact identity and
nondecreasing trust counters, and became healthy. A new enrolled G14 invocation
against Core `43715c4edce1` passed issuance, the two-second disconnect/reconnect,
revocation and forced online CRL refresh. Fresh revoked handshakes were denied
within 24.217 seconds and an already-open request returned 403 within 24.226
seconds, inside the selected 120-second fixture bound. The unrevoked control
remained allowed. Both Agent delivery and consumer use of generation/CRL 7 were
observed. Caddy issued no session tickets; resumed-session enforcement remains
unexecuted rather than claimed. Old/corrupt replay preserved monotonic state.
The earlier failed G14 report is retained. This is provisional image-specific
evidence; full G01–G20 acceptance against frozen final artifacts remains open.

The strengthened G11 lifecycle check also passed on this push-fix Agent in
64.032 seconds. Both restarts preserved identity and enrollment inventory, fresh
heartbeats followed restart completion, Core restarted sealed until manual
unseal, and a damaged identity copy was rejected without changing live state.

Copy-only G15 selected negative checks passed in 87.361 seconds against the
push-fix Agent and the exact Caddy consumer, using retained generation/CRL 7.
The running consumer observed a bundle-transcript integrity failure after CRL
disk damage, retained last-known-good trust, denied the revoked leaf and allowed
the unrevoked control. A new consumer process exited nonzero on the damaged
bundle and denied the control. With every copied generation's CRL and the copied
manager watermark damaged, the manager quarantined itself and twice rejected
application with `damaged_state_recovery_required`. Consumer watermarks, current
link and copied identity inventory stayed unchanged; the original source volume
inventory stayed byte-identical. All invocation-owned containers stopped and
all diagnostic copies remain. No forced recovery was selected or authorized;
G15 remains partial in the report, with recovery held. The two failed prior
reports are retained. The successful run includes a socket-probe correction:
`SO_REUSEADDR` permits a free port in `TIME_WAIT` while still rejecting an active
listener, verified against the actual helper before and after the change.

The independent static-consumer image `ae6125bf3306` starts as UID1002 outside
the checkout and passes its CLI contract probe. Authorized delivery remains
unexecuted: Core `43715c4edce1` predates application-principal/revisioned reads,
the authorization migrations and typed-runtime gate. Current Agent requests
already require that newer contract. Source API inspection is preparation,
not G12/G13 acceptance; a separate release `eval` cannot inspect a live Agent's
cache because release distribution is disabled.

Consistent disposable snapshots now include the enrolled Agent's private
identity, SSH host key and monotonic trust state, kept separately from database
archives and independently held unseal/audit material. Generation-7 and later
generation-9 database backups were taken with the owned Core and Agent stopped;
the original services were restarted and Agent identity digests preserved. The
snapshot operations measured 21.139 and 34.587 seconds respectively. Both were
restored into new empty databases in the isolated recovery cluster without
dropping or overwriting the earlier databases (3.500 and 3.518 seconds including
fixture preparation). These durations do not establish full application RTO.

The generation-7 restore passed restricted static decryption, historical audit
verification and CA signing checks. A fresh PKI invocation independently retained
generation/CRL 9 after a newer revocation; the old generation-7 signed bundle was
rejected against that history with actual revoked/control requests. All leaves
used for those requests passed expiry checks. Earlier expired leaves were not
used as revocation evidence. The first restricted check selected equal supplied
counters (7 versus 7) and correctly failed its older-history assertion; its
report is retained. The later independently checked 7-versus-9 case passed.

Authoritative PKI reconciliation selected the complete newer generation-9 backup
rather than modifying the older database or raising its counters. Its restricted
integrity/key-use checks passed in 23.125 seconds, with the original CA pin,
signed publication, old static data and historical audit preserved. The first
attempt failed because ordinary file copying lost the original service group;
the copied inputs now preserve exact numeric ownership and `0640` modes, with no
change to original files or broader permissions.

A controlled PKI service restore then passed in 61.596 seconds after database
import/preflight. The restored Core started sealed, was manually unsealed through
the existing protected ingress, and the copied Agent reconnected with a fresh
heartbeat and identical identity digests. The restored publication matched
retained generation/CRL 9; the actual Caddy consumer denied the revoked leaf and
allowed the control, with expiry checked before and after. No new CA or counter
reset was used. All serving drill containers were removed and both original
fixture services are healthy. The older databases and diagnostic state remain
held. New-generation distribution during this restore was unexecuted; the
retained valid generation was used. G16/G17 and the full plan remain partial:
static-consumer recovery and immutable final-artifact acceptance are outstanding.

Remaining qualification depends on the matched Core authorization artifact.
The prepared `text[]` to `varchar[]` policy-query repair remains unapplied pending
the previously requested extra focused repair round. Live fixture catalog
inspection confirms `entity_bindings` is `character varying(255)[]`. The same
approval dependency has persisted across goal continuations; provisional source
and image checks do not authorize bypassing that recovery limit or freezing a
candidate while the focused Core/channel failures remain.
