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
| WP3 | Separate runtime-only Core/Agent inputs, historical audit keyring, disabled distribution, redacted preflight, accurate readiness/required CRL worker and restricted features. Runtime/preflight focused tests passed. Pinned/nonroot provisional OCI builds, locked assets/digest and release assembly passed. | Frozen committed source and exact final image qualification; provisional evidence must be rerun |
| WP4 | Actual static-consumer update/denial/revocation/restarts/outage passed; direct live-cache expiry observed on the exact-image debug clone. Enrolled PKI consumer issuance/revocation/reconnect and retained-history refusal passed. Approved SQL and both reviewed authorization regressions passed 28 Core, 30 existing policy and 17 channel tests. | Clean committed artifact build and final exact-artifact qualification |
| WP5 | Manifest/checksum backups and transactional empty-target PG16 restores passed. Separate Agent/consumer identity snapshots, restricted static/audit/PKI checks, retained-history reconciliation, controlled PKI and static-consumer reopen, and required-worker stop/readiness/recovery passed provisionally. | Selected nonempty upgrade/compatible rollback and monitoring qualification; final full restore/RTO/RPO evidence |
| WP6 | Artifact harness underway. Provisional Core/Agent images built, empty candidate explicitly migrated, real nonroot Core started outside checkout. | All G01–G20 tied to a frozen source and exact final image identifiers |

## Current acceptance audit

The report files were inspected again after commits `8c88de3` and `181e0f2`.
No frozen final candidate is accepted. The current diagnostic Core image
`1eb1bcc88a87` still has source revision `e5e1107` and
`secrethub.source.dirty=true`; committed harness updates do not change that
image's source provenance. The early Core gates used `ab0e6cbc24ae`, not this
diagnostic image. Every gate below requires replay on the frozen final artifacts.

| Gate | Inspected provisional evidence | Remaining acceptance |
| --- | --- | --- |
| G01 | Runtime audit-key gate passed on `ab0e6cbc24ae` | Final image runtime-key and invalid-input checks |
| G02 | Empty-database initialization passed on `ab0e6cbc24ae` | Final image durability/share-release checks |
| G03 | Unavailable/corrupt database rejection passed on `ab0e6cbc24ae` | Final image startup negatives |
| G04 | Repeated/concurrent initialization passed on `ab0e6cbc24ae` | Final image preservation/concurrency checks |
| G05 | Invalid-share negatives passed on `ab0e6cbc24ae` | Final image rejection/process-survival checks |
| G06 | Restart/correct-share ciphertext readback passed on `ab0e6cbc24ae` | Final image identity/old-data checks |
| G07 | Protected administrative access passed on `ab0e6cbc24ae` | Final image protected workflows |
| G08 | Separate ingress-negative invocation passed on `ab0e6cbc24ae` | Final image route/network/spoofing negatives |
| G09 | Origin/CSRF negatives passed on `ab0e6cbc24ae` | Final image browser/connected-transport negatives |
| G10 | Sealed lifecycle passed on `ab0e6cbc24ae` | Final image liveness, unseal reachability and secret/signing refusal |
| G11 | Real enrollment/restart/reconnect passed on `43715c4edce1` | Final Core/Agent lifecycle and damaged-state rejection |
| G12 | Actual consumer lifecycle passed on `1eb1bcc88a87`/`3b95f124b819` | Final pair read/update/denial/revocation/restart readback |
| G13 | Actual outage rejection and separately observed live expiry passed; helper report remains partial | One final-pair report joining cache/outage/reauthorization observations and debug-configuration scope |
| G14 | Real PKI consumer issue/revoke/reconnect report passed | Final pair enforcement measurement with fresh leaves and explicit session semantics |
| G15 | Copy-only corrupt-state checks passed; report remains partial | Final artifacts' old/corrupt-state behavior, with supported recovery or explicit fail-closed hold |
| G16 | Restricted integrity, PKI reopen and actual static-consumer reopen passed in separate provisional drills | Full final-artifact restore inventory, consumers and measured recovery/data-loss window |
| G17 | Actual older-7/newer-9 history refusal and authoritative reconciliation passed provisionally; report remains partial | Final-artifact older-database restriction and safe recovery with retained history |
| G18 | Current-schema migration and incompatible rollback refusal report remains partial | Selected nonempty older-artifact upgrade and reviewed compatible binary rollback/recovery boundary |
| G19 | Scoped VM fault/log redaction passed on `43715c4edce1`; later helpers keep raw inputs private | Final image logs/crash reports and complete exported-artifact scan |
| G20 | Required-worker stop/readiness/restart recovery passed on `1eb1bcc88a87`; report remains partial | Final image replay and selected existing monitoring integration; host alert delivery is unexecuted |

Inspected private report references: `artifact-core-refreshed-1/report.json`,
`artifact-core-refreshed-ingress-1/report.json`,
`artifact-core-refreshed-extra-1/report.json`,
`artifact-core-vm-fault4-run1/report.json`,
`runtime-artifact5-pushfix-run1/runtime-report.json`,
`static-runtime-auth-artifact-run1/static-report.json`,
`static-cache-expiry-runtime-auth-observation2/report.json`,
`pki-runtime-artifact5-pushfix-run1/report.json`,
`corruption-artifact7-run3/report.json`,
`history-artifact7-versus9-run1/report.json`,
`restore10/static-service-readback10-run2/static-restore-report.json`, and
`monitoring11/worker-health-report11.json`. Raw private inputs and diagnostics
remain outside the checkout. The final archive must identify the accepted source,
artifact digests, platform, format/schema versions, commands and measurements;
this audit table is not that archive or a release acceptance claim.

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

The matched diagnostic Core build completed successfully as image
`sha256:1eb1bcc88a874b3eb2cdd00ea42d58fcfe3d0f142f26a4a30418acadc6e2df70`.
Its source label is `e5e1107dd7530f65e5b72b0f2ff78c6e4579bf64` with
`secrethub.source.dirty=true`; the authorization implementation is uncommitted.
Warnings-as-errors compilation, asset digest generation and release assembly
passed. Runtime consumer qualification on this image remains unexecuted; build
success does not clear G12/G13 or the pending legacy-query repair approval.

The diagnostic Core swap passed with the original container retained stopped.
The replacement started sealed, accepted protected manual unseal and observed
a fresh enrolled Agent heartbeat. Agent certificate/key/CA/floor digests,
enrollment IDs and its Core certificate association stayed identical. The
isolated database was preserved. The authorization report had zero findings;
the typed-runtime gate was verified without activating minimum auth floor 2.

A new disposable application was assigned to the enrolled Agent database UUID,
issued a canonical proof certificate and independently granted exact-path Agent
and application policies. The real UID1002 consumer image `ae6125bf3306` then
authenticated through the actual Agent UDS, atomically applied the private file
and passed exact fixture readback with version 1 and revision 2. Fixture
provisioning initially used an invalid query expression and then passed a map
to the string-only virtual `value` attribute; the fixture now uses the documented
`secret_data` map API. These fixture errors were corrected without modifying
application source, and the disposable diagnostic fixtures remain retained.
G12/G13 are not yet accepted: updates, denials, revocation, restart, outage and
directly observed cache expiry remain required. Default production/info logging
and disabled distribution do not expose live cache expiry; separate release
`eval` cache checks would not supply that evidence.

The same exact Agent image now also has an isolated debug-logging clone, using
the standard `RELEASE_SYS_CONFIG` template override. The original info-level
container is retained stopped. Parsed configuration differs only in Logger
level; provider, formatter and disabled distribution are identical. The template
comment marker changes from false to true so the release shell copies configuration
into its writable private runtime directory. Identity/enrollment and a fresh
heartbeat were verified after the clone started; this does not retroactively
qualify the original info-level container.

The clone started with zero cache population events. One actual auth-v2 consumer
read seeded one entry with TTL 300 seconds. Its expiry timestamp was followed
by exactly one `count=1` expired-entry cleanup 330.649 seconds after population,
with no additional reads, invalidations, refreshes, cache/process restarts or
post-seed warning/error events. Captured logs had no fixture plaintext/private-key
markers; raw logs remain private and the report exports only metadata. The first
observer incorrectly included a legitimate pre-seed startup clear and failed;
the second resumed the same live seed without restarting or reseeding anything.
This is direct live-cache expiry evidence for the debug clone, not a claim about
a separate release-eval cache. G13 still needs the real outage/reauthorization
checks and final immutable-candidate qualification.

The real static-consumer acceptance run passed all selected G12 scenarios in
155.340 seconds on Core `1eb1bcc88a87`, Agent `3b95f124b819` and consumer
`ae6125bf3306`. Auth-v2 initial readback returned version 1/revision 2; the
supported fixture update returned version 2/revision 3. A denied path and actual
application-policy revocation after successful warm-up both rejected delivery
and preserved the private file's bytes, inode and mode. The sole fixture
application policy was recreated with its original attributes and binding;
the separate Agent policy was unchanged. The replacement policy ID is retained
in the report rather than treating the old ID as still active.

Agent restart preserved certificate/key/CA/floor identity and enrollment, with
a fresh heartbeat and correct consumer readback. Core restart was observed
sealed until protected manual unseal, followed by fresh Agent reconnection and
version-2 readback. Pausing only the owned Core caused a warmed consumer read
to reject; its previously applied configuration remained unchanged. Core was
unpaused after 7.731 seconds and correct readback resumed without identity loss.
Both fixture services are running, unpaused and healthy after the drill.

The static helper owns every evaluation/consumer container and verifies VM
absence before policy restoration or continuation. Review caught the earlier
unowned `docker exec` timeout and copied Core node-ID collision; both were
corrected and independently re-reviewed before this real run. Twelve owned Core
evaluations used distinct temporary node IDs and preserved serving-node
incarnation/registration/capabilities within each restart phase. Their incidental
cluster rows remain retained; no row deletion/backfill occurred. Cleanup was
confirmed. This source/helper review does not repair or authorize the pending
legacy policy cast. The static report leaves G13 partial because its own code
does not run the separately verified debug-clone TTL observer; the independent
expiry report remains scoped evidence. Full restore with this static consumer,
upgrade/monitoring qualification and final frozen-artifact G01–G20 remain open.

Snapshot 10 adds the accepted version-2/revision-3 static consumer to a consistent
database/Agent/consumer backup. Original Core and Agent were stopped for the
snapshot and recovered afterward with the same certificate, key, CA, auth floor,
enrollment and actual consumer readback. Database backup, separate identity
archives and ownership-preserving Core input copies completed in 70.064 seconds;
shares and audit inputs remain separately held. This does not establish full RTO.

The snapshot was imported into a new empty database in the isolated recovery
cluster without overwriting earlier restores. Restricted exact-image evaluation
passed static decryption, historical audit verification and original PKI key use;
Vault/PKI inventory and historical audit rows remained unchanged, and temporary
VM absence was confirmed. The copied database URL retained its original numeric
ownership and mode. The first fixture setup rejected an empty environment entry;
continuation corrected only that private environment and reused the already
restored database, without another import or reset. This current-generation
integrity check does not claim the older-database G17 scenario.

The new read-only static restore helper and its instructions passed independent
source review, including deny-path and cleanup/report checks. Serving restore
execution remains pending. G16 stays partial, G17 retains its separately scoped
history evidence, and the recovery hold and final-candidate gates remain open.

The first controlled static service reopen reached restart-sealed status and
protected manual unseal but failed before restore-helper construction: its
baseline validator incorrectly required a bare UUID for the canonical
`agent-<UUID>` runtime identity. No identity change or database replacement was
used to bypass it. The original services recovered with unchanged identity and
version-2/revision-3 readback; all owned serving/evaluator/consumer containers
were confirmed absent. The failed 73.326-second report and copied restore state
are retained. A scoped helper correction/review is pending; this failed attempt
does not clear G16.

The canonical runtime-ID correction passed 30 focused worker checks and ten
independent reviewer cases; database UUID validation and exact baseline identity
comparisons were preserved. The second service reopen reused the same restored
database and copied identity, with new report paths. It passed in 110.229 seconds
including original-fixture recovery; the selected read-only helper portion took
70.129 seconds. Restart-sealed status, protected manual unseal, post-start Agent
heartbeat, original Agent certificate/key/CA/floor/enrollment and Core certificate
association, typed authorization gate/hash/generation and real UID1002 consumer
version-2/revision-3 readback all passed. Eight unique owned Core evaluations
preserved serving-node registration/incarnation/capabilities; all temporary VMs
and both serving restore containers were confirmed absent. Original services
remain healthy with identity and actual consumer readback preserved. The imported
database, copied identity/trust and unsuccessful first report remain retained.
Import (39.808 seconds), restricted integrity (17.175 seconds) and controlled
reopen durations are separately scoped observations, not an accepted end-to-end
RTO/RPO. G16 and full-plan acceptance remain partial and recovery held; no result
is transferred to a future frozen candidate.

The copied-database required-worker helper passed nine worker offline checks,
embedded Elixir/source API review and 19 independent reviewer cases with no
repair rounds. A separate new empty database was restored from snapshot 10 for
this test; runtime input ownership/modes were preserved and independent shares
were supplied separately. No original service was stopped or modified.

The exact provisional Core worker lifecycle passed in 11.422 seconds: initially
healthy required CRL refresher and unsealed readiness, supervised child stop,
`crl_worker_unavailable` with background/readiness false and overall degraded,
then explicit child restart with healthy readiness recovered. Seal state stayed
unsealed, and liveness/internal management health stayed available. The actual
persisted authority/current CRL was present, avoiding an absent-authority health
shortcut. Unique node identity and owned VM absence were confirmed; diagnostics
excluded held shares. Normal CRL/audit/cluster mutations occurred only in the
retained copy. Original Core/Agent are still healthy. G20/monitoring remain
partial because this network-free drill does not test protected HTTP/Caddy or
existing host alert routing/delivery. Final immutable-artifact replay, selected
upgrade/rollback and the pending legacy-query repair authorization remain open.

On October 4 the operator approved the prepared additional focused SQL repair
round. The policy overlap query now casts its bindings to `varchar[]`, matching
the read-only verified `character varying(255)[]` column. Only necessary wrapping
of that query was added for the formatter. Core authorization checks passed
25 tests with zero failures; channel checks passed 16 tests with zero failures.
No assertions were changed, unknown database reset performed or serving fixture
modified. The approved extra round completed successfully; its former approval
block no longer applies.

Before source freeze, read-only review found two separate authorization bugs:
the literal pattern segment `___DOUBLE_STAR___` became a wildcard, and the
dual-accept legacy channel branch checked the minimum authentication floor
outside its authorization transaction. The current single-operator profile
disables that legacy branch, but compatibility cutover still requires atomic
floor enforcement. The exact-pattern regression reproduced the unintended grant
and then passed five focused tests after wildcard tokens and literals were
separated; independent source review found no blocker in that correction. The
floor-race regression reproduced release after activation with an independently
blocked PostgreSQL connection. The legacy read now holds the shared epoch lock
through floor recheck, identity authorization, read and transaction commit;
independent source review found no blocker. A first channel run passed the new
regression but timed out at an existing typed-read test's unchanged 100 ms
assertion. That test passed in isolation, then the complete channel suite passed
17 tests with zero failures using the original failing seed 458707. The initial
timeout's cause remains unconfirmed; no assertion or timeout was changed.

Final focused Core authorization checks passed 28 tests with zero failures,
and existing policy checks passed 30 tests with zero failures. Formatter checks
on all 31 owned Elixir files, compilation with warnings as errors, and scoped
diff checks passed. These results qualify source changes, not a new artifact or
the complete launch plan. Final candidate construction remains outstanding.

Fixture freshness checks at October 4 04:12 UTC found the disposable management
CA, server and operator certificates expired on October 3. Runtime Core, runtime
CA, Agent and static-consumer certificates remain valid. Management HTTPS was
not tested with verification disabled. Separate disposable management test
certificates were prepared separately using the same fixture CA public key and
copied existing Caddy mechanism. Chain, SAN, EKU and negative certificate checks,
plus Caddy adaptation/validation, passed. No service was started. The renewed
fixture uses separate ports 17667/17669 and preserves every original input digest;
original fixture identities, backups and all production configuration remain
preserved. Final management HTTP acceptance remains unexecuted.
