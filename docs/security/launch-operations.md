# Single-operator launch and operations

This is the authoritative operations runbook for the Linux amd64 OCI launch
profile: one Core, PostgreSQL 16, existing Caddy management mTLS, Client Auth PKI
and one static-secret consumer. Production cutover is operator-owned. Follow
this runbook only after the exact-candidate G01–G20 report passes; provisional
images and source tests are insufficient. Current acceptance is incomplete.
See the [combined candidate report](prelaunch/candidate11/acceptance-report.json):
isolated selected checks passed; backup destination/cadence still require
qualification. Console logging is the selected application boundary; Docker
forwards it to the existing remote logging system. Production cutover remains
operator-owned.

## Required inventory

Record the immutable Core/Agent image IDs/digests, source SHA, platform, release
versions and exact migration set. Preserve deployment inputs in the existing
secure configuration system. See [runtime inputs](runtime-contract.md) and
[ingress boundary](ingress-contract.md). Existing Caddy authentication, its
protected management routing, and the private backend network are prerequisites.
This runbook does not provision or replace that administrative trust authority.

Hold recovery material independently of SecretHub: unseal shares and generation,
audit signing/verification keys and IDs, listener keys/trust, Agent host identity
and enrolled identity, Agent/Caddy watermarks, authorization floor, backup
manifest/checksum and independent authoritative revocation evidence. A database
dump does not back up cluster-global roles, runtime secrets or consumer state.
Never archive the dump together with sufficient material to decrypt it.

## Startup and explicit migration

1. Confirm the accepted image/platform and configuration. Keep management private;
   the trusted proxy peer is a network boundary, not a certificate-header check.
   Human endpoints, dynamic engines and rotation remain disabled. Review any
   historical dynamic leases before adopting this profile.
2. Start the existing PostgreSQL service with the intended role/extensions and
   persistent storage. Take a verified backup before a nonempty upgrade. Do not
   run `db-reset`, demo seeds or any schema/data reset.
3. Run the accepted Core image as UID 1001 with the final runtime-only input files
   and persistent mounts. Run `bin/secrethub_core eval
   'SecretHub.Core.Release.migrate()'` as a separate explicit operation before
   service startup; migration is never implicit in boot.
4. Run `bin/secrethub_core eval 'SecretHub.Core.Release.preflight()'` in that
   environment. Its redacted checks must pass, including exact schema, independent
   machine/Agent listeners and readable mTLS files. A partially configured system
   does not pass preflight just because liveness works.
5. Start Core. `/v1/sys/health/live` must return 200. Empty/sealed readiness is
   expected to return 503; it must not cause a restart loop. Reach protected
   `/v1/sys/health/management` through existing Caddy and verify management access.
6. Initialize only a verified empty Vault through protected `/vault/init`, once.
   Securely capture the returned shares after successful durable creation.
   Database errors/loading/corruption are not proof that initialization is needed.
   For an existing Vault, use its existing shares; never create a replacement.
7. Manually unseal through `/vault/unseal`. Verify readiness and old-secret access.
   Wrong, mixed or malformed shares must leave service sealed. Legacy recovery
   follows [key integrity](vault-key-integrity.md); certificate-only ciphertext
   cannot establish the provenance of a historical Vault key.
8. Start Agent as UID 1002 with its persistent identity/bundle directories and
   existing host key readable only by the required service identity. Run its
   preflight first. Do not enable the development host-key fallback, run the whole
   service as root, or loosen all host-key permissions to fix access.
9. Complete the established pending enrollment and operator approval when needed.
   Subsequent starts load the same Core-issued certificate and state. Partial or
   corrupt identity must fail; deleting state to force enrollment is not recovery.
10. Verify the actual local application read/reload and Client Auth allow/reject
    requests. A receipt, written bundle or Agent socket ping is insufficient.

Release distribution is explicitly disabled. `rpc` is unavailable in this
profile. Use supported protected APIs for live state. Release `eval` runs a
separate process; it is not an RPC into an already unsealed service and cannot
inherit that service's in-memory key.

For a protected JSON mutation, fetch `/v1/sys/csrf-token`, keep its secure session
cookie and send `X-CSRF-Token`. This is CSRF state, never a second operator login.
Do not print response bodies from initialization/unseal or export browser traces
containing them. Exact public Origin checks apply to WebSocket and long-poll.

## Normal restart and consumer checks

Record the Vault ID and consumer version before restart. Stop and restart Core
with the same accepted artifact, configuration and persistent data. Expect
restart-sealed status, successful liveness and reachable protected unseal. Supply
correct shares manually, then check readiness, old-secret readback, audit
verification and stable Agent reconnection. Do not use an unseal sidecar or store
sufficient shares in application configuration.

Agent restart must retain identity, CA pinning, authorization floor and trust
high-water marks. Each static delivery requires fresh Core authorization (an
exact-revision `not_modified` response may confirm a cached value). An offline
Agent cannot authorize a new secret delivery. Application-held values already
received cannot be remotely erased; the application's own expiry/reload and
credential revocation govern those values.

For Client Auth PKI, record Core publication generation/CRL number, Agent applied
state and the independent Caddy watermark. Confirm valid authentication and
unrelated-certificate rejection using real requests. Test a revoked certificate
with a new handshake, session resumption and an already-open connection. Use the
measured enforcement interval in the accepted report. Never promise that a CRL
refresh automatically terminates an existing TLS session.

Candidate 11's [final PKI fixture](prelaunch/candidate11/g14-pki-report.json) measured revoked-client rejection upper bounds
of 13.186 seconds for a new handshake and 13.197 seconds for a request on an
already-open connection, within its explicit 30-second bound. The exact consumer
policy disables session resumption; connection termination was not tested. These
measurements qualify that isolated configuration, not the operator's deployment.

## Required monitoring and responses

SecretHub logs to the console. Docker forwards stdout/stderr to the existing
remote logging system; forwarding, alert routing and delivery are managed outside
this repository. The operator confirmed this boundary on 2026-10-05. Use the
actionable health signals below with that existing system, keeping shares,
plaintext values and private keys out of console output.

| Signal | Observe | Operator action |
| --- | --- | --- |
| Core unavailable | Private process liveness and supervisor/container exit | Check runtime-input/preflight failure and service logs; retain original data |
| Awaiting manual unseal | Readiness 503, sealed state, management 200 | Manual unseal after an expected restart; investigate unexpected loss of verified key |
| Database unavailable/schema mismatch | Bounded health/preflight result | Restore connectivity or compatible schema; never initialize based on this error |
| Backup failed/stale | Script nonzero exit, `latest-backup.json` UTC finish time | Restore destination/tool access; require a recent verified backup before upgrade |
| Agent disconnected | Core Agent monitoring and local runtime connection state | Restore transport/identity validity; do not remove persisted identity |
| Bundle lag/application failed | Publication versus applied receipts, local manifest/watermarks and actual consumer requests | Investigate failed validation/application; retain monotonic history |
| Certificate/CRL expiry approaching | Persisted certificate validity and current CRL `next_update` | Renew/refresh through established paths before expiry; verify publication/convergence |
| Required CRL worker failed/stopped | `/v1/sys/health/ready` returns 503 with `crl_worker_unavailable`; general `/health` stays 200 with degraded body | Repair the required worker; alert on readiness/body, and keep liveness/management available |
| Audit append/verification failed | Bounded audit failure logs and protected audit verification | Restrict sensitive operations and preserve evidence; check runtime keys/storage |

The external logging/alert configuration owns alert thresholds: backup
staleness from the chosen cadence; certificate/CRL warning before expiry; bundle
lag from the measured configured enforcement bound. No RPO/RTO or revocation bound
is accepted until the candidate report measures it. An Agent ping establishes
only local responsiveness, not consumer convergence.

## Upgrade and compatible rollback

Take and verify a backup and independent recovery inventory. Stop affected writes,
record the existing Vault/key/share/schema/audit formats and monotonic state, run
explicit migrations, and repeat preflight and enabled consumer checks. Release
only the artifact that was accepted; rebuilding changes the artifact identity.

Rollback is allowed only across a reviewed compatible schema/key/share/signature
boundary. The authenticated Vault envelope and version-2 audit rows block their
schema downgrade. New authorization floor/revision state must also be preserved;
do not run older software that ignores an activated floor. When compatibility is
unproven, stop service and use a reviewed recovery path rather than an older
binary. Restoring an older database loses later data and security decisions.

Candidate 11's [archived G18 rehearsal](prelaunch/candidate11/g18-report.json)
used frozen source `c226bf43ba3ed1292db08bcc4506b5435616c22b` and final Core
`7dc01a18b500`, whose revision/source/MIT labels match that source and whose
`secrethub.source.dirty` label is false. On one new copied nonempty database,
older Core `1eb1bcc88a87` read the original static value, final Core ran an
explicit migration and read it, then the same older binary read the same
post-final database. All 48 migration versions were already installed: zero
pending migrations made the explicit migration a no-op. This proves a
same-schema binary transition, not execution of a pending schema upgrade.

The supported rollback boundary is isolated recovery at authentication floor 1,
with envelope version 1, share version 4 and audit signature version 2 preserved.
The old artifact has dirty source provenance and a known legacy-read cutover
race; it is unsafe for serving rollback. Each recovery eval ran as UID 1001,
stopped the CRL refresher before manual unseal and exposed no serving application
or listener. Static readback, the complete audit chain and the original PKI key
verified; all security/data hashes and the original audit prefix stayed intact.
Three expected unseal audit rows were retained, with only cluster bookkeeping
changed. No restore or down migration occurred between binary phases. Serving
downgrade, floor-2 rollback and pending schema/key conversion remain unsupported
by this evidence; keep the recovery hold until the separate reopen proof passes.

## Backup and full restore

Follow [database recovery](../testing/disaster-recovery-procedures.md) using the
existing destination and pinned PostgreSQL 16 tools. Configure nonsecret artifact,
deployment and independent-inventory references. Recurring backup execution never
changes bucket lifecycle, retention or notification policy.

Restore only into an explicitly selected empty, isolated database with no other
clients. Validate the manifest and dump checksum, required role/extensions,
matching PostgreSQL major and restored inventory. The restore script never drops
schemas, kills other clients or overwrites existing data. `database_restored` is
not full recovery acceptance.

Hold the restored Core isolated with no management, machine or Agent listener
and no reachable consumer. Start only the Core application in a bounded recovery
process; immediately terminate its supervised
`SecretHub.Core.Workers.ClientAuthCRLRefresher` child before manual unseal. Normal
release eval starts that worker and an unseal event triggers reconciliation.
Verify the child remains stopped. Do not issue certificates, refresh CRLs or
publish trust bundles while inspecting the restored snapshot. A sealed startup
or isolated network alone does not establish this restriction after unseal.

Read a pre-backup secret, verify historical audit signatures using the preserved
keyring and prove the original PKI private key matches and can sign against its
CA certificate. Compare Vault/key/share identity and the entire ClientAuth
certificate/revocation/generation/CRL inventory before and after these checks.
The [partial artifact helper](../../scripts/prelaunch/RECOVERY.md) automates only
this restricted scenario. It retains database/state and always reports G16/G17
partial and `complete: false`; a readable secret and usable key do not prove
Agent/consumer recovery or permit reopen.

If the database predates a retained Agent/Caddy watermark, activated authorization
floor or certificate revocation, preserve the newer consumer manifests, watermarks,
floor files and independently held certificate/revocation evidence. Keep issuance,
refresh, publication and affected delivery on hold. Record the restored and
retained counters separately; for example generation/CRL 1 versus consumer 3 is
a recovery hold, not an instruction to increment the restored counters.

Reopen only through a reviewed operator recovery procedure with all of this proof:

1. Identify the exact original CA certificate, fingerprint/public key and recovered
   private-key match. Reconcile issued certificate identities/serials and the
   complete authoritative revoked set, including decisions after the snapshot;
   record the source, integrity and completeness of that evidence. Missing or
   conflicting evidence keeps the hold in place.
2. Reconcile publication generations and CRL numbers with retained Agent/Caddy
   history under the same CA. Review the proposed signed bundle's exact contents
   and counters against that history; preserve every authoritative revocation.
   Do not lower watermarks, wipe identity/floor files, create a replacement CA,
   or bump a generation to disguise lost revocations.
3. In an isolated consumer rehearsal retaining the newer watermarks, demonstrate
   refusal of the older bundle. Then demonstrate that the proposed reconciled
   bundle denies a known revoked credential and allows an unrevoked control
   credential against the actual consumer. Check fresh, resumed and already-open
   connections as applicable; receipts and file writes alone are insufficient.
4. Preserve the reviewed reconciliation and consumer evidence before explicitly
   authorizing restoration of the required worker, listeners and publication.
   Run normal serving preflight/readiness and reconnect original Agents/consumers
   without losing identity, authorization floor or trust history. Recheck actual
   static reads and ClientAuth allow/deny behavior before completing G16/G17.

Candidate 11's [copy-only corruption rehearsal](prelaunch/candidate11/g15-corruption-report.json) found that the existing recovery
API rejects a damaged retained same-generation directory with
`corrupted_existing_generation`. It remains quarantined; retrying the same bundle
is insufficient. Preserve the damaged directory and its watermarks. Use a
separately restored, complete known-good backup and the reconciliation proof above
before reopening affected delivery. Do not delete the directory or counters to
force acceptance. Invalid live reloads retain the last valid trust state; damaged
bundle or TLS/HTTP watermark files fail closed on consumer restart.

The [final stale-database rehearsal](prelaunch/candidate11/g17-history-reconciliation-report.json)
qualified recovery using a separately restored complete newer authoritative backup,
while retaining the older database under a hold. Its original CA and complete
revoked set matched the newer retained publication and consumer history. Actual
revoked/control requests passed without changing watermarks. The [full fresh
restore](prelaunch/candidate11/g16-service-restore-report.json) separately qualified
serving that newer backup. Recovery from incomplete evidence stays unsupported.

Never copy old revoked credentials into a running consumer. Without every required
proof, keep the affected service restricted. Measure total elapsed time through
consumer checks separately from database import time. Record the snapshot/data-loss
window and configured backup cadence without claiming an unmeasured objective.

## Incident stop

The manual `seal` operation intentionally does nothing. Its API returns the real
state; it is not an emergency stop. Stop Core through the existing service manager
and restrict machine ingress to prevent further Core-authorized operations.
Stopping Core does not erase values already delivered. Stop/isolate affected
Agents and consumers, revoke or rotate compromised credentials through the
appropriate authoritative system, and account for cached files, open connections
and TLS resumption. Keep revocation evidence and monotonic state for recovery.
Never delete persistent data or recovery inventory as part of stopping service.

## Acceptance evidence

The redacted candidate report must identify source SHA, immutable image IDs,
platform, schema/key/share versions, executed commands and G01–G20 outcomes,
including measured restore/revocation intervals and existing/resumed-session
behavior. Mark every skipped/unexecuted gate explicitly. Keep test credentials,
shares, private keys, plaintext secrets, raw HTTP/RPC output and crash dumps out
of exported evidence. Only after all enabled gates pass may the operator freeze
and cut over that exact candidate.
