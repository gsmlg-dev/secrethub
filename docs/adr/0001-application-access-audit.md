# ADR 0001: Durable application access observations

Date: 2026-10-20. Status: accepted for implementation by the supplied access audit plan.

Amendment, 2026-10-28: the owner approved credential-free local socket reads
sharing Agent policies. This deliberately extends the original certificate-only
UDS assumption below. Local requests retain authenticated Agent association and
null application identity (`unverified` / `none` in the existing event schema);
they are not counted as verified application accesses. See the
[local-read design](../superpowers/specs/2026-10-27-local-agent-secret-reads-design.md).

## Boundary and evidence

This decision implements the static-secret read slice in `secrethub-access-audit-plan.md`, reviewed against `ebd3cab87ad6ba20a5bf61e3e6b62fe98c1a4263`. It preserves certificate identity, policy checks, Core validation of cached revisions, and the existing Caddy management boundary. It does not authorize publication, deployment, database migration on an existing service, credential changes, or changes to unrelated engines.

| Enabled entry point | Identity and cache evidence | Instrumentation owner |
| --- | --- | --- |
| Local UDS `get_secret` | Socket filesystem permission and mTLS-derived Agent; Agent policies and every cached revision reauthorized by Core | Agent admission/attempt/release/send; Core Agent-scoped typed authorization |
| Explicit application UDS `get_secret` | Connection-bound application certificate proof; every cached revision reauthorized by Core | Agent admission/attempt/release/send; Core typed authorization |
| Trusted runtime `secret:read` with app claims | mTLS Agent plus independently resolved application certificate association | Runtime principal resolution and RuntimeAuthorization |
| Trusted runtime legacy `secret:read` | mTLS Agent only; available only below floor 2 outside single_operator | AgentRuntimeChannel legacy read |
| Token HTTP `/v1/secret/data/*path`, latest and historical | Validated Agent/AppRole token and policies; no application identity | SecretApiController read boundary |

The unauthenticated legacy AgentChannel cannot read secrets. Dynamic engines, SSH lookup/signing, management reads/mutations and Human vault operations retain their existing audit facilities and are outside this request projection. Invalid UDS traffic is recorded separately without assigning a claimed application identity.

## Contract

`SecretHub.Shared.AccessAudit.Event` owns schema version 1. Envelopes contain only the following string keys: `schema_version`, `event_id`, `producer_id`, `producer_sequence`, `request_id`, `attempt_id`, `source`, `phase`, `observed_at`, `agent_id`, `application_id`, `identity_status`, `attribution`, `secret_id`, `secret_path`, `operation`, `secret_version`, `outcome`, `reason_code`, `duration_us`, `cache_status`, `policy_id`, `policy_version`, `core_event_id`, `client_correlation_id`. Unknown or duplicate normalized keys are rejected. Events are at most 4096 encoded bytes; batches at most 100 events and 131072 bytes.

Required fields are version, UUID event/producer/request identity, positive persistent sequence, source, phase, ISO8601 observed time, identity status, attribution, operation, outcome, reason and cache status. Attempt UUID is required for attempt, Core decision/access and release/send phases. Optional identity/resource fields are nullable. Correlation supplied by a caller is UUID-only, untrusted, and never used for joins. Invalid paths are omitted rather than copied from requests. No arbitrary metadata, bodies, exception strings, values, tokens, key material or secret-derived hashes enter the envelope.

Sources are `agent` and `core`. Agent phases are `admitted`, `attempt`, `release_intent`, `response_sent`, `response_failed`, `rejected`; Core phases additionally include `core_decision` and `core_access`. Outcomes are `success`, `denied`, `error`, `unknown`. Cache statuses are `none`, `miss`, `hit`, `validated`, `invalidated`. Identity status is `verified` or `unverified`; attribution is `core_certificate`, `agent_certificate`, `token`, or `none`. Agent certificate attribution is Agent-attested, never independently verified Core identity. Uploaded events cannot use Core phases or attribution. Reasons use an explicit bounded vocabulary; unknown implementation errors map to `internal_error` without serializing them.

Core assigns `received_at`, binds Agent identity to the authenticated channel, and signs the entire canonical envelope plus namespace and receive time through the existing checked version-2 Audit chain. Legacy hashes and signatures retain their historical semantics. Raw observations are append-only. One projection per `(namespace, request_id)` is updated in the same transaction; `agent:<authenticated public id>` joins independent Core observations with that Agent's reports; direct HTTP requests use `core`. Producer keys include the authenticated Agent namespace and persisted producer UUID. Core has a fixed reserved producer UUID and allocates its sequence under a database lock.

## Counting and reconciliation

Admission is one accepted secret operation, including locally rejected operations in a separate unverified category. Phase records, attempts and upload retries do not increment request totals. Core first observations can create an incomplete summary before delayed Agent admission arrives. A terminal Agent send observation, or direct Core transport observation, determines the local outcome. A Core grant never implies delivery. Release intent without send observation remains incomplete. Core denial and Agent-reported success are retained independently and flagged as contradictory, rather than replacing the denial. Verified application attribution comes from Core when available; Agent-only attribution is labeled.

Queries return request totals, outcome totals, attempt totals and incomplete totals separately. Unverified requests never contribute to a verified application's totals. Time windows are finite (maximum 31 days); pagination uses `(started_at, id)` keysets, at most 100 rows. Late events reconcile an existing projection. Retained, received observations define the available history; pipeline lag/gaps/staleness accompany the totals.

## Agent persistence and delivery

A serialized Agent-owned WAL lives under the existing persistent state directory. It stores only validated envelopes, persistent producer identity/sequence, acknowledgements and bounded quarantine dispositions. Each framed record has a length and checksum and is synced before success. Replay has finite byte/record limits; corruption or a partial write fails closed pending operator recovery. An interrupted append is never acknowledged. Compaction writes and syncs a replacement, atomically renames it, and syncs the directory before discarding old evidence. Persistent sequence survives empty compaction and acknowledgement.

Admission reserves capacity for all remaining records of that operation. Limits cover WAL bytes, pending events, record bytes and active admissions. Failure to reserve or append refuses delivery with `AUDIT_UNAVAILABLE`; no unacknowledged evidence is evicted. No journal is equivalent to unavailable. The journal outlives UDS/runtime consumers under actual supervision. A crash after transport send but before recording the observation remains ambiguous; it never causes a secret response to be resent.

Reporting uses negotiated `access_audit_v1` capability and authenticated `audit:batch` RPC. One bounded batch is in flight. Transient failure uses capped exponential backoff and jitter. Core uses an atomic all-valid contract: success acknowledges precisely the returned event IDs only after commit; identical producer/event replay is success, different content is conflict. Sequence uniqueness also rejects reuse. Out-of-order valid events are accepted and gaps remain visible. Permanent invalid/unsupported events are preserved in a bounded local quarantine that stops unsafe admission when full. Operator recovery retains original evidence and explicitly replays after correcting compatibility; it does not silently delete records.

## Alternatives

ETS/mailboxes cannot meet restart durability. DETS alone does not provide the required transactional acknowledgement and crash-safe compaction contract. A native SQLite dependency adds packaging and multi-platform qualification cost; the small framed WAL reuses OTP file primitives and existing JSON dependencies. Telemetry remains a separate lightweight operational signal; no handler is responsible for the sole durable write.

## Operations and acceptance

Roll out additive Core storage/ingestion first, then compatible Agents. Old peers retain legacy/partial coverage labels, and unsupported reporting leaves visible pending evidence. Automatic retention deletion defaults off. Configurable retention and explicit prune operations preserve integrity-chain checkpoints; nonexistent historical request identities are not backfilled. Export completeness is bounded to the queried retained evidence; cloud archival is not assumed operational.

Acceptance requires disposable-database transport and supervised-process tests, the deterministic 100-request distribution, duplicate/reordered ingestion, committed-only acknowledgements, outage/capacity/corruption recovery, canary exclusion, real query/UI state tests, migration rollback, and representative EXPLAIN plans. Source checks do not constitute deployment acceptance.
