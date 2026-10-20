# Application access audit

This feature covers static secret reads through the Agent UDS, typed trusted-runtime reads, enabled legacy trusted-runtime reads, and authenticated token HTTP latest/historical reads. Dynamic engines, SSH operations, Human vault operations and administrative mutations retain their existing audit facilities. They do not contribute to these application request totals. The management page remains behind the existing Caddy client-certificate boundary.

## What the numbers mean

One generated request ID represents one accepted inbound operation. Phase observations, authorization calls, internal attempts and retransmissions are separate facts. Request totals come from durable request projections. An independently authorized Core read is not proof that an application received data. A successful Agent/HTTP transport write means `response_sent`, never consumption. An interrupted operation without a terminal observation remains incomplete.

Invalid traffic and failed local authentication remain unverified and separate from verified application totals. A claimed application ID never establishes attribution. Agent certificate attribution is Agent-attested; Core certificate attribution is independently resolved by Core. A compromised Agent can fabricate its own observations, but cannot replace or upload a Core authorization decision. Contradictory identities, resources or outcomes remain visible.

Use `/admin/audit` to select an application and interval, inspect requested secrets and reasons, page recent requests, and open a request timeline. Filters and pagination remain in the URL. Legacy rows are explicitly partial coverage: old records do not establish exact logical request counts or invented application identities. An empty query result describes only retained, received evidence. Always check reporting health before interpreting it as inactivity.

Queries accept windows of at most 31 days and keyset pages of 1–100 requests (default 50). Application, secret and reason lists are bounded to 100 groups. Timelines contain at most 1000 observations per request; ingestion rejects further observations atomically. Health lists are bounded to 100 entries and indicate limited coverage. The page refreshes every 15 seconds. A failed query clears its totals and displays an error instead of showing zero activity.

To reconstruct a missing or damaged request summary in an authorized Core release console, call `SecretHub.Core.AccessAudit.rebuild_request(namespace, request_id)`, using `agent:<public_agent_id>` or `core` as the namespace. It validates the retained observations against independently queried signed ledger entries and rebuilds one bounded projection under the ingestion lock, without adding events or changing producer counts. Repeat calls produce the same totals. Absent source history returns `:not_found`; missing raw rows with surviving signed evidence return `:invalid_source`; expired raw detail returns `:raw_expired` and cannot be reconstructed from checkpoints. Invalid source evidence is refused rather than used to replace the summary.

## Durability and reporting

The Agent journal lives at `<state_dir>/access-audit/observations.wal`, using the existing configured persistent Agent state directory. The directory is mode 0700 and the WAL 0600. Persist that directory across container replacement. Startup synchronizes the parent entry of each newly created directory before opening the journal; a required directory-sync failure refuses startup. Each framed record contains a length, checksum and validated envelope; successful admission and append require `fsync`. Compaction syncs the replacement, renames it, then syncs the directory. This relies on the host filesystem and storage honoring those operations.

Admission reserves room for the attempt, release intent and terminal observation. Defaults are 16 MiB WAL, 2000 events including reservations/quarantine, 256 concurrent admissions and 100 quarantined events. Override these positive limits through `config :secrethub_agent, :access_audit_journal, max_bytes: ..., max_events: ..., max_admissions: ..., max_quarantine: ...` after sizing persistent storage. No unacknowledged evidence is evicted. Exhaustion or uncertain writes refuse new secret delivery with `AUDIT_UNAVAILABLE`. A full disk cannot record an unlimited stream of refused operations; operational failure signals and stale health expose this counting limitation.

The journal precedes its consumers in the real Agent `rest_for_one` supervisor. A consumer crash releases its unused reservation while retaining accepted evidence. A crash after plaintext transmission and before the terminal append remains ambiguous; recovery uploads evidence and never resends plaintext.

The reporter sends one bounded batch at a time, with at most 100 events and 131072 encoded bytes. The event limit is 4096 bytes. Delivery is at least once. Core validates and commits the whole batch or rejects it; acknowledgements name committed event IDs. Lost acknowledgements replay the original IDs and sequences. Same content deduplicates; conflicting content or sequence reuse is rejected. Out-of-order valid events are accepted and reconcile existing requests.

Health includes producer sequence gaps, last producer observation, Core receipt time, pending events/bytes, quarantined events and the Agent's locally measured pending age. Core never derives latency by subtracting Agent and Core clocks. Reports older than five minutes are stale. Enrolled Agents without a report and disconnected Agents remain visible. A healthy report from one Agent does not establish coverage for another.

## Rollout and rollback

1. Back up the database and Agent state using existing operator procedures. Verify the backup destination before calling it complete.
2. Apply the additive Core migrations and install Core with `access_audit_v1` ingestion before upgrading Agents. These instructions are an operator runbook; implementation qualification does not migrate or restart existing services.
3. Upgrade one Agent with persistent journal storage, confirm capability negotiation, perform a disposable secret read, and inspect the correlated timeline and cleared pending backlog. Check metrics and disk capacity before upgrading the remaining Agents.
4. Old Agents can still use their existing authorized protocol, but provide partial application-request evidence and no new journal health. A new Agent talking to an old Core retains pending evidence, reports unsupported compatibility locally and eventually refuses admission if the journal fills. Never enable offline cache delivery to work around this.
5. To roll back binaries, stop the new reporting producer before reverting Core. Preserve the additive schema, journal and checkpoints. Do not drop populated audit tables as a binary rollback. Schema down/up qualification uses disposable databases only; removing live tables destroys retained evidence and is not a rollback runbook.

The v1 envelope and capability are negotiated independently of application-authentication versions. Unknown schema or permanent event errors enter bounded quarantine. Database outages return a transient failure without committed acknowledgements. Certificate/Agent revocation is rechecked on every upload and secret authorization.

## Quarantine and damaged storage

In an authorized Agent release console, inspect `SecretHub.Agent.AccessAudit.Journal.health()` and `SecretHub.Agent.AccessAudit.Journal.quarantined()`. The latter returns bounded identifiers and reasons. Repair compatibility or the producer defect first. Then explicitly call `SecretHub.Agent.AccessAudit.Journal.replay_quarantined([event_id, ...])`; the synced replay preserves every original envelope, event ID and sequence. Replaying an unresolved collision returns it to quarantine. `outside_retention` requires an operator decision about evidence preservation, not repeated automatic replay.

Never delete or truncate the WAL to clear an alert. Preserve the original WAL and any `.compact` file before recovery. Check storage health, ownership, available space and filesystem durability. A partial frame, checksum failure or interrupted compaction fails startup closed. Restore only a verified consistent copy through the existing operator backup procedure, retaining the damaged evidence and documenting the uncertain interval. There is no automatic evidence repair or claim that an unavailable archive is complete.

## Retention

Raw detail and request aggregate targets are independently configurable under `:secrethub_core, :access_audit_retention`. Defaults are `enabled: false, raw_days: 30, aggregate_days: 365`; both horizons must be finite positive days and raw retention cannot exceed aggregate retention. Automatic deletion has no scheduler. Deliberate opt-in and explicit `SecretHub.Core.AccessAudit.prune/1` execute bounded manual pruning. Inspect `retention_policy/0` before enabling it.

Raw expiry uses Core receipt activity, so producer clock skew cannot cause immediate expiry. Raw expiry freezes the request projection: its aggregate remains until aggregate expiry, while its timeline is explicitly expired. Minimal event/sequence digests retain replay and conflict protection. New observations for a frozen request are rejected as `outside_retention` and preserved in Agent quarantine instead of reconstructing an incorrect total from partial history. Exact replay remains idempotent. Late reports for requests that have not been frozen reconcile normally.

Before deleting an access observation, pruning records signed minimal chain checkpoints and a checked retention marker. Verification joins retained ledger entries and checkpoints; changing checkpoint evidence fails verification. Checkpoints, request tombstones and event identity digests remain preserved after aggregate expiry. Non-access audit events are not pruned by this operation. Historical detail that has expired cannot be recovered from checkpoints. Cloud archive upload is not implemented by this feature and is never a prerequisite silently assumed to have succeeded.

## Telemetry catalog

All names begin `[:secrethub, :access_audit]`. Telemetry is operational observation; explicit checked journal/database writes enforce durability. Handlers execute synchronously and must stay lightweight. Failing exporters can detach; the handler-failure monitor exposes that failure without becoming the audit writer.

| Suffix | Measurement and meaning |
| --- | --- |
| `[:request, :start]` | `count`: processing starts at an instrumented boundary |
| `[:request, :stop]` | `count`, `duration_us`: observed terminal processing; incomplete operations may never stop |
| `[:request, :exception]` | `count`: bounded operational failure |
| `[:authorization, :result]` | `count`, `duration_us`: Core authorization decisions, including cache validation |
| `[:response, :observation]` | `count`: actual transport result |
| `[:journal, :append_failure]` | `count`: required recording could not be guaranteed |
| `[:upload, :result]` | `count`, `duration_us`: one reporting operation |
| `[:ingestion, :result]` | `count`, `duplicates`: committed or rejected batch and exact replay |
| `[:backlog]` | pending events/bytes, quarantine count, oldest pending age in milliseconds |
| `[:handler, :failure]` | `count`: a Telemetry handler detached after failing |

Labels are limited to operation, outcome, bounded reason code, cache status and source. Request IDs, application IDs, paths and certificate fingerprints are not metric labels. Do not add Agent and Core boundary counters together to derive logical requests, or add starts and stops. App totals belong in the persisted query API. No event stores plaintext, tokens, key material, raw request/response bodies, exception text or secret-derived hashes. Application IDs and paths are still sensitive metadata and require the protected management boundary.
