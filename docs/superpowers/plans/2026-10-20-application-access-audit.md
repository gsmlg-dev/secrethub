# Application Access Audit Implementation Plan

> For agentic workers: use the executing-plans and subagent-driven-development skills. The user's supplied access audit plan is the scope and acceptance authority.

**Goal:** Answer application access questions from correlated durable Core and Agent evidence.

**Architecture:** Strict shared v1 envelope; checked Core append plus transactional request projections; synced bounded Agent WAL and authenticated idempotent batch RPC; database queries drive the management UI. See ADR 0001 for identities, limits and failure semantics.

**Tech stack:** Elixir/OTP, Ecto/PostgreSQL, existing Phoenix runtime channel/LiveView, Telemetry, framed OTP file WAL. No new native dependency.

## Phase 0: inventory and contract

- [x] Reconcile pinned source and read enabled paths; preserve external management and machine identity boundaries.
- [x] Document architecture, request/attempt/event semantics, provenance, invalid traffic, limits and exclusions in ADR 0001.
- [x] Record baseline constraints and scoped existing-regression results on isolated PostgreSQL; reconstruct exact-HEAD static comparisons. A pristine pre-edit runtime baseline was not captured; see the qualification report.
- [x] Implement and test `apps/secrethub_shared/lib/secrethub_shared/access_audit/event.ex`: strict validation and canonical representation, phase/source rules, bounded vocabulary and no arbitrary metadata.

## Phase 1: Core storage and ingestion

- [x] Add additive migration and Core AccessAudit event/request/producer schemas and context. Store signed observations and update deterministic projections transactionally.
- [x] Check authenticated identity, validate atomic bounded batches, deduplicate exact replay, reject collisions and accept reordered sequence arrivals.
- [x] Provide bounded typed queries for app summaries, secrets, requests/timelines, reasons/time buckets and producer health; keyset pagination and finite windows.
- [x] Add negotiated runtime upload RPC; recheck revocation on every upload.
- [x] Instrument typed authorization (including rejected principals), direct token latest/version reads, and enabled legacy reads with checked Core facts before release.
- [x] Verify rollback/outage, duplicates/lost ack, sequence gaps, invalid provenance/input, revoked/unauthenticated RPC and deterministic request counts.

## Phase 2: Agent journal and reporting

- [x] Implement bounded checksummed synced WAL, persistent producer sequence, reservation, acknowledgement, quarantine and atomic synced compaction.
- [x] Integrate journal before runtime/UDS in supervision, admission before authorization, release intent before send, and actual transport result afterward. Propagate generated request/attempt IDs to Core.
- [x] Add one-batch reporter, negotiated compatibility, capped backoff/jitter, explicit acknowledgement and permanent-event quarantine.
- [x] Verify actual processes/supervisor restart at append/send/commit/ack boundaries, unavailable recording, bounded storage, disk failure and corruption. Use disposable canaries. Verify first-start parent-directory sync and retry after real sync failure.

## Phase 3: operational telemetry and persisted UI

- [x] Publish bounded event/metric catalog, monitor handler failure without moving required writes into handlers.
- [x] Replace AuditLogLive sample rows with real query APIs, preserving management protection. Add app overview/detail, request timeline, filters/URL pagination and pipeline health.
- [x] Test known counts, filter/time boundaries, late events, provenance/contradictions, empty/error/stale state, malformed cursors and metrics handler failure.

## Phase 4: rollout and qualification

- [x] Document Core-first negotiation, mixed-version behavior, rollback, configurable retention disabled by default, WAL/quarantine recovery, checkpoints and partial historical coverage.
- [x] Qualify migration up/down, bounded storage, late/reordered reporting, representative query plans and complete 100-request scenario (60 success/20 denial/10 error/10 incomplete).
- [x] Run scoped formatting, compilation, static checks and final focused tests; record PASS/FAIL/NOT RUN accurately. Review spec compliance, then code quality. Final suites total 249 tests, 0 failures, 2 legacy skips; raw static checks retain documented baseline debt with no new underlying finding.
- [x] Commit focused changes locally. Publication, deployment and credential changes need separate authorization.

## Reproducible verification environment

Worktree: `.trees/access-audit`, branch `codex/access-audit`. Dependencies reuse the pinned checkout; build output is copied and isolated. PostgreSQL is a dedicated trust-authenticated local Unix-socket fixture at `/tmp/secrethub-access-audit-pg`, port 55486, with no TCP listener. Commands use `MIX_ENV=test MIX_TEST_PARTITION=audit PGHOST=/tmp/secrethub-access-audit-pg PGPORT=55486 PGUSER=secrethub`. Only fixture databases are migrated or dropped; existing services and credentials are untouched.

Scoped tests live in shared `access_audit_event_test`, Core `access_audit_test` and existing runtime/audit integrity tests, Agent `access_audit_*` and UDS/connection/application tests, Web access-audit channel/controller/LiveView tests. Test new behavior red before green. Keep baseline failures separate, and stop if an out-of-scope test is inadvertently run and fails.

Final scenario mapping, exact scoped commands, review repairs, static baseline comparisons, query plan and qualification limits are recorded in [the qualification report](../../operations/access-audit-qualification-2026-10-20.md).

## Agent skills

- [Elixir](https://github.com/gsmlg-dev/secrethub/blob/main/AGENTS.md)
- [Executing plans](/home/gao/.agents/skills/executing-plans/SKILL.md)
- [Subagent development](/home/gao/.agents/skills/subagent-driven-development/SKILL.md)
- [Verification](/home/gao/.agents/skills/verification-before-completion/SKILL.md)
