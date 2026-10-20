# Application access audit qualification

Qualification date: 2026-10-20. Source baseline: `ebd3cab87ad6ba20a5bf61e3e6b62fe98c1a4263`. Qualified implementation revision: `06e3c2d` (documentation committed afterward). Implementation branch: `codex/access-audit`, in `.trees/access-audit`.

## Scope and environment

This report qualifies static-secret application access observations, their local persistence and reporting, Core integrity/projections, and the persisted management page. The contract and entry-point inventory are in [ADR 0001](../adr/0001-application-access-audit.md); rollout and recovery instructions are in [access-audit.md](access-audit.md).

Verification uses Elixir 1.18.5 and Erlang/OTP 28, with eight scheduler threads. PostgreSQL is an isolated fixture at Unix socket `/tmp/secrethub-access-audit-pg`, port 55486, without a TCP listener. Only disposable fixture databases and migrated clones are used. Existing services, databases and credentials are untouched. The original supplied plan and unrelated worktree are preserved.

There was no pristine pre-edit runtime baseline: the earlier `baseline.log` already included concurrent expected-failing regressions. It is not evidence of pre-existing test failures. Static comparisons instead reconstruct the exact baseline source from Git into an isolated temporary directory. The final scoped existing audit/authorization regressions provide compatibility evidence.

## Checks

Local implementation qualification is complete: 249 tests across the four disjoint scoped runs, with 0 failures and 2 existing skips (247 executed tests passed). Raw static-check debt is recorded separately below. This is source/test qualification, not production deployment acceptance.

| Check | Result | Evidence |
| --- | --- | --- |
| Shared envelope and Telemetry | PASS: 8 tests | `qualified-shared.log` |
| Agent journal, reporting, supervision, connection and UDS | PASS: 68 tests, including final directory repair | `qualified-agent.log` |
| Core access, retention/rebuild, authorization, upgrade gates and existing audit integrity | PASS: 135 tests, 2 existing skips | `qualified-core.log` |
| Cursor repair | PASS: Core 14 tests and persisted UI 8 tests | `cursor-review-green.log` |
| Complete final Web scope | PASS: 38 tests | `qualified-web.log` |
| Scoped formatter and diff whitespace | PASS: all 44 changed Elixir source/test/migration/build files | Final explicit source manifest |
| Development and test compilation with warnings as errors | PASS in both environments | `qualified-compile-dev.log`, `qualified-compile-test.log` |
| Scoped strict Credo | FAIL with inherited debt: 39 findings against 47 at baseline; incremental comparison PASS with 0 new | `qualified-credo.json`, `qualified-credo-comparison.json` |
| Scoped production-beam Dialyzer | FAIL with inherited contracts/types: 19 warnings against 15 at baseline; diagnostic comparison has 0 new underlying findings | `qualified-dialyzer.log`, `qualified-dialyzer-comparison.json` |
| Independent spec review | PASS after signed-source, rebuild and runtime-rejection repairs | Read-only source review |
| Independent quality review | PASS after cursor and directory-durability repairs | Read-only re-review; Journal 18-test repair evidence |

Log names refer to `/tmp/secrethub-access-audit-pg/`. This report preserves the durable result summary; temporary logs are local diagnostic evidence, not a verified archive destination.

The two existing skipped tests are `AuditTest`'s `mark_as_archived/1` cases. They explicitly document missing legacy archive schema fields. This feature does not implement cloud archival or claim those tests passed. Expected fault-injection logs include a deliberately failing Telemetry exporter and repeated migration-module definitions in disposable fixture setup.

The raw static commands are not clean. Credo's remaining findings all match the exact baseline after allowing for line movement. Dialyzer analyzes 25 production modules, compared with 13 existing baseline modules. Existing findings include tuple cache keys rejected by inaccurate `String.t()` contracts, unresolved SSH calls, unknown legacy `AuditLog.t()` types and unreachable baseline clauses. The four additional UDS classification-pattern warnings propagate from those same cache contracts. A diagnostic compiles temporary beams with only the unchanged `Cache.put/3` and `Cache.invalidate/1` contracts omitted: baseline and feature then produce the same eleven warnings, with no new finding. No workspace contract, warning suppression or unrelated baseline code was changed. Diagnostic logs are `qualified-dialyzer-cache-diagnostic.log` and `qualified-dialyzer-baseline-cache-diagnostic.log`.

## Required scenario evidence

| Supplied-plan scenario | Scoped evidence |
| --- | --- |
| 1. 100 logical requests: 60 success, 20 denied, 10 error, 10 incomplete | Core `access_audit_test` and Web `access_audit_live_test` assert exact persisted totals after phase events, attempts and replay. Correlated channel test retains separate Core decision/access and Agent send phases. |
| 2. Cache validation still asks Core | RuntimeAuthorization exact-revision tests, UDS cached read/denial/outage tests, and correlated channel scenario. Cache contents cannot authorize a read during Core outage. |
| 3. Distinguishable failures | Core runtime and Web direct-read/rejection tests cover policy, identity suspension/revocation/expiry, missing secret/version, malformed paths/payloads, auth-version floors and sealed/unavailable Core. Public errors retain their existing disclosure policy; bounded audit reasons retain classification. |
| 4. Local rejection without Core authorization | Real UDS certificate/proof/malformed/timeout regressions and correlated channel reporting assert unverified identity and no charged claimed application. |
| 5. Restart before/during upload and after commit before ACK | Production Agent supervisor restarts Journal with pending WAL, reporter process tests preserve one bounded in-flight batch, and the correlated channel test kills Reporter after actual database commit before ACK, then verifies identical replay and duplicate acknowledgement. |
| 6. Crash around plaintext transmission | Real UDS pre-Core-response crash, actual closed-port send failure and post-send/pre-terminal crash preserve incomplete intent or recorded transport failure; recovery never resends plaintext. |
| 7. Storage and permanent-event failure | Database/table outage and checked append rollback tests; kernel `/dev/full` ENOSPC; closed descriptor; real first-start parent-directory permission failure and recovery; traced parent descriptor sync before WAL creation, including failed-start residue; directory-sync failure after compaction; damaged/partial WAL and interrupted compaction; bounded quarantine and explicit replay. |
| 8. Producer/provenance/conflict abuse | Core/channel tests reject unauthenticated/revoked upload, claimed other Agent, uploaded Core phases, event collision and producer-sequence reuse. Failed atomic batches leave no partial ledger/projection. |
| 9. Late/reordered events and honest reporting health | Core projection and UI regressions reconcile late terminal observations, sequence order and gaps; missing/stale/disconnected Agents remain visible alongside a healthy reporter. |
| 10. Secret/token canaries | Envelope rejection, raw signed audit fields, WAL, bounded Telemetry metadata, actual HTTP log capture and CSV export, and rendered persisted UI are checked using disposable canaries. No real user secret is used. |
| 11. Real persisted query/UI | Database-backed overview, app secret/reason detail, keyset filters/URLs, timeline provenance, empty/error/stale/expired states and bounded refresh; no production sample rows. |

The transport evidence combines real Unix sockets, production OTP supervision, Phoenix channel processes and committed PostgreSQL data. The correlated test uses a controlled bridge between UDS authorization and the authenticated channel fixture; it does not establish a deployed TLS/Caddy/browser path. Web controller and LiveView callback tests deliberately keep the excluded ingress configuration outside scope.

## Integrity, migration and retention

Additive migration up/down/up preserves the existing audit chain in a disposable database. Legacy signature/hash verification remains covered by the existing audit suites. New version-2 signed observations bind the entire strict envelope, namespace and Core receive time.

Review regressions first reproduced then repaired retention trusting altered raw columns, rebuild overlooking missing raw evidence, and missing durable Core runtime rejection records. Retention now validates eleven raw identity/canonical/timestamp/ledger fields against signed evidence before checkpointing. Rebuild independently queries signed evidence and refuses both partial and entirely missing raw rows without replacing a complete projection.

Retention remains explicitly disabled by default (`raw_days: 30`, `aggregate_days: 365`), with no scheduler. Manual bounded pruning preserves signed checkpoints and permanent replay tombstones. Frozen requests reject new late observations as `outside_retention`, while exact replay still deduplicates; raw detail expiry is visible separately from query errors. Tests cover rollback, checkpoint tampering, aggregate expiry and protected sequence identities.

## Query plan

`access_audit_test` inserts 5,004 representative request projections, analyzes the table, and explains the actual application/time query without forcing a planner option. `core-query-explain.txt` shows a backward index scan on `access_audit_requests_application_id_started_at_id_index`, returning four matching rows. The final sample reported 1.043 ms planning and 0.064 ms execution. Timing is an observation of this disposable fixture, not a production capacity benchmark.

## Reproduction

Run from the feature worktree with the isolated fixture available:

```sh
export MIX_ENV=test MIX_TEST_PARTITION=audit
export PGHOST=/tmp/secrethub-access-audit-pg PGPORT=55486 PGUSER=secrethub
export ERL_FLAGS='+S 8:8'

mix test apps/secrethub_shared/test/secrethub_shared/access_audit_event_test.exs apps/secrethub_shared/test/secrethub_shared/access_audit_telemetry_test.exs

mix test apps/secrethub_agent/test/secrethub_agent/access_audit_journal_test.exs apps/secrethub_agent/test/secrethub_agent/access_audit_reporter_test.exs apps/secrethub_agent/test/secrethub_agent/application_test.exs apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs apps/secrethub_agent/test/secrethub_agent/runtime_config_integration_test.exs apps/secrethub_agent/test/secrethub_agent/uds_server_test.exs

mix test apps/secrethub_core/test/secrethub_core/access_audit_test.exs apps/secrethub_core/test/secrethub_core/access_audit_rebuild_test.exs apps/secrethub_core/test/secrethub_core/access_audit_retention_test.exs apps/secrethub_core/test/secrethub_core/runtime_authorization_test.exs apps/secrethub_core/test/secrethub_core/upgrade_gates_test.exs apps/secrethub_core/test/secrethub_core/audit_test.exs apps/secrethub_core/test/secrethub_core/audit_concurrent_test.exs apps/secrethub_core/test/secrethub_core/audit_hash_version_test.exs apps/secrethub_core/test/secrethub_core/audit_hash_version_migration_test.exs apps/secrethub_core/test/secrethub_core/audit_signing_keys_test.exs apps/secrethub_core/test/secrethub_core/audit_runtime_keys_test.exs

mix test apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs apps/secrethub_web/test/secrethub_web/runtime_access_rejection_audit_test.exs apps/secrethub_web/test/secrethub_web/access_read_audit_test.exs apps/secrethub_web/test/secrethub_web/live/access_audit_live_test.exs
```

Run each app-sized command separately; fixture setup and global application state are serialized. Format and Credo must receive the explicit changed `.ex`/`.exs` paths. For Credo, use `mix credo suggest --strict --format json <paths...>`; repeated `--files-included` with an implicit command does not reliably check the full manifest. Compile both `MIX_ENV=test` and `MIX_ENV=dev` with `mix compile --warnings-as-errors`. Scoped Dialyzer analyzes the production beams for changed modules using the existing matching development PLT; compare inherited findings against the exact Git baseline, not an earlier concurrent test snapshot.

## Qualification limits

No publication, deployment, existing-service restart, live/shared migration or credential change was performed. Production TLS/proxy acceptance, physical power-loss testing, production-scale load, and unrelated repository-wide checks are not run. WAL guarantees require the filesystem/storage to honor successful file and directory syncs. Full disks cannot preserve unlimited rejected-traffic counts; explicit degraded pipeline health describes that limit.
