# Dynamic Secret Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver PostgreSQL and Redis credentials through the authenticated Agent path with durable application ownership, encrypted persistence, replay-safe issuance, real renewal, and crash-recoverable revocation/expiry.

**Architecture:** Replace the in-memory LeaseManager lifecycle with PostgreSQL state plus unique Oban cleanup intent. Every external engine operation uses a deterministic principal, a connection-pinned advisory lock, an operation token, and compare-and-swap finalization. Role and engine inputs are immutable snapshots referencing a stable static administrative secret; generated/admin credentials never appear in plaintext rows, jobs, logs, or audit metadata.

**Tech Stack:** Elixir/Ecto, PostgreSQL advisory locks and roles, Redis ACL, Oban, Phoenix Channels, Agent UDS, ExUnit/StreamData where useful, SecretHub vault/audit contexts, devenv.

---

## Dependencies and public contracts

Start runtime wiring only after the app-PKI plan provides `%SecretHub.Core.RuntimePrincipal{}`. Terminal lease notification wiring also depends on the cache plan's `SecretHub.Core.AgentNotifications`. Core persistence/engine tasks may begin earlier.

The new Core context owns this interface:

```elixir
SecretHub.Core.DynamicSecrets.generate(principal, role_name, %{
  request_id: request_id,
  ttl: ttl_or_nil,
  auto_renew: boolean
})

SecretHub.Core.DynamicSecrets.renew_explicit(principal, lease_id, %{
  request_id: request_id,
  increment: seconds
})

SecretHub.Core.DynamicSecrets.renew_delegated(agent_id, lease_id, %{
  request_id: request_id,
  increment: seconds
})

SecretHub.Core.DynamicSecrets.revoke(principal, lease_id, %{
  request_id: request_id,
  reason: reason
})

SecretHub.Core.DynamicSecrets.list_auto_renewable(agent_id)
SecretHub.Core.DynamicSecrets.reconcile_lifecycle(lease_id)
```

Use public `lease_id` everywhere outside Ecto internals. AWS STS returns stable `ENGINE_UNAVAILABLE`/`aws_sts_engine_not_available` before any durable or external side effect.

## Task 1: Install and supervise Oban for durable lifecycle ownership

**Files:**

- Create: `apps/secrethub_core/priv/repo/migrations/20260716010100_install_oban.exs`
- Modify: `config/config.exs`
- Modify: `config/test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/application.ex`
- Modify: `apps/secrethub_core/test/test_helper.exs`
- Modify: `apps/secrethub_web/test/test_helper.exs`
- Create: `apps/secrethub_core/test/secrethub_core/oban_configuration_test.exs`

- [ ] Add tests asserting the Oban tables exist, the Core supervisor starts Oban, and test mode is `testing: :manual`.
- [ ] Assert configured queues include high-priority `lease_cleanup`, `leases`, existing `rotation`, and `default`, with explicit bounded concurrency.
- [ ] Run `devenv shell -- test-all apps/secrethub_core/test/secrethub_core/oban_configuration_test.exs`; expect missing tables/supervision failure.
- [ ] Implement reversible `Oban.Migrations.up/down` migration and add an `oban_children/0` boundary after Repo in the Core tree. Like Repo, it returns no application child in test mode; both Core and Web test helpers must stop Oban before replacing Repo and start test-mode Oban only after the sandbox Repo is ready.
- [ ] Keep job arguments JSON-safe string-key maps and prohibit secrets by module API/test, not convention alone.
- [ ] Rerun focused test and commit with `feat(core): supervise durable lease jobs`.

## Task 2: Add record-bound encrypted JSON envelopes

**Files:**

- Create: `apps/secrethub_core/lib/secrethub_core/vault/envelope.ex`
- Create: `apps/secrethub_core/test/secrethub_core/vault/envelope_test.exs`

- [ ] Write round-trip tests for maps containing binary/string values using a test master key, plus key-version dispatch.
- [ ] Add tamper tests for ciphertext, nonce, tag, table, record ID, field, and key version; every AAD mismatch must fail authentication.
- [ ] Assert serialized envelopes never contain source JSON substrings and sealed vault returns stable `VAULT_SEALED`.
- [ ] Run the focused file; expect missing-module failure.
- [ ] Implement:

  ```elixir
  seal_json(table, record_id, field, value, key_version \\ 1)
  open_json(table, record_id, field, envelope)
  ```

- [ ] Use a versioned binary envelope, cryptographically random nonce, AEAD, and AAD containing table, record UUID, field name, and key version; obtain keys from the existing vault boundary.
- [ ] Leave existing static-secret v1 blobs readable and do not silently reinterpret them as this envelope.
- [ ] Rerun focused tests and commit with `feat(core): encrypt record-bound lifecycle data`.

## Task 3: Create immutable engine versions and persistent dynamic roles

**Files:**

- Create: `apps/secrethub_core/priv/repo/migrations/20260716010200_create_engine_configuration_versions.exs`
- Create: `apps/secrethub_core/priv/repo/migrations/20260716010250_add_secret_access_class.exs`
- Create: `apps/secrethub_core/priv/repo/migrations/20260716010300_create_dynamic_secret_roles.exs`
- Create: `apps/secrethub_shared/lib/secrethub_shared/schemas/engine_configuration_version.ex`
- Create: `apps/secrethub_shared/lib/secrethub_shared/schemas/dynamic_secret_role.ex`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/secret.ex`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/engine_configuration.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/secrets.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/secrets_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/runtime_authorization.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/runtime_authorization_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/engine_configurations.ex`
- Create: `apps/secrethub_core/lib/secrethub_core/dynamic_secrets/engine_admin_secret_resolver.ex`
- Create: `apps/secrethub_core/test/secrethub_core/dynamic_secrets/engine_admin_secret_resolver_test.exs`
- Create: `apps/secrethub_core/lib/secrethub_core/dynamic_secrets/roles.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/controllers/secret_api_controller.ex`
- Create: `apps/secrethub_web/test/secrethub_web_web/controllers/internal_secret_access_test.exs`
- Modify: `apps/secrethub_web/lib/secret_hub/web/live/dynamic_postgresql_config_live.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/live/engine_setup_wizard_live.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/live/engine_configuration_live.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/live/engine_health_dashboard_live.ex`
- Create: `apps/secrethub_web/lib/secret_hub/web/live/dynamic_secret_role_live.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/router.ex`
- Create: `apps/secrethub_web/test/secrethub_web_web/live/engine_configuration_live_test.exs`
- Create: `apps/secrethub_web/test/secrethub_web_web/live/engine_health_dashboard_live_test.exs`
- Create: `apps/secrethub_web/test/secrethub_web_web/live/engine_setup_wizard_live_test.exs`
- Create: `apps/secrethub_web/test/secrethub_web_web/live/dynamic_secret_role_live_test.exs`
- Create: `apps/secrethub_core/test/secrethub_core/engine_configurations_test.exs`
- Create: `apps/secrethub_core/test/secrethub_core/dynamic_secrets/roles_test.exs`
- Create: `apps/secrethub_core/lib/secrethub_core/dynamic_secrets/legacy_backfill.ex`
- Create: `apps/secrethub_core/test/secrethub_core/dynamic_secrets/legacy_backfill_test.exs`

- [ ] Add tests that updating a logical engine config inserts a new immutable version and atomically advances `current_version_id` without mutating an old version.
- [ ] Validate nonsecret configuration with an explicit per-engine allowlist and reject sensitive value keys such as `password`, `admin_password`, `secret_key`, `access_key`, `private_key`, and `token` at all nesting levels. Permit the reference field `admin_secret_id` and require it to reference a static Secret.
- [ ] Add `secrets.access_class` with exact values `application` and `internal_engine_admin`, default/not-null `application`, a database check, and a database trigger that forbids changing an `internal_engine_admin` row back to application-visible. The ordinary Secret changeset/API cannot cast this field; only the engine-configuration transaction may promote a static secret to internal use.
- [ ] Add authorization/controller tests proving runtime wildcard policies and REST read/list/metadata/version endpoints cannot return an `internal_engine_admin` secret, and API create/update cannot set or clear that class. Reject it before policy evaluation with a stable not-found/denied result and sanitized audit metadata.
- [ ] Implement a separately audited `EngineAdminSecretResolver.resolve(engine_version_id)` that requires an immutable engine version to reference a secret already classified `internal_engine_admin`, checks the vault is unsealed, and returns plaintext only to the bounded engine operation. General `Secrets.read_decrypted/1`, runtime authorization, and controllers must not be a route to internal credentials.
- [ ] Add role tests for unique normalized name, enabled flag, engine compatibility, creation/renewal/revocation rule maps, default/max TTL, absolute lifetime, max renewals, and active-version delete protection.
- [ ] Run focused tests and capture current mutable/plaintext/Application-env behavior.
- [ ] Add the two schemas and restrictive FKs. A version stores nonsecret connection metadata, engine type, stable `admin_secret_id`, and version number.
- [ ] Make PostgreSQL/Redis admin forms select an existing static secret; in the same transaction that publishes the first referencing engine version, irreversibly promote it to `internal_engine_admin`. Never copy its decrypted data into engine configuration.
- [ ] Move PostgreSQL role configuration out of `Application` env into `dynamic_secret_roles`.
- [ ] Add one shared operator role-management surface for PostgreSQL and Redis using the persistent role context; validate engine-specific rule fields and TTL/lifetime limits without exposing administrative credentials.
- [ ] Implement an unsealed, resumable legacy engine backfill keyed by source configuration ID: split recognized mixed maps into nonsecret connection settings and role rules, create/update one internal static administrative secret for extracted credentials, publish an immutable version referencing it, and record verified progress. Unsupported shapes produce operator-fixable rows and never guess/hard-code a role.
- [ ] Add a preflight count proving every production-path engine configuration has a current immutable version whose stable secret reference is classified `internal_engine_admin` before cutover; defer clearing/dropping plaintext `engine_configurations.config` credential keys to a separate engine-configuration contract release.
- [ ] During Release A, read secure current versions first and temporarily fall back to recognized legacy maps only for unresolved rows, while every create/update writes secure versions/references only. Rerun the resumable backfill after the last legacy-capability node exits because an old node may have written another plaintext row during rolling deployment.
- [ ] Update configuration delete/disable and health-check consumers for immutable versions: refuse deletion while any role/lease references a version, and ensure health paths resolve the current version without exposing the admin secret. Run the three exact new LiveView test files.
- [ ] Commit with `feat(core): persist immutable dynamic secret roles`.

## Task 4: Expand leases and scoped operation idempotency

**Files:**

- Create: `apps/secrethub_core/priv/repo/migrations/20260716010400_expand_dynamic_leases.exs`
- Create: `apps/secrethub_core/priv/repo/migrations/20260716010500_create_lease_operations.exs`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/lease.ex`
- Create: `apps/secrethub_shared/lib/secrethub_shared/schemas/lease_operation.ex`
- Create: `apps/secrethub_core/test/secrethub_core/dynamic_secrets/lease_persistence_test.exs`

- [ ] Add schema tests for lifecycle states `pending_issue`, `active`, `issue_failed`, `cleanup_required`, `cleanup_blocked`, `renewing`, `revoking`, `revoked`, and `expired`.
- [ ] Test collision-safe expand fields `agent_ref_id` and `application_ref_id` as real FKs alongside the existing string `agent_id`/`app_id` fields, immutable issuing fingerprint, role/config-version FKs, unique public `lease_id`, deterministic external principal, `auto_renew`, target/max expiry, renewal count, operation token, `external_started_at`, persisted `quiesce_until`, revoke request time, encrypted credential/snapshot envelopes, key version, and lifecycle job ID. Rename typed fields to their final names only in the contract release.
- [ ] Test `lease_operations` unique `(application_id, operation, request_id)`, normalized payload hash, lease link, status/result metadata, and conflict behavior.
- [ ] Run the focused file and expect current string/plaintext/revoked-boolean schema to fail.
- [ ] Add nullable expand columns and indexes first; do not remove existing `credentials`, `engine_metadata`, `secret_id`, or legacy string owner fields in this release.
- [ ] Add `LeasePreflight.report/0` in `apps/secrethub_core/lib/secrethub_core/dynamic_secrets/lease_preflight.ex` to resolve legacy Agent strings through `agents.agent_id`, report `system`/ambiguous/orphan owners, and enumerate plaintext rows.
- [ ] Implement vault-unsealed, resumable runtime backfill that creates immutable snapshots/envelopes, verifies decryptability, resolves ownership, and transactionally creates/records one live lifecycle job for every nonterminal legacy lease; never decrypt or perform external cleanup inside the DDL migration.
- [ ] During Release A, dynamic reads prefer typed ownership/envelopes/snapshots and use a narrowly tested legacy fallback only for unresolved rows; all new/updated rows write secure fields only. Disable fallback at `dynamic_secure_storage` cutover and rerun backfill after every fresh node advertises the secure-write capability.
- [ ] Rerun focused tests and commit with `feat(core): expand durable dynamic lease state`.

## Task 5: Add a connection-pinned lease advisory lock

**Files:**

- Create: `apps/secrethub_core/lib/secrethub_core/dynamic_secrets/advisory_lock.ex`
- Create: `apps/secrethub_core/test/secrethub_core/dynamic_secrets/advisory_lock_test.exs`

- [ ] Add tests that the same `lease_id` serializes two processes across an injected slow external call, different IDs proceed concurrently, timeout returns a stable busy error, and process crash releases the lock.
- [ ] Run the focused test and expect missing-module failure.
- [ ] Implement `with_lock(lease_id, opts \\ [], fun)` using `Repo.checkout/2`, a two-integer key derived from SHA-256 of the public lease ID, `pg_try_advisory_lock`, and release in `after` on that same checked-out connection.
- [ ] Do not reuse `SecretHub.Core.DistributedLock`; its pooled acquisition/release does not prove session affinity.
- [ ] Keep the advisory lock held through external engine call and database finalization/handoff, but never expose its key as an authorization token.
- [ ] Rerun focused tests and commit with `feat(core): serialize external lease operations`.

## Task 6: Make engine behavior deterministic, safe, and externally real

**Files:**

- Modify: `apps/secrethub_core/lib/secrethub_core/engines/dynamic.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/engines/dynamic/postgresql.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/engines/dynamic/redis.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/engines/dynamic/aws_sts.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/engines/dynamic/test_engine.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/engines/dynamic/postgresql_test.exs`
- Create: `apps/secrethub_core/test/secrethub_core/engines/dynamic/redis_test.exs`

- [ ] Replace tests around random principal/raw template behavior with this contract:

  ```elixir
  issue(snapshot, external_principal, expires_at, admin_credentials)
  renew(snapshot, external_principal, expires_at, admin_credentials)
  revoke(snapshot, external_principal, admin_credentials)
  exists?(snapshot, external_principal, admin_credentials)
  ```

- [ ] Add PostgreSQL integration tests for safely quoted identifier/password/timestamp, real `VALID UNTIL`, idempotent drop, invalid template/rule rejection, partial multi-statement result, timeout, and lost response.
- [ ] Add Redis tests for deterministic ACL user create/delete, externally idempotent delete, durable-only renewal, exists check, timeout, and partial/lost response.
- [ ] Assert AWS returns unavailable without network or database side effects.
- [ ] Run engine tests and capture failures.
- [ ] Build statements from validated structured rules and driver parameters/strict quoting; do not use raw string replacement for untrusted values.
- [ ] Resolve admin credentials immediately before each operation through a separately audited internal engine-credential read that neither uses nor broadens the requesting application's secret policy, and audit the static-secret version ID used. Generation/renewal use only the current value. On cleanup authentication failure, try still-retained prior versions newest-first within a configured attempt bound; never persist those plaintext values in the lease.
- [ ] Never return admin credentials in engine results or exceptions.
- [ ] Rerun engine tests and commit with `feat(core): implement deterministic dynamic engines`.

## Task 7: Implement fenced generation and exact replay

**Files:**

- Create: `apps/secrethub_core/lib/secrethub_core/dynamic_secrets.ex`
- Create: `apps/secrethub_core/lib/secrethub_core/dynamic_secrets/generation.ex`
- Create: `apps/secrethub_core/test/secrethub_core/dynamic_secrets/generation_test.exs`
- Create: `apps/secrethub_core/lib/secrethub_core/workers/lease_lifecycle_worker.ex`

- [ ] Add happy-path tests proving authorization, role/config resolution, deterministic principal, encrypted persistence, pre-created unique job, active CAS, issuance audit, and plaintext returned only after final transaction commit.
- [ ] Add exact replay tests: same app/request/normalized role-TTL-auto-renew returns the same active lease and decrypted initial credentials; changed payload returns `IDEMPOTENCY_CONFLICT`.
- [ ] Add intermediate idempotency tests for duplicate requests while `pending_issue`/`cleanup_required`, a same-request retry after confirmed `issue_failed`, and a response lost after active commit. A duplicate must observe/reconcile the one fenced operation, never start a concurrent external issue.
- [ ] Add faults at every boundary: before intent commit, after intent/before side effect, partial issue, timeout/lost result, after external creation/before credential persistence, and after final commit/before response.
- [ ] Add a late-completion test where an ambiguous issue first appears absent, completes after that check, and is then found/revoked after the persisted quiescence deadline; terminal `issue_failed` is forbidden before the post-quiescence absence check.
- [ ] Assert every ambiguous outcome enters `cleanup_required` or stale `pending_issue` with a runnable pre-created job; Core never reports successful untracked credentials.
- [ ] Run the focused test and expect missing-context failure.
- [ ] Implement the ordered flow from the design: authorize/normalize under shared authorization-version locks; transactionally insert operation + pending lease + encrypted snapshot + token + short-deadline job; acquire the advisory lock; reauthorize from current Agent/app/certificate/policy state immediately before the side effect; external issue; CAS active/encrypted credentials/rescheduled expiry job/audit; return after commit.
- [ ] Use deterministic request-derived principal names that fit PostgreSQL/Redis limits and cannot collide across applications/roles.
- [ ] On any ambiguous result, best-effort mark cleanup and wake the durable job; never rely only on immediate cleanup. After cleanup confirms an issue-failed principal absent, allow the same request ID to begin a new fenced attempt on that lease record without ever creating two live principals.
- [ ] Before every external call, persist `external_started_at` and `quiesce_until` derived from a configured bounded driver timeout plus safety margin. Ambiguous issuance cleanup must snooze/recheck through that deadline and cannot become `issue_failed` merely because an earlier existence check returned absent.
- [ ] Rerun focused tests and commit with `feat(core): fence dynamic credential issuance`.

## Task 8: Implement serialized renewal, revocation, expiry, and reconciliation

**Files:**

- Create: `apps/secrethub_core/lib/secrethub_core/dynamic_secrets/lifecycle.ex`
- Create: `apps/secrethub_core/lib/secrethub_core/dynamic_secrets/lifecycle_intent.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/workers/lease_lifecycle_worker.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/lease_manager.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/application.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/live/lease_viewer_live.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/live/lease_dashboard_live.ex`
- Create: `apps/secrethub_web/test/secrethub_web_web/live/lease_viewer_live_test.exs`
- Create: `apps/secrethub_web/test/secrethub_web_web/live/lease_dashboard_live_test.exs`
- Create: `apps/secrethub_core/test/secrethub_core/dynamic_secrets/lifecycle_test.exs`
- Create: `apps/secrethub_core/test/secrethub_core/workers/lease_lifecycle_worker_test.exs`
- Modify: `apps/secrethub_core/test/secrethub_core/lease_manager_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/agent_notifications.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/agent_notifications_test.exs`

- [ ] Add explicit/delegated renewal tests for ownership, `auto_renew`, app status, active app certificate existence, both policy gates, max TTL, absolute lifetime, max renewals, and no password re-delivery.
- [ ] Add renew/revoke idempotency tests for lost successful responses, exact replay in intermediate and terminal states, and changed payload conflict.
- [ ] Add concurrency tests for renew vs manual revoke, renew vs expiry, duplicate worker, stale operation token, revoke request after external renewal, process crash in every state, and late external completion.
- [ ] Add a late-renewal test where cleanup first observes absence/old state, the timed-out renewal completes, and post-quiescence cleanup removes the principal. No `revoked`/`expired` terminal transition is allowed until absence is confirmed after persisted `quiesce_until`.
- [ ] Add worker tests: args exactly `%{"lease_id" => lease_id}`, old-expiry job snoozes to current expiry, sealed vault retries, external failure retries, cleanup threshold reaches `cleanup_blocked` plus operational alert while remaining scheduled, and job restart reconciles stale pending/renewing/revoking rows.
- [ ] Run focused tests and capture current in-memory timer/fake-renew behavior.
- [ ] Renewal must commit `renewing`, unique token, target expiry, and operation record before the advisory-locked engine call; finalize only if token matches and `revoke_requested_at` is nil. Exact renew/revoke replays return their stored transition result, while a changed normalized payload for the same scoped request ID returns `IDEMPOTENCY_CONFLICT`.
- [ ] Revocation/expiry sets `revoke_requested_at`, wakes the existing lifecycle job, waits for the same advisory lock, performs idempotent cleanup, and moves to terminal `revoked`/`expired` only after confirmed absence.
- [ ] Implement `LifecycleIntent.ensure_or_wake_in_multi/3`: in the same database transaction as any nonterminal lifecycle/status change, retain or create exactly one live unique job, make a scheduled/retryable job runnable now when cleanup is requested, and replace a completed/cancelled/discarded row while updating `lifecycle_job_id`.
- [ ] Ambiguous renewal never extends durable expiry; transition/handoff to cleanup. The worker snoozes until persisted `quiesce_until`, then repeats idempotent cleanup and confirms absence so a late completion cannot resurrect access.
- [ ] Never let retry exhaustion discard the only cleanup intent. After the alert threshold, persist `cleanup_blocked` and return bounded snoozes/re-enqueue indefinitely until the lease is terminal or an operator resolves it.
- [ ] Keep `LeaseManager` as a stateless compatibility façade only for sanitized list/stats and audited operator safety revocation; remove it from supervision and remove its generation/renewal/timer APIs. Update LeaseViewer/Dashboard to query durable state, remove the admin renew action (it cannot mint an app principal), and route operator revoke through `DynamicSecrets.request_operator_revoke/3`.
- [ ] Emit sanitized `secret.dynamic_issued`, `secret.lease_renewed`, `secret.lease_revoked`, `secret.lease_expired`, and `secret.lease_cleanup_failed` audit events.
- [ ] After each committed lease state/expiry change, publish sanitized `AgentNotifications.lease_updated/4` to the owning Agent; failed/rolled-back transitions publish nothing and notification delivery never changes durable lifecycle outcome.
- [ ] Rerun focused tests and commit with `feat(core): reconcile dynamic lease lifecycle`.

## Task 9: Trigger safety cleanup on identity changes

**Files:**

- Modify: `apps/secrethub_core/lib/secrethub_core/apps.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/agents.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/pki/app_certificates.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/apps_test.exs`
- Modify: `apps/secrethub_core/test/secrethub_core/agents_test.exs`
- Modify: `apps/secrethub_core/test/secrethub_core/pki/app_certificates_test.exs`
- Modify: `apps/secrethub_core/test/secrethub_core/dynamic_secrets/lifecycle_test.exs`

- [ ] Add tests proving app suspension/retirement and Agent reassignment mark every nonterminal app lease for cleanup and wake jobs. The delete API must soft-retire the application and retain its row/audit identity; physical deletion is refused while any historical lease references it and lease ownership FKs never cascade.
- [ ] Add equivalent Agent retirement tests: public Agent deletion becomes suspend/retire plus cleanup/disconnect, and physical deletion is refused while any application or historical lease references the Agent. Typed ownership FKs never cascade historical leases.
- [ ] Add tests proving `compromised` certificate revocation cleans leases issued through that fingerprint while normal `superseded` rotation does not strand/revoke app-owned leases.
- [ ] Prove cleanup does not require a now-suspended app, active cert, current assignment, or allow policy; it validates durable ownership/snapshot and audits the safety action.
- [ ] Run focused tests and capture missing hooks.
- [ ] Add cleanup-intent updates and `LifecycleIntent.ensure_or_wake_in_multi/3` inside the same identity-change transaction; no crash window may exist between committing suspension/reassignment/compromise and making cleanup runnable. Pending issuance must converge through cleanup.
- [ ] Rerun focused tests and commit with `fix(core): revoke leases after identity compromise`.

## Task 10: Wire trusted runtime events and Agent auto-renewal

**Files:**

- Modify: `apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex`
- Modify: `apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/connection.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/lease_renewer.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/application.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/uds_server.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/lease_renewer_test.exs`
- Create: `apps/secrethub_agent/test/secrethub_agent/uds_server_dynamic_test.exs`

- [ ] Add channel contracts `secret:dynamic_generate`, `secret:lease_renew`, `secret:lease_revoke`, and `secret:lease_list_auto_renew`; remove fake renew success and the incorrect dynamic→`secret:read` mapping.
- [ ] Test explicit operations carry the authenticated app claims, while delegated renewal carries only lease ID/increment/request ID and Core derives ownership.
- [ ] Add UDS actions `generate_dynamic_secret`, `renew_lease`, `revoke_lease`; assert auth v2 is mandatory and responses use public lease ID.
- [ ] Change LeaseRenewer to take a trusted connection and replace (not merge) its tracked metadata from Core-owned active `auto_renew` leases on every normal runtime join. Derive each retry request ID from lease ID plus the current renewal count/target expiry so it remains stable across retries of one renewal but changes after a successful renewal.
- [ ] Test successful opted-in generation tracks scheduling, revoked/expired events untrack it, restart reloads it, and no REST/Vault-token renewal is attempted.
- [ ] Run focused channel/Agent tests and implement only the approved request/response flow; streaming/watch remains out of scope.
- [ ] Rerun focused tests and commit with `feat(agent): deliver and renew dynamic credentials`.

## Task 11: Add CLI generation and lease actions; remove HTTP bypass

**Files:**

- Modify: `apps/secrethub_cli/lib/secrethub_cli.ex`
- Modify: `apps/secrethub_cli/lib/secrethub_cli/agent_client.ex`
- Modify: `apps/secrethub_cli/lib/secrethub_cli/commands/secret_commands.ex`
- Create: `apps/secrethub_cli/lib/secrethub_cli/commands/lease_commands.ex`
- Modify: `apps/secrethub_cli/test/secrethub_cli/agent_client_test.exs`
- Modify: `apps/secrethub_cli/test/secrethub_cli/commands/secret_commands_test.exs`
- Create: `apps/secrethub_cli/test/secrethub_cli/commands/lease_commands_test.exs`
- Modify: `apps/secrethub_web/lib/secret_hub/web/controllers/dynamic_secrets_controller.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/router.ex`
- Create: `apps/secrethub_web/test/secrethub_web_web/controllers/dynamic_secrets_controller_test.exs`

- [ ] Add parser/transport tests for `secret generate <role> --ttl --auto-renew [--request-id]`, `lease renew <lease_id> --increment [--request-id]`, and `lease revoke <lease_id> [--request-id]`.
- [ ] Require `--agent-socket`, `--agent-cert`, and `--agent-key`; assert no Vault-token HTTP fallback when Agent transport is selected or required.
- [ ] Assert retries reuse request ID, CLI never prints admin material, renewal does not print the password again, and public errors are stable.
- [ ] Keep the UDS frame/correlation `request_id` distinct from the lifecycle operation idempotency `operation_request_id`; add a lost-UDS-response test proving bounded transport retry reuses only the operation ID while generating a fresh frame ID.
- [ ] Run focused CLI tests and capture missing-command failures.
- [ ] Implement exact UDS action maps and secure output formatting.
- [ ] Remove public direct generate/renew/revoke HTTP routes or make them explicit `agent_required`/gone responses; retain sanitized admin list/stats only if used by current admin UI.
- [ ] Rerun CLI/controller tests and commit with `feat(cli): manage dynamic leases through agent`.

## Task 12: Verify external lifecycle and gate the contract release

**Files:**

- Modify: `apps/secrethub_web/test/e2e/core_agent_flow_test.exs`
- Modify: `docs/deploy.md`

- [ ] Add real PostgreSQL and Redis E2E assertions for issue, exact replay, real PostgreSQL `VALID UNTIL` renewal, Redis durable renewal, manual revoke, automatic expiry, Core restart, sealed-vault retry, and cleanup after app suspension.
- [ ] Add publisher tests proving every committed terminal/relevant lease transition emits sanitized `AgentNotifications` `lease:updated` after commit so Agent cache/renewer state converges; failed transactions emit nothing.
- [ ] Scan database rows, Oban args, audit data, and captured logs for generated passwords/admin secrets; require zero matches.
- [ ] Run the lease preflight/backfill on representative legacy rows and verify unresolved `system`/ambiguous ownership blocks cutover without data deletion.
- [ ] Persist `UpgradeGates` marker `dynamic_secure_storage` only after engine, internal-admin-classification, and lease zero-count reports verify. Before any contract DDL, require every fresh active cluster node to advertise the secure-dynamic-read/write capability; test old active node block, explicit shutdown, and stale-node acknowledgement semantics.
- [ ] Record but do not create the future lease/engine contract migrations in this implementation branch. A separately reviewed later-release plan may drop `credentials`/legacy owners, rename typed FKs, and remove engine credential keys only after every sensitive row is verified, all ownership is resolved, every nonterminal row has one live intent, the matching gates are current, and every fresh node advertises secure-only capability.
- [ ] Run `devenv shell -- test-all apps/secrethub_core/test/secrethub_core/dynamic_secrets/ apps/secrethub_core/test/secrethub_core/workers/lease_lifecycle_worker_test.exs apps/secrethub_core/test/secrethub_core/engines/dynamic/`.
- [ ] Run `devenv shell -- test-all apps/secrethub_core/test/secrethub_core/oban_configuration_test.exs apps/secrethub_core/test/secrethub_core/engine_configurations_test.exs apps/secrethub_core/test/secrethub_core/secrets_test.exs apps/secrethub_core/test/secrethub_core/runtime_authorization_test.exs apps/secrethub_core/test/secrethub_core/dynamic_secrets/engine_admin_secret_resolver_test.exs apps/secrethub_agent/test/secrethub_agent/lease_renewer_test.exs apps/secrethub_agent/test/secrethub_agent/uds_server_dynamic_test.exs apps/secrethub_cli/test/secrethub_cli/agent_client_test.exs apps/secrethub_cli/test/secrethub_cli/commands/secret_commands_test.exs apps/secrethub_cli/test/secrethub_cli/commands/lease_commands_test.exs apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs apps/secrethub_web/test/secrethub_web_web/controllers/dynamic_secrets_controller_test.exs apps/secrethub_web/test/secrethub_web_web/controllers/internal_secret_access_test.exs apps/secrethub_web/test/secrethub_web_web/live/dynamic_secret_role_live_test.exs`.
- [ ] Run the dynamic E2E cases, format check, compile with warnings as errors, Credo, and `git diff --check`.
- [ ] Commit with `test(e2e): verify durable dynamic secret lifecycle`.
