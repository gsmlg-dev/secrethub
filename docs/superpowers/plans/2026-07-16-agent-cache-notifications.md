# Agent Cache and Runtime Notifications Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve the performance benefit of versioned Agent cache entries while guaranteeing every static-secret release has a current Core authorization decision and promptly reacting to rotations, policy changes, app revocation, and lease lifecycle events.

**Architecture:** Replace path-only/fallback cache behavior with application-scoped synchronous entries, per-path monotonic mutation-revision tombstones, and scope generations. UDS reads always round-trip to Core with an optional known revision; Core returns a value/revision or an explicit authorized `not_modified`. Notifications carry identifiers and revisions only, reject stale in-flight writes, and improve convergence without becoming an authorization boundary.

**Tech Stack:** Elixir GenServer, Phoenix Channels, Ecto contexts, Unix domain sockets, ExUnit, SecretHub Core connection registry.

---

## Dependency

Start after the app-PKI plan provides:

```elixir
%SecretHub.Core.RuntimePrincipal{}
SecretHub.Core.RuntimeAuthorization.authorize_static_read/3
```

Do not implement a second authorization path in this slice.

## Task 1: Replace path-only fallback cache with scoped/versioned state

**Files:**

- Modify: `apps/secrethub_agent/lib/secrethub_agent/cache.ex`
- Create: `apps/secrethub_agent/test/secrethub_agent/cache_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/template_renderer.ex`
- Create: `apps/secrethub_agent/test/secrethub_agent/template_renderer_test.exs`

- [ ] Write tests for independent `{:application, app_id}` entries at the same path, synchronous put/get, TTL expiry, maximum size, and secret-free metrics.
- [ ] Write ordering tests: tombstone revision 4 rejects response revision 3, duplicate revision 4 does not regress state, revision 5 replaces it, and clearing entries retains tombstones.
- [ ] Write scope-generation tests: a policy clear increments the application generation and rejects an in-flight response carrying the prior generation.
- [ ] Add tests proving stale/expired data is never returned by `get/2` and `get_with_fallback/1` no longer exists.
- [ ] Run `devenv shell -- test-all apps/secrethub_agent/test/secrethub_agent/cache_test.exs apps/secrethub_agent/test/secrethub_agent/template_renderer_test.exs`; expect current path-only/fallback behavior to fail.
- [ ] Implement this interface with `GenServer.call` for mutations that gate response release:

  ```elixir
  snapshot(scope, path) :: {:ok, %{entry: CacheEntry.t() | nil, generation: non_neg_integer()}}
  put(scope, path, data, revision: pos_integer(), ttl: pos_integer(), generation: non_neg_integer()) ::
    :ok | {:error, :stale_revision | :stale_generation}
  invalidate_path(path, minimum_revision) :: :ok
  clear_scope(scope) :: :ok
  clear_entries() :: :ok
  ```

- [ ] Key static values by `{scope, normalized_path}`; keep tombstones separately by path and keep scope generations after entry eviction/reconnect.
- [ ] Remove `fallback_enabled`, stale warning/release, and every direct Cache read from TemplateRenderer. Replace it with `render(template, vars, authorized_secrets: %{normalized_path => value})`; a missing path returns `UNAVAILABLE`, and preloading Cache alone can never make rendering succeed.
- [ ] Do not store dynamic credential values in this cache. LeaseRenewer owns only nonsecret lease scheduling metadata and consumes terminal `lease:updated` events directly.
- [ ] Rerun focused tests and commit with `fix(agent): make secret cache scoped and versioned`.

## Task 2: Make every UDS static read conditional on Core authorization

**Files:**

- Modify: `apps/secrethub_agent/lib/secrethub_agent/uds_server.ex`
- Create: `apps/secrethub_agent/test/secrethub_agent/uds_server_static_read_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/connection.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs`
- Modify: `apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex`
- Modify: `apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/secret_path_revision.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/secrets.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/secrets_test.exs`

- [ ] Add a UDS test proving a cache hit still sends `secret:read` with authenticated app ID, canonical fingerprint, path, and `known_revision`.
- [ ] Add Core tests for a persisted monotonic path revision that increments in the same transaction as create, update, rollback, rotation, and delete, survives deletion, and increments again when the same path is recreated.
- [ ] Test Core `not_modified` releases only a still-present cache entry with exactly that revision; if the entry disappeared, Agent retries once without `known_revision`.
- [ ] Test a value/revision response is synchronously cached before release; a tombstone/generation rejection triggers one fresh Core retry instead of releasing stale bytes.
- [ ] Test Core unavailable, denied, malformed `not_modified`, and second-race failure return stable errors with no value.
- [ ] Run the four focused files and capture the current cache-first bypass failure.
- [ ] Implement the bounded algorithm:

  ```text
  snapshot scope/path
  -> Core read(known_revision or nil)
  -> not_modified: verify exact cached revision, then release
  -> value/revision: synchronous put with snapshot generation, then release
  -> cache race: retry once from a new snapshot without known_revision
  -> any second race/error: fail closed
  ```

- [ ] Remove the current direct cache-return branch and app-policy TODO from UDSServer; use the auth-v2 connection's immutable app claims.
- [ ] Keep Core audit on both value and `not_modified` decisions; do not treat `not_modified` as unaudited cache access.
- [ ] Rerun focused tests and commit with `fix(agent): authorize every cached secret read`.

## Task 3: Add sanitized Core notification production and routing

**Files:**

- Create: `apps/secrethub_core/lib/secrethub_core/agent_notifications.ex`
- Create: `apps/secrethub_core/test/secrethub_core/agent_notifications_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/agents/connection_manager.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/agents/connection_manager_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/secrets.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/secrets_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/policies.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/policies_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/apps.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/apps_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/pki/app_certificates.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/pki/app_certificates_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/pki/verifier.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/channels/agent_trusted_socket.ex`

- [ ] Write exact envelope tests: `secret:rotated` has normalized path plus monotonic revision; `policy:updated` has affected app UUIDs or `clear_all`; app status/assignment has old/new Agent database UUIDs; certificate status has app UUID, old canonical fingerprint, status, and reason; `lease:updated` has public lease ID/app UUID/state only.
- [ ] Add routing tests for one Agent, a set of Agents, and broadcast; duplicate/disconnected delivery is tolerated and never changes the mutation result.
- [ ] Add context tests proving notification happens only after a successful commit for secret create/update/delete/rollback/rotation, policy content/binding changes, app status/assignment changes, and app-certificate revocation/supersession.
- [ ] Run focused tests and expect missing production/routing behavior.
- [ ] Make PKI verifier/socket join carry both `agent_db_id` (database UUID) and `agent_id` (public Agent identifier). Key Core ConnectionManager/routing by database UUID while retaining the public identifier only as protocol/audit metadata.
- [ ] Implement `ConnectionManager.send_to_agent/2`, `send_to_agents/2`, and `broadcast/1` with one internal message shape; use database Agent UUID consistently. Application reassignment routes invalidation to both old and new Agent registries.
- [ ] Implement `AgentNotifications` builders and affected-Agent resolution. Never include decrypted secret data, encrypted blobs, credentials, proofs, PEM, or full policy documents.
- [ ] Call notifications after successful context transactions. Log sanitized delivery failures as operational telemetry; do not roll back an already committed mutation.
- [ ] Rerun focused tests and commit with `feat(core): publish agent cache invalidations`.

## Task 4: Make UDS request completion independently evictable

**Files:**

- Modify: `apps/secrethub_agent/lib/secrethub_agent/application.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/uds_server.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/uds_server_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/uds_server_static_read_test.exs`

- [ ] Add multi-socket tests proving connections are indexed only after successful auth-v2 proof by application ID and canonical fingerprint.
- [ ] Add tests for nonblocking `disconnect_application/2`, `disconnect_certificate/2`, duplicate eviction, unrelated connection survival, and generation increment before close.
- [ ] Refactor Core-bound UDS operations onto supervised per-request workers so the UDSServer process remains able to process eviction while a Connection call is outstanding; workers return `{connection_ref, connection_generation, frame_id, result}`.
- [ ] Before writing any worker result, compare the socket's current connection generation and authenticated identity. Drop/close mismatched results so an eviction queued before completion cannot release bytes.
- [ ] Never call UDSServer synchronously from a Connection push handler. Eviction/clear delivery is a nonblocking cast, eliminating `UDSServer -> Connection -> UDSServer` call cycles.
- [ ] Assert an evicted socket cannot issue another request even if a complete frame was queued, and the client receives at most a sanitized revocation error before close.
- [ ] Rerun focused tests and commit with `feat(agent): evict in-flight application sessions`.

## Task 5: Push and consume Core runtime notifications

**Files:**

- Modify: `apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex`
- Modify: `apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/connection.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/lease_renewer.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/connection_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/lease_renewer_test.exs`

- [ ] Add channel tests proving `{:secrethub_agent_message, envelope}` becomes `push(socket, envelope.event, envelope.payload)` only for a registered trusted connection.
- [ ] Add Agent tests for duplicate/unknown events, monotonic rotation revision, policy scope, app status/assignment, exact certificate supersession, and lease terminal state.
- [ ] Add `handle_info({:secrethub_agent_message, %{event: event, payload: payload}}, socket)` with an explicit allowed-event set; reject unexpected maps instead of atomizing input.
- [ ] On `secret:rotated`, call `Cache.invalidate_path(path, revision)`; on policy update, clear affected app scopes or all entries.
- [ ] On app suspension/revocation/reassignment, cast application eviction; on certificate revocation/supersession, cast eviction for only the old fingerprint. Clear affected scope without evicting unrelated apps or replacement-certificate connections.
- [ ] Route `lease:updated` to LeaseRenewer's metadata tracker; terminal states untrack the public lease ID. Dynamic credential values never enter static Cache.
- [ ] Rerun focused tests and commit with `feat(agent): consume runtime invalidation events`.

## Task 6: Reconcile cache on reconnect and adversarial event ordering

**Files:**

- Modify: `apps/secrethub_agent/lib/secrethub_agent/connection.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/connection_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/cache_test.exs`
- Modify: `apps/secrethub_web/test/e2e/core_agent_flow_test.exs`

- [ ] Add a test that every normal runtime rejoin calls `Cache.clear_entries/0` while preserving rotation tombstones and incrementing scope generations.
- [ ] Add adversarial sequences: response(r3) races rotation(r4), duplicate rotation(r4), rotation(r5) then delayed r4, delete/recreate at a higher revision, missed notification across disconnect, policy denial during in-flight read, and app revocation during queued UDS request.
- [ ] Prove all sequences either release the value authorized at Core's linearization point or fail closed; none release a cache-only value.
- [ ] Run focused tests, then the cache/runtime cases in `core_agent_flow_test.exs`.
- [ ] Run `devenv shell -- test-all apps/secrethub_agent/test/secrethub_agent/cache_test.exs apps/secrethub_agent/test/secrethub_agent/template_renderer_test.exs apps/secrethub_agent/test/secrethub_agent/uds_server_test.exs apps/secrethub_agent/test/secrethub_agent/uds_server_static_read_test.exs apps/secrethub_agent/test/secrethub_agent/connection_test.exs apps/secrethub_agent/test/secrethub_agent/lease_renewer_test.exs apps/secrethub_core/test/secrethub_core/agent_notifications_test.exs apps/secrethub_core/test/secrethub_core/agents/connection_manager_test.exs apps/secrethub_core/test/secrethub_core/secrets_test.exs apps/secrethub_core/test/secrethub_core/policies_test.exs apps/secrethub_core/test/secrethub_core/apps_test.exs apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs`.
- [ ] Run format check, compile with warnings as errors for the changed apps, Credo, and `git diff --check`.
- [ ] Commit with `test(agent): verify cache invalidation ordering`.
