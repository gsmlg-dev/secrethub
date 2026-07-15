# Agent Certificate Renewal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Renew Agent mTLS certificates before expiry without transferring private keys to Core or creating a restart window in which neither old nor new material can connect.

**Architecture:** Add explicit Agent-certificate bindings and a persisted two-phase generation workflow. RuntimeBootstrapper creates and fsyncs candidate key/CSR material, Core issues a pending binding, a second restricted mTLS connection validates it, Core atomically activates it while retaining the old binding for bounded rollback, and only a successful normal runtime join finalizes/revokes the old certificate.

**Tech Stack:** Elixir/OTP GenServer and supervision, Ecto/PostgreSQL, Phoenix sockets/channels over mTLS, X.509/PKIX, atomic filesystem persistence, ExUnit, devenv.

---

## Dependencies and invariants

- Start after the startup plan establishes one RuntimeBootstrapper and secure atomic state/generation persistence.
- Reuse the canonical DER SHA-256 fingerprint from the app-PKI plan.
- A `pending_validation` binding has no runtime, heartbeat, static-secret, dynamic-secret, or lease privilege.
- An expired/revoked current certificate cannot request renewal or automatic enrollment. Return `RE_ENROLLMENT_REQUIRED` and require host-identity enrollment plus operator approval.
- RuntimeBootstrapper is the sole renewal scheduler/coordinator; Connection remains a low-level socket/RPC client.

## Exact channel events

Normal `agent:runtime` connections expose:

```text
agent:certificate_renew_request {renewal_id, csr}
agent:certificate_renew_status  {renewal_id}
agent:certificate_finalize      {renewal_id}
agent:certificate_rollback      {renewal_id}
```

Core derives Agent, current binding, and certificate IDs exclusively from socket assigns. Only `renew_request` carries Base64 PEM CSR bytes. Status/finalize/rollback carry no certificate identity claims. An eligible active or retiring normal binding may query/recover its own renewal; finalization is accepted only from the newly active candidate after Core recorded that normal join.

Restricted `agent:renewal_validation` exposes only:

```text
agent:certificate_status   {renewal_id}
agent:certificate_activate {renewal_id}
agent:certificate_rollback {renewal_id}
```

The candidate binding/Agent come from the validation socket. All replies use stable uppercase error codes and omit CSR/private-key material.

## Task 1: Expand Agent certificate binding storage and backfill

**Files:**

- Create: `apps/secrethub_core/priv/repo/migrations/20260716020100_create_agent_certificate_bindings.exs`
- Create: `apps/secrethub_shared/lib/secrethub_shared/schemas/agent_certificate_binding.ex`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/agent.ex`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/agent_enrollment.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/agents/enrollment.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/agents/enrollment_test.exs`
- Create: `apps/secrethub_core/lib/secrethub_core/agents/certificate_binding_preflight.ex`
- Create: `apps/secrethub_core/test/secrethub_core/agents/certificate_binding_preflight_test.exs`

- [ ] Write migration/schema tests for states `pending_validation`, `active`, `retiring`, and `revoked`; Agent/certificate FKs; renewal ID; mandatory `retire_until` for retiring; transition timestamps; revocation reason; and unique Agent/certificate association.
- [ ] Assert unique `(agent_id, renewal_id)` plus partial unique indexes permit at most one binding in each of `active`, `pending_validation`, and `retiring` per Agent. The state model may contain active+pending during validation or active+retiring during rollback, but never two concurrent rollover workflows.
- [ ] Add preflight tests that one valid current `agents.certificate_id` becomes one active binding and missing, wrong-entity, revoked, expired, host-mismatched, or duplicate pointers block backfill.
- [ ] Run `devenv shell -- test-all apps/secrethub_core/test/secrethub_core/agents/certificate_binding_preflight_test.exs`; expect missing table/module failure.
- [ ] Add the table/schema without removing `agents.certificate_id`; it remains a transactionally updated compatibility pointer.
- [ ] In the expand release, make successful initial enrollment issuance atomically insert an `active` binding and update `agents.certificate_id`; new enrollments must dual-write before backfill begins so they cannot race behind it.
- [ ] Implement batched runtime backfill with row locks and structured failure report; do not invent replacement certificates for invalid rows.
- [ ] Persist the shared `UpgradeGates` marker `agent_certificate_bindings` only after backfill/preflight reaches zero. Verifier remains in dual-read compatibility mode until that marker is verified, then binding state becomes authoritative.
- [ ] Rerun focused tests and commit with `feat(core): expand agent certificate bindings`.

## Task 2: Add Core renewal state transitions and idempotent issuance

**Files:**

- Create: `apps/secrethub_core/lib/secrethub_core/agents/certificate_renewal.ex`
- Create: `apps/secrethub_core/test/secrethub_core/agents/certificate_renewal_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/pki/issuer.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/agents.ex`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/audit_log.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/audit_test.exs`

- [ ] Add tests for `request_candidate(agent_id, current_certificate_id, renewal_id, csr_pem)`: current binding must be active, unexpired/unrevoked, same host identity, CSR signature/key strength valid, and candidate identity/extensions Core-owned.
- [ ] Add exact idempotency and concurrency tests: same Agent/renewal ID/CSR digest returns the same candidate/result; changed CSR returns `IDEMPOTENCY_CONFLICT`; simultaneous distinct renewal IDs create one candidate while the loser returns `RENEWAL_IN_PROGRESS`.
- [ ] Add transition tests for validate, activate, finalize, and rollback, including duplicate calls returning their stored result and a second renewal being rejected until the first pending/retiring workflow reaches a terminal state.
- [ ] Add sanitized audit tests and allowlist entries for renewal requested/candidate issued/denied/failed, validation, activation, finalization, rollback, expiry/re-enrollment-required, and revocation. Never include CSR, certificate PEM, or private material.
- [ ] Run the focused file and expect missing-context failure.
- [ ] Implement candidate issuance without receiving/storing the private key; bind certificate SAN/entity metadata to the same Agent and enrolled SSH-host-key fingerprint.
- [ ] Serialize every mutating transition by locking the Agent row and all of its nonrevoked bindings in a fixed order. Under that lock, resolve exact idempotent replay first; otherwise reject `request_candidate` while any `pending_validation` or `retiring` binding exists. Database partial indexes remain the final race guard.
- [ ] Implement these public transitions:

  ```elixir
  request_candidate(agent_id, current_certificate_id, renewal_id, csr_pem)
  candidate_status(agent_id, renewal_id)
  mark_validated(agent_id, candidate_certificate_id, renewal_id)
  activate(agent_id, candidate_certificate_id, renewal_id)
  finalize(agent_id, candidate_certificate_id, renewal_id)
  rollback(agent_id, candidate_certificate_id, renewal_id)
  ```

- [ ] Activation transaction rechecks exactly one old active and one matching pending candidate, then updates old active → retiring with bounded `retire_until`, candidate pending → active, and `agents.certificate_id` → candidate in uniqueness-safe order. Finalize or rollback must consume the sole retiring workflow before another request can start.
- [ ] Finalization requires evidence of an accepted normal runtime join using the candidate, then revokes the retiring certificate/binding atomically.
- [ ] Rerun focused tests and commit with `feat(core): manage agent certificate rollover state`.

## Task 3: Restrict pending candidates to a validation topic

**Files:**

- Modify: `apps/secrethub_core/lib/secrethub_core/pki/verifier.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/channels/agent_trusted_socket.ex`
- Create: `apps/secrethub_web/lib/secret_hub/web/channels/agent_renewal_validation_channel.ex`
- Create: `apps/secrethub_web/test/secrethub_web/channels/agent_renewal_validation_channel_test.exs`
- Modify: `apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex`
- Modify: `apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/audit_log.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/audit_test.exs`

- [ ] Add socket/channel tests proving pending candidates may complete the TLS handshake/connect but may join only `agent:renewal_validation` for their own Agent/renewal ID.
- [ ] Assert candidate attempts to join `agent:runtime`, heartbeat, read/generate/renew/revoke/list leases, or send operational events all fail without registering a normal connection.
- [ ] Assert active bindings join runtime; bounded retiring bindings may join/resume only during their stored window; expired deadline/revoked cert fails.
- [ ] Run focused tests and capture current verifier's single-pointer behavior.
- [ ] Have `Verifier.verify_agent_certificate/2` return binding ID/state and identity metadata after chain/EKU/SAN/host checks; do not equate transport acceptance with runtime authorization.
- [ ] Register both topics on AgentTrustedSocket. In validation join, match peer candidate certificate/Agent to the stored renewal and call `mark_validated/3`.
- [ ] Allow validation RPCs only for status and activation/rollback of that exact renewal. Never register the validation PID in normal `ConnectionManager`.
- [ ] Implement the exact restricted events above and audit validation/activation/rollback outcomes using only IDs, binding state, and sanitized reason codes.
- [ ] Make RuntimeChannel join reauthorize binding state and, on candidate normal join after activation, persist the evidence needed for finalization.
- [ ] Rerun focused tests and commit with `feat(web): isolate agent renewal validation channel`.

## Task 4: Persist atomic Agent certificate generations

**Files:**

- Create: `apps/secrethub_agent/lib/secrethub_agent/identity_generation_store.ex`
- Create: `apps/secrethub_agent/test/secrethub_agent/identity_generation_store_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/identity_store.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/identity_store_test.exs`

- [ ] Add tests for this layout under the configured state directory:

  ```text
  generations/<generation-id>/
    private_key.pem
    csr.pem
    certificate.pem
    ca_chain.pem
    metadata.json
  current-generation
  ```

- [ ] Test pending generation creation, completion, ready rename, atomic current-pointer switch, old-generation retention, cleanup after finalization, and restart selection of the last fully committed generation.
- [ ] Add crash-injection tests after every file write/fsync/rename/pointer step and symlink/mode/ownership rejection.
- [ ] Run focused tests and expect missing generation API.
- [ ] Implement owner-only generation directories/private keys, atomic regular-file pointer update (not an unchecked symlink), file and directory fsync, and strict metadata schema including renewal ID/state/fingerprint.
- [ ] Never overwrite the current generation in place; keep the known-good old generation until Core finalization or confirmed rollback.
- [ ] Make legacy flat IdentityStore material import once into an initial generation during expand, preserving a rollback-safe backup until verified.
- [ ] Rerun focused tests and commit with `feat(agent): persist atomic certificate generations`.

## Task 5: Schedule and request renewal from RuntimeBootstrapper

**Files:**

- Modify: `apps/secrethub_agent/lib/secrethub_agent/runtime_bootstrapper.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/runtime_bootstrapper_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/connection.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/tls_identity.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/tls_identity_test.exs`
- Modify: `apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex`
- Modify: `apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs`

- [ ] Add scheduling tests at approximately 70% of certificate lifetime with bounded jitter, immediate resume for persisted nonterminal renewal, and no renewal scheduling for expired/revoked material.
- [ ] Add tests that a new TLS private key/CSR is generated locally, renewal ID and pending generation are fsynced before RPC, and retry reuses both.
- [ ] Add stable `RE_ENROLLMENT_REQUIRED` tests when current cert is expired/revoked; prove RuntimeBootstrapper does not call Enrollment automatically.
- [ ] Run focused tests and capture missing renewal ownership.
- [ ] Add low-level Connection RPCs for the exact `renew_request`, `renew_status`, `finalize`, and `rollback` events; implement matching RuntimeChannel handlers that derive identity from socket assigns. Keep scheduling/state decisions out of Connection.
- [ ] Add lost-response tests for request/status/finalize and post-activation restart recovery through an eligible retiring connection.
- [ ] Extend RuntimeBootstrapper state with timer, renewal ID, candidate generation, phase, old generation, and rollback deadline; persist every externally visible phase before advancing.
- [ ] On successful candidate response, verify returned certificate matches local CSR key and expected canonical Agent identity before completing/fsyncing the pending generation.
- [ ] Rerun focused tests and commit with `feat(agent): persist and request certificate renewal`.

## Task 6: Validate, activate, and switch to the candidate generation

**Files:**

- Modify: `apps/secrethub_agent/lib/secrethub_agent/trusted_connection.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/connection.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/runtime_bootstrapper.ex`
- Create: `apps/secrethub_agent/lib/secrethub_agent/runtime_connection_router.ex`
- Create: `apps/secrethub_agent/test/secrethub_agent/runtime_connection_router_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/application.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/uds_server.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/lease_renewer.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/agents/connection_manager.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/agents/connection_manager_test.exs`
- Modify: `apps/secrethub_web/lib/secret_hub/web/channels/agent_trusted_socket.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/trusted_connection_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/connection_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/runtime_bootstrapper_test.exs`

- [ ] Add tests that the candidate opens a distinct restricted connection, joins validation, persists ready state, requests activation, then atomically switches current-generation pointer.
- [ ] Assert the original normal runtime connection remains up through validation/activation and can resume during the retiring window.
- [ ] Add Core registry tests proving old-retiring and new-active runtime connections may coexist, are keyed by Agent plus certificate/binding ID, and finalization disconnects only the old connection. Update the trusted socket ID to include certificate identity so a candidate/old disconnect cannot target both accidentally.
- [ ] Add Agent tests proving Connection can run as explicitly named primary or unnamed rollover instances; no second process attempts to register the singleton `SecretHub.Agent.Connection` name.
- [ ] Add router tests proving UDS and LeaseRenewer resolve the current primary PID per call, candidate registration does not route traffic, and one atomic promotion switches all new calls while in-flight calls remain bound to their original PID.
- [ ] Add tests for validation rejection, lost activation response, duplicate activation, candidate TLS failure, and crash before/after pointer switch.
- [ ] Run focused tests and capture missing restricted-connection support.
- [ ] Add `TrustedConnection.start_validation/2` using the candidate material and validation topic; do not reuse/mutate the current Connection process's TLS options.
- [ ] Extend Core `ConnectionManager` from one connection per Agent to a bounded per-binding registry with an explicit primary active connection; keep existing single-Agent send APIs targeting the primary unless a certificate-specific disconnect is requested.
- [ ] Start RuntimeConnectionRouter before RuntimeBootstrapper/UDSServer/LeaseRenewer. Replace direct calls to the registered `SecretHub.Agent.Connection` name with router lookup plus connection-generation/PID capture.
- [ ] After Core activation succeeds, persist activation result and deadline, switch pointer, then start a new normal runtime connection from the selected generation.
- [ ] Do not delete the old generation or terminate the old runtime yet.
- [ ] Rerun focused tests and commit with `feat(agent): activate renewed certificate safely`.

## Task 7: Finalize only after the new normal runtime join

**Files:**

- Modify: `apps/secrethub_agent/lib/secrethub_agent/runtime_bootstrapper.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/connection.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/agents/certificate_renewal.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/agents/connection_manager.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/agents/certificate_renewal_test.exs`
- Modify: `apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/runtime_bootstrapper_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/runtime_connection_router_test.exs`

- [ ] Add a test proving validation-topic acceptance alone never finalizes or revokes the old certificate.
- [ ] Add a test proving a normal runtime `accepted` reply with candidate certificate ID triggers idempotent finalization, old-connection disconnect, then old-generation deletion.
- [ ] Add lost-response/restart tests after Core finalization but before local cleanup; status reconciliation must converge without deleting the current candidate.
- [ ] Run the focused tests and capture failures.
- [ ] Include binding/certificate ID in normal join acceptance; RuntimeBootstrapper verifies it equals the candidate before calling finalize.
- [ ] After candidate normal acceptance, atomically promote its PID in RuntimeConnectionRouter, send `agent:certificate_finalize` over that candidate, and retain the old PID only for rollback/disconnect until Core confirms finalization.
- [ ] Finalize Core first, receive/confirm terminal state, disconnect the old runtime, fsync local finalized metadata, then remove the old generation.
- [ ] Insert the sanitized finalization/revocation audit result in the same Core transition transaction; response loss/replay must not duplicate the logical lifecycle event.
- [ ] On channel termination, Core marks the Agent disconnected only when ConnectionManager confirms no accepted active/eligible-retiring binding remains; termination of a stale old socket cannot overwrite new-connected status.
- [ ] Rerun focused tests and commit with `feat(agent): finalize certificate rollover after runtime join`.

## Task 8: Implement bounded rollback and crash recovery matrix

**Files:**

- Modify: `apps/secrethub_core/lib/secrethub_core/agents/certificate_renewal.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/runtime_bootstrapper.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/agents/certificate_renewal_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/runtime_bootstrapper_test.exs`

- [ ] Add Core rollback tests requiring old binding within `retire_until`, unexpired, unrevoked, uncompromised, and same host; reject after deadline or any failed predicate with `RE_ENROLLMENT_REQUIRED`.
- [ ] Add Agent startup recovery tests for crashes before request, after issuance, after validation, after activation, before pointer switch, after pointer switch, after normal join, after Core finalization, and during local cleanup.
- [ ] Assert every converged state has exactly one primary active binding and pointer; at most one bounded retiring binding; no pending candidate with runtime privileges.
- [ ] Run focused tests and capture failures.
- [ ] Eligible rollback atomically changes old retiring → active, candidate active → revoked, and compatibility pointer → old; Agent switches pointer back only after confirmation and then removes candidate.
- [ ] On startup, reconcile persisted phase/generations with `candidate_status/2` before choosing a pointer or retrying a transition. Ineligible rollback fails closed, preserves evidence for operators, stops secret-serving runtime, and enters re-enrollment-required health phase.
- [ ] Audit rollback success/denial and re-enrollment-required outcomes with Agent/binding/certificate IDs and reason codes only.
- [ ] Rerun focused tests repeatedly with `--seed 0`, a random seed, and async concurrency; commit with `test(agent): verify certificate rollover crash recovery`.

## Task 9: Remove the token renewal stub and verify end to end

**Files:**

- Modify: `apps/secrethub_web/lib/secret_hub/web/router.ex`
- Delete: `apps/secrethub_web/lib/secret_hub/web/controllers/agent_cert_controller.ex`
- Create: `apps/secrethub_web/test/secrethub_web_web/controllers/agent_cert_controller_test.exs`
- Modify: `apps/secrethub_web/test/e2e/core_agent_flow_test.exs`
- Modify: `docs/agents/trusted-agent-connection.md`
- Modify: `docs/deploy.md`

- [ ] Add a route test proving the Vault-token-authenticated `/v1/agent/certificate/renew` surface is absent or returns gone—not an advertised 501 renewal mechanism.
- [ ] Add E2E force-renewal coverage: candidate issuance, restricted privileges, activation, new normal join, finalization, restart, and old-certificate rejection.
- [ ] Add E2E rollback-before-deadline and rollback-after-deadline/re-enrollment-required cases.
- [ ] Run `devenv shell -- test-all apps/secrethub_core/test/secrethub_core/agents/certificate_renewal_test.exs apps/secrethub_web/test/secrethub_web/channels/agent_renewal_validation_channel_test.exs apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs apps/secrethub_agent/test/secrethub_agent/identity_generation_store_test.exs apps/secrethub_agent/test/secrethub_agent/runtime_bootstrapper_test.exs`.
- [ ] Run the renewal E2E cases, format check, compile with warnings as errors, Credo, and `git diff --check`.
- [ ] Update docs to state expired cert requires re-enrollment/operator approval and to describe generation persistence/rollback deadline.
- [ ] Commit with `feat(agent): complete automatic certificate rollover`.
