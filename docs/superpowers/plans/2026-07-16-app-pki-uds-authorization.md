# Application PKI, UDS Proof, and Core Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Authenticate every local application by possession of a canonical Core-issued private key and make Core atomically enforce Agent, application, certificate, and policy authorization before releasing a static secret or accepting a dynamic lifecycle intent.

**Architecture:** Move application issuance/renewal/revocation into one transactional Core context, introduce a canonical DER fingerprint, and deploy a strict UDS auth-v2 challenge/proof state machine. The trusted Agent socket supplies Agent identity; Core resolves application identity from the presented fingerprint and evaluates Agent and app policies as separate fail-closed gates under authorization-version locks.

**Tech Stack:** Elixir/OTP `:public_key` and `:crypto`, Ecto/PostgreSQL, Phoenix Router/Channels, Unix domain sockets, ExUnit, SecretHub audit/vault contexts, devenv.

---

## Preconditions and Non-Negotiable Invariants

- Follow `docs/superpowers/specs/2026-07-16-agent-security-secret-lifecycle-design.md`.
- Preserve current newline-delimited framing; framed protocol work remains out of scope.
- The socket is not TLS. Filesystem permissions provide local confidentiality; auth v2 provides application private-key possession.
- Do not enable strict v2 cutover until the legacy-certificate preflight reports zero active noncanonical certificates.
- Treat the Core `UpgradeGates` row—not Agent-local configuration—as the production authority for the minimum UDS authentication version.
- Do not trust `application_id`, Agent ID, or fingerprint merely because the Agent sent them. Agent ID comes from the mTLS socket; app and certificate come from the canonical fingerprint association.

## Exact cryptographic wire encoding

All binary JSON fields below use standard RFC 4648 Base64 with padding. Canonical signed fields use `u32` unsigned big-endian byte lengths followed by the exact field bytes.

UDS auth-v2 algorithm identifiers are exactly `rsa-pss-sha256` and `ecdsa-sha256`. The transcript is:

```text
lp("secrethub-uds-auth")
|| lp(0x02)
|| lp(signature_algorithm UTF-8)
|| lp(agent_public_id UTF-8)
|| lp(connection_id UTF-8)
|| lp(challenge_id UTF-8)
|| lp(32 raw nonce bytes)
|| lp(32 raw DER-SHA256 fingerprint bytes)
|| lp("authenticate")
```

where `lp(bytes) = <<byte_size(bytes)::unsigned-big-32, bytes::binary>>`. RSA uses PSS/SHA-256, MGF1-SHA-256, and a 32-byte salt; ECDSA uses SHA-256 and DER-encoded signatures.

```json
{"request_id":"frame-1","action":"authenticate","params":{"auth_version":2,"certificate":"<base64 PEM bytes>"}}
{"request_id":"frame-1","status":"ok","data":{"auth_version":2,"agent_id":"agent-public-id","connection_id":"uuid","challenge_id":"uuid","challenge":"<base64 32 bytes>","certificate_fingerprint":"64-lowercase-hex","signature_algorithm":"rsa-pss-sha256","expires_at":"RFC3339"}}
{"request_id":"frame-2","action":"authenticate_proof","params":{"auth_version":2,"connection_id":"uuid","challenge_id":"uuid","signature_algorithm":"rsa-pss-sha256","signature":"<base64 signature>"}}
```

App renewal uses domain `secrethub-app-cert-renewal-v1` and the same `lp/1` encoding over: domain, app UUID UTF-8, current raw fingerprint, new CSR raw SHA-256, request ID UTF-8, and raw SHA-256 of canonical JSON containing only `app_id`, `current_fingerprint`, `csr_sha256`, and `request_id` with lexicographically sorted keys and no insignificant whitespace.

```json
{"app_id":"uuid","current_fingerprint":"64-lowercase-hex","csr":"<base64 PEM bytes>","request_id":"uuid","signature_algorithm":"ecdsa-sha256","proof":"<base64 signature>"}
```

Protocol error strings are the approved uppercase codes; adapters never return `inspect(reason)` or crypto/database details.

## Task 1: Expand canonical certificate and idempotency storage

**Files:**

- Create: `apps/secrethub_core/priv/repo/migrations/20260716000100_expand_app_certificate_security.exs`
- Create: `apps/secrethub_core/priv/repo/migrations/20260716000200_create_app_certificate_renewals.exs`
- Create: `apps/secrethub_shared/lib/secrethub_shared/schemas/app_certificate_renewal.ex`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/certificate.ex`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/app_bootstrap_token.ex`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/application.ex`
- Create: `apps/secrethub_core/test/secrethub_core/pki/app_certificate_migration_test.exs`

- [ ] Write a migration test asserting a nullable `certificates.canonical_fingerprint` stores exactly 64 lowercase hex characters and has a partial unique index `WHERE canonical_fingerprint IS NOT NULL`.
- [ ] Run `devenv shell -- test-all apps/secrethub_core/test/secrethub_core/pki/app_certificate_migration_test.exs`; expect failure because the columns/tables do not exist.
- [ ] Add `canonical_fingerprint`, `app_bootstrap_tokens.issuance_request_id`, and `app_bootstrap_tokens.issued_certificate_id`; keep legacy `fingerprint` intact for the expand release.
- [ ] Add `app_certificate_renewals` with app/current/issued certificate FKs, unique `(app_id, request_id)`, original fingerprint, CSR SHA-256, normalized-payload SHA-256, proof bytes/algorithm, and timestamps.
- [ ] Add and validate changesets; reject noncanonical fingerprints and unsupported proof algorithm names before database access.
- [ ] Add a `NOT VALID` FK constraint from the existing non-null `applications.agent_id` column to `agents.id`, keep its ordinary many-apps-per-Agent index, preflight orphan rows, and validate the FK only after the orphan count reaches zero.
- [ ] Rerun the focused test and require zero failures.
- [ ] Run `devenv shell -- mix format apps/secrethub_shared/lib/secrethub_shared/schemas/{certificate,app_bootstrap_token,application,app_certificate_renewal}.ex apps/secrethub_core/priv/repo/migrations/20260716000{100_expand_app_certificate_security,200_create_app_certificate_renewals}.exs`.
- [ ] Commit with `feat(core): expand application certificate security data`.

## Task 2: Centralize canonical fingerprint parsing and upgrade preflight

**Files:**

- Create: `apps/secrethub_core/lib/secrethub_core/pki/certificate_identity.ex`
- Create: `apps/secrethub_core/lib/secrethub_core/pki/app_certificate_preflight.ex`
- Create: `apps/secrethub_core/test/secrethub_core/pki/certificate_identity_test.exs`
- Create: `apps/secrethub_core/test/secrethub_core/pki/app_certificate_preflight_test.exs`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/certificate.ex`

- [ ] Write tests proving PEM → DER → SHA-256 returns lowercase unseparated hex and `decode_fingerprint!/1` returns the canonical 32 bytes.
- [ ] Add tests rejecting colon-delimited, uppercase, malformed PEM, wrong CN, missing/wrong URI SAN, missing `clientAuth`, wrong organization, and entity mismatch.
- [ ] Run both focused files; expect missing-module failures.
- [ ] Implement this public interface:

  ```elixir
  canonical_fingerprint_from_pem(pem) :: {:ok, binary()} | {:error, atom()}
  canonical_fingerprint_from_der(der) :: binary()
  decode_fingerprint(fingerprint) :: {:ok, <<_::256>>} | {:error, :invalid_fingerprint}
  validate_app_certificate(pem_or_der, expected_app_id) :: {:ok, metadata} | {:error, atom()}
  ```

- [ ] Keep `Certificate.fingerprint/1` only as legacy compatibility during expand; route every new authorization write/read through `canonical_fingerprint`.
- [ ] Implement `AppCertificatePreflight.report/0` returning structured rows for malformed PEM, canonical fingerprint mismatch/collision, missing EKU/SAN, name-based identity, entity mismatch, expired/revoked association mismatch, and orphan Agent assignment.
- [ ] Implement `backfill_canonical_fingerprints/0` as batched runtime code with row locks; abort on malformed/collision rows and never rewrite audit events.
- [ ] Rerun both focused files and `devenv shell -- test-all apps/secrethub_core/test/secrethub_core/pki/`.
- [ ] Commit with `feat(core): add canonical certificate identity preflight`.

## Task 3: Implement transactional canonical app issuance

**Files:**

- Create: `apps/secrethub_core/lib/secrethub_core/pki/app_certificates.ex`
- Create: `apps/secrethub_core/test/secrethub_core/pki/app_certificates_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/pki/ca.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/apps.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/controllers/pki_controller.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/router.ex`
- Modify: `apps/secrethub_web/test/secrethub_web_web/controllers/pki_controller_test.exs`
- Modify: `apps/secrethub_web/test/secrethub_web_web/plugs/rate_limiter_test.exs`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/audit_log.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/audit_test.exs`

- [ ] Write Core tests for valid RSA-2048, RSA-too-small, ECDSA P-256/P-384, unsupported curve, invalid CSR signature, and hostile CSR CN/SAN/EKU fields.
- [ ] Assert issued identity is always CN app UUID, organization `SecretHub Applications`, URI SAN `urn:secrethub:app:<uuid>`, EKU `clientAuth`, key usage `digitalSignature`, `entity_id` app UUID, `entity_type` `app`, and `cert_type` `app_client`.
- [ ] Add transaction fault tests before certificate insert, association insert, and token consumption; assert no tracked partial result and token remains unused.
- [ ] Add lost-response replay tests: same token/request ID returns the original result, different request ID returns `IDEMPOTENCY_CONFLICT`.
- [ ] Add sanitized audit tests for issuance allowed/denied/failed. Success is inserted in the issuance transaction; denial/failure is recorded after rollback without CSR, PEM, token, proof, or private material. Extend the restrictive audit event allowlist with exact app-certificate lifecycle event names.
- [ ] Run the Core test; expect current controller/context sequencing and CSR identity reuse to fail.
- [ ] Implement `AppCertificates.issue_from_bootstrap(token, csr_pem, request_id)` using one `Repo.transaction`, `FOR UPDATE` token locking, Agent assignment validation, verified CSR public key, Core-owned identity/extensions, association insert, and final token consumption.
- [ ] Add a dedicated rate-limited app-certificate pipeline/route that does not use normal Vault-token authentication; issuance accepts only token, CSR, and request ID. Remove the legacy issuance route from the Vault-token scope so there is no second sequencing/bypass path.
- [ ] Make `PKIController.issue_app_certificate/2` a thin error-mapping adapter; remove separate validate/issue/associate sequencing.
- [ ] Rerun focused Core/controller/rate-limiter tests; assert stable error codes and no private material in logs.
- [ ] Commit with `feat(core): issue canonical application certificates`.

## Task 4: Implement proof-bound app renewal and atomic revocation

**Files:**

- Modify: `apps/secrethub_core/lib/secrethub_core/pki/app_certificates.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/apps.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/controllers/pki_controller.ex`
- Modify: `apps/secrethub_web/lib/secret_hub/web/router.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/pki/app_certificates_test.exs`
- Modify: `apps/secrethub_web/test/secrethub_web_web/controllers/pki_controller_test.exs`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/audit_log.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/audit_test.exs`

- [ ] Add tests for the domain-separated renewal payload containing app ID, current raw fingerprint, new CSR digest, request ID, and normalized request fields.
- [ ] Add valid RSA-PSS/ECDSA renewal, wrong-key, expired/revoked current cert, changed payload replay, and lost-response replay after old cert becomes superseded.
- [ ] Add revocation consistency tests proving association and underlying certificate change in one transaction for `superseded`, `compromised`, `operator_revoked`, and `app_suspended`.
- [ ] Add sanitized audit tests for renewal/replay/denial/revocation/failure; no CSR, PEM, signature/proof, bootstrap token, or key material may enter audit metadata.
- [ ] Run focused tests and capture failures.
- [ ] Implement `renew/1` so idempotency lookup precedes current-status validation; for an existing record, verify the original proof against the stored original certificate and return only an exact replay.
- [ ] For a new renewal, verify the current certificate/proof, issue canonical replacement, insert renewal result, and mark old association plus certificate revoked as `superseded` in one transaction.
- [ ] Move app renewal onto the dedicated rate-limited proof-authenticated app-certificate route; it must not require or accept a Vault token as a substitute for current-private-key proof. Keep operator revocation on the authenticated administration surface.
- [ ] Implement `revoke/3` and `revoke_all/2` in the same context and make `Apps` delegate to it. Expose sanitized lifecycle results/events; the later dynamic plan adds transactional lease-cleanup intent once that interface exists, so this slice never references a not-yet-defined dynamic module.
- [ ] Rerun focused tests and commit with `feat(core): secure application certificate renewal`.

## Task 5: Add strict UDS authentication transcript primitives

**Files:**

- Create: `apps/secrethub_agent/lib/secrethub_agent/uds_auth.ex`
- Create: `apps/secrethub_agent/test/secrethub_agent/uds_auth_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/cert_verifier.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/runtime_bootstrapper.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/application.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/uds_server.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/runtime_bootstrapper_test.exs`
- Create: `apps/secrethub_agent/test/secrethub_agent/uds_server_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs`

- [ ] Add exact transcript-vector tests for fixed unsigned big-endian length prefixes over `secrethub-uds-auth`, auth version, algorithm, Agent ID, connection ID, challenge ID, raw nonce, raw fingerprint, and `authenticate`.
- [ ] Add RSA-PSS/SHA-256 with 32-byte salt and ECDSA/SHA-256 DER-signature tests, including tampered field and wrong-key failures.
- [ ] Add certificate verifier tests for missing CA, self-signed leaf, invalid chain, expiry, missing `clientAuth`, noncanonical CN/SAN, and CA-unavailable-before-enrollment.
- [ ] Run focused tests and expect current mock-CA behavior to fail.
- [ ] Implement `UDSAuth.new_challenge/3`, `transcript/1`, `verify_proof/3`, and algorithm selection from the certificate public-key type.
- [ ] Change CertVerifier to start in an explicit unavailable state, support `configure_trust(ca_chain)` after persisted material loads/enrollment completes, and delete mock CA insertion. Before trust is configured, UDS stays live but every authentication attempt fails closed as `CA_UNAVAILABLE`.
- [ ] Wire RuntimeBootstrapper to install/reload the persisted CA chain into the live verifier both on ready-state boot and immediately after enrollment material commits. Test pre-enrollment `CA_UNAVAILABLE` and post-enrollment authentication without restarting UDSServer.
- [ ] Return validated app ID, parsed public key, and canonical fingerprint from certificate verification; do not mark the socket authenticated yet.
- [ ] Rerun focused tests and commit with `feat(agent): verify application key possession`.

## Task 6: Replace one-message UDS authentication with auth v2 state machine

**Files:**

- Modify: `apps/secrethub_agent/lib/secrethub_agent/uds_server.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/uds_server_test.exs`
- Modify: `apps/secrethub_cli/lib/secrethub_cli/agent_client.ex`
- Modify: `apps/secrethub_cli/lib/secrethub_cli.ex`
- Modify: `apps/secrethub_cli/test/secrethub_cli/agent_client_test.exs`
- Modify: `apps/secrethub_cli/test/secrethub_cli/commands/secret_commands_test.exs`

- [ ] Write socket tests for missing/unsupported version, legacy auth, proof required, expired challenge, echoed-field mismatch, same-socket replay, cross-socket replay, cross-Agent replay, re-authentication, oversized frame, and bounded failed attempts.
- [ ] Assert challenge nonce is 32 random bytes, expiry is at most 30 seconds, one outstanding challenge exists, and any failed/expired/replayed proof closes the connection.
- [ ] Run the new UDS test and expect failure against current one-message authentication.
- [ ] Deploy the complete v2 state machine in dual-accept expand mode. The legacy handler remains reachable only while the monotonic Core-issued minimum authentication version is `1`; once that floor becomes `2`, one-message auth permanently returns `INCOMPATIBLE_VERSION`. Do not add an independently mutable production `:uds_auth_v2_enabled` flag.
- [ ] Give every accepted connection a server-generated connection ID and explicit state `:unauthenticated | {:challenge, challenge} | {:authenticated, principal_claims}`.
- [ ] Cap a newline frame at 64 KiB before JSON decode and reject secret actions until proof succeeds.
- [ ] Implement `authenticate` response fields exactly as approved and atomically consume the connection-owned challenge before setting authenticated state.
- [ ] Update CLI to require `--agent-cert` and `--agent-key`, negotiate auth version 2, sign the returned transcript with the matching private key, and send `authenticate_proof`.
- [ ] Rerun Agent/CLI focused tests and commit with `feat(agent): require signed UDS authentication`.

## Task 7: Expand typed policy bindings and authorization versions

**Files:**

- Create: `apps/secrethub_core/priv/repo/migrations/20260716000300_create_authorization_versions.exs`
- Create: `apps/secrethub_shared/lib/secrethub_shared/schemas/authorization_epoch.ex`
- Create: `apps/secrethub_shared/lib/secrethub_shared/schemas/authorization_subject_version.ex`
- Create: `apps/secrethub_core/lib/secrethub_core/authorization_versions.ex`
- Create: `apps/secrethub_core/test/secrethub_core/authorization_versions_test.exs`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/policy.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/policies.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/policy_evaluator.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/policies_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/apps.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/apps_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/agents.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/agents_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/pki/app_certificates.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/pki/app_certificates_test.exs`
- Modify: `apps/secrethub_core/lib/secrethub_core/pki/ca.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/pki/ca_test.exs`

- [ ] Add migration/context tests for one global epoch and unique typed subject rows `agent:<database_uuid>` and `application:<app_uuid>`.
- [ ] Add preflight tests that deterministically resolve legacy values and report missing or ambiguous Agent/application identifiers without guessing.
- [ ] Add evaluator tests for dot-path normalization, stable operations `read|generate|renew|revoke`, independent gates, explicit deny precedence, and fail-closed malformed/missing condition context.
- [ ] Run the focused tests and capture current fail-open condition behavior.
- [ ] Seed the singleton global epoch and backfill one subject row for every existing Agent/application. Every new Agent/application inserts its subject row in the same creation transaction; no authorization reader may lazily create one.
- [ ] Implement `lock_for_share(repo, agent_id, app_id)` and `bump_subjects(repo, subjects)`; lock global then Agent then app in the same fixed order everywhere.
- [ ] Make app/Agent status, assignment, certificate revocation, policy binding, and scoped policy content writers lock affected version rows `FOR UPDATE` and increment in the same transaction; global policy change increments the global epoch.
- [ ] Preserve `Application.policies` only as transactionally maintained UI compatibility; evaluate authoritative typed `Policy.entity_bindings` once preflight reaches zero.
- [ ] Persist `UpgradeGates` marker `typed_runtime_authorization` only after subject rows, application Agent FK, and typed-binding preflights all report zero.
- [ ] Rerun focused tests and commit with `feat(core): linearize runtime authorization changes`.

## Task 8: Add Core-derived runtime principal and authorized static reads

**Files:**

- Create: `apps/secrethub_core/lib/secrethub_core/runtime_principal.ex`
- Create: `apps/secrethub_core/lib/secrethub_core/runtime_authorization.ex`
- Create: `apps/secrethub_core/test/secrethub_core/runtime_authorization_test.exs`
- Create: `apps/secrethub_core/priv/repo/migrations/20260716000400_create_secret_path_revisions.exs`
- Create: `apps/secrethub_shared/lib/secrethub_shared/schemas/secret_path_revision.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/secrets.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/secrets_test.exs`
- Modify: `apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex`
- Modify: `apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/connection.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs`

- [ ] Add tests for wrong claimed Agent/app, app assigned elsewhere, suspended app, revoked/expired/wrong-type cert, missing active association, Agent deny, app deny, and malformed resource/operation.
- [ ] Add concurrency tests proving a revocation committed before read linearization is observed and a writer blocked behind the reader is ordered after that read.
- [ ] Add a monotonic per-path cache revision row that is locked/incremented in the same transaction as create, update, rollback, rotation, and delete; retain it after delete so recreating the same path receives a higher revision.
- [ ] Assert allow/deny audit actor is application UUID with Agent ID and canonical fingerprint metadata and no secret value.
- [ ] Run focused tests and expect the current Agent-only `secret:read` path to fail them.
- [ ] Implement `resolve_runtime_principal(socket_identity, app_id_claim, fingerprint_claim)` by deriving Agent from the socket and app/cert from canonical association.
- [ ] Implement `authorize_static_read(principal, path, known_revision \\ nil)` in one transaction: shared authorization locks, row locks for app/cert/current secret/path revision, independent policy gates, audit intent, then value/revision or explicit `not_modified` for that exact monotonic revision.
- [ ] Keep system cleanup separate from access grants; do not let this principal API authorize safety cleanup.
- [ ] Change `AgentRuntimeChannel` `secret:read` to accept the two claims plus normalized path and optional `known_revision`, call the new context, and map only stable public errors.
- [ ] Update `Connection.get_static_secret` to forward authenticated app claims; do not accept caller-provided Agent ID.
- [ ] Rerun focused Core/channel/Agent tests and commit with `feat(core): authorize application runtime reads`.

## Task 9: Gate cutover and verify the slice

**Files:**

- Create: `apps/secrethub_core/priv/repo/migrations/20260716000500_add_agent_runtime_capabilities.exs`
- Modify: `apps/secrethub_shared/lib/secrethub_shared/schemas/agent.ex`
- Modify: `apps/secrethub_core/lib/secrethub_core/upgrade_gates.ex`
- Modify: `apps/secrethub_core/test/secrethub_core/upgrade_gates_test.exs`
- Modify: `apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex`
- Modify: `apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/connection.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/identity_store.ex`
- Modify: `apps/secrethub_agent/lib/secrethub_agent/uds_server.ex`
- Modify: `apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/identity_store_test.exs`
- Modify: `apps/secrethub_agent/test/secrethub_agent/uds_server_test.exs`
- Modify: `docs/architecture/app-certificate-issuance.md`
- Modify: `docs/agents/trusted-agent-connection.md`

- [ ] Add explicit `agents.runtime_capabilities` and `runtime_capabilities_seen_at` columns. On every trusted normal join the Agent advertises `uds_auth_v2`; Core records only its authenticated Agent's normalized capability set and freshness, never caller-selected identity.
- [ ] Add concurrency tests for one Core-owned `activate_app_certificate_v2/1` operation. In one database transaction it requires zero canonical-certificate findings, verified `typed_runtime_authorization`, and `uds_auth_v2` on every fresh active Agent; stale or intentionally retired Agents require the same explicit acknowledgement discipline as stale cluster nodes. It then persists the irreversible `app_certificate_v2` gate/floor.
- [ ] Make every Agent-originated static or dynamic application request carry `local_auth_version` derived by UDSServer from its connection state. After gate activation Core rejects missing/v1 values with `INCOMPATIBLE_VERSION` before authorization, so a delayed or lost notification cannot create an authorization bypass.
- [ ] After commit, broadcast the new floor. Connection atomically persists the maximum observed floor in trusted state before acknowledging it and updates UDSServer; rollback, restart, stale messages, or local application config cannot lower it. Runtime join replies always include the current floor, and Core rejects an incapable Agent's normal join after cutover.
- [ ] Test expand deployment with a dual-accept capable Agent, an incapable/stale Agent blocking activation, blocked cutover with legacy rows, successful reissue/backfill, a request in the notification race window, reconnect after a lost broadcast, restart from the persisted floor, and permanent v1 rejection.
- [ ] Record the future contract-release predicates and destructive changes, but do not create a contract migration in this implementation branch. A separately reviewed later-release plan may drop legacy authorization use only after every deployed node advertises canonical capability and the zero-count preflight is rerun.
- [ ] Run `devenv shell -- test-all apps/secrethub_core/test/secrethub_core/upgrade_gates_test.exs apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs apps/secrethub_agent/test/secrethub_agent/identity_store_test.exs apps/secrethub_agent/test/secrethub_agent/uds_server_test.exs`.
- [ ] Run `devenv shell -- test-all apps/secrethub_core/test/secrethub_core/pki/ apps/secrethub_core/test/secrethub_core/authorization_versions_test.exs apps/secrethub_core/test/secrethub_core/runtime_authorization_test.exs apps/secrethub_core/test/secrethub_core/policies_test.exs`.
- [ ] Run `devenv shell -- test-all apps/secrethub_agent/test/secrethub_agent/uds_auth_test.exs apps/secrethub_agent/test/secrethub_agent/uds_server_test.exs apps/secrethub_agent/test/secrethub_agent/connection_protocol_test.exs`.
- [ ] Run `devenv shell -- test-all apps/secrethub_cli/test/secrethub_cli/agent_client_test.exs apps/secrethub_cli/test/secrethub_cli/commands/secret_commands_test.exs apps/secrethub_web/test/secrethub_web/channels/agent_runtime_channel_test.exs`.
- [ ] Run format check, compile with warnings as errors, Credo for changed modules, and `git diff --check`.
- [ ] Commit docs/gate changes with `docs(agent): document application proof cutover`.
