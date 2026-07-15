# Agent Security and Secret Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the production path from a certificate-authenticated local application through SecretHub Agent to Core for authorized static and dynamic secret delivery, durable lifecycle cleanup, and safe Agent certificate rollover.

**Architecture:** Implement five independently verified vertical slices in dependency order. Core remains the authorization and lifecycle authority; the Agent proves local application key possession, forwards claims over its trusted mTLS channel, and never releases cached data without a current Core decision. Database changes use expand/backfill/cutover/contract releases whenever old nodes or plaintext/legacy identity rows could make a one-step migration unsafe.

**Tech Stack:** Elixir 1.18, OTP 28, Phoenix/Channels, Ecto/PostgreSQL 16, Oban, Mint/WebSockex-compatible transport, Unix domain sockets, X.509/PKIX, ExUnit, Bun/Tailwind where admin forms change, Docker/Compose, devenv.

---

## Source of Truth

Implement against the approved design:

- `docs/superpowers/specs/2026-07-16-agent-security-secret-lifecycle-design.md`

Do not restore behavior that the design supersedes:

- no one-message certificate presentation as UDS authentication;
- no peer-credential authorization;
- no cache-only or offline-stale secret release;
- no Vault-token HTTP fallback for Agent secret/lease commands;
- no automatic renewal with an expired Agent certificate;
- no plaintext engine administration or lease credential maps.

## Plan Set and Ownership

Execute each child plan as its own reviewable implementation slice:

1. `docs/superpowers/plans/2026-07-16-app-pki-uds-authorization.md`
   - canonical application certificate lifecycle;
   - signed UDS proof;
   - Core-derived runtime principal;
   - independent Agent/application policy gates;
   - authorization linearization.
2. `docs/superpowers/plans/2026-07-16-agent-startup-packaging.md`
   - deterministic release configuration;
   - secure external host identity;
   - persisted-state boot;
   - socket health and container packaging.
3. `docs/superpowers/plans/2026-07-16-agent-cache-notifications.md`
   - authorized conditional static reads;
   - scoped/versioned Agent cache;
   - Core runtime notifications and tombstones;
   - application connection eviction.
4. `docs/superpowers/plans/2026-07-16-dynamic-secret-lifecycle.md`
   - immutable roles/configuration versions;
   - encrypted leases;
   - fenced PostgreSQL/Redis issue, renew, revoke, and cleanup;
   - Agent/CLI delivery and Oban reconciliation.
5. `docs/superpowers/plans/2026-07-16-agent-certificate-renewal.md`
   - persisted certificate generations;
   - pending validation connection;
   - activation/finalization/rollback;
   - expiry fail-closed behavior.

## Dependency Graph

```text
shared upgrade-gate foundation ----------+------> every expand/backfill/cutover task

app PKI + runtime authorization --------+------> cache/runtime notifications
                                       |
                                       +------> dynamic secret lifecycle

Agent startup + identity persistence ---+------> Agent certificate renewal

all five slices ------------------------------> full clean-boot/lifecycle E2E gate
```

Implement the shared upgrade-gate foundation first. The startup slice may then run in parallel with the app-PKI slice. Cache work starts after the runtime-principal and authorized-static-read interfaces exist. Dynamic work starts after the runtime-principal interface exists; its Core persistence work may proceed in parallel with cache work. Certificate rollover starts after startup establishes the generation-store interface.

## Cross-Plan Contracts

### Runtime principal

The app-PKI plan owns this struct and all validation that creates it:

```elixir
%SecretHub.Core.RuntimePrincipal{
  agent_id: agent_database_uuid,
  application_id: application_uuid,
  certificate_id: certificate_uuid,
  certificate_fingerprint: lowercase_sha256_hex
}
```

Static and explicit dynamic requests accept this struct. Delegated renewal and safety cleanup derive application ownership from the durable lease instead of reconstructing a live application principal.

### Core-to-Agent notification envelope

The cache plan owns this envelope and the channel delivery helpers:

```elixir
%{
  event: "secret:rotated" | "policy:updated" | "application:updated" | "lease:updated",
  payload: map()
}
```

Payloads contain identifiers, paths, versions, and lifecycle state only—never secret values, generated credentials, engine administration credentials, private keys, or renewal proofs.

### Public identifiers

- Use application UUID, Agent database UUID, canonical certificate fingerprint, and public `lease_id` on runtime/UDS/CLI boundaries.
- Keep Ecto primary keys internal.
- Normalize static resources to dot-delimited paths and dynamic resources to `dynamic.<role_name>` before policy evaluation.

### UDS authentication floor

The Core database gate is the only production authority for the minimum accepted UDS authentication version. Agents advertise protocol capabilities on trusted runtime join, derive the authentication version from their own UDS connection state, and attach it to Core requests. Once Core activates auth v2 it rejects every request derived from a v1 local session, even before an Agent receives the post-commit cutover notification; runtime join responses and notifications then monotonically advance capable Agents to v2-only operation. A local environment flag cannot weaken this floor.

## Foundation Task: Persist mechanical upgrade gates and node capabilities

**Files:**

- Create: `apps/secrethub_core/priv/repo/migrations/20260716000010_create_upgrade_gates.exs`
- Create: `apps/secrethub_shared/lib/secrethub_shared/schemas/upgrade_gate.ex`
- Create: `apps/secrethub_core/lib/secrethub_core/upgrade_gates.ex`
- Create: `apps/secrethub_core/lib/mix/tasks/secrethub.upgrade.verify.ex`
- Create: `apps/secrethub_core/test/secrethub_core/upgrade_gates_test.exs`

- [ ] Write tests for named markers `app_certificate_v2`, `typed_runtime_authorization`, `dynamic_secure_storage`, and `agent_certificate_bindings`; only a zero-finding report with a canonical report hash may mark one verified.
- [ ] Add node-capability tests using `cluster_nodes.metadata["capabilities"]`, status, version, and fresh `last_seen_at`: a fresh active node missing the required capability blocks cutover/contract, an explicitly shutdown node does not, and stale-node handling requires an explicit operator acknowledgement recorded in the gate rather than silently ignoring it.
- [ ] Run `devenv shell -- test-all apps/secrethub_core/test/secrethub_core/upgrade_gates_test.exs`; expect missing table/module failure.
- [ ] Implement `verify/3`, `require_verified!/1`, and `require_cluster_capability!/2` with transactionally stored report hash, verifier/version, timestamp, stale-node acknowledgements, and immutable audit event—never row details or secret data.
- [ ] Implement `mix secrethub.upgrade.verify <gate>` to run the gate's registered preflight, print structured unresolved identifiers/counts, and persist verification only at zero. Any contract Mix task must call both gate and fresh-cluster capability checks immediately before DDL.
- [ ] Rerun focused tests and commit with `feat(core): add mechanical upgrade gates`.

## Release and Migration Boundaries

This effort cannot safely collapse every schema change into one deploy.

### Release A: expand and dual-write

- [ ] Add nullable canonical fingerprint, typed identity/version rows, rollover bindings, immutable engine versions, irreversible internal-admin secret classification, encrypted lease fields, and idempotency tables.
- [ ] Write new rows in canonical/encrypted form while old read paths remain deployable where the design permits it.
- [ ] Add preflight/reporting functions and tests; do not delete or silently coerce unresolved rows.

### Operator backfill gate

- [ ] Run the canonical certificate preflight and reissue every nonconforming active app certificate with a fresh bootstrap token.
- [ ] Backfill canonical fingerprints from DER and verify uniqueness.
- [ ] Resolve application Agent foreign keys and typed policy bindings; fail on ambiguity.
- [ ] Convert engine and lease sensitive fields through runtime code with the vault unsealed; verify every engine admin reference has internal-only classification, every row containing legacy sensitive data decrypts under record-bound AAD, and every nonterminal lease has one live lifecycle intent.
- [ ] Backfill one active Agent certificate binding for every valid existing `agents.certificate_id` pointer.
- [ ] Record the named `UpgradeGates` marker only after all counts are zero; do not use an ad hoc config flag or handwritten operator assertion.

### Release B: cutover

- [ ] Enable UDS auth v2 and strict canonical app-certificate verification only when the preflight marker is present.
- [ ] Switch runtime reads and lifecycle operations to canonical/typed/encrypted columns.
- [ ] Refuse startup or the affected operation with an operator-facing error if the backfill gate is incomplete.

### Release C: contract

- [ ] Before dropping legacy columns, require the matching node capability on every fresh active cluster node, explicitly resolve/acknowledge stale nodes, and rerun zero-count verification.
- [ ] Remove legacy authorization/fingerprint/plaintext read paths and then add `NOT NULL`, validated foreign keys, and restrictive indexes.
- [ ] Keep historical audit evidence immutable and schema-versioned.

Never put Release C destructive changes in the same migration batch as Release A.

## Execution Discipline

For every task in every child plan:

- [ ] Run the named focused test first and capture the expected failure.
- [ ] Implement only enough production code to make that test pass.
- [ ] Run the entire named slice suite after the focused test passes.
- [ ] Run `devenv shell -- mix format <changed-files>` before committing.
- [ ] Run `git diff --check` and inspect `git diff --stat` plus the relevant diff.
- [ ] Commit at the task boundary using `type(scope): subject`; do not combine unrelated slices.

If a dependency from a listed upstream organization is defective or missing a required feature, follow `AGENTS.md`: identify the upstream repository, create the labeled internal request issue, add the required TODO/workaround marker, and stop only the blocked task when severity is `blocker`.

## Integration Task 1: Compose the clean-boot application path

**Files:**

- Modify: `apps/secrethub_web/test/e2e/core_agent_flow_test.exs`
- Modify: `apps/secrethub_web/test/support/e2e_helpers.ex`
- Modify: `docs/agents/trusted-agent-connection.md`
- Modify: `docs/architecture/app-certificate-issuance.md`
- Modify: `docs/deploy.md`

- [ ] Add an E2E test that boots Core and a full Agent application with an empty temporary state directory, an explicitly provisioned host key, and a temporary UDS path.
- [ ] Run `devenv shell -- test-all apps/secrethub_web/test/e2e/core_agent_flow_test.exs`; verify the new test fails before orchestration is complete.
- [ ] Drive pending enrollment through approval and finalization, issue a canonical app certificate, complete UDS auth v2, and read an allowed static secret.
- [ ] Add negative assertions for copied certificate without key, wrong key, wrong Agent assignment, and independent application policy denial.
- [ ] Rerun the E2E file and require zero failures.
- [ ] Update the two architecture documents so examples match the implemented two-message auth, canonical fingerprints, and fail-closed cache behavior.
- [ ] Commit with `test(e2e): verify authenticated agent secret delivery`.

## Integration Task 2: Compose dynamic and rollover lifecycle

**Files:**

- Modify: `apps/secrethub_web/test/e2e/core_agent_flow_test.exs`
- Modify: `apps/secrethub_web/test/support/e2e_helpers.ex`
- Modify: `docs/deploy.md`

- [ ] Add real PostgreSQL and Redis fixtures and assert issue, request replay, renew, revoke, expiry, and restart reconciliation through CLI → UDS → Agent channel → Core.
- [ ] Assert database rows, Oban args, audit metadata, and captured logs do not contain plaintext generated/admin credentials.
- [ ] Rotate an app certificate and prove the lease remains application-owned; suspend the app and prove all nonterminal credentials converge to cleanup.
- [ ] Force Agent certificate renewal; prove pending material cannot join `agent:runtime`, complete validation/activation/new runtime join/finalization, restart, and prove only the new generation connects.
- [ ] Run `devenv shell -- test-all apps/secrethub_web/test/e2e/core_agent_flow_test.exs`; require zero failures.
- [ ] Commit with `test(e2e): verify secret and certificate lifecycles`.

## Final Verification Gate

- [ ] Run each child plan's focused suite and resolve only failures caused by this work.
- [ ] Run `devenv shell -- mix format --check-formatted`.
- [ ] Run `devenv shell -- env MIX_ENV=test mix compile --warnings-as-errors`.
- [ ] Run `devenv shell -- mix credo --strict`.
- [ ] Run `devenv shell -- test-all`.
- [ ] Run `devenv shell -- ./scripts/quality-check.sh` if the individual gates pass and the script is supported by the current environment.
- [ ] Run `git diff --check` and inspect the full branch diff against its base.
- [ ] Verify all migrations both up and down in a disposable test database, except irreversible data-contract migrations, which must have an explicit guarded `down/0` refusal.
- [ ] Verify a standalone Agent release with `SECRET_HUB_AGENT_CORE_URL=https://core.invalid bin/secrethub_agent eval 'Application.load(:secrethub_agent)'` and a clean container/Compose boot; no database or Phoenix secrets are supplied.
- [ ] Request a final code review focused on auth bypass, secret leakage, external-side-effect ambiguity, migration safety, and rollover crash recovery.
- [ ] Update checkboxes only after fresh command evidence exists; do not claim completion from prior runs.
