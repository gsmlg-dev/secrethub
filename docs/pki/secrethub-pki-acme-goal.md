# Goal: Ship Mozilla Public Trust and Let's Encrypt DNS-01 in SecretHub

Repository: https://github.com/gsmlg-dev/secrethub

Planning baseline: `main` at `e1d09953bc1393e389e7fea1d03827c5358a5e1c`, reviewed 2026-10-22. Reconcile the current checkout before editing; the baseline is evidence, not an instruction to reset a newer branch.

## Agent skills

- [Agent Note](app://asdk_app_6a5d80337f3c81918ee11e45e8cf72ce): use the user's selected connection for relevant project knowledge only after resolving the exact configured project label. Do not guess the label from the repository name. Missing note configuration must not block implementation.
- [GitHub](app://connector_76869538009648d5b282a4bb21c3d157): use the user's selected connection or available authenticated repository tooling for source, CI and release work.
- Read current `AGENTS.md`, `docs/agents/domain.md`, `docs/agents/issue-tracker.md`, applicable ADRs and release instructions. Use applicable installed Elixir/Phoenix/Ecto/OTP/review/verification skills; do not invent skill paths.

## Mission

Implement and release the complete feature. SecretHub must ship a Mozilla-derived TLS root CA bundle by default and request/manage Let's Encrypt server certificates using ACME v2 DNS-01 through both AWS Route 53 and Cloudflare.

Deliver working code, migrations, management UI/API, durable jobs, tests, operational documentation and release evidence. Continue through implementation and verification; do not stop after another plan, a library survey, schemas, UI mockups, or one DNS provider.

Read the companion design and implementation plan before implementing:

- [Architecture design](secrethub-pki-acme-design.md)
- [Implementation plan](secrethub-pki-acme-implementation-plan.md)

Maintain these documents under `docs/pki/` as `secrethub-pki-acme-design.md`, `secrethub-pki-acme-implementation-plan.md`, and `secrethub-pki-acme-goal.md`, preserving their relative links and recording any justified changes. This goal also states the mandatory contract so execution can start without access to the original conversation.

## Product and architectural boundaries

1. Extend existing Core, Shared and Web ownership; add only necessary Agent/read-path integration. Do not add an umbrella application.
2. Preserve Caddy mTLS as the management authentication boundary. Add no admin login or user-management system. Preserve CSRF, private management ingress, machine authentication and existing policies.
3. Treat public trust, internal identity PKI and external public certificate issuance as separate concerns. Public roots and ACME intermediates must not be inserted as internal `:root_ca` or `:intermediate_ca` records.
4. Do not alter internal Agent/app/client-auth trust, identity issuance or enrollment. A public server certificate must not become a valid SecretHub machine credential.
5. V1 provides public bundle inspection/export, ACME issuance/renewal/revocation, management export, and an encrypted versioned static-secret projection. Existing Agent reads and a single combined-PEM sink are the delivery boundary. Do not claim atomic separate-file deployment or automatic application reload unless it is actually implemented and verified.
6. Keep the scope to Let's Encrypt production/staging and the two DNS providers. Do not add an ACME server, HTTP challenge listener, arbitrary DNS editor, runtime CA download service, automatic account-key rollover or unrelated engine refactor.

## Required implementation

### A. Default public trust

Create `SecretHub.Core.PKI.TrustStores` or an equivalently clear context. Declare CAStore directly as a Core runtime dependency and lock the verified release. Expose `mozilla_webpki` from its packaged PEM, with actual-byte SHA-256, package/source provenance, root count and root metadata.

Make catalogue/PEM reads work offline, from a real assembled release, before vault unsealing. Use an immutable derived catalogue; a new trust-store database or runtime updater is unnecessary. Document updates through dependency/release changes, replacement of removed roots, license notices and the trust consequence of a binary rollback.

Use explicit public trust for ACME/AWS/Cloudflare HTTPS with peer and hostname verification. Never use `verify_none`, depend on a developer-machine path, modify global SSL trust, or merge Mozilla roots into client-auth bundles. Describe the bundle as Mozilla-derived roots, not full Firefox policy enforcement.

### B. Domain state and keys

Add dedicated accounts, provider configurations/bindings, managed certificate definitions, immutable certificate versions, orders, authorizations, DNS intent/receipt and cleanup state. Place schemas in Shared and all database migrations in Core.

Persist account/environment identity, normalized identifier sets, provider-zone bindings, requested configuration revision, expected prior version, CSR, encrypted pending leaf key, remote URLs, retry/deadline data and redacted errors. Keep the serving certificate separate from a replacement attempt. Distinguish `configuration_revision` for desired edits, `publication_sequence` for each successful issuance/renewal, and `claim_token` for worker ownership. Use constraints and claim/revision checks to prevent duplicate active work and duplicate publication. Immutable certificate/key material and secret-version links permit mutable ARI/revocation lifecycle annotations.

Use a stable request ID plus normalized request digest for idempotency; repeated identical requests reuse work, conflicting payloads are rejected. New certificate versions use canonical DER fingerprints, not globally unique public serial numbers. Current version pointers must belong to the correct managed resource.

Encrypt account and pending leaf keys with existing vault primitives. DNS settings reference existing encrypted secrets or an explicit supported AWS credential chain; support temporary AWS session tokens. Never store credentials in plain engine config, job arguments, metadata or logs. Account and leaf keys are distinct. Generate one leaf key per durable order and retain it across retries.

### C. Core jobs must actually run

The reviewed Core depends on Oban but does not start its own instance. Add a named Core instance bound to `SecretHub.Core.Repo`, correct installed-version migrations, supervision, bounded queues, reconciliation, shutdown, tests and release configuration. Keep Human Oban separate.

Integrate `:public_trust` and `:acme` in the supported launch profile, including `config/core_runtime.exs`, route/view mappings, context commands and workers. Do not enable dormant generic rotation/dynamic engines. Default bundle availability must not contact external services; new ACME work requires explicitly configured/enabled resources. Disabling ACME, a provider or a resource stops new issuance/renewal/publication while allowing already-owned reconciliation, cleanup and pending revocation to finish. Retain original bindings and credential references until obligations resolve.

### D. Native ACME protocol and workflow

Use the project's HTTP stack plus established JOSE/OTP/X509 primitives behind a small adapter. Perform at most one bounded compatibility check for a current native ACME library; adopt it only through supported interfaces that allow explicit TLS trust, transport injection, bounded retries, full status/headers, caller-owned keys, URL-based recovery and ARI. Otherwise implement the narrow adapter directly. Do not monkey-patch dependencies or shell out to certbot/acme.sh by default.

Implement directory/nonces, register/recover account, new/read order, authorization/challenge operations, CSR finalization, chain retrieval, revocation and ARI. Handle JWS, POST-as-GET, bounded badNonce, Retry-After, already-valid authorizations, processing orders, ACME problems and ambiguous HTTP responses. DNS-01 publishes the SHA-256/base64url digest of key authorization, not the raw key-authorization string.

Use explicit production/staging accounts and operator terms acceptance. Verify the staging API over public HTTPS. Ship official Let's Encrypt staging roots in a separately pinned profile with source URLs/hashes for staging-issued-chain validation only, and require it before staging order/DNS effects. Pebble trust is separately injected by tests. Never promote staging material into production trust or production output, and never bypass verification when a profile is unavailable.

Persist intended effects before execution and known remote URLs immediately. Resume existing orders after restart. When an order-create response is lost and the remote order cannot be located, record uncertainty and bound recovery/replacement; do not promise exactly-once remote issuance.

Before publication validate the leaf/key pair, normalized SAN set, server-auth usage, validity, chain and environment. Preserve the returned intermediate chain. Do not hardcode a Let's Encrypt intermediate or append every trusted root to fullchain output.

### E. DNS-01 with both providers

Implement common bounded contracts for zone validation, observation, presentation, reconciliation, propagation and cleanup, with provider-specific ownership evidence.

Support individual names, wildcard plus apex, SANs across providers, explicit public zones and explicitly configured delegation. Normalize IDNA/case/dots and match suffixes on label boundaries. Reject unsupported identifiers, private hosted zones and unconfigured delegated targets. Bound CNAME traversal and reject loops. Public DNS-01 TXT resolution is required; public service A/AAAA records and inbound HTTP/TLS reachability are not.

Persist DNS intent before API mutation. Track exact owner/value, provider account and zone, operation identity, record/change IDs, created/borrowed/ambiguous ownership and independent cleanup state. Preserve existing records and other orders' values; use shared ownership or reference checks when values are shared.

Cloudflare: scoped DNS token; create individual TXT records; persist record IDs/markers; reconcile timed-out creation; delete only demonstrably owned, unchanged records. Never delete by name alone or remove borrowed matching records.

Route 53: read the complete supported TXT RRset; preserve unrelated values/TTL; serialize internal mutations; use conflict-aware create or exact-preimage DELETE-plus-CREATE transactional changes rather than a token-only unconditional UPSERT. Re-read current state for cleanup. Validate conflict/ambiguity behavior and reject unfamiliar routing-policy records. Local locks do not serialize external DNS writers or provide a remote fencing token.

Do not blindly reuse the existing pooled session-lock helper. Use correct bounded locking/claims and reconciliation. Never hold a DB transaction or connection during propagation waits. Check public authoritative DNS, not just API acknowledgment/INSYNC, before challenge acknowledgment. Keep cleanup retryable after success, failure, cancellation, timeout and restart.

### F. Atomic secret publication

Publish a single structured encrypted static secret at `pki.acme.<slug>`, using current dotted path conventions and `engine_type: "static"`. Its certificate, chain, fullchain, private key and metadata must describe one immutable version.

Create a narrow transaction-composable helper from existing Secrets database steps. In one short transaction, take the existing authorization lock before resource locks; recheck order/generation/ownership; archive old output; write the new material version; link the managed version to exact `output_secret_id` and `secret_version_number`; switch the current pointer; mark the order published; clear the pending key; and append checked audit evidence. Roll back all steps on any failure. Perform no DNS or ACME HTTP in this transaction.

Respect current version semantics: `secret_versions` contains historical snapshots only; current material lives in `secrets`. Do not rely on the unmaintained `current_version_id` association. Resolve a requested version from current material or history, then validate its embedded certificate identity. Never return the latest key with an older certificate.

Keep one permanent encrypted key copy in the output secret/history, with public metadata in managed versions. Enforce authoritative output ownership against generic value changes, rollback, deletion, rotation and history pruning. Preserve policy binding and existing trigger-maintained cache revisions. Retained certificate versions must pin referenced secret history. Replay must not increment versions again.

### G. Renewal, revocation and UI

Implement RFC 9773 ARI: discover renewalInfo, derive the certificate identifier correctly, persist windows and randomized due time, honor refresh timing, and include replacement information when applicable. Use actual certificate lifetime as fallback: approximately two-thirds elapsed, or half for lifetimes shorter than ten days. Add bounded backoff, jitter, expiry guards and visible failures. Do not encode 90-day validity or fixed 30-day renewal assumptions.

Keep the current valid certificate available when renewal fails. Periodic reconciliation must recover due renewals and cleanup obligations after a worker exhausts attempts or the vault was unavailable.

Revocation is an explicit operator action with pending/confirmed/failed remote state. Quarantine the selected version from new private-material exports/delivery when requested, and retain that local state through ambiguous failures. Confirm remote revocation only from ACME evidence. Current reads check the current managed version; historical reads/exports check the resolved historical version. Revoking an old version must not block a newer healthy current version, and a healthy current version cannot bypass historical quarantine. Apply gates before cache `not_modified` responses and atomically update normal secret path revision on active availability changes. Already distributed bytes cannot be recalled.

Add focused PKI views for trust, providers/accounts, managed certificates, versions, order progress, renewal and cleanup. Reuse current private management/CSRF routes; do not expose management operations on MachineRouter. Lists/details omit private keys. Protected explicit exports use no-store responses. Requests enqueue durable work and return promptly.

Use existing Audit for lifecycle events. Do not create a fake local CA solely to satisfy the existing CA-scoped PKI event schema.

## Mandatory verification

Implement meaningful tests around observable contracts, especially:

- Offline/read-only assembled-release bundle availability, exact hashes and no internal-trust expansion.
- Working named Core Oban under the supported launch profile, with restart recovery and feature gates.
- ACME protocol tests and local Pebble issuance, renewal and revocation.
- Both real HTTP adapters exercised through deterministic provider fixtures, including pagination/auth/throttling and session-token behavior.
- Apex plus wildcard at one TXT owner; mixed-provider SANs; unrelated/borrowed record preservation; two concurrent orders; explicit delegation; ambiguous creates; failed/retried cleanup; stale workers.
- Crashes after DNS mutation, acknowledgment, finalization/download and before publication; disabling immediately after TXT creation still allows cleanup.
- Atomic secret publication, replay, exact-version export, referenced-history retention and unauthorized read rejection.
- ARI changed/missing/invalid windows and synthetic 90/64/45/6-day validity periods; two renewals without configuration edits; an edit racing publication; renewal failure retaining the serving version.
- Revocation delivery gates, historical material and cache revalidation, without claiming remote file recall.
- Existing internal CA/app/client-auth/ingress/secret-read regressions for touched boundaries.

Run scoped tests during development and the repository's required quality/CI/release gates before completion. Record actual commands/results. Do not hide unrelated failures or expand into unrelated fixes.

Run real Let's Encrypt staging through each provider when authorized test zones and credentials are available. Otherwise complete implementation, fixtures and Pebble tests and mark those live gates as not run. Mocked/provider-fixture success must not be presented as live validation. Do not request a production certificate solely for testing.

## Documentation, release and completion report

Document provider permissions, account/terms setup, credential rotation, delegation, trust updates, renewal/revocation, cleanup recovery, exact-version export, single-bundle delivery, backups/restore and known limitations. Distinguish implemented, tested, released and operationally validated behavior.

Use parallel agents for independent protocol/provider/UI work after shared contracts are settled. Keep a coordinator for migrations, transaction integration and review. Finish the entire scope before declaring completion.

After mandatory gates pass, commit, push and publish the next appropriate release using the repository's existing version/release convention, as requested by the owner's standing workflow. Verify the release workflow and artifacts. Respect repository protections and preserve unrelated changes. If an actual permission or required gate blocks a final external action, complete the remaining work and report the exact blocker and remaining action; do not claim success.

The final report must include the starting/final commits, delivered capability matrix, migration/configuration requirements, automated evidence, each provider's live-staging status, remaining limitations and release link/status. The feature is not complete if only one provider works, renewal jobs are not running, DNS cleanup is volatile, public trust changes internal identities, or the output key and certificate can come from different versions.
