# SecretHub PKI: Mozilla Trust and ACME Implementation Plan

**Status:** Proposed implementation handoff; no implementation or live certificate issuance was performed while preparing this plan.  
**Prepared:** 2026-10-22 (Asia/Shanghai)  
**Repository:** [gsmlg-dev/secrethub](https://github.com/gsmlg-dev/secrethub)  
**Inspected baseline:** [e1d09953bc1393e389e7fea1d03827c5358a5e1c](https://github.com/gsmlg-dev/secrethub/commit/e1d09953bc1393e389e7fea1d03827c5358a5e1c)

Companion documents: [architecture design](secrethub-pki-acme-design.md) and [Codex goal](secrethub-pki-acme-goal.md).

## Agent skills

- [Agent Note](app://asdk_app_6a5d80337f3c81918ee11e45e8cf72ce) — the exact connection invoked by the user. Recall or maintain scoped project knowledge only after resolving an explicit Agent Note project declaration; do not infer the label from the repository name.
- [GitHub](app://connector_76869538009648d5b282a4bb21c3d157) — the exact connection invoked by the user. Inspect current source, changes, and release results.
- Read the repository's [AGENTS.md](https://github.com/gsmlg-dev/secrethub/blob/e1d09953bc1393e389e7fea1d03827c5358a5e1c/AGENTS.md), [domain documentation instructions](https://github.com/gsmlg-dev/secrethub/blob/e1d09953bc1393e389e7fea1d03827c5358a5e1c/docs/agents/domain.md), and [agent handoff conventions](https://github.com/gsmlg-dev/secrethub/blob/e1d09953bc1393e389e7fea1d03827c5358a5e1c/docs/agents/issue-tracker.md). Use applicable installed Elixir, Phoenix, Ecto, OTP, review, and verification skills when available; do not invent local skill paths.

## Outcome and boundaries

Ship a default, offline-available Mozilla public root catalogue and complete Let's Encrypt ACME DNS-01 issuance, renewal, and revocation using Cloudflare and AWS Route 53. The owner must be able to configure credentials, request a certificate, inspect progress, retrieve a coherent certificate/key generation, and recover failed operations.

Implement inside the existing Core, Shared, and Web applications. Preserve the personal management model, Caddy mTLS ingress, internal Agent/application identities, and Client Auth PKI. Add no account system or umbrella application.

Version one provides management export and a structured static-secret projection for existing authorized Agent reads and single combined-PEM rendering. Automatic multi-file certificate deployment and distributed-byte recall are outside this version.

## Baseline facts that affect implementation

The current source requires several explicit integration changes:

| Existing boundary | Implementation consequence |
| --- | --- |
| `PKI.CA.get_ca_chain_pems/0` selects internal root/intermediate rows; `RootCA.active_ca/0` chooses a signer from them. | Store Mozilla roots and public issuer chains separately. |
| `Certificate` has internal certificate types and globally unique serial numbers. | Introduce dedicated managed-server-certificate/version schemas; use fingerprints for external certificate identity. |
| `PKI.AppCertificates` issues canonical internal client identities. | Do not route public DNS server certificates through application bootstrap or renewal. |
| Core depends on Oban but does not supervise a Core Oban instance; current configuration belongs to Human. | Install and verify Core-owned durable job infrastructure. |
| `ClientAuth.TrustBundle` and Agent bundle management assume an internal authority, CRL, pin, and monotonic generations. | Mozilla trust is a separate catalogue and trust purpose. |
| Secrets use dotted paths, a fixed engine whitelist, historical snapshots, and database path-revision triggers. | Publish `pki.acme.<slug>` as `engine_type: "static"`; integrate existing version/revalidation rules. |

These observations come from the pinned source; recheck current HEAD before implementation. References appear at the end.

## Execution order

Phase 0 precedes all work. Phases 1 and 2 can proceed independently. Phase 3 depends on schema decisions from Phase 2. The ACME adapter and the two DNS adapters can be implemented in parallel after their contracts are agreed. Durable orchestration then connects them. Publication, management surfaces, and final verification complete the feature.

Use parallel agents for independent modules, with one coordinator owning migrations, shared contracts, integration, and release. Avoid concurrent edits to the same schema or runtime configuration.

## Phase 0 — Reconcile the current checkout and establish scope

**Work**

Read current instructions, relevant domain documentation and ADRs, release configuration, launch-feature controls, PKI code, secrets versioning, and existing tests. Record the actual starting commit. Preserve unrelated working-tree changes.

Inspect existing Core migrations for Oban installation before creating one. Confirm the installed Oban, Req, JOSE, X509, OTP, and CAStore versions. Conduct a bounded compatibility check for a maintained native ACME client. Adopt one only if it supports the required account persistence, DNS hooks, durable order recovery, ARI, revocation, and injectable transport. Otherwise implement a small protocol adapter using Req, JOSE, OTP, and the existing X509 package.

**Output**

A checked dependency decision and scoped implementation checklist. Record concrete conflicts with newer source; update this plan where necessary without expanding product scope.

**Acceptance**

The implementer can identify the current management ingress, machine routes, encryption API, secret delivery paths, migration owner, and release process. No prerequisite assumes that declared dependencies are already running services.

## Phase 1 — Default Mozilla trust catalogue

**Proposed ownership**

`SecretHub.Core.PKI.TrustStores`, backed by an explicit, pinned CAStore runtime dependency in Core and the shared lockfile.

**Work**

Build an immutable public catalogue from the packaged CAStore PEM bundle. Expose bundle bytes, canonical certificate fingerprints, subject/issuer, validity, bundle digest, dependency version, and provenance. Compute catalogue identity from the actual packaged bytes; avoid mutable copies or redundant trust tables.

Use the bundle explicitly for the new ACME and DNS-provider HTTPS clients, with peer verification, hostname verification, and SNI. Never alter internal mTLS trust or add public roots to internal signer selection. Package official Let's Encrypt staging roots separately, with reviewed source URLs/fingerprints, for staging-issued-chain validation only. Verify this profile before staging order/DNS effects. Pebble transport/issuance trust remains explicit test configuration.

Document updates as a reviewed dependency/lockfile and release change. Include provenance and license notices. The catalogue represents Mozilla-derived public roots, not the complete Firefox certificate-verification policy.

**Acceptance**

A release without outbound network can list and export the bundle. Repeated startup produces the same digest. Invalid certificate input fails predictably in parser tests. A public-CA certificate is not accepted as an internal Agent/application/admin identity. The release contains the dependency's runtime PEM asset.

## Phase 2 — Schemas, credentials, and invariants

**Proposed ownership**

New schemas in `apps/secrethub_shared/lib/secrethub_shared/schemas/`; migrations only in `apps/secrethub_core/priv/repo/migrations/`; contexts under `SecretHub.Core.PKI.ACME`, `DNS`, and `ManagedCertificates`.

**Work**

Model accounts, DNS provider configurations/bindings, managed certificate definitions, immutable certificate versions, orders, authorizations/challenges, DNS mutation receipts, cleanup work, and operation claims. Keep current certificate generation separate from current issuance/renewal attempt. Use distinct `configuration_revision` (desired edits), `publication_sequence` (each successful issuance/renewal), and `claim_token` (worker ownership). Persist the expected prior version on replacement orders. Immutable material/key associations must not prevent mutable ARI/revocation lifecycle annotations.

Persist directory identity and environment with each account and order. Bind each identifier to an explicit provider/zone; support SANs spanning providers. Store requested identifiers, canonical CSR digest, remote URLs, retry deadlines, and sanitized errors. Enforce one active publication workflow per managed certificate with database constraints/claims.

DNS configuration stores secret references and nonsecret options. Encrypt account keys and pending certificate keys with the existing vault primitives. Never use plain `EngineConfiguration.config` for credentials. Keep private material out of job arguments, metadata, inspection, logs, and error responses.

**Acceptance**

Constraints reject contradictory ownership and duplicate active work. Migration tests preserve existing PKI rows. Account keys survive restart encrypted. Missing/unavailable vault keys produce resumable errors. Staging and production accounts cannot be accidentally interchanged.

## Phase 3 — Core durable runtime and feature availability

**Work**

Add a named `SecretHub.Core.Oban` bound to `SecretHub.Core.Repo`, its required migration, supervision after Repo startup, dedicated bounded queues, periodic reconciliation, test settings, and shutdown integration. Calls must address the named instance explicitly.

Add `:public_trust` and `:acme` to supported launch configuration and feature checks. Update `config/core_runtime.exs`, which currently supplies an explicit feature list. Public trust is available by default. ACME makes no issuance/DNS changes until configured.

Do not activate dormant generic rotation workers, dynamic engines, or Human features. Keep DNS propagation waits and remote polling outside long database transactions; schedule the next bounded job instead of sleeping a worker for minutes.

**Acceptance**

A test starts the actual Core runtime configuration, enqueues a named-instance job, observes execution, restarts it, and observes recovery. A disabled ACME feature blocks new issuance/renewal commands, jobs and publication as well as UI controls, while already-owned reconciliation, cleanup and pending revocation can finish. Provider/resource disabling follows the same rule and retains bindings/credential references until obligations are resolved. Core and Human Oban instances remain independent.

## Phase 4 — ACME protocol adapter

**Work**

Implement or integrate directory discovery, nonces, JWS signing, account creation/reuse, explicit terms acceptance, orders, authorization retrieval, challenge acknowledgement, CSR finalization, certificate retrieval, renewal information, and revocation.

Implement POST-as-GET correctly, bounded badNonce recovery, Retry-After handling, normalized ACME problem responses, request timeouts, and response limits. Do not blindly retry non-idempotent operations after transport ambiguity. Persist remote identifiers immediately and reconcile known resources before creating replacements.

Generate certificate keys independently of account keys. Validate downloaded leaf/chain structure, key match, exact requested SAN set, validity, server-auth purpose, and issuer signatures before publication. Staging certificates remain clearly marked and require staging-specific validation; staging test roots must not enter production HTTPS trust.

**Acceptance**

Deterministic protocol tests cover nonce rejection, reused authorization, pending/ready/processing/valid/invalid states, failed finalization, delayed issuance, ambiguous responses, and certificate/key/SAN mismatch. No protocol test requires a live public CA.

## Phase 5 — DNS-01 adapters and propagation

**Cloudflare**

Use scoped API tokens and explicit zone IDs where possible. Preserve unrelated TXT records. Persist intent before create; persist the resulting record ID and ownership evidence. Cleanup deletes only a record demonstrably owned by this operation. Existing matching records are borrowed, not claimed for deletion.

Resolve ambiguous creates by bounded inspection using exact owner/value and durable evidence. If ownership cannot be established, preserve the record and expose unresolved cleanup rather than guessing.

**Route 53**

Use supported AWS credential resolution, including session tokens; document restricted hosted-zone/TXT permissions. Reject private zones for public validation. Serialize SecretHub mutations by zone and canonical record owner.

Read the complete RRset, preserve unrelated values and supported metadata, merge owned challenge values, and submit a conflict-aware exact DELETE-plus-CREATE batch where appropriate. For initially absent RRsets, use creation semantics that detect intervening creation. Cleanup subtracts only owned values.

This is not a general external-writer CAS guarantee. Validate exact-preimage rejection, transactional batch behavior, retries, and ambiguous outcomes against the real adapter contract. If a safe transition cannot be established, retain state and report conflict. Never delete/recreate an unfamiliar routing-policy RRset using a simplified representation.

**Shared behavior**

Canonicalize names and enforce configured zone boundaries. Support apex plus wildcard, which may require multiple simultaneous values at the same owner. Honor explicit CNAME/delegated-zone mappings with bounded traversal and loop detection; never silently mutate an unconfigured target.

Wait for the expected values at public authoritative DNS, with configurable deadlines and bounded retry. Provider acknowledgement and Route 53 INSYNC alone are insufficient evidence of ACME visibility.

**Acceptance**

Provider fixtures cover pagination, authentication failure, throttling, existing values, two concurrent challenges, borrowed records, TTL preservation, ambiguous mutation, cleanup retries, conflicting external changes, delegation, and wrong-zone rejection. Both adapters pass the same ownership/concurrency contract suite.

## Phase 6 — Durable order workflow, renewal, and cleanup

**Work**

Persist each transition and intended effect before performing external work. Workers claim a bounded operation, perform one effect, then record the result under the expected generation. An obsolete worker cannot publish over a newer configuration or certificate.

Track issuance state separately from DNS cleanup state. Cleanup must survive success, failure, cancellation, timeout, worker crash, restart, and vault unavailability. Retain per-authorization receipts and ownership until cleanup is confirmed; scheduled reconciliation revisits unfinished effects.

Implement ACME Renewal Information, including persisted suggested windows, chosen renewal time, polling schedule, and replacement metadata where required. Fall back to the certificate's actual lifetime when ARI is absent/unavailable. Do not assume a 90-day certificate or a fixed 30-day renewal window. Apply jitter, backoff, Retry-After, and expiry-aware alerts.

A failed renewal leaves the current valid certificate available. Local cancellation stops future issuance progression while preserving cleanup obligations; it does not imply that remote work never occurred.

**Acceptance**

Crash-injection tests resume after DNS creation, acknowledgement, finalization, certificate download, and immediately before publication. Concurrent reconciliation cannot create two active generations. Test two successful renewals without configuration edits, an edit racing publication, and disabling a resource/provider immediately after TXT creation. Tests use synthetic short and long lifetimes and ARI windows. Cleanup failure does not erase successful issuance, and issuance failure does not erase cleanup obligations.

## Phase 7 — Atomic publication and managed output secrets

**Work**

Publish one structured secret at `pki.acme.<slug>`, with `secret_type: :static` and `engine_type: "static"`. Include matching certificate, chain, fullchain, private key, fingerprint, validity, and generation identity in its encrypted payload.

Add a surgical, transaction-composable helper to the existing Secrets implementation. Preserve its normal wrappers. In one short transaction:

1. Take the global authorization write lock before managed/secret row locks.
2. Verify the order, intended generation, and idempotency result.
3. Archive the previous output payload and write the next secret version.
4. Link the immutable managed version to `output_secret_id` plus `secret_version_number`.
5. Switch the current certificate pointer and mark publication complete.
6. Clear temporary order key material once ownership has moved to the durable output.
7. Require the publication audit append to succeed.

Existing `secret_versions` stores old snapshots only. Add an exact-version resolver that reads the current secret when its version matches, otherwise reads history. Do not rely on the currently unmaintained `current_version_id` association.

Protect managed outputs from generic mutation, rollback, deletion, and pruning of referenced history. Use an authoritative ownership relation, with descriptive metadata as supplementary information. Preserve path-revision triggers and existing policy bindings. Do not publish network effects inside this transaction.

**Acceptance**

Injected failure at any publication step leaves the previous coherent generation available. Replayed completion creates no extra secret version. Retention cannot remove referenced material. Agent revalidation observes the new path revision and receives one matching generation. Unauthorized applications cannot read the output.

## Phase 8 — Management UI, export, and revocation

**Work**

Extend the existing PKI management area with public roots, DNS providers, ACME accounts, managed certificates, order progress, renewal health, cleanup status, and safe exports. Reuse existing Caddy mTLS ingress and CSRF protection. Do not expose management mutations through MachineRouter.

Make staging/production selection explicit. Show credentials as references with write-only replacement. Distinguish certificate issuance, local publication, and deployment status. Version-one exports and Agent material delivery are sufficient; avoid claiming separate-file atomic deployment.

Implement manual ACME revocation with durable remote-request state and confirmed result. Locally quarantine the selected version from new material exports/delivery while revocation is pending; preserve remote failure/pending status for recovery. Confirmed revoked material remains blocked.

Update the authoritative delivery gate and secret path revision atomically when active availability changes. Apply the gate before returning a cache not-modified response, and cover every relevant secret-read/export path. Resolve the exact version first: current reads check the current managed version, while historical reads/exports check the requested version. Revoking an old version must not block a newer healthy current version. Existing static reads do not automatically enforce managed-certificate status. Already distributed files or cached bytes cannot be recalled by this feature.

**Acceptance**

Management tests exercise configuration through issue/renew/revoke/export. Machine endpoints reject management actions. Failed revocation stays visibly pending/failed rather than falsely confirmed. Quarantined/revoked versions cannot be newly exported or returned through secret delivery, including cache revalidation. Test both an old revoked version with a healthy current version and a quarantined current version with historical reads. Read-only public certificate history may remain available without the private key.

## Phase 9 — Verification, documentation, and release

**Required automated evidence**

| Layer | Meaningful gate |
| --- | --- |
| Trust | Offline release catalogue, fingerprint/provenance checks, internal trust isolation |
| Protocol | ACME state/error tests and local Pebble issuance/renewal/revocation |
| Providers | Real HTTP adapter serialization plus deterministic ownership/conflict fixtures |
| Durability | Restart, duplicate worker, stale generation, ambiguous effect, cleanup recovery |
| Publication | Atomic pointer/material/audit update, exact-version reads, retention protection |
| Authorization | Managed delivery denial, policy preservation, revocation cache revalidation |
| Runtime | Named Core Oban actually executes under supported release configuration |
| Regression | Existing internal CA, app certificates, Client Auth bundle, ingress and secret-read tests |

Use scoped tests during development, then the repository's required release gates. Run formatting, warnings-as-errors compilation, applicable Credo/Dialyzer checks, and required CI workflows. Fix in-scope regressions; identify unrelated failures accurately.

Live Let's Encrypt staging issuance using both Route 53 and Cloudflare is rollout evidence when credentials and authorized domains exist. Record account environment, SANs, result fingerprint, renewal/revocation observations, and cleanup evidence without secrets. Missing live credentials must not stop implementation or replace offline/Pebble gates with placeholders. Mark live evidence as not run.

Document account creation and terms, provider permissions, credential rotation, delegation, renewal behavior, unavailable-vault recovery, cleanup reconciliation, exports, managed-secret ownership, backup/restore, and CAStore update procedure. Update the existing deployment/release documentation and changelog.

Commit, push, and release according to the repository's current convention and the user's preference once mandatory gates pass. Verify the resulting release artifacts/workflow. Do not automatically create production certificates or mutate real DNS as part of release. If publishing is unavailable, report the precise remaining command/action and completed verification rather than claiming release success.

## Completion definition

The work is complete when a fresh supported release includes Mozilla roots offline; both DNS adapters can complete the tested ACME lifecycle; issuance and renewal recover durably; published keys/certificates are coherent and encrypted; revocation blocks new managed delivery; management and existing machine authorization remain separated; and release evidence distinguishes automated validation from optional live staging checks.

## References

- [Internal CA selection and storage](https://github.com/gsmlg-dev/secrethub/blob/e1d09953bc1393e389e7fea1d03827c5358a5e1c/apps/secrethub_core/lib/secrethub_core/pki/ca.ex)
- [Internal certificate schema](https://github.com/gsmlg-dev/secrethub/blob/e1d09953bc1393e389e7fea1d03827c5358a5e1c/apps/secrethub_shared/lib/secrethub_shared/schemas/certificate.ex)
- [Core supervision](https://github.com/gsmlg-dev/secrethub/blob/e1d09953bc1393e389e7fea1d03827c5358a5e1c/apps/secrethub_core/lib/secrethub_core/application.ex)
- [Secret publication/versioning](https://github.com/gsmlg-dev/secrethub/blob/e1d09953bc1393e389e7fea1d03827c5358a5e1c/apps/secrethub_core/lib/secrethub_core/secrets.ex)
- [Secret path revision triggers](https://github.com/gsmlg-dev/secrethub/blob/e1d09953bc1393e389e7fea1d03827c5358a5e1c/apps/secrethub_core/priv/repo/migrations/20261001000004_create_secret_path_revisions.exs)
- [Runtime secret authorization](https://github.com/gsmlg-dev/secrethub/blob/e1d09953bc1393e389e7fea1d03827c5358a5e1c/apps/secrethub_core/lib/secrethub_core/runtime_authorization.ex)
- [Core launch configuration](https://github.com/gsmlg-dev/secrethub/blob/e1d09953bc1393e389e7fea1d03827c5358a5e1c/config/core_runtime.exs)
- [ACME RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)
- [ACME Renewal Information RFC 9773](https://www.rfc-editor.org/rfc/rfc9773)
- [Let's Encrypt integration guide](https://letsencrypt.org/docs/integration-guide/)
- [Let's Encrypt challenge types](https://letsencrypt.org/docs/challenge-types/)
- [Route 53 ChangeResourceRecordSets](https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html)
- [Cloudflare DNS API](https://developers.cloudflare.com/api/resources/dns/subresources/records/)
- [CAStore source and packaging](https://github.com/elixir-mint/castore)

