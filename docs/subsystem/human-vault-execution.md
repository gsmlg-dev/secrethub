# Human Vault execution report

Milestones **0–7 are implemented and qualified** for the initial **co-hosted Core plus one Human node** topology. Verification completed on 2026-10-08 (Asia/Shanghai). The owner's request extended the original plan's first-pass Milestone 0 restriction to all milestones.

Qualification ran in the isolated `codex/human-vault` worktree, based on `f8f79eaf708093e198c8877d8c8a7e183c9a2e58`, before the integration commit. The archive and client evidence below describe that tested source state. Integration into `main` and a push were subsequently requested by the owner. The main checkout's existing `AGENTS.md`, `README.md` and untracked Human plan are excluded from the implementation commit. No production deployment occurred.

## Milestone reconciliation

| Milestone | Status | Implemented behavior and evidence |
| --- | --- | --- |
| M0 — architecture foundation | Complete | Independent Human Repo, Endpoint, PubSub and Oban; runtime opt-in; independent migrations; disabled-Human behavior; simultaneous Core/Human listeners. Scoped application/runtime tests and extracted production archive startup passed. |
| M1 — identity and sessions | Complete | Provisioning and optional registration; client-derived verifier with salted server hashing; digest-only access/refresh tokens; device-bound sessions; revocation; replay-family revocation; rate limits; JWT authentication plugs; sanitized login audit. MFA extension points deny MFA-required access until actual MFA exists. |
| M2 — personal vault | Complete | Client-encrypted item/folder CRUD; login, note, API credential and dynamic reference types; ciphertext history; deletion tombstones; revision cursors and full snapshots; owner isolation and concurrent mutation tests. Core master keys never decrypt Human payloads. |
| M3 — personal Bitwarden sync | Complete | Identity, device, cipher/folder, revision and sync DTOs plus SignalR MessagePack notifications. Unmodified official CLI 2026.9.1 passed encrypted CRUD, sync, deletion and re-login; Chrome extension 2026.9.3 passed HTTPS authentication and unlocked initial sync. |
| M4 — dynamic references | Complete | Public Core capability/grant boundary; verified principal projection; real PostgreSQL issuance/revocation; metadata-only leases; bounded, single-use reveal; lease UI and expiry updates; sanitized audit. Tests prove real SCRAM login, ownership denial, no credential persistence, failure compensation and caller-death deadlines. |
| M5 — renewal and approval | Complete | PostgreSQL `VALID UNTIL` renewal; Core-owned approval decisions, TTL ceilings, denial, expiry and atomic consumption; requester/session binding; native approver UI; renewal and cleanup concurrency tests. A distinct account approves in browser acceptance. |
| M6 — organizations and collections | Complete | Encrypted organization/member key envelopes; collection read/write permissions; client re-encrypted shared items; shared dynamic references; removal denies future access and invalidates reveal/renewal while scheduling durable backend revocation. |
| M7 — attachments and extended types | Complete | Ciphertext-only storage abstraction and private filesystem backend; independent encrypted attachment key envelopes; size/quota bounds and concurrent reservations; retryable deletion/orphan cleanup; TOTP, SSH, identity and card envelopes; explicitly authorized and audited ciphertext export. |

## Verification results

| Check | Result |
| --- | --- |
| Final Core HumanAccess suite | **28 tests, 0 failures**, seed `506446` |
| Final complete Human suite | **93 tests, 0 failures**, seed `506446` |
| Focused existing runtime/profile/audit regression suites | **53 tests, 0 failures, 2 existing skips**, seed `543163` |
| Native UI expiry and reveal lifecycle tests | **6 passed**, including late-response sign-out, Clear and page-exit regressions |
| Pinned official CLI acceptance | **10 passed** |
| Pinned official Chrome acceptance | **2 passed**, empty personal-vault fixture |
| Official Microsoft SignalR MessagePack decoder over real TLS websocket | **2 passed**: user isolation and revoked-session closure |
| Native browser with disposable PostgreSQL | **5 passed**: client KDF/login, request/reveal/clear, renewal/revocation, distinct approver, sign-out |
| Extracted production release startup | **11 passed**: separate database usernames/names, both packaged migrations, concurrent endpoints, readiness, native UI/assets |
| Formatting and compilation | All **112 touched Elixir files** formatted; test and production compilation passed `--warnings-as-errors` |
| Strict Credo on touched files | **No introduced findings**. Five findings also reproduced from the baseline: three existing alias suggestions and two existing audit-normalization complexity/nesting findings. Strict Credo consequently exits nonzero; the baseline was preserved. |
| Source/harness checks | `git diff --check`, browser/Node harness syntax, private-key fixture scan, Human→Core public-boundary and Web→context checks passed |

The scoped regression files were Core `launch_profile_test.exs`, `prelaunch_runtime_config_test.exs`, `release_runtime_config_test.exs`, `audit_test.exs`, and Shared `runtime_config_test.exs`. The full umbrella suite and full Dialyzer analysis were not run.

The qualified combined release was built locally with `mix release secrethub_core --overwrite`. The extracted archive was migrated and started using its packaged executable, rather than Mix. Its exact SHA256 is recorded in [release-smoke.json](evidence/human-vault/release-smoke.json):

```text
5c9be1e91a8a5ebc2cb2469ce3f6bf1bd3b8c9079fea9291589354164cc88b2e
```

A subsequent pre-merge review found and repaired a native UI race in which a pending reveal response could restore credentials after sign-out, Clear or page exit. Six Node tests pass against the updated UI, including three regressions that failed before the fix and a successful reveal/timeout check. The recorded client/browser checks and archive hash predate this JavaScript-only repair; they remain evidence of the qualified server and packaging state, rather than a rebuilt final archive.

The packaged Core vault remained uninitialized and sealed; its degraded health was expected. Human readiness passed Repo, public Core boundary, reveal store and notification checks. This proves packaging and local startup, not production cutover readiness.

Sanitized client reports, artifact hashes and reproduction instructions are in [the evidence directory](evidence/human-vault/README.md). Client acceptance was refreshed after the final authentication repair. The Chrome fixture tests the loaded empty-vault state; encrypted item and folder round trips are verified by the official CLI.

## Security and runtime decisions

Human authentication belongs to the independent Human service. Core management continues to use Caddy mTLS. Core has no new admin login, accounts or session authentication. Human owns its database and never reads Core Repo or schemas; it calls `SecretHub.Access`. Core verifies each session through the configured trusted identity adapter and owns grants, approval authorization, current policy checks and dynamic lease lifecycle.

Access tokens keep their individual original expiry across refreshes. This supports official-client requests that captured an earlier bearer while a refresh completed. The access store persists SHA256 digests, session UUIDs and expiries only. Refresh never extends an older token's expiry. Session/device revocation, disabled users and refresh-token replay invalidate all session tokens immediately. Tests cover captured actors, concurrent refresh, multiple rotations, original expiries, replay, spoofed proofs and actual migration backfill.

Core's existing typed Agent/application policy bindings and legacy dynamic engine exclusions remain intact. Human uses additive Core grants and metadata-only leases. Production dynamic access requires an explicit opt-in and a bounded trusted `HUMAN_DYNAMIC_MOUNTS_FILE`; startup reloads that catalog so durable cleanup can still resolve backend configuration after restart. Failed revocations remain retryable.

Reveals use a private supervised ETS store, digest-only tokens, constant-time digest comparison, atomic consumption, 30–60-second expiry and per-user/session/global caps. Session and current lease authorization are rechecked before release. Restart destroys unrevealed credentials. Credentials never enter vault rows, lease records, job arguments, audit metadata or logs. Native UI credentials are held temporarily and cleared on timeout, exit or sign-out.

Human mutations write sanitized audit outbox entries transactionally. UUID-only Oban jobs deliver canonical, idempotent hash-v2 evidence to Core. Delivery is eventual across the two databases. Aggregate metrics cover the nine planned counters; readiness checks cover all planned components. Console logging uses the existing Docker pipeline; backup and restore remain owned by the operator's existing systems.

Attachments store client ciphertext, encrypted filenames and encrypted key envelopes under server UUID paths, with private directory/file modes. Client-side authentication/decryption and independent key generation remain client responsibilities; server envelope checks are structural. Export requires current authorization and explicit confirmation and returns active personal ciphertext. Folders and attachment files are fetched separately.

## Supported limits and operation

- Initial production topology: **one Human node alongside Core**, enabled explicitly. Remote Core transport and distributed reveal routing are future work.
- Qualified official clients: CLI **2026.9.1** and Chrome extension **2026.9.3**, personal-vault subset. Desktop/mobile, full Bitwarden parity, enterprise features and Send are unqualified.
- Organizations, attachments, approvals and dynamic access use native APIs; organizations and attachments are not exposed through the Bitwarden compatibility routes.
- Production proxy TLS/mTLS, deployment, unseal and operator acceptance were not performed. Every owned acceptance listener and temporary PostgreSQL backend was stopped and release-smoke private fixtures were removed.

See [the Human operational README](../../apps/secrethub_human/README.md) for configuration, separate database credentials, migrations before startup, trusted mount catalog format, storage lifecycle and reproduction commands. The original [Human Vault plan](human-vault.md) remains the design reference.
