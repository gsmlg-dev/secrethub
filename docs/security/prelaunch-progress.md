# Prelaunch implementation evidence

Date: 2026-10-01
Source baseline: `c7cb03083f98a7d461120013bf7b3b5933ffafaa`
Branch: `codex/prelaunch-wp1`
Plan: `secrethub-prelaunch-plan.en.md` (operator-provided input)

This records the first implementation slice, not production acceptance. Work is
isolated in `.trees/codex/prelaunch-wp1`. Existing main-checkout documentation
edits are preserved. No production credentials, database contents, ingress
configuration, release publication, or deployment are changed.

## Refreshed baseline

These findings refer to the source baseline above. They are source observations,
not results from running the release acceptance matrix.

| ID | Confirmed baseline evidence | Remaining work |
| --- | --- | --- |
| R1 | `apps/secrethub_shared/lib/secrethub_shared/crypto/shamir.ex` uses modulus 251, secret-derived adjustment masks, biased modulo sampling, and coordinate 251. Its v3 decoder can raise on a truncated mask. | First slice replaces sharing and decoding; Vault generation binding remains part of the next slice. |
| R2 | `apps/secrethub_core/lib/secrethub_core/vault/seal_state.ex:171` encrypts the key with a discarded random KDK; `:294` accepts interpolation without authentication; `:338` treats every load failure as empty; `:379` deletes before inserting. Initialization ignores persistence failure. The original unique index on each UUID does not enforce a singleton. | Authenticated key envelope, explicit unavailable state, transactional create, singleton enforcement, restart and failure tests. |
| R3 | `apps/secrethub_core/lib/secrethub_core/audit.ex:63` uses a compile-time HMAC key with a development default; production emits a warning. | Runtime-only signing inputs, startup rejection and historical key-ID contract. |
| R4 | `apps/secrethub_web/lib/secret_hub/web/router.ex:33` retains certificate/session admin authentication; `:56` uses a separate AppRole management plug. | Trace all management routes and connected transports; prove the existing protected ingress boundary. |
| R5 | `mix.exs:169` and `:178` select separate Core/Agent runtime files; `config/runtime.exs` delegates to Core. The Core release also includes the existing Human app at `:167`. | Preserve runtime separation and review Human availability in the launch profile. |
| R6 | `Dockerfile.core` uses a broad builder tag, mutable npm install, a placeholder release cookie and `/health` probe. | Qualify and harden the selected real artifact path. |
| R7 | `apps/secrethub_core/lib/secrethub_core/health.ex:56` allows sealed readiness; `:196` returns constant worker success. | Separate liveness, protected management availability, secret readiness and actual required-worker health. |
| R8 | `apps/secrethub_agent/lib/secrethub_agent/application.ex:152`, `:165` and `:191` retain cache/notification TODOs. | Keep dynamic lifecycle unavailable in the launch profile; qualify static delivery separately. |
| R9 | `.github/workflows/e2e.yml:94` runs source Mix tests with a test build rather than the production image. | Add the exact-artifact acceptance harness after the prerequisite packages. |

## First slice: sharing format

The first code change is scoped to the shared Shamir implementation and its
focused tests. The versioned GF(256) representation removes the adjustment mask
and retains the existing limit of 251 shares. All permitted coordinates are
nonzero in this field. The accompanying sharing specification defines the byte
representation, input limits, randomness and independent reference checks.

Share-set metadata detects accidental mixing. It does **not** authenticate a
reconstructed key. The current SealState still needs to persist the expected
Vault/key generation, match it before accumulating shares, and authenticate a
wrapped data key before changing state. A complete foreign share set or a
modified value must never authorize unseal in the completed WP1 implementation.

## Existing data compatibility

Share formats v1-v3 are rejected by the new normal decoder and combiner. This is
a breaking recovery boundary: **do not deploy this slice over an existing Vault**
or discard old shares. There is no automatic reset or migration in this slice.

The legacy `vault_config.encrypted_master_key` cannot validate a reconstructed
key: its wrapping KDK was generated independently and discarded. Existing
authenticated ciphertext can provide evidence instead:

- `secrets.encrypted_data` and `secret_versions.encrypted_data`, used in
  `apps/secrethub_core/lib/secrethub_core/secrets.ex`.
- `certificates.private_key_encrypted`, used in
  `apps/secrethub_core/lib/secrethub_core/pki/client_auth/authority.ex`.

Existing encryption blobs use a version byte, 12-byte nonce, 16-byte GCM tag and
ciphertext, with AAD `SecretHub-v1`. A future explicit legacy recovery path must
strictly validate old shares, authenticate the candidate against trustworthy
existing ciphertext with trusted provenance, preserve that data key, then
transactionally install the new wrapping envelope and issue replacement shares.
PKI development fallback encryption is not evidence of the Vault key; require
the private key to match its persisted certificate as well. The legacy fixed
AAD does not bind ciphertext to a Vault, so backup/record provenance matters.
If there is no reliable authenticated evidence, recovery remains blocked.
Never create a verifier from
an unvalidated interpolation, delete configuration or recreate unknown data.

## Next implementation boundary

Complete WP1 sections 4.2-4.4 before consumer work or candidate qualification:

1. Persist a versioned AES-GCM data-key envelope wrapped by a separate shared
   unseal key, binding Vault ID, key generation and share parameters as AAD.
2. Distinguish loading/unavailable, empty, sealed and verified-unsealed state;
   reject invalid attempts and reset their partial progress safely.
3. Enforce a database singleton and transactional create without deletion;
   release shares only after successful commit. Exercise concurrent callers,
   unavailable database, corrupt schema, insert failure and delayed recovery.
4. Rehearse supported nonempty recovery with authenticated evidence. Preserve
   restart-sealed behavior and the existing no-op manual seal contract.

WP2-WP6 and G01-G20 remain unaccepted. No built production candidate, consumer
enforcement measurements, restore drill or launch cutover is claimed here.

## Executed checks

The implementation regressions ran against the baseline before the repair:
47 tests, 11 failures, including field/reference disagreement, legacy and
mixed/duplicate acceptance, missing v4 generation and invalid-envelope handling.

After the repair, the following focused commands passed from the worktree root:

```sh
elixir -r apps/secrethub_shared/lib/secrethub_shared/crypto/shamir.ex \
  -r apps/secrethub_shared/test/test_helper.exs \
  apps/secrethub_shared/test/secrethub_shared/crypto/shamir_test.exs

MIX_ENV=test mix test --no-start \
  apps/secrethub_shared/test/secrethub_shared/crypto/shamir_test.exs
```

The final suite completed with **49 tests, 0 failures**, with no compiler warnings
(independent standalone review seed 445694; final Mix seed 415958). Mix compiled the umbrella dependencies;
only the selected Shamir tests ran. `--no-start` avoids starting unrelated
applications or contacting a database. This is module evidence, not an
application-startup or production-artifact test.

Earlier shared-app-directory Mix attempts, with and without `--no-start`,
failed before tests because Core runtime configuration references
`SecretHub.Human.RuntimeRole` outside the shared application's code path.
Running the scoped command from the umbrella root resolved that test invocation
issue without changing runtime configuration.

Independent specification review passed: reproduction of all six Python
reference vectors, 251-of-251 reconstruction and malformed-input smoke checks.
Quality review found permissive Base64 decoding; two additional regressions
failed before the canonical re-encoding check (49 tests, 2 failures), then passed
after the fix. Final code-quality review, scoped `mix format --check-formatted`
and `git diff --check` passed. These reviews cover the sharing slice only.
