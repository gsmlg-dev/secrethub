# SSH Access Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use [subagent-driven-development](/home/gao/.agents/skills/subagent-driven-development/SKILL.md) to execute these tasks and review each responsibility. Steps use checkboxes for tracking.

**Goal:** Deliver grouped, user-specific SSH signing, authorized-key lookup, and known-host trust with batch management.

**Architecture:** Core owns encrypted signing identities, approved host endpoints, groups and directed allow/deny rules. Agents expose separate Linux SSH-agent and public lookup sockets, with fresh authorization through the existing mTLS runtime. The management LiveView previews and applies atomic revisioned changes.

**Tech Stack:** Elixir/OTP 28, Ecto/PostgreSQL, Phoenix LiveView/DuskMoon, OpenSSH, Mix releases and NixOS.

**Execution status (2026-10-19): INCOMPLETE / BLOCKED_UPSTREAM.** Local code is
committed in reviewable chunks; consolidated source checks are **98 tests / 0
failures**, scoped format and incremental compilation pass, and packaged public
helpers pass. Signing confidentiality is blocked by
[phoenix_socket_client#108](https://github.com/gsmlg-dev/phoenix_socket_client/issues/108).
No workaround, push, merge or deployment. Full real SSH login qualification,
remaining scoped lint findings and target architecture/runtime checks are still
open. See [exact evidence](../../testing/ssh-access-evidence.md).

Historical first-start baseline/missing-module RED transcripts are not preserved
here; unchecked provenance steps below are not assertions of current failures.

## Agent skills

- [using-elixir-skills](/home/gao/.agents/skills/using-elixir-skills/SKILL.md)
- [test-driven-development](/home/gao/.agents/skills/test-driven-development/SKILL.md)
- [phoenix-duskmoon-ui](/home/gao/.agents/skills/phoenix-duskmoon-ui/SKILL.md)
- [verification-before-completion](/home/gao/.agents/skills/verification-before-completion/SKILL.md)

## Execution boundaries

Worktree: `/home/gao/Workspace/gsmlg-dev/secrethub/.trees/ssh-access`, branch `codex/ssh-access`.
Only the approved SSH scope is editable. Existing origin handling and adjacent
changes are excluded from inspection, diff, formatting, testing and modification.
Never run an umbrella-wide formatter or test command. Preserve other work.
Changes are local implementation; running hosts and production sshd are untouched.

Tasks 2 and 3 are independent once the contracts below are fixed and run in
parallel. The primary worker owns shared keys, trusted-channel integration,
management, NixOS, documentation and end-to-end qualification. Tests involving
the shared build directory run serially through the primary worker.

## Fixed contracts

`SecretHub.Shared.SSH.Key` provides:

```elixir
decode_public(line_or_base64) # {:ok, %{type:, blob:, encoded:, public_line:, fingerprint:, key:}}
import_private(pem)          # {:ok, %{public: public_map, private_pem: pem}}
generate("ed25519" | "rsa") # same import result
sign(private_pem, data, flags) # {:ok, binary_ssh_signature_blob}
```

Public fingerprints use OpenSSH `SHA256:` encoding without trailing padding.
Private import accepts a single unencrypted Ed25519/RSA OpenSSH/PEM key; RSA
signatures require SSH SHA2 flags 2 or 4, with flag 0 rejected.

`SecretHub.Core.SSH` provides public management functions:

```elixir
snapshot()                         # public inventory + :revision, never private keys
preview(changes, expected_revision) # {:ok, %{revision:, changes:, gained:, lost:}}
apply_changes(changes, expected_revision) # {:ok, public_snapshot}; atomic, audit first
runtime_operation(identity, operation, payload) # {:ok, map} | {:error, atom}
```

`identity` contains certificate-derived `agent_id` and `certificate_id`. Management
and runtime boundary `agent_id` values are the public Agent IDs, not caller-chosen
database primary keys. Operations are `identities`, `authorize_sign`,
`authorized_keys`, `known_hosts`, and `inventory`. Runtime events prefix these
with `ssh:`. Agent and Core advertise `ssh_lookup_v1` / `ssh_signing_v1` separately.

Runtime payloads and replies:

```elixir
"identities": %{"uid" => uid, "username" => user}
# %{identities: [%{public_key: line, key_revision: revision}], revision: policy_revision}
"authorize_sign": %{"uid" => uid, "username" => user, "public_key" => base64_blob}
# %{private_key: pem, public_key: line, key_revision: revision, revision: policy_revision}
"authorized_keys": %{"username" => target_user, "key" => base64_blob}
# %{lines: [authorized_key_line], revision: policy_revision}
"known_hosts": %{"uid" => uid, "username" => user, "reason" => reason, "host" => host, "port" => port}
# %{lines: [known_host_line], revision: policy_revision}
```

Successful denied public lookups return an empty `lines` list. Signing denial is
an error. No cross-request private-key cache is needed: fetch each authorized
signing key afresh and retain it only for that operation, satisfying the approved
memory and invalidation rules with less state.

Management changes use string keys and these operations:

```elixir
%{"op" => "group_upsert", "id" => id, "name" => name}
%{"op" => "group_members", "group_id" => id, "agent_ids" => public_agent_ids}
%{"op" => "endpoint_upsert", "agent_id" => agent_id, "aliases" => aliases, "port" => 22, "host_keys" => public_lines, "approved" => true}
%{"op" => "identity_upsert", "agent_id" => agent_id, "username" => user, "uid" => uid, "algorithm" => "ed25519"}
%{"op" => "identity_upsert", "agent_id" => agent_id, "username" => user, "uid" => uid, "private_key" => pem}
%{"op" => "identity_revoke", "id" => id}
%{"op" => "rule_upsert", "id" => id, "effect" => "allow", "enabled" => true,
  "source_kind" => "agent", "source_id" => agent_id, "source_user" => user,
  "destination_kind" => "group", "destination_id" => group_id, "destination_user" => target_user}
%{"op" => "rule_delete", "id" => id}
```

Omitted IDs create records. Group/endpoint deletion follows the same `_delete`
shape. A failed member of a batch rolls back all changes and the revision.

## Task 1: Shared SSH key codec and clean baseline

**Ownership:** primary worker.
**Files:** create `apps/secrethub_shared/lib/secrethub_shared/ssh/key.ex` and
`apps/secrethub_shared/test/secrethub_shared/ssh/key_test.exs`.

- [ ] Run existing Agent config CLI tests in the isolated worktree before editing code.
- [x] Generate independent OpenSSH Ed25519/RSA fixtures in test temporary directories.
- [x] Add failing import, fingerprint, public-key validation and SHA2 signing tests.

```elixir
assert {:ok, imported} = Key.import_private(File.read!(path))
assert imported.public.public_line == File.read!(path <> ".pub") |> String.split() |> Enum.take(2) |> Enum.join(" ")
assert {:error, _} = Key.decode_public("not-a-key")
assert {:error, _} = Key.sign(rsa_pem, "session", 0)
```

- [ ] Run `MIX_ENV=test mix test --no-start apps/secrethub_shared/test/secrethub_shared/ssh/key_test.exs`; confirm the missing-module failure, implement the contract, rerun green.
- [x] Commit only shared codec/tests and approved design/plan documents.

## Task 2: Core SSH inventory, policy and runtime service

**Ownership:** Core worker. Create `apps/secrethub_core/lib/secrethub_core/ssh.ex`,
supporting modules under `ssh/`, shared schemas under `schemas/ssh/`, one Core
migration, and tests under `apps/secrethub_core/test/secrethub_core/ssh/`.

- [x] Add failing tests for default denial, direction, exact users, deny priority,
  persistent group membership, deduplication and gained/lost previews.
- [x] Implement a pure evaluator and dedicated revisioned inventory schemas.
- [x] Test atomic apply, stale revisions, unique source key/UID, endpoint alias/port
  collisions, pending host keys, revocation and encryption at rest against a disposable database.
- [x] Implement the fixed management contracts and public-only snapshots.
- [x] Test runtime identity/certificate checks, seal/audit failure and exact lookup
  output, then implement the five runtime operations with no generic-secret bypass.
- [x] Ensure source/destination liveness, public-key approval and certificate
  eligibility are freshly evaluated; audit commits precede release.
- [x] Run `MIX_ENV=test mix test apps/secrethub_core/test/secrethub_core/ssh/` through the coordinated isolated test environment.
- [x] Review and commit only owned files; report actual red/green evidence.

## Task 3: Agent SSH sockets, Linux identity and release helpers

**Ownership:** Agent worker. Create modules/tests under
`apps/secrethub_agent/{lib,test}/secrethub_agent/ssh/`; integrate only Agent
`connection.ex`, `application.ex`, `config.ex`, `runtime_bootstrapper.ex`,
`config/agent_runtime.exs`, `rel/env.sh.eex`, and the Agent example TOML.

- [x] Write failing binary-framing/list/sign tests and real Unix peer-UID tests.
- [x] Implement bounded Linux peer identification, OS username/UID checking and
  separate sign/public lookup socket handlers with configured mode/group ownership.
- [x] Use current Core RPCs for every operation; hold no private key between requests.
- [x] Add separate negotiated lookup/signing capabilities; old peers remain SSH-unavailable.
- [x] Test public-only lookup, nobody-compatible helper startup, strict stdout/exit
  status, parser limits, minimal environment, unknown/unsupported operations and outages.
- [x] Implement `fetch-ssh-keys [--socket PATH] USER KEY` and
  `fetch-ssh-host-keys [--socket PATH] REASON HOST PORT` with early release dispatch.
- [x] Add explicit opt-in TOML defaults and release runtime configuration without
  touching private existing UDS or excluded origin configuration.
- [x] Run `MIX_ENV=test mix test --no-start apps/secrethub_agent/test/secrethub_agent/ssh/` through the primary worker after shared compilation is ready.
- [x] Review and commit only owned files; report actual red/green evidence.

## Task 4: Trusted runtime channel integration

**Ownership:** primary worker. Modify only
`apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex` and its
focused channel tests.

- [x] Write denied/missing-capability tests before routing the SSH RPCs.
- [x] Add capability-scoped handlers guarded by existing per-request runtime
  identity checks; ignore caller-supplied Agent IDs.
- [x] Include Core SSH capability negotiation and revision notification handling.
- [x] Verify new RPC success and revoked/expired current certificates using
  `MIX_ENV=test mix test apps/secrethub_web/test/secrethub_web/channels/ssh_runtime_channel_test.exs`.

## Task 5: Management UI and strict managed SSH profiles

**Ownership:** primary worker. Create `ssh_access_live.ex` and focused LiveView
tests; add its admin route/navigation entry; create `ssh/profiles.ex` and tests.

- [x] Test the public management snapshot, matrix explanations and empty state.
- [x] Implement group/member, endpoint/key approval, source identity generation/import,
  rule allow/deny/delete and multi-selection forms using existing DuskMoon APIs.
- [x] Test preview/confirm against the exact expected revision, gained/lost edges,
  unresolved users/capabilities, stale edits and private-key removal after import.
- [x] Generate client profiles with strict host checking, DNS trust disabled,
  null alternate known-host files and no forwarding; generate account-scoped sshd
  profiles with only the managed command, `AuthorizedKeysFile none`,
  `AuthenticationMethods publickey` and `TrustedUserCAKeys none`.
- [x] Qualify effective profiles using real `ssh -G` and isolated `sshd -T/-t`.
- [x] Run only the new profile/LiveView tests and necessary scoped route tests.

## Task 6: Packaging, NixOS and consumer qualification

**Ownership:** primary worker. Modify only Agent flake/module checks, relevant
release packaging tests, and SSH documentation. Add an isolated OpenSSH fixture.

- [x] Add optional SSH socket/group/TOML module configuration with existing
  DynamicUser/private-state boundaries and root-owned executable profiles.
- [x] Build a standalone Agent release and run both helper commands as an
  unprivileged/nobody consumer, with no private config, cookie or release writes.
- [ ] Test real ssh-add list/sign and actual SSH login against isolated sshd using
  current Core/Agent runtime and two source users/target accounts where available.
- [ ] Prove reverse/wrong-user/host-key/alternate CA/local-file denials and batch
  revocation. Do not use a fake server as evidence of real Core acceptance.
- [ ] Qualify Linux amd64 locally; run aarch64/Nix checks when available and record
  explicit BLOCKED/NOT RUN evidence where target execution is unavailable.
- [x] Run scoped formatting, compile and the complete in-scope test set once after integration.
- [ ] Perform independent specification review, then quality/security review;
  fix findings before marking acceptance items complete.
- [x] Record exact results and remaining material limitations in an evidence file,
  commit reviewable chunks, and finish the branch without publishing/deploying.

### Remaining acceptance work

- [ ] Consume the upstream confidentiality fix and make the preserved sentinel
  diagnostic pass; do not patch dependency internals locally.
- [ ] Resolve in-scope findings from the explicit 18-file strict Credo run; keep
  pre-existing integration findings separate from new SSH code.
- [ ] Rebuild the matching release and rerun complete actual login, direction,
  wrong-user/host-key, alternate local-file/CA and batch-revocation scenarios.
- [ ] Qualify aarch64 and a running NixOS service when target environments exist.

Fresh specification and quality/security reviews were completed, with follow-up
reviews confirming the corrected helper exits, host scope, socket integrity and
delayed-response checks. Both preserve overall acceptance as incomplete because
upstream #108 remains open.
