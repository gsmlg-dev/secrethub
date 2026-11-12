# SSH Identity and Access Redesign

Date: 2026-11-12
Status: Approved (brainstorming)
Scopes: core, agent, web, shared

## Problem

The SSH management subsystem has two defects:

1. **The source identity model is wrong.** The model ties each SSH source
   identity to one connected Agent and one local user (`identity_upsert`
   requires `agent_id`). `authorized_keys` delivery also requires the source
   Agent to be live (`live_agent?(identity.agent_id, "ssh_signing_v1")`). The
   original requirement covered only Agent ↔ Core enrollment, where the Agent
   authenticates using the host SSH key. It did not require every SSH login
   source to be an Agent. Sources that are not Agents, such as the GitHub
   Actions deploy key, cannot be represented.
2. **Core holds and transmits private keys.** Core generates source private
   keys and stores them encrypted. `authorize_sign` returns the decrypted
   private PEM to the Agent on every signature. This conflicts with
   device-held keys and with the mobile Agent design, which uses
   non-exportable keys.

The management UI (`ssh_access_live.ex`, 935 lines) is one long page. Operators
paste host keys and type UIDs by hand, even though Agents already report both.
Group IDs and rule users are free text, and change previews show raw JSON.
There is no automatic key rotation.

## Goals

- Every device that runs an Agent joins Core. Supported devices: NixOS
  servers, NixOS workstations, macOS, Linux/ARM without Nix, and the mobile
  Agent (mobile acts only as a source).
- Sources are **identities**. An identity is either Agent-provided, with the
  private key kept on the device, or external, where the operator adds a
  public key.
- Operators never maintain `authorized_keys` or `known_hosts` by hand.
- Agent identities rotate automatically on a schedule and on demand.
  External identities produce reminders when due.
- The UI matches the three operator tasks: onboard devices, manage keys, and
  adjust access.

Primary access patterns: an operator on their own devices logs in to servers
(same account), automation between servers, and mobile as a client. Only the
GitHub Actions deploy key uses a dedicated account.

## Non-goals

- **Rotating host keys.** Agent enrollment uses the host RSA key, and
  sops-nix derives age keys from `ssh_host_ed25519_key`. Host keys keep the
  current flow: Agent reports → operator trusts → Core distributes to
  `known_hosts`.
- Implementing the mobile Agent (`gsmlg-app/secrethub_agent`). The model
  supports it; client work happens in that repository.
- Updating GitHub Secrets automatically for external identities (tracked as
  a follow-up issue; see Follow-ups).
- Per-role fine-grained authorization beyond identity/group → host/group as
  user.

## Data model (Core)

### Identities

The new `ssh_identities` table replaces the old one. Production holds 0 rows,
so a single migration drops and recreates the table without migrating data.

| Field | Notes |
|---|---|
| `id` (uuid), `name` | Display name, unique (e.g. `gao@laptop`, `gh-deploy`) |
| `origin` | `agent` \| `external` |
| `agent_id`, `local_username`, `local_uid` | Required when `origin = agent`, otherwise null; unique per (`agent_id`, `local_uid`) |
| `status` | `pending` \| `active` \| `retired` |
| `rotation_days` | Default 90; null disables scheduled rotation |
| `next_rotation_at` | Set when the identity activates or rotates |
| `requested_generation` | Increased to request a rotation (Agent origin only) |
| `rotation_overdue` | Boolean; set by the worker on external identities |

The child table `ssh_identity_keys` holds:

- `identity_id`, `generation`, `public_key`, `fingerprint`, `inserted_at`
- `not_after`: null while the key is current; set when the key is superseded

The fingerprint is unique across all keys.

A key is **valid** when its identity is `active` and its `not_after` is null
or in the future.

Removed: `private_key_encrypted`, Core-side key generation and import, and the
per-identity encryption key derivation.

### Groups and rules

Groups live inside the revisioned inventory and come in two kinds:

- `host` groups, whose members are Agent IDs
- `identity` groups, whose members are identity IDs

Each rule has these fields:

```
source_kind: identity | identity_group
source_id
destination_kind: endpoint | host_group
destination_id
destination_user
effect: allow | deny
enabled
```

`source_user` is removed: the identity carries the source user. Every matching
deny overrides every allow, and default is deny (unchanged).

Endpoints, host-key approval, and `candidate_host_keys` are unchanged.

The inventory row keeps its `revision`. Every management change still uses
preview → confirm with expected-revision checks.

## Agent

### Key storage

Each local user's identity key lives in `<state_dir>/ssh-identities/<uid>/`
as `<generation>.key` (mode 0600, readable only by the Agent service user).
Users cannot read their own private key; the signing socket is the only way
to use it.

### Enrollment of an identity

1. A local user connects to the signing socket. The Agent resolves the peer
   UID, as it does today.
2. If the user has no local key, the Agent generates ed25519 key generation 1.
3. The Agent sends `ssh:identity_report` with `local_uid`, `local_username`,
   `generation`, and the public key.
4. Core creates a `pending` identity and pushes `ssh:policy_changed`.
5. The operator approves the identity in the UI, which sets `status = active`.

### Signing

1. The Agent reads the current local key.
2. The Agent calls `authorize_sign` with the public key. Core answers only
   `allow` or `deny`, based on identity status, key validity, and whether at
   least one outgoing allow edge exists. **Core never returns key material.**
3. On `allow`, the Agent signs locally.

Signing still requires online authorization, so revocation and policy changes
take effect immediately. The ssh-agent `identities` request lists only valid
keys that Core reports as authorized.

### Rotation (pull-based reconcile)

1. Core increases `requested_generation` and pushes `ssh:policy_changed`.
2. On each `identities` view fetch (on push, on reconnect, and periodically),
   the Agent compares its local generation with `requested_generation`.
3. If the local generation is lower, the Agent generates a new key and reports
   it with `ssh:identity_report`, using generation = requested.
4. Core accepts the report **automatically**, because it arrives over the
   Agent's runtime mTLS certificate for the identity's `agent_id` and the
   generation matches the request. Core then sets
   `not_after = now + grace` (default 3 days) on the previous key.
5. The Agent deletes local key files whose generation Core no longer lists as
   valid.

An offline Agent loses no rotation request: it reconciles when it reconnects.
Reports that do not match the requested generation are rejected and audited.

## Rotation scheduling (Styx)

`SecretHub.Core.Workers.SshIdentityRotationWorker` runs as an hourly cron on
`SecretHub.Core.Styx`. Each run does three things:

1. For each active Agent identity with `next_rotation_at <= now`, it increases
   `requested_generation`, sets `next_rotation_at = now + rotation_days`, and
   pushes `ssh:policy_changed` to the Agent.
2. Superseded keys past `not_after` stop being valid, because validity is
   derived from time. The worker deletes keys that expired more than 30 days
   ago, so audit history keeps fingerprints only.
3. For each external identity past `next_rotation_at`, it sets
   `rotation_overdue = true`. **It does not deactivate the identity.**

Every state transition writes an audit event to the hash chain:

- **Management changes** are recorded as `ssh.configuration`, with each operation in the record: `identity_approve`, `identity_revoke`, `identity_delete`, `identity_rotate`, `identity_rotation`, `identity_external_add`, `identity_external_replace`.
- **Agent reports** are recorded as `ssh.identity_report`. The record holds the outcome (`reported`, `rotated` or `unchanged`). For a rejected report it holds the reason instead.
- **The worker** records `ssh.identity_rotation_requested`, `ssh.identity_rotation_overdue` and `ssh.identity_keys_pruned`.

Key expiry needs no event of its own, because validity is computed from `not_after`.

The UI's "rotate now" action follows path 1 for a single identity.

For an external identity, "replace public key" adds a new generation and
applies the same grace period to the old key.

## Runtime views

- **`authorized_keys`**: Core returns `no-agent-forwarding <key>` for each valid
  key that matches the presented key. It requires an approved destination
  endpoint and a policy allow for (identity, destination Agent, user).
  **It no longer requires the source Agent to be live.**
- **`known_hosts`**: unchanged, except that the source is resolved through
  identities.
- **`identities` (Agent)**: returns, per local user, the valid public keys,
  `requested_generation`, and authorization status.
- **`authorize_sign`**: returns allow or deny only.

## UI (`/admin/ssh-access`)

The existing route and `SSHAccessLive` stay. One LiveView with three tabs. A badge on each tab counts pending items.
Function components live in separate modules: devices, identities, access, and
preview. They replace the single 935-line page.

1. **Devices**
   - A pending strip at the top lists newly reported host keys (trust/reject)
     and changed host keys (compare/replace).
   - One card per Agent shows online state, platform, and version.
   - Each card has an **As target** block (aliases, port, host key state, who
     can log in) and an **As source** block (identities and next rotation).
   - Mobile Agents show only As source.
2. **Identities**
   - One table lists Agent and external identities: name, origin,
     fingerprint, status, rotation period and countdown, and overdue warnings.
   - Actions: approve, rotate now, revoke, edit rotation days, add external
     public key, and replace external public key.
3. **Access**
   - The matrix shows identities and identity groups as rows, and host groups
     and endpoints as columns.
   - A cell holds the destination user, chosen from users that the
     destination Agents reported. A cell can also be set to deny or cleared.
   - Group management happens in a drawer.
   - The change preview renders gained and lost edges as sentences ("+
     phone@pixel-9 can log in as gao on vultr-01…, − …"), with confirm and
     cancel.

Free-text inputs remain only for external public keys, names, aliases, and
port.

## Error handling

| Situation | Behavior |
|---|---|
| Stale revision on confirm | Flash and reload the snapshot (existing behavior) |
| Rotation requested while the Agent is offline | Identity shows "waiting for device"; reconcile completes on reconnect |
| Reported key fingerprint already exists | Reject the report and audit it |
| Report generation ≠ requested | Reject the report and audit it |
| Invalid external public key | Show an inline form error; no change |
| Vault sealed | Management changes and `authorize_sign` fail closed (existing behavior) |

## Testing

- **Core unit**
  - Evaluator (pure): identity groups, deny-wins, grace-period validity of old
    and new keys, edges and diffs.
  - Change operations, including validation failures.
- **Core integration**
  - Migration.
  - Identity report and approval.
  - Rotation acceptance and rejection paths.
  - Rotation worker, with time controlled.
  - `authorized_keys` with an offline source.
  - `authorize_sign` returns no key material.
- **Agent**
  - Local key generation and permissions.
  - Local signing.
  - Generation reconcile.
  - Cleanup of retired keys.
- **LiveView**
  - Tab rendering and pending counts.
  - Approve host key and identity.
  - Matrix cell edit → preview sentences → confirm.
  - Add external key.
- **End-to-end (local devenv)**
  1. Enroll an Agent.
  2. Approve its identity.
  3. Run `ssh` through the signing socket to a lookup-enabled host.
  4. Rotate now.
  5. Confirm that both keys work during the grace period and that only the
     new key works after it.

## Follow-ups

- Issue: update the GitHub Actions secret automatically for external
  identities on rotation. This requires storing a GitHub token in Core, with
  repository-scoped secrets write access.
- Sub-project: unify device onboarding and inventory (per-platform install
  instructions, versions, capabilities).
- Sub-project: Core support for mobile Agent capabilities.
