# SecretHub Human Subsystem Implementation Plan

## 1. Objective

Add a new umbrella application named:

```text
secrethub_human
```

`secrethub_human` will be SecretHub’s human-facing secrets subsystem.

It will initially provide:

* Bitwarden-compatible personal password vault capabilities
* Human access to SecretHub dynamic secrets
* Lease-aware credential reveal
* Secure notes and credentials
* Human identity, device, and session management
* Unified audit integration with SecretHub Core

The new application must run its own Phoenix Endpoint and Web service while remaining a single umbrella application.

The application must not be split into separate domain and Web applications.

---

## 2. Target Umbrella Structure

```text
apps/
├── secrethub_shared
├── secrethub_core
├── secrethub_web
├── secrethub_agent
└── secrethub_human
```

The new application owns both domain and Web layers:

```text
apps/secrethub_human/
├── lib/
│   ├── secrethub_human/
│   │   ├── application.ex
│   │   ├── repo.ex
│   │   ├── accounts/
│   │   ├── identities/
│   │   ├── devices/
│   │   ├── vault/
│   │   ├── organizations/
│   │   ├── collections/
│   │   ├── dynamic_secrets/
│   │   ├── leases/
│   │   ├── approvals/
│   │   ├── audit/
│   │   └── notifications/
│   │
│   └── secrethub_human_web/
│       ├── endpoint.ex
│       ├── router.ex
│       ├── controllers/
│       ├── plugs/
│       ├── channels/
│       ├── live/
│       └── telemetry.ex
│
├── priv/
│   ├── repo/migrations/
│   └── static/
│
├── test/
└── mix.exs
```

The primary module namespaces are:

```elixir
SecretHub.Human
SecretHub.HumanWeb
```

---

## 3. Architectural Position

SecretHub Core remains the authoritative system for:

* Static infrastructure secrets
* Dynamic secret engines
* Credential generation
* Lease creation
* Lease renewal
* Lease revocation
* Secret rotation
* Machine authentication
* Policy evaluation
* Core audit records

`secrethub_human` owns:

* Human accounts
* Human sessions
* Human devices
* Personal password vault data
* Secure notes
* Organizations and collections
* Human-facing access workflows
* Dynamic secret references
* Credential reveal sessions
* Human approval workflows
* Human-oriented audit views

The dependency direction must be:

```text
secrethub_human
        ↓
public SecretHub Core access boundary
        ↓
secrethub_core
```

The following dependency is prohibited:

```text
secrethub_human
        ↓
SecretHub Core internal schemas or Repo
```

`secrethub_human` must not query SecretHub Core tables directly.

---

## 4. Runtime Model

`secrethub_human` must start its own Phoenix Endpoint:

```elixir
SecretHub.HumanWeb.Endpoint
```

Example local ports:

```text
SecretHubWeb.Endpoint        :4000
SecretHub.HumanWeb.Endpoint  :4001
```

Example production routing:

```text
secrethub.example.com -> SecretHubWeb.Endpoint
vault.example.com     -> SecretHub.HumanWeb.Endpoint
```

Both endpoints may run inside the same BEAM release.

The application must also support role-based startup so the same release can run selected subsystems:

```text
SECRETHUB_ROLE=all
SECRETHUB_ROLE=core
SECRETHUB_ROLE=human
SECRETHUB_ROLE=agent
```

Example deployment:

```text
secrethub-core-1
secrethub-core-2
secrethub-human-1
secrethub-human-2
```

The initial implementation may start all applications together, but the supervision structure must not prevent future role-based releases.

---

## 5. Database Boundary

`secrethub_human` should own a dedicated Ecto Repo:

```elixir
SecretHub.Human.Repo
```

Preferred deployment:

```text
PostgreSQL instance
├── secrethub_core database
└── secrethub_human database
```

Acceptable initial deployment:

```text
PostgreSQL instance
└── one database
    ├── core schema
    └── human schema
```

The application must own its own:

* migrations
* database credentials
* connection pool
* backup policy
* retention policy
* restore tests

Cross-database joins and cross-context Ecto associations are prohibited.

The Human subsystem should store references to Core resources using opaque identifiers.

Example:

```elixir
%DynamicSecretReference{
  core_mount_id: "mount_...",
  core_role_id: "role_...",
  display_name: "Production PostgreSQL",
  requested_ttl: 900
}
```

It must not use Ecto associations to Core schemas.

---

## 6. Security Model

The Human subsystem contains two fundamentally different secret classes.

### 6.1 Human Vault Data

Examples:

* Usernames
* Passwords
* Secure notes
* TOTP seeds
* Custom fields
* Attachments
* Personal API tokens

These should follow a client-encrypted or zero-knowledge-compatible model where possible.

The server must not reuse the SecretHub Core master key to encrypt Human Vault items.

Human Vault cryptography must have an independent key hierarchy.

### 6.2 Dynamic Secrets

Examples:

* Temporary PostgreSQL users
* Redis credentials
* AWS STS credentials
* SSH certificates
* Kubernetes tokens

Dynamic secrets remain owned by SecretHub Core.

`secrethub_human` stores only:

* Dynamic secret references
* Display metadata
* Access policy hints
* Requested TTL
* Lease metadata
* Audit references

It must not persist issued credential values.

---

## 7. Core Access Boundary

Expose or formalize a public Core facade that may be called by Human, Web, Agent, and CLI clients.

Suggested namespace:

```elixir
SecretHub.Access
```

Required operations:

```elixir
SecretHub.Access.issue_dynamic_secret/2
SecretHub.Access.renew_lease/2
SecretHub.Access.revoke_lease/2
SecretHub.Access.read_lease/2
SecretHub.Access.authorize/2
SecretHub.Access.list_capabilities/1
```

Example principal:

```elixir
%SecretHub.Access.Principal{
  type: :human,
  subject: "human_user_id",
  tenant_id: "tenant_id",
  groups: ["developers"],
  device_id: "device_id",
  auth_strength: :mfa,
  source: :secrethub_human
}
```

Example request:

```elixir
%SecretHub.Access.DynamicSecretRequest{
  mount_id: "postgres-production",
  role_id: "readonly",
  requested_ttl: 900,
  request_id: "request_id",
  metadata: %{
    human_session_id: "session_id"
  }
}
```

The Core facade must enforce:

* Authentication
* Authorization
* Maximum TTL
* Approval requirements
* Device requirements
* MFA requirements
* Lease rules
* Audit generation

The Human application must not duplicate Core policy evaluation.

---

## 8. Credential Reveal Flow

Dynamic credentials must use a short-lived reveal flow.

Recommended flow:

```text
Human user requests credential
        ↓
Human builds Principal
        ↓
SecretHub.Access.authorize
        ↓
SecretHub.Access.issue_dynamic_secret
        ↓
Core creates lease
        ↓
Human creates one-time reveal token
        ↓
Client redeems reveal token
        ↓
Credential returned once
        ↓
Reveal token destroyed
```

Reveal tokens must be:

* Random and unguessable
* Single-use
* Bound to user
* Bound to session
* Bound to device when available
* Stored only as a digest
* Expired within 30–60 seconds
* Deleted immediately after redemption

Credential values must never be stored in:

* Ecto tables
* Phoenix sessions
* Oban arguments
* Telemetry metadata
* Audit metadata
* Application logs
* Error reports
* Long-lived LiveView assigns

Lease metadata may be stored, but credential values may not.

---

## 9. Initial Domain Model

### 9.1 Accounts

Suggested entities:

```text
human_users
human_identities
human_sessions
human_devices
human_recovery_codes
human_mfa_methods
```

Responsibilities:

* User identity
* Authentication
* Session lifecycle
* Device registration
* MFA state
* Recovery workflows

### 9.2 Vault

Suggested entities:

```text
vault_items
vault_item_versions
vault_folders
vault_attachments
vault_favorites
```

Initial item types:

```text
login
secure_note
identity
card
ssh_key
api_credential
dynamic_secret_reference
```

### 9.3 Organizations

Suggested entities:

```text
human_organizations
human_organization_members
human_collections
human_collection_items
human_collection_permissions
```

Organizations may be deferred until the personal vault is stable.

### 9.4 Dynamic Secret Access

Suggested entities:

```text
dynamic_secret_references
dynamic_secret_requests
dynamic_secret_leases
credential_reveal_tokens
human_approvals
```

The `dynamic_secret_leases` table stores metadata only:

```text
lease identifier
core engine identifier
core role identifier
issued time
expiry time
renewable flag
status
requesting user
requesting device
```

It must not contain secret values.

---

## 10. Bitwarden Compatibility Strategy

Treat Bitwarden compatibility as an external protocol compatibility project.

Do not copy Vaultwarden source code into the repository.

Implementation sources should be prioritized as:

1. Official Bitwarden client behavior
2. Official Bitwarden SDKs and protocol definitions
3. Official server API behavior where documented
4. Compatibility tests using official clients
5. Vaultwarden behavior as a secondary reference

Use clean-room implementation practices.

The first compatibility target should be a constrained subset:

* Identity/token endpoint
* User authentication
* Device registration
* Personal cipher CRUD
* Folder CRUD
* Sync endpoint
* Basic notifications
* Browser extension compatibility
* Desktop client compatibility
* Mobile client compatibility

Do not target full Vaultwarden parity in the first milestone.

---

## 11. Phoenix Endpoint and Routing

The Human Endpoint should expose separate routing groups.

Example:

```text
/identity/*
/api/*
/notifications/*
/human/*
/health
```

Suggested split:

```text
/identity/*       Bitwarden-compatible identity operations
/api/*            Bitwarden-compatible vault operations
/notifications/*  client synchronization notifications
/human/*          SecretHub-native Human UI and APIs
/health           operational health
```

The Bitwarden-compatible routes and SecretHub-native routes must remain logically separated.

Do not mix protocol DTOs directly with internal domain schemas.

Use explicit boundary modules:

```elixir
SecretHub.HumanWeb.Bitwarden.*
SecretHub.HumanWeb.Native.*
```

---

## 12. Internal Module Boundaries

Recommended context structure:

```text
SecretHub.Human.Accounts
SecretHub.Human.Authentication
SecretHub.Human.Devices
SecretHub.Human.Vault
SecretHub.Human.Organizations
SecretHub.Human.DynamicSecrets
SecretHub.Human.Leases
SecretHub.Human.Approvals
SecretHub.Human.Audit
SecretHub.Human.Notifications
```

Each context should expose functional APIs and hide Ecto schemas.

Controllers and LiveViews must call contexts rather than Repo directly.

Avoid generic service modules.

Prefer explicit commands and transformations:

```elixir
Vault.create_item(actor, attrs)
Vault.update_item(actor, item_id, attrs)
DynamicSecrets.request(actor, reference_id, attrs)
Leases.revoke(actor, lease_id)
```

---

## 13. Supervision Tree

Initial supervision tree:

```text
SecretHub.Human.Supervisor
├── SecretHub.Human.Repo
├── SecretHub.Human.Telemetry
├── SecretHub.Human.PubSub
├── SecretHub.Human.RevealStore
├── SecretHub.Human.LeaseMonitor
├── SecretHub.Human.NotificationSupervisor
└── SecretHub.HumanWeb.Endpoint
```

### Reveal Store

Use an isolated supervised process or cache abstraction for one-time reveal tokens.

Possible initial implementation:

```text
ETS
```

Requirements:

* No persistence
* Automatic expiration
* Constant-time token digest comparison
* Per-user and per-session limits
* Cleanup process
* Maximum bounded memory

Do not use a general distributed cache as the first implementation.

If multiple Human nodes are deployed later, replace or extend the reveal store with an explicit distributed strategy.

---

## 14. Audit Integration

Human actions must be written into the existing SecretHub audit model through the public Core audit boundary.

Required events include:

```text
human.login.succeeded
human.login.failed
human.device.registered
human.vault.item.created
human.vault.item.updated
human.vault.item.deleted
human.dynamic_secret.requested
human.dynamic_secret.approved
human.dynamic_secret.denied
human.dynamic_secret.issued
human.dynamic_secret.revealed
human.dynamic_secret.renewed
human.dynamic_secret.revoked
human.dynamic_secret.expired
```

Audit records may include:

* Actor ID
* Tenant ID
* Device ID
* Session ID
* Request ID
* Dynamic secret mount
* Dynamic secret role
* Lease ID
* TTL
* Result
* Failure reason category

Audit records must never contain:

* Passwords
* Tokens
* Private keys
* TOTP seeds
* Dynamic credential values
* Attachment content

---

## 15. Implementation Milestones

## Milestone 0: Architecture Foundation

Deliverables:

* Create `apps/secrethub_human`
* Add Phoenix Endpoint
* Add Human Repo
* Add Human PubSub
* Add health endpoint
* Add application supervision tree
* Add configuration for local, test, and release environments
* Add umbrella dependency wiring
* Confirm both SecretHub endpoints can run simultaneously

Acceptance criteria:

* Umbrella compiles
* Existing tests continue to pass
* Human endpoint responds independently
* Human migrations run independently
* Human app can be disabled without breaking Core

---

## Milestone 1: Human Identity and Sessions

Deliverables:

* Human user schema
* Identity schema
* Session schema
* Device schema
* Password authentication
* Session creation and revocation
* Device registration
* Basic MFA extension points
* Authentication plugs
* Login audit events

Acceptance criteria:

* User can register or be provisioned
* User can authenticate
* Sessions can be revoked
* Devices can be listed and removed
* Authentication failures are rate-limited
* Sensitive fields are not logged

---

## Milestone 2: Personal Vault Foundation

Deliverables:

* Vault item schema
* Folder schema
* Item version schema
* CRUD contexts
* Soft-delete or tombstone support
* Basic sync cursor
* Encryption envelope abstraction
* Personal vault API

Initial item types:

* Login
* Secure note
* API credential
* Dynamic secret reference

Acceptance criteria:

* User can create, update, list, and delete personal items
* Item history is retained according to policy
* Deleted items are represented correctly in sync
* Server-side plaintext exposure is explicitly controlled
* Core master key is not reused

---

## Milestone 3: Bitwarden-Compatible Personal Sync

Deliverables:

* Identity/token compatibility endpoint
* Device-compatible authentication
* Cipher-compatible DTO mapping
* Folder endpoints
* Personal sync endpoint
* Revision timestamps
* Notification channel
* Compatibility test suite

Acceptance criteria:

* Official browser extension can authenticate
* Official client can perform initial sync
* Login item can be created and updated
* Folder changes synchronize
* Delete operations synchronize
* Re-login and device registration work correctly

Limit the milestone to personal vault functionality.

Organizations, Send, emergency access, and enterprise policies are out of scope.

---

## Milestone 4: Dynamic Secret References

Deliverables:

* Dynamic secret reference item type
* Core capability discovery
* Principal projection
* Dynamic secret request flow
* Lease metadata storage
* One-time reveal token store
* Reveal API
* Lease revoke action
* Lease expiry status updates

Acceptance criteria:

* Human user can request an authorized dynamic secret
* Unauthorized request is denied by Core
* Credential can be revealed only once
* Credential value is not persisted
* Lease appears in Human UI
* User can revoke an active lease
* Expired lease state is reflected correctly
* All operations are audited

---

## Milestone 5: Renewal and Approval Workflows

Deliverables:

* Lease renewal
* Approval request schema
* Approval policy projection
* Approver UI/API
* Approval expiry
* Denial flow
* Multi-step audit trail

Acceptance criteria:

* Core can require approval for selected roles
* Human request remains pending until approved
* Approval cannot exceed policy TTL
* Expired approval requests cannot issue credentials
* Renewal respects Core policy
* Denial and approval are audited

---

## Milestone 6: Organizations and Shared Collections

Deliverables:

* Human organizations
* Memberships
* Collections
* Collection permissions
* Shared vault items
* Organization-level dynamic secret references

Acceptance criteria:

* Users can share selected items through collections
* Collection access is permission-controlled
* Dynamic secret references can be shared without sharing issued values
* Removing membership removes future access
* Existing active leases follow explicit revocation policy

---

## Milestone 7: Attachments and Extended Vault Types

Deliverables:

* Attachment metadata
* Encrypted attachment storage
* Storage backend abstraction
* TOTP items
* SSH key items
* Identity and payment card item types
* Secure export policy

Acceptance criteria:

* Attachments are encrypted independently
* Storage backend never sees plaintext
* Attachment size and quota limits are enforced
* Export actions require explicit authorization and audit

---

## 16. Testing Strategy

### Unit Tests

Cover:

* Domain commands
* Encryption envelope logic
* Principal projection
* DTO mapping
* Lease state transitions
* Reveal token lifecycle
* Approval transitions

### Integration Tests

Cover:

* Human to Core dynamic secret issuance
* Core policy denial
* Lease renewal and revocation
* Audit generation
* Independent Repo operation
* Two-endpoint startup

### Compatibility Tests

Create black-box tests for:

* Bitwarden authentication
* Device registration
* Personal sync
* Cipher CRUD
* Folder CRUD
* Deletion and revision behavior

Run compatibility tests against official Bitwarden clients where automation is practical.

### Security Tests

Cover:

* Token replay
* Reveal token reuse
* Session fixation
* Device mismatch
* Expired reveal
* Unauthorized lease access
* Log leakage
* Error-report leakage
* Rate limiting
* Brute-force protection

---

## 17. Operational Requirements

Add separate configuration for:

```text
HUMAN_DATABASE_URL
HUMAN_ENDPOINT_HOST
HUMAN_ENDPOINT_PORT
HUMAN_SECRET_KEY_BASE
HUMAN_ENCRYPTION_CONFIG
HUMAN_REVEAL_TTL
HUMAN_SESSION_TTL
HUMAN_SIGNUPS_ENABLED
```

Operational metrics should include:

```text
human_sessions_active
human_login_failures_total
human_vault_items_total
human_dynamic_requests_total
human_dynamic_requests_denied_total
human_reveals_total
human_reveal_failures_total
human_active_leases
human_pending_approvals
```

Add health checks for:

* Human Repo
* Human Endpoint
* Core access boundary
* Reveal store
* Notification subsystem

---

## 18. Explicit Non-Goals for the First Release

Do not implement these in the first release:

* Full Vaultwarden feature parity
* Full Bitwarden enterprise compatibility
* Emergency access
* Directory synchronization
* SCIM
* Bitwarden Send
* Enterprise policy matrix
* Full FIDO2/WebAuthn compatibility
* Cross-region active-active Human database
* Offline dynamic secret issuance
* Persistent caching of dynamic credential values
* Direct Core database access
* Shared Core/Human encryption master key

---

## 19. Engineering Constraints

The implementation must:

* Follow functional Elixir design
* Use explicit context boundaries
* Avoid direct Repo access from Web modules
* Avoid global mutable state
* Use supervisors for lifecycle ownership
* Use Tasks or Oban only for bounded asynchronous work
* Preserve existing SecretHub behavior
* Add no circular umbrella dependencies
* Keep Core independent from Human
* Keep Human optional at runtime
* Keep credential values out of persistence and logs
* Use opaque identifiers between Human and Core
* Add tests before expanding protocol scope

---

## 20. First Codex Execution Scope

For the first implementation pass, complete only Milestone 0.

Tasks:

1. Inspect the existing umbrella structure and dependency graph.
2. Generate `apps/secrethub_human` as a Phoenix application with its own Endpoint.
3. Add `SecretHub.Human.Repo`.
4. Add a dedicated database configuration.
5. Add `SecretHub.Human.PubSub`.
6. Add `SecretHub.HumanWeb.Endpoint`.
7. Add a minimal router with:

   * `GET /health`
   * `GET /`
8. Add the app to umbrella configuration and release startup.
9. Ensure existing SecretHub endpoint remains unchanged.
10. Add tests proving both endpoints can start.
11. Add documentation describing:

    * Runtime ports
    * Database configuration
    * Application boundary
    * Dependency direction
12. Do not implement accounts, vault items, or Bitwarden APIs yet.

Expected output:

* Compiling umbrella
* Passing tests
* Independent Human Endpoint
* Independent Human Repo
* No behavioral regression in existing applications
* A short implementation report listing changed files, decisions, and remaining work
