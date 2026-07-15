# Agent Security and Secret Lifecycle Completion Design

**Date:** 2026-07-16
**Status:** Approved

## Overview

This design completes the production path from a local application through a
SecretHub Agent to SecretHub Core. It covers application proof-of-possession,
Core-enforced application authorization, deployable Agent enrollment, static
cache invalidation, PostgreSQL and Redis dynamic credentials, lease lifecycle,
and automatic Agent certificate renewal.

The work is one coordinated implementation effort delivered as independently
verified vertical slices. Each slice must leave the system in an honest state:
an unsupported operation returns an explicit error and no operation reports
success before its external side effects and durable state are complete.

## Relationship to Existing Designs

This design preserves the Agent-to-Core trust decisions in
`docs/agents/trusted-agent-connection.md` and completes its deferred renewal
work.

This design supersedes the issuance, identity, renewal, revocation, and
Application-to-Agent sections of
`docs/architecture/app-certificate-issuance.md`, not only its authentication
message. For the current line-delimited UDS protocol, applications prove
possession of their certificate private key with a signed, connection-bound
challenge. The local hop is a filesystem-protected Unix socket with
application-layer authentication, not TLS or mTLS; confidentiality relies on
kernel isolation, restrictive socket-directory ownership, and socket mode.

The approved future Agent Client API in
`docs/superpowers/specs/2026-03-25-agent-client-api-design.md` still owns the
eventual length-prefixed framing, streaming, and standalone client libraries.
This design supersedes its peer-credential authorization model and requirements
R3, R14, R15, and R19 in
`docs/superpowers/specs/2026-03-26-agent-client-api-prd.md`. Peer credentials may
later be recorded as defense-in-depth context, but never authorize secret
access; every secret-capable connection must prove possession of a current
Core-issued application private key. The current OTP 28 environment also does
not expose the assumed named `peercred` socket option. Streaming and external
client libraries remain out of scope. For the currently authenticated
line-delimited protocol, this design supersedes the draft PRD's cache-hit and
offline stale-value goals: every secret release requires a current Core
authorization decision.

The future framed protocol must perform an equivalent mandatory two-step
proof-of-possession exchange before entering its `READY` state. The automatic
peer-authentication, optional one-message token/certificate authentication, and
related state-machine examples in the older design are superseded even when its
framing and streaming work is implemented.

This design also supersedes the expired-certificate recovery rule in
`docs/agents/trusted-agent-connection.md`. An Agent that lets its runtime
certificate expire cannot use it for automatic renewal; it fails closed and
requires host-identity re-enrollment plus operator approval.

## Goals

1. Authenticate local applications with Core-issued certificates and private-key
   proof rather than public certificate presentation.
2. Make Core the source of truth for Agent, application, certificate, and policy
   authorization on every secret operation.
3. Make a clean standalone Agent release enroll and connect with explicit,
   persistent host identity and state configuration.
4. Deliver and renew PostgreSQL and Redis dynamic credentials through the
   trusted runtime channel with durable ownership, revocation, and audit state.
5. Invalidate Agent state promptly after secret rotation, policy changes, and
   certificate revocation.
6. Renew Agent certificates before expiry without creating a restart window in
   which neither the old nor new certificate can connect.

## Non-Goals

- AWS STS credentials. The engine continues to return
  `aws_sts_engine_not_available`.
- Peer-credential authentication, length-prefixed UDS framing, streaming secret
  watches, or new Elixir, Node.js, and Go client libraries.
- Serving decrypted UDS cache entries while Core is unavailable. A local cache
  must never bypass current authorization.
- Replacing the Core-issued Agent runtime identity or the dedicated mTLS
  endpoint.
- Silently generating a production host identity when none was provisioned.

## Architecture

```text
Application certificate + private key
              |
              | UDS challenge and signed proof
              v
SecretHub Agent
              |
              | trusted mTLS channel
              | app_id + certificate fingerprint + operation
              v
SecretHub Core
              |
              +-- Agent runtime authorization
              +-- application and certificate authorization
              +-- Agent and application policy evaluation
              +-- static secret read or dynamic credential lifecycle
```

The Agent establishes local identity but does not decide whether that identity
is currently registered, active, bound to the connected Agent, or authorized
for a secret. Those decisions require Core state and are performed for every
operation.

## Security Invariants

- Missing or invalid Core CA material fails closed. There is no mock CA mode.
- A public certificate alone never authenticates an application.
- Authentication challenges are random, connection-bound, short-lived, and
  single-use.
- Certificate fingerprints are SHA-256 hashes of DER certificate bytes, encoded
  as lowercase 64-character hexadecimal in storage and JSON/wire fields. Signed
  transcripts decode that value to the canonical 32 raw bytes.
- The immutable application UUID is the only authorization identity. Core
  derives it from `urn:secrethub:app:<uuid>` URI SAN and requires certificate CN
  and `Certificate.entity_id` to match; application names are display metadata.
- App certificates require `clientAuth`, must be unexpired and unrevoked, and
  must be associated with the active application in Core.
- An application may access secrets only through its assigned Agent, and both
  Agent and application policies must allow the operation.
- A UDS cache hit never releases a secret without fresh Core authorization.
- Dynamic lease ownership is bound to Agent ID and application ID. The issuing
  application certificate fingerprint is immutable audit evidence, not the
  long-term ownership key across normal certificate rotation.
- Engine credentials and generated lease credentials are not stored in
  plaintext database maps.
- A pending Agent renewal certificate cannot read secrets or manage leases.
- Every Core authorization allow/denial and lifecycle issuance, renewal,
  activation, expiration, and revocation decision produces an audit event
  without logging secret values.

## Application Certificate Lifecycle

### Canonical issuance

Application issuance uses the public key from a verified CSR but builds the
certificate subject and extensions from Core state:

- CN: application UUID
- Organization: `SecretHub Applications`
- URI SAN: `urn:secrethub:app:<uuid>`
- Extended Key Usage: `clientAuth`
- Key Usage: `digitalSignature`
- `Certificate.entity_id`: application UUID
- `Certificate.entity_type`: `app`
- `Certificate.cert_type`: `app_client`

The issuance endpoint uses a dedicated, rate-limited bootstrap pipeline. The
single-use bootstrap token is its authorization; the endpoint is not placed
behind the normal vault-token pipeline. Core verifies the CSR signature,
requires RSA keys of at least 2048 bits or ECDSA P-256/P-384 keys, ignores all
CSR identity and extension fields, and injects the canonical identity above.

Issuance locks the bootstrap token and performs app lookup, Agent binding
validation, CSR verification, certificate insertion, `Certificate.entity_id`
assignment, app-certificate association, and token update as one transaction.
The token records `issuance_request_id` and `issued_certificate_id` when it is
consumed as the final transactional step. A failure leaves the token unused and
does not return an untracked certificate. A retry with the same token and request
ID receives the already-issued result; a different request ID against a used
token is rejected.

Application certificate renewal requires proof by the current private key. The
client signs a domain-separated payload containing the app ID, current DER
fingerprint, new CSR digest, and an idempotency request ID. A persistent
`app_certificate_renewals` record binds those inputs to the issued certificate.
Core checks that idempotency record before current-certificate status. When a
result exists, Core requires the original fingerprint, CSR digest, complete
normalized payload, and proof to match, verifies the proof with the stored
original certificate even if it is now `superseded`, and returns the stored
result. For a new request, Core verifies the signature with the current
certificate and rejects expired or revoked records. One transaction inserts the
new certificate and association, records the renewal result, and marks both old
records revoked with reason `superseded`. Other revocation also updates both the
application association and underlying certificate record atomically. Security
revocation uses canonical reason codes such as
`compromised`, `operator_revoked`, or `app_suspended`; those reasons drive lease
cleanup, while `superseded` does not.

### Fingerprint and certificate cutover

Fingerprint migration uses expand/backfill/cutover. The expand release adds a
nullable, uniquely indexed canonical SHA-256 fingerprint column and writes it for
new certificates. Backfill decodes every stored PEM certificate, hashes its DER
bytes, verifies uniqueness, and reports malformed or mismatched rows. Core and
Agent switch authorization and wire messages only after every active certificate
has a verified canonical value; a later contract release removes authorization
use of legacy fingerprint forms. Persisted Agent identity derives and records the
canonical value from its certificate on load. Historical audit-chain entries are
never rewritten and remain schema-versioned legacy evidence, not authorization
input.

Legacy application certificates may have name-based subjects, no canonical URI
SAN, or no `clientAuth` EKU. A preflight lists every nonconforming active
certificate. Operators issue fresh single-use bootstrap tokens and reissue those
certificates through the canonical path before strict authentication is enabled.
The v2 proof handler may be deployed behind an explicit migration gate, but
production cutover cannot enable the fail-closed verifier until preflight reaches
zero; after cutover there is no legacy-certificate compatibility bypass.

The Core database gate is the production authority for that cutover. Agents
advertise auth-v2 capability on their trusted runtime join and derive the local
authentication version from UDS state rather than application input. Gate
activation requires capable fresh Agents, Core immediately rejects requests
derived from v1 local sessions, and join replies plus post-commit notifications
monotonically move Agents to v2-only mode. A delayed notification may affect
availability but cannot authorize a legacy session, and local configuration
cannot lower a persisted Core-issued floor.

### Application-to-Agent proof

UDS authentication version 2 uses two requests. This version names the
authentication exchange inside the existing line-delimited protocol and is
independent of the future length-prefixed Agent Client API protocol version:

1. `authenticate` sends `auth_version: 2` and the application certificate. The
   Agent rejects a missing or unsupported version before creating a challenge,
   validates the chain, validity, mandatory EKU, canonical CN/SAN, and extracts
   the public key. It returns the negotiated authentication version, Agent ID,
   server-generated connection ID, challenge ID, a base64-encoded
   cryptographically random 32-byte nonce, lowercase hexadecimal fingerprint,
   selected signature algorithm, and an expiry no more than 30 seconds in the
   future.
2. `authenticate_proof` echoes authentication version, connection ID,
   challenge ID, and signature algorithm, then sends a signature over the
   canonical transcript. The transcript is domain-separated with
   `secrethub-uds-auth`, uses a fixed field order with unsigned big-endian length
   prefixes, and contains authentication version, signature algorithm, Agent
   ID, server-generated connection ID, challenge ID, challenge nonce,
   certificate fingerprint, and the action `authenticate`. IDs, algorithm, and
   action use UTF-8 bytes; nonce and fingerprint use raw bytes. The Agent rejects
   any echo mismatch, verifies the signature, and atomically consumes the
   connection-owned challenge before marking the connection authenticated.

RSA and ECDSA keys are supported. A failed, expired, or replayed challenge
closes the connection. Challenges cannot be replayed on the same connection,
another connection, or another Agent, and a connection cannot change identity
after authentication. Frames are capped at 64 KiB, only one challenge may be
outstanding, and authentication attempts are bounded before the socket closes.
Proof algorithms are RSA-PSS with SHA-256 and a 32-byte salt or ECDSA with
SHA-256 and DER-encoded signatures, selected from the certificate key type. The
CLI requires both `--agent-cert` and `--agent-key`. Legacy one-message
certificate authentication receives an explicit protocol upgrade error.

The Agent loads the CA chain from its persisted trusted state. Before enrollment
has produced that state, UDS authentication returns unavailable rather than
accepting untrusted material.

## Core Authorization

Every application-originated static read, dynamic generation, and explicit
lease request carries the certificate fingerprint and the Agent's locally
derived application ID over the already authenticated Agent channel. Core
treats both as claims. It derives Agent ID only from the trusted socket, resolves
the certificate by fingerprint, derives the application from the certificate
association, and requires the claimed application ID to match. Delegated lease
renewal and system-triggered cleanup carry only public `lease_id`; Core derives
their application, issuing-certificate evidence, and ownership from the durable
lease instead of trusting caller-supplied identity. Core then performs these
checks in order:

1. The socket's Agent certificate has an `active` binding, or a bounded
   `retiring` binding whose `retire_until` has not elapsed during an in-progress
   rollover. The certificate must still be unexpired, unrevoked, and bound to
   the enrolled host identity. A `pending_validation` certificate is never
   accepted on the runtime topic.
2. The application exists, is active, and is assigned to that Agent.
3. A live application request uses an unexpired, unrevoked `app_client`
   certificate associated with that application. A delegated automatic renewal
   uses a renewable lease owned by the socket's Agent and an application that
   still has an active certificate; the issuing fingerprint remains evidence
   rather than the active ownership key.
4. The Agent policy permits the resource and operation.
5. The application policy permits the resource and operation.

System-triggered expiration, compromise cleanup, and operator revocation are
safety actions, not access grants. They validate lease identity, immutable
issuing configuration, and idempotent state but do not require an active app or
certificate, a current Agent assignment, or a policy allow; otherwise the state
that triggered cleanup could prevent credential removal. Their outcomes are
still audited against the owning Agent and application.

`Policy.entity_bindings` is authoritative and uses typed canonical values such
as `agent:<agent_database_uuid>` and `application:<app_uuid>`. An
expand/backfill step resolves legacy untyped values and fails on ambiguous or
missing entities before the evaluator stops accepting them. The legacy
`Application.policies` name list is maintained transactionally for UI
compatibility but is not evaluated independently.

Agent and application policies are evaluated as two independent gates, not as a
merged policy set. Explicit deny wins in either gate. Runtime operations use the
stable names `read`, `generate`, `renew`, and `revoke`; unknown or malformed
conditions and conditions missing required request context fail closed. Core
rechecks identity and both policy gates in the linearizable authorization
transaction described below before accepting a read or lifecycle intent.

Policy resources use the repository's existing dot-delimited canonical paths:
static secrets use their normalized stored path, such as `prod.db.password`, and
dynamic roles use `dynamic.<role_name>`. Empty segments, traversal syntax, and
slash-delimited aliases are rejected before policy evaluation. The future
length-prefixed client API must translate its external path syntax to this
canonical form rather than introduce a second policy namespace.

Core stores one global authorization epoch and a subject-version row for each
Agent and application. Certificate revocation, app or Agent status/assignment
changes, and scoped policy binding or content changes lock affected subject rows
`FOR UPDATE` and increment them in the same transaction as the change. A global
policy change locks and increments the global epoch instead. A static read locks
the global, Agent, and application version rows `FOR SHARE`, locks the
application, certificate, and current secret-version rows, evaluates both policy
gates, and prepares the value or `not_modified` result inside one transaction.
Commit is the operation's authorization linearization point: a writer that
committed first is observed; a writer blocked behind the reader is ordered after
that read. Response bytes may arrive after a later revocation, but Core never
authorizes from state older than a writer already committed at the linearization
point.

Dynamic issuance uses the same subject-version locks when it records its durable
intent and rechecks them immediately before the external side effect. Because an
external system cannot join the Core transaction, a later revocation wins by
marking the pre-created cleanup intent and converging through the serialized
lease lifecycle below.

Static reads are audited with actor type `application`, actor ID equal to the
application UUID, and Agent ID plus certificate fingerprint in event metadata.
The Agent does not release a static secret from its local cache without a Core
round trip. The Agent includes its cached monotonic path-mutation revision in
the read request. After authorization Core returns either the current value and
revision or an explicit `not_modified` response for that same revision; only the
latter permits the Agent to release the matching cached value. Delete retains
the revision row, so recreating a path cannot reuse an older revision. Dynamic
credential values are never placed in this static cache; the renewal subsystem
stores only nonsecret lease scheduling metadata.

## Agent First Boot and Packaging

The standalone release reads and passes:

- `SECRET_HUB_AGENT_CORE_URL`
- `SECRET_HUB_AGENT_STATE_DIR`
- `SECRET_HUB_AGENT_HOST_KEY_PATH`
- `SECRET_HUB_AGENT_SOCKET_PATH`

Configuration precedence is environment value, release application config,
then the documented production default. `Agent.Application` passes the resolved
values into RuntimeBootstrapper, enrollment, UDS server, and persisted-state
loading rather than allowing each process to invent a different default.

First enrollment requires a persistent RSA or ECDSA SSH host-identity private
key at the configured path. It must be a regular, non-symlink file owned by the
Agent runtime UID with no group or world access. The Agent derives the public
SSH key and canonical SSH fingerprint without copying or logging the private
key. Container deployments mount a dedicated key owned by the Agent UID rather
than a root-only host SSH private key. Development tooling may generate an
explicitly named local key, but release startup never creates a fallback
identity.

An Agent with valid persisted runtime certificate material may start when the
enrollment host key is temporarily unavailable, because runtime identity is the
Core-issued certificate. A first boot without either identity fails clearly and
does not create an enrollment. Enrollment retries resume the one nonterminal
record for the same host fingerprint and idempotency key instead of creating
duplicate pending Agents; Core serializes on the canonical host fingerprint and
a partial unique constraint rejects concurrent different request IDs for the
same nonterminal identity. A changed host fingerprint requires operator action.

The published Docker image creates a writable socket directory, uses the actual
release environment names, and checks that the UDS accepts a bounded liveness
probe. A pre-authentication `health` action returns only liveness,
identity-material readiness, and Core-connection readiness; it exposes no
identity or secret data. The container health check uses liveness, while
operator readiness checks may require the other states. It does not claim Core
readiness merely because the process exists. Docker Compose and deployment
examples use the published Dockerfile, `/app` state path, persistent state and
host-key mounts, the real container UID, and the correct Core URL variable.
`mix agent.run` defaults to the HTTP development endpoint and relies on the
existing explicit development allowance for insecure enrollment.

The socket directory is owned by the Agent runtime UID and an explicitly
configured application group, with mode `0750`; the socket uses mode `0660`.
Release startup refuses group/world-writable directories or a world-accessible
socket instead of weakening local-hop confidentiality.

The UDS server may start before enrollment completes, but it denies
authentication until trusted CA material is available. RuntimeBootstrapper
reloads that material after enrollment succeeds.

## Dynamic Secret Model

### Roles and engine configuration

A persistent `dynamic_secret_roles` record defines:

- unique role name and enabled status
- engine configuration reference
- creation, renewal, and revocation statements or engine-specific rules
- default and maximum TTL
- absolute maximum lifetime and maximum renewal count
- non-secret metadata

PostgreSQL and Redis are supported. AWS STS remains explicitly unavailable.

Published engine-configuration versions are immutable. Updating a configuration
creates a new version, while existing leases retain the issuing version.
Configuration stores non-secret connection metadata and a stable reference to a
static SecretHub secret containing administrative credentials. Generation,
renewal, and cleanup resolve the current version of that credential secret and
audit the version used. Resolving it is an internal, separately audited operation
that requires the vault to be unsealed; it does not use or broaden the
requesting application's secret policy. Plaintext passwords or cloud keys in
`engine_configurations.config` are rejected for the production dynamic path.
An administrative secret has a database-enforced, irreversible
`internal_engine_admin` access class. Runtime and REST application paths reject
that class before wildcard policy evaluation; only an immutable engine-version
reference and the bounded internal resolver can decrypt it.

`EngineConfiguration` contains connection-level settings only; engine-specific
creation, renewal, and revocation rules live in the dynamic role. Backfill splits
recognized legacy mixed maps into those two records and reports an unsupported
shape for operator correction rather than guessing or retaining hard-coded
roles.

For revocation only, an authentication failure with the current administrative
credential may try still-retained prior secret versions newest-first within a
configured attempt bound, because an external rotation may not yet match Core.
Generation and renewal never use stale administrative credentials. If cleanup
cannot authenticate with any retained version, the lease becomes
`cleanup_blocked`, remains scheduled for retry, and raises an operator alert.

### Lease storage

Leases store role and immutable configuration version IDs, Agent ID,
application ID, issuing application certificate fingerprint, timing, engine
type, lifecycle state, auto-renew delegation, app-scoped idempotency request ID,
deterministic external principal ID, and encrypted credential material. Agent ID
and application ID are the authorization ownership fields; the certificate
fingerprint remains audit evidence across normal application-certificate
rotation. Runtime issuance never defaults ownership to `system`.

Lifecycle states are `pending_issue`, `active`, `issue_failed`,
`cleanup_required`, `cleanup_blocked`, `renewing`, `revoking`, `revoked`, and
`expired`. Transitions are validated and fenced by operation token.

The lease also stores the minimum immutable issuing snapshot needed for later
renewal and revocation when the active role or configuration changes: endpoint,
role statements/rules, external principal, and stable administrative-secret
reference, but not the administrative credential value. Generated credentials
and sensitive snapshot fields are encrypted with the unsealed vault master key
before insertion. Ciphertext uses a versioned binary envelope and AEAD additional
authenticated data containing table, record ID, field, and key version. List and
audit APIs never return ciphertext or plaintext credentials.

Existing plaintext configuration and lease data moves through an
expand/backfill/contract migration. The expand release adds ciphertext/reference
columns and reads legacy values while writing only the secure representation. An
unsealed, resumable backfill moves engine credentials into stable referenced
static secrets, encrypts lease credentials, and verifies every row. Only after all
nodes run the new code may the contract release clear and drop plaintext
fields; that point of no return and its lossy rollback limits are explicit.
Upgrade preflight also fails on orphan applications or rows that cannot be
backfilled, reports their identifiers, and never silently deletes identities or
external credentials.

### Generation

The current line-delimited UDS exposes three authenticated actions:

- `generate_dynamic_secret` accepts role, requested TTL, and an app-scoped
  request ID, plus explicit `auto_renew` (default `false`). It returns public
  `lease_id`, initial credentials, expiry, and renewable status.
- `renew_lease` accepts public `lease_id`, requested increment, and request ID.
  PostgreSQL and Redis keep the same credential and return updated lease
  metadata; renewal does not re-deliver the password.
- `revoke_lease` accepts public `lease_id` and request ID and returns the final
  lifecycle state.

The CLI exposes these through `secrethub secret generate <role> --ttl <seconds>`,
`secrethub lease renew <lease_id> --increment <seconds>`, and
`secrethub lease revoke <lease_id>`. Agent transport requires `--agent-socket`,
`--agent-cert`, and `--agent-key`; it never falls back to a vault token when an
Agent socket was requested. `--auto-renew` opts generation into the bounded
Agent-managed renewal delegation.

The Ecto primary key remains internal. The unique `lease_id` is the identifier
used by UDS and channel APIs, Agent state, audit metadata, and Oban jobs. The
Agent tracks successful opted-in generation responses for automatic renewal.
Streaming watch delivery, reconnect re-subscription, and PRD requirements
R5-R13 remain a separate future protocol-v1 deliverable; this slice provides
request/response delivery only.

Generation idempotency is scoped by application ID and request ID. Repeating an
authorized request with the same normalized role, TTL, and `auto_renew` value
returns the existing lease and, while it remains active, the same decrypted
initial credentials; changing the payload returns a conflict. This makes a lost
initial response retryable without creating another external principal. Renew
and revoke requests use their own scoped idempotency records and return the
stored transition result.

The Agent maps `generate_dynamic_secret` to `secret:dynamic_generate` with the
role, requested TTL, `auto_renew`, idempotency request ID, and authenticated
application principal. Core rejects unsupported engines before any side effect,
then:

1. authorizes Agent and application for the role;
2. loads the enabled role and engine configuration;
3. resolves administrative credentials from the referenced static secret;
4. in one database transaction, inserts a `pending_issue` lease with the
   idempotency key, deterministic external principal, encrypted issuing snapshot,
   operation token, and a unique short-deadline Oban cleanup intent;
5. acquires the lease advisory lock and reauthorizes the same Agent/application
   pair immediately before the external side effect, retaining the lock through
   finalization or cleanup handoff;
6. generates PostgreSQL or Redis credentials using that external principal;
7. in one database transaction, uses compare-and-swap on the operation token and
   absence of `revoke_requested_at`, encrypts the generated credentials, moves
   the lease to `active`, reschedules its pre-created lifecycle job for
   expiration, and appends the issuance audit event; and
8. returns the plaintext response only after that transaction commits.

A database transaction cannot contain the PostgreSQL or Redis side effect. Every
engine error, timeout, partial multi-statement result, lost response, or
post-creation persistence failure is treated as ambiguous success. Core attempts
to move the lease to `cleanup_required`, wakes the already-durable lifecycle job,
and returns an error. If Core's database is unavailable after external creation,
the pre-created job still finds the stale `pending_issue` row after restart and
performs idempotent cleanup of the deterministic principal. Only after cleanup
confirms the principal absent does the row become terminal `issue_failed`; the
same request may then retry by creating a new fenced operation on that row. A
best-effort immediate cleanup never replaces the durable intent. Network retries
reuse the app-scoped request ID and deterministic external principal, so they do
not create duplicate users. Core never reports success with an untracked
credential.

When the vault is sealed, generation, renewal, and revocation return a stable
sealed error. Durable cleanup and expiry jobs retry without placing credentials
or configuration in job arguments. Plaintext exists only in bounded process
memory, the initial successful response, and an authorized idempotent replay of
that response.

### Renewal and revocation

The Agent `LeaseRenewer` uses only the trusted runtime channel. On startup it
reloads only active `auto_renew` leases for its Agent from Core, then schedules
renewal at the configured threshold. A renewable generation records the
application's bounded delegation for Agent-managed renewal; the Agent does not
fabricate a live app certificate claim after the local application disconnects.
Core derives the application from the lease and re-evaluates its current status
and policy.

- PostgreSQL renewal executes the role's renewal statement, normally
  `ALTER ROLE ... VALID UNTIL`, using the engine's safe identifier quoting and a
  validated timestamp rather than raw interpolation, plus the immutable issuing
  configuration, before extending the lease record.
- Redis renewal extends the durable lease; the ACL user remains active until
  the expiration worker or manual revocation deletes it because Redis has no
  native ACL-user TTL.
- Explicit renewal checks the currently authenticated app certificate. Both
  explicit and delegated renewal check Agent ownership, application status, at
  least one active app certificate, both policies, maximum TTL, absolute
  lifetime, and maximum renewal count.
- Manual and automatic revocation are idempotent: cleanup moves the lease to
  `revoking`, and only engine success moves it to terminal `revoked` or `expired`
  according to the trigger. Failure leaves a retryable state rather than
  claiming cleanup.

Every external lease operation acquires a database-backed advisory lock keyed by
`lease_id`; all Core nodes use the same lock. Unlike an Ecto row lock, the
operation process holds this lock across the external PostgreSQL or Redis call.
Renewal first commits state `renewing`, a unique operation token, and target
expiry. A concurrent revocation or expiry request records
`revoke_requested_at` and wakes its lifecycle job, then waits for the advisory
lock. After the engine call, renewal finalizes with compare-and-swap only when
its token still matches and no revoke was requested. Otherwise it performs or
hands off cleanup before releasing the lock. An ambiguous renewal result never
extends the durable lease and instead transitions to cleanup.

If the operation process crashes, its advisory lock is released and the
pre-created lifecycle job reconciles `renewing`, `revoking`, or stale pending
state. Cleanup is repeated idempotently after the engine quiescence timeout so a
late external completion cannot resurrect the principal. This operation token,
advisory lock, revoke-request flag, and reconciliation rule make revocation or
expiry converge after any concurrent renewal rather than relying on a database
row lock across an external side effect.

PostgreSQL is authoritative for lease state. Oban uniquely owns durable expiry,
revocation, and compensating cleanup; `LeaseManager` becomes a stateless context
and does not schedule competing in-memory expiry timers. Jobs contain only
`lease_id`, use string-key arguments, acquire the shared advisory lock, then lock
the row and make fenced, idempotent state transitions. If a worker wakes at an
old expiry after renewal, it observes the new timestamp and snoozes until the
current expiry. External or sealed-vault failures retry with backoff and emit an
operational alert after the configured threshold. PostgreSQL `VALID UNTIL` is a
defense-in-depth expiry backstop; Redis cleanup uses a high-priority queue
because SecretHub is its only TTL control.

Normal app-certificate rotation does not strand app-owned leases. Application
suspension or Agent reassignment sets `revoke_requested_at` on every nonterminal
application lease, transitions pending issuance to cleanup, and wakes all
lifecycle jobs. Explicit compromise revocation does the same for nonterminal
leases issued through that fingerprint; normal supersession does not. No
suspended or revoked identity may generate or renew a lease.

## Cache and Runtime Notifications

Core publishes a path/revision-only `secret:rotated` event after a successful
mutation or rotation and a scoped `policy:updated` event after policy binding or
content changes. The revision is a monotonic per-path mutation counter that
survives deletion and recreation. Certificate and application revocation emit
an app identity event.

The Agent:

- invalidates the rotated path;
- clears affected application cache entries after policy changes;
- closes matching authenticated UDS connections after app certificate or app
  revocation; and
- removes revoked or expired dynamic leases from cache.

Notifications are an optimization, not a correctness boundary: they may be
duplicated, delayed, reordered, or missed during disconnect. The Agent keeps
per-path revision tombstones so an older in-flight response cannot repopulate a
rotated value, and it clears or reconciles application caches on reconnect.
Static UDS reads still require current Core authorization and a matching current
revision, so a missed event cannot release stale data. Dynamic credential
values are not cached; lease scheduling metadata is scoped by application and
lease and contains no credential material.

## Agent Certificate Renewal

RuntimeBootstrapper is the sole Agent renewal coordinator. It schedules renewal
at approximately 70 percent of the certificate lifetime and resumes persisted
renewal state after restart. Core introduces `agent_certificate_bindings` because
the existing single `agents.certificate_id` invariant cannot represent rollover.
Each binding references an Agent and certificate and has lifecycle state
`pending_validation`, `active`, `retiring`, or `revoked`, plus idempotency and
transition timestamps and mandatory `retire_until` for a retiring binding.
`agents.certificate_id` remains a transactionally updated
compatibility pointer to the primary active certificate. Backfill creates one
active binding for each valid existing pointer and fails on missing, mismatched,
or revoked references. Partial unique constraints permit at most one binding in
each of `active`, `pending_validation`, and `retiring` per Agent. Every mutating
transition locks the Agent and its bindings; a new renewal is rejected until the
current pending or retiring workflow terminates. This permits active+pending
during validation and active+retiring during bounded rollback without allowing
concurrent rollover workflows.

The flow is intentionally two-phase:

1. RuntimeBootstrapper generates a new private key and CSR locally, writes them
   with the renewal ID to an owner-only pending generation, and fsyncs it before
   sending the CSR. Core never receives the private key.
2. The active Agent connection submits the CSR. Core issues a stored pending
   binding bound to the same Agent and enrolled host identity. Repeating the
   renewal ID returns the same candidate. The Agent completes and fsyncs the
   pending generation with the certificate and chain; the current pointer and
   old certificate remain unchanged.
3. The Agent opens a second mTLS connection with the pending material. That
   connection may only join a dedicated renewal-validation topic and inspect or
   advance its own renewal; it cannot send heartbeats, read secrets, or manage
   leases.
4. After validation, the Agent marks the pending generation ready using an
   atomic rename and directory fsync while retaining the known-good old
   generation.
5. The restricted connection requests activation. Core atomically promotes the
   candidate to `active`, marks the old binding `retiring`, and updates the
   compatibility pointer. The old certificate remains usable only until its
   stored `retire_until` rollback deadline.
6. The Agent atomically switches its current-generation pointer and opens a
   normal runtime connection with the new certificate.
7. Only after Core accepts that normal runtime join does it finalize the
   renewal, revoke the retiring certificate, and disconnect its old runtime.
   The Agent removes the old generation only after receiving finalization.

Startup chooses the last fully committed generation and reconciles it with Core
renewal state. A crash before issuance resumes the persisted CSR and renewal ID;
a crash before activation leaves the old binding active. A crash after
activation but before the pointer switch can still use the retiring old identity
to resume. A crash after the switch resumes with the candidate. If the new
certificate cannot make a normal runtime join before the rollback deadline,
Core restores the old binding to active only if it is still within
`retire_until`, unexpired, unrevoked, uncompromised, and bound to the same host.
Otherwise rollback fails closed and requires operator re-enrollment. On an
eligible rollback Core revokes the candidate; the Agent switches back to the
retained generation and removes the candidate only after revocation is
confirmed. Repeated validation, activation, join, finalization, and rollback
requests are idempotent. A revoked or expired current certificate never
auto-enrolls or renews; it requires operator approval.

The token-authenticated 501 renewal endpoint is removed from the advertised
surface because Agent renewal is available only through the trusted channel.

## Errors and Audit

Protocol errors use stable codes and do not expose inspected database or crypto
terms. Required codes include:

- `INCOMPATIBLE_VERSION`
- `CA_UNAVAILABLE`
- `INVALID_CERTIFICATE`
- `PROOF_REQUIRED`
- `PROOF_FAILED`
- `IDEMPOTENCY_CONFLICT`
- `ENROLLMENT_IN_PROGRESS`
- `RENEWAL_IN_PROGRESS`
- `UNAUTHORIZED`
- `FORBIDDEN`
- `ROLE_NOT_FOUND`
- `ENGINE_UNAVAILABLE`
- `VAULT_SEALED`
- `LEASE_NOT_FOUND`
- `LEASE_NOT_RENEWABLE`
- `LEASE_CLEANUP_PENDING`
- `RE_ENROLLMENT_REQUIRED`
- `UNAVAILABLE`

Expected authorization and validation failures return errors. Unexpected
process failures crash under supervision. External generation, renewal, and
revocation failures are audited with the resource identifiers and sanitized
reason, never credentials.

## Data Changes

The implementation requires migrations for:

1. persisted upgrade gates and fresh Core/Agent capability evidence for
   mechanical cutover decisions;
2. enrollment request/payload idempotency plus nonterminal canonical host-key
   fingerprint uniqueness;
3. `app_bootstrap_tokens.issuance_request_id` and
   `app_bootstrap_tokens.issued_certificate_id` for issuance idempotency;
4. `app_certificate_renewals` for payload-bound renewal idempotency;
5. a canonical certificate SHA-256 fingerprint column, with
   expand/backfill/cutover from legacy forms;
6. a validated `applications.agent_id -> agents.id` foreign key, with a
   fail-fast orphan preflight;
7. a global authorization epoch, authorization-subject version rows, typed
   policy entity bindings, and monotonic secret-path revisions, with
   deterministic backfill from legacy raw identifiers;
8. `dynamic_secret_roles`, immutable engine-configuration versions, stable
   administrative-secret references, irreversible internal-secret access
   classification, and their restrictive foreign keys;
9. lease public ID, lifecycle state, auto-renew delegation, operation token,
   target expiry, `revoke_requested_at`, deterministic external principal,
   role/configuration version, application ownership, issuing certificate
   evidence, encrypted credentials/snapshot fields, and scoped operation
   idempotency records; and
10. `agent_certificate_bindings` for pending, active, retiring, and revoked
    rollover states, including renewal uniqueness and `retire_until`.

Active roles or leases prevent deletion of an issuing configuration version.
No migration silently removes or rewrites unresolved identity or active lease
records. Operator-facing preflight output identifies data that must be resolved
before constraints are validated. Sensitive-field conversion follows the
expand/backfill/contract sequence above rather than attempting vault-dependent
decryption inside a schema migration.

## Testing Strategy

Implementation follows red-green-refactor for each vertical slice.

### Focused tests

- Certificate issuance: CSR signature and key strength, ignored CSR identity
  fields, canonical identity, EKU, transactional token use, lost-response
  issuance/renewal idempotency, and revocation consistency.
- UDS authentication: missing CA, self-signed certificate, wrong key, missing EKU
  or URI SAN, tampered transcript, expired challenge, same- and cross-socket
  replay, wrong Agent binding, echoed-field mismatch, RSA and ECDSA proof,
  oversized frame, re-authentication, missing version, legacy auth, and
  incompatible client version.
- Core authorization: wrong Agent, suspended app, revoked/expired certificate,
  independent Agent/app allow, deny precedence, fail-closed conditions,
  subject-version reader/writer ordering, revocation committed before the read
  linearization point, and audit actor identity.
- Startup: state and host-key environment propagation, missing or changed key,
  bad ownership/mode, symlink rejection, no release fallback, container UID and
  mounts, enrollment-phase restart, duplicate-enrollment prevention, writable
  socket, and real UDS liveness/readiness reporting.
- Dynamic contexts: role resolution, encrypted storage, ownership, TTL bounds,
  absolute lifetime, idempotent generation, ambiguous and partial engine
  results, stale-pending cleanup, failure after external creation, concurrent
  renew/revoke, stale operation token, late external completion, Core restart
  before expiry, sealed-vault retry, current and prior admin-credential cleanup,
  PostgreSQL real renewal, Redis durable cleanup, normal certificate
  supersession, compromise cleanup, idempotent revocation, and audit events.
  Tests assert database rows, logs, and Oban arguments contain no plaintext
  secrets.
- Cache notifications: rotation, policy update, app revocation, duplicate,
  out-of-order and missed events, reconnect reconciliation, revision tombstones,
  and an in-flight stale response after rotation.
- Agent renewal: scheduling, restricted candidate privileges, atomic generation
  persistence, activation, normal runtime acceptance, finalization, rollback,
  expired/compromised rollback rejection, retiring deadline enforcement, retry
  idempotency, and crashes after every phase. Exactly one primary active
  certificate remains after convergence.
- Upgrade tests: canonical fingerprint backfill, immutable historical audit
  evidence, legacy app-certificate preflight/reissue gate, typed policy binding
  ambiguity, secure-field backfill verification, and contract-release refusal
  while an old node or unresolved row remains.

### End-to-end tests

1. Boot the full Agent application with an empty temporary state directory and
   configured host identity.
2. Observe and approve pending enrollment, complete mTLS connection, and verify
   the Agent status.
3. Issue a real application certificate, authenticate with private-key proof,
   and read an allowed static secret.
4. Verify a second application, a copied public certificate without its private
   key, and a wrong private key cannot cross the first application's policy
   boundary.
5. Generate, renew, and revoke PostgreSQL and Redis credentials through the
   CLI-to-Agent-to-Core path and verify external credential state plus audit
   records.
6. Rotate an application certificate and verify its lease remains owned by the
   application, then suspend the application and verify all of its credentials
   are cleaned up.
7. Rotate a static secret and change a policy, then verify cache invalidation and
   denial.
8. Force Agent certificate renewal, verify the candidate has no runtime
   privileges, complete a new normal runtime join, restart the Agent, and verify
   only the new material connects.

## Implementation Order

1. App PKI correctness, signed UDS proof, and Core per-app authorization.
2. Standalone Agent first-boot and packaging repairs.
3. Runtime notification production and cache invalidation.
4. Persistent dynamic roles, encrypted leases, PostgreSQL and Redis generation,
   renewal, revocation, and Oban expiry.
5. Two-phase Agent certificate renewal.
6. Full clean-boot and lifecycle E2E verification plus documentation updates.

Each phase must pass its scoped tests before the next begins. Final completion
requires the focused suites, full E2E flow, formatting, compile with warnings as
errors, Credo, and migration verification.
