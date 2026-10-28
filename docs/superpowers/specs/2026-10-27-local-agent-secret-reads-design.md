# Local Agent secret reads without application credentials

Date: 2026-10-27. Approved with optional socket/default amendment on 2026-10-28.

The owner selected shared Agent permissions: every process permitted to connect
to an Agent's Unix socket can read the secrets that Core authorizes for that
Agent. Local callers supply neither an application certificate/private key nor
a CLI login token.

## Agent skills

- [brainstorming](/home/gao/.agents/skills/brainstorming/SKILL.md): review the changed local trust boundary before implementation.
- [elixir-thinking](/home/gao/.agents/skills/elixir-thinking/SKILL.md): follow existing functional composition and explicit data flow.
- [scoped-prd-execution](/home/gao/.agents/skills/scoped-prd-execution/SKILL.md): implement only the approved local static-read slice.
- [verification-before-completion](/home/gao/.agents/skills/verification-before-completion/SKILL.md): report actual regression results and remaining verification limits.

## Caller experience and trust boundary

After the Agent has enrolled and connected to Core, a local caller can run:

```sh
secrethub secret get prod.db.password --format json
```

`--agent-socket` is optional. Socket selection follows the explicit flag, then
`SECRET_HUB_AGENT_SOCKET_PATH`, then `/var/run/secrethub/agent.sock`. The caller needs
operating-system permission to connect.
The existing socket mode remains `0600`: the Agent UID and root can connect.
There is no per-application permission distinction inside this local access
boundary.

Agent enrollment, Agent-to-Core mTLS, and Core authorization of the Agent remain
required. Local access does not authorize secrets outside the Agent's policies.
An application is not implicitly registered or assigned a synthetic identity.

The existing certificate-authenticated application read path remains available
for consumers that explicitly provide a complete certificate/key pair. A partial
pair or a failed application-authentication exchange fails without falling back
to shared Agent permissions.

## Alternatives and decision

1. **Shared Agent permissions, selected:** filesystem access to the socket is
   the local boundary; Core evaluates the Agent's policies. This needs no
   per-application credentials or UID mapping. All socket consumers share the
   same permissions and have no individual application attribution.
2. **Map operating-system UIDs to application policies:** also avoids caller
   certificates but needs identity mappings, peer-credential support and policy
   lifecycle rules. This adds configuration and is outside the selected model.

This is a deliberate change from the universal application-proof assumption in
[UDS auth-v2](../../security/app-uds-auth-v2.md) and
[ADR 0001](../../adr/0001-application-access-audit.md). The new local read mode
uses Agent-scoped authorization and audit observations; the certificate read
mode retains its existing application-proof contract.

## Protocol and data flow

1. `secret get` defaults to the local Unix socket. An explicit `--server` selects
   the existing token-authenticated Core HTTP read; combining `--server` with
   Agent-specific options is rejected. Connection failure never changes
   transport automatically. The CLI connects to the selected Unix socket. When no application
   certificate/key options are present, it sends the existing newline-delimited
   `get_secret` request directly. The JSON response envelope and value formats
   remain the same.
2. The Agent distinguishes a local connection from an explicitly initiated
   application-authentication exchange. Starting such an exchange commits that
   connection to application authentication: challenge-pending or failed
   authentication cannot enter the local read path. Existing frame limits,
   connection limits, request correlation and audit admission apply.
3. Agent and Core negotiate a new runtime capability, `local_socket_read_v1`.
   The local path is unavailable until a live trusted runtime has accepted it.
   A missing capability produces a bounded error without legacy or HTTP fallback.
4. The Agent forwards local reads using a separate runtime operation,
   `secret:read_local`. Its payload contains the path, optional known revision,
   and audit request/attempt correlation. It carries no application identity,
   application certificate fingerprint, caller-selected Agent identity or
   application authentication version. Core rejects identity claims in this
   operation's payload.
5. Core derives the Agent and its certificate from trusted mTLS socket assigns,
   checks the negotiated capability, and executes Agent-scoped static-read
   authorization. A successful response contains the value or exact-revision
   `not_modified`, version, revision, value format and Core audit correlation.
6. The Agent records the delivery observation and returns the normal local
   response. A future SDK can use this same credential-free local operation;
   this slice does not implement SDK packages or subscriptions.

The durable `minimum_uds_auth_version` is not reset or lowered. It continues to
govern application-certificate authentication and legacy application reads.
The new operation is an explicit Agent authorization contract, not a legacy
read or a fabricated auth-v2 proof. Existing bare `secret:read` requests remain
rejected at floor 2 and under the `single_operator` launch profile.

## Core authorization and cache

Add an Agent-scoped authorization entry point alongside the existing
application entry point. It acquires the global authorization epoch and Agent
subject locks, then the Agent and runtime-certificate row locks in a consistent
order. It revalidates current Agent status/certificate binding inside the
transaction and requires the existing typed runtime authorization gate.

Policies are evaluated against `agent:<database Agent UUID>`, using the existing
canonical path and operation rules. A missing policy grant, explicit deny,
malformed applicable policy, revoked/suspended Agent or invalid certificate
causes Core to refuse the read. Missing authorization state is not created by
the reader.

Reuse the existing durable Vault readiness check, secret/revision row locks,
managed-certificate delivery checks, value decoding and checked audit writes.
An exact cached revision still requires current authorization and Vault
readiness before Core can return `not_modified`.

Local cache keys contain an explicit local-Agent namespace, the Agent identity
and canonical path. They cannot collide with application/fingerprint cache
keys. Every release of cached plaintext requires a fresh Core response for its
exact revision. Core outage, denial, sealed Vault, audit failure or inconsistent
revision refuses delivery. Existing policy/reconnect/rotation invalidation
continues to apply.

## Audit semantics

Local reads keep durable Agent admission, attempt, release and transport
observations, plus correlated Core authorization/access observations. The Agent
identity comes from the authenticated runtime channel. There is no application
identity to verify or claim.

Keep the current access-audit event schema for this slice:

```text
agent_id = authenticated Agent public ID
application_id = null
identity_status = "unverified"
attribution = "none"
```

In this schema, `verified` means verified application attribution. For local
reads, `unverified` describes the absence of an identified application; it does
not mean the Core-Agent connection is unauthenticated. Existing audit queries
must retain the Agent association and must not count these requests as a
verified application's accesses. The older audit record uses actor type
`agent`. No secret value, private key, token or secret-derived digest is logged.

## Implementation boundary

The implementation covers CLI `secret get`, Agent UDS dispatch/runtime/cache,
Core Agent-scoped static authorization and capability negotiation, their
regressions, and current user-facing documentation. Reuse the existing modules;
do not add a new service, supervisor, database schema or dependency for this
slice.

Document the default socket permissions and the credential-free read command
in the Agent README, Agent deployment guide, deployment overview and CLI README.
Update current security/runtime documents to distinguish local Agent reads
from application-certificate reads. Keep historical plans as historical evidence.

CLI process execution, new SDK packages, application subscriptions, secret
write/update operations through the Agent, dynamic credentials, and configurable
group/UID policy mapping are separate work. No commit, publication, deployment,
shared/live database migration, auth-floor activation or service restart is
included.

## Acceptance and verification

- A credential-free CLI read reaches a real Unix socket and returns a secret
  authorized for the connected Agent. It does not attempt CLI login or read
  application certificate/key files.
- The Core local operation succeeds in `single_operator` at authentication
  floor 2 when Agent policy permits it. The floor remains unchanged; old bare
  reads and application-authentication downgrade attempts still fail.
- A socket remains owner-only. A complete application certificate/key pair
  continues to use the application path; partial or invalid credentials never
  fall back to local permissions. Caller-supplied identity is rejected.
- Missing capability, no policy grant, explicit deny, malformed policy,
  revoked/suspended/expired Agent identity, sealed Vault and failed audit
  persistence cannot release a value.
- Real Core authorization validates fresh and exact-revision cached reads.
  Denial/outage cannot release cached plaintext; local and application cache
  entries remain separate. Core authorization begun after a committed policy
  denial or revocation must observe that change; overlapping authorizations and
  mutations serialize through the existing lock order.
- Correlated audit observations survive ingestion/query/rebuild with Agent ID
  and null application ID, without secret contents or fabricated application
  totals.
- Run focused CLI, real UDS, trusted channel, Core authorization/locking and
  audit regressions. Core runtime tests use their disposable database fixtures;
  do not migrate a shared database or restart an existing service. Run formatting,
  the appropriate compile check, and final integrated diff review. Record any
  unavailable checks and unrelated failures explicitly.

Implementation and verification evidence is recorded in the associated
implementation plan after running the scoped checks.
