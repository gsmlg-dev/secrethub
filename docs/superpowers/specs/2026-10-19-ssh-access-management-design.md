# SSH Access Management Design

**Date:** 2026-10-19

**Status:** Draft for user review

## Confirmed Decisions

The owner has confirmed these requirements:

- SecretHub Agent provides SSH-agent signing, SSH authorized-key lookup, and
  SSH known-host lookup.
- Core stores SSH signing private keys encrypted. An authorized Agent receives
  private material only for use in memory.
- Servers can be organized into groups, and SSH access can be configured in
  bulk or for individual machines.
- An access rule identifies both ends: source machine/group and source Unix
  user, then destination machine/group and destination Unix user.

The defaults and delivery boundaries below are proposed for review. They are
not an implementation or deployment acceptance report.

## Agent skills

- [brainstorming](/home/gao/.agents/skills/brainstorming/SKILL.md): validate the
  design before implementation.
- [writing-plans](/home/gao/.agents/skills/writing-plans/SKILL.md): turn the
  approved design into bounded implementation slices.
- [using-elixir-skills](/home/gao/.agents/skills/using-elixir-skills/SKILL.md):
  select the applicable Elixir, Ecto, Phoenix, and OTP implementation guidance.
- [test-driven-development](/home/gao/.agents/skills/test-driven-development/SKILL.md):
  establish regressions for authorization and OpenSSH interoperability.
- [phoenix-duskmoon-ui](/home/gao/.agents/skills/phoenix-duskmoon-ui/SKILL.md):
  consume the existing component APIs for the management screens.
- [verification-before-completion](/home/gao/.agents/skills/verification-before-completion/SKILL.md):
  distinguish source tests, release-consumer tests, and deployment evidence.

## Outcome

An operator selects source machines or groups, source users, destination
machines or groups, and destination users. Core previews the resulting directed
access, commits the change, and serves the corresponding SSH views to Agents.

For example, `build:deploy -> app:deploy` permits the `deploy` user on each build
server to authenticate as `deploy` on each app server. It does not create the
reverse grant or a grant to another Unix account.

The same rule evaluation produces:

1. Public host keys that the source user should trust for destination endpoints.
2. Source public signing keys accepted by each destination Unix account.
3. The source signing identities available through the local SSH agent.

Every source machine/user has its own signing identity. A server group does not
share a private key.

## Existing Contracts

Core derives the connected Agent from its verified Core-issued mTLS certificate,
following [the trusted runtime contract](../../agents/trusted-agent-connection.md).
SSH requests never select their own authoritative Agent ID.

The existing application socket and
[application UDS authentication](../../security/app-uds-auth-v2.md) remain a
separate contract. A kernel UID authorizes only the new SSH-specific operations;
it never authorizes application secret reads. SSH signing keys are not exposed
through the generic secret-read API.

There are three separate key roles: the enrollment host-identity key, the Agent
TLS client key, and SSH user signing keys. SSH server host keys are inventoried
separately from all three. Enrollment currently records one RSA/ECDSA identity
key; that is insufficient evidence of every key actually served by sshd.

Management uses the existing Caddy mTLS boundary. Unix usernames and UIDs are
policy attributes, not application accounts or a new login system.

## Inventory and Rule Model

### Servers, groups, and SSH endpoints

- A server is an existing enrolled Agent, identified by its immutable Agent ID.
- Groups have explicit, operator-controlled membership. A server may belong to
  multiple groups. Agent-reported tags or capabilities cannot change membership.
- An SSH endpoint belongs to a server and records approved hostnames/IP aliases,
  port, and approved SSH host public keys and fingerprints.
- Endpoint names and ports are unique across active servers. Conflicting claims
  cannot silently replace an existing server's host identity.
- Agents may submit candidate public host keys over their authenticated runtime
  channel. The operator approves their endpoint binding. Existing enrollment
  keys are candidates only; an unauthenticated `ssh-keyscan` result cannot create
  trust.
- Host-key rotation approves the replacement before removing the old key. Only
  explicitly approved keys are returned during the overlap.
- Host public-key inventory supports Ed25519, RSA, and ECDSA server keys. This
  does not expand the separate initial user-signing algorithm set below.

### Source identities

A source identity binds one Agent, a Unix username, its approved numeric UID,
and an active SSH signing key. The Agent resolves users through the operating
system; client messages cannot assert another UID or username. A changed
username/UID binding requires operator confirmation before the identity can be
used again. Each approved username/UID binding is unique within its Agent. Unix
accounts sharing a numeric UID cannot receive separate SSH identities; ambiguous
aliases are rejected rather than presented as isolated users.

Core may generate a key or import one unencrypted Ed25519/RSA private key in an
OpenSSH or supported PEM container. It derives and checks the corresponding
public key, validates the algorithm, and encrypts the private representation
using the existing Vault encryption primitives. SSH keys have dedicated storage
and authorization, rather than an ordinary readable secret path. Importing the
same private key for another source identity is rejected.

The first implementation supports Ed25519 and RSA keys of at least 2048 bits,
with RSA-SHA2-256/512 signatures. It rejects SHA-1 signatures, encrypted private
key containers, unsupported algorithms, and multiple-key imports with explicit
format errors. Key replacement invalidates the previous signing key and its
public-key grants; graceful user-key rotation is a later extension.

The current OTP OpenSSH private-key decoder is experimental. Its use must be
isolated in a key-import module and qualified with independently generated
Ed25519 and RSA fixtures. Public-key parsing and signature verification must not
depend on round-tripping through that same implementation.

### Directed access rules

Each rule contains:

- `allow` or `deny` effect and an enabled state;
- one source selector, either a machine or a group, and an explicit source user;
- one destination selector, either a machine or a group, and an explicit
  destination user.

There are no implicit reverse edges or wildcard user grants. No matching allow
means denial. Any matching deny overrides all matching allows; rule ordering and
selector specificity do not change that result. An explicit single-machine deny
can therefore exclude one member from a group allow.

Group rules are persistent and follow membership, rather than being snapshots
of the initial selection. Membership edits preview all gained and lost access
before confirmation. New members inherit existing applicable rules only when
the operator commits that membership change. An unresolved source user has no
usable identity and cannot sign until its machine/user binding is approved.

Batch selection can create or edit several rules in one transaction. Preview
shows concrete source identity -> destination account edges, including the
rules responsible for each result. Multiple group memberships do not duplicate
keys or grants.

## Runtime Architecture

```text
Operator -> Core groups, identities, endpoints, and directed rules
                    |
                    | current authorization over existing mTLS runtime
                    v
             SecretHub Agent
              |           |
       SSH-agent socket   public-key lookup socket
              |           |                    |
       source ssh      KnownHostsCommand   AuthorizedKeysCommand
                                                |
                                         destination sshd
```

The source and destination normally use different Agents. Each runtime request
is scoped by the caller Agent's certificate, not a hostname supplied by a helper.

SSH support is opt-in in the Agent TOML. Trusted runtime negotiation advertises
versioned lookup and signing capabilities separately, so a lookup-only destination
does not claim signing support. An older Core/Agent or an unavailable capability
leaves that SSH operation unavailable; it does not fall back to generic secret
RPCs or change the existing application UDS authentication floor. Runtime RPCs
for identity listing, signing authorization, authorized-key lookup, known-host
lookup, and candidate public inventory have explicit SSH-specific contracts.

### Local endpoints and process identity

The existing private JSON socket retains its current protocol and permissions.
SSH uses two new sockets in a separate runtime directory:

- A signing socket implements SSH-agent binary framing and permits only the
  configured local client group. Every accepted connection obtains its actual
  peer UID from the kernel before identities or signatures are available.
- A lookup socket exposes only the two public-key lookup operations. A static
  lookup group includes the configured `AuthorizedKeysCommandUser`, including
  `nobody`, and local users that need known-host lookup.

Both sockets use mode `0660`, with parents traversable by the appropriate group.
The Agent service can retain `DynamicUser`; membership in the relevant static
groups permits socket creation. Its private state, TLS material, existing socket,
and configuration keep their existing restrictive access.

Source-user onboarding requires an existing Unix account and operating-system
access to the relevant socket groups. A Core rule does not create accounts or
change local group membership. The UI reports missing prerequisites instead of
showing the new grant as usable.

The first delivery targets Linux, including x86_64 and aarch64. Linux
`SO_PEERCRED` is read through OTP's native/raw socket-option API; the unimplemented
symbolic `peercred` option is not used. Unsupported platforms or unavailable
peer credentials fail explicitly rather than trusting a supplied username.

### SSH-agent operations

`SSH_AUTH_SOCK` or OpenSSH's `IdentityAgent` selects the new signing socket.
The initial protocol supports identity listing and signing. Mutation, local
key import, and unsupported extensions return the standard agent failure.
Core remains the owner of key provisioning and revocation.

Every signing request obtains fresh Core authorization for the certificate-derived
source Agent, kernel-derived UID, identity, and key revision. Identity listing
also obtains current authorization. The source identity must be active and have
at least one effective outgoing access grant to an active destination endpoint.
An applicable deny can remove the last grant.

Private material is delivered only to the trusted Agent and remains in process
memory. A memory cache is scoped to source UID, identity, key revision, policy
revision, and runtime connection generation. Cached material cannot bypass a
new Core decision. A response for an older generation cannot refill an invalidated
cache. Denial, seal, disconnect, identity/key revocation, policy change, or
runtime restart drops the affected references.

Private keys, signing payloads, and raw protocol messages are excluded from logs,
status formatting, audit payloads, and application-managed files. Dropping BEAM
references does not claim cryptographic memory zeroization. The existing
crash-dump suppression remains part of the release contract.

### Authorized-key lookup

The requested sshd interface is preserved:

```sshconfig
AuthorizedKeysCommand <base>/bin/secrethub_agent fetch-ssh-keys %u %k
AuthorizedKeysCommandUser nobody
```

The helper asks the local Agent, which asks Core as the destination machine.
`%u` is the destination account and `%k` is the offered Base64 SSH key blob.
Core resolves the offered key to its registered source identity and evaluates
current source/destination state and the exact directed user grant.

The helper validates the embedded key type and returns only matching authorized-key
lines. It cannot query private material, request signatures, or read ordinary
secrets. Running as `nobody` is not proof that sshd launched it; the lookup is
safe for any permitted local caller because it exposes public authorization
data only. The target sshd still verifies possession of the allowed private key.

The managed lines initially include `no-agent-forwarding`. Arbitrary shell
fragments and unvalidated authorized-key options are not copied from input.

### Known-host lookup

The corresponding source-side interface is:

```sshconfig
KnownHostsCommand <base>/bin/secrethub_agent fetch-ssh-host-keys %I %H %p
StrictHostKeyChecking yes
VerifyHostKeyDNS no
ForwardAgent no
```

This helper runs as the local SSH user, not as `nobody`. The Agent derives that
user from peer credentials and asks Core for approved host keys matching the
requested endpoint and at least one effective grant for that source identity.
Different allowed destination usernames do not change the endpoint's host key.

`%I` distinguishes `ORDER`, `HOSTNAME`, and `ADDRESS` lookups. All are supported;
the helper does not require a presented server key during `ORDER`. `%H` is the
known-host lookup name/address, and `%p` is the destination port. Matching handles
approved aliases, IPv4/IPv6, and nondefault-port `[host]:port` formatting without
creating a second conflicting identity for an alias.

Output is standard known-host lines containing approved host public keys. The
helper never learns trust by accepting whichever key the remote server presents.

### Helper packaging and configuration

Both commands dispatch from `bin/secrethub_agent` before normal Agent startup,
using the existing offline-command launcher pattern. They do not start the Agent
application, evaluate its private runtime configuration, read its TLS keys or
release cookie, use Erlang distribution, or write into the release directory.
Their public socket path is resolved from an explicit public override or a
documented default, independently of the private Agent TOML.
An optional `--socket <absolute-path>` selects a nondefault lookup socket;
generated profiles include it when needed rather than relying on sshd to inherit
the Agent service's environment. The original command forms work with the default.

All SSH sockets and RPCs enforce bounded input/output frames, request deadlines,
and concurrency. Helpers pass structured arguments, never construct shell
commands from usernames, endpoint names, or key content.

Successful lookups exit zero and print only protocol lines. A successful deny or
no-match lookup prints nothing. Invalid input, timeout, runtime unavailability,
or Core/audit failure exits nonzero, with sanitized diagnostics on stderr and
empty stdout. Responses are buffered and validated before any stdout is written.

Agent SSH options are explicit additions to the active TOML schema and generated
template. The NixOS module configures the sockets, directory/group permissions,
and service settings. Helpers must work under sshd's minimal environment and the
documented default socket path.

## Enforcement and Consistency

Destination sshd enforces login permission by accepting only keys allowed for
its exact Unix account. Known-host lookup verifies server identity. Basic
SSH-agent sign requests do not contain a trustworthy destination; a preceding
known-host lookup is never used as proof of the destination being signed for.

The initial product therefore provides managed SSH-identity login authorization,
not network-path enforcement or destination-bound signing. Agent forwarding is
disabled in generated profiles. OpenSSH session binding, destination-constrained
signing, SSH certificates, and forwarded-agent operation require another approved
protocol slice.

Existing OpenSSH trust sources remain relevant unless the generated managed
profile explicitly excludes them. For managed endpoints the client profile uses
only SecretHub host trust, with `UserKnownHostsFile /dev/null` and
`GlobalKnownHostsFile /dev/null` scoped to those endpoints, and
`VerifyHostKeyDNS no`. The destination profile uses `AuthorizedKeysFile none`
and public-key-only authentication, with `TrustedUserCAKeys none`, scoped to the
managed users. Qualification checks effective client and server configuration,
including applicable `Match` blocks, and rejects alternate user-certificate CA
trust. Local key files, another authentication method, or another certificate
authority must not override a SecretHub denial. Profiles are generated and
validated; applying them to running hosts is a separate deployment action.

Inventory, key, rule, and membership mutations advance one monotonic SSH policy
revision transactionally. Batch validation is all-or-nothing and uses an
expected revision to reject stale edits. Both lookup views and signing decisions
use the same evaluator and committed revision. No persistent precomputed grants
or offline authorization cache can outlive that source of truth.

Core rechecks current machine/certificate, identity, key, rule, and endpoint
state on every operation, including operations on an established runtime
connection. A revoked source identity is excluded from destination lookups even
when its public key is known. Active destinations also need an approved host key.
Core seal, unavailability, audit failure, or missing capability fails closed.

Mutation notifications invalidate Agent state; fresh Core authorization is still
required if a notification is delayed or lost. Reconnect clears SSH memory state.
An authorization already committed before a change may finish in flight; the
next authorization observes the new revision. Existing authenticated SSH sessions
are not terminated by a rule change.

All decisions and configuration changes are audited with machine IDs, source
identity, destination account/endpoint where applicable, key fingerprint, policy
revision, and outcome. An authorization decision and a completed SSH login are
different evidence: actual login outcomes belong to sshd and are not invented by
the key-lookup helper. Signing authorization and completed signing are likewise
distinct events.

## Management Workflow

The existing management UI adds server groups, SSH endpoint/key approval,
machine/user signing identities, and directed access rules.

The access matrix uses source machine/user rows and destination machine/user
columns. Group filters and multi-selection support bulk allow, bulk deny, and
rule removal. Cells show the effective result and contributing rules. Removing
one allow does not hide another allow that still grants access; denying a cell
can create an explicit deny rule.

Every batch or membership change previews concrete gained/lost access, then
commits against the previewed revision. A stale preview must be regenerated.
The UI shows unresolved users, unapproved host keys, and Agent runtime capability
instead of presenting them as usable access. Imported private keys are never
returned to the browser after storage.

## Delivery Slices and Allowed Scope

1. **Core policy and inventory:** dedicated SSH models and Core migrations,
   encrypted key handling, rule evaluator, revisions/audit, and runtime SSH RPCs.
2. **Public lookups:** Agent lookup service, both offline release commands,
   endpoint/user matching, isolated OpenSSH consumer fixtures, and scoped release
   and NixOS configuration.
3. **Signing:** Linux peer identity, SSH-agent protocol, per-user in-memory keys,
   fresh Core authorization, failure/revocation behavior, and OpenSSH consumers.
4. **Management and qualification:** group/access matrix and approval screens,
   batch previews, generated managed SSH profiles, and full scoped end-to-end
   tests of the three capabilities together.

Each slice has its own tests and review boundary. The feature is complete only
after all four pass; partial delivery does not claim the whole product works.

Implementation touches only new SSH modules and the necessary integrations in
`secrethub_core`, `secrethub_shared`, `secrethub_agent`, `secrethub_web`, the trusted
runtime channel, Agent configuration, release-command packaging, NixOS Agent
configuration, and SSH-specific documentation/tests. All database migrations
remain under `apps/secrethub_core/priv/repo/migrations/`.

The work does not alter existing generic secret authorization or application
UDS authentication, add an application user/admin system, change enrollment
identity formats, export private keys through helpers, or deploy/restart running
Core, Agents, or system sshd. Production rollout requires its own authorization.

## Acceptance Evidence

| Area | Required scoped evidence |
| --- | --- |
| Rules | Default deny; direction; exact source/destination users; overlapping groups; deny precedence; membership changes; single-machine exceptions; atomic batch rollback; stale preview rejection. |
| Host trust | Approved aliases, ports, IPv6, multiple host keys, pending/replaced keys, wrong host keys, and conflicting endpoint claims. |
| Keys | Independent Ed25519/RSA import and signature verification; public/private mismatch; duplicate source-key rejection; unsupported/encrypted containers; replacement/revocation. |
| Local isolation | Kernel-derived UID; forged identity fields; inaccessible signing socket; lookup-only `nobody`; unknown/rebound users; duplicate UID aliases; missing socket-group access or credentials; unsupported platform. |
| OpenSSH helpers | Real release commands under minimal/unprivileged environments; exact stdout/exit status; ORDER/HOSTNAME/ADDRESS; malformed input; no private config/cookie access or release writes. |
| SSH agent | Independent binary frames; identities/signing with real `ssh-add -l`, `ssh-add -L`, `ssh-add -T`, and `ssh`; fragmented/oversized requests; unsupported operations; cross-user denial. |
| Runtime | Revoked/expired machine credentials; disabled identities; seal/outage/audit failure; delayed invalidation and responses; reconnect and restart; no offline cache release. |
| End to end | Two source Unix users and two target accounts with allow/deny rules; real isolated sshd and actual Core/Agent runtime; allowed login, reverse denial, wrong-user denial, host-key mismatch, batch revocation, local-file fallback exclusion, alternate trusted user-certificate rejection, and DNS-trust override exclusion. |
| Management | Group/matrix actions; effective rule explanations; batch/member previews; stale edits; key approval; private data absent after import. |
| Packaging | Linux amd64/arm64 release-consumer and NixOS permission qualification, with unavailable environments explicitly reported as BLOCKED or NOT RUN. |

Only SSH-scoped tests and the existing tests needed to protect touched integration
contracts are run. An unrelated out-of-scope failure is reported without repair.
Source tests, package-consumer qualification, and live deployment evidence are
reported separately.
