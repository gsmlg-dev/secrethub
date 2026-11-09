# Host keyring subsystem

Status: implemented (`host_credentials_v1`). Requirements source: the host
keyring implementation plan supplied with this change.

The SecretHub Agent is a headless credential provider for its host. Git,
Docker, process launchers, systemd services and Python `keyring` applications
obtain credentials through the local Agent. Core remains the authority for
encrypted storage, typed policy, revisions and audit evidence. Every plaintext
release requires a fresh Core decision; there is no offline delivery path.

Out of scope: desktop keyring services, Secret Service/D-Bus, GNOME/KWallet,
OS Keychain replacement, kernel keyrings, unlock UI, application user
accounts, Windows/mobile, and changes to the Caddy mTLS management boundary.

## Components

| Layer | Module / artifact | Responsibility |
| --- | --- | --- |
| Shared | `SecretHub.Shared.HostCredentials` | Request validation, limits, resource names |
| Shared | `SecretHub.Shared.AccessAudit.Event` schema v2 | `credential_*` audit vocabulary |
| Core | `SecretHub.Core.HostCredentials` | Typed facade: locks, grants, effects, evidence |
| Core | `SecretHub.Core.HostCredentials.Management` | Operator reference bind/enable/rebind/disable |
| Core | `host_credential_bindings` table | Lookup metadata and source association; no values |
| Web | `AgentRuntimeChannel` `credential:*` | mTLS-derived principal dispatch |
| Agent | `HostCredentials.LocalAPI`, `UDSServer` | Local API, bounded concurrency, revision cache |
| Agent | `HostCredentials.Provider` | systemd `LoadCredential=` provider sockets |
| CLI | `secrethub credential …`, `git-credential-secrethub`, `docker-credential-secrethub`, `secrethub exec` | Consumers |
| Native | `secrethub-exec` | Outer launcher that `execve`s the target |
| Python | `integrations/python-keyring` (`keyrings.secrethub`) | Generic keyring backend |

## Data model

A binding (`host_credential_bindings`) belongs to exactly one Agent
(`owner_agent_id`, the database UUID derived from the authenticated runtime
certificate). Its identity is unique per Agent:

`(owner_agent_id, namespace, service, authority, account, context)`

| Namespace | `service` | `authority` | `account` | `context` |
| --- | --- | --- | --- | --- |
| `git` | protocol (`https`) | host, including port | username | path supplied by Git (`""` if omitted) |
| `docker` | normalized registry key | `""` | `""` (one credential per registry) | `""` |
| `generic` | application service name, exact | `""` | username, exact (may be `""`) | `""` |

`username` is display metadata (for Docker it may be `<token>`). Values are
never stored in the binding.

* **Owned** entries store `{"username", "value"}` in a dedicated encrypted
  Secret at `host-credentials.<agent_uuid>.<namespace>.<entry_uuid>`. Erase
  deletes the binding and that Secret.
* **Reference** entries point at an operator-chosen static Secret by stable ID
  (`source_secret_id`), with `value_field` and optional `username_field`
  selectors. Erase disables the binding. A disabled binding keeps its identity:
  a store, reconnect or source rotation cannot reactivate it. Deleting the
  source leaves the binding unusable; recreating the same path does not
  retarget it. Only `Management.enable_reference/2` or `rebind_reference/3`
  restore it.

## Authorization

Typed runtime operations: `credential_read`, `credential_write`,
`credential_delete`, `credential_list`. Static `read` never implies them.

| Resource | Used for |
| --- | --- |
| `host-credentials.<agent_uuid>.<namespace>` | create, initial listing, miss/ambiguity answers |
| `host-credentials.<agent_uuid>.<namespace>.<entry_uuid>` | existing-entry operations, per-entry list filtering |
| the source Secret path (`read`) | reference reads and identical-store acknowledgements |

Grant the collection root explicitly; `host-credentials.<uuid>.git.*` does not
include `host-credentials.<uuid>.git`. Example policy bound to
`agent:<agent_uuid>`:

```json
{
  "version": "1.0",
  "allowed_secrets": [
    "host-credentials.<agent_uuid>.git", "host-credentials.<agent_uuid>.git.*",
    "host-credentials.<agent_uuid>.docker", "host-credentials.<agent_uuid>.docker.*"
  ],
  "allowed_operations": ["credential_read", "credential_write", "credential_delete", "credential_list"]
}
```

Writers take the global authorization epoch (`FOR UPDATE`); readers share it.
Conflicting updates and deletions therefore serialize. Same-value stores and
repeated deletion are idempotent. Static runtime reads (`secret:read*`) refuse
the reserved `host-credentials.` prefix, so owned payloads are released only
through this facade.

## Local Agent protocol

Newline-delimited JSON on the existing owner-only socket (frame limit 64 KiB,
selected by `--agent-socket`, then `SECRET_HUB_AGENT_SOCKET_PATH`, then
`/var/run/secrethub/agent.sock`). No authentication exchange: the operations
are Agent-scoped and refused (`AGENT_SCOPE_REQUIRED`) on an application
auth-v2 connection.

```json
{"request_id":"<id>","action":"credential_get","params":{...}}
```

| Action | Params | `data` on success |
| --- | --- | --- |
| `credential_get` | selector, or `{"entry_id"}` | `entry_id namespace source_kind username value binding_revision source_revision` |
| `credential_put` | selector with `account` (Git/generic) or `username` (Docker), `value` | `status` (`created`/`updated`/`unchanged`) `entry_id source_kind binding_revision source_revision` |
| `credential_delete` | selector or `{"entry_id"}`, optional `expected_value` | `status` (`deleted`/`disabled`/`absent`/`unchanged`) |
| `credential_list` | `namespace`, optional `cursor`, `limit` (1–100) | `entries` (metadata only), `next_cursor` |

Selector fields: `namespace` (`git`/`docker`/`generic`), `service`,
`authority`, `context`, `account`. Omitting `account` in a Git or generic
lookup asks for a unique match (`AMBIGUOUS` when several accounts match). Limits: `service`/`authority` 255 bytes, `account`/`username`
512, `context` 1024; printable UTF-8 without control characters. Values are
exact UTF-8 strings up to 16 KiB; an empty string is a value, not a deletion.
`expected_value` erases only when it equals the current value (status
`unchanged` otherwise).

Errors (`{"status":"error","error":{"code":…}}`):

| Code | Meaning | Consumer treatment |
| --- | --- | --- |
| `NOT_FOUND` | genuine miss (authorized) | Git: empty reply; Docker: `credentials not found in native keychain`; Python: `None` |
| `AMBIGUOUS` | several accounts match | treated as a miss for lookup; erase refused |
| `READ_ONLY` | reference replacement or disabled reference | store fails |
| `FORBIDDEN`, `UNAUTHORIZED` | policy or identity denial | hard failure |
| `INCOMPATIBLE_VERSION` | Core lacks `host_credentials_v1` | hard failure |
| `VAULT_SEALED`, `UNAVAILABLE`, `SOURCE_UNAVAILABLE`, `AUDIT_UNAVAILABLE`, `BUSY` | not available now | hard failure |
| `UNCONFIRMED` | write/delete transport timeout; outcome unknown | report, do not auto-retry |
| `INVALID_REQUEST`, `INVALID_VALUE`, `RESPONSE_TOO_LARGE` | rejected | hard failure |

Each request runs in a supervised task (64 Agent-wide, 8 per connection), so
slow Core calls do not stall other helpers. Responses always echo
`request_id`; clients must check it.

## Runtime protocol and compatibility

The Agent advertises `host_credentials_v1` and uses `credential:get|put|delete|list`
only after Core accepts it. Older Core peers never accept the capability, so
the Agent returns `INCOMPATIBLE_VERSION` locally. Older Agents are unaffected.
Existing `get_secret`, application auth-v2, framing and audit v1 are unchanged.

Agent cache entries for credentials are keyed by the canonical selector and
hold the binding and source revisions. The Agent sends them as `known`; Core
re-runs the full authorization and returns `not_modified` only when both exact
revisions still match. Denial, sealing, outage or audit failure invalidates the
entry and never releases cached plaintext.

## Audit

Access observations gain schema version 2. It has the same envelope keys as
version 1, restricted to `credential_read|write|delete|list`, with reasons
extended by `ambiguous read_only unconfirmed busy invalid_value`. Version 1
events and signatures are unchanged and cannot carry v2 vocabulary. Core also
appends `host_credential.*` entries to the checked audit chain. `secret_path`
in evidence is the opaque resource, never Git/Docker lookup data. Values,
request bodies and digests of values are never recorded.

Rollback: an older Core rejects v2 events as invalid; the Agent quarantines
them (ADR 0001) and may stop admitting requests when the quarantine is full.
Restore a v2-capable Core and replay quarantined events; do not delete them.

## Consumers

### Git (`git-credential-secrethub`)

`get`/`store`/`erase` per gitcredentials(7). Fields: `protocol`→`service`,
`host`→`authority`, `path`→`context` (only when Git supplies it, i.e.
`credential.useHttpPath=true`), `username`→`account`. Stdout carries only the
protocol reply. A miss or ambiguity prints nothing and exits 0. Agent
unavailability or denial prints `quit=true` for `get` and exits non-zero, so Git
stops instead of falling through to prompts. Unknown operations are ignored.
Fields containing newline or NUL are rejected. `erase` passes `password` as
`expected_value`.

```sh
git config --global credential.helper secrethub
git config --global credential.useHttpPath true   # optional, per-repository scope
```

### Docker (`docker-credential-secrethub`)

`store`/`get`/`erase`/`list` with the docker-credential-helpers framing. Registry
keys: Docker Hub aliases (`docker.io`, `index.docker.io`, `registry-1.docker.io`,
`registry.hub.docker.com`, with or without scheme or `/v1/`) map to
`https://index.docker.io/v1/`. Other registries map to the lowercase
`host[:port]` with any `http://`/`https://` prefix removed; paths other than a
trailing `/` are rejected. A miss writes
`credentials not found in native keychain` to stdout and exits 1.

```json
{"credsStore": "secrethub"}
```

or per registry: `{"credHelpers": {"registry.example.com:5000": "secrethub"}}`.

### General CLI

```sh
secrethub credential get    --namespace generic --service SVC --account USER [--format json]
printf %s "$VALUE" | secrethub credential put --namespace generic --service SVC --account USER
secrethub credential delete --namespace generic --service SVC --account USER
secrethub credential list   --namespace git
```

Values are read from stdin, never from arguments.

### `secrethub exec`

`secrethub exec --map MAP.json [--replace-env] -- TARGET ARGS…` resolves every
mapped credential through the Agent, then replaces itself with `TARGET`
(no shell). Map:

```json
{"env": {"DB_PASSWORD": {"entry_id": "<uuid>", "field": "value"},
         "DB_USER": {"entry_id": "<uuid>", "field": "username"},
         "OPTIONAL": {"entry_id": "<uuid>", "field": "value", "allow_empty": true}}}
```

Implementation: `secrethub` (wrapper) → `secrethub-exec` (native) forks the CLI
resolver `secrethub __exec-resolve`, reads `NAME=VALUE\0` records from a
private pipe (1 MiB limit), checks the resolver exit status, applies the
environment and calls `execvp`. Any missing, denied or empty (unless allowed)
value, NUL, invalid name, duplicate or pre-existing variable (without
`--replace-env`) stops before the target starts. SIGINT/SIGTERM/SIGHUP/SIGQUIT
received during resolution are forwarded to the resolver, which is reaped
before the launcher exits by the same signal.

`secrethub-exec --credential NAME[=ENVVAR]… [--replace-env] -- TARGET ARGS…`
is the systemd main-process mode: each `NAME` is read from
`$CREDENTIALS_DIRECTORY`, must exist and be non-empty, and is optionally
exported as `ENVVAR` (exact bytes, no NUL). This mode never contacts the Agent.

Environment injection is a startup snapshot: later rotation does not change a
running process.

### systemd services

The Agent can expose provider sockets for `LoadCredential=`; each socket maps
to exactly one binding ID and field. The provider accepts only peers with
UID 0 (the service manager), resolves the value through the same Core facade,
and writes the raw bytes on success. On any failure it closes without writing.
systemd then passes an empty credential, which the mandatory `secrethub-exec
--credential` main launcher rejects, so the target does not start. An
`ExecStartPre=` check alone is insufficient because systemd prepares
credentials again for the main process.

See `docs/deployment/nixos-agent.md` for module options and
`docs/user-guides/host-keyring.md` for operator steps.

### Python (`keyrings.secrethub`)

`integrations/python-keyring` implements `get_password`, `set_password`,
`delete_password`, `get_credential` using the generic namespace. It registers
no entry point, so it is never auto-selected; choose it explicitly with
`PYTHON_KEYRING_BACKEND=keyrings.secrethub.SecretHubKeyring` or
`keyringrc.cfg`.
