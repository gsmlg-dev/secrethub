# Read secrets from the local Agent

Local reads need no application certificate, private key or CLI login.
Operating-system permissions on the Unix socket control which processes can
connect; those processes share the Agent's Core-authorized secret permissions.

## Prepare the Agent and read a secret

Follow the [deployment guide](../deployment/agent-deployment-guide.md) to
configure and start the Agent. Core must be initialized and unsealed, the
Agent's enrollment approved, and its mTLS runtime connected. Assign the Agent
a read policy for the required paths. A healthy local socket alone does not
establish these prerequisites.

Core also requires its existing `typed_runtime_authorization` preflight gate.
In the Core operator console, verify the policy state and record that gate:

```elixir
SecretHub.Core.UpgradeGates.verify_typed_runtime_authorization(actor_id: "operator:local-agent")
```

Continue after `{:ok, gate}`. Resolve any reported preflight findings before
retrying. This records verified typed policy state without changing the
application authentication floor; see [runtime authorization](../security/runtime-authorization.md).

The socket remains mode `0600`: use the Agent UID or root to connect. The
complete read command is:

```sh
secrethub secret get prod.db.password --format json
```

The CLI selects its socket in this order:

1. Explicit `--agent-socket PATH`.
2. `SECRET_HUB_AGENT_SOCKET_PATH` from its environment.
3. `/var/run/secrethub/agent.sock`.

For a custom socket, either pass the option or set the environment variable:

```sh
export SECRET_HUB_AGENT_SOCKET_PATH=/run/secrethub-agent/agent.sock
secrethub secret get prod.db.password --format json
```

An unavailable socket or denied read returns an error. The CLI does not
automatically switch to Core HTTP or prompt for login after a local failure.

## Start an application with a password

For a text secret, CLI JSON output contains its string in `value`. This Bash
script stops if retrieval or extraction fails, then starts the application:

```bash
#!/usr/bin/env bash
set -euo pipefail

DB_PASSWORD="$(secrethub secret get prod.db.password --format json | jq -er '.value')"
export DB_PASSWORD
exec /opt/myapp/bin/start
```

For a structured secret containing `username` and `password`, the CLI prints
those object fields directly; select `.password` instead of `.value`. See
[secret value formats](../secrets/value-formats.md).

## Application code and SDKs

The Agent accepts newline-delimited JSON over its Unix socket. A local caller
sends `get_secret` directly, without an authentication exchange:

```json
{"request_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479","action":"get_secret","params":{"path":"prod.db.password"}}
```

Append a newline to each frame. Responses echo `request_id` and contain either
`status: "ok"` with `data`, or `status: "error"` with an error code. Successful
`data` contains `value`, `version` and `revision`; the frame limit is 64 KiB.
Check the request ID and status before using the value. Caller-selected
Agent/application identity and authentication claims are rejected.

This is the current SDK integration contract. The CLI contains an Elixir
client; standalone Elixir, Node.js and Go SDK packages and application
subscriptions are not implemented by this change. Older client API designs
describe a different framing/authentication proposal, not the current protocol.

## Password changes and explicit Core access

Core changes invalidate the Agent's cached path; the next read obtains a
currently authorized value. Cached delivery still requires fresh Core approval.
Core outage, sealed Vault, policy denial or failed audit persistence refuses
delivery rather than releasing cached plaintext.

Startup environment variables do not change inside a running application. The
application must retrieve the new password and reload its configuration and
connections, or restart using its startup script.

Secret creation/update remains a Core management/API operation. The Agent
socket supports reading, not writing passwords back to Core. CLI Core
operations retain token authentication. For an explicit Core HTTP read:

```sh
secrethub secret get prod.db.password --server https://core.example.com --format json
```

`--server` cannot be combined with Agent socket/certificate/key options. A
complete explicit `--agent-cert` and `--agent-key` pair retains application
auth-v2 for existing consumers. Partial or invalid credentials fail without
switching to shared local permissions. See the
[local and application read contracts](../security/app-uds-auth-v2.md).
