# secrethub_sdk

Elixir client for publishing and reading SecretHub static secrets through the
local SecretHub Agent.

A service on an Agent host (for example backplane) publishes a secret, such as
a newly added API key, to SecretHub. Other services consume it through their
own Agents and policies. The SDK talks only to the Agent's local Unix socket.
The Agent acts with its Core-issued identity, and Core authorizes and audits
every call. The SDK holds no credentials of its own.

## Installation

```elixir
def deps do
  [{:secrethub_sdk, "~> 1.0.0-rc"}]
end
```

## Usage

```elixir
path = SecretHub.SDK.path(["backplane", "llm", "OpenAI_Main"])
#=> "backplane.llm.openai-main"

{:ok, %{status: :created, version: 1}} =
  SecretHub.SDK.put_secret(path, %{"api_key" => api_key})

# Republishing identical data is a no-op; a new value creates a new version.
{:ok, %{status: :unchanged}} = SecretHub.SDK.put_secret(path, %{"api_key" => api_key})

# Compare-and-set when several publishers may write the same path.
{:ok, %{status: :updated, version: 2}} =
  SecretHub.SDK.put_secret(path, %{"api_key" => rotated}, expected_version: 1)

{:ok, %{data: %{"api_key" => ^rotated}, version: 2}} = SecretHub.SDK.get_secret(path)

{:ok, %{status: :deleted}} = SecretHub.SDK.delete_secret(path)
```

Options for every call:

| Option | Default |
| --- | --- |
| `:socket_path` | `$SECRET_HUB_AGENT_SOCKET_PATH`, else `/var/run/secrethub/agent.sock` |
| `:timeout` | `15_000` ms |

Data is a map of string field names (`A-Z a-z 0-9 _ . -`, up to 128
characters) to string values: at most 64 fields and 64 KiB encoded. Paths use
lowercase dotted segments (`a-z 0-9 -`). `SecretHub.SDK.path/1` builds them
from arbitrary names. Paths under `host-credentials.` are reserved.

## Errors

Failures are `{:error, %SecretHub.SDK.Error{code: code}}`. Secret values never
appear in errors.

| Code | Meaning |
| --- | --- |
| `:agent_unavailable` | The Agent socket could not be reached; nothing is known about SecretHub |
| `:unconfirmed` | A write or delete was sent but its outcome is unknown; it may have been applied |
| `:forbidden` | Core denied this Agent and path. Reads also report a missing secret this way |
| `:conflict` | `:expected_version` did not match |
| `:invalid_request` | Path or data rejected |
| `:sealed`, `:unavailable`, `:audit_unavailable`, `:busy` | SecretHub temporarily cannot serve the request |
| `:incompatible_version` | The Agent or Core does not support this operation yet |

## SecretHub configuration

1. The publishing host runs an enrolled, approved SecretHub Agent, and the
   publishing process can open its socket. The socket is owner-only (mode
   `0600`), so either run the publisher as the Agent's user, or give the
   publisher's user its own Agent. On NixOS that is
   `services.secrethub-agent.userAgent`. That Agent enrolls with its own
   identity and needs its own approval and policy. Do not widen the socket's
   permissions.
2. Bind a policy to that Agent granting the dedicated publication operations on
   the prefix it owns. The generic `write`/`delete` operations do not apply:

   ```json
   {
     "version": "1.0",
     "allowed_secrets": ["backplane.**"],
     "allowed_operations": ["secret_write", "secret_delete"]
   }
   ```

3. Grant `read` on the specific paths to each consuming Agent or application.
   Consumers read through their own Agent (`secrethub secret get`, templates,
   or `SecretHub.SDK.get_secret/2`).

Publishing requires a SecretHub Core and Agent that negotiate
`secret_write_v1`. Older peers return `:incompatible_version`.
