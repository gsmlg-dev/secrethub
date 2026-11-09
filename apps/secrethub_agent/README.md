# SecretHub Agent

The Agent delivers secrets to local applications through a private Unix socket.
It enrolls with Core and maintains a trusted mTLS connection. Core authorizes
each read against the Agent's policies, including reads of cached values.

## Read a local secret

Once the Agent is connected and authorized, use the SecretHub CLI:

```sh
secrethub secret get prod.db.password --format json
```

No application certificate, private key or CLI login is required. The socket
defaults to `/var/run/secrethub/agent.sock`; an explicit `--agent-socket` overrides
`SECRET_HUB_AGENT_SOCKET_PATH`, which overrides that default:

```sh
secrethub secret get prod.db.password --agent-socket /run/secrethub-agent/agent.sock
```

The socket is mode `0600`, so callers need the Agent UID or root access. All
processes allowed to connect share the Agent's secret permissions. Agent
enrollment and runtime keys are managed by the Agent and are not passed to
local callers. Core must be available and unsealed for every delivery.

## Host credentials

The same socket serves Agent-scoped host credentials for Git, Docker,
`secrethub exec`, systemd services and Python `keyring` (`credential_get`,
`credential_put`, `credential_delete`, `credential_list`). They need explicit
`credential_*` policy grants, and every release is authorized by Core. Set
`SECRET_HUB_AGENT_CREDENTIAL_PROVIDERS` to a provider configuration file to
serve systemd `LoadCredential=` sockets. See the
[host credentials guide](../../docs/user-guides/host-keyring.md).

See the [local application guide](../../docs/user-guides/local-agent-secrets.md)
for startup scripts, the local protocol and updates. Use the
[Agent deployment guide](../../docs/deployment/agent-deployment-guide.md) for
TOML configuration, systemd, containers and enrollment, or the
[NixOS guide](../../docs/deployment/nixos-agent.md) for flake deployment.

