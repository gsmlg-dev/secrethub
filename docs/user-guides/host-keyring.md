# Host credentials through the local Agent

The SecretHub Agent can act as the credential store for its host. Git, Docker,
service launchers and Python applications ask the local Agent for credentials;
Core stores the values encrypted, authorizes every release and records audit
evidence. There is no offline mode: when Core is unavailable, sealed or denies
access, consumers get an error, never a cached value.

Design and protocol reference: [host keyring subsystem](../subsystem/host-keyring.md).

## 1. Prerequisites

* Core and the Agent run a version with `host_credentials_v1`. Apply the Core
  migration `20261109000001_create_host_credential_bindings` before upgrading
  Agents. Older Agents keep working; they simply do not offer credentials.
* The Agent is enrolled, approved and connected, and the
  `typed_runtime_authorization` gate is recorded (see
  [local Agent secrets](local-agent-secrets.md)).
* The consumer can open the Agent socket. The socket stays owner-only (`0600`);
  see section 4 for the per-user profile used by interactive Git/Docker users.

## 2. Grant credential operations

Credential operations are separate grants. A policy that allows `read` never
allows storing, erasing or listing credentials. Bind the policy to the Agent
(`agent:<agent database UUID>`) and grant the collection root and its entries
explicitly:

```json
{
  "version": "1.0",
  "allowed_secrets": [
    "host-credentials.<agent_uuid>.git",     "host-credentials.<agent_uuid>.git.*",
    "host-credentials.<agent_uuid>.docker",  "host-credentials.<agent_uuid>.docker.*",
    "host-credentials.<agent_uuid>.generic", "host-credentials.<agent_uuid>.generic.*"
  ],
  "allowed_operations": ["credential_read", "credential_write", "credential_delete", "credential_list"]
}
```

Grant fewer operations for read-only hosts (for example only
`credential_read`). The management policy editor offers the four operations.

## 3. Shared credentials (managed references)

A helper `store` always creates an Agent-owned entry. To give an Agent an
existing team credential, an operator binds a reference in the Core console;
the source Secret is addressed by its stable ID:

```elixir
alias SecretHub.Core.HostCredentials.Management

{:ok, binding} =
  Management.bind_reference("<agent public id or UUID>", %{
    namespace: "docker",
    service: "https://index.docker.io/v1/",
    username: "deploy",
    secret_id: "<source secret UUID>",
    username_field: "user",     # optional; otherwise `username` is used
    value_field: "token"
  }, "operator:<name>")
```

The Agent additionally needs `read` on the source Secret's path. Reference
behavior:

* Reads always use the current source value.
* `store` of the identical value is accepted as a no-op; any other value is
  refused (`READ_ONLY`). Helpers can never replace or retarget a reference.
* `erase`/`docker logout` disables the binding only. The source Secret and
  other Agents are unaffected, and no upstream token is revoked.
* A disabled reference stays disabled across restarts, reconnects and source
  rotation. Re-enable it explicitly: `Management.enable_reference(id, actor)`.
* If the source Secret is deleted, the binding becomes unavailable
  (`SOURCE_UNAVAILABLE`); recreating a Secret at the same path does not
  restore it. Use `Management.rebind_reference(id, %{secret_id: ...}, actor)`.
* `Management.list_bindings(agent)` shows bindings including disabled ones.

The same operations are available on the management API (behind Caddy mTLS,
CSRF-protected like other `/admin/api` endpoints; responses never contain
values):

| Method and path | Operation |
| --- | --- |
| `GET /admin/api/agents/:agent_id/host-credentials` | list bindings |
| `POST /admin/api/agents/:agent_id/host-credentials/references` | bind (`namespace`, `service`, `secret_id`, `value_field`, …) |
| `POST /admin/api/host-credentials/:id/enable` | re-enable |
| `POST /admin/api/host-credentials/:id/rebind` | rebind (`secret_id`, `value_field`, `username_field`) |
| `POST /admin/api/host-credentials/:id/disable` | disable |

## 4. Profiles

### System services

The default NixOS Agent (`services.secrethub-agent`) keeps its private socket.
Services receive credentials through systemd `LoadCredential=` provider
sockets, so service users never need access to the Agent socket:

```nix
services.secrethub-agent = {
  credentialProviders.billing-db.entryId = "<binding UUID>";
  serviceCredentials.billing = {
    credentials.db = "billing-db";
    environment.DATABASE_PASSWORD = "db";        # optional env conversion
    command = [ "${billing}/bin/billing" "serve" ];
  };
};
systemd.services.billing.serviceConfig.DynamicUser = true;
```

The generated `ExecStart=` runs `secrethub-exec --credential db=DATABASE_PASSWORD
-- …`. It checks the credential files of the main process and replaces itself
with the program; a missing or empty credential (denial, Core outage, Agent
down) stops the service before the program runs, including on restart.
Credentials are a snapshot taken at activation: a rotated value is picked up at
the next start. Restart the unit explicitly to apply a rotation.

### Interactive users (Git, Docker, keyring)

Enable the per-user Agent profile; each login user runs their own Agent with
their own enrollment key and socket at `$XDG_RUNTIME_DIR/secrethub/agent.sock`
(exported as `SECRET_HUB_AGENT_SOCKET_PATH`):

```nix
services.secrethub-agent.userAgent.enable = true;   # also installs the CLI and helpers
```

Approve each user Agent once in `/admin/pending-agents` and grant it its own
credential policy. It is a separate Agent identity, not an account system.
Without NixOS, run an Agent as the user with `SECRET_HUB_AGENT_STATE_DIR`,
`SECRET_HUB_AGENT_SOCKET_PATH` and a user-owned `SECRET_HUB_AGENT_HOST_KEY_PATH`.

Clients never fall back to another Agent or to Core HTTP after a failure.

## 5. Consumers

Install the CLI package (`secrethub`, `secrethub-exec`,
`git-credential-secrethub`, `docker-credential-secrethub`) from the flake
(`secrethub-cli`), from the release archive
`secrethub-host-tools-<tag>-<target>.tar.gz` (extract it, keep the directory,
run `./install.sh [BIN_DIR]`; requires Erlang/OTP 28 `escript` on PATH), or
build it locally with `scripts/host-keyring/build-local.sh`.
The Hex escript (`mix escript.install hex secrethub_cli`) provides only
`secrethub` and `secrethub credential`.
Installing the helpers does not change any Git or Docker configuration.

### Git

```sh
git config --global credential.helper secrethub
git config --global credential.useHttpPath true    # optional: per-repository entries
```

`git credential approve` stores, a rejected password is erased (only if it is
still the stored value), and a missing entry lets Git continue normally. If the
Agent is unavailable or denies access, the helper stops Git (`quit=true`)
instead of prompting. Git HTTPS helpers do not cover SSH remotes.

### Docker

```json
{ "credsStore": "secrethub" }
```

or per registry `{"credHelpers": {"registry.example.com:5000": "secrethub"}}`.
`docker login`/`logout` store and erase; after logout, check with
`docker-credential-secrethub list` because the Docker CLI can report success
even when an erase failed.

### Programs that read environment variables

```sh
cat > billing.map.json <<'EOF'
{"env": {"DATABASE_PASSWORD": {"entry_id": "<binding UUID>", "field": "value"}}}
EOF
secrethub exec --map billing.map.json -- /opt/billing/bin/serve --port 8080
```

All values are fetched before the program starts; the program replaces the
launcher (same PID, terminal, exit status and signals). Values are never
placed in arguments or temporary files. Existing variables are not overwritten
unless `--replace-env` is given. Empty values need `"allow_empty": true`.

### Scripts

```sh
printf %s "$TOKEN" | secrethub credential put --namespace generic --service ci --account deploy
secrethub credential get --namespace generic --service ci --account deploy --field value
secrethub credential list --namespace generic
secrethub credential delete --namespace generic --service ci --account deploy
```

### Python

Install `integrations/python-keyring` into the application's environment (or
use the flake's `python-keyrings-secrethub`) and select it explicitly:

```sh
export PYTHON_KEYRING_BACKEND=keyrings.secrethub.SecretHubKeyring
```

The backend is never selected automatically.

## 6. Failures and recovery

| Symptom | Meaning | Action |
| --- | --- | --- |
| `INCOMPATIBLE_VERSION` | Core or Agent lacks `host_credentials_v1` | upgrade Core first, then the Agent |
| `FORBIDDEN` | missing grant or explicit deny | adjust the Agent's credential policy |
| `AMBIGUOUS` | several accounts match a lookup without a username | pass the username |
| `READ_ONLY` | store against a reference or disabled reference | use Management APIs |
| `SOURCE_UNAVAILABLE` | reference source deleted | rebind |
| `UNCONFIRMED` | write timed out; it may or may not have committed | read back before retrying |
| `AUDIT_UNAVAILABLE` | audit journal or Core audit write unavailable | restore audit storage; no value is released meanwhile |

Rollback: entries, disabled references and pending audit evidence remain in
the database and the Agent journal. An older Core quarantines version 2 audit
events instead of discarding them; after restoring a current Core, replay them
with `SecretHub.Agent.AccessAudit.Journal.replay_quarantined/1`.
