# SecretHub Agent Deployment and Configuration

The standalone `secrethub_agent` release reads a TOML configuration file at
startup. Use a build or release that includes this feature; older published
releases do not gain file support by adding a configuration file.

For native NixOS deployment, use the [NixOS Agent guide](nixos-agent.md). Its
module already supplies required options and manages service credentials.

## Prerequisites

- Core is initialized, unsealed, and configured with its Agent PKI.
- The host can reach Core's single Agent HTTPS/WSS listener, normally port
  `4665`, with a trusted server certificate matching its advertised hostname.
- An existing, unencrypted RSA or ECDSA SSH host private key is readable by
  the Agent service. Ed25519 host keys are not supported for enrollment.
- Persistent state and PKI bundle directories, and the socket's parent
  directory, exist and are writable by the service UID.

Use one Agent URL, such as `https://core.example.com:4665`, for `core_url`.
Core has two service listeners: the existing management listener on `4664`
behind Caddy's operator mTLS, and the Agent listener on `4665` for enrollment
HTTPS, machine HTTP APIs, and runtime WSS. A fresh Agent uses the Agent URL;
management requires an operator client certificate. There is no `4668` listener;
retired `SECRET_HUB_MACHINE_*` flags cannot start one. See the
[runtime contract](../security/runtime-contract.md) for listener requirements.

### Configure the Core Agent listener

Set these existing Core environment variables before starting Core:

```bash
SECRET_HUB_AGENT_ENDPOINT_SERVER=true
SECRET_HUB_AGENT_ENDPOINT_HOST=core.example.com
SECRET_HUB_AGENT_ENDPOINT_PORT=4665
SECRET_HUB_AGENT_ENDPOINT_CERT_PATH=/run/secrethub/agent-server-cert.pem
SECRET_HUB_AGENT_ENDPOINT_KEY_PATH=/run/secrethub/agent-server-key.pem
SECRET_HUB_AGENT_ENDPOINT_CA_CERT_PATH=/run/secrethub/signing-ca.pem
```

Provision the server certificate and private key first using the existing
[protected certificate issuance operation](runtime-server-certificate.md).
Its SANs must contain the advertised hostname. The server certificate and client
CA must use the same internal signing CA used for Agent runtime certificates:
Agents receive that CA chain during enrollment and use it to verify runtime TLS.
Explicitly provisioned listener material can start independently of certificate
issuance availability; issuing a certificate does not install it or restart Core.

Preserve TLS to Core, directly or through TCP passthrough. The Agent listener
supports TLS 1.2 and 1.3. It verifies presented client certificates and allows
bootstrap HTTPS without one. Runtime socket admission still requires a valid
Core-issued Agent certificate; enrollment proof/token checks and existing
application/CLI token authorization remain separate from runtime identity.

For a private signing CA, distribute its public CA certificate to each Agent
out of band and set `enrollment_ca_path` (or install it in system trust) before
first enrollment. Enrollment HTTPS verifies both the server chain and hostname;
never disable verification. The returned runtime CA chain does not establish
trust for the initial HTTPS request.

For managed development, `devenv` defaults to
`https://<SECRET_HUB_AGENT_ENDPOINT_HOST>:<SECRET_HUB_AGENT_ENDPOINT_PORT>`
(`https://localhost:4665`) and, when supplying that default URL, trusts
`/tmp/secrethub/agent_endpoint/ca-cert.pem`. Explicit URL and enrollment CA
environment values are preserved; an explicit URL without a CA override uses
normal system trust. For direct `mix agent.run`, export
`SECRET_HUB_AGENT_ENROLLMENT_CA_PATH=/tmp/secrethub/agent_endpoint/ca-cert.pem`
when using this private development CA; without an override, direct execution
uses the normal trust store. If Vault is sealed or its CA is absent when Core
starts, development TLS generation cannot succeed and the Agent listener
is absent. Initialize/unseal Vault and configure its signing CA, then restart
Core to create listener material. Enrollment or a later connect-info request
cannot bootstrap an absent listener. Preserve existing Agent identity/state
when restarting. These are operator steps; this guide does not perform a restart.

## Configuration file

The default file is `/etc/secrethub/agent.toml`. When present, it loads
automatically. Select another file with:

```bash
SECRET_HUB_AGENT_CONFIG_FILE=/etc/secrethub/production-agent.toml \
  /path/to/built-or-new-release/bin/secrethub_agent start
```

If the default file is absent, existing environment-only configuration continues
to work. An explicitly selected file must exist and be readable. A present
default file that cannot be read or parsed also prevents startup.

Generate a configuration template outside the release directory, then edit it
for the host:

```bash
/path/to/built-or-new-release/bin/secrethub_agent config generate > agent.toml
```

Generation needs no existing configuration and writes only TOML to standard
output. The same template is available as
[agent.example.toml](../../rel/agent/overlays/config/agent.example.toml), bundled
as `config/agent.example.toml` in new Agent release archives.

For example:

```toml
# One HTTPS Agent URL; enrollment and runtime WSS share this listener.
core_url = "https://core.example.com:4665"

# Stable, existing RSA or ECDSA SSH private host key.
# The systemd example below provides this credential copy.
host_key_path = "/run/credentials/secrethub-agent.service/ssh-host-key"

# Preserve these directories across restarts and upgrades.
state_dir = "/var/lib/secrethub-agent"
client_auth_bundle_dir = "/var/lib/secrethub-agent/client-auth"

# Local consumers use this private Unix socket.
socket_path = "/run/secrethub-agent/agent.sock"

# Optional: private Agent server CA bundle, provisioned out of band.
# enrollment_ca_path = "/etc/secrethub/enrollment-ca.pem"
```

These are flat, root-level TOML keys. All values must be nonempty strings of
at most 4096 bytes. The file is limited to 64 KiB. Unknown keys, TOML tables,
wrong types, malformed TOML, and invalid HTTPS enrollment URLs are rejected at
startup. Errors identify the setting or failure category without printing
configuration values or file contents.

Relative path values in TOML resolve relative to the configuration file's
directory: `enrollment_ca_path = "enrollment-ca.pem"` in
`/etc/secrethub/agent.toml` selects `/etc/secrethub/enrollment-ca.pem`.
Environment paths retain their existing behavior. TOML values do not expand
shell variables or `~`; use explicit paths.

### Generate and validate configuration

After editing the generated file, validate it before installing it:

```bash
/path/to/built-or-new-release/bin/secrethub_agent config validate agent.toml
```

`config validate [file]` selects the explicit file argument first, otherwise
`SECRET_HUB_AGENT_CONFIG_FILE`, otherwise `/etc/secrethub/agent.toml`. The
selected file must exist and be readable, including when using the default
path. Validation checks only that file: TOML syntax, allowed keys, string types
and size limits, all five required values, and the HTTPS enrollment URL.
Per-option environment variables and their `_FILE` forms are ignored, so they
cannot supply missing file values or override invalid ones.

Neither configuration command starts the Agent or connects to Core. Validation
does not check whether configured keys or directories exist, their permissions,
or whether the enrollment CA contains valid PEM certificates. Run preflight as
the service UID after provisioning those files and directories, as shown below.

| Exit code | Meaning |
| --- | --- |
| `0` | Command succeeded; for validation, the file is valid |
| `1` | Configuration is invalid or the selected file cannot be loaded |
| `2` | Command usage is invalid |

### Options and environment overrides

Required means the file or an environment override must supply the value.
The release has no defaults for these five required values.

| TOML key | Environment variable | Required | Purpose |
| --- | --- | --- | --- |
| `core_url` | `SECRET_HUB_AGENT_CORE_URL` | Yes | HTTPS Agent listener URL for enrollment; do not supply a WebSocket URL |
| `host_key_path` | `SECRET_HUB_AGENT_HOST_KEY_PATH` | Yes | Existing RSA/ECDSA SSH private host key for host-identity proof |
| `state_dir` | `SECRET_HUB_AGENT_STATE_DIR` | Yes | Persistent Core-issued identity, TLS material, and enrollment state |
| `socket_path` | `SECRET_HUB_AGENT_SOCKET_PATH` | Yes | Unix socket for local applications; its parent must exist and be writable |
| `client_auth_bundle_dir` | `SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR` | Yes | Persistent client-auth PKI bundle storage |
| `enrollment_ca_path` | `SECRET_HUB_AGENT_ENROLLMENT_CA_PATH` | No | PEM CA bundle for enrollment HTTPS; omitted uses the normal trust store |

`SECRET_HUB_AGENT_CONFIG_FILE` selects the TOML file itself. It is not a TOML
key or a value-file override for another option.

Each option's environment variable accepts the existing `_FILE` form.
For example, `SECRET_HUB_AGENT_CORE_URL_FILE=/run/secrets/enrollment-url`
reads the URL from that file. `SECRET_HUB_AGENT_HOST_KEY_PATH_FILE` reads a
**path string**, rather than SSH private-key contents.

The precedence is:

1. The option's environment variable or its `_FILE` value.
2. The option in the selected TOML file.

Setting both `NAME` and `NAME_FILE` is an error, even when TOML supplies that
option. Empty or invalid overrides fail instead of falling back to TOML.
Value files must be readable regular files outside the Nix store, at most
4096 bytes, with a nonempty value; trailing line endings are removed.
The TOML file is validated even when environment variables override every
value, so invalid file contents cannot be hidden by overrides.

Runtime Agent ID, WebSocket URL, expected TLS server name, certificates,
heartbeat, and timeout settings come from Core-issued state. AppRole credentials
do not authorize runtime access. Logger, cache, sinker, dynamic-secret, and
launch-profile settings are not additional TOML keys.

### Permissions and restart behavior

Keep configuration writable only by the operator. For a dedicated
`secrethub-agent` user, use root ownership, group `secrethub-agent`, and mode
`0640`. Keep host keys private; systemd credentials provide a readable copy
without opening the original host key to other users. Preflight requires a
readable supported host key without world access.

Create state and bundle directories and the socket's parent before startup;
preflight checks writeability and does not create missing directories. Use
private directories, normally mode `0700`. The socket is mode `0600`, so
consumers need the Agent UID or root access. Local readers share the Agent's
Core-authorized permissions without application certificates, private keys or
login tokens. Group membership alone does not grant socket access.

The CLI defaults to `/var/run/secrethub/agent.sock`. For this guide's custom
socket, select it explicitly or export `SECRET_HUB_AGENT_SOCKET_PATH`:

```sh
secrethub secret get prod.db.password --agent-socket /run/secrethub-agent/agent.sock
```

See [local Agent secrets](../user-guides/local-agent-secrets.md) for default
reads, application startup and the local client protocol.

Configuration loads when the release process starts. Restart after editing;
there is no hot reload. Preserve state and bundle directories across restarts
and upgrades. Changing `core_url` does not replace the runtime endpoint
persisted in an enrolled Agent's `connect-info.json`.

## Tarball and systemd

Download the matching `secrethub_agent-<tag>-<platform>.tar.gz` artifact from
[GitHub Releases](https://github.com/gsmlg-dev/secrethub/releases), using a tag
that includes TOML support. Extract the **whole archive**, including `bin`,
`lib`, `releases`, and the bundled runtime; the launcher is not a standalone
executable. This example is for Linux with systemd:

```bash
sudo useradd --system --home /var/lib/secrethub-agent \
  --shell /usr/sbin/nologin secrethub-agent
sudo install -d -o root -g root /opt/secrethub-agent
sudo tar -xzf /path/to/downloaded-agent-release.tar.gz -C /opt/secrethub-agent
sudo install -d -o root -g secrethub-agent -m 0750 /etc/secrethub
sudo install -o root -g secrethub-agent -m 0640 \
  /path/to/prepared-agent.toml /etc/secrethub/agent.toml
```

Use the TOML example above with this unit in
`/etc/systemd/system/secrethub-agent.service`:

```ini
[Unit]
Description=SecretHub Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=secrethub-agent
Group=secrethub-agent
WorkingDirectory=/var/lib/secrethub-agent
StateDirectory=secrethub-agent
StateDirectoryMode=0700
RuntimeDirectory=secrethub-agent
RuntimeDirectoryMode=0700
UMask=0077
LoadCredential=ssh-host-key:/etc/ssh/ssh_host_rsa_key
Environment=SECRET_HUB_AGENT_CONFIG_FILE=/etc/secrethub/agent.toml
Environment=RELEASE_TMP=/run/secrethub-agent
ExecStartPre=/usr/bin/install -d -m 0700 /var/lib/secrethub-agent/client-auth
ExecStartPre=/opt/secrethub-agent/bin/secrethub_agent eval 'SecretHub.Agent.Preflight.run()'
ExecStart=/opt/secrethub-agent/bin/secrethub_agent start
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

systemd creates directories and copies the SSH credential before
`ExecStartPre`. The explicit preflight runs as the service user with the same
credentials and configuration as the Agent. An optional private enrollment CA
must also be readable by this user.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now secrethub-agent.service
sudo systemctl status secrethub-agent.service
sudo journalctl -u secrethub-agent.service -f
```

The launcher defaults to `RELEASE_DISTRIBUTION=none`. This unit lets systemd
stop the foreground process; it does not use the distribution-based release
`stop` command.

## Docker

Use an Agent image built from a revision containing TOML support. The root
`Dockerfile.agent` supplies these environment defaults, which **override TOML**:

| Image environment | Default |
| --- | --- |
| `SECRET_HUB_AGENT_STATE_DIR` | `/var/lib/secrethub/agent` |
| `SECRET_HUB_AGENT_SOCKET_PATH` | `/var/run/secrethub/agent.sock` |
| `SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR` | `/var/lib/secrethub/pki/client-auth` |

For this container example, keep those same three paths in TOML and set
`host_key_path = "/run/secrethub-host-key"`. To change storage paths, override
the corresponding image environment variables too and provide writable mounts.
Mount configuration and key files read-only; persist identity and bundle storage.

The service runs as UID/GID 1002. Provision a private copy of the existing
supported host key readable by that UID; do not make the original host key
world-readable.

```bash
# Set this to an image built from a revision containing TOML support.
export SECRETHUB_AGENT_IMAGE=your-registry/secrethub-agent:your-build
sudo install -d -o 1002 -g 1002 -m 0700 \
  /var/lib/secrethub-agent /var/lib/secrethub-agent/agent \
  /var/lib/secrethub-agent/pki/client-auth /var/run/secrethub
sudo install -d -o root -g root -m 0755 /etc/secrethub
sudo install -o root -g 1002 -m 0640 \
  /path/to/prepared-container-agent.toml /etc/secrethub/agent.toml
sudo install -o 1002 -g 1002 -m 0600 \
  /etc/ssh/ssh_host_rsa_key /etc/secrethub/agent-host-key

docker run -d \
  --name secrethub-agent \
  --restart unless-stopped \
  --mount type=bind,src=/etc/secrethub/agent.toml,dst=/etc/secrethub/agent.toml,readonly \
  --mount type=bind,src=/etc/secrethub/agent-host-key,dst=/run/secrethub-host-key,readonly \
  --mount type=bind,src=/var/lib/secrethub-agent,dst=/var/lib/secrethub \
  --mount type=bind,src=/var/run/secrethub,dst=/var/run/secrethub \
  "$SECRETHUB_AGENT_IMAGE"
```

For a private enrollment CA, mount the PEM file read-only at the path specified
by `enrollment_ca_path`. This CA verifies enrollment HTTPS; it does not replace
the Core-issued `ca-chain.pem` used for runtime mTLS.

To run preflight without enrollment, use the same mounts in a temporary
container and append `eval 'SecretHub.Agent.Preflight.run()'` after the image
name. Preflight prints boolean checks and exits nonzero on failure; it does not
contact Core. Inspect the running container with:

```bash
docker logs -f secrethub-agent
docker exec secrethub-agent /app/bin/secrethub_agent eval 'SecretHub.Agent.Preflight.run()'
```

## Enrollment, state, and verification

On first boot the Agent submits a pending enrollment using its SSH public
identity. Open `/admin/pending-agents` through the Caddy mTLS management URL,
verify the hostname and SSH fingerprint, and approve it. The Agent generates a
separate TLS keypair, signs a CSR-binding proof with its SSH host key, receives
its Core-issued client certificate, connects to `agent:runtime` over mTLS, and
finalizes after Core accepts the connection.

The state directory contains:

| File | Purpose |
| --- | --- |
| `agent-cert.pem` | Core-issued Agent client certificate |
| `agent-key.pem` | Agent-generated TLS private key; mode `0600` |
| `ca-chain.pem` | Core-issued CA chain for runtime TLS verification |
| `connect-info.json` | Core-advertised runtime endpoint and connection settings |
| `identity.json` | Core-issued Agent ID and identity metadata |
| `pending.json` | Pending credential; mode `0600`, removed after finalization |

Subsequent starts reuse this state. Preflight rejects partial or damaged
identity instead of silently enrolling a replacement. Preserve the directory
for investigation and recovery; do not delete it to hide a startup failure.

Confirm the Agent is connected in `/admin/agents` and its heartbeat advances.
A running process, passing preflight, or local socket health check alone does
not prove Core connectivity or authorization to read a secret.

## Troubleshooting

- **Configuration rejected:** check the selected file, flat key names, string
  types, file size, and required values. Remove stale overrides or conflicting
  `NAME`/`NAME_FILE` pairs. Restart after edits.
- **Preflight fails:** verify directories exist and are writable by the service
  UID, the SSH key is supported and private, a configured enrollment CA is valid
  PEM, and persisted identity is complete.
- **Enrollment cannot connect:** check the HTTPS Agent URL and port `4665`,
  DNS, outbound access, server certificate trust/hostname, and pending approval.
  If development TLS generation failed at startup, initialize/unseal Vault and
  configure its CA, then restart Core. An operator-only management URL is
  unsuitable for fresh enrollment.
- **Runtime cannot connect:** check the endpoint advertised in
  `connect-info.json`, its network access, certificate validity, and the
  Core-issued CA chain. Enrollment CA overrides do not change this chain.
- **Local application cannot use the socket:** check the effective path,
  directory/socket permissions, negotiated local-read capability and Agent
  policies in Core. When explicitly using application credentials, also check
  the certificate/proof and application policies.
