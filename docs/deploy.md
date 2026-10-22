# Deploy SecretHub

This guide covers the supported deployment path for SecretHub Core, SecretHub Agent, and the CLI. It is the short operational guide; deeper runbooks live under [`docs/deployment/`](./deployment/).

Examples use `v1.0.0-rc9`. Replace it with the release tag you are deploying.

```bash
export SECRETHUB_VERSION=v1.0.0-rc9
export SECRETHUB_HOST=secrethub.example.com
```

## Components

| Component | Runs where | Purpose |
| --- | --- | --- |
| SecretHub Core | Central service | Phoenix API, LiveView admin UI, PKI, policies, secret engines, audit, leases |
| PostgreSQL 16 | Managed database or standalone image | Durable storage for Core |
| SecretHub Agent | Beside applications | Enrolls with Core, maintains mTLS runtime link, serves local Unix socket secrets |
| SecretHub CLI | Operator workstation or automation | Login, secret reads/writes, admin workflows |

Core and Agent are separate OTP releases. Core uses `config/core_runtime.exs` in packaged releases, while `config/runtime.exs` preserves direct production execution from source. The standalone Agent release uses `config/agent_runtime.exs`; builds containing TOML support read `/etc/secrethub/agent.toml` or the file selected by `SECRET_HUB_AGENT_CONFIG_FILE`. See the [Agent configuration guide](deployment/agent-deployment-guide.md) for required options and environment overrides. CLI builds use an app-local empty runtime config and do not require Core runtime variables.

## Release Artifacts

The GitHub release workflow publishes:

- Core tarballs: Linux amd64 and Linux arm64
- Agent tarballs: Linux amd64, Linux arm64, macOS amd64, macOS arm64, FreeBSD amd64
- Agent zip: Windows amd64
- Docker images:
  - `ghcr.io/gsmlg-dev/secrethub/core:<tag>`
  - `ghcr.io/gsmlg-dev/secrethub/core-standalone:<tag>`
  - `ghcr.io/gsmlg-dev/secrethub/agent:<tag>`
- CLI package: `secrethub_cli` on Hex.pm

To cut a release, run `.github/workflows/release.yml` with:

- `version`: `1.0.0-rc9`, `1.0.0`, etc. Do not include the leading `v`.
- `git-rev`: source branch, usually `main`.

The workflow bumps versions, pushes the release commit, builds artifacts/images, publishes the CLI package, tags the release, and creates GitHub release notes. It requires the repository secret `HEX_API_KEY` to publish the CLI package.

## Public trust and managed certificates

Core packages Mozilla-derived public roots for offline inspection/export and runs
managed Let's Encrypt DNS-01 orders through its own named Oban instance. Apply
the Core migrations before starting a binary containing this feature: they add
Oban schema version 14 and the dedicated ACME tables and retention guards.
Back up PostgreSQL together with Vault recovery material before upgrading.

Follow the [managed public certificate guide](pki/managed-public-certificates.md)
for explicit account terms acceptance, encrypted Cloudflare/Route 53 credential
references, public zones, renewal, cleanup and exact-version exports. Set
`SECRET_HUB_ACME_ENABLED=false` to stop new issuance/publication while allowing
existing cleanup and pending revocation to finish. Public-root inspection needs
neither network access nor an unsealed Vault; account/key operations need Vault.

Deploy the single combined PEM through the existing authorized Agent secret
read/sink path, then arrange and verify application adoption. Public roots and
server certificates do not change internal machine/client authentication. See
the [execution evidence](pki/secrethub-pki-acme-execution.md) for tested behavior,
live-provider qualification and publication status before rollout.

## Prerequisites

- PostgreSQL 16 for Core, unless using the standalone image
- A stable DNS name for Core, for example `secrethub.example.com`
- TLS termination for browser/API traffic
- A persistent volume for Agent enrollment material
- A writable Unix socket directory for the Agent local API
- A generated `SECRET_KEY_BASE` for Core:

```bash
openssl rand -base64 48
```

Assign each Core replica a stable, deployment-owned
`SECRET_HUB_CLUSTER_NODE_ID`, for example `core-replica-a`. Keep the value
across restarts and never share it between concurrently running Core replicas.

Create the PostgreSQL database and required extensions:

```sql
CREATE USER secrethub WITH ENCRYPTED PASSWORD 'change-me';
CREATE DATABASE secrethub_prod OWNER secrethub;

\c secrethub_prod
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
```

## Deploy Core With Docker

Use `core` when PostgreSQL is managed outside the container.

```bash
export DATABASE_URL='postgresql://secrethub:change-me@postgres.example.internal:5432/secrethub_prod'
export SECRET_KEY_BASE="$(openssl rand -base64 48)"
export SECRET_HUB_CLUSTER_NODE_ID=core-replica-a

docker run --rm \
  -e DATABASE_URL="$DATABASE_URL" \
  -e SECRET_KEY_BASE="$SECRET_KEY_BASE" \
  -e SECRET_HUB_CLUSTER_NODE_ID=core-migration-runner \
  ghcr.io/gsmlg-dev/secrethub/core:$SECRETHUB_VERSION \
  eval "SecretHub.Core.Release.migrate()"

docker run -d \
  --name secrethub-core \
  --restart unless-stopped \
  -p 4664:4664 \
  -e PHX_SERVER=true \
  -e PORT=4664 \
  -e PHX_HOST="$SECRETHUB_HOST" \
  -e DATABASE_URL="$DATABASE_URL" \
  -e SECRET_KEY_BASE="$SECRET_KEY_BASE" \
  -e SECRET_HUB_CLUSTER_NODE_ID="$SECRET_HUB_CLUSTER_NODE_ID" \
  -e POOL_SIZE=10 \
  -e RELEASE_COOKIE="$(openssl rand -hex 32)" \
  ghcr.io/gsmlg-dev/secrethub/core:$SECRETHUB_VERSION
```

Verify Core:

```bash
curl -f "http://localhost:4664/v1/sys/health/live"
```

The local admin UI route is available at:

```text
http://localhost:4664/admin
```

Put Core behind HTTPS for production. If your reverse proxy terminates TLS, forward the normal web/API listener to port `4664`.

## Enable the Admin mTLS Endpoint

Production certificate login uses a second, direct-TLS listener on port `4667`.
It requires both a client certificate trusted by the configured client CA and an
exact certificate fingerprint in the runtime allowlist. The normal browser/API
listener remains on `4664`, and the trusted Agent endpoint remains on `4665`.

This opt-in listener is for installations where the SecretHub CA and first admin
client certificate have already been provisioned through a trusted operator
process. It does not bootstrap the first CA or first admin credential.

Calculate the canonical SHA-256 fingerprint from the exact DER certificate:

```bash
export ADMIN_CERT_FINGERPRINT="$(openssl x509 -in admin-client.pem -outform DER | openssl dgst -sha256 -r | awk '{print $1}')"
```

Enable the listener when starting Core:

```bash
docker run -d \
  --name secrethub-core \
  --restart unless-stopped \
  -p 4664:4664 \
  -p 4667:4667 \
  -v /etc/secrethub/admin-endpoint:/etc/secrethub/admin-endpoint:ro \
  -e PHX_SERVER=true \
  -e PORT=4664 \
  -e PHX_HOST="$SECRETHUB_HOST" \
  -e DATABASE_URL="$DATABASE_URL" \
  -e SECRET_KEY_BASE="$SECRET_KEY_BASE" \
  -e SECRET_HUB_CLUSTER_NODE_ID="$SECRET_HUB_CLUSTER_NODE_ID" \
  -e SECRET_HUB_ADMIN_ENDPOINT_SERVER=true \
  -e SECRET_HUB_ADMIN_ENDPOINT_PORT=4667 \
  -e SECRET_HUB_ADMIN_ENDPOINT_CERT_PATH=/etc/secrethub/admin-endpoint/server.pem \
  -e SECRET_HUB_ADMIN_ENDPOINT_KEY_PATH=/etc/secrethub/admin-endpoint/server-key.pem \
  -e SECRET_HUB_ADMIN_ENDPOINT_CA_CERT_PATH=/etc/secrethub/admin-endpoint/client-ca-chain.pem \
  -e SECRET_HUB_ADMIN_CERT_FINGERPRINTS="$ADMIN_CERT_FINGERPRINT" \
  ghcr.io/gsmlg-dev/secrethub/core:$SECRETHUB_VERSION
```

Open `https://$SECRETHUB_HOST:4667/admin`. The server certificate must be valid
for that hostname. The client CA chain must also match the active SecretHub CA
chain used for application-level verification. Multiple fingerprints may be
separated by commas or whitespace; each value is 64 hexadecimal characters
without colons or a `sha256:` prefix.

Terminate TLS in Core or use L4/TCP passthrough for port `4667`. An HTTP reverse
proxy that terminates TLS removes the peer-certificate identity and is not
supported for this listener. Forwarded certificate headers such as
`x-ssl-client-cert` are deliberately ignored. Keep health checks on `4664`,
because `4667` rejects clients that do not present a certificate.

## Enable the Trusted Agent Endpoint

Agents use a dedicated mTLS WebSocket listener for runtime traffic. Normal browser/API traffic stays on the standard Core endpoint.

Enable the trusted Agent endpoint when starting Core:

If the trusted endpoint server certificate is issued by SecretHub itself, start Core first without this listener, initialize and unseal the vault, create/export the endpoint certificate material, then restart Core with the listener enabled.

```bash
docker run -d \
  --name secrethub-core \
  --restart unless-stopped \
  -p 4664:4664 \
  -p 4665:4665 \
  -v /etc/secrethub/agent-endpoint:/etc/secrethub/agent-endpoint:ro \
  -e PHX_SERVER=true \
  -e PORT=4664 \
  -e PHX_HOST="$SECRETHUB_HOST" \
  -e DATABASE_URL="$DATABASE_URL" \
  -e SECRET_KEY_BASE="$SECRET_KEY_BASE" \
  -e SECRET_HUB_CLUSTER_NODE_ID="$SECRET_HUB_CLUSTER_NODE_ID" \
  -e SECRET_HUB_AGENT_ENDPOINT_SERVER=true \
  -e SECRET_HUB_AGENT_ENDPOINT_HOST="$SECRETHUB_HOST" \
  -e SECRET_HUB_AGENT_ENDPOINT_PORT=4665 \
  -e SECRET_HUB_AGENT_ENDPOINT_CERT_PATH=/etc/secrethub/agent-endpoint/server.pem \
  -e SECRET_HUB_AGENT_ENDPOINT_KEY_PATH=/etc/secrethub/agent-endpoint/server-key.pem \
  -e SECRET_HUB_AGENT_ENDPOINT_CA_CERT_PATH=/etc/secrethub/agent-endpoint/ca-chain.pem \
  ghcr.io/gsmlg-dev/secrethub/core:$SECRETHUB_VERSION
```

For port `4665`, use TCP passthrough or let Core terminate TLS directly so Phoenix receives and verifies the Agent client certificate.

## Standalone Core

Use `core-standalone` for evaluation, demos, and single-node environments. It includes PostgreSQL and stores data under `/data`.

```bash
docker volume create secrethub-standalone-data

docker run -d \
  --name secrethub-core \
  --restart unless-stopped \
  -p 4737:4737 \
  -v secrethub-standalone-data:/data \
  -e PHX_HOST=localhost \
  -e SECRET_KEY_BASE="$(openssl rand -base64 48)" \
  -e SECRET_HUB_CLUSTER_NODE_ID=secrethub-core-standalone \
  -e RELEASE_COOKIE="$(openssl rand -hex 32)" \
  ghcr.io/gsmlg-dev/secrethub/core-standalone:$SECRETHUB_VERSION
```

The standalone image initializes PostgreSQL and runs migrations on startup. Its
deterministic `secrethub-core-standalone` node identity matches the image
default. Do not use it for high availability or production database operations.

## Deploy Core From a Tarball

Download the `secrethub_core-<tag>-linux-<arch>.tar.gz` artifact from the GitHub release.

```bash
sudo install -d -o secrethub -g secrethub /opt/secrethub-core
sudo tar -xzf secrethub_core-$SECRETHUB_VERSION-linux-amd64.tar.gz -C /opt/secrethub-core

export PHX_SERVER=true
export PORT=4664
export PHX_HOST="$SECRETHUB_HOST"
export DATABASE_URL='postgresql://secrethub:change-me@postgres.example.internal:5432/secrethub_prod'
export SECRET_KEY_BASE="$(openssl rand -base64 48)"
export SECRET_HUB_CLUSTER_NODE_ID=core-replica-a
export RELEASE_COOKIE="$(openssl rand -hex 32)"

/opt/secrethub-core/bin/secrethub_core eval "SecretHub.Core.Release.migrate()"
/opt/secrethub-core/bin/secrethub_core start
```

For systemd, put the environment in an `EnvironmentFile` and run:

```ini
[Unit]
Description=SecretHub Core
After=network-online.target
Wants=network-online.target

[Service]
User=secrethub
Group=secrethub
WorkingDirectory=/opt/secrethub-core
EnvironmentFile=/etc/secrethub/core.env
ExecStart=/opt/secrethub-core/bin/secrethub_core start
ExecStop=/opt/secrethub-core/bin/secrethub_core stop
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Initialize Core

After Core is reachable:

1. Open `/admin`.
2. Initialize the vault.
3. Store the generated unseal shares in your approved key storage.
4. Unseal with the configured threshold.
5. Generate or import PKI material needed for Agent enrollment.
6. Configure policies and AppRoles for applications and CLI users.

Health endpoints:

```bash
curl -f "https://$SECRETHUB_HOST/v1/sys/health/live"
curl -f "https://$SECRETHUB_HOST/v1/sys/health/ready"
```

## Deploy Agent With Docker

Use an image built from a revision containing TOML support; the historical
`v1.0.0-rc9` examples elsewhere in this guide do not include it. Prepare
`/etc/secrethub/agent.toml`, a private readable host-key copy, and persistent
mounts using the [Agent deployment and configuration guide](deployment/agent-deployment-guide.md#docker).
The container runs as UID/GID `1002`.

```bash
# Set this to your newly built image, or a release containing TOML support.
export SECRETHUB_AGENT_IMAGE=your-registry/secrethub-agent:your-build

docker run -d \
  --name secrethub-agent \
  --restart unless-stopped \
  --mount type=bind,src=/etc/secrethub/agent.toml,dst=/etc/secrethub/agent.toml,readonly \
  --mount type=bind,src=/etc/secrethub/agent-host-key,dst=/run/secrethub-host-key,readonly \
  --mount type=bind,src=/var/lib/secrethub-agent,dst=/var/lib/secrethub \
  --mount type=bind,src=/var/run/secrethub,dst=/var/run/secrethub \
  "$SECRETHUB_AGENT_IMAGE"
```

Set `core_url` to the machine enrollment HTTPS URL and `host_key_path` to
`/run/secrethub-host-key` in TOML. The image environment supplies state
`/var/lib/secrethub/agent`, bundle directory
`/var/lib/secrethub/pki/client-auth`, and socket
`/var/run/secrethub/agent.sock`. These environment values override TOML;
keep the same paths in the file or override the image environment too.

Approve the first enrollment in `/admin/pending-agents` through the Caddy mTLS
management URL after verifying the host fingerprint. Confirm connection and
advancing heartbeat in `/admin/agents`; a healthy local socket alone does not
prove connection to Core.

## Deploy Agent From a Tarball

Download an Agent artifact containing TOML support for the host platform.
Extract the entire release, rather than copying its launcher alone:

```bash
sudo install -d /opt/secrethub-agent
sudo tar -xzf /path/to/downloaded-agent-release.tar.gz -C /opt/secrethub-agent
```

Generate and edit a template, then validate the file before installing it:

```bash
/opt/secrethub-agent/bin/secrethub_agent config generate > agent.toml
# Edit agent.toml for this host.
/opt/secrethub-agent/bin/secrethub_agent config validate agent.toml
```

Generation needs no existing configuration and writes only TOML to standard
output. Validation selects its explicit file argument, then
`SECRET_HUB_AGENT_CONFIG_FILE`, then `/etc/secrethub/agent.toml`; the selected
file must exist. It checks TOML, supported options, required values, and HTTPS
without per-option environment overrides. It does not check configured key or
directory access, connect to Core, or start the Agent. Exit codes are `0` for
success, `1` for invalid configuration, and `2` for invalid command usage.

Prepare the service user, private host-key access, writable directories, and
`/etc/secrethub/agent.toml` following the complete
[tarball/systemd example](deployment/agent-deployment-guide.md#tarball-and-systemd).
Once those prerequisites are in place, the release uses the default file with:

```bash
/opt/secrethub-agent/bin/secrethub_agent eval 'SecretHub.Agent.Preflight.run()'
/opt/secrethub-agent/bin/secrethub_agent start
```

Run both commands as the service UID with its configured credentials, as the
systemd example does. For another configuration location, set
`SECRET_HUB_AGENT_CONFIG_FILE`. Restart after configuration changes; preserve
Agent identity and PKI bundle directories across restarts and upgrades.

## Install the CLI

The release workflow publishes the CLI to Hex.pm.

```bash
mix local.hex --force
mix escript.install hex secrethub_cli ${SECRETHUB_VERSION#v}
export PATH="$HOME/.mix/escripts:$PATH"

secrethub version
secrethub config set server_url "https://$SECRETHUB_HOST"
```

Login with AppRole credentials:

```bash
secrethub login --role-id "$ROLE_ID" --secret-id "$SECRET_ID"
secrethub secret get prod.db.password --format json
```

Read through a local Agent socket:

```bash
secrethub secret get prod.db.password \
  --agent-socket /var/run/secrethub/agent.sock \
  --agent-cert /path/to/app-client.pem \
  --format json
```

## Upgrade

1. Read release notes for the target tag.
2. Back up PostgreSQL.
3. Stop old Core instances or drain them behind the load balancer.
4. Run migrations using the new Core image or tarball:

   ```bash
   SECRET_HUB_CLUSTER_NODE_ID=core-migration-runner \
     bin/secrethub_core eval "SecretHub.Core.Release.migrate()"
   ```

5. Start Core with the new version.
6. Verify `/v1/sys/health/live`, `/v1/sys/health/ready`, `/admin`, and representative CLI secret reads.
7. Upgrade Agents after Core is healthy.

## Rollback

1. Stop the new Core release.
2. Restore PostgreSQL from backup if migrations are not backward-compatible.
3. Start the previous Core image or tarball.
4. Verify health checks and audit logging.
5. Roll back Agents only if the Agent/Core protocol changed.

See [`docs/deployment/rollback-procedures.md`](./deployment/rollback-procedures.md) for the full emergency procedure.

## More Deployment Docs

- [`docs/deployment/agent-deployment-guide.md`](./deployment/agent-deployment-guide.md)
- [`docs/deployment/postgresql-ha-setup.md`](./deployment/postgresql-ha-setup.md)
- [`docs/deployment/production-runbook.md`](./deployment/production-runbook.md)
- [`docs/deployment/production-launch-checklist.md`](./deployment/production-launch-checklist.md)
- [`docs/deployment/rollback-procedures.md`](./deployment/rollback-procedures.md)
