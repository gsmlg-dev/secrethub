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

Core and Agent are separate OTP releases. Core uses `config/runtime.exs` and requires database and Phoenix runtime secrets. The standalone Agent release uses `config/agent_runtime.exs` and requires only `SECRET_HUB_AGENT_CORE_URL` at boot.

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

docker run --rm \
  -e DATABASE_URL="$DATABASE_URL" \
  -e SECRET_KEY_BASE="$SECRET_KEY_BASE" \
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
  -e POOL_SIZE=10 \
  -e RELEASE_COOKIE="$(openssl rand -hex 32)" \
  ghcr.io/gsmlg-dev/secrethub/core:$SECRETHUB_VERSION
```

Verify Core:

```bash
curl -f "http://localhost:4664/v1/sys/health/live"
```

The admin UI is available at:

```text
http://localhost:4664/admin
```

Put Core behind HTTPS for production. If your reverse proxy terminates TLS, forward the normal web/API listener to port `4664`.

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
  -e RELEASE_COOKIE="$(openssl rand -hex 32)" \
  ghcr.io/gsmlg-dev/secrethub/core-standalone:$SECRETHUB_VERSION
```

The standalone image initializes PostgreSQL and runs migrations on startup. Do not use it for high availability or production database operations.

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

The Agent container runs as uid/gid `1002`. Ensure mounted state and Unix socket directories are writable by that uid/gid.

```bash
sudo install -d -o 1002 -g 1002 -m 0700 /var/lib/secrethub-agent
sudo install -d -o 1002 -g 1002 -m 0770 /var/run/secrethub

docker run -d \
  --name secrethub-agent \
  --restart unless-stopped \
  -e SECRET_HUB_AGENT_CORE_URL="https://$SECRETHUB_HOST" \
  -v /var/lib/secrethub-agent:/app/.local/state/secrethub/agent \
  -v /var/run/secrethub:/var/run/secrethub \
  ghcr.io/gsmlg-dev/secrethub/agent:$SECRETHUB_VERSION
```

On first boot, the Agent creates a pending enrollment. Approve it in Core at:

```text
/admin/pending-agents
```

After approval, the Agent generates a TLS keypair, submits a CSR and SSH host-key proof, stores trusted material, connects to the mTLS runtime endpoint, and serves the local Unix socket at:

```text
/var/run/secrethub/agent.sock
```

Applications and the CLI can use that socket to retrieve secrets through the Agent.

## Deploy Agent From a Tarball

Download the matching Agent artifact for the host OS and architecture.

```bash
sudo useradd --system --home /var/lib/secrethub-agent --shell /usr/sbin/nologin secrethub-agent
sudo install -d -o secrethub-agent -g secrethub-agent -m 0700 /var/lib/secrethub-agent
sudo install -d -o secrethub-agent -g secrethub-agent -m 0770 /var/run/secrethub
sudo install -d -o secrethub-agent -g secrethub-agent /opt/secrethub-agent
sudo tar -xzf secrethub_agent-$SECRETHUB_VERSION-linux-amd64.tar.gz -C /opt/secrethub-agent
```

Example systemd unit:

```ini
[Unit]
Description=SecretHub Agent
After=network-online.target
Wants=network-online.target

[Service]
User=secrethub-agent
Group=secrethub-agent
WorkingDirectory=/opt/secrethub-agent
Environment=HOME=/var/lib/secrethub-agent
Environment=SECRET_HUB_AGENT_CORE_URL=https://secrethub.example.com
ExecStart=/opt/secrethub-agent/bin/secrethub_agent start
ExecStop=/opt/secrethub-agent/bin/secrethub_agent stop
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

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
