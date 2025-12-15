# SecretHub Quickstart Guide

Get SecretHub up and running in 5 minutes.

---

## Prerequisites

- Docker & Docker Compose (or local Elixir 1.18 + PostgreSQL 16)
- 4 GB RAM minimum
- Linux, macOS, or Windows with WSL2

---

## Option 1: Docker Compose (Recommended)

### 1. Clone and Start

```bash
git clone https://github.com/your-org/secrethub.git
cd secrethub

# Start services
docker-compose up -d

# Wait for services to be ready
docker-compose logs -f secrethub-core
```

### 2. Initialize Vault

```bash
# Initialize the vault (returns unseal keys and root token)
curl -X POST http://localhost:4000/v1/sys/init \
  -H "Content-Type: application/json" \
  -d '{
    "secret_shares": 5,
    "secret_threshold": 3
  }'
```

**⚠️ IMPORTANT:** Save the unseal keys and root token securely!

Response:
```json
{
  "keys": ["key1...", "key2...", "key3...", "key4...", "key5..."],
  "keys_base64": ["..."],
  "root_token": "s.XXXXXXXXXXX"
}
```

### 3. Unseal Vault

Unseal with 3 of 5 keys:

```bash
# Unseal with key 1
curl -X POST http://localhost:4000/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "key1..."}'

# Unseal with key 2
curl -X POST http://localhost:4000/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "key2..."}'

# Unseal with key 3 (vault is now unsealed)
curl -X POST http://localhost:4000/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "key3..."}'
```

### 4. Access Web UI

Open [http://localhost:4000](http://localhost:4000) in your browser.

**Login:**
- Navigate to `/admin/auth/login`
- Use admin credentials (set via `ADMIN_USERNAME` and `ADMIN_PASSWORD` env vars)

---

## Option 2: Local Development

### 1. Setup Environment

```bash
# Clone repository
git clone https://github.com/your-org/secrethub.git
cd secrethub

# Enter devenv shell (uses Nix)
devenv shell

# Or install dependencies manually
mix deps.get
cd apps/secrethub_web && npm install && cd ../..
```

### 2. Setup Database

```bash
# Create and migrate database
db-setup

# Or manually:
cd apps/secrethub_core
mix ecto.create
mix ecto.migrate
cd ../..
```

### 3. Start Server

```bash
# Start Phoenix server
mix phx.server

# Or use devenv script:
server
```

Server will be available at [http://localhost:4000](http://localhost:4000).

### 4. Initialize Vault

Follow steps 2-4 from Docker Compose option above.

---

## Next Steps

### Create Your First AppRole

AppRoles provide authentication for applications and agents.

```bash
# Create an AppRole for your application
curl -X POST http://localhost:4000/v1/auth/approle/role/myapp \
  -H "X-Vault-Token: s.XXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{
    "role_name": "myapp",
    "policies": ["default"],
    "token_ttl": 3600
  }'

# Get Role ID
curl http://localhost:4000/v1/auth/approle/role/myapp/role-id \
  -H "X-Vault-Token: s.XXXXXXXXXXX"

# Generate Secret ID
curl -X POST http://localhost:4000/v1/auth/approle/role/myapp/secret-id \
  -H "X-Vault-Token: s.XXXXXXXXXXX"
```

### Store Your First Secret

```bash
# Store a static secret
curl -X POST http://localhost:4000/v1/secrets/static/prod/db/postgres \
  -H "X-Vault-Token: s.XXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "username": "myapp",
      "password": "supersecret",
      "host": "db.example.com",
      "port": 5432
    }
  }'

# Read the secret back
curl http://localhost:4000/v1/secrets/static/prod/db/postgres \
  -H "X-Vault-Token: s.XXXXXXXXXXX"
```

### Deploy an Agent

```bash
# Deploy agent with Docker
docker run -d \
  --name secrethub-agent \
  -e AGENT_ID=agent-01 \
  -e CORE_URL=ws://secrethub-core:4000 \
  -e ROLE_ID=<your-role-id> \
  -e SECRET_ID=<your-secret-id> \
  secrethub/agent:latest

# Check agent connection in Web UI
# Navigate to /admin/agents
```

### Create a Policy

```bash
# Create a policy that grants read access to production secrets
curl -X POST http://localhost:4000/v1/policies \
  -H "X-Vault-Token: s.XXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-read",
    "rules": [
      {
        "path": "prod/*",
        "capabilities": ["read"],
        "effect": "allow"
      }
    ]
  }'

# Assign policy to AppRole
curl -X PUT http://localhost:4000/v1/auth/approle/role/myapp \
  -H "X-Vault-Token: s.XXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{
    "policies": ["prod-read"]
  }'
```

---

## Using the CLI

Install the CLI tool:

```bash
# Build from source
cd apps/secrethub_cli
mix escript.build

# Add to PATH
sudo mv secrethub /usr/local/bin/

# Or use directly
./secrethub --help
```

Configure and authenticate:

```bash
# Configure CLI
secrethub config set-url http://localhost:4000
secrethub auth login --role-id <role-id> --secret-id <secret-id>

# Read a secret
secrethub secret read prod/db/postgres

# List secrets
secrethub secret list prod/

# Create a secret
secrethub secret create dev/api/key \
  --data '{"api_key": "abc123"}'
```

---

## Architecture Overview

```
┌─────────────────────────────────────────┐
│          SecretHub Core                 │
│                                         │
│  ┌───────────┐     ┌──────────────┐   │
│  │  Web UI   │     │  REST API    │   │
│  └───────────┘     └──────────────┘   │
│                                         │
│  ┌───────────────────────────────────┐ │
│  │  Policy Engine                    │ │
│  ├───────────────────────────────────┤ │
│  │  Secret Engines (Static/Dynamic)  │ │
│  ├───────────────────────────────────┤ │
│  │  PKI Engine                       │ │
│  ├───────────────────────────────────┤ │
│  │  Audit Logging                    │ │
│  └───────────────────────────────────┘ │
│                                         │
│         ↕ mTLS WebSocket                │
└─────────────────────────────────────────┘
              ↕
┌─────────────────────────────────────────┐
│       SecretHub Agent (on app host)     │
│                                         │
│  ┌──────────────┐  ┌─────────────────┐ │
│  │ Local Cache  │  │ Template Engine │ │
│  └──────────────┘  └─────────────────┘ │
│                                         │
│         ↕ Unix Domain Socket (mTLS)     │
└─────────────────────────────────────────┘
              ↕
┌─────────────────────────────────────────┐
│          Your Application               │
└─────────────────────────────────────────┘
```

---

## Common Tasks

### Check System Health

```bash
# Health check
curl http://localhost:4000/v1/sys/health

# Seal status
curl http://localhost:4000/v1/sys/seal-status
```

### Rotate a Secret

```bash
# Update secret (creates new version)
curl -X POST http://localhost:4000/v1/secrets/static/prod/db/postgres \
  -H "X-Vault-Token: s.XXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "username": "myapp",
      "password": "newsupersecret",
      "host": "db.example.com",
      "port": 5432
    }
  }'

# Agents with active connections will be notified automatically
```

### View Audit Logs

```bash
# Via Web UI: /admin/audit
# Or via API:
curl http://localhost:4000/admin/api/dashboard/audit \
  -H "X-Vault-Token: s.XXXXXXXXXXX"
```

---

## Troubleshooting

### Vault is Sealed

**Problem:** API returns 503 Service Unavailable

**Solution:**
```bash
# Check seal status
curl http://localhost:4000/v1/sys/seal-status

# Unseal if needed (requires 3 of 5 keys)
curl -X POST http://localhost:4000/v1/sys/unseal \
  -d '{"key": "key1..."}'
```

### Agent Can't Connect

**Problem:** Agent logs show "Connection refused"

**Solution:**
1. Check Core is running: `curl http://localhost:4000/v1/sys/health`
2. Verify agent config: `CORE_URL`, `ROLE_ID`, `SECRET_ID`
3. Check network connectivity
4. Check firewall rules

### Database Connection Error

**Problem:** Core logs show "Connection refused" to database

**Solution:**
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Check database credentials in config
# Verify DATABASE_URL environment variable
```

---

## Next Steps

- **[Architecture Overview](./architecture.md)** - Understand the system design
- **[Deployment Guide](./deployment/README.md)** - Deploy to production
- **[Operator Manual](./operator-manual.md)** - Day-to-day operations
- **[Best Practices](./best-practices.md)** - Security and performance tips

---

## Getting Help

- **Documentation:** [docs/](./README.md)
- **GitHub Issues:** [https://github.com/your-org/secrethub/issues](https://github.com/your-org/secrethub/issues)
- **Community:** [https://github.com/your-org/secrethub/discussions](https://github.com/your-org/secrethub/discussions)
