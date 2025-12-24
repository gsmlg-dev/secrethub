# SecretHub

> Enterprise-grade Machine-to-Machine secrets management platform

**Status:** 🚀 v1.0.0-rc3 Released

---

## 🎯 Project Overview

SecretHub is a secure, reliable, and highly automated secrets management platform designed specifically for Machine-to-Machine (M2M) communication. Built in Elixir with a HashiCorp Vault-like architecture, it eliminates hardcoded credentials through centralized management, dynamic generation, and automatic rotation.

### Core Features

| Feature | Description |
|---------|-------------|
| 🔐 **mTLS Everywhere** | Mutual TLS for all Core-Agent communications with PKI-issued certificates |
| 🔑 **Dynamic Secrets** | Short-lived credentials for PostgreSQL, Redis, and AWS STS |
| 🔄 **Automatic Rotation** | Oban-scheduled zero-downtime secret rotation |
| 📝 **Template Rendering** | EEx-based secret injection into configuration files |
| 📊 **Tamper-Proof Audit** | SHA-256 hash-chained logs with HMAC signatures |
| 🛡️ **Vault Seal/Unseal** | Shamir's Secret Sharing for master key protection |
| ⚡ **High Availability** | Multi-node deployment with distributed locking |
| 🔓 **Auto-Unseal** | AWS KMS, Azure Key Vault, GCP KMS integrations |

---

## 🏗️ Architecture

SecretHub implements a **two-tier architecture** with a central Core service and distributed Agents:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SecretHub Core                                │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐       │
│  │    PKI    │  │  Policy   │  │  Secret   │  │   Audit   │       │
│  │  Engine   │  │  Engine   │  │  Engines  │  │  Logger   │       │
│  │           │  │           │  │           │  │           │       │
│  │ • Root CA │  │ • JSONB   │  │ • Static  │  │ • Hash    │       │
│  │ • Int. CA │  │ • Glob    │  │ • Dynamic │  │   Chain   │       │
│  │ • CSR     │  │   Match   │  │ • Leases  │  │ • HMAC    │       │
│  └───────────┘  └───────────┘  └───────────┘  └───────────┘       │
│                                                                      │
│  ┌───────────┐  ┌───────────┐  ┌───────────────────────────┐       │
│  │  AppRole  │  │   Vault   │  │      REST API + WebSocket  │       │
│  │   Auth    │  │ Seal/     │  │  /v1/secrets, /v1/auth,   │       │
│  │           │  │ Unseal    │  │  /v1/pki, /v1/sys         │       │
│  └───────────┘  └───────────┘  └───────────────────────────┘       │
│                                                                      │
│                    Phoenix LiveView Admin Dashboard                  │
└─────────────────────────────────────────────────────────────────────┘
                              ↕ mTLS WebSocket
┌─────────────────────────────────────────────────────────────────────┐
│                       SecretHub Agent                                │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐       │
│  │ Bootstrap │  │Connection │  │   Cache   │  │  Sinker   │       │
│  │           │  │  Manager  │  │   Layer   │  │           │       │
│  │ • AppRole │  │           │  │           │  │ • Atomic  │       │
│  │ • CSR Gen │  │ • Reconn  │  │ • TTL     │  │   Write   │       │
│  │ • Cert    │  │ • Backoff │  │ • LRU     │  │ • Reload  │       │
│  └───────────┘  └───────────┘  └───────────┘  └───────────┘       │
│                                                                      │
│  ┌───────────┐  ┌───────────┐  ┌───────────────────────────┐       │
│  │ Template  │  │  Lease    │  │   Unix Domain Socket API   │       │
│  │ Renderer  │  │ Renewer   │  │   (for local applications) │       │
│  └───────────┘  └───────────┘  └───────────────────────────┘       │
└─────────────────────────────────────────────────────────────────────┘
                              ↕ UDS + mTLS
                    ┌──────────────────────┐
                    │    Applications      │
                    └──────────────────────┘
```

### Agent Lifecycle

1. **Bootstrap Phase**: AppRole auth → RSA-2048 keypair generation → CSR → Certificate issuance
2. **Operational Phase**: mTLS WebSocket to Core → Secret requests → Local caching
3. **Delivery Phase**: EEx template rendering → Atomic file writes → Application reload triggers
4. **Local Access**: Unix Domain Socket API for application secret retrieval

---

## 🔒 Security Architecture

### Encryption

| Layer | Algorithm | Details |
|-------|-----------|---------|
| At Rest | AES-256-GCM | Per-secret nonces, 128-bit auth tags |
| Master Key | Shamir's Secret Sharing | Configurable N shares, K threshold |
| Key Derivation | PBKDF2-SHA256 | 100,000 iterations |

### Authentication Flow

```
┌─────────────┐     RoleID/SecretID      ┌─────────────┐
│   Agent     │ ─────────────────────────▶│    Core     │
│  Bootstrap  │                           │   AppRole   │
└─────────────┘                           └─────────────┘
       │                                         │
       │              CSR Request                │
       │ ◀───────────────────────────────────────│
       │                                         │
       │           Signed Certificate            │
       │ ────────────────────────────────────────▶
       │                                         │
       ▼                                         ▼
┌─────────────┐      mTLS WebSocket      ┌─────────────┐
│   Agent     │ ◀═══════════════════════▶│    Core     │
│   Running   │                           │   Running   │
└─────────────┘                           └─────────────┘
```

### PKI Hierarchy

- **Root CA**: Self-signed, RSA-4096 or ECDSA P-384
- **Intermediate CA**: Root-signed, issues client certificates
- **Client Certificates**: 1-year validity, auto-renewal 7 days before expiry

---

## 🔑 Secret Engines

### Static Secrets
- Encrypted storage with versioning
- Oban-scheduled rotation
- Template rendering support

### Dynamic Secrets

| Engine | Description | Lease Management |
|--------|-------------|------------------|
| **PostgreSQL** | Temporary users with `VALID UNTIL`, custom SQL templates | Auto-revocation |
| **Redis** | Dynamic ACL-based credentials | Auto-revocation |
| **AWS STS** | Temporary IAM credentials via AssumeRole | TTL-based |

---

## 🚀 Quick Start

### Prerequisites

- **devenv:** [Install from devenv.sh](https://devenv.sh/getting-started/)
- **direnv (optional):** [Install from direnv.net](https://direnv.net/)

### Installation

```bash
# Clone the repository
git clone https://github.com/gsmlg-dev/secrethub.git
cd secrethub

# Activate devenv (or use direnv allow)
devenv shell

# Set up the database
db-setup

# Start the development server
server
```

**Available at:**
- **Web UI / Admin Dashboard:** http://localhost:4000/admin
- **REST API:** http://localhost:4000/v1
- **Metrics:** http://localhost:9090 (Prometheus)

### Quick Commands

```bash
# Database
db-setup        # Create and migrate database
db-reset        # Reset database (drop, create, migrate, seed)

# Development
server          # Start Phoenix server
console         # Start IEx shell with app loaded

# Testing
mix test                    # Run all tests
mix coveralls.html          # Generate coverage report

# Code Quality
quality         # Run format, credo, dialyzer
```

---

## 📁 Project Structure

```
secrethub/                              # Elixir Umbrella Application
├── apps/
│   ├── secrethub_core/                 # Core Business Logic
│   │   └── lib/secrethub_core/
│   │       ├── auth/app_role.ex        # AppRole authentication
│   │       ├── pki/ca.ex               # PKI/CA management
│   │       ├── policies.ex             # Policy engine
│   │       ├── audit.ex                # Hash-chained audit logs
│   │       ├── vault/seal_state.ex     # Seal/unseal with Shamir
│   │       ├── engines/dynamic/        # PostgreSQL, Redis, AWS STS
│   │       ├── auto_unseal/providers/  # KMS integrations
│   │       ├── lease_manager.ex        # Lease lifecycle
│   │       └── rotation_manager.ex     # Oban-scheduled rotation
│   │
│   ├── secrethub_web/                  # Phoenix Web Layer
│   │   └── lib/secrethub_web_web/
│   │       ├── controllers/            # REST API endpoints
│   │       ├── live/admin/             # LiveView admin dashboard
│   │       ├── channels/               # Agent WebSocket channels
│   │       └── plugs/                  # Rate limiter, mTLS verification
│   │
│   ├── secrethub_agent/                # Distributed Agent Daemon
│   │   └── lib/secrethub_agent/
│   │       ├── bootstrap.ex            # AppRole → Certificate flow
│   │       ├── connection.ex           # WebSocket client with reconnect
│   │       ├── cache.ex                # TTL + LRU secret cache
│   │       ├── sinker.ex               # Atomic file writer
│   │       ├── template_renderer.ex    # EEx template engine
│   │       ├── uds_server.ex           # Unix Domain Socket API
│   │       └── lease_renewer.ex        # Auto lease renewal
│   │
│   └── secrethub_shared/               # Shared Code
│       └── lib/secrethub_shared/
│           ├── schemas/                # 20+ Ecto schemas
│           └── crypto/                 # AES-256-GCM, Shamir
│
├── config/                             # Environment configs
├── infrastructure/                     # IaC (Docker, K8s, Terraform)
└── .github/workflows/                  # CI/CD pipelines
```

---

## 🌐 API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /v1/sys/init` | Initialize vault with Shamir shares |
| `POST /v1/sys/unseal` | Unseal vault with key shares |
| `GET /v1/sys/health` | Health check |
| `POST /v1/auth/approle/login` | AppRole authentication |
| `GET /v1/secrets/:path` | Read secret |
| `POST /v1/secrets/:path` | Write secret |
| `POST /v1/secrets/dynamic/postgresql/creds/:role` | Generate PostgreSQL credentials |
| `POST /v1/pki/issue` | Issue certificate |
| `GET /v1/sys/leases` | List active leases |
| `POST /v1/sys/leases/revoke` | Revoke lease |

---

## 🖥️ Admin Dashboard

The LiveView-based admin dashboard provides:

- **Dashboard**: System overview, health metrics
- **Agents**: Connected agents, status monitoring
- **Secrets**: Secret browser, version history
- **Policies**: Policy management, entity bindings
- **PKI**: CA management, certificate issuance
- **Audit**: Log viewer, CSV export
- **Dynamic Engines**: PostgreSQL/Redis configuration
- **Leases**: Active lease management
- **Cluster**: Node health, distributed state

---

## 🚢 Deployment

### Release Artifacts

| Release | Includes |
|---------|----------|
| `secrethub_core` | Core + Web + Shared |
| `secrethub_agent` | Agent + Shared |

### Docker Images

```bash
# Core Service
docker run -d -p 4000:4000 \
  -e DATABASE_URL="postgresql://..." \
  -e SECRET_KEY_BASE="..." \
  ghcr.io/gsmlg-dev/secrethub/core:v1.0.0-rc3

# Agent
docker run -d \
  -e SECRETHUB_CORE_URL="wss://core:4000" \
  -e SECRETHUB_ROLE_ID="..." \
  -e SECRETHUB_SECRET_ID="..." \
  ghcr.io/gsmlg-dev/secrethub/agent:v1.0.0-rc3
```

### Environment Variables

```bash
# Core Service
DATABASE_URL=postgresql://user:pass@host/db  # Or with socket: ?host=/var/run/postgresql
SECRET_KEY_BASE=<64-char-hex>
PHX_HOST=secrethub.example.com

# Agent
SECRETHUB_CORE_URL=wss://core.example.com:4000
SECRETHUB_ROLE_ID=<role-id>
SECRETHUB_SECRET_ID=<secret-id>
```

---

## 🧪 Development Status

### ✅ Completed Features

- [x] Umbrella project structure with 4 apps
- [x] PostgreSQL 16 with UUID, pgcrypto extensions
- [x] AppRole authentication (RoleID/SecretID)
- [x] Full PKI engine (Root CA, Intermediate CA, CSR)
- [x] Vault seal/unseal with Shamir's Secret Sharing
- [x] Policy engine with glob patterns and conditions
- [x] Tamper-evident audit logging (hash chains + HMAC)
- [x] Dynamic secret engines (PostgreSQL, Redis, AWS STS)
- [x] Auto-unseal providers (AWS KMS, Azure, GCP)
- [x] Agent bootstrap and mTLS WebSocket connection
- [x] Secret caching with TTL and LRU eviction
- [x] Template rendering and atomic file writes
- [x] Lease management with auto-renewal
- [x] Oban-scheduled secret rotation
- [x] LiveView admin dashboard
- [x] CI/CD with GitHub Actions
- [x] Multi-arch Docker images (amd64/arm64)

---

## 📝 Contributing

### Commit Convention

```
type(scope): subject

Types: feat, fix, docs, style, refactor, test, chore
```

**Example:**
```
feat(core): implement AWS STS dynamic secret engine

- Add AssumeRole credential generation
- Implement lease management
- Add integration tests
```

---

## 📄 License

MIT License

---

## 🔗 Links

- **Repository:** https://github.com/gsmlg-dev/secrethub
- **Latest Release:** [v1.0.0-rc3](https://github.com/gsmlg-dev/secrethub/releases/tag/v1.0.0-rc3)
- **Docker Images:** `ghcr.io/gsmlg-dev/secrethub/core` | `ghcr.io/gsmlg-dev/secrethub/agent`
