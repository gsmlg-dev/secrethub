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
| 🚨 **Anomaly Detection** | Real-time security anomaly detection and alerting |
| 📋 **Policy Templates** | Pre-built policy templates for common use cases |

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
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐       │
│  │  AppRole  │  │   Vault   │  │  Anomaly  │  │   Apps    │       │
│  │   Auth    │  │ Seal/     │  │ Detection │  │  Manager  │       │
│  │           │  │ Unseal    │  │           │  │           │       │
│  └───────────┘  └───────────┘  └───────────┘  └───────────┘       │
│                                                                      │
│              REST API + WebSocket + LiveView Admin                  │
└─────────────────────────────────────────────────────────────────────┘
                              ↕ mTLS WebSocket
┌─────────────────────────────────────────────────────────────────────┐
│                       SecretHub Agent                                │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐       │
│  │ Bootstrap │  │Connection │  │   Cache   │  │  Sinker   │       │
│  │           │  │  Manager  │  │   Layer   │  │           │       │
│  │ • Enroll  │  │           │  │           │  │ • Atomic  │       │
│  │ • CSR Gen │  │ • Reconn  │  │ • TTL     │  │   Write   │       │
│  │ • mTLS ID │  │ • Backoff │  │ • LRU     │  │ • Reload  │       │
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

1. **Enrollment Phase**: Host identity discovery → pending enrollment → operator approval → TLS CSR + SSH host-key proof → certificate issuance
2. **Operational Phase**: Core-issued mTLS WebSocket identity → Secret requests → Local caching
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
┌─────────────┐   pending enrollment     ┌─────────────┐
│   Agent     │ ─────────────────────────▶│    Core     │
│ Enrollment  │   SSH host public key     │  Approval   │
└─────────────┘                           └─────────────┘
       │                                         │
       │       TLS CSR + SSH proof               │
       │ ────────────────────────────────────────▶
       │                                         │
       │       Agent client certificate          │
       │ ◀───────────────────────────────────────│
       │                                         │
       ▼                                         ▼
┌─────────────┐   Core-issued mTLS WS    ┌─────────────┐
│   Agent     │ ◀═══════════════════════▶│    Core     │
│   Runtime   │    certificate identity   │   Runtime   │
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
- **Web UI / Admin Dashboard:** http://localhost:4664/admin
- **REST API:** http://localhost:4664/v1
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
│   │       ├── policy_templates.ex     # Pre-built policy templates
│   │       ├── apps.ex                 # Application management
│   │       ├── audit.ex                # Hash-chained audit logs
│   │       ├── vault/seal_state.ex     # Seal/unseal with Shamir
│   │       ├── engines/dynamic/        # PostgreSQL, Redis, AWS STS
│   │       ├── auto_unseal/providers/  # AWS KMS, Azure KV, GCP KMS
│   │       ├── anomaly_detection.ex    # Security anomaly detection
│   │       ├── alerting.ex             # Multi-channel alerting
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
│   │       ├── bootstrap.ex            # Legacy AppRole bootstrap guard
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
├── infrastructure/                     # IaC
│   └── postgres/                       # PostgreSQL init scripts
└── .github/workflows/                  # CI/CD pipelines
```

---

## 🌐 API Reference

### System Endpoints (`/v1/sys`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/sys/init` | POST | Initialize vault with Shamir shares |
| `/v1/sys/seal` | POST | Seal the vault |
| `/v1/sys/unseal` | POST | Unseal vault with key shares |
| `/v1/sys/seal-status` | GET | Get vault seal status |
| `/v1/sys/health` | GET | Health check |
| `/v1/sys/health/ready` | GET | Kubernetes readiness probe |
| `/v1/sys/health/live` | GET | Kubernetes liveness probe |

### Authentication (`/v1/auth`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/auth/approle/login` | POST | AppRole login |
| `/v1/auth/approle/role` | GET | List all roles |
| `/v1/auth/approle/role/:role_name` | POST | Create AppRole |
| `/v1/auth/approle/role/:role_name` | DELETE | Delete AppRole |
| `/v1/auth/approle/role/:role_name/role-id` | GET | Get Role ID |
| `/v1/auth/approle/role/:role_name/secret-id` | POST | Generate Secret ID |

### Secrets (`/v1/secrets`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/secrets/:path` | GET | Read secret |
| `/v1/secrets/:path` | POST | Write secret |
| `/v1/secrets/:path` | DELETE | Delete secret |
| `/v1/secrets/dynamic/postgresql/creds/:role` | POST | Generate PostgreSQL credentials |
| `/v1/secrets/dynamic/redis/creds/:role` | POST | Generate Redis credentials |
| `/v1/secrets/dynamic/aws/creds/:role` | POST | Generate AWS STS credentials |

### PKI (`/v1/pki`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/pki/ca/root/generate` | POST | Generate Root CA |
| `/v1/pki/ca/intermediate/generate` | POST | Generate Intermediate CA |
| `/v1/pki/issue` | POST | Issue certificate |
| `/v1/pki/sign-request` | POST | Sign a CSR |
| `/v1/pki/certificates` | GET | List certificates |
| `/v1/pki/certificates/:id` | GET | Get certificate details |
| `/v1/pki/certificates/:id/revoke` | POST | Revoke certificate |
| `/v1/pki/app/issue` | POST | Issue app certificate (bootstrap) |
| `/v1/pki/app/renew` | POST | Renew app certificate |

### Applications (`/v1/apps`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/apps` | GET | List applications |
| `/v1/apps` | POST | Register application |
| `/v1/apps/:id` | GET | Get application details |
| `/v1/apps/:id` | PUT | Update application |
| `/v1/apps/:id` | DELETE | Delete application |
| `/v1/apps/:id/suspend` | POST | Suspend application |
| `/v1/apps/:id/activate` | POST | Activate application |
| `/v1/apps/:id/certificates` | GET | List app certificates |

### Leases (`/v1/sys/leases`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/sys/leases` | GET | List active leases |
| `/v1/sys/leases/stats` | GET | Get lease statistics |
| `/v1/sys/leases/renew` | POST | Renew a lease |
| `/v1/sys/leases/revoke` | POST | Revoke a lease |

---

## 🖥️ Admin Dashboard

The LiveView-based admin dashboard (`/admin`) provides:

### Core Management
- **Dashboard**: System overview, health metrics, quick stats
- **Secrets**: Secret browser, version history, bulk operations
- **Policies**: Policy editor, entity bindings, simulator
- **Policy Templates**: Pre-built templates for common scenarios

### Security & PKI
- **PKI**: Root/Intermediate CA management, certificate issuance
- **Certificates**: Certificate browser, revocation, renewal
- **AppRoles**: Role management, secret ID rotation

### Infrastructure
- **Agents**: Connected agents, status monitoring, health checks
- **Dynamic Engines**: PostgreSQL/Redis engine configuration
- **Engine Health**: Real-time engine status dashboard
- **Leases**: Active lease management, bulk revocation

### Operations
- **Audit**: Log viewer, search, CSV export
- **Rotations**: Rotation schedules, history, manual triggers
- **Templates**: Secret template management

### Cluster & Monitoring
- **Cluster**: Node health, distributed state, deployment status
- **Auto-Unseal**: KMS provider configuration
- **Alerts**: Alert rules, notification channels
- **Anomalies**: Anomaly detection rules, triggered alerts
- **Performance**: Performance metrics dashboard

---

## 🚨 Anomaly Detection

SecretHub includes a built-in anomaly detection engine with rules for:

| Rule Type | Description |
|-----------|-------------|
| Failed Logins | Detect brute-force authentication attempts |
| Bulk Deletion | Alert on mass secret deletion |
| Unusual Access Time | Detect access outside business hours |
| Mass Secret Access | Alert on abnormal secret read patterns |
| Credential Export Spike | Detect unusual credential generation |
| Rotation Failures | Alert on failed secret rotations |
| Policy Violations | Detect policy bypass attempts |

### Alert Channels

- Email notifications
- Slack webhooks
- Generic webhooks
- PagerDuty integration
- Opsgenie integration

---

## 📋 Policy Templates

Pre-built policy templates for common scenarios:

| Template | Description |
|----------|-------------|
| `business_hours` | Access restricted to business hours (9-5) |
| `ip_restricted` | Access limited to specific IP ranges |
| `read_only` | Read-only access to secrets |
| `emergency_access` | Break-glass emergency access |
| `dev_environment` | Development environment access |
| `production_readonly` | Production read-only access |
| `time_limited` | Time-limited access with expiration |
| `multi_region` | Multi-region access policies |

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
docker run -d -p 4664:4664 \
  -e PORT=4664 \
  -e DATABASE_URL="postgresql://..." \
  -e SECRET_KEY_BASE="..." \
  ghcr.io/gsmlg-dev/secrethub/core:v1.0.0-rc3

# Agent
docker run -d \
  -e SECRET_HUB_AGENT_CORE_URL="http://core:4664" \
  -v secrethub-agent-state:/home/secrethub/.local/state/secrethub/agent \
  ghcr.io/gsmlg-dev/secrethub/agent:v1.0.0-rc3
```

### Kubernetes (Helm)

```bash
helm install secrethub ./infrastructure/helm/secrethub \
  --set core.database.url="postgresql://..." \
  --set core.secretKeyBase="..."
```

### Environment Variables

```bash
# Core Service
DATABASE_URL=postgresql://user:pass@host/db  # Or with socket: ?host=/var/run/postgresql
SECRET_KEY_BASE=<64-char-hex>
PHX_HOST=secrethub.example.com
POOL_SIZE=10

# Agent
SECRET_HUB_AGENT_CORE_URL=https://core.example.com:4664
```

---

## 🧪 Development Status

### ✅ Completed Features

- [x] Umbrella project structure with 4 apps
- [x] PostgreSQL 16 with UUID, pgcrypto extensions (Unix socket support)
- [x] AppRole authentication (RoleID/SecretID)
- [x] Full PKI engine (Root CA, Intermediate CA, CSR)
- [x] Vault seal/unseal with Shamir's Secret Sharing
- [x] Policy engine with glob patterns and conditions
- [x] Policy templates for common scenarios
- [x] Tamper-evident audit logging (hash chains + HMAC)
- [x] Dynamic secret engines (PostgreSQL, Redis, AWS STS)
- [x] Auto-unseal providers (AWS KMS, Azure Key Vault, GCP KMS)
- [x] Agent bootstrap and mTLS WebSocket connection
- [x] Secret caching with TTL and LRU eviction
- [x] Template rendering and atomic file writes
- [x] Lease management with auto-renewal
- [x] Oban-scheduled secret rotation
- [x] Application management system
- [x] Anomaly detection engine
- [x] Multi-channel alerting (Email, Slack, PagerDuty, Opsgenie)
- [x] LiveView admin dashboard (20+ pages)
- [x] CI/CD with GitHub Actions
- [x] Multi-arch Docker images (amd64/arm64)
- [x] Helm charts for Kubernetes deployment

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
