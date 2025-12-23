# SecretHub

> Enterprise-grade Machine-to-Machine secrets management platform

**Status:** 🚀 v1.0.0-rc2 Released

---

## 🎯 Project Overview

SecretHub is a secure, reliable, and highly automated secrets management platform designed specifically for Machine-to-Machine (M2M) communication. It eliminates hardcoded credentials and static secrets through centralized management, dynamic generation, and automatic rotation.

### Core Features
- 🔐 **mTLS Everywhere** - Mutual TLS for all communications
- 🔑 **Dynamic Secrets** - Short-lived credentials for PostgreSQL, Redis, AWS
- 🔄 **Automatic Rotation** - Zero-downtime secret rotation
- 📝 **Template Rendering** - Inject secrets into configuration files
- 📊 **Comprehensive Audit** - Every action logged with tamper-proof hash chains
- ⚡ **High Availability** - Multi-node deployment with auto-failover

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SecretHub Core                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │   PKI    │  │  Policy  │  │  Secret  │            │
│  │  Engine  │  │  Engine  │  │  Engines │            │
│  └──────────┘  └──────────┘  └──────────┘            │
│                                                         │
│  Phoenix WebSocket API + Web UI                       │
└─────────────────────────────────────────────────────────┘
                         ↕ mTLS WebSocket
┌─────────────────────────────────────────────────────────┐
│                  SecretHub Agent                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │Connection│  │  Cache   │  │ Template │            │
│  │ Manager  │  │  Layer   │  │ Renderer │            │
│  └──────────┘  └──────────┘  └──────────┘            │
│                                                         │
│  Unix Domain Socket (mTLS)                            │
└─────────────────────────────────────────────────────────┘
                         ↕
                 ┌──────────────┐
                 │ Applications │
                 └──────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- **devenv:** [Install from devenv.sh](https://devenv.sh/getting-started/)
- **direnv (optional):** [Install from direnv.net](https://direnv.net/) - For automatic environment activation
- **Nix:** Installed automatically with devenv

### Installation

```bash
# Clone the repository
git clone https://github.com/gsmlg-dev/secrethub.git
cd secrethub

# If using direnv (recommended)
direnv allow

# Or activate devenv manually
devenv shell

# Set up the database
db-setup

# Start the development server
server
```

The application will be available at:
- **Web UI:** http://localhost:4000
- **API:** http://localhost:4000/api/v1
- **Metrics:** http://localhost:9090 (Prometheus)

### Development Services

devenv automatically manages:
- **PostgreSQL 16** via Unix domain socket (no TCP port exposed for security)
  - Database: `secrethub_dev`
  - User: `secrethub`
  - Password: `secrethub_dev_password`
- **Prometheus** on `localhost:9090`

### Quick Commands

```bash
# Database
db-setup        # Create and migrate database
db-reset        # Reset database (drop, create, migrate, seed)
db-migrate      # Run pending migrations

# Assets (Frontend - uses Elixir's esbuild/tailwind, no Node.js required)
mix assets.setup   # Install esbuild and tailwind binaries
mix assets.deploy  # Build minified assets for production

# Development
server          # Start Phoenix server
console         # Start IEx shell with app loaded

# Testing
test-all        # Run all tests
test-watch      # Run tests in watch mode

# Code Quality
format          # Format code
lint            # Run Credo linter
quality         # Run all quality checks (format, lint, dialyzer)

# Utilities
gen-secret      # Generate a secret key for Phoenix
```

---

## 📁 Project Structure

```
secrethub/                          # Umbrella root
├── apps/
│   ├── secrethub_core/            # Core service (backend logic)
│   │   ├── lib/
│   │   │   └── secrethub_core/
│   │   │       ├── auth/          # Authentication backends
│   │   │       ├── engines/       # Secret engines
│   │   │       ├── pki/           # PKI & certificate management
│   │   │       ├── policies/      # Policy engine
│   │   │       ├── audit/         # Audit logging
│   │   │       └── crypto/        # Encryption & unsealing
│   │   ├── priv/repo/migrations/  # Database migrations
│   │   └── test/
│   │
│   ├── secrethub_web/             # Web UI & API endpoints
│   │   ├── lib/
│   │   │   └── secrethub_web/
│   │   │       ├── controllers/   # REST API
│   │   │       ├── live/          # LiveView components
│   │   │       └── channels/      # WebSocket for agents
│   │   ├── assets/                # Frontend assets
│   │   └── test/
│   │
│   ├── secrethub_agent/           # Agent service
│   │   ├── lib/
│   │   │   └── secrethub_agent/
│   │   │       ├── bootstrap.ex   # Bootstrap & authentication
│   │   │       ├── connection.ex  # WebSocket client
│   │   │       ├── cache.ex       # Local caching
│   │   │       ├── template.ex    # Template rendering
│   │   │       └── sinker.ex      # File writer
│   │   └── test/
│   │
│   └── secrethub_shared/          # Shared code
│       ├── lib/
│       │   └── secrethub_shared/
│       │       ├── schemas/       # Ecto schemas
│       │       └── protocols/     # Communication protocols
│       └── test/
│
├── config/                        # Configuration files
├── docs/                          # Documentation
├── infrastructure/                # Infrastructure as Code
│   ├── docker/                    # Docker configs
│   ├── terraform/                 # Terraform modules
│   └── kubernetes/                # K8s manifests
├── docker-compose.yml             # Development environment
└── mix.exs                        # Umbrella configuration
```

---

## 🛠️ Development

### Running Tests

```bash
# Run all tests
mix test

# Run tests for specific app
cd apps/secrethub_core && mix test

# Run tests with coverage
mix coveralls.html

# Watch mode (auto-run on file changes)
mix test.watch
```

### Code Quality

```bash
# Format code
mix format

# Run linter
mix credo --strict

# Run static analysis
mix dialyzer

# Run all quality checks
mix quality
```

### Database Management

```bash
# Create database
mix ecto.create

# Run migrations
mix ecto.migrate

# Rollback migration
mix ecto.rollback

# Reset database (drop, create, migrate, seed)
mix ecto.reset

# Generate new migration
cd apps/secrethub_core
mix ecto.gen.migration create_secrets_table
```

---

## 🔧 Configuration

### Environment Variables

Development environment variables are automatically set by devenv. For production:

```bash
# Core service
export DATABASE_URL="postgresql://user:password@host/secrethub_prod"
export SECRET_KEY_BASE="generate-with-mix-phx.gen.secret"

# Agent
export SECRETHUB_CORE_URL="wss://core.example.com:4000"
export SECRETHUB_AGENT_ID="agent-prod-01"
```

---

## 📚 Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [API Reference](docs/api/README.md)
- [Deployment Guide](docs/deployment/README.md)
- [Security Model](docs/security/README.md)

---

## 🧪 Development Status

### Completed Features

- [x] Umbrella project structure
- [x] Database schemas and migrations
- [x] AppRole authentication backend
- [x] PKI engine with CA management
- [x] Agent bootstrap and WebSocket connection
- [x] Static and dynamic secret engines
- [x] Policy engine for authorization
- [x] Audit logging with hash chains
- [x] Template rendering for config files
- [x] CLI tool for management
- [x] CI/CD with GitHub Actions
- [x] Docker images (multi-arch)

---

## 👥 Team

**Development Team:**
- **Lead Developer:** [Your Name] - Architecture & Integration
- **AI Assistant 1:** Claude - Architecture, Security, Documentation
- **AI Assistant 2:** Kimi K2 - Core Backend, Database
- **AI Assistant 3:** GLM-4.6 - Agent, OTP, GenServers

---

## 📝 Contributing

### Commit Message Convention

```
type(scope): subject

body

footer
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

**Example:**
```
feat(core): implement AppRole authentication backend

- Add RoleID/SecretID generation
- Implement token validation
- Add integration tests

Closes #123
```

---

## 📄 License

[Your License Here]

---

## 🗺️ Roadmap

### Phase 1: MVP (Weeks 1-12) ✅ Complete
- Basic authentication & storage
- PKI engine
- Static secrets
- Basic audit logging

### Phase 2: Production (Weeks 13-24) ✅ Complete
- Dynamic secrets (PostgreSQL, Redis, AWS)
- Template rendering
- High availability
- Secret rotation

### Phase 3: Advanced (Weeks 25-28) ✅ Complete
- Secret versioning
- Advanced policies
- CLI tool

### Phase 4: Launch (Weeks 29-32) 🚀 Current
- Security audit
- Performance testing
- Documentation
- Production deployment (v1.0.0-rc2 released)

---

## 🆘 Getting Help

- **Documentation:** Check `docs/` folder
- **Issues:** Open an issue on GitHub
- **Discussions:** Use GitHub Discussions

---

**Latest Release:** [v1.0.0-rc2](https://github.com/gsmlg-dev/secrethub/releases/tag/v1.0.0-rc2) 🎉

