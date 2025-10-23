# SecretHub MVP Deployment Guide

**Version:** 1.0
**Last Updated:** 2025-10-23
**Status:** MVP (Weeks 1-11 Complete)

This guide covers deploying the SecretHub MVP for evaluation and testing purposes. For production deployment, refer to the Production Deployment Guide (available after Phase 2 completion).

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture-overview)
3. [Deployment Options](#deployment-options)
4. [Quick Start (Docker Compose)](#quick-start-docker-compose)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Initial Configuration](#initial-configuration)
7. [Agent Deployment](#agent-deployment)
8. [Verification](#verification)
9. [Troubleshooting](#troubleshooting)
10. [Security Considerations](#security-considerations)

---

## Prerequisites

### Infrastructure Requirements

**SecretHub Core:**
- 2 CPU cores minimum (4 recommended)
- 4 GB RAM minimum (8 GB recommended)
- 20 GB disk space
- PostgreSQL 16+ (external or containerized)
- Redis 7+ (optional, for caching)

**SecretHub Agent:**
- 0.5 CPU cores per agent
- 512 MB RAM per agent
- 1 GB disk space per agent

### Software Requirements

- Docker 24+ and Docker Compose 2.20+ (for containerized deployment)
- Kubernetes 1.28+ (for K8s deployment)
- PostgreSQL 16+
- Elixir 1.18+ and Erlang/OTP 27+ (for source deployment)

### Network Requirements

- Core requires inbound access on port 4000 (HTTP) or 4001 (HTTPS with mTLS)
- PostgreSQL access from Core (default port 5432)
- Agents need outbound access to Core
- Admin UI access via web browser to Core port 4000

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         Admin Users                         │
│                    (Web UI via HTTPS)                       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    SecretHub Core                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Phoenix Web  │  │ PKI Engine   │  │ Policy Engine│     │
│  │   (LiveView) │  │              │  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Vault/Crypto │  │ Audit Logs   │  │ AppRole Auth │     │
│  │              │  │ (Hash Chain) │  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   PostgreSQL 16      │
              │  (Secrets, Policies, │
              │   Audit Logs, PKI)   │
              └──────────────────────┘
                         ▲
                         │
         ┌───────────────┴───────────────┐
         │                               │
         ▼                               ▼
┌─────────────────┐           ┌─────────────────┐
│ SecretHub Agent │           │ SecretHub Agent │
│  (App Server 1) │           │  (App Server 2) │
│  ┌───────────┐  │           │  ┌───────────┐  │
│  │ WS Client │  │           │  │ WS Client │  │
│  │ + mTLS    │  │           │  │ + mTLS    │  │
│  └───────────┘  │           │  └───────────┘  │
│  ┌───────────┐  │           │  ┌───────────┐  │
│  │   Cache   │  │           │  │   Cache   │  │
│  └───────────┘  │           │  └───────────┘  │
└─────────────────┘           └─────────────────┘
         │                               │
         ▼                               ▼
┌─────────────────┐           ┌─────────────────┐
│ Application 1   │           │ Application 2   │
│ (reads secrets  │           │ (reads secrets  │
│  via Unix sock) │           │  via Unix sock) │
└─────────────────┘           └─────────────────┘
```

---

## Deployment Options

### Option 1: Docker Compose (Recommended for MVP/Testing)

**Pros:**
- Fastest setup (5-10 minutes)
- All-in-one configuration
- Easy to teardown and restart

**Cons:**
- Not suitable for production
- Single-node only
- No high availability

### Option 2: Kubernetes

**Pros:**
- Production-ready architecture
- High availability
- Scalable

**Cons:**
- More complex setup
- Requires K8s cluster
- Longer deployment time

### Option 3: Source Deployment

**Pros:**
- Full control over configuration
- Easy debugging
- Best for development

**Cons:**
- Requires Elixir/Erlang installation
- Manual dependency management
- More complex updates

---

## Quick Start (Docker Compose)

### Step 1: Clone Repository

```bash
git clone https://github.com/your-org/secrethub.git
cd secrethub
```

### Step 2: Configure Environment

Create `.env` file:

```bash
# Database Configuration
DATABASE_URL=postgresql://secrethub:secrethub_password@postgres:5432/secrethub_prod
SECRET_KEY_BASE=$(openssl rand -base64 48)

# Core Configuration
PHX_HOST=localhost
PHX_PORT=4000

# Security (generate with: openssl rand -hex 32)
ENCRYPTION_KEY=$(openssl rand -hex 32)
AUDIT_HMAC_KEY=$(openssl rand -hex 32)

# Optional: Redis for caching
REDIS_URL=redis://redis:6379
```

### Step 3: Start Services

```bash
docker-compose up -d
```

This starts:
- SecretHub Core (port 4000)
- PostgreSQL 16
- Redis (optional)

### Step 4: Run Database Migrations

```bash
docker-compose exec secrethub_core bin/secrethub_core eval "SecretHub.Core.Release.migrate"
```

### Step 5: Initialize Vault

Open browser to `http://localhost:4000/vault/init`

1. Configure Shamir Secret Sharing:
   - Total shares: 5
   - Threshold: 3
2. **CRITICAL:** Save all 5 unseal keys securely
3. Save root token

### Step 6: Unseal Vault

Navigate to `http://localhost:4000/vault/unseal`

1. Enter any 3 of the 5 unseal keys
2. Vault will transition to "unsealed" state
3. You can now access the admin UI

### Step 7: Access Admin UI

1. Navigate to `http://localhost:4000/admin/auth/login`
2. For MVP: Use development bypass (if enabled)
3. For production: Upload admin client certificate

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (1.28+)
- `kubectl` configured
- Helm 3+ (optional)

### Step 1: Create Namespace

```bash
kubectl create namespace secrethub
```

### Step 2: Create Secrets

```bash
# Generate encryption keys
ENCRYPTION_KEY=$(openssl rand -hex 32)
AUDIT_HMAC_KEY=$(openssl rand -hex 32)
SECRET_KEY_BASE=$(openssl rand -base64 48)

# Create Kubernetes secret
kubectl create secret generic secrethub-secrets \
  --namespace=secrethub \
  --from-literal=encryption-key=$ENCRYPTION_KEY \
  --from-literal=audit-hmac-key=$AUDIT_HMAC_KEY \
  --from-literal=secret-key-base=$SECRET_KEY_BASE \
  --from-literal=database-url="postgresql://secrethub:password@postgres:5432/secrethub_prod"
```

### Step 3: Deploy PostgreSQL

```bash
kubectl apply -f infrastructure/kubernetes/postgres-statefulset.yaml -n secrethub
```

Wait for PostgreSQL to be ready:

```bash
kubectl wait --for=condition=ready pod -l app=postgres -n secrethub --timeout=120s
```

### Step 4: Deploy SecretHub Core

```bash
kubectl apply -f infrastructure/kubernetes/secrethub-core-deployment.yaml -n secrethub
kubectl apply -f infrastructure/kubernetes/secrethub-core-service.yaml -n secrethub
```

### Step 5: Expose Service

**For development (NodePort):**

```bash
kubectl apply -f infrastructure/kubernetes/secrethub-nodeport.yaml -n secrethub
```

**For production (Ingress with TLS):**

```bash
kubectl apply -f infrastructure/kubernetes/secrethub-ingress.yaml -n secrethub
```

### Step 6: Run Migrations

```bash
POD=$(kubectl get pod -n secrethub -l app=secrethub-core -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n secrethub $POD -- bin/secrethub_core eval "SecretHub.Core.Release.migrate"
```

### Step 7: Initialize Vault

Access the Core service and follow the vault initialization steps from the Quick Start section.

---

## Initial Configuration

### 1. Generate Root CA

After unsealing the vault:

1. Navigate to `/admin/pki`
2. Click "Generate Root CA"
3. Fill in:
   - Common Name: `SecretHub Root CA`
   - Organization: `Your Organization`
   - Country: `US`
   - Key Algorithm: `RSA-4096` (recommended) or `ECDSA P-384`
   - Validity: `3650` days (10 years)
4. Click "Generate"
5. **Save the Root CA certificate** for distribution

### 2. Generate Intermediate CA

1. Click "Generate Intermediate CA"
2. Fill in:
   - Common Name: `SecretHub Intermediate CA`
   - Organization: `Your Organization`
   - Country: `US`
   - Root CA: Select the Root CA created above
   - Validity: `1825` days (5 years)
3. Click "Generate"

### 3. Create First AppRole

1. Navigate to `/admin/approles`
2. Click "Create AppRole"
3. Fill in:
   - Role Name: `production-app`
   - Policies: Select relevant policies (create if needed)
4. Click "Create"
5. **CRITICAL:** Save the RoleID and SecretID immediately
   - These will only be displayed once
   - Store them securely

### 4. Create Policies

1. Navigate to `/admin/policies`
2. Click "Create Policy"
3. Example policy for production database secrets:

```json
{
  "version": "1.0",
  "allowed_secrets": ["prod.db.*"],
  "allowed_operations": ["read"],
  "conditions": {
    "time_of_day": "00:00-23:59",
    "max_ttl": "3600"
  }
}
```

4. Bind policy to entities (agents/apps)

### 5. Create Secrets

1. Navigate to `/admin/secrets`
2. Click "Create Secret"
3. Fill in:
   - Path: `prod.db.postgres.password` (reverse domain notation)
   - Type: Static
   - Value: (enter secret value)
   - TTL: 3600 seconds (1 hour)
4. Bind policies for access control

---

## Agent Deployment

### Method 1: Docker

```bash
# Create agent configuration
cat > agent-config.yaml <<EOF
core:
  url: "wss://secrethub-core.example.com:4001"
  ca_cert_path: "/etc/secrethub/ca-chain.pem"

auth:
  role_id: "your-role-id-from-step-3"
  secret_id: "your-secret-id-from-step-3"

cache:
  ttl: 300
  max_size: 1000
  fallback_enabled: true

secrets:
  - path: "prod.db.postgres.password"
    dest: "/var/secrets/db_password"
    template: "{{ .Value }}"
EOF

# Run agent
docker run -d \
  --name secrethub-agent \
  --network host \
  -v $(pwd)/agent-config.yaml:/etc/secrethub/config.yaml:ro \
  -v /var/run/secrethub:/var/run/secrethub \
  secrethub/agent:latest
```

### Method 2: Kubernetes DaemonSet

```bash
# Create ConfigMap with agent configuration
kubectl create configmap agent-config \
  --from-file=config.yaml=agent-config.yaml \
  -n secrethub

# Deploy agent
kubectl apply -f infrastructure/kubernetes/agent-daemonset.yaml -n secrethub
```

### Method 3: Systemd Service

See [Agent Deployment Guide](./agent-deployment-guide.md) for detailed systemd setup.

---

## Verification

### 1. Verify Core Health

```bash
curl http://localhost:4000/v1/sys/health
```

Expected response:

```json
{
  "initialized": true,
  "sealed": false,
  "standby": false,
  "performance_standby": false,
  "replication_performance_mode": "disabled",
  "replication_dr_mode": "disabled",
  "server_time_utc": "2025-10-23T10:00:00Z",
  "version": "0.1.0",
  "cluster_name": "secrethub-primary",
  "cluster_id": "..."
}
```

### 2. Verify Database Connection

```bash
docker-compose exec secrethub_core bin/secrethub_core rpc "SecretHub.Core.Repo.query!(\"SELECT 1\")"
```

### 3. Verify Agent Connection

Check agent logs:

```bash
docker logs secrethub-agent
```

Look for:
```
[info] Agent bootstrap successful
[info] Connected to SecretHub Core
[info] Certificate obtained, switching to mTLS
[info] Heartbeat established
```

Check Core UI:
1. Navigate to `/admin/agents`
2. Verify agent appears in "Connected Agents" list
3. Status should show "Connected" with green indicator

### 4. Test Secret Retrieval

On agent host:

```bash
# If agent configured Unix socket
cat /var/run/secrethub/secrets/db_password

# Should output the secret value
```

### 5. Verify Audit Logging

1. Navigate to `/admin/audit`
2. Verify events are being logged:
   - Vault initialization
   - Unseal operations
   - Agent connections
   - Secret accesses
3. Test CSV export functionality

---

## Troubleshooting

### Core Won't Start

**Symptom:** Container exits immediately

**Check:**
```bash
docker-compose logs secrethub_core
```

**Common causes:**
1. Database connection failure
   - Verify DATABASE_URL
   - Check PostgreSQL is running: `docker-compose ps postgres`
   - Test connection: `docker-compose exec postgres psql -U secrethub`

2. Missing SECRET_KEY_BASE
   - Generate: `openssl rand -base64 48`
   - Add to `.env` file

3. Port already in use
   - Check: `netstat -tulpn | grep 4000`
   - Change PHX_PORT in `.env`

### Vault Remains Sealed

**Symptom:** "Vault is sealed" error when accessing UI

**Solution:**
1. Navigate to `/vault/unseal`
2. Enter 3 of 5 unseal keys
3. If keys are lost, vault must be re-initialized (all data will be lost)

### Agent Can't Connect

**Symptom:** Agent logs show connection errors

**Check:**
1. Core URL is accessible from agent
   ```bash
   curl http://secrethub-core:4000/v1/sys/health
   ```

2. AppRole credentials are valid
   - Verify RoleID and SecretID in agent config
   - Check role exists in `/admin/approles`

3. Network connectivity
   - Check firewall rules
   - Verify DNS resolution

4. Certificate issues (if using mTLS)
   - Verify CA chain is correct
   - Check certificate hasn't expired

### Secret Access Denied

**Symptom:** Agent receives 403 when requesting secret

**Check:**
1. Policy exists and is bound to agent
   - Navigate to `/admin/policies`
   - Verify policy allows the secret path
   - Check entity bindings

2. Secret path matches policy pattern
   - Policy: `prod.db.*`
   - Secret: `prod.db.postgres.password` ✓
   - Secret: `staging.db.password` ✗

3. Audit logs for denial reason
   - Navigate to `/admin/audit`
   - Filter by agent ID
   - Check `access_granted: false` events

### Database Migration Failures

**Symptom:** Core fails with "relation does not exist"

**Solution:**
```bash
# Drop and recreate (WARNING: destroys all data)
docker-compose exec postgres psql -U secrethub -c "DROP DATABASE secrethub_prod;"
docker-compose exec postgres psql -U secrethub -c "CREATE DATABASE secrethub_prod;"

# Run migrations
docker-compose exec secrethub_core bin/secrethub_core eval "SecretHub.Core.Release.migrate"
```

### Performance Issues

**Symptom:** Slow response times, high CPU/memory

**Check:**
1. Database performance
   ```sql
   -- Check slow queries
   SELECT query, calls, total_time, mean_time
   FROM pg_stat_statements
   ORDER BY mean_time DESC
   LIMIT 10;
   ```

2. Agent cache hit rate
   - Check agent logs for cache statistics
   - Adjust cache TTL if too low

3. Audit log partition size
   - Large audit tables can slow queries
   - Consider archiving old logs

---

## Security Considerations

### MVP Limitations

⚠️ **This MVP deployment has the following limitations:**

1. **Single-node deployment** - No high availability
2. **Self-signed certificates** - Not suitable for public internet
3. **Basic authentication** - Certificate-based admin auth is optional
4. **No automated backups** - Manual backup procedures required
5. **Limited monitoring** - Basic health checks only

### Recommended Security Practices

1. **Store unseal keys securely**
   - Use separate secure locations for each key share
   - Never store all keys together
   - Consider hardware security modules (HSMs) for production

2. **Rotate secrets regularly**
   - Set appropriate TTLs on secrets
   - Use dynamic secrets where possible (Phase 2 feature)

3. **Monitor audit logs**
   - Review access denied events daily
   - Set up alerts for suspicious patterns
   - Export logs to SIEM system

4. **Use TLS everywhere**
   - Enable mTLS for agent connections
   - Use valid certificates (not self-signed) in production
   - Enforce TLS 1.3

5. **Principle of least privilege**
   - Create narrow policies for each use case
   - Bind policies to specific entities
   - Review and audit policy assignments regularly

6. **Backup procedures**
   - Backup PostgreSQL database daily
   - Store backups encrypted
   - Test restore procedures monthly

---

## Next Steps

### For Production Deployment

1. **Complete Phase 2** (Weeks 13-24)
   - Dynamic secret engines
   - High availability setup
   - Automated secret rotation
   - Comprehensive monitoring

2. **Security Hardening**
   - External PKI integration
   - HSM integration for key storage
   - Network segmentation
   - Intrusion detection

3. **Operational Readiness**
   - Disaster recovery procedures
   - Runbooks for common issues
   - On-call rotation setup
   - Incident response plan

### Support and Documentation

- **Agent Deployment Guide:** [agent-deployment-guide.md](./agent-deployment-guide.md)
- **API Documentation:** `/docs/api/`
- **Architecture Documentation:** [DESIGN.md](../../DESIGN.md)
- **Issue Tracker:** GitHub Issues

---

## Appendix: Docker Compose Configuration

Full `docker-compose.yml` example:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: secrethub
      POSTGRES_PASSWORD: secrethub_password
      POSTGRES_DB: secrethub_prod
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U secrethub"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 3

  secrethub_core:
    image: secrethub/core:latest
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql://secrethub:secrethub_password@postgres:5432/secrethub_prod
      SECRET_KEY_BASE: ${SECRET_KEY_BASE}
      PHX_HOST: ${PHX_HOST:-localhost}
      PHX_PORT: ${PHX_PORT:-4000}
      ENCRYPTION_KEY: ${ENCRYPTION_KEY}
      AUDIT_HMAC_KEY: ${AUDIT_HMAC_KEY}
      REDIS_URL: redis://redis:6379
    ports:
      - "4000:4000"
    volumes:
      - secrethub_data:/app/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:4000/v1/sys/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

volumes:
  postgres_data:
  redis_data:
  secrethub_data:
```

---

**End of MVP Deployment Guide**
