# Production Deployment Runbook

This runbook provides step-by-step instructions for deploying SecretHub to production environments.

---

## Pre-Deployment Checklist

### Infrastructure Requirements

- [ ] **Compute:** 3x VM instances (4 cores, 8 GB RAM each) for Core
- [ ] **Database:** PostgreSQL 16 (RDS Multi-AZ or equivalent)
- [ ] **Load Balancer:** ALB/NLB with SSL termination
- [ ] **Network:** VPC with private subnets, security groups configured
- [ ] **DNS:** Domain name configured (e.g., secrethub.company.com)
- [ ] **SSL Certificate:** Valid SSL certificate for HTTPS
- [ ] **Monitoring:** Prometheus + Grafana deployed
- [ ] **Logging:** Centralized logging (CloudWatch, ELK, etc.)
- [ ] **Backup:** Database backup strategy in place

### Security Requirements

- [ ] **Unseal Keys:** Secure storage prepared (HSM, vault, key management service)
- [ ] **Admin Credentials:** Bcrypt hashed password generated
- [ ] **Database Credentials:** Strong passwords generated
- [ ] **SSL Certificates:** Valid certificates for Core and Agent
- [ ] **Firewall Rules:** Security groups/firewall rules configured
- [ ] **Audit Compliance:** Audit log retention policy defined

### Environment Variables Prepared

```bash
# Core Application
SECRET_KEY_BASE=<generate with: mix phx.gen.secret>
DATABASE_URL=postgresql://secrethub:PASSWORD@db.internal:5432/secrethub_prod
PHX_HOST=secrethub.company.com
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=<bcrypt hash>

# Database Pool
DB_POOL_SIZE=40

# Optional: Auto-unseal
AWS_KMS_KEY_ID=<kms-key-id>
AUTO_UNSEAL_ENABLED=true
```

---

## Deployment Steps

### Phase 1: Database Setup

#### 1.1 Create Database

```bash
# Connect to PostgreSQL instance
psql -h db.internal -U postgres

# Create database and user
CREATE DATABASE secrethub_prod;
CREATE USER secrethub WITH ENCRYPTED PASSWORD 'STRONG_PASSWORD_HERE';
GRANT ALL PRIVILEGES ON DATABASE secrethub_prod TO secrethub;

# Connect to database
\c secrethub_prod

# Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

# Create audit schema
CREATE SCHEMA audit;
GRANT ALL ON SCHEMA audit TO secrethub;
```

#### 1.2 Run Migrations

```bash
# From application directory
cd /opt/secrethub
export MIX_ENV=prod
export DATABASE_URL=postgresql://secrethub:PASSWORD@db.internal:5432/secrethub_prod

# Run migrations
mix ecto.migrate
```

**Expected Output:**
```
[info] == Running SecretHub.Core.Repo.Migrations.CreateSecrets.change/0 forward
[info] create table secrets
[info] create index secrets_path_index
[info] == Migrated in 0.1s
...
```

#### 1.3 Verify Database

```bash
# Check tables created
psql $DATABASE_URL -c "\dt"

# Should show:
# secrets, secret_versions, policies, approle_tokens, certificates, leases, etc.

# Check audit schema
psql $DATABASE_URL -c "\dt audit.*"

# Should show:
# audit.events, audit.hash_chain
```

---

### Phase 2: Core Deployment

#### 2.1 Build Release

```bash
# Build production release
MIX_ENV=prod mix release secrethub_core

# Release will be in _build/prod/rel/secrethub_core/
```

#### 2.2 Deploy to Servers

Deploy to all 3 Core instances:

```bash
# Copy release to servers
scp -r _build/prod/rel/secrethub_core/ user@core-1:/opt/secrethub/
scp -r _build/prod/rel/secrethub_core/ user@core-2:/opt/secrethub/
scp -r _build/prod/rel/secrethub_core/ user@core-3:/opt/secrethub/
```

#### 2.3 Configure Environment

On each Core instance, create `/opt/secrethub/secrethub.env`:

```bash
# Application
SECRET_KEY_BASE=<generated-secret>
PHX_SERVER=true
PHX_HOST=secrethub.company.com
PORT=4000

# Database
DATABASE_URL=postgresql://secrethub:PASSWORD@db.internal:5432/secrethub_prod
DB_POOL_SIZE=40

# Security
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=$2b$12$... # bcrypt hash

# Auto-unseal (optional)
AUTO_UNSEAL_ENABLED=true
AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789:key/abc-123

# Monitoring
PROMETHEUS_ENABLED=true
```

#### 2.4 Create Systemd Service

Create `/etc/systemd/system/secrethub-core.service` on each Core instance:

```ini
[Unit]
Description=SecretHub Core
After=network.target

[Service]
Type=simple
User=secrethub
Group=secrethub
WorkingDirectory=/opt/secrethub
EnvironmentFile=/opt/secrethub/secrethub.env
ExecStart=/opt/secrethub/secrethub_core/bin/secrethub_core start
ExecStop=/opt/secrethub/secrethub_core/bin/secrethub_core stop
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=secrethub-core

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/secrethub/data

[Install]
WantedBy=multi-user.target
```

#### 2.5 Start Services

```bash
# On each Core instance
sudo systemctl daemon-reload
sudo systemctl enable secrethub-core
sudo systemctl start secrethub-core

# Check status
sudo systemctl status secrethub-core
sudo journalctl -u secrethub-core -f
```

**Expected Log Output:**
```
[info] SecretHub.Core.Application started
[info] Running SecretHub.WebWeb.Endpoint with Bandit on http://0.0.0.0:4000
```

---

### Phase 3: Load Balancer Setup

#### 3.1 Configure Health Checks

```yaml
Health Check Configuration:
  Protocol: HTTP
  Port: 4000
  Path: /v1/sys/health
  Interval: 10 seconds
  Timeout: 5 seconds
  Healthy Threshold: 2
  Unhealthy Threshold: 3
```

#### 3.2 Configure Target Group

```
Target Group:
  Protocol: HTTP
  Port: 4000
  Health Check: /v1/sys/health

  Targets:
    - core-1:4000
    - core-2:4000
    - core-3:4000
```

#### 3.3 Configure SSL/TLS

```
Listener:
  Protocol: HTTPS
  Port: 443
  Certificate: arn:aws:acm:us-east-1:123456789:certificate/abc-123

  Default Action:
    Type: forward
    Target Group: secrethub-core-tg
```

#### 3.4 Verify Load Balancer

```bash
# Test health check
curl https://secrethub.company.com/v1/sys/health

# Expected response:
{"initialized": false, "sealed": true, "standby": false}
```

---

### Phase 4: Initialize and Unseal Vault

#### 4.1 Initialize Vault

**⚠️ CRITICAL: This step generates unseal keys. Store them securely!**

```bash
# Initialize vault (do this ONCE from any Core instance)
curl -X POST https://secrethub.company.com/v1/sys/init \
  -H "Content-Type: application/json" \
  -d '{
    "secret_shares": 5,
    "secret_threshold": 3
  }'
```

**Response:**
```json
{
  "keys": [
    "key1-abc...",
    "key2-def...",
    "key3-ghi...",
    "key4-jkl...",
    "key5-mno..."
  ],
  "keys_base64": ["..."],
  "root_token": "s.XXXXXXXXXXX"
}
```

**⚠️ IMMEDIATELY:**
1. Save unseal keys to secure storage (HSM, KMS, password manager)
2. Distribute keys to 5 different key custodians
3. Save root token securely
4. **NEVER store unseal keys in plain text**

#### 4.2 Unseal All Core Instances

Unseal each Core instance separately:

```bash
# Unseal core-1 (requires 3 of 5 keys)
curl -X POST https://core-1.internal:4000/v1/sys/unseal \
  -d '{"key": "key1..."}'

curl -X POST https://core-1.internal:4000/v1/sys/unseal \
  -d '{"key": "key2..."}'

curl -X POST https://core-1.internal:4000/v1/sys/unseal \
  -d '{"key": "key3..."}'

# Repeat for core-2 and core-3
```

**Verify Unsealed:**
```bash
curl https://secrethub.company.com/v1/sys/seal-status

# Expected:
{
  "sealed": false,
  "t": 3,
  "n": 5,
  "progress": 0
}
```

#### 4.3 Setup Auto-Unseal (Optional but Recommended)

If using AWS KMS:

```bash
# Configure KMS key permissions
# Allow Core instances to use KMS key for encrypt/decrypt

# Set environment variable on all Core instances
AUTO_UNSEAL_ENABLED=true
AWS_KMS_KEY_ID=arn:aws:kms:...

# Restart services
sudo systemctl restart secrethub-core

# Vault will auto-unseal on startup using KMS
```

---

### Phase 5: Initial Configuration

#### 5.1 Create Admin AppRole

```bash
# Create admin AppRole
curl -X POST https://secrethub.company.com/v1/auth/approle/role/admin \
  -H "X-Vault-Token: s.XXXXXXXXXXX" \
  -d '{
    "role_name": "admin",
    "policies": ["admin"],
    "token_ttl": 86400
  }'

# Get RoleID
curl https://secrethub.company.com/v1/auth/approle/role/admin/role-id \
  -H "X-Vault-Token: s.XXXXXXXXXXX"

# Generate SecretID
curl -X POST https://secrethub.company.com/v1/auth/approle/role/admin/secret-id \
  -H "X-Vault-Token: s.XXXXXXXXXXX"
```

#### 5.2 Create Default Policies

```bash
# Read-only policy
curl -X POST https://secrethub.company.com/v1/policies \
  -H "X-Vault-Token: s.XXXXXXXXXXX" \
  -d '{
    "name": "read-only",
    "rules": [
      {
        "path": "*",
        "capabilities": ["read"],
        "effect": "allow"
      }
    ]
  }'

# Production policy
curl -X POST https://secrethub.company.com/v1/policies \
  -H "X-Vault-Token: s.XXXXXXXXXXX" \
  -d '{
    "name": "production",
    "rules": [
      {
        "path": "prod/*",
        "capabilities": ["read"],
        "effect": "allow",
        "conditions": {
          "time_of_day": [0, 23],
          "source_ip": "10.0.0.0/8"
        }
      }
    ]
  }'
```

#### 5.3 Configure PKI Engine

```bash
# Generate root CA
curl -X POST https://secrethub.company.com/v1/pki/ca/root/generate \
  -H "X-Vault-Token: s.XXXXXXXXXXX" \
  -d '{
    "common_name": "SecretHub Root CA",
    "ttl": "87600h",
    "key_type": "rsa",
    "key_bits": 4096
  }'

# Generate intermediate CA
curl -X POST https://secrethub.company.com/v1/pki/ca/intermediate/generate \
  -H "X-Vault-Token: s.XXXXXXXXXXX" \
  -d '{
    "common_name": "SecretHub Intermediate CA",
    "ttl": "43800h"
  }'
```

---

### Phase 6: Monitoring Setup

#### 6.1 Configure Prometheus

Add to Prometheus `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'secrethub-core'
    static_configs:
      - targets:
        - core-1:4000
        - core-2:4000
        - core-3:4000
    metrics_path: '/metrics'
    scrape_interval: 15s
```

#### 6.2 Import Grafana Dashboards

```bash
# Import SecretHub dashboard
curl -X POST http://grafana:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @grafana-dashboard.json
```

#### 6.3 Configure Alerts

Create Prometheus alert rules:

```yaml
groups:
  - name: secrethub
    rules:
      - alert: SecretHubCoreDown
        expr: up{job="secrethub-core"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "SecretHub Core {{ $labels.instance }} is down"

      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(secrethub_request_duration_ms_bucket[5m])) > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High latency detected (P95 > 100ms)"

      - alert: DatabasePoolExhausted
        expr: secrethub_db_pool_utilization > 90
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Database connection pool nearly exhausted"
```

---

### Phase 7: Agent Deployment

#### 7.1 Create AppRole for Agents

```bash
# Create agent AppRole
curl -X POST https://secrethub.company.com/v1/auth/approle/role/agents \
  -H "X-Vault-Token: s.XXXXXXXXXXX" \
  -d '{
    "role_name": "agents",
    "policies": ["agent-policy"],
    "token_ttl": 3600
  }'
```

#### 7.2 Deploy Agent

On application hosts:

```bash
# Install agent
curl -L https://releases.secrethub.io/agent/latest/secrethub-agent-linux-amd64 \
  -o /usr/local/bin/secrethub-agent
chmod +x /usr/local/bin/secrethub-agent

# Configure agent
cat > /etc/secrethub/agent.toml <<EOF
[agent]
id = "agent-prod-01"
core_url = "wss://secrethub.company.com"

[auth]
role_id = "<role-id>"
secret_id = "<secret-id>"

[cache]
enabled = true
ttl = 300

[templates]
enabled = true
directory = "/etc/secrethub/templates"
EOF

# Start agent
secrethub-agent start
```

---

### Phase 8: Verification

#### 8.1 Verify Core Health

```bash
# Check all Core instances
for host in core-1 core-2 core-3; do
  echo "Checking $host..."
  curl -s https://$host.internal:4000/v1/sys/health | jq
done

# Expected: All should show unsealed
```

#### 8.2 Verify Load Balancer

```bash
# Test load balancing
for i in {1..10}; do
  curl -s https://secrethub.company.com/v1/sys/health | jq '.hostname'
done

# Should see requests distributed across all 3 Core instances
```

#### 8.3 Verify Agent Connectivity

```bash
# Check agent status
secrethub-agent status

# Expected:
Connected: true
Core: secrethub.company.com
Last Heartbeat: 2s ago
```

#### 8.4 Test Secret Operations

```bash
# Create secret
curl -X POST https://secrethub.company.com/v1/secrets/static/test/hello \
  -H "X-Vault-Token: s.XXXXXXXXXXX" \
  -d '{"data": {"message": "Hello Production!"}}'

# Read secret
curl https://secrethub.company.com/v1/secrets/static/test/hello \
  -H "X-Vault-Token: s.XXXXXXXXXXX"

# Delete secret
curl -X DELETE https://secrethub.company.com/v1/secrets/static/test/hello \
  -H "X-Vault-Token: s.XXXXXXXXXXX"
```

---

## Post-Deployment

### Backup Procedures

#### Database Backup

```bash
# Daily automated backup
pg_dump $DATABASE_URL > backup-$(date +%Y%m%d).sql
aws s3 cp backup-*.sql s3://secrethub-backups/

# Point-in-time recovery enabled (RDS)
```

#### Unseal Keys Backup

- Store in multiple secure locations
- Consider key management service (AWS KMS, HashiCorp Vault)
- Document key custodians and emergency procedures

### Monitoring Checklist

- [ ] Prometheus scraping all Core instances
- [ ] Grafana dashboards imported and working
- [ ] Alerts configured and tested
- [ ] Log aggregation collecting Core logs
- [ ] Database metrics monitored
- [ ] SSL certificate expiration monitoring

### Security Hardening

- [ ] Firewall rules restrict access to Core (only from load balancer)
- [ ] Database only accessible from Core instances
- [ ] SSH access restricted with key-based auth
- [ ] Audit logs forwarded to SIEM
- [ ] Regular security scans scheduled
- [ ] Incident response procedures documented

---

## Rollback Procedure

If deployment fails:

```bash
# 1. Stop new Core instances
sudo systemctl stop secrethub-core

# 2. Restore database from backup
psql $DATABASE_URL < backup-latest.sql

# 3. Start previous version
sudo systemctl start secrethub-core-previous

# 4. Update load balancer to point to previous version

# 5. Investigate and fix issues before redeploying
```

---

## Troubleshooting

### Core Won't Start

```bash
# Check logs
sudo journalctl -u secrethub-core -n 100

# Common issues:
# - Database connection failed: Check DATABASE_URL
# - Port already in use: Check if previous instance running
# - Missing env vars: Verify /opt/secrethub/secrethub.env
```

### Database Migration Failed

```bash
# Rollback migration
mix ecto.rollback

# Check database connectivity
psql $DATABASE_URL -c "SELECT version();"

# Re-run migration with verbose logging
mix ecto.migrate --log-sql
```

### Agent Can't Connect

```bash
# Check Core accessibility
curl https://secrethub.company.com/v1/sys/health

# Check agent logs
journalctl -u secrethub-agent -f

# Verify Role ID and Secret ID
# Check network connectivity and firewall rules
```

---

## Related Documentation

- [Architecture Overview](../architecture.md)
- [Operator Manual](../operator-manual.md)
- [Troubleshooting Guide](../troubleshooting.md)
- [High Availability](../ha-architecture.md)

---

**Deployment Completed:** ___________
**Deployed By:** ___________
**Next Review:** ___________
