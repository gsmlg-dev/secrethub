# SecretHub - System Design & Implementation Plan

**Version:** 2.0  
**Date:** October 18, 2025  
**Authors:** Gemini, Claude

---

## 1. Project Overview

### 1.1. Project Vision

Build a secure, reliable, and highly automated enterprise-grade secrets management platform designed specifically for Machine-to-Machine (M2M) communication. Through centralized management, dynamic generation, and automatic rotation of secrets, eliminate security risks from hardcoded and static credentials, achieving credential automation under a zero-trust security architecture.

### 1.2. Core Objectives

- **Centralized Storage**: Uniformly encrypt and store all sensitive credentials including application secrets, certificates, and API keys
- **Access Control**: Implement role-based, fine-grained access policies ensuring applications can only access authorized secrets
- **Credential Automation**:
  - **Dynamic Secrets**: Dynamically generate extremely short-lived temporary credentials for databases, caches, and other services
  - **Static Secret Rotation**: Automatically rotate long-lived static credentials like cloud platform IAM keys and database root passwords
- **Last Mile Delivery**: Seamlessly and securely deliver credentials to final applications through local Agent mode, transparent to applications
- **High Availability & Fault Tolerance**: Core services must be highly available; no single point of failure should affect running applications
- **Comprehensive Auditing**: Record all authentication, authorization, and secret access behavior, providing immutable audit logs

---

## 2. System Architecture

The system adopts a Two-Tier architecture: **Central Core Service (Core)** and **Local Agent (Agent)**. Applications are the final consumers, interacting with the local Agent.

### 2.1. Tier 1: SecretHub Core (Central Core Service)

Central service cluster built on Elixir/Phoenix, serving as the brain and trust root of the entire system.

#### Components:

**Web Management Interface (Web UI)**
- Provides administrators with graphical interface for system configuration, policy management, audit viewing, and PKI system management

**API Layer (Phoenix Endpoint)**
- Provides persistent WebSocket (Phoenix Channels) based on mTLS as the primary communication channel for Agents
- Supplemented with RESTful API for management and initial bootstrap

**PKI Engine (Certificate Authority)**
- Built-in Certificate Authority managing root CA and intermediate CAs
- Dynamically issues client certificates for Agents and applications
- Manages Certificate Revocation Lists (CRL) and OCSP responder service
- Configurable certificate TTL (Time To Live)

**Authentication Backends (Auth Backends)**
- Validates Agent identity (e.g., AppRole, Kubernetes Service Account)
- Supports multiple authentication methods

**Policy Engine**
- Validates tokens for each request and authorizes based on preset policies
- Policies directly bind to Agent certificate identities

**Secret Engines**:
- **Dynamic Engine**: Real-time creation/destruction of temporary credentials (e.g., PostgreSQL engine)
- **Static Engine**: Rotates long-term credentials in external systems (e.g., AWS IAM engine)

**Lease Manager**
- Tracks lifecycle of all dynamic secrets
- Handles renewals and revocations

**Background Scheduler (Oban)**
- Processes persistent background tasks
- Primary function is static secret rotation

**Audit Logger**
- Records all operations to independent audit path
- Implements tamper-evident logging with hash chains
- Multi-tier storage strategy (hot/warm/cold)

**Persistent Storage (PostgreSQL)**
- Stores all configurations, policies, and encrypted secret data
- Application-layer encryption using AES-256-GCM

---

### 2.2. Tier 2: SecretHub Agent (Local Agent)

Lightweight daemon based on Elixir/OTP, deployed on the same server or K8s Pod as the final application.

#### Components:

**Authentication Client (Auth Client)**
- Uses "secret zero" (e.g., one-time RoleID/SecretID) to bootstrap and obtain client certificate from Core service
- Establishes persistent mTLS WebSocket connection

**Local Authentication & Authorization Module**
- Validates local application identity (e.g., via Unix Domain Socket client certificates)
- Authorizes access to specific secrets based on policies

**Core Logic (OTP Supervisor/GenServer)**
- Maintains persistent mTLS WebSocket connection with Core service
- Sends secret requests, renews leases via this connection
- Passively receives real-time notifications from Core (e.g., secret rotations)

**Template Renderer**
- Renders obtained secrets into predefined configuration file templates

**Sinker**
- Writes rendered configuration files to specified paths
- Triggers application reload based on configuration

**Local Cache**
- Aggressive multi-layer caching to reduce Core load
- Serves stale secrets during Core unavailability
- Implements request deduplication for thundering herd scenarios

---

## 3. Core Security Design

### 3.1. Zero Trust Principles

Every component and every API request must undergo strict authentication and authorization. Trust is never assumed, even for requests from local applications.

### 3.2. Startup & Unsealing

**Encryption Key Hierarchy:**
- All data in Core service database encrypted using "Master Encryption Key"
- "Master Encryption Key" itself encrypted by "Root Key"
- "Root Key" generated during initial system initialization and split into N "Unseal Key Shards" using Shamir Secret Sharing algorithm

**Unsealing Process:**
- Core service starts in Sealed state, unable to provide services
- Requires K (threshold) different administrators to provide their shards to reconstruct "Root Key" in memory
- Root key exists only in memory; service restart requires re-unsealing

**Production Recommendations:**
- Use cloud KMS (AWS KMS, GCP KMS) for automatic unsealing in production environments
- Reserve Shamir shares for disaster recovery/break-glass scenarios
- Implement auto-unsealing with proper HSM integration

### 3.3. Encryption Mechanisms

**Core ↔ Agent Communication Encryption**
- All communication through persistent, mandatory mTLS bidirectional authenticated WebSocket (WSS) connection
- Ensures channel confidentiality, integrity, and identity authenticity

**Encryption at Rest**
- All sensitive data (secrets, configurations) in Core service PostgreSQL database encrypted at application layer using AES-256-GCM

### 3.4. Identity Authentication

**Agent → Core:**
- Agent identity established by unique client certificate
- Certificate obtained securely from Core service's built-in PKI engine during first deployment through bootstrap process (e.g., using one-time AppRole token)
- All subsequent communication authenticated through persistent mTLS WebSocket connection
- Core-side policies bind directly to certificate identity (e.g., Common Name)

**Administrator → Core:**
- Strong authentication using OIDC (e.g., Keycloak) or mTLS client certificates
- Required for accessing Web UI and management API
- MFA verification logged in audit trail

**Application → Agent (Local Authentication):**
- Mutual authentication (mTLS) based on client certificates
- Each application issued unique, short-lived client certificate with identity ID embedded
- Certificate issued by Core service PKI engine and securely distributed through Agent
- Communication forced through secure Unix Domain Socket

### 3.5. Certificate Management

**Certificate Lifecycle:**
- Short-lived certificates (hours to days) to reduce revocation needs
- Automatic renewal before expiry through existing authenticated WebSocket
- Hitless certificate cutover with overlap period
- Old certificate remains valid during transition

**Revocation Strategy:**
- OCSP stapling instead of real-time OCSP checks
- CRL distribution for offline verification
- Certificate Transparency logs for audit
- Immediate revocation for compromised certificates

### 3.6. Audit Logging

**Comprehensive Event Logging:**
- All API requests recorded regardless of success/failure
- Request source, operation, timestamp, authorization result logged
- Implements tamper-evident logging with hash chains and HMAC signatures

**Storage Strategy:**
- Audit logs sent to independent, tamper-proof storage system (e.g., Write-Once-Read-Many object storage)
- Multi-tier storage: Hot (PostgreSQL 30 days), Warm (S3/GCS 1 year), Cold (Glacier 1+ years)

---

## 4. Functional Modules

### 4.1. Secret ID Naming Convention

All secrets (static or dynamic roles) use **Reverse Domain Name Notation** for structured, hierarchical namespace.

**Format:** `[environment].[service_type].[service_name].[instance/role].[credential_type]`

**Examples:**
- `prod.db.postgres.billing-db.password`
- `staging.api.payment-gateway.apikey`
- `dev.db.postgres.readonly.creds` (dynamic secret role)

**Benefits:**
- Clear hierarchical structure
- Easy policy wildcard matching
- Natural grouping for access control

**Enhanced Convention:**
- Version suffixes: `prod.db.postgres.billing-db.password@v2`
- Tenant prefixes: `{tenant-id}.prod.db.postgres...`
- Wildcards in policies: `prod.db.*.readonly.creds`

---

### 4.2. PKI Engine (Certificate Authority)

**Responsibilities:**
- Act as internal root CA and intermediate CA
- Automate mTLS certificate lifecycle management

**Functionality:**
- Securely generate and store CA key pairs
- Provide API endpoints for processing Certificate Signing Requests (CSR) from Agents
- Issue certificates under different intermediate CAs for different environments or business lines
- Manage Certificate Revocation Lists (CRL) and provide OCSP responder service
- Configurable certificate TTL

**API Endpoints:**
```
POST /v1/pki/ca/root/generate          # Generate root CA
POST /v1/pki/ca/intermediate/generate  # Generate intermediate CA
POST /v1/pki/sign-request              # Sign CSR from Agent
GET  /v1/pki/cert/:serial              # Get certificate by serial
POST /v1/pki/revoke                    # Revoke certificate
GET  /v1/pki/crl                       # Get CRL
```

---

### 4.3. Comprehensive Audit Logging System

#### 4.3.1. Audit Log Events

SecretHub logs every security-relevant event across 5 categories:

##### 1. Secret Access Events
*WHO accessed WHAT, WHEN, from WHERE*

**Logged Information:**
- Event metadata: event_id, event_type, timestamp, correlation_id
- Accessor identity: agent_id, agent_certificate_fingerprint, app_id, app_certificate_fingerprint
- Secret details: secret_id, secret_version, secret_type, lease_id
- Access result: access_granted, policy_matched, denial_reason
- Source context: source_ip, hostname, kubernetes_namespace, kubernetes_pod, cloud_instance_id
- Performance: response_time_ms, error_message

**Event Types:**
- `secret.accessed` - Secret read/retrieval
- `secret.dynamic_issued` - Dynamic credential generation
- `secret.lease_renewed` - Lease renewal
- `secret.access_denied` - Access denial

##### 2. Secret Mutation Events
*WHAT changed, WHO changed it, WHY*

**Logged Information:**
- Actor details: actor_type (admin/system/rotation_engine), actor_id, actor_ip, admin_mfa_verified
- Secret details: secret_id, old_version, new_version, secret_type
- Change context: change_type (manual/scheduled_rotation/emergency_rotation), rotation_strategy, change_reason
- Metadata changes: policy_changes, ttl_changed
- Approval workflow: approval_required, approved_by, approval_timestamp

**Event Types:**
- `secret.created` - New secret creation
- `secret.updated` - Manual secret update
- `secret.rotated` - Automatic rotation
- `secret.deleted` - Secret deletion

##### 3. Authentication Events
*All authentication attempts*

**Logged Information:**
- Entity details: entity_type, entity_id, certificate_fingerprint
- Authentication method: auth_method (approle/kubernetes/oidc/mtls), auth_backend
- Result: success, failure_reason, mfa_used
- Context: source_ip, user_agent, geo_location

**Event Types:**
- `auth.agent_bootstrap` - Agent initial bootstrap
- `auth.agent_certificate_issued` - Certificate issuance
- `auth.agent_login` - Agent authentication
- `auth.admin_login` - Administrator login
- `auth.failed` - Failed authentication attempt

##### 4. Policy Changes
*ACL and permission modifications*

**Logged Information:**
- Administrator: admin_id, admin_ip
- Policy details: policy_id, policy_name, affected_entities
- Changes: permissions_added, permissions_removed, secrets_added_to_allowlist, secrets_removed_from_allowlist

**Event Types:**
- `policy.created` - New policy creation
- `policy.updated` - Policy modification
- `policy.deleted` - Policy deletion
- `policy.bound` - Policy binding to entity

##### 5. System Events
*System-level operations*

**Logged Information:**
- System operations: operator_id, unseal_key_count
- Backup operations: backup_id, backup_location
- Certificate management: certificate_revoked, revocation_reason

**Event Types:**
- `system.unsealed` - System unsealed
- `system.sealed` - System sealed
- `system.backup_created` - Backup operation
- `system.certificate_revoked` - Certificate revocation

---

#### 4.3.2. Tamper-Evident Storage

**Hash Chain Implementation:**
- Each log entry contains hash of previous entry (blockchain-like)
- HMAC signatures for all entries using HSM-stored key
- Monotonically increasing sequence numbers
- Periodic chain verification jobs

**PostgreSQL Schema:**
```sql
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID UNIQUE NOT NULL,
    sequence_number BIGINT UNIQUE NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    
    -- Actor information
    actor_type VARCHAR(50),
    actor_id VARCHAR(255),
    agent_id VARCHAR(255),
    app_id VARCHAR(255),
    admin_id VARCHAR(255),
    
    -- Certificate fingerprints for non-repudiation
    agent_cert_fingerprint VARCHAR(64),
    app_cert_fingerprint VARCHAR(64),
    
    -- Secret information
    secret_id VARCHAR(500),
    secret_version INTEGER,
    secret_type VARCHAR(50),
    lease_id UUID,
    
    -- Access control
    access_granted BOOLEAN,
    policy_matched VARCHAR(255),
    denial_reason TEXT,
    
    -- Context
    source_ip INET,
    hostname VARCHAR(255),
    kubernetes_namespace VARCHAR(255),
    kubernetes_pod VARCHAR(255),
    
    -- Full event data
    event_data JSONB,
    
    -- Tamper-evidence
    previous_hash VARCHAR(64),
    current_hash VARCHAR(64),
    signature VARCHAR(128),
    
    -- Performance
    response_time_ms INTEGER,
    correlation_id UUID,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (timestamp);

-- Indexes for common queries
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_id, timestamp DESC);
CREATE INDEX idx_audit_logs_secret ON audit_logs(secret_id, timestamp DESC);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type, timestamp DESC);
CREATE INDEX idx_audit_logs_access_denied ON audit_logs(timestamp DESC) 
    WHERE access_granted = false;
CREATE INDEX idx_audit_logs_event_data ON audit_logs USING GIN(event_data);
```

**Multi-Tier Storage Strategy:**
- **Tier 1 (Hot)**: PostgreSQL - Last 30 days
  - Fast queries for recent activity
  - Real-time alerting and monitoring
- **Tier 2 (Warm)**: S3/GCS Standard-IA - 31 days to 1 year
  - Compliance queries and investigations
  - Compressed JSONL format
- **Tier 3 (Cold)**: Glacier/Coldline - 1+ years
  - Long-term compliance retention
  - Rare access, low cost

**Automatic Archival:**
- Daily Oban job moves logs older than 30 days to S3/GCS
- Compressed using gzip
- Encrypted at rest (AES-256)
- Partitioned by year/month for efficient queries

---

#### 4.3.3. Real-Time Security Monitoring

**Anomaly Detection Patterns:**

1. **Repeated Failed Access Attempts**
   - Threshold: >10 failures in 5 minutes
   - Alert: High severity
   - Action: Page security team

2. **Mass Secret Access**
   - Threshold: >50 unique secrets in 1 minute
   - Alert: Critical severity (potential exfiltration)
   - Action: Immediate incident response

3. **After-Hours Access**
   - Detection: Access outside 8 AM - 6 PM
   - Alert: Medium severity
   - Action: Log and notify

4. **Geographic Anomaly**
   - Detection: Access from new geographic location
   - Alert: Medium severity
   - Action: Verify with application owner

5. **Privilege Escalation Attempts**
   - Detection: Accessing secrets outside normal scope
   - Alert: High severity
   - Action: Investigate immediately

**Alert Routing:**
- **Critical**: PagerDuty + Slack security channel + Email
- **High**: Slack security channel + Email
- **Medium**: Email to security team
- **Low**: Dashboard notification

---

#### 4.3.4. Query & Reporting Interface

**Common Audit Queries:**

1. **Secret Access History**
   ```
   Query: Who accessed secret X in last 30 days?
   Returns: timestamp, accessor (app_id), agent, IP, result
   ```

2. **Agent Activity Timeline**
   ```
   Query: All actions by agent Y in date range
   Returns: Complete activity timeline with all events
   ```

3. **Failed Access Report**
   ```
   Query: All failed access attempts in last 24 hours
   Returns: Grouped by agent/app with failure counts and reasons
   ```

4. **Compliance Report**
   ```
   Query: All accesses to secret Z in fiscal year
   Returns: Complete access log for compliance audits
   Format: CSV/PDF export available
   ```

5. **Rotation History**
   ```
   Query: When was secret rotated? Who initiated?
   Returns: Rotation timeline with change reasons
   ```

**Web UI Dashboard:**
- Recent Activity Timeline (last 1 hour)
- Secret Access Heatmap (7-day view)
- Top Accessed Secrets
- Failed Access Attempts Chart
- Active Leases Summary
- Anomaly Alerts Panel

**API Endpoints:**
```
GET  /v1/audit/search                 # Advanced search with filters
GET  /v1/audit/secret/:id/history     # Secret access history
GET  /v1/audit/agent/:id/activity     # Agent activity log
GET  /v1/audit/failures               # Failed access attempts
GET  /v1/audit/export                 # Export audit logs (CSV/JSONL)
POST /v1/audit/compliance-report      # Generate compliance report
```

---

#### 4.3.5. Privacy & Security Considerations

**What NOT to Log:**
- ❌ Actual secret values (passwords, API keys, private keys)
- ❌ Full certificate private keys
- ❌ Personally Identifiable Information (PII) unless required for audit

**What IS Logged:**
- ✅ Certificate fingerprints (SHA-256 hash)
- ✅ Secret IDs and versions
- ✅ Access patterns and metadata
- ✅ Authentication results
- ✅ Policy decisions

**Retention Policy:**
- Hot storage: 30 days
- Warm storage: 1 year
- Cold storage: 7 years (configurable for compliance)
- After retention period: Secure deletion with verification

---

### 4.4. Web Management Interface

**Functionality:**

**PKI Management:**
- View CA information and certificate hierarchy
- Browse issued certificates with search/filter
- Manually revoke certificates with reason codes
- Manage CRL and OCSP responder
- Certificate expiry monitoring and alerts

**Policy Management:**
- Create, update, delete access policies
- Bind policies to Agent or application identities
- Policy simulation/testing tool
- Template-based policy creation
- Bulk policy operations

**Secret Management:**
- Manual static secret management (CRUD)
- Configure dynamic secret engines
- Set up rotation schedules and strategies
- Secret versioning and rollback
- Secret access analytics

**Audit Viewing:**
- Search and filter audit logs
- Export audit reports (CSV, PDF, JSONL)
- Real-time activity monitoring
- Anomaly detection dashboard
- Compliance report generation

**System Configuration:**
- Unseal/seal operations
- Backup and restore management
- System health monitoring
- Performance metrics dashboard
- Alert configuration

---

### 4.5. API Endpoint Design

#### REST API

**Authentication & Bootstrap:**
```
POST /v1/auth/bootstrap/approle       # Agent bootstrap with AppRole
POST /v1/auth/bootstrap/kubernetes    # Agent bootstrap with K8s SA
POST /v1/auth/verify                  # Verify authentication token
```

**PKI Operations:**
```
POST /v1/pki/sign-request             # Sign CSR for Agent/Application
GET  /v1/pki/cert/:serial             # Get certificate details
POST /v1/pki/revoke                   # Revoke certificate
GET  /v1/pki/crl                      # Download CRL
POST /v1/pki/ca/intermediate          # Create intermediate CA
```

**Secret Management:**
```
GET    /v1/secrets/static/:path       # Get static secret
POST   /v1/secrets/static/:path       # Create static secret
PUT    /v1/secrets/static/:path       # Update static secret
DELETE /v1/secrets/static/:path       # Delete static secret
POST   /v1/secrets/dynamic/:role      # Generate dynamic credentials
```

**Policy Management:**
```
GET    /v1/policies                   # List policies
POST   /v1/policies                   # Create policy
GET    /v1/policies/:id               # Get policy details
PUT    /v1/policies/:id               # Update policy
DELETE /v1/policies/:id               # Delete policy
```

---

#### WebSocket API (Phoenix Channels)

Agent connects via mTLS-authenticated WebSocket. All operations through dedicated Topic using JSON-RPC style messages.

**Message Format:**
```json
{
  "event": "event_name",
  "payload": { /* request data */ },
  "ref": 1  /* message reference ID */
}
```

**Agent Operations:**

**Get Dynamic Secret:**
```json
{
  "event": "secrets:get_dynamic",
  "payload": {
    "role_id": "prod.db.postgres.readonly.creds",
    "ttl": "1h"
  },
  "ref": 1
}

Response:
{
  "event": "secrets:dynamic_response",
  "payload": {
    "username": "v-agent-prod-01-readonly-abc123",
    "password": "randomly-generated-password",
    "lease_id": "lease-uuid",
    "lease_duration": 3600,
    "renewable": true
  },
  "ref": 1
}
```

**Get Static Secret:**
```json
{
  "event": "secrets:get_static",
  "payload": {
    "path": "prod.api.payment-gateway.apikey"
  },
  "ref": 2
}

Response:
{
  "event": "secrets:static_response",
  "payload": {
    "value": "encrypted-secret-value",
    "version": 3,
    "metadata": {
      "created_at": "2025-10-01T00:00:00Z",
      "last_rotated": "2025-10-15T12:00:00Z"
    }
  },
  "ref": 2
}
```

**Renew Lease:**
```json
{
  "event": "lease:renew",
  "payload": {
    "lease_id": "lease-uuid",
    "increment": 3600
  },
  "ref": 3
}
```

**Server Push Notifications:**

Core can proactively push messages to connected Agents:

**Secret Rotation Notification:**
```json
{
  "event": "secrets:rotated",
  "payload": {
    "secret_id": "prod.api.payment-gateway.apikey",
    "new_version": 4,
    "rotation_reason": "scheduled_rotation"
  }
}
```

**Policy Update Notification:**
```json
{
  "event": "policy:updated",
  "payload": {
    "policy_id": "policy-uuid",
    "changes": ["secrets_added", "ttl_changed"]
  }
}
```

---

### 4.6. SecretHub Agent Implementation

#### Core GenServer State Machine

**State Structure:**
```elixir
defmodule SecretHub.Agent.State do
  defstruct [
    :websocket_conn,          # Phoenix.Channel.Socket
    :certificate,             # Agent client certificate
    :connection_status,       # :connected | :reconnecting | :disconnected
    :local_cache,             # Map of cached secrets
    :policy_cache,            # Cached authorization policies
    :pending_requests,        # Map of in-flight requests
    :lease_renewals,          # Timer refs for lease renewals
    :backoff_state            # Exponential backoff for reconnection
  ]
end
```

**Connection Management:**
- Persistent WebSocket connection with automatic reconnection
- Exponential backoff on connection failures (1s, 2s, 4s, 8s, max 60s)
- Heartbeat mechanism to detect connection issues
- Graceful connection upgrade for certificate renewal

---

#### Local Application Authentication & Authorization

**Communication Method:**
- Agent creates Unix Domain Socket at `/var/run/secrethub-agent.sock`
- Only processes with appropriate permissions can connect
- Each application uses mTLS client certificate for identity

**Policy File Format:**
```json
{
  "version": "1.0",
  "policies": [
    {
      "app_id": "webapp-frontend-prod",
      "app_certificate_fingerprint": "sha256:abc123...",
      "allowed_secrets": [
        "prod.api.payment-gateway.apikey",
        "prod.db.redis.cache.password"
      ],
      "allowed_operations": ["read"],
      "conditions": {
        "time_of_day": "00:00-23:59",
        "max_ttl": "1h"
      }
    },
    {
      "app_id": "billing-service-prod",
      "app_certificate_fingerprint": "sha256:def456...",
      "allowed_secrets": [
        "prod.db.postgres.billing-db.*"  // Wildcard support
      ],
      "allowed_operations": ["read", "renew"],
      "conditions": {
        "lease_ttl_min": "5m"
      }
    }
  ]
}
```

**Authorization Flow:**
1. Application connects to Unix Domain Socket with client certificate
2. Agent verifies certificate against Core's CA
3. Extract app_id from certificate CN or SAN
4. Check cached policy for app_id's allowed_secrets
5. Grant or deny access based on policy match
6. Log authorization decision to local audit log
7. Forward request to Core if authorized

---

#### Local Cache Strategy

**Cache Layers:**

1. **Memory Cache** (Priority 1)
   - Static secrets: Cache until invalidation
   - Dynamic secrets: Cache until 5 minutes before lease expiry
   - Policies: Cache for 5 minutes

2. **Disk Cache** (Priority 2 - Fallback)
   - Encrypted cache file for offline operation
   - Used when Core unreachable
   - TTL: 1 hour for static, not applicable for dynamic

**Cache Invalidation:**
- Active: Core pushes rotation notification via WebSocket
- Passive: TTL expiration
- Emergency: Explicit invalidation command from Core

**Graceful Degradation:**
```
Core Available:
  → Fetch from Core
  → Update cache
  → Serve to application

Core Unreachable:
  → Serve from memory cache (if fresh)
  → Serve from disk cache (if within TTL)
  → Serve stale secret with warning (if TTL expired < 1 hour)
  → Fail request (if no cache or too stale)
```

---

#### Template Rendering

**Configuration Template Example:**
```yaml
# database.yml.tmpl
production:
  adapter: postgresql
  host: {{ secrets.prod.db.postgres.billing-db.host }}
  port: {{ secrets.prod.db.postgres.billing-db.port }}
  database: {{ secrets.prod.db.postgres.billing-db.database }}
  username: {{ secrets.prod.db.postgres.billing-db.username }}
  password: {{ secrets.prod.db.postgres.billing-db.password }}
  
redis:
  url: redis://{{ secrets.prod.db.redis.cache.password }}@redis.prod:6379/0
```

**Template Rendering Process:**
1. Agent receives template path from configuration
2. Fetches required secrets based on template placeholders
3. Renders template using fetched secrets
4. Writes rendered file to target path with restricted permissions (0600)
5. Optionally triggers application reload via:
   - Signal (SIGHUP)
   - HTTP endpoint call
   - Systemd reload
   - Kubernetes configmap update

---

#### Sinker (File Writer)

**File Writing Strategy:**
- Atomic write: Write to temp file, then rename (ensures no partial reads)
- Permission management: Set owner/group and permissions (typically 0600)
- Change detection: Only trigger reload if file content actually changed
- Rollback capability: Keep last N versions for emergency rollback

**Supported Reload Methods:**
```json
{
  "sinks": [
    {
      "template": "/etc/secrethub/templates/database.yml.tmpl",
      "destination": "/app/config/database.yml",
      "permissions": "0600",
      "owner": "app-user:app-group",
      "reload": {
        "method": "signal",
        "target": "app-process",
        "signal": "SIGHUP"
      }
    },
    {
      "template": "/etc/secrethub/templates/api-keys.env.tmpl",
      "destination": "/app/.env",
      "permissions": "0400",
      "reload": {
        "method": "http",
        "url": "http://localhost:8080/admin/reload",
        "method": "POST",
        "headers": {
          "X-Admin-Token": "{{ secrets.admin.reload-token }}"
        }
      }
    }
  ]
}
```

---

## 5. High Availability & Reliability Design

### 5.1. Core Service HA

**Architecture:**
- Minimum 3 Core nodes in production (quorum)
- Load balanced behind HAProxy/Nginx with health checks
- PostgreSQL in HA configuration (streaming replication or Patroni cluster)
- Agents connect to load balancer, automatically failover to healthy nodes

**Health Checks:**
```
GET /health/live    # Liveness: Is process running?
GET /health/ready   # Readiness: Can handle requests (unsealed)?
GET /health/status  # Detailed status including DB connection
```

**Sealed State Handling:**
- Unsealed node: `200 OK` on `/health/ready`
- Sealed node: `503 Service Unavailable` on `/health/ready`
- Load balancer removes sealed nodes from rotation

---

### 5.2. Agent Resilience

**Connection Resilience:**
- Multiple Core endpoints configured (comma-separated)
- Round-robin + health check for endpoint selection
- Exponential backoff on connection failures
- Maximum reconnection attempts before alerting

**Offline Operation:**
- Serve from cache when Core unreachable
- Log all operations for later sync
- Alert monitoring system after 5 minutes offline
- Page on-call after 15 minutes offline

**Lease Renewal Strategy:**
- Renew leases at 50% of TTL
- If renewal fails, retry with exponential backoff
- If lease expires, immediately revoke access to application
- Log lease expiry event for audit

---

### 5.3. Database Backup & Recovery

**Backup Strategy:**
- **Continuous WAL Archival**: Stream WAL files to S3/GCS
- **Daily Full Backup**: Automated via Oban scheduler
- **Weekly Snapshot**: For faster restore
- **Backup Encryption**: All backups encrypted with separate key

**Backup Verification:**
- Monthly restore test to separate environment
- Automated integrity checks on backup files
- Backup retention: 30 daily, 12 monthly, 7 yearly

**Recovery Procedures:**
1. **Point-in-Time Recovery (PITR)**: Restore to specific timestamp using WAL replay
2. **Full Restore**: Restore from latest full backup + WAL replay
3. **Emergency Recovery**: Use most recent snapshot for fastest RTO

**Recovery Time Objectives:**
- RTO (Recovery Time Objective): < 1 hour
- RPO (Recovery Point Objective): < 5 minutes (based on WAL streaming)

---

### 5.4. Disaster Recovery Plan

**Scenario 1: Single Core Node Failure**
- **Impact**: None (HA cluster continues)
- **Action**: Automatic failover via load balancer
- **Recovery**: Restart node, re-join cluster

**Scenario 2: Database Failure**
- **Impact**: Core services sealed, read-only mode
- **Action**: Failover to PostgreSQL replica
- **Recovery**: Promote replica, reconfigure Core nodes

**Scenario 3: All Shamir Keyholders Unavailable**
- **Prevention**: Store sealed envelope with root key in bank vault
- **Recovery**: Break-glass procedure with C-level approval
- **Alternative**: Use cloud KMS auto-unseal

**Scenario 4: Complete Data Center Loss**
- **Prevention**: Multi-region deployment
- **Recovery**: Restore from S3 backup in secondary region
- **Time**: 2-4 hours (includes database restore + unseal)

**Scenario 5: Audit Log Tampering**
- **Detection**: Hash chain verification fails
- **Response**: Trigger security incident, notify security team
- **Investigation**: Compare with SIEM copy of logs

---

## 6. Secret Engines Implementation

### 6.1. Dynamic Secret Engines

#### PostgreSQL Engine

**Functionality:**
- Dynamically create database users with limited privileges
- Automatically revoke access when lease expires
- Support for read-only, read-write, and admin roles

**Configuration:**
```json
{
  "engine": "postgresql",
  "config": {
    "connection_url": "postgresql://root:master-password@postgres.prod:5432/database",
    "max_open_connections": 5,
    "max_connection_lifetime": "10m"
  },
  "roles": [
    {
      "name": "prod.db.postgres.billing-db.readonly",
      "sql": [
        "CREATE USER '{{name}}' WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
        "GRANT CONNECT ON DATABASE billing TO '{{name}}';",
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO '{{name}}';"
      ],
      "revocation_sql": [
        "REVOKE ALL PRIVILEGES ON DATABASE billing FROM '{{name}}';",
        "DROP USER '{{name}}';"
      ],
      "default_ttl": "1h",
      "max_ttl": "24h"
    },
    {
      "name": "prod.db.postgres.billing-db.readwrite",
      "sql": [
        "CREATE USER '{{name}}' WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
        "GRANT CONNECT ON DATABASE billing TO '{{name}}';",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO '{{name}}';"
      ],
      "revocation_sql": [
        "REVOKE ALL PRIVILEGES ON DATABASE billing FROM '{{name}}';",
        "DROP USER '{{name}}';"
      ],
      "default_ttl": "30m",
      "max_ttl": "4h"
    }
  ]
}
```

**Username Generation:**
- Format: `v-{agent-id}-{role}-{random-suffix}`
- Example: `v-agent-prod-01-readonly-abc123`
- Ensures uniqueness and traceability

**Lifecycle:**
1. Application requests credentials via Agent
2. Core creates PostgreSQL user with random password
3. Returns credentials with lease_id and TTL
4. Agent caches credentials and auto-renews lease
5. On lease expiry or revocation, Core executes revocation_sql
6. User is dropped from database

---

#### Redis Engine

**Functionality:**
- Generate ACL users with specific command permissions
- Support for Redis 6+ ACL system

**Configuration:**
```json
{
  "engine": "redis",
  "config": {
    "host": "redis.prod",
    "port": 6379,
    "password": "master-password"
  },
  "roles": [
    {
      "name": "prod.db.redis.cache.readonly",
      "commands": ["+get", "+hget", "+keys", "+scan"],
      "keys": ["cache:*"],
      "default_ttl": "2h",
      "max_ttl": "12h"
    }
  ]
}
```

---

#### AWS IAM Engine

**Functionality:**
- Generate temporary AWS access keys (STS AssumeRole)
- Attach specific IAM policies to temporary credentials

**Configuration:**
```json
{
  "engine": "aws-iam",
  "config": {
    "access_key": "AKIA...",
    "secret_key": "secret",
    "region": "us-east-1"
  },
  "roles": [
    {
      "name": "prod.cloud.aws.s3-readonly",
      "role_arn": "arn:aws:iam::123456789012:role/S3ReadOnlyRole",
      "policy_document": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": "arn:aws:s3:::my-bucket/*"
          }
        ]
      },
      "default_ttl": "1h",
      "max_ttl": "12h"
    }
  ]
}
```

---

### 6.2. Static Secret Rotation Engines

#### AWS IAM Key Rotation

**Strategy:**
- Each IAM user can have 2 access keys simultaneously
- Create new key → Update applications → Delete old key

**Rotation Process:**
```
1. Generate new AWS access key (Key B)
2. Store Key B in SecretHub with version N+1
3. Push notification to all Agents using this secret
4. Wait for grace period (e.g., 1 hour) for Agents to fetch new key
5. Verify all Agents have fetched new version
6. Delete old AWS access key (Key A)
7. Mark version N as deprecated
```

**Configuration:**
```json
{
  "engine": "aws-iam-rotation",
  "secret_id": "prod.cloud.aws.billing-service.access-key",
  "config": {
    "iam_username": "billing-service-prod",
    "rotation_schedule": "0 2 * * 0",  // Every Sunday at 2 AM
    "grace_period": "1h"
  }
}
```

---

#### Database Root Password Rotation

**Strategy:**
- Blue-Green rotation with validation

**Rotation Process:**
```
1. Generate new random password (Password B)
2. Update database with: ALTER USER root WITH PASSWORD 'Password B';
3. Test connection with Password B
4. If successful:
   - Store Password B in SecretHub
   - Push notification to Agents
   - Wait for grace period
   - Mark Password A as deprecated
5. If failed:
   - Rollback to Password A
   - Alert operators
```

**Configuration:**
```json
{
  "engine": "postgres-root-rotation",
  "secret_id": "prod.db.postgres.billing-db.root-password",
  "config": {
    "connection_url": "postgresql://root:current-password@postgres.prod:5432/postgres",
    "rotation_schedule": "0 3 1 * *",  // First day of month at 3 AM
    "grace_period": "2h",
    "validation_query": "SELECT 1"
  }
}
```

---

#### API Key Rotation (Generic)

**Strategy:**
- For third-party APIs supporting multiple simultaneous keys

**Rotation Process:**
```
1. Call third-party API to generate new key
2. Store new key in SecretHub
3. Push notification to Agents
4. Wait for grace period
5. Call third-party API to revoke old key
```

**Configuration:**
```json
{
  "engine": "api-key-rotation",
  "secret_id": "prod.api.stripe.secret-key",
  "config": {
    "provider": "stripe",
    "rotation_schedule": "0 4 */15 * *",  // Every 15 days at 4 AM
    "grace_period": "30m",
    "api_config": {
      "create_endpoint": "https://api.stripe.com/v1/keys",
      "revoke_endpoint": "https://api.stripe.com/v1/keys/:id",
      "auth_method": "bearer",
      "auth_token": "{{ secrets.prod.api.stripe.admin-token }}"
    }
  }
}
```

---

## 7. Deployment Architecture

### 7.1. Kubernetes Deployment

**Core Service Deployment:**

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: secrethub-core
  namespace: secrethub-system
spec:
  serviceName: secrethub-core
  replicas: 3
  selector:
    matchLabels:
      app: secrethub-core
  template:
    metadata:
      labels:
        app: secrethub-core
    spec:
      serviceAccountName: secrethub-core
      containers:
      - name: core
        image: secrethub/core:v2.0.0
        ports:
        - containerPort: 4000
          name: http
        - containerPort: 4001
          name: websocket
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: secrethub-db-credentials
              key: url
        - name: ERLANG_COOKIE
          valueFrom:
            secretKeyRef:
              name: secrethub-cluster
              key: cookie
        livenessProbe:
          httpGet:
            path: /health/live
            port: 4000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 4000
          initialDelaySeconds: 10
          periodSeconds: 5
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        volumeMounts:
        - name: audit-logs
          mountPath: /var/log/secrethub
        - name: tls-certs
          mountPath: /etc/secrethub/tls
          readOnly: true
  volumeClaimTemplates:
  - metadata:
      name: audit-logs
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
---
apiVersion: v1
kind: Service
metadata:
  name: secrethub-core
  namespace: secrethub-system
spec:
  selector:
    app: secrethub-core
  ports:
  - name: http
    port: 4000
    targetPort: 4000
  - name: websocket
    port: 4001
    targetPort: 4001
  clusterIP: None  # Headless service for StatefulSet
---
apiVersion: v1
kind: Service
metadata:
  name: secrethub-core-lb
  namespace: secrethub-system
spec:
  type: LoadBalancer
  selector:
    app: secrethub-core
  ports:
  - name: https
    port: 443
    targetPort: 4001
```

**Agent Deployment (Sidecar Pattern):**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webapp-frontend
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: webapp-frontend
  template:
    metadata:
      labels:
        app: webapp-frontend
    spec:
      serviceAccountName: webapp-frontend
      initContainers:
      - name: secrethub-agent-init
        image: secrethub/agent:v2.0.0
        command: ["/bin/secrethub-agent", "bootstrap"]
        env:
        - name: SECRETHUB_CORE_URL
          value: "wss://secrethub-core-lb.secrethub-system.svc.cluster.local:443"
        - name: SECRETHUB_ROLE_ID
          valueFrom:
            secretKeyRef:
              name: webapp-frontend-approle
              key: role-id
        - name: SECRETHUB_SECRET_ID
          valueFrom:
            secretKeyRef:
              name: webapp-frontend-approle
              key: secret-id
        volumeMounts:
        - name: secrethub-config
          mountPath: /etc/secrethub
        - name: shared-secrets
          mountPath: /secrets
      containers:
      - name: agent
        image: secrethub/agent:v2.0.0
        command: ["/bin/secrethub-agent", "run"]
        env:
        - name: SECRETHUB_CONFIG
          value: "/etc/secrethub/agent-config.json"
        volumeMounts:
        - name: secrethub-config
          mountPath: /etc/secrethub
        - name: shared-secrets
          mountPath: /secrets
        - name: agent-socket
          mountPath: /var/run/secrethub
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
      - name: webapp
        image: webapp-frontend:v1.0.0
        env:
        - name: DATABASE_CONFIG
          value: "/secrets/database.yml"
        - name: API_KEYS
          value: "/secrets/api-keys.env"
        volumeMounts:
        - name: shared-secrets
          mountPath: /secrets
          readOnly: true
        - name: agent-socket
          mountPath: /var/run/secrethub
        ports:
        - containerPort: 8080
      volumes:
      - name: secrethub-config
        emptyDir: {}
      - name: shared-secrets
        emptyDir:
          medium: Memory  # Store secrets in tmpfs
      - name: agent-socket
        emptyDir: {}
```

---

### 7.2. VM/Bare Metal Deployment

**Core Service (systemd):**

```ini
# /etc/systemd/system/secrethub-core.service
[Unit]
Description=SecretHub Core Service
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=exec
User=secrethub
Group=secrethub
WorkingDirectory=/opt/secrethub
Environment="MIX_ENV=prod"
Environment="RELEASE_COOKIE=your-erlang-cookie"
ExecStart=/opt/secrethub/bin/secrethub_core start
ExecStop=/opt/secrethub/bin/secrethub_core stop
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

**Agent Service (systemd):**

```ini
# /etc/systemd/system/secrethub-agent.service
[Unit]
Description=SecretHub Agent
After=network.target

[Service]
Type=exec
User=secrethub-agent
Group=secrethub-agent
WorkingDirectory=/opt/secrethub-agent
Environment="SECRETHUB_CONFIG=/etc/secrethub/agent-config.json"
ExecStartPre=/opt/secrethub-agent/bin/bootstrap.sh
ExecStart=/opt/secrethub-agent/bin/secrethub_agent foreground
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

### 7.3. Network Architecture

**Security Zones:**

```
┌─────────────────────────────────────────────────────────────┐
│ DMZ (Internet-facing)                                       │
│  ├─ Load Balancer (TLS termination)                         │
│  └─ WAF / DDoS Protection                                   │
└─────────────────────────────────────────────────────────────┘
                           │
                           ↓ (mTLS only)
┌─────────────────────────────────────────────────────────────┐
│ Management Zone                                             │
│  ├─ SecretHub Core Cluster (3+ nodes)                       │
│  ├─ Web UI (Admin access via VPN/Bastion)                   │
│  └─ Monitoring & Alerting                                   │
└─────────────────────────────────────────────────────────────┘
                           │
                           ↓ (PostgreSQL encrypted)
┌─────────────────────────────────────────────────────────────┐
│ Data Zone                                                   │
│  ├─ PostgreSQL HA Cluster                                   │
│  └─ Backup Storage (S3/GCS)                                 │
└─────────────────────────────────────────────────────────────┘
                           │
                           ↑ (mTLS WebSocket)
┌─────────────────────────────────────────────────────────────┐
│ Application Zone                                            │
│  ├─ Application Servers with Agents                         │
│  └─ Kubernetes Clusters with Agent Sidecars                 │
└─────────────────────────────────────────────────────────────┘
```

**Firewall Rules:**
- Allow inbound 443/tcp to Load Balancer from Agent zones
- Allow inbound 5432/tcp to PostgreSQL from Core nodes only
- Deny all other inbound traffic
- Allow outbound from Core to target systems for dynamic secret generation

---

## 8. Monitoring & Observability

### 8.1. Metrics (Prometheus)

**Core Service Metrics:**

```
# Request metrics
secrethub_requests_total{method, endpoint, status}
secrethub_request_duration_seconds{method, endpoint, quantile}

# WebSocket metrics
secrethub_websocket_connections_active
secrethub_websocket_messages_sent_total
secrethub_websocket_messages_received_total

# Secret engine metrics
secrethub_secrets_generated_total{engine, role}
secrethub_secrets_revoked_total{engine, role}
secrethub_leases_active{engine}
secrethub_lease_renewals_total{engine, status}

# Rotation metrics
secrethub_rotations_scheduled_total{secret_id}
secrethub_rotations_completed_total{secret_id, status}
secrethub_rotation_duration_seconds{secret_id}

# Database metrics
secrethub_db_connections_active
secrethub_db_query_duration_seconds{query_type, quantile}

# Audit metrics
secrethub_audit_logs_written_total
secrethub_audit_logs_failed_total
secrethub_audit_chain_verifications_total{status}

# System metrics
secrethub_core_sealed{node}  # 0=unsealed, 1=sealed
secrethub_core_nodes_active
```

**Agent Metrics:**

```
# Connection metrics
secrethub_agent_connection_status{agent_id}  # 0=disconnected, 1=connected
secrethub_agent_reconnection_attempts_total{agent_id}

# Cache metrics
secrethub_agent_cache_hits_total{agent_id, secret_id}
secrethub_agent_cache_misses_total{agent_id, secret_id}
secrethub_agent_cache_size_bytes{agent_id}

# Request metrics
secrethub_agent_requests_to_core_total{agent_id, operation, status}
secrethub_agent_local_requests_total{agent_id, app_id, status}

# Template rendering metrics
secrethub_agent_template_renders_total{agent_id, template, status}
secrethub_agent_sink_writes_total{agent_id, sink, status}
```

---

### 8.2. Distributed Tracing (OpenTelemetry)

**Trace Flow:**

```
1. Application → Agent (local UDS)
   ├─ Span: app_request_secret
   └─ Attributes: app_id, secret_id
   
2. Agent → Core (WebSocket)
   ├─ Span: agent_fetch_secret
   └─ Attributes: agent_id, secret_id, cache_hit
   
3. Core → Secret Engine
   ├─ Span: generate_dynamic_secret
   └─ Attributes: engine_type, role, ttl
   
4. Core → Database
   ├─ Span: db_create_lease
   └─ Attributes: lease_id, expiry
   
5. Core → Audit Log
   ├─ Span: audit_log_write
   └─ Attributes: event_type, actor_id
```

**Example Trace Context:**
```json
{
  "trace_id": "abc123def456",
  "spans": [
    {
      "span_id": "span-1",
      "operation": "app_request_secret",
      "start_time": "2025-10-18T10:00:00.000Z",
      "duration_ms": 45,
      "attributes": {
        "app_id": "webapp-frontend-prod",
        "secret_id": "prod.db.postgres.billing-db.readonly"
      }
    },
    {
      "span_id": "span-2",
      "parent_span_id": "span-1",
      "operation": "agent_fetch_secret",
      "duration_ms": 40,
      "attributes": {
        "agent_id": "agent-k8s-prod-01",
        "cache_hit": false
      }
    }
  ]
}
```

---

### 8.3. Logging Strategy

**Log Levels:**
- **DEBUG**: Detailed diagnostic information (disabled in production)
- **INFO**: General informational messages (e.g., "Agent connected")
- **WARN**: Warning messages (e.g., "Lease renewal failed, retrying")
- **ERROR**: Error messages (e.g., "Database connection failed")
- **CRITICAL**: Critical issues requiring immediate attention (e.g., "Core service sealed")

**Structured Logging Format (JSON):**

```json
{
  "timestamp": "2025-10-18T10:00:00.000Z",
  "level": "INFO",
  "service": "secrethub-core",
  "node": "core-node-1",
  "module": "SecretHub.Auth",
  "function": "authenticate_agent/2",
  "message": "Agent authenticated successfully",
  "metadata": {
    "agent_id": "agent-k8s-prod-01",
    "certificate_fingerprint": "sha256:abc123...",
    "source_ip": "10.0.1.50"
  },
  "trace_id": "abc123def456",
  "span_id": "span-2"
}
```

**Log Aggregation:**
- Forward all logs to centralized logging (ELK, Loki, CloudWatch)
- Separate operational logs from audit logs
- Retain operational logs for 30 days
- Retain audit logs per compliance requirements (7 years)

---

### 8.4. Alerting Rules

**Critical Alerts (Page On-Call):**

```yaml
# Core service sealed
- alert: SecretHubCoreSealed
  expr: secrethub_core_sealed == 1
  for: 1m
  annotations:
    summary: "SecretHub Core node {{ $labels.node }} is sealed"
    description: "Core service requires unsealing to resume operations"

# No healthy Core nodes
- alert: SecretHubCoreAllNodesDown
  expr: sum(up{job="secrethub-core"}) == 0
  for: 2m
  annotations:
    summary: "All SecretHub Core nodes are down"

# Database connection lost
- alert: SecretHubDatabaseDown
  expr: secrethub_db_connections_active == 0
  for: 1m
  annotations:
    summary: "SecretHub cannot connect to PostgreSQL"

# Audit log write failures
- alert: SecretHubAuditLogFailures
  expr: rate(secrethub_audit_logs_failed_total[5m]) > 0.1
  for: 2m
  annotations:
    summary: "Audit log write failures detected"
    description: "{{ $value }} audit log writes failing per second"
```

**High Priority Alerts (Slack Notification):**

```yaml
# High error rate
- alert: SecretHubHighErrorRate
  expr: rate(secrethub_requests_total{status=~"5.."}[5m]) > 0.05
  for: 5m
  annotations:
    summary: "High error rate in SecretHub Core"

# Rotation failures
- alert: SecretHubRotationFailed
  expr: secrethub_rotations_completed_total{status="failed"} > 0
  annotations:
    summary: "Secret rotation failed for {{ $labels.secret_id }}"

# Agent disconnections
- alert: SecretHubAgentDisconnected
  expr: secrethub_agent_connection_status == 0
  for: 5m
  annotations:
    summary: "Agent {{ $labels.agent_id }} disconnected"
```

**Warning Alerts (Email):**

```yaml
# Certificate expiring soon
- alert: SecretHubCertificateExpiringSoon
  expr: secrethub_certificate_expiry_seconds < 604800  # 7 days
  annotations:
    summary: "Certificate {{ $labels.cert_cn }} expires in < 7 days"

# High lease count
- alert: SecretHubHighLeaseCount
  expr: secrethub_leases_active > 10000
  annotations:
    summary: "High number of active leases: {{ $value }}"
```

---

## 9. Security Hardening

### 9.1. Network Security

**TLS Configuration:**
- TLS 1.3 only (disable TLS 1.2 and below)
- Strong cipher suites only:
  - `TLS_AES_256_GCM_SHA384`
  - `TLS_CHACHA20_POLY1305_SHA256`
  - `TLS_AES_128_GCM_SHA256`
- Perfect Forward Secrecy (PFS) mandatory
- OCSP stapling enabled

**mTLS Configuration:**
- Mandatory client certificate authentication
- Certificate pinning for Core→Agent communication
- Short-lived certificates (24-72 hours)
- Automatic rotation before expiry

---

### 9.2. Access Control

**Principle of Least Privilege:**
- Each Agent only has access to secrets explicitly authorized in policy
- Each application only has access to secrets for its specific function
- Admin accounts have role-based permissions (read-only, operator, admin)

**Multi-Factor Authentication:**
- MFA required for all admin operations
- TOTP, WebAuthn, or hardware security keys supported
- Session timeout after 1 hour of inactivity

**Approval Workflows:**
- Sensitive operations require dual approval:
  - Root password rotation
  - Policy changes affecting production
  - Certificate revocation
  - System unsealing

---

### 9.3. Hardening Checklist

**Operating System:**
- [ ] Disable unnecessary services
- [ ] Configure firewall (iptables/nftables)
- [ ] Enable SELinux/AppArmor
- [ ] Regular security updates
- [ ] Disable root SSH access
- [ ] Use sudo with logging

**Application:**
- [ ] Run as non-privileged user
- [ ] Restrict file permissions (0600 for configs)
- [ ] Enable ASLR and stack protection
- [ ] Disable debug endpoints in production
- [ ] Rate limiting on API endpoints (for admin endpoints only)
- [ ] Input validation on all user inputs

**Database:**
- [ ] Encrypt connections (SSL/TLS)
- [ ] Strong authentication
- [ ] Regular backups tested
- [ ] Audit logging enabled
- [ ] Principle of least privilege for database users

---

## 10. Capacity Planning

### 10.1. Core Service Sizing

**Small Deployment (< 100 Agents):**
- **Core Nodes**: 3 nodes
- **CPU**: 2 vCPU per node
- **Memory**: 4 GB per node
- **Database**: PostgreSQL with 2 vCPU, 8 GB RAM, 100 GB SSD
- **Expected Load**: 1,000 requests/minute

**Medium Deployment (100-1,000 Agents):**
- **Core Nodes**: 5 nodes
- **CPU**: 4 vCPU per node
- **Memory**: 8 GB per node
- **Database**: PostgreSQL with 8 vCPU, 32 GB RAM, 500 GB SSD
- **Expected Load**: 10,000 requests/minute

**Large Deployment (1,000+ Agents):**
- **Core Nodes**: 7+ nodes
- **CPU**: 8 vCPU per node
- **Memory**: 16 GB per node
- **Database**: PostgreSQL cluster with 16 vCPU, 64 GB RAM, 1 TB SSD
- **Expected Load**: 100,000+ requests/minute

---

### 10.2. Scaling Strategy

**Horizontal Scaling:**
- Add more Core nodes behind load balancer
- Agents automatically distribute across nodes
- WebSocket connections balanced via consistent hashing

**Database Scaling:**
- Read replicas for audit log queries
- Connection pooling (PgBouncer) for efficient connection management
- Partitioning for audit_logs table by time

**Caching:**
- Agent-side caching reduces Core load by 90%+
- Core-side caching for policies and configurations
- Redis for distributed session management (if needed)

---

## 11. Testing Strategy

### 11.1. Unit Testing

**Core Service:**
- Policy engine logic
- Encryption/decryption functions
- Secret engine implementations
- Audit log hash chain verification

**Agent:**
- Local authentication logic
- Template rendering
- Cache management
- Connection retry logic

---

### 11.2. Integration Testing

**Scenarios:**
- Agent bootstrap and certificate issuance
- Secret retrieval and caching
- Dynamic secret generation and revocation
- Lease renewal and expiry
- Policy enforcement
- Audit log writing and verification

---

### 11.3. Load Testing

**Test Scenarios:**
- 10,000 concurrent Agent connections
- 100,000 secret requests per minute
- 1,000 dynamic secrets generated per minute
- Database failover during load
- Core node failure during load

**Tools:**
- Locust for load generation
- JMeter for WebSocket load testing
- Custom Elixir scripts for protocol-specific testing

---

### 11.4. Security Testing

**Tests:**
- Penetration testing (annual)
- Vulnerability scanning (continuous)
- Fuzzing of API endpoints
- Certificate validation testing
- Audit log tampering detection
- Encryption strength verification

---

## 12. Compliance & Governance

### 12.1. Compliance Frameworks

**SOC 2 Type II:**
- Audit logging of all access
- Encryption at rest and in transit
- Access control and authentication
- Change management procedures
- Incident response plan

**PCI-DSS (if handling payment data):**
- Strong cryptography (AES-256)
- Unique user IDs and authentication
- Restrict access on need-to-know basis
- Track and monitor all access
- Regularly test security systems

**GDPR (if handling EU data):**
- Data encryption
- Audit trails
- Access controls and authentication
- Right to be forgotten (secret deletion)
- Data breach notification procedures

---

### 12.2. Compliance Reporting

**Automated Compliance Reports:**

```elixir
defmodule SecretHub.Compliance.Reports do
  @doc "Generate SOC 2 access control report"
  def soc2_access_control_report(start_date, end_date) do
    %{
      report_type: "SOC 2 - Access Control",
      period: "#{start_date} to #{end_date}",
      sections: [
        %{
          control: "CC6.1 - Logical Access Controls",
          evidence: [
            access_attempts_summary(start_date, end_date),
            failed_access_analysis(start_date, end_date),
            privileged_access_review(start_date, end_date)
          ]
        },
        %{
          control: "CC6.2 - Authentication",
          evidence: [
            mfa_usage_statistics(start_date, end_date),
            authentication_failures(start_date, end_date),
            certificate_issuance_log(start_date, end_date)
          ]
        },
        %{
          control: "CC6.3 - Authorization",
          evidence: [
            policy_changes_log(start_date, end_date),
            unauthorized_access_attempts(start_date, end_date),
            access_reviews_completed(start_date, end_date)
          ]
        }
      ]
    }
  end
  
  @doc "Generate PCI-DSS encryption report"
  def pci_dss_encryption_report do
    %{
      report_type: "PCI-DSS Requirement 3 & 4",
      encryption_at_rest: %{
        algorithm: "AES-256-GCM",
        key_management: "Shamir Secret Sharing + HSM",
        databases_encrypted: true,
        backups_encrypted: true
      },
      encryption_in_transit: %{
        protocol: "TLS 1.3",
        mutual_authentication: true,
        cipher_suites: ["TLS_AES_256_GCM_SHA384"],
        certificate_validity: "24-72 hours"
      },
      key_rotation: %{
        static_secrets: "Monthly or on-demand",
        dynamic_secrets: "1-24 hours TTL",
        certificates: "Auto-renewed before expiry"
      }
    }
  end
  
  @doc "Generate access activity summary for auditor"
  def auditor_access_summary(entity_type, entity_id, months \\ 3) do
    start_date = Date.utc_today() |> Date.add(-months * 30)
    
    %{
      entity_type: entity_type,
      entity_id: entity_id,
      reporting_period: "Last #{months} months",
      total_accesses: count_accesses(entity_id, start_date),
      unique_secrets_accessed: count_unique_secrets(entity_id, start_date),
      failed_attempts: count_failed_accesses(entity_id, start_date),
      after_hours_accesses: count_after_hours(entity_id, start_date),
      geographic_locations: list_access_locations(entity_id, start_date),
      policy_violations: list_violations(entity_id, start_date)
    }
  end
end
```

**Quarterly Compliance Review Checklist:**
- [ ] Review all policy changes
- [ ] Audit certificate issuances and revocations
- [ ] Verify backup restoration procedures
- [ ] Review failed access attempts and responses
- [ ] Verify encryption key rotation logs
- [ ] Review privileged access logs
- [ ] Test incident response procedures
- [ ] Update security documentation

---

### 12.3. Data Retention Policies

**Secret Data:**
- **Active Secrets**: Retained while in use
- **Rotated/Deprecated Secrets**: 90 days after rotation
- **Deleted Secrets**: Marked deleted but retained in audit for 30 days, then permanently purged

**Audit Logs:**
- **Hot Storage (PostgreSQL)**: 30 days
- **Warm Storage (S3/GCS)**: 1 year
- **Cold Storage (Glacier)**: 7 years (configurable per compliance requirements)
- **Permanent Deletion**: After retention period, securely deleted with verification

**Certificate Records:**
- **Active Certificates**: Retained while valid
- **Expired Certificates**: 1 year after expiry
- **Revoked Certificates**: 7 years (for non-repudiation)

**Backup Data:**
- **Daily Backups**: 30 days
- **Monthly Backups**: 12 months
- **Yearly Backups**: 7 years

---

## 13. Operational Procedures

### 13.1. Initial Deployment

**Step 1: Infrastructure Setup**
```bash
# 1. Provision infrastructure
terraform apply -var-file=production.tfvars

# 2. Deploy PostgreSQL cluster
kubectl apply -f k8s/postgres/

# 3. Wait for database ready
kubectl wait --for=condition=ready pod -l app=postgres -n secrethub-system
```

**Step 2: Core Service Initialization**
```bash
# 1. Deploy Core services (starts in sealed state)
kubectl apply -f k8s/core/

# 2. Initialize Core (generates root key and unseal shards)
kubectl exec -it secrethub-core-0 -- /opt/secrethub/bin/secrethub_core init
# Output: 5 unseal keys and root token (SAVE SECURELY!)

# 3. Unseal Core (requires 3 of 5 keys)
kubectl exec -it secrethub-core-0 -- /opt/secrethub/bin/secrethub_core unseal <key-1>
kubectl exec -it secrethub-core-0 -- /opt/secrethub/bin/secrethub_core unseal <key-2>
kubectl exec -it secrethub-core-0 -- /opt/secrethub/bin/secrethub_core unseal <key-3>

# 4. Verify unsealed
curl https://secrethub-core.example.com/health/ready
# Expected: 200 OK
```

**Step 3: PKI Setup**
```bash
# 1. Generate root CA
curl -X POST https://secrethub-core.example.com/v1/pki/ca/root/generate \
  -H "X-SecretHub-Token: $ROOT_TOKEN" \
  -d '{
    "common_name": "SecretHub Root CA",
    "ttl": "87600h"
  }'

# 2. Generate intermediate CA
curl -X POST https://secrethub-core.example.com/v1/pki/ca/intermediate/generate \
  -H "X-SecretHub-Token: $ROOT_TOKEN" \
  -d '{
    "common_name": "SecretHub Intermediate CA - Production",
    "ttl": "43800h"
  }'
```

**Step 4: Configure Authentication Backends**
```bash
# Configure AppRole authentication
curl -X POST https://secrethub-core.example.com/v1/auth/approle/enable \
  -H "X-SecretHub-Token: $ROOT_TOKEN"

# Configure Kubernetes authentication
curl -X POST https://secrethub-core.example.com/v1/auth/kubernetes/enable \
  -H "X-SecretHub-Token: $ROOT_TOKEN" \
  -d '{
    "kubernetes_host": "https://kubernetes.default.svc",
    "kubernetes_ca_cert": "...",
    "token_reviewer_jwt": "..."
  }'
```

**Step 5: Deploy First Agent**
```bash
# 1. Create AppRole for agent
curl -X POST https://secrethub-core.example.com/v1/auth/approle/role/webapp-prod \
  -H "X-SecretHub-Token: $ROOT_TOKEN" \
  -d '{
    "policies": ["webapp-prod-policy"],
    "secret_id_ttl": "10m",
    "token_ttl": "1h"
  }'

# 2. Generate RoleID and SecretID
ROLE_ID=$(curl -X GET https://secrethub-core.example.com/v1/auth/approle/role/webapp-prod/role-id)
SECRET_ID=$(curl -X POST https://secrethub-core.example.com/v1/auth/approle/role/webapp-prod/secret-id)

# 3. Deploy agent with credentials
kubectl create secret generic webapp-prod-approle \
  --from-literal=role-id=$ROLE_ID \
  --from-literal=secret-id=$SECRET_ID \
  -n production

kubectl apply -f k8s/apps/webapp-prod.yaml
```

---

### 13.2. Unsealing Procedures

**Automated Unsealing (Production):**
```elixir
# Configure cloud KMS auto-unseal
# config/prod.exs
config :secrethub, :unseal,
  type: :aws_kms,
  kms_key_id: "arn:aws:kms:us-east-1:123456789012:key/abc-123",
  region: "us-east-1"
```

**Manual Unsealing (Emergency):**
```bash
# Unsealing Ceremony Procedure
# Requires 3 of 5 keyholders present

# Keyholder 1
secrethub-core unseal
# Enter unseal key 1: [KEYHOLDER ENTERS KEY]

# Keyholder 2
secrethub-core unseal
# Enter unseal key 2: [KEYHOLDER ENTERS KEY]

# Keyholder 3
secrethub-core unseal
# Enter unseal key 3: [KEYHOLDER ENTERS KEY]

# Verify unsealed
secrethub-core status
# Expected: Sealed: false
```

**Unsealing via Web UI:**
1. Navigate to `https://secrethub.example.com`
2. Click "Unseal"
3. Three authorized operators enter their unseal keys
4. System transitions to unsealed state
5. All events logged in audit log

---

### 13.3. Backup & Restore Procedures

**Daily Backup Procedure:**
```bash
#!/bin/bash
# /opt/secrethub/scripts/backup.sh

DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/backup/secrethub"
S3_BUCKET="s3://secrethub-backups"

# 1. Create PostgreSQL backup
pg_dump -h postgres.secrethub.svc -U secrethub secrethub_db | \
  gzip > "$BACKUP_DIR/secrethub-db-$DATE.sql.gz"

# 2. Encrypt backup
openssl enc -aes-256-cbc -salt \
  -in "$BACKUP_DIR/secrethub-db-$DATE.sql.gz" \
  -out "$BACKUP_DIR/secrethub-db-$DATE.sql.gz.enc" \
  -pass file:/etc/secrethub/backup-key

# 3. Upload to S3
aws s3 cp "$BACKUP_DIR/secrethub-db-$DATE.sql.gz.enc" \
  "$S3_BUCKET/daily/$DATE/"

# 4. Verify backup integrity
aws s3api head-object --bucket secrethub-backups \
  --key "daily/$DATE/secrethub-db-$DATE.sql.gz.enc"

# 5. Clean old local backups (keep 7 days)
find "$BACKUP_DIR" -name "*.enc" -mtime +7 -delete

# 6. Log backup completion
echo "$(date): Backup completed successfully: $DATE" >> /var/log/secrethub-backup.log
```

**Restore Procedure:**
```bash
#!/bin/bash
# /opt/secrethub/scripts/restore.sh

if [ -z "$1" ]; then
  echo "Usage: $0 <backup-date>"
  exit 1
fi

BACKUP_DATE=$1
S3_BUCKET="s3://secrethub-backups"
RESTORE_DIR="/restore/secrethub"

# 1. Download backup from S3
aws s3 cp "$S3_BUCKET/daily/$BACKUP_DATE/secrethub-db-$BACKUP_DATE.sql.gz.enc" \
  "$RESTORE_DIR/"

# 2. Decrypt backup
openssl enc -aes-256-cbc -d \
  -in "$RESTORE_DIR/secrethub-db-$BACKUP_DATE.sql.gz.enc" \
  -out "$RESTORE_DIR/secrethub-db-$BACKUP_DATE.sql.gz" \
  -pass file:/etc/secrethub/backup-key

# 3. Decompress
gunzip "$RESTORE_DIR/secrethub-db-$BACKUP_DATE.sql.gz"

# 4. Stop Core services
kubectl scale deployment secrethub-core --replicas=0 -n secrethub-system

# 5. Restore database
psql -h postgres.secrethub.svc -U secrethub secrethub_db < \
  "$RESTORE_DIR/secrethub-db-$BACKUP_DATE.sql"

# 6. Verify restoration
psql -h postgres.secrethub.svc -U secrethub -d secrethub_db \
  -c "SELECT COUNT(*) FROM secrets;"

# 7. Restart Core services
kubectl scale deployment secrethub-core --replicas=3 -n secrethub-system

# 8. Unseal Core services
# (Follow unsealing procedure)

echo "Restore completed successfully"
```

---

### 13.4. Secret Rotation Procedures

**Manual Static Secret Rotation:**
```bash
# 1. Generate new secret value
NEW_SECRET=$(openssl rand -base64 32)

# 2. Create new version
curl -X POST https://secrethub-core.example.com/v1/secrets/static/prod.api.stripe.secret-key \
  -H "X-SecretHub-Token: $ADMIN_TOKEN" \
  -d "{
    \"value\": \"$NEW_SECRET\",
    \"rotation_reason\": \"Scheduled monthly rotation\"
  }"

# 3. Verify agents received notification
curl https://secrethub-core.example.com/v1/audit/search \
  -H "X-SecretHub-Token: $ADMIN_TOKEN" \
  -d '{
    "event_type": "secrets:rotated",
    "secret_id": "prod.api.stripe.secret-key",
    "time_range": "last_5_minutes"
  }'

# 4. Monitor application health
# Wait 5 minutes for all agents to fetch new secret

# 5. Deprecate old version
curl -X POST https://secrethub-core.example.com/v1/secrets/static/prod.api.stripe.secret-key/deprecate \
  -H "X-SecretHub-Token: $ADMIN_TOKEN" \
  -d '{"version": 5}'
```

**Emergency Secret Rotation:**
```bash
# When secret is compromised, immediate rotation required

# 1. Rotate secret immediately
curl -X POST https://secrethub-core.example.com/v1/secrets/static/prod.api.stripe.secret-key/rotate \
  -H "X-SecretHub-Token: $ADMIN_TOKEN" \
  -d '{
    "rotation_type": "emergency",
    "reason": "Secret compromised - detected in public GitHub repo",
    "grace_period": "0m"
  }'

# 2. Invalidate old version immediately (no grace period)
# 3. Trigger application restarts to fetch new secret
# 4. Update external system (e.g., Stripe API key)
# 5. File incident report
```

---

### 13.5. Agent Certificate Renewal

**Automatic Renewal (Normal Operation):**
```
Agent monitors certificate expiry
  └─> At 50% of TTL remaining:
      ├─> Generate new CSR
      ├─> Send to Core via authenticated WebSocket
      ├─> Core validates agent identity
      ├─> Core signs new certificate
      ├─> Agent receives new certificate
      └─> Agent performs hitless cutover:
          ├─> Establish new WebSocket with new cert
          ├─> Transfer all active leases to new connection
          └─> Close old WebSocket gracefully
```

**Manual Certificate Renewal:**
```bash
# If automatic renewal fails

# 1. SSH to agent host
ssh admin@agent-host

# 2. Trigger manual renewal
sudo secrethub-agent renew-certificate

# 3. Verify new certificate
sudo secrethub-agent status
# Expected: Certificate valid until: 2025-10-21

# 4. Check audit log for renewal event
curl https://secrethub-core.example.com/v1/audit/search \
  -d '{
    "event_type": "auth.agent_certificate_issued",
    "agent_id": "agent-prod-01"
  }'
```

---

### 13.6. Incident Response Procedures

**Incident Classification:**

| Severity | Definition | Response Time | Examples |
|----------|------------|---------------|----------|
| P0 - Critical | Complete service outage | 15 minutes | All Core nodes down, database failure |
| P1 - High | Partial service degradation | 1 hour | Single Core node down, certificate expiry |
| P2 - Medium | Limited impact | 4 hours | Agent disconnection, audit log delay |
| P3 - Low | Minimal impact | Next business day | Single failed rotation, cache miss spike |

**P0 Incident Response - Complete Outage:**

```
1. Acknowledge incident (PagerDuty)
2. Assemble incident response team
3. Create incident war room (Slack/Teams)
4. Begin status page updates

Investigation:
  ├─> Check Core service status: kubectl get pods -n secrethub-system
  ├─> Check database connectivity: psql -h postgres.secrethub.svc
  ├─> Review recent changes: git log --since="1 hour ago"
  └─> Check cloud provider status

Mitigation:
  ├─> If database down: Failover to replica
  ├─> If Core sealed: Execute unsealing procedure
  ├─> If configuration issue: Rollback deployment
  └─> If infrastructure issue: Failover to secondary region

Recovery:
  ├─> Verify all services healthy
  ├─> Test critical flows (agent connection, secret retrieval)
  ├─> Monitor for 30 minutes
  └─> Update status page

Post-Incident:
  ├─> Write incident report within 24 hours
  ├─> Schedule blameless post-mortem
  ├─> Identify action items
  └─> Update runbooks
```

**Security Incident - Suspected Compromise:**

```
1. Immediately revoke suspected compromised certificates
2. Rotate all potentially exposed secrets
3. Review audit logs for unauthorized access
4. Isolate affected systems
5. Notify security team and management
6. Engage forensics team if needed
7. File incident report with timestamps
8. Update security procedures based on findings
```

---

## 14. Roadmap & Future Enhancements

### Phase 1: MVP (Months 1-3)
- [x] Core service with basic PKI
- [x] Agent with mTLS authentication
- [x] Static secret storage and retrieval
- [x] Basic policy engine
- [x] Web UI for administration
- [x] PostgreSQL dynamic secret engine
- [x] Comprehensive audit logging
- [x] Manual unsealing

### Phase 2: Production Hardening (Months 4-5)
- [ ] Auto-unsealing with cloud KMS
- [ ] High availability deployment
- [ ] Agent local caching with fallback
- [ ] Redis dynamic secret engine
- [ ] Static secret rotation (AWS IAM, database passwords)
- [ ] Distributed tracing integration
- [ ] Load testing and optimization
- [ ] Security audit and penetration testing

### Phase 3: Advanced Features (Months 6-8)
- [ ] Multiple authentication backends (LDAP, OIDC)
- [ ] Multi-tenancy support
- [ ] Advanced policy engine (time/geo restrictions)
- [ ] Secret versioning with rollback
- [ ] Approval workflows for sensitive operations
- [ ] Kubernetes operator for declarative management
- [ ] Terraform provider
- [ ] CLI tool for developers

### Phase 4: Enterprise Features (Months 9-12)
- [ ] Multi-region active-active deployment
- [ ] Secrets replication across regions
- [ ] Advanced anomaly detection with ML
- [ ] Integration with SIEM systems (Splunk, QRadar)
- [ ] Compliance automation (SOC 2, PCI-DSS reports)
- [ ] Custom secret engines plugin system
- [ ] GraphQL API
- [ ] Mobile app for emergency access

### Future Considerations
- Blockchain-based audit log for enhanced tamper-evidence
- Hardware Security Module (HSM) integration
- Quantum-resistant cryptography
- Zero-knowledge proof for secret access
- Browser extension for developer access
- IDE plugins (VSCode, IntelliJ)

---

## 15. Migration Strategy

### 15.1. Migration from HashiCorp Vault

**Pre-Migration:**
1. Audit current Vault usage (policies, secrets, engines)
2. Map Vault paths to SecretHub IDs
3. Identify all applications and agents
4. Create migration plan with rollback procedures

**Migration Steps:**

```bash
# 1. Export secrets from Vault
vault kv export -format=json secret/ > vault-export.json

# 2. Transform to SecretHub format
python3 transform-vault-to-secrethub.py vault-export.json > secrethub-import.json

# 3. Import to SecretHub
curl -X POST https://secrethub-core.example.com/v1/secrets/bulk-import \
  -H "X-SecretHub-Token: $ADMIN_TOKEN" \
  -d @secrethub-import.json

# 4. Deploy agents alongside Vault agents (dual-run)
# 5. Gradually switch applications to SecretHub agents
# 6. Monitor for 2 weeks
# 7. Decommission Vault agents
# 8. Decommission Vault infrastructure
```

**Rollback Plan:**
- Keep Vault running for 30 days post-migration
- Document rollback procedures for each application
- Automated health checks to detect issues
- Immediate rollback trigger if > 5% error rate

---

### 15.2. Migration from AWS Secrets Manager

**Comparison:**

| Feature | AWS Secrets Manager | SecretHub |
|---------|-------------------|-----------|
| Deployment | Managed service | Self-hosted |
| Cost | ~$0.40/secret/month | Infrastructure cost only |
| Dynamic secrets | Limited | Full support |
| Multi-cloud | No | Yes |
| Audit granularity | CloudTrail | Comprehensive built-in |
| mTLS | No | Yes |
| On-premises | No | Yes |

**Migration Strategy:**
- Use SecretHub for new applications
- Gradually migrate existing secrets
- Dual-run during transition period
- Keep AWS Secrets Manager for AWS-native integrations

---

## 16. Cost Analysis

### 16.1. Infrastructure Costs (AWS Example)

**Small Deployment (< 100 Agents):**
```
Core Cluster:
  - 3x t3.medium (2 vCPU, 4GB) = $75/month
  - Application Load Balancer = $25/month
Database:
  - RDS PostgreSQL db.t3.medium = $65/month
  - Storage (100GB) = $12/month
  - Backups (100GB) = $10/month
Storage:
  - S3 for audit logs (500GB/month) = $12/month
  - S3 Glacier (5TB archive) = $20/month
Networking:
  - Data transfer = $20/month
------------------------
Total: ~$239/month
```

**Medium Deployment (100-1,000 Agents):**
```
Core Cluster:
  - 5x t3.xlarge (4 vCPU, 16GB) = $625/month
  - Application Load Balancer = $25/month
Database:
  - RDS PostgreSQL db.m5.2xlarge = $560/month
  - Multi-AZ = +100% = $560/month
  - Storage (500GB) = $58/month
  - Backups (500GB) = $50/month
Storage:
  - S3 for audit logs (5TB/month) = $120/month
  - S3 Glacier (50TB archive) = $200/month
Networking:
  - Data transfer = $100/month
------------------------
Total: ~$2,298/month
```

### 16.2. Operational Costs

**Personnel:**
- Platform Engineer (maintenance): 0.2 FTE = ~$30k/year
- Security Engineer (audits): 0.1 FTE = ~$15k/year
- On-call rotation: 4 engineers, 1 week/month = ~$20k/year

**Total Operational Cost:**
- Infrastructure: $2,298/month ($27,576/year)
- Personnel: $65,000/year
- **Total: ~$92,576/year for medium deployment**

**Cost per Secret:**
- Assuming 10,000 secrets: $9.26/secret/year
- Significantly lower than managed services at scale

---

## 17. Glossary

**Agent**: Local daemon deployed alongside applications to securely fetch and deliver secrets

**AppRole**: Authentication method using RoleID and SecretID for machine authentication

**Certificate Authority (CA)**: System component that issues and manages TLS certificates

**Core**: Central service cluster that manages secrets, policies, and authentication

**Dynamic Secret**: Temporary credential generated on-demand with short TTL

**Lease**: Time-bound access grant for a dynamic secret

**mTLS**: Mutual TLS authentication where both client and server present certificates

**PKI**: Public Key Infrastructure for certificate management

**Policy**: Set of rules defining which entities can access which secrets

**Seal/Unseal**: Security mechanism where Core service requires manual unsealing to decrypt data

**Secret Engine**: Plugin that generates or manages secrets (dynamic or static)

**Shamir Secret Sharing**: Cryptographic algorithm to split a secret into multiple shares

**Static Secret**: Long-lived credential stored in SecretHub (API keys, passwords)

**Unix Domain Socket (UDS)**: IPC mechanism for local communication between Agent and applications

---

## 18. References & Resources

### Documentation
- [Elixir/Phoenix Documentation](https://hexdocs.pm/phoenix/)
- [PostgreSQL Security Guide](https://www.postgresql.org/docs/current/security.html)
- [mTLS Best Practices](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/)
- [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)

### Standards & Compliance
- [NIST Cryptographic Standards](https://csrc.nist.gov/)
- [SOC 2 Framework](https://www.aicpa.org/soc-2)
- [PCI-DSS Requirements](https://www.pcisecuritystandards.org/)
- [GDPR Compliance Guide](https://gdpr.eu/)

### Security Research
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [CWE-798: Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

### Similar Projects
- HashiCorp Vault
- AWS Secrets Manager
- Google Secret Manager
- CyberArk Conjur

---

## Appendix A: Configuration Examples

### A.1. Core Service Configuration

```elixir
# config/prod.exs
import Config

config :secrethub, SecretHub.Endpoint,
  url: [host: "secrethub-core.example.com", port: 443, scheme: "https"],
  http: [
    port: 4000,
    transport_options: [socket_opts: [:inet6]]
  ],
  https: [
    port: 4001,
    cipher_suite: :strong,
    certfile: "/etc/secrethub/tls/cert.pem",
    keyfile: "/etc/secrethub/tls/key.pem",
    cacertfile: "/etc/secrethub/tls/ca.pem",
    verify: :verify_peer,
    fail_if_no_peer_cert: true
  ]

config :secrethub, SecretHub.Repo,
  username: System.get_env("DB_USERNAME"),
  password: System.get_env("DB_PASSWORD"),
  hostname: System.get_env("DB_HOSTNAME"),
  database: "secrethub_prod",
  pool_size: 20,
  ssl: true,
  ssl_opts: [
    verify: :verify_peer,
    cacertfile: "/etc/secrethub/db-ca.pem"
  ]

config :secrethub, :unseal,
  type: :aws_kms,
  kms_key_id: System.get_env("KMS_KEY_ID"),
  region: "us-east-1"

config :secrethub, :audit,
  enabled: true,
  backends: [:postgresql, :file, :siem],
  file_path: "/var/log/secrethub/audit.log",
  siem_endpoint: System.get_env("SIEM_ENDPOINT")

config :secrethub, :pki,
  root_ca_ttl: "87600h",  # 10 years
  intermediate_ca_ttl: "43800h",  # 5 years
  cert_default_ttl: "72h",  # 3 days
  cert_max_ttl: "720h",  # 30 days
  ocsp_enabled: true

config :logger, level: :info

config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id, :agent_id, :event_type]
```

---

### A.2. Agent Configuration

```json
{
  "version": "2.0",
  "agent": {
    "id": "agent-k8s-prod-01",
    "hostname": "webapp-frontend-abc123",
    "environment": "production"
  },
  "core": {
    "endpoints": [
      "wss://secrethub-core-1.example.com:443",
      "wss://secrethub-core-2.example.com:443",
      "wss://secrethub-core-3.example.com:443"
    ],
    "ca_cert": "/etc/secrethub/ca.pem",
    "connection": {
      "retry_attempts": 10,
      "retry_backoff_max": "60s",
      "heartbeat_interval": "30s",
      "reconnect_on_heartbeat_failure": true
    }
  },
  "authentication": {
    "method": "kubernetes",
    "role": "webapp-frontend-prod",
    "service_account_token_path": "/var/run/secrets/kubernetes.io/serviceaccount/token"
  },
  "cache": {
    "enabled": true,
    "memory_cache": {
      "max_size_mb": 128,
      "eviction_policy": "lru"
    },
    "disk_cache": {
      "enabled": true,
      "path": "/var/cache/secrethub",
      "encryption": true
    },
    "ttl": {
      "static_secrets": "infinity",
      "dynamic_secrets": "lease_duration_minus_5m",
      "policies": "5m"
    }
  },
  "local_server": {
    "socket_path": "/var/run/secrethub-agent.sock",
    "socket_permissions": "0600",
          "authentication": {
      "method": "mtls",
      "ca_cert": "/etc/secrethub/app-ca.pem"
    }
  },
  "sinks": [
    {
      "name": "database-config",
      "template": "/etc/secrethub/templates/database.yml.tmpl",
      "destination": "/app/config/database.yml",
      "permissions": "0600",
      "owner": "app:app",
      "reload": {
        "method": "signal",
        "target": "webapp",
        "signal": "SIGHUP"
      },
      "secrets_required": [
        "prod.db.postgres.webapp.password",
        "prod.db.redis.cache.password"
      ]
    },
    {
      "name": "api-keys",
      "template": "/etc/secrethub/templates/api-keys.env.tmpl",
      "destination": "/app/.env",
      "permissions": "0400",
      "reload": {
        "method": "http",
        "url": "http://localhost:8080/admin/reload",
        "method": "POST",
        "headers": {
          "X-Admin-Token": "{{ secrets.prod.admin.reload-token }}"
        }
      }
    }
  ],
  "monitoring": {
    "metrics_enabled": true,
    "metrics_port": 9090,
    "health_check_port": 9091,
    "log_level": "info",
    "log_format": "json"
  }
}
```

---

### A.3. Policy Example

```json
{
  "policy_id": "webapp-frontend-prod-policy",
  "version": "1.0",
  "description": "Policy for webapp-frontend production application",
  "bindings": [
    {
      "entity_type": "agent",
      "entity_id": "agent-k8s-prod-01",
      "certificate_fingerprint": "sha256:abc123..."
    }
  ],
  "rules": [
    {
      "path": "prod.db.postgres.webapp.*",
      "capabilities": ["read"],
      "allowed_operations": ["get", "renew"],
      "conditions": {
        "time_of_day": "00:00-23:59",
        "max_ttl": "2h",
        "min_ttl": "5m"
      }
    },
    {
      "path": "prod.db.redis.cache.*",
      "capabilities": ["read"],
      "allowed_operations": ["get", "renew"],
      "conditions": {
        "max_ttl": "4h"
      }
    },
    {
      "path": "prod.api.payment-gateway.apikey",
      "capabilities": ["read"],
      "allowed_operations": ["get"],
      "conditions": {
        "require_mfa": false,
        "audit_level": "high"
      }
    }
  ],
  "deny_rules": [
    {
      "path": "prod.db.postgres.*.root",
      "reason": "Applications cannot access root credentials"
    },
    {
      "path": "*.admin.*",
      "reason": "Applications cannot access admin secrets"
    }
  ]
}
```

---

### A.4. Template Example

```yaml
# /etc/secrethub/templates/database.yml.tmpl
# Database configuration template for Rails application

default: &default
  adapter: postgresql
  encoding: unicode
  pool: <%= ENV['DB_POOL'] || 5 %>
  timeout: 5000

production:
  <<: *default
  host: {{ secrets.prod.db.postgres.webapp.host }}
  port: {{ secrets.prod.db.postgres.webapp.port }}
  database: {{ secrets.prod.db.postgres.webapp.database }}
  username: {{ secrets.prod.db.postgres.webapp.username }}
  password: {{ secrets.prod.db.postgres.webapp.password }}
  
  # Connection pooling
  pool: 25
  checkout_timeout: 5
  
  # SSL configuration
  sslmode: require
  sslcert: /etc/ssl/certs/client-cert.pem
  sslkey: /etc/ssl/private/client-key.pem
  sslrootcert: /etc/ssl/certs/server-ca.pem

redis:
  url: redis://{{ secrets.prod.db.redis.cache.username }}:{{ secrets.prod.db.redis.cache.password }}@redis.prod.svc.cluster.local:6379/0
  timeout: 5
  connect_timeout: 5
  reconnect_attempts: 3
  
# Metadata for SecretHub
# secrets_version: {{ metadata.version }}
# last_updated: {{ metadata.timestamp }}
# rotated_by: {{ metadata.actor }}
```

---

## Appendix B: API Reference

### B.1. Authentication API

#### Bootstrap Agent with AppRole

```http
POST /v1/auth/bootstrap/approle
Content-Type: application/json

{
  "role_id": "abc-123-def-456",
  "secret_id": "xyz-789-uvw-012"
}

Response 200:
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "ca_chain": ["-----BEGIN CERTIFICATE-----\n..."],
  "expires_at": "2025-10-21T10:00:00Z",
  "agent_id": "agent-prod-01",
  "websocket_url": "wss://secrethub-core.example.com:4001/agent/ws"
}
```

#### Bootstrap Agent with Kubernetes

```http
POST /v1/auth/bootstrap/kubernetes
Content-Type: application/json

{
  "jwt": "<kubernetes-service-account-token>",
  "role": "webapp-frontend-prod"
}

Response 200:
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "ca_chain": ["-----BEGIN CERTIFICATE-----\n..."],
  "expires_at": "2025-10-21T10:00:00Z",
  "agent_id": "agent-k8s-prod-webapp-abc123",
  "websocket_url": "wss://secrethub-core.example.com:4001/agent/ws"
}
```

---

### B.2. Secrets API

#### Get Static Secret

```http
GET /v1/secrets/static/prod.api.stripe.secret-key
X-SecretHub-Token: <admin-token>

Response 200:
{
  "secret_id": "prod.api.stripe.secret-key",
  "value": "<encrypted-secret-value>",
  "version": 3,
  "metadata": {
    "created_at": "2025-10-01T00:00:00Z",
    "created_by": "admin-user",
    "last_rotated": "2025-10-15T12:00:00Z",
    "rotation_reason": "Scheduled monthly rotation",
    "tags": {
      "environment": "production",
      "service": "billing",
      "criticality": "high"
    }
  }
}
```

#### Create Static Secret

```http
POST /v1/secrets/static/prod.api.stripe.secret-key
Content-Type: application/json
X-SecretHub-Token: <admin-token>

{
  "value": "sk_live_abc123...",
  "metadata": {
    "tags": {
      "environment": "production",
      "service": "billing"
    }
  }
}

Response 201:
{
  "secret_id": "prod.api.stripe.secret-key",
  "version": 1,
  "created_at": "2025-10-18T10:00:00Z"
}
```

#### Generate Dynamic Secret

```http
POST /v1/secrets/dynamic/prod.db.postgres.webapp.readonly
Content-Type: application/json
X-SecretHub-Token: <agent-token>

{
  "ttl": "1h"
}

Response 200:
{
  "lease_id": "lease-abc-123",
  "lease_duration": 3600,
  "renewable": true,
  "data": {
    "username": "v-agent-prod-01-readonly-abc123",
    "password": "randomly-generated-password",
    "host": "postgres.prod.svc.cluster.local",
    "port": 5432,
    "database": "webapp_db"
  },
  "warnings": null
}
```

#### Renew Lease

```http
POST /v1/leases/renew
Content-Type: application/json
X-SecretHub-Token: <agent-token>

{
  "lease_id": "lease-abc-123",
  "increment": 3600
}

Response 200:
{
  "lease_id": "lease-abc-123",
  "lease_duration": 3600,
  "renewable": true
}
```

#### Revoke Lease

```http
POST /v1/leases/revoke
Content-Type: application/json
X-SecretHub-Token: <agent-token>

{
  "lease_id": "lease-abc-123"
}

Response 204: No Content
```

---

### B.3. PKI API

#### Sign Certificate Request

```http
POST /v1/pki/sign-request
Content-Type: application/json
X-SecretHub-Token: <agent-token>

{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "common_name": "webapp-frontend-prod",
  "ttl": "72h",
  "alt_names": ["webapp.prod.svc.cluster.local"],
  "ip_sans": ["10.0.1.50"]
}

Response 200:
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "issuing_ca": "-----BEGIN CERTIFICATE-----\n...",
  "ca_chain": ["-----BEGIN CERTIFICATE-----\n..."],
  "serial_number": "4d:c9:1f:2e:a3:b4:7c:8d",
  "expiration": "2025-10-21T10:00:00Z"
}
```

#### Revoke Certificate

```http
POST /v1/pki/revoke
Content-Type: application/json
X-SecretHub-Token: <admin-token>

{
  "serial_number": "4d:c9:1f:2e:a3:b4:7c:8d",
  "reason": "key_compromise"
}

Response 200:
{
  "revocation_time": "2025-10-18T10:00:00Z",
  "revocation_time_rfc3339": "2025-10-18T10:00:00Z"
}
```

---

### B.4. Audit API

#### Search Audit Logs

```http
POST /v1/audit/search
Content-Type: application/json
X-SecretHub-Token: <admin-token>

{
  "event_type": "secret.accessed",
  "secret_id": "prod.api.stripe.secret-key",
  "start_time": "2025-10-01T00:00:00Z",
  "end_time": "2025-10-18T23:59:59Z",
  "limit": 100
}

Response 200:
{
  "total": 150,
  "results": [
    {
      "event_id": "evt-123",
      "timestamp": "2025-10-18T10:00:00Z",
      "event_type": "secret.accessed",
      "agent_id": "agent-prod-01",
      "app_id": "webapp-frontend-prod",
      "secret_id": "prod.api.stripe.secret-key",
      "access_granted": true,
      "policy_matched": "webapp-frontend-prod-policy",
      "source_ip": "10.0.1.50"
    }
  ]
}
```

#### Generate Compliance Report

```http
POST /v1/audit/compliance-report
Content-Type: application/json
X-SecretHub-Token: <admin-token>

{
  "report_type": "soc2_access_control",
  "start_date": "2025-07-01",
  "end_date": "2025-09-30",
  "format": "pdf"
}

Response 200:
{
  "report_id": "report-q3-2025",
  "download_url": "/v1/audit/reports/report-q3-2025.pdf",
  "expires_at": "2025-10-25T00:00:00Z"
}
```

---

### B.5. Policy API

#### Create Policy

```http
POST /v1/policies
Content-Type: application/json
X-SecretHub-Token: <admin-token>

{
  "name": "webapp-frontend-prod-policy",
  "description": "Production policy for webapp frontend",
  "rules": [
    {
      "path": "prod.db.postgres.webapp.*",
      "capabilities": ["read"],
      "conditions": {
        "max_ttl": "2h"
      }
    }
  ]
}

Response 201:
{
  "policy_id": "policy-123",
  "name": "webapp-frontend-prod-policy",
  "created_at": "2025-10-18T10:00:00Z"
}
```

#### Bind Policy to Entity

```http
POST /v1/policies/policy-123/bind
Content-Type: application/json
X-SecretHub-Token: <admin-token>

{
  "entity_type": "agent",
  "entity_id": "agent-k8s-prod-01",
  "certificate_fingerprint": "sha256:abc123..."
}

Response 200:
{
  "binding_id": "binding-456",
  "policy_id": "policy-123",
  "entity_id": "agent-k8s-prod-01",
  "bound_at": "2025-10-18T10:00:00Z"
}
```

---

## Appendix C: Troubleshooting Guide

### C.1. Common Issues

#### Issue: Core Service Sealed After Restart

**Symptoms:**
- HTTP 503 on `/health/ready`
- Logs show: "Core is sealed"
- Agents cannot connect

**Solution:**
```bash
# 1. Check seal status
secrethub-core status

# 2. Unseal with 3 keys
secrethub-core unseal <key-1>
secrethub-core unseal <key-2>
secrethub-core unseal <key-3>

# 3. Verify unsealed
curl https://secrethub-core.example.com/health/ready
# Expected: 200 OK

# 4. If using cloud KMS, check KMS permissions
aws kms describe-key --key-id <kms-key-id>
```

**Prevention:**
- Enable auto-unsealing with cloud KMS for production
- Document unseal key locations
- Test unseal procedure quarterly

---

#### Issue: Agent Cannot Connect to Core

**Symptoms:**
- Agent logs show: "Connection refused" or "TLS handshake failed"
- Applications cannot fetch secrets

**Diagnosis:**
```bash
# 1. Test network connectivity
telnet secrethub-core.example.com 443

# 2. Verify certificate validity
openssl s_client -connect secrethub-core.example.com:443 \
  -cert /etc/secrethub/agent-cert.pem \
  -key /etc/secrethub/agent-key.pem

# 3. Check agent logs
journalctl -u secrethub-agent -f

# 4. Verify Core service is running
kubectl get pods -n secrethub-system -l app=secrethub-core
```

**Common Causes:**
- Expired agent certificate → Renew certificate
- Network firewall blocking connection → Check firewall rules
- Core service scaled to 0 → Scale up Core deployment
- Invalid agent credentials → Re-bootstrap agent

---

#### Issue: Dynamic Secret Generation Fails

**Symptoms:**
- Agent returns error: "Failed to generate secret"
- Audit log shows failed secret generation attempts

**Diagnosis:**
```bash
# 1. Check secret engine configuration
curl https://secrethub-core.example.com/v1/engines/postgresql/config \
  -H "X-SecretHub-Token: $ADMIN_TOKEN"

# 2. Test database connection from Core
kubectl exec -it secrethub-core-0 -- psql -h postgres.prod -U root -d webapp_db -c "SELECT 1"

# 3. Review Core logs for errors
kubectl logs -n secrethub-system secrethub-core-0 | grep "ERROR"
```

**Common Causes:**
- Database credentials incorrect → Update engine configuration
- Database max connections reached → Increase max_connections
- Insufficient privileges → Grant CREATE USER to SecretHub database user
- Network connectivity issue → Check security groups/firewall

---

#### Issue: Audit Logs Not Being Written

**Symptoms:**
- Audit log table not updating
- No new entries in `/var/log/secrethub/audit.log`

**Diagnosis:**
```bash
# 1. Check audit log configuration
curl https://secrethub-core.example.com/v1/sys/config/audit \
  -H "X-SecretHub-Token: $ADMIN_TOKEN"

# 2. Check PostgreSQL connection
psql -h postgres.secrethub.svc -U secrethub -d secrethub_db \
  -c "SELECT COUNT(*) FROM audit_logs WHERE timestamp > NOW() - INTERVAL '1 hour'"

# 3. Check file permissions
ls -la /var/log/secrethub/
# Expected: -rw------- secrethub secrethub audit.log

# 4. Check disk space
df -h /var/log/secrethub
```

**Solution:**
- If disk full → Clean up old logs, increase disk size
- If permission denied → Fix file ownership: `chown secrethub:secrethub audit.log`
- If database issue → Check connection pooling, increase pool size

---

#### Issue: Secret Rotation Failed

**Symptoms:**
- Scheduled rotation job failed
- Old secret still in use
- Alert: "Rotation failed for secret X"

**Diagnosis:**
```bash
# 1. Check rotation job status
curl https://secrethub-core.example.com/v1/secrets/static/<secret-id>/rotation/status \
  -H "X-SecretHub-Token: $ADMIN_TOKEN"

# 2. Review rotation logs
kubectl logs -n secrethub-system secrethub-core-0 | grep "rotation"

# 3. Test connectivity to target system
# For AWS IAM rotation:
aws iam list-access-keys --user-name billing-service-prod
```

**Common Causes:**
- External API unreachable → Check network connectivity
- Insufficient permissions → Verify IAM role/credentials
- Grace period too short → Extend grace period
- Target system rate limiting → Add backoff, reduce rotation frequency

**Recovery:**
```bash
# Manual rotation
curl -X POST https://secrethub-core.example.com/v1/secrets/static/<secret-id>/rotate \
  -H "X-SecretHub-Token: $ADMIN_TOKEN" \
  -d '{"force": true}'
```

---

### C.2. Performance Issues

#### Issue: High Latency on Secret Retrieval

**Diagnosis:**
```bash
# 1. Check Core service CPU/memory
kubectl top pods -n secrethub-system

# 2. Check database performance
psql -h postgres.secrethub.svc -U secrethub -d secrethub_db \
  -c "SELECT * FROM pg_stat_activity WHERE state = 'active'"

# 3. Check Agent cache hit rate
curl http://localhost:9090/metrics | grep secrethub_agent_cache_hit_rate
```

**Optimization:**
- Enable/increase Agent-side caching
- Add database read replicas for audit queries
- Increase Core service replicas
- Optimize database queries with proper indexes

---

#### Issue: WebSocket Connection Drops Frequently

**Diagnosis:**
```bash
# 1. Check network stability
ping -c 100 secrethub-core.example.com

# 2. Check load balancer timeout settings
# AWS ALB: Idle timeout should be > 60s

# 3. Review Agent reconnection logs
journalctl -u secrethub-agent | grep "reconnect"
```

**Solution:**
- Increase load balancer idle timeout to 120s
- Reduce Agent heartbeat interval to 30s
- Enable TCP keepalive on both ends
- Check for network MTU issues

---

### C.3. Emergency Procedures

#### Emergency: Root Password Compromised

```bash
# 1. Immediately rotate root password
curl -X POST https://secrethub-core.example.com/v1/secrets/static/prod.db.postgres.root-password/rotate \
  -H "X-SecretHub-Token: $ADMIN_TOKEN" \
  -d '{"rotation_type": "emergency", "grace_period": "0m"}'

# 2. Revoke all active leases for affected database
curl -X POST https://secrethub-core.example.com/v1/leases/revoke-prefix \
  -H "X-SecretHub-Token: $ADMIN_TOKEN" \
  -d '{"prefix": "prod.db.postgres"}'

# 3. Audit all access in last 24 hours
curl -X POST https://secrethub-core.example.com/v1/audit/search \
  -H "X-SecretHub-Token: $ADMIN_TOKEN" \
  -d '{
    "secret_id": "prod.db.postgres.root-password",
    "start_time": "'"$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)"'",
    "end_time": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
  }'

# 4. Trigger security incident response
# 5. File incident report
```

---

## Appendix D: Security Checklist

### Pre-Production Security Review

#### Infrastructure
- [ ] All Core nodes running with non-root user
- [ ] Database encryption at rest enabled
- [ ] Database connections using TLS
- [ ] Firewall rules restricting access to Core services
- [ ] Network segmentation between zones implemented
- [ ] DDoS protection enabled
- [ ] WAF configured with OWASP rules

#### Authentication & Authorization
- [ ] mTLS enforced for all Agent connections
- [ ] Admin access requires MFA
- [ ] Certificate TTLs configured appropriately (24-72h)
- [ ] Root CA private key stored securely (HSM/Vault)
- [ ] Shamir unseal keys distributed to keyholders
- [ ] Cloud KMS auto-unseal configured (production)
- [ ] RBAC policies defined for all entities
- [ ] Principle of least privilege applied

#### Secrets Management
- [ ] No secrets hardcoded in configuration files
- [ ] All static secrets encrypted with AES-256-GCM
- [ ] Dynamic secrets with short TTL (<24h)
- [ ] Rotation schedules configured for static secrets
- [ ] Grace periods configured for rotation
- [ ] Backup encryption key stored separately

#### Audit & Monitoring
- [ ] Audit logging enabled for all operations
- [ ] Audit logs sent to immutable storage
- [ ] Hash chain verification scheduled
- [ ] Metrics exported to Prometheus
- [ ] Alerting rules configured for critical events
- [ ] SIEM integration completed
- [ ] Distributed tracing enabled
- [ ] Log retention policy documented

#### Operational
- [ ] Backup procedures tested and documented
- [ ] Restore procedures tested (quarterly)
- [ ] Disaster recovery plan documented
- [ ] Incident response plan documented
- [ ] Runbooks created for common scenarios
- [ ] On-call rotation established
- [ ] Security contact information updated
- [ ] Compliance documentation completed

#### Testing
- [ ] Unit tests passing (>90% coverage)
- [ ] Integration tests passing
- [ ] Load testing completed
- [ ] Penetration testing completed
- [ ] Vulnerability scanning passed
- [ ] TLS configuration verified (A+ rating)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-10-01 | Gemini | Initial draft |
| 1.4 | 2025-10-18 | Gemini | Added PKI details, audit system |
| 2.0 | 2025-10-18 | Gemini + Claude | Complete redesign with comprehensive audit logging, removed rate limiting, added operational procedures, expanded security model |

---

**End of Document**

