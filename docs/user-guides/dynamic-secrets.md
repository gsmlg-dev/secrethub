# Dynamic Secrets User Guide

## Table of Contents

1. [Overview](#overview)
2. [Key Concepts](#key-concepts)
3. [PostgreSQL Dynamic Engine](#postgresql-dynamic-engine)
4. [Role Configuration](#role-configuration)
5. [Generating Credentials](#generating-credentials)
6. [Lease Management](#lease-management)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Overview

SecretHub's dynamic secret engines generate credentials on-demand with automatic expiration and renewal. Unlike static secrets that exist until manually rotated, dynamic secrets are temporary and automatically revoked when they expire.

### Benefits

- **Reduced Credential Sprawl**: Credentials exist only as long as needed
- **Automatic Rotation**: No manual rotation required - new credentials generated on each request
- **Audit Trail**: Complete visibility into who accessed what and when
- **Least Privilege**: Grant minimal TTL based on actual need
- **Simplified Revocation**: Revoke access by simply not renewing leases

### Supported Engines

- **PostgreSQL**: Generate temporary database users with configurable permissions
- **Redis** (Planned): Generate temporary Redis ACL users
- **AWS** (Planned): Generate temporary IAM credentials

---

## Key Concepts

### Dynamic Secret Engines

Dynamic secret engines generate credentials on-demand based on pre-configured roles. Each engine type (PostgreSQL, Redis, AWS) implements the same interface:

- `generate_credentials/2` - Create new temporary credentials
- `revoke_credentials/2` - Delete credentials when lease expires
- `renew_lease/2` - Extend credential lifetime (optional)

### Roles

Roles define the permissions and configuration for generated credentials:

- **Database connection parameters** (host, port, database, credentials)
- **SQL statement templates** for creation, renewal, and revocation
- **TTL configuration** (default and maximum)
- **Permission grants** (SELECT, INSERT, UPDATE, DELETE, etc.)

### Leases

A lease represents the lifetime of a set of dynamic credentials:

- **Lease ID**: Unique identifier (UUID)
- **TTL**: Time-to-live in seconds
- **Expires At**: When credentials will be automatically revoked
- **Renewable**: Whether lease can be extended
- **Credentials**: The generated username/password

### Lease Lifecycle

```
┌─────────────┐
│   Request   │
│ Credentials │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Generate   │ ◄── Role Config (SQL templates, TTL)
│ Credentials │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Create Lease│ ◄── Track expiration, agent_id
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Active    │ ──────┐
│   Lease     │       │ Auto-renew before expiry
└──────┬──────┘       │ (Agent LeaseRenewer)
       │              │
       │ ◄────────────┘
       ▼
┌─────────────┐
│  Expired?   │
└──────┬──────┘
       │
       ├─ Yes ──► Revoke Credentials (DROP USER)
       │
       └─ No ──► Continue Renewal Loop
```

---

## PostgreSQL Dynamic Engine

The PostgreSQL engine generates temporary database users with configurable permissions and automatic cleanup.

### How It Works

1. **Agent requests credentials** for a specific role (e.g., `readonly-analytics`)
2. **SecretHub generates** a unique username and secure password
3. **SQL creation statements execute** on the target PostgreSQL database
4. **Lease created** with configurable TTL (default: 1 hour)
5. **Credentials returned** to agent for application use
6. **Automatic renewal** by agent before lease expires (at 33% remaining TTL)
7. **Automatic revocation** when lease expires or is manually revoked

### Generated Username Format

```
shub_<role_name>_<random>_<timestamp>
```

Example: `shub_readonly_k3m9x2p4_1730012345`

- **Prefix**: `shub_` (SecretHub)
- **Role**: Sanitized role name (max 20 chars, alphanumeric + underscore)
- **Random**: 8 characters (base32 lowercase)
- **Timestamp**: Unix epoch seconds

### Password Generation

- **Length**: 32 characters
- **Character set**: Base64 (A-Z, a-z, 0-9, +, /)
- **Entropy**: 256 bits (from `:crypto.strong_rand_bytes/1`)

---

## Role Configuration

### Via Web UI

1. Navigate to **Admin → Dynamic Secrets → PostgreSQL**
2. Click **"New Role"**
3. Fill in the role configuration form
4. Test database connection
5. Save role

### Role Parameters

#### Connection Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| **Role Name** | Unique identifier for this role | `readonly-analytics` |
| **Host** | PostgreSQL server hostname | `postgres.production.internal` |
| **Port** | PostgreSQL server port | `5432` |
| **Database** | Target database name | `analytics_db` |
| **Username** | Admin user with CREATE USER privilege | `secrethub_admin` |
| **Password** | Admin user password | `********` |
| **SSL** | Enable SSL/TLS connection | `true` |

#### TTL Configuration

| Parameter | Description | Default | Recommended Range |
|-----------|-------------|---------|-------------------|
| **Default TTL** | Default lease duration (seconds) | `3600` (1 hour) | 300 - 86400 |
| **Max TTL** | Maximum allowed lease duration | `86400` (24 hours) | 3600 - 604800 |

**Guidelines:**
- Short-lived jobs: Default TTL = 300s (5 minutes)
- Long-running services: Default TTL = 3600s (1 hour)
- Batch processes: Default TTL = 7200s (2 hours)

#### SQL Statement Templates

Templates use the following variables:

- `{{username}}` - Generated username
- `{{password}}` - Generated password
- `{{expiration}}` - ISO 8601 timestamp of lease expiry

**Creation Statements** (Required):
```sql
CREATE USER "{{username}}" WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
GRANT CONNECT ON DATABASE analytics_db TO "{{username}}";
GRANT USAGE ON SCHEMA public TO "{{username}}";
GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{username}}";
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO "{{username}}";
```

**Renewal Statements** (Optional):
```sql
ALTER USER "{{username}}" VALID UNTIL '{{expiration}}';
```

**Revocation Statements** (Required):
```sql
-- Terminate existing connections
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE usename = '{{username}}';

-- Drop the user
DROP USER IF EXISTS "{{username}}";
```

### Example Roles

#### Read-Only Analytics User

```sql
-- Creation
CREATE USER "{{username}}" WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
GRANT CONNECT ON DATABASE analytics_db TO "{{username}}";
GRANT USAGE ON SCHEMA public TO "{{username}}";
GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{username}}";
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO "{{username}}";

-- Revocation
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{username}}';
DROP USER IF EXISTS "{{username}}";
```

#### Read-Write Application User

```sql
-- Creation
CREATE USER "{{username}}" WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
GRANT CONNECT ON DATABASE app_db TO "{{username}}";
GRANT USAGE ON SCHEMA public TO "{{username}}";
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO "{{username}}";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{{username}}";

-- Revocation
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{username}}';
DROP USER IF EXISTS "{{username}}";
```

#### Schema-Specific Admin User

```sql
-- Creation
CREATE USER "{{username}}" WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
GRANT CONNECT ON DATABASE app_db TO "{{username}}";
GRANT ALL PRIVILEGES ON SCHEMA reporting TO "{{username}}";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA reporting TO "{{username}}";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA reporting TO "{{username}}";
ALTER DEFAULT PRIVILEGES IN SCHEMA reporting GRANT ALL ON TABLES TO "{{username}}";

-- Revocation
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{username}}';
DROP USER IF EXISTS "{{username}}";
```

---

## Generating Credentials

### Via REST API

```bash
curl -X POST https://secrethub.example.com/v1/secrets/dynamic/readonly-analytics \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: <agent_token>" \
  -d '{
    "ttl": 3600,
    "metadata": {
      "purpose": "analytics query",
      "requester": "data-pipeline-job"
    }
  }'
```

**Response:**
```json
{
  "lease_id": "550e8400-e29b-41d4-a716-446655440000",
  "credentials": {
    "username": "shub_readonly_k3m9x2p4_1730012345",
    "password": "aB3$xYz9....",
    "host": "postgres.production.internal",
    "port": 5432,
    "database": "analytics_db"
  },
  "lease_duration": 3600,
  "renewable": true
}
```

### Via Agent Cache

Agents automatically cache dynamic credentials and handle renewal:

```elixir
# Agent automatically requests and caches credentials
{:ok, creds} = SecretHub.Agent.Cache.get("dynamic/postgresql/readonly-analytics")

# Use credentials in application
conn = Postgrex.start_link(
  hostname: creds.host,
  port: creds.port,
  database: creds.database,
  username: creds.username,
  password: creds.password
)
```

### Connection String Example

```
postgresql://shub_readonly_k3m9x2p4_1730012345:aB3$xYz9....@postgres.production.internal:5432/analytics_db?sslmode=require
```

---

## Lease Management

### Viewing Active Leases

**Web UI**: Navigate to **Admin → Leases**

**REST API**:
```bash
curl -X GET https://secrethub.example.com/v1/sys/leases \
  -H "X-Agent-Token: <agent_token>"
```

### Lease Renewal

Leases are automatically renewed by the Agent's `LeaseRenewer` module when they reach 33% remaining TTL.

**Manual Renewal via REST API**:
```bash
curl -X POST https://secrethub.example.com/v1/sys/leases/renew \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: <agent_token>" \
  -d '{
    "lease_id": "550e8400-e29b-41d4-a716-446655440000",
    "increment": 3600
  }'
```

**Renewal Strategy:**
- **Trigger**: Remaining TTL < 33% of original lease duration
- **Retry**: Exponential backoff (1s → 2s → 4s → 8s → 60s max)
- **Failure**: Agent logs error and triggers `on_failed` callback
- **Max Attempts**: 5 retries before giving up

### Lease Revocation

**Via Web UI**: Click "Revoke" button in Lease Viewer

**Via REST API**:
```bash
curl -X POST https://secrethub.example.com/v1/sys/leases/revoke \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: <agent_token>" \
  -d '{
    "lease_id": "550e8400-e29b-41d4-a716-446655440000"
  }'
```

**Revocation Process:**
1. Mark lease as revoked in LeaseManager
2. Execute revocation SQL statements (DROP USER)
3. Remove from Agent cache
4. Log audit event
5. Return confirmation

### Automatic Expiration

The LeaseManager runs a cleanup task every 10 seconds to revoke expired leases:

```
Cleanup Task (every 10s)
  ├─ Identify expired leases (expires_at < now)
  ├─ Execute revocation SQL
  ├─ Remove from in-memory lease map
  └─ Log audit events
```

---

## Best Practices

### Security

1. **Principle of Least Privilege**
   - Grant only the minimum required permissions
   - Use schema-specific or table-specific grants instead of database-wide
   - Avoid SUPERUSER, CREATEDB, CREATEROLE privileges

2. **Short TTLs**
   - Default TTL: 1 hour for long-running services
   - Short jobs: 5-15 minutes
   - Batch processes: Match job duration + 10% buffer

3. **SSL/TLS Enforcement**
   - Always enable SSL for PostgreSQL connections
   - Use certificate-based authentication when possible
   - Configure `sslmode=require` in connection strings

4. **Role Isolation**
   - Create separate roles for different use cases
   - Don't reuse roles across environments (dev/staging/prod)
   - Use role naming conventions: `<environment>-<purpose>`

### Performance

1. **Connection Pooling**
   - Don't create new credentials for every connection
   - Cache credentials in Agent and reuse until expiry
   - Use connection pooling libraries (PgBouncer, Postgrex pool)

2. **Renewal Timing**
   - Agent renews at 33% remaining TTL by default
   - For critical applications, configure earlier renewal (50%)
   - Monitor renewal failure rates

3. **Cleanup Efficiency**
   - Expired leases cleaned up every 10 seconds
   - Consider increasing cleanup interval if managing 1000+ leases
   - Monitor LeaseManager memory usage

### Monitoring

1. **Key Metrics**
   - Lease creation rate
   - Renewal success rate (target: >99.9%)
   - Renewal latency (P95, P99)
   - Active lease count
   - Expired lease count

2. **Alerts**
   - Renewal failure rate > 1%
   - Lease creation errors
   - Database connection failures in role config
   - Expired lease accumulation

3. **Audit Logs**
   - Review lease access patterns
   - Identify unusual TTL requests
   - Track revocation events

### Operational

1. **Role Management**
   - Version control your SQL statement templates
   - Test role configurations in non-prod environments
   - Use "Test Connection" feature before saving
   - Document role purposes and permissions

2. **Credential Rotation**
   - Rotate admin credentials (role config) quarterly
   - Update SSL certificates before expiry
   - Audit role configurations monthly

3. **Disaster Recovery**
   - Leases are in-memory; plan for Core restarts
   - Agents automatically re-request credentials on failure
   - Document manual recovery procedures

---

## Troubleshooting

### Common Issues

#### 1. "Connection failed" when testing role configuration

**Symptoms:**
- Test connection button shows error
- Cannot save role configuration

**Causes:**
- Incorrect host/port/database
- Admin credentials invalid
- Network connectivity issues
- SSL configuration mismatch

**Resolution:**
```bash
# Test connectivity from Core server
psql -h postgres.production.internal -p 5432 -U secrethub_admin -d analytics_db

# Check SSL requirement
psql "postgresql://secrethub_admin@postgres.production.internal:5432/analytics_db?sslmode=require"

# Verify admin user privileges
psql -U secrethub_admin -c "SELECT rolname, rolcreaterole FROM pg_roles WHERE rolname = 'secrethub_admin';"
# Should show rolcreaterole = true
```

#### 2. Generated credentials don't work

**Symptoms:**
- Application cannot connect with generated credentials
- "authentication failed" errors

**Causes:**
- SQL creation statements missing GRANT CONNECT
- Missing schema privileges
- pg_hba.conf doesn't allow generated user
- Password contains special characters not escaped properly

**Resolution:**
```sql
-- Verify user was created
SELECT usename, valuntil FROM pg_user WHERE usename LIKE 'shub_%';

-- Check user privileges
SELECT grantee, privilege_type
FROM information_schema.role_table_grants
WHERE grantee LIKE 'shub_%';

-- Test connection manually
psql -h postgres.production.internal -U shub_readonly_k3m9x2p4_1730012345 -d analytics_db
```

#### 3. Leases not automatically renewing

**Symptoms:**
- Leases expire despite Agent running
- Application loses database connection after TTL expires

**Causes:**
- Agent LeaseRenewer not started
- Network issues between Agent and Core
- Renewal endpoint returning errors
- TTL too short for renewal threshold

**Resolution:**
```bash
# Check Agent LeaseRenewer is running
# Agent logs should show:
[info] LeaseRenewer started with core_url: http://core:4000

# Check renewal attempts in Agent logs
[info] Renewing lease: 550e8400-e29b-41d4-a716-446655440000 (TTL remaining: 600s)

# Verify renewal endpoint
curl -X POST http://core:4000/v1/sys/leases/renew \
  -H "Content-Type: application/json" \
  -d '{"lease_id": "550e8400...", "increment": 3600}'

# Check Core LeaseManager stats
curl -X GET http://core:4000/v1/sys/leases/stats
```

#### 4. "DROP USER failed: user has active connections"

**Symptoms:**
- Lease revocation fails
- Database shows "user has dependent objects"

**Causes:**
- Active connections not terminated before DROP USER
- User owns database objects

**Resolution:**
```sql
-- Update revocation statements to include connection termination
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE usename = '{{username}}';

-- Check for owned objects
SELECT schemaname, objectname, objecttype
FROM pg_catalog.pg_depend d
JOIN pg_catalog.pg_roles r ON d.refobjid = r.oid
WHERE r.rolname = 'shub_readonly_k3m9x2p4_1730012345';

-- If user owns objects, update revocation to REASSIGN OWNED
REASSIGN OWNED BY "{{username}}" TO postgres;
DROP OWNED BY "{{username}}";
DROP USER IF EXISTS "{{username}}";
```

#### 5. Memory usage growing on Core server

**Symptoms:**
- LeaseManager process memory increasing
- Core server OOM errors

**Causes:**
- Too many active leases (>10,000)
- Expired leases not being cleaned up
- Lease metadata too large

**Resolution:**
```bash
# Check lease stats
curl http://core:4000/v1/sys/leases/stats

# Monitor LeaseManager process
:observer.start()  # In IEx console
# Navigate to Applications → secrethub_core → LeaseManager

# Adjust cleanup interval in config
# config/prod.exs
config :secrethub_core, :lease_manager,
  cleanup_interval: 5_000  # Clean up every 5s instead of 10s

# Consider implementing lease archival for historical data
```

### Debug Mode

Enable detailed logging for troubleshooting:

```elixir
# config/dev.exs or runtime.exs
config :logger, :console,
  level: :debug,
  format: "$time $metadata[$level] $message\n",
  metadata: [:module, :function, :line]

# Filter for lease-related logs
config :logger, :console,
  metadata_filter: [module: SecretHub.Core.LeaseManager]
```

### Getting Help

- **GitHub Issues**: https://github.com/yourorg/secrethub/issues
- **Slack Channel**: #secrethub-support
- **Documentation**: https://docs.secrethub.example.com
- **Audit Logs**: Check `/admin/audit` for detailed event history

---

## Appendix

### PostgreSQL Version Compatibility

| PostgreSQL Version | Supported | Notes |
|--------------------|-----------|-------|
| 16.x | ✅ Yes | Fully tested |
| 15.x | ✅ Yes | Fully tested |
| 14.x | ✅ Yes | Compatible |
| 13.x | ✅ Yes | Compatible |
| 12.x | ⚠️ Limited | VALID UNTIL not supported in all cases |
| 11.x and below | ❌ No | Not tested |

### Required PostgreSQL Extensions

None required. Dynamic secrets work with vanilla PostgreSQL installations.

### Admin User Required Privileges

The admin user (configured in role settings) must have:

```sql
-- Create the admin user
CREATE USER secrethub_admin WITH PASSWORD 'secure_password';

-- Grant CREATEROLE privilege
ALTER USER secrethub_admin WITH CREATEROLE;

-- Grant CONNECT on target databases
GRANT CONNECT ON DATABASE analytics_db TO secrethub_admin;
GRANT CONNECT ON DATABASE app_db TO secrethub_admin;

-- Grant permissions to grant permissions (meta-privilege)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secrethub_admin WITH GRANT OPTION;
```

### Environment Variables

```bash
# Core
DATABASE_URL=postgresql://secrethub:password@localhost:5432/secrethub_dev
LEASE_CLEANUP_INTERVAL=10000  # milliseconds

# Agent
SECRETHUB_CORE_URL=https://core.secrethub.example.com
LEASE_RENEWAL_THRESHOLD=0.33  # Renew at 33% remaining TTL
LEASE_RENEWAL_RETRIES=5
```

### Further Reading

- [Lease Manager Implementation](../development/lease-manager.md)
- [Agent Lease Renewal](../development/agent-lease-renewal.md)
- [Dynamic Secret Engine Architecture](../architecture/dynamic-secrets.md)
- [Security Best Practices](../security/best-practices.md)
