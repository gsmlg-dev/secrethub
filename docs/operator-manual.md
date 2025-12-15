# SecretHub Operator Manual

**Version:** 1.0.0
**Last Updated:** 2025-11-03

This manual provides day-to-day operational procedures for SecretHub administrators.

---

## Table of Contents

1. [Daily Operations](#daily-operations)
2. [Common Tasks](#common-tasks)
3. [Maintenance Procedures](#maintenance-procedures)
4. [Emergency Procedures](#emergency-procedures)
5. [Monitoring](#monitoring)
6. [Backup & Recovery](#backup--recovery)

---

## Daily Operations

### Morning Checklist

Run these checks at the start of each day:

```bash
#!/bin/bash
# daily-health-check.sh

echo "=== SecretHub Daily Health Check ==="
echo "Date: $(date)"
echo ""

# 1. Check Core status
echo "1. Checking Core instances..."
for host in core-1 core-2 core-3; do
  status=$(curl -s https://$host.internal:4000/v1/sys/health | jq -r '.sealed')
  echo "  $host: sealed=$status"
done

# 2. Check agent connectivity
echo ""
echo "2. Checking agent connections..."
agent_count=$(curl -s https://secrethub.company.com/admin/api/dashboard/stats \
  -H "X-Vault-Token: $TOKEN" | jq '.connected_agents')
echo "  Connected agents: $agent_count"

# 3. Check database
echo ""
echo "3. Checking database..."
psql $DATABASE_URL -c "SELECT pg_database_size('secrethub_prod');" -t | \
  numfmt --to=iec | xargs echo "  Database size:"

# 4. Check disk space
echo ""
echo "4. Checking disk space..."
df -h | grep -E '(Filesystem|/opt|/var)'

# 5. Check recent errors
echo ""
echo "5. Recent errors (last hour)..."
error_count=$(journalctl -u secrethub-core --since "1 hour ago" | grep -i error | wc -l)
echo "  Error count: $error_count"

# 6. Check performance metrics
echo ""
echo "6. Performance metrics..."
curl -s https://secrethub.company.com/admin/performance \
  -H "X-Vault-Token: $TOKEN" | jq '{
    p95_latency,
    memory_mb,
    db_pool_utilization,
    cache_hit_rate
  }'

echo ""
echo "=== Health Check Complete ==="
```

**Expected Results:**
- All Core instances unsealed
- Agent count matches expected deployment
- Database size growing steadily but not rapidly
- Disk usage < 80%
- Error count < 100 per hour
- P95 latency < 100ms
- Cache hit rate > 80%

---

## Common Tasks

### Managing Secrets

#### Create a Secret

```bash
# Via CLI
secrethub secret create prod/db/postgres \
  --data '{
    "username": "myapp",
    "password": "supersecret",
    "host": "db.internal.com",
    "port": 5432
  }'

# Via API
curl -X POST https://secrethub.company.com/v1/secrets/static/prod/db/postgres \
  -H "X-Vault-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "username": "myapp",
      "password": "supersecret",
      "host": "db.internal.com",
      "port": 5432
    }
  }'
```

#### Update a Secret

```bash
# This creates a new version
secrethub secret create prod/db/postgres \
  --data '{
    "username": "myapp",
    "password": "newsupersecret",
    "host": "db.internal.com",
    "port": 5432
  }'

# Connected agents will be notified automatically
```

#### Delete a Secret

```bash
secrethub secret delete prod/db/postgres

# Or via API
curl -X DELETE https://secrethub.company.com/v1/secrets/static/prod/db/postgres \
  -H "X-Vault-Token: $TOKEN"
```

#### View Secret Versions

```bash
# Via Web UI: /admin/secrets/prod/db/postgres/versions

# Via API
curl https://secrethub.company.com/v1/secrets/static/prod/db/postgres/versions \
  -H "X-Vault-Token: $TOKEN"
```

---

### Managing AppRoles

#### Create an AppRole

```bash
curl -X POST https://secrethub.company.com/v1/auth/approle/role/myapp \
  -H "X-Vault-Token: $TOKEN" \
  -d '{
    "role_name": "myapp",
    "policies": ["prod-read"],
    "token_ttl": 3600
  }'
```

#### Get Role ID

```bash
curl https://secrethub.company.com/v1/auth/approle/role/myapp/role-id \
  -H "X-Vault-Token: $TOKEN"

# Output: {"role_id": "abc-123-def-456"}
```

#### Generate Secret ID

```bash
curl -X POST https://secrethub.company.com/v1/auth/approle/role/myapp/secret-id \
  -H "X-Vault-Token: $TOKEN"

# Output: {"secret_id": "xyz-789-uvw-012", "secret_id_ttl": 0}
```

#### Revoke Secret ID

```bash
curl -X POST https://secrethub.company.com/v1/auth/approle/role/myapp/secret-id/destroy \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"secret_id": "xyz-789-uvw-012"}'
```

#### Delete AppRole

```bash
curl -X DELETE https://secrethub.company.com/v1/auth/approle/role/myapp \
  -H "X-Vault-Token: $TOKEN"
```

---

### Managing Policies

#### Create a Policy

```bash
curl -X POST https://secrethub.company.com/v1/policies \
  -H "X-Vault-Token: $TOKEN" \
  -d '{
    "name": "prod-read",
    "rules": [
      {
        "path": "prod/*",
        "capabilities": ["read"],
        "effect": "allow",
        "conditions": {
          "time_of_day": [9, 17],
          "days_of_week": [1,2,3,4,5],
          "source_ip": "10.0.0.0/8"
        }
      }
    ]
  }'
```

#### Update a Policy

```bash
curl -X PUT https://secrethub.company.com/v1/policies/prod-read \
  -H "X-Vault-Token: $TOKEN" \
  -d '{
    "rules": [...]  # Updated rules
  }'
```

#### Test a Policy

```bash
# Via Web UI: /admin/policies/prod-read/simulate

# Or via API
curl -X POST https://secrethub.company.com/v1/policies/prod-read/simulate \
  -H "X-Vault-Token: $TOKEN" \
  -d '{
    "path": "prod/db/postgres",
    "capability": "read",
    "context": {
      "source_ip": "10.0.1.100",
      "time": "2025-11-03T14:30:00Z"
    }
  }'
```

#### Delete a Policy

```bash
curl -X DELETE https://secrethub.company.com/v1/policies/prod-read \
  -H "X-Vault-Token: $TOKEN"
```

---

### Managing Dynamic Secrets

#### Configure PostgreSQL Engine

```bash
curl -X POST https://secrethub.company.com/v1/secrets/dynamic/config/postgresql \
  -H "X-Vault-Token: $TOKEN" \
  -d '{
    "connection_url": "postgresql://admin:password@db.internal:5432/mydb",
    "allowed_roles": ["readonly", "readwrite"]
  }'
```

#### Create a Role

```bash
curl -X POST https://secrethub.company.com/v1/secrets/dynamic/roles/postgresql/readonly \
  -H "X-Vault-Token: $TOKEN" \
  -d '{
    "db_name": "mydb",
    "creation_statements": [
      "CREATE USER {{name}} WITH PASSWORD {{password}} VALID UNTIL {{expiration}};",
      "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};"
    ],
    "default_ttl": 3600,
    "max_ttl": 86400
  }'
```

#### Generate Credentials

```bash
curl -X POST https://secrethub.company.com/v1/secrets/dynamic/postgresql/readonly \
  -H "X-Vault-Token: $TOKEN"

# Response:
{
  "lease_id": "postgresql/readonly/abc-123",
  "lease_duration": 3600,
  "data": {
    "username": "v-readonly-abc123",
    "password": "generated-password"
  }
}
```

#### Renew Lease

```bash
curl -X POST https://secrethub.company.com/v1/sys/leases/renew \
  -H "X-Vault-Token: $TOKEN" \
  -d '{
    "lease_id": "postgresql/readonly/abc-123",
    "increment": 3600
  }'
```

#### Revoke Lease

```bash
curl -X POST https://secrethub.company.com/v1/sys/leases/revoke \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"lease_id": "postgresql/readonly/abc-123"}'
```

---

## Maintenance Procedures

### Weekly Maintenance

#### 1. Review Audit Logs

```bash
# Export last week's audit logs
curl https://secrethub.company.com/admin/api/export/audit \
  -H "X-Vault-Token: $TOKEN" \
  -d '{
    "from_date": "2025-10-27T00:00:00Z",
    "to_date": "2025-11-03T23:59:59Z"
  }' > audit-logs-week-44.csv

# Analyze for anomalies
grep "access_granted.*false" audit-logs-week-44.csv | wc -l

# Archive to S3
aws s3 cp audit-logs-week-44.csv s3://secrethub-audit-logs/2025/week-44/
```

#### 2. Rotate Old Secrets

```bash
# List secrets older than 90 days
psql $DATABASE_URL <<EOF
SELECT path, updated_at
FROM secrets
WHERE updated_at < NOW() - INTERVAL '90 days';
EOF

# Rotate critical secrets manually or via automation
```

#### 3. Review Agent Connections

```bash
# List inactive agents (not connected in 7 days)
curl https://secrethub.company.com/admin/api/dashboard/agents \
  -H "X-Vault-Token: $TOKEN" | \
  jq '.[] | select(.last_seen < "2025-10-27")'

# Decommission inactive agents
```

#### 4. Database Maintenance

```bash
# Analyze tables
psql $DATABASE_URL <<EOF
ANALYZE;
EOF

# Reindex if needed
psql $DATABASE_URL <<EOF
REINDEX INDEX CONCURRENTLY secrets_path_idx;
EOF

# Vacuum audit logs
psql $DATABASE_URL <<EOF
VACUUM ANALYZE audit.events;
EOF
```

---

### Monthly Maintenance

#### 1. Database Backup

```bash
# Full database backup
pg_dump $DATABASE_URL | gzip > backup-$(date +%Y%m%d).sql.gz

# Upload to S3
aws s3 cp backup-$(date +%Y%m%d).sql.gz s3://secrethub-backups/monthly/

# Verify backup
gunzip -c backup-$(date +%Y%m%d).sql.gz | head -n 100
```

#### 2. Certificate Renewal

```bash
# List certificates expiring in 30 days
curl https://secrethub.company.com/admin/api/certificates \
  -H "X-Vault-Token: $TOKEN" | \
  jq '.[] | select(.expires_at < "2025-12-03")'

# Renew certificates
# Auto-renewal should handle this, but verify manually
```

#### 3. Clean Up Old Data

```bash
# Archive audit logs older than 180 days
psql $DATABASE_URL <<EOF
COPY (
  SELECT * FROM audit.events
  WHERE timestamp < NOW() - INTERVAL '180 days'
) TO '/tmp/audit-archive-$(date +%Y%m).csv' CSV HEADER;
EOF

# Upload to S3
aws s3 cp /tmp/audit-archive-*.csv s3://secrethub-audit-archive/

# Delete from database
psql $DATABASE_URL <<EOF
DELETE FROM audit.events WHERE timestamp < NOW() - INTERVAL '180 days';
VACUUM FULL audit.events;
EOF
```

#### 4. Security Review

```bash
# Review failed authentication attempts
psql $DATABASE_URL <<EOF
SELECT actor_id, COUNT(*) as failed_attempts
FROM audit.events
WHERE event_type = 'auth.failed'
  AND timestamp > NOW() - INTERVAL '30 days'
GROUP BY actor_id
HAVING COUNT(*) > 10
ORDER BY failed_attempts DESC;
EOF

# Review policy changes
psql $DATABASE_URL <<EOF
SELECT * FROM audit.events
WHERE event_type LIKE 'policy.%'
  AND timestamp > NOW() - INTERVAL '30 days'
ORDER BY timestamp DESC;
EOF
```

---

### Quarterly Maintenance

#### 1. Performance Review

```bash
# Generate performance report
curl https://secrethub.company.com/admin/performance \
  -H "X-Vault-Token: $TOKEN" > performance-report-Q4.json

# Review trends
# - P95 latency trending upward?
# - Cache hit rate declining?
# - Database pool utilization increasing?
```

#### 2. Capacity Planning

```bash
# Database growth rate
psql $DATABASE_URL <<EOF
SELECT
  current_database() as db_name,
  pg_size_pretty(pg_database_size(current_database())) as current_size,
  pg_size_pretty(
    pg_database_size(current_database()) * 4
  ) as projected_size_in_year
FROM pg_database;
EOF

# Agent count trend
# Review if infrastructure scaling needed
```

#### 3. DR Test

```bash
# Schedule disaster recovery test
# - Backup restoration
# - Failover to standby region
# - Data integrity verification
# See Disaster Recovery documentation
```

---

## Emergency Procedures

### Emergency: Core Instance Down

**Symptoms:** One or more Core instances unreachable

**Immediate Actions:**

1. **Verify the issue:**
   ```bash
   curl https://core-1.internal:4000/v1/sys/health
   # If timeout, instance is down
   ```

2. **Check other instances:**
   ```bash
   for host in core-2 core-3; do
     curl https://$host.internal:4000/v1/sys/health
   done
   # If others are healthy, system is still operational
   ```

3. **Review logs:**
   ```bash
   ssh core-1
   sudo journalctl -u secrethub-core -n 500
   ```

4. **Attempt restart:**
   ```bash
   sudo systemctl restart secrethub-core
   sudo journalctl -u secrethub-core -f
   ```

5. **If restart fails:**
   - Restore from backup
   - Or provision new instance
   - Update load balancer

**Post-Incident:**
- Root cause analysis
- Update runbooks
- Implement preventive measures

---

### Emergency: Database Failure

**Symptoms:** All Core instances reporting database connection errors

**Immediate Actions:**

1. **Check database status:**
   ```bash
   psql $DATABASE_URL -c "SELECT 1;"
   # If fails, database is down
   ```

2. **Check RDS Multi-AZ status:**
   ```bash
   aws rds describe-db-instances \
     --db-instance-identifier secrethub-prod
   ```

3. **If standby available:**
   ```bash
   # RDS will auto-failover
   # Update DATABASE_URL if needed
   # Restart Core instances
   ```

4. **If database is corrupted:**
   ```bash
   # Restore from latest backup
   # See Backup & Recovery section
   ```

**Post-Incident:**
- Verify data integrity
- Review backup procedures
- Test failover process

---

### Emergency: Vault Sealed

**Symptoms:** All API requests return 503 with "Vault is sealed"

**Immediate Actions:**

1. **Gather key custodians:**
   - Need 3 of 5 unseal keys
   - Contact on-call key custodians

2. **Unseal each Core instance:**
   ```bash
   # Core-1
   curl -X POST https://core-1.internal:4000/v1/sys/unseal \
     -d '{"key": "key1"}'
   curl -X POST https://core-1.internal:4000/v1/sys/unseal \
     -d '{"key": "key2"}'
   curl -X POST https://core-1.internal:4000/v1/sys/unseal \
     -d '{"key": "key3"}'

   # Repeat for core-2 and core-3
   ```

3. **Verify unseal:**
   ```bash
   curl https://secrethub.company.com/v1/sys/seal-status
   # {"sealed": false, ...}
   ```

**Prevention:**
- Enable auto-unseal with AWS KMS
- Document unseal procedures
- Test unseal process quarterly

---

### Emergency: Security Breach

**Symptoms:** Unauthorized access detected, data exfiltration suspected

**Immediate Actions:**

1. **Contain the breach:**
   ```bash
   # Seal the vault
   curl -X POST https://secrethub.company.com/v1/sys/seal \
     -H "X-Vault-Token: $TOKEN"

   # Revoke all AppRole tokens
   # Block suspicious IPs at firewall
   ```

2. **Notify security team:**
   - Follow incident response procedures
   - Preserve logs for forensics

3. **Review audit logs:**
   ```bash
   # Export all recent audit logs
   psql $DATABASE_URL <<EOF
   COPY (SELECT * FROM audit.events WHERE timestamp > NOW() - INTERVAL '24 hours')
   TO '/tmp/audit-breach-$(date +%Y%m%d-%H%M).csv' CSV HEADER;
   EOF
   ```

4. **Rotate all credentials:**
   - Admin passwords
   - AppRole Secret IDs
   - Database passwords
   - SSL certificates

**Post-Incident:**
- Full security audit
- Update security procedures
- Implement additional controls

---

## Monitoring

### Key Metrics to Monitor

#### Core Health
- **Vault Seal Status** (should be: `false`)
- **Core Instance Availability** (should be: 100% for at least 2/3 instances)
- **API Response Time P95** (target: < 100ms)
- **Error Rate** (target: < 0.1%)

#### Database
- **Connection Pool Utilization** (alert if > 80%)
- **Query Response Time** (target: P95 < 50ms)
- **Disk Usage** (alert if > 80%)
- **Replication Lag** (if using read replicas)

#### Agents
- **Connected Agent Count** (should match expected deployment)
- **Agent Disconnections** (alert if > 5% disconnect in 5min)
- **WebSocket Message Latency** (target: < 50ms)

#### Security
- **Failed Authentication Rate** (alert if > 10/min)
- **Policy Denials** (alert if spike detected)
- **Rate Limit Violations** (alert if > 100/min)
- **Certificate Expiration** (alert 30 days before)

### Monitoring Dashboard

Access: https://secrethub.company.com/admin/performance

**Panels:**
- Current agent count
- Request rate (req/sec)
- P95/P99 latency
- Memory usage
- Database pool utilization
- Cache hit rate
- WebSocket metrics

---

## Backup & Recovery

### Backup Schedule

| Data | Frequency | Retention | Location |
|------|-----------|-----------|----------|
| **Database Full** | Daily | 30 days | S3 + RDS Snapshots |
| **Audit Logs** | Weekly | 7 years | S3 Glacier |
| **Configuration** | On Change | 90 days | Git + S3 |
| **Unseal Keys** | N/A | Permanent | HSM/KMS |

### Backup Procedures

#### Database Backup

```bash
#!/bin/bash
# daily-backup.sh

BACKUP_DIR="/var/backups/secrethub"
DATE=$(date +%Y%m%d)

# Backup database
pg_dump $DATABASE_URL | gzip > $BACKUP_DIR/db-$DATE.sql.gz

# Upload to S3
aws s3 cp $BACKUP_DIR/db-$DATE.sql.gz \
  s3://secrethub-backups/daily/

# Keep local backups for 7 days
find $BACKUP_DIR -name "db-*.sql.gz" -mtime +7 -delete

# Verify backup
if aws s3 ls s3://secrethub-backups/daily/db-$DATE.sql.gz; then
  echo "Backup successful: db-$DATE.sql.gz"
else
  echo "ERROR: Backup failed!"
  exit 1
fi
```

### Recovery Procedures

#### Restore from Backup

```bash
# 1. Download backup from S3
aws s3 cp s3://secrethub-backups/daily/db-20251103.sql.gz .

# 2. Stop Core instances
for host in core-1 core-2 core-3; do
  ssh $host "sudo systemctl stop secrethub-core"
done

# 3. Restore database
gunzip db-20251103.sql.gz
psql $DATABASE_URL < db-20251103.sql

# 4. Verify restoration
psql $DATABASE_URL -c "SELECT COUNT(*) FROM secrets;"

# 5. Start Core instances
for host in core-1 core-2 core-3; do
  ssh $host "sudo systemctl start secrethub-core"
done

# 6. Verify system health
curl https://secrethub.company.com/v1/sys/health
```

---

## Related Documentation

- [Troubleshooting Guide](./troubleshooting.md)
- [Architecture Overview](./architecture.md)
- [Deployment Runbook](./deployment/production-runbook.md)
- [Best Practices](./best-practices.md)

---

**Operator:** ___________
**Date:** ___________
**Version:** 1.0.0
