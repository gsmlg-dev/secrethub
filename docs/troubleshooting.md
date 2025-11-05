# SecretHub Troubleshooting Guide

Common issues and their solutions for SecretHub deployment and operations.

---

## Quick Diagnosis

### System Health Check

```bash
# 1. Check Core health
curl https://secrethub.company.com/v1/sys/health

# 2. Check seal status
curl https://secrethub.company.com/v1/sys/seal-status

# 3. Check database connectivity
psql $DATABASE_URL -c "SELECT 1;"

# 4. Check Core logs
sudo journalctl -u secrethub-core -n 50

# 5. Check agent connectivity
secrethub-agent status
```

---

## Core Issues

### Issue: Vault is Sealed

**Symptoms:**
- API returns `503 Service Unavailable`
- Error: `{"errors":["Vault is sealed"]}`
- Web UI shows "Vault Sealed" message

**Diagnosis:**
```bash
curl https://secrethub.company.com/v1/sys/seal-status
# Output: {"sealed": true, "t": 3, "n": 5, "progress": 0}
```

**Solution:**

Unseal the vault with 3 of 5 unseal keys:

```bash
# Unseal with key 1
curl -X POST https://secrethub.company.com/v1/sys/unseal \
  -d '{"key": "unseal-key-1"}'

# Unseal with key 2
curl -X POST https://secrethub.company.com/v1/sys/unseal \
  -d '{"key": "unseal-key-2"}'

# Unseal with key 3 (vault is now unsealed)
curl -X POST https://secrethub.company.com/v1/sys/unseal \
  -d '{"key": "unseal-key-3"}'
```

**Prevention:**
- Enable auto-unseal with AWS KMS or other KMS
- Set up monitoring alerts for seal status
- Document unseal procedures for on-call team

---

### Issue: Core Won't Start

**Symptoms:**
- `systemctl status secrethub-core` shows "failed"
- Error in logs: `** (exit) an exception was raised`

**Diagnosis:**
```bash
# Check logs
sudo journalctl -u secrethub-core -n 100 --no-pager

# Check if port is in use
sudo lsof -i :4000

# Check environment variables
sudo systemctl show secrethub-core --property=Environment
```

**Common Causes & Solutions:**

**1. Database Connection Error**
```
Error: (Postgrex.Error) connection not available and request was dropped from queue
```

Solution:
```bash
# Verify DATABASE_URL
echo $DATABASE_URL

# Test database connectivity
psql $DATABASE_URL -c "SELECT version();"

# Check database is running
sudo systemctl status postgresql
```

**2. Port Already in Use**
```
Error: (Bandit.ListeningError) failed to listen on port 4000
```

Solution:
```bash
# Find process using port 4000
sudo lsof -i :4000

# Kill conflicting process
sudo kill -9 <PID>

# Or change PORT in environment
export PORT=4001
```

**3. Missing Environment Variables**
```
Error: environment variable SECRET_KEY_BASE is missing
```

Solution:
```bash
# Add to /opt/secrethub/secrethub.env
SECRET_KEY_BASE=$(mix phx.gen.secret)

# Reload systemd
sudo systemctl daemon-reload
sudo systemctl restart secrethub-core
```

---

### Issue: High Memory Usage

**Symptoms:**
- Core process using > 8 GB RAM
- OOM (Out of Memory) errors
- System becoming unresponsive

**Diagnosis:**
```bash
# Check memory usage
ps aux | grep beam

# Check ETS table sizes
# Connect to running Core instance
/opt/secrethub/secrethub_core/bin/secrethub_core remote

# In Elixir console:
:ets.i()
```

**Solutions:**

**1. Cache Size Too Large**
```elixir
# Check cache stats
SecretHub.Core.Cache.stats_all()

# If cache is too large, reduce max entries
# In config:
config :secrethub_core, :cache,
  max_entries: 5_000  # Reduce from 10,000
```

**2. Memory Leak in Long-Running Processes**
```bash
# Restart Core instances one at a time
sudo systemctl restart secrethub-core

# Monitor memory after restart
watch -n 1 'ps aux | grep beam'
```

**3. Increase System Memory**
```bash
# For production, ensure:
# - 8 GB RAM minimum per Core instance
# - Swap space configured (4 GB)
```

---

### Issue: Slow Database Queries

**Symptoms:**
- High API latency (P95 > 500ms)
- Database pool exhausted warnings
- Timeout errors

**Diagnosis:**
```bash
# Check database pool utilization
curl https://secrethub.company.com/admin/api/dashboard/stats \
  -H "X-Vault-Token: $TOKEN" | jq '.db_pool_utilization'

# Check slow queries in PostgreSQL
psql $DATABASE_URL <<EOF
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
WHERE mean_exec_time > 100
ORDER BY mean_exec_time DESC
LIMIT 10;
EOF
```

**Solutions:**

**1. Missing Indexes**
```sql
-- Add index on frequently queried columns
CREATE INDEX CONCURRENTLY secrets_path_idx ON secrets(path);
CREATE INDEX CONCURRENTLY audit_timestamp_idx ON audit.events(timestamp);
CREATE INDEX CONCURRENTLY policies_entity_id_idx ON policies(entity_id);
```

**2. Increase Connection Pool**
```elixir
# In config/prod.exs
config :secrethub_core, SecretHub.Core.Repo,
  pool_size: 60  # Increase from 40
```

**3. Enable Query Caching**
```bash
# Verify cache is enabled
curl https://secrethub.company.com/admin/performance | grep cache_hit_rate

# If cache hit rate < 70%, investigate why caching isn't working
```

---

## Agent Issues

### Issue: Agent Can't Connect to Core

**Symptoms:**
- Agent logs: `Connection refused`
- Agent status: `Connected: false`
- Applications can't retrieve secrets

**Diagnosis:**
```bash
# Check agent logs
journalctl -u secrethub-agent -f

# Test Core connectivity
curl https://secrethub.company.com/v1/sys/health

# Check agent configuration
cat /etc/secrethub/agent.toml
```

**Solutions:**

**1. Network Connectivity**
```bash
# Test DNS resolution
nslookup secrethub.company.com

# Test HTTPS connectivity
curl -v https://secrethub.company.com/v1/sys/health

# Check firewall rules
sudo iptables -L -n | grep 443
```

**2. Invalid Credentials**
```
Error: authentication failed: invalid role_id or secret_id
```

Solution:
```bash
# Regenerate Secret ID
curl -X POST https://secrethub.company.com/v1/auth/approle/role/agents/secret-id \
  -H "X-Vault-Token: $TOKEN"

# Update agent config with new secret_id
sudo vim /etc/secrethub/agent.toml

# Restart agent
sudo systemctl restart secrethub-agent
```

**3. SSL Certificate Issues**
```
Error: certificate verify failed
```

Solution:
```bash
# Update CA certificates
sudo update-ca-certificates

# Or disable SSL verification (NOT recommended for production)
# In agent.toml:
[tls]
verify_ssl = false
```

---

### Issue: Agent Connection Dropping Frequently

**Symptoms:**
- Agent logs show repeated reconnections
- Applications experiencing intermittent secret access failures

**Diagnosis:**
```bash
# Check reconnection frequency
journalctl -u secrethub-agent | grep "reconnecting"

# Check network stability
ping -c 100 secrethub.company.com

# Check Core load
curl https://secrethub.company.com/admin/performance
```

**Solutions:**

**1. Network Instability**
```bash
# Increase heartbeat interval
# In agent.toml:
[connection]
heartbeat_interval = 60  # Increase from 30 seconds
```

**2. Load Balancer Timeout**
```
# Increase load balancer idle timeout to 120 seconds
# AWS ALB example:
aws elbv2 modify-target-group-attributes \
  --target-group-arn <arn> \
  --attributes Key=deregistration_delay.timeout_seconds,Value=120
```

**3. Core Instance Unhealthy**
```bash
# Check Core instances
for host in core-1 core-2 core-3; do
  curl https://$host.internal:4000/v1/sys/health
done

# If any are unhealthy, investigate:
sudo journalctl -u secrethub-core -n 100
```

---

## Database Issues

### Issue: Database Connection Pool Exhausted

**Symptoms:**
- Error: `connection not available and request was dropped from queue`
- High API latency
- 503 errors

**Diagnosis:**
```bash
# Check pool utilization
curl https://secrethub.company.com/admin/performance | jq '.db_pool_utilization'

# Check active connections in PostgreSQL
psql $DATABASE_URL <<EOF
SELECT count(*) as active_connections,
       max_connections
FROM pg_stat_activity, pg_settings
WHERE pg_settings.name = 'max_connections'
GROUP BY max_connections;
EOF
```

**Solutions:**

**1. Increase Pool Size**
```elixir
# In config/prod.exs
config :secrethub_core, SecretHub.Core.Repo,
  pool_size: 60  # Increase based on load

# Restart Core instances
```

**2. Optimize Slow Queries**
```sql
-- Find queries holding connections
SELECT pid, age(clock_timestamp(), query_start), usename, query
FROM pg_stat_activity
WHERE state != 'idle' AND query NOT ILIKE '%pg_stat_activity%'
ORDER BY query_start;

-- Kill long-running queries if needed
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE ...;
```

**3. Increase PostgreSQL max_connections**
```sql
-- Check current max
SHOW max_connections;

-- Increase (requires restart)
ALTER SYSTEM SET max_connections = 200;
-- Then restart PostgreSQL
```

---

### Issue: Database Running Out of Disk Space

**Symptoms:**
- Error: `No space left on device`
- Write operations failing
- Database growing rapidly

**Diagnosis:**
```bash
# Check disk usage
df -h /var/lib/postgresql

# Check table sizes
psql $DATABASE_URL <<EOF
SELECT schemaname, tablename,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
LIMIT 10;
EOF
```

**Solutions:**

**1. Clean Up Audit Logs**
```sql
-- Archive old audit logs to S3
COPY (SELECT * FROM audit.events WHERE timestamp < NOW() - INTERVAL '90 days')
TO '/tmp/audit_archive.csv' CSV HEADER;

-- Delete old logs
DELETE FROM audit.events WHERE timestamp < NOW() - INTERVAL '90 days';

-- Vacuum to reclaim space
VACUUM FULL audit.events;
```

**2. Clean Up Old Secret Versions**
```sql
-- Keep only last 10 versions per secret
DELETE FROM secret_versions
WHERE id NOT IN (
  SELECT id FROM (
    SELECT id, ROW_NUMBER() OVER (PARTITION BY secret_id ORDER BY created_at DESC) as rn
    FROM secret_versions
  ) t
  WHERE rn <= 10
);

VACUUM FULL secret_versions;
```

**3. Increase Disk Space**
```bash
# Resize volume (AWS EBS example)
aws ec2 modify-volume --volume-id vol-xxxxx --size 500

# Resize filesystem
sudo resize2fs /dev/xvdf
```

---

## Performance Issues

### Issue: High API Latency

**Symptoms:**
- P95 latency > 200ms
- Slow Web UI
- Timeouts

**Diagnosis:**
```bash
# Check performance dashboard
open https://secrethub.company.com/admin/performance

# Check specific endpoint latency
curl -w "@curl-format.txt" https://secrethub.company.com/v1/secrets/static/test
```

**Create `curl-format.txt`:**
```
time_namelookup:  %{time_namelookup}
time_connect:  %{time_connect}
time_appconnect:  %{time_appconnect}
time_pretransfer:  %{time_pretransfer}
time_redirect:  %{time_redirect}
time_starttransfer:  %{time_starttransfer}
----------
time_total:  %{time_total}
```

**Solutions:**

**1. Enable Query Caching**
```elixir
# Verify cache is working
SecretHub.Core.Cache.stats(:policy_cache)
SecretHub.Core.Cache.stats(:query_cache)

# If hit rate is low, increase TTL
# In config:
config :secrethub_core, :cache,
  default_ttl: 600  # 10 minutes
```

**2. Optimize Database Queries**
```elixir
# Enable query logging
config :secrethub_core, SecretHub.Core.Repo,
  log: :info

# Identify N+1 queries and add preloading
# Before:
secrets = Repo.all(Secret)
Enum.map(secrets, & &1.versions)  # N+1 query

# After:
secrets = Repo.all(Secret) |> Repo.preload(:versions)
```

**3. Scale Horizontally**
```bash
# Add more Core instances
# Update load balancer to include new instances
```

---

## Security Issues

### Issue: Unauthorized Access Attempts

**Symptoms:**
- Audit logs showing many denied access attempts
- Unusual login patterns
- Failed authentication spike

**Diagnosis:**
```bash
# Check audit logs for denied access
curl https://secrethub.company.com/admin/api/dashboard/audit \
  -H "X-Vault-Token: $TOKEN" | jq '.[] | select(.access_granted == false)'

# Check rate limiter violations
curl https://secrethub.company.com/admin/performance | jq '.rate_limit_violations'
```

**Actions:**

**1. Review Access Patterns**
```sql
-- Find IPs with high denial rate
SELECT source_ip, COUNT(*) as denied_attempts
FROM audit.events
WHERE access_granted = false
  AND timestamp > NOW() - INTERVAL '1 hour'
GROUP BY source_ip
ORDER BY denied_attempts DESC
LIMIT 10;
```

**2. Block Malicious IPs**
```bash
# Add to firewall
sudo iptables -A INPUT -s <malicious-ip> -j DROP

# Or use AWS security groups
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxx \
  --ip-permissions IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges='[{CidrIp=<malicious-ip>/32}]'
```

**3. Rotate Compromised Credentials**
```bash
# Revoke AppRole Secret IDs
curl -X POST https://secrethub.company.com/v1/auth/approle/role/<role>/secret-id/revoke \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"secret_id": "<compromised-secret-id>"}'

# Generate new Secret ID
curl -X POST https://secrethub.company.com/v1/auth/approle/role/<role>/secret-id \
  -H "X-Vault-Token: $TOKEN"
```

---

## Monitoring & Alerting

### Setting Up Alerts

**Critical Alerts:**
```yaml
# Prometheus alert rules
groups:
  - name: secrethub-critical
    rules:
      - alert: CoreDown
        expr: up{job="secrethub-core"} == 0
        for: 1m
        annotations:
          summary: "SecretHub Core instance down"

      - alert: VaultSealed
        expr: secrethub_vault_sealed == 1
        for: 1m
        annotations:
          summary: "Vault is sealed - requires unseal"

      - alert: DatabaseDown
        expr: secrethub_db_connection_errors > 10
        for: 2m
        annotations:
          summary: "Database connection errors"
```

---

## Getting Help

### Before Opening an Issue

1. **Collect logs:**
   ```bash
   # Core logs
   sudo journalctl -u secrethub-core -n 1000 > core-logs.txt

   # Agent logs
   sudo journalctl -u secrethub-agent -n 1000 > agent-logs.txt

   # Database logs
   sudo tail -n 1000 /var/log/postgresql/postgresql-16-main.log > db-logs.txt
   ```

2. **System information:**
   ```bash
   # System info
   uname -a
   free -h
   df -h

   # Core version
   /opt/secrethub/secrethub_core/bin/secrethub_core version
   ```

3. **Configuration (redact secrets):**
   ```bash
   # Sanitized config
   cat /etc/secrethub/agent.toml | grep -v secret_id
   ```

### Support Channels

- **GitHub Issues:** https://github.com/your-org/secrethub/issues
- **Discussions:** https://github.com/your-org/secrethub/discussions
- **Slack:** #secrethub-support
- **Email:** support@secrethub.io

---

## Related Documentation

- [Operator Manual](./operator-manual.md)
- [Architecture](./architecture.md)
- [Deployment Guide](./deployment/README.md)
- [Performance Tuning](./best-practices/performance.md)
