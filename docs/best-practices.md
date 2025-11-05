# SecretHub Best Practices

**Version:** 1.0.0
**Last Updated:** 2025-11-03

This guide provides security, performance, and operational best practices for deploying and managing SecretHub.

---

## Security Best Practices

### 1. Vault Unsealing

✅ **DO:**
- Use auto-unseal with AWS KMS or other KMS solution for production
- Distribute unseal keys to 5 different key custodians
- Store unseal keys in hardware security modules (HSMs) or secure vaults
- Test unseal procedures quarterly
- Document emergency unseal procedures

❌ **DON'T:**
- Store unseal keys in plain text or in version control
- Give all unseal keys to a single person
- Use manual unsealing in production (use auto-unseal)
- Store unseal keys on the same infrastructure as SecretHub

**Example: Auto-Unseal Configuration**
```elixir
# config/prod.exs
config :secrethub_core, :vault,
  auto_unseal: true,
  kms_provider: :aws_kms,
  kms_key_id: System.get_env("AWS_KMS_KEY_ID")
```

---

### 2. Authentication & Authorization

✅ **DO:**
- Use AppRole authentication for all machine-to-machine access
- Implement least privilege principle - grant minimum required permissions
- Rotate Secret IDs regularly (recommended: every 90 days)
- Use time-based and IP-based policy restrictions
- Enable MFA for admin users (future enhancement)
- Audit all authentication attempts

❌ **DON'T:**
- Share Secret IDs across multiple applications
- Use overly broad policies (e.g., `*` for all paths)
- Hard-code Secret IDs in application code
- Reuse Secret IDs after revocation
- Allow unauthenticated access to any endpoint

**Example: Restrictive Policy**
```json
{
  "name": "production-app",
  "rules": [
    {
      "path": "prod/myapp/*",
      "capabilities": ["read"],
      "effect": "allow",
      "conditions": {
        "time_of_day": [6, 22],           // 6 AM - 10 PM
        "days_of_week": [1,2,3,4,5],      // Weekdays only
        "source_ip": "10.0.0.0/8",        // Internal network only
        "ttl_max": 3600                    // Max 1-hour token TTL
      }
    }
  ]
}
```

---

### 3. Secret Management

✅ **DO:**
- Use dynamic secrets whenever possible (they auto-expire)
- Rotate static secrets regularly (recommended: every 90 days)
- Use descriptive secret paths (e.g., `prod/db/postgres/readonly`)
- Version secrets to enable rollback
- Audit all secret access
- Encrypt secrets at rest (enabled by default)
- Use short TTLs for dynamic secrets (1-24 hours)

❌ **DON'T:**
- Store secrets in environment variables or config files
- Use the same secret across multiple environments
- Share secrets between applications
- Store PII or sensitive customer data in secrets
- Keep secrets longer than necessary

**Secret Path Naming Convention:**
```
<environment>/<service>/<resource>/<role>

Examples:
prod/db/postgres/admin
prod/db/postgres/readonly
prod/api/stripe/webhook-secret
dev/cache/redis/password
```

---

### 4. Network Security

✅ **DO:**
- Use mTLS for all Agent ↔ Core communication
- Use HTTPS for all API access (TLS 1.2+)
- Restrict Core access to internal network or VPN
- Use security groups/firewall rules to limit access
- Enable force_ssl in production
- Use private subnets for Core and database

❌ **DON'T:**
- Expose Core directly to the internet without firewall
- Use plain HTTP in production
- Allow database direct access from outside VPC
- Disable SSL certificate verification

**Network Architecture:**
```
Internet
    │
    ├─ (HTTPS) Load Balancer (public subnet)
    │           │
    │           ├─ Core-1 (private subnet)
    │           ├─ Core-2 (private subnet)
    │           └─ Core-3 (private subnet)
    │                      │
    │                      └─ PostgreSQL (private subnet, no internet access)
    │
    └─ Agents (application subnets)
       ├─ agent-prod-01
       ├─ agent-prod-02
       └─ agent-prod-03
```

---

### 5. Audit Logging

✅ **DO:**
- Enable comprehensive audit logging (enabled by default)
- Export audit logs to SIEM or log aggregation system
- Review audit logs weekly for anomalies
- Retain audit logs for compliance period (typically 7 years)
- Monitor for unusual access patterns
- Alert on repeated authentication failures

❌ **DON'T:**
- Disable audit logging
- Delete audit logs prematurely
- Ignore audit log alerts
- Store audit logs only locally

**Audit Log Retention:**
```
Hot Storage (PostgreSQL):    30 days
Warm Storage (S3 Standard):  180 days
Cold Storage (S3 Glacier):   7 years
```

---

### 6. Certificate Management

✅ **DO:**
- Use internal PKI for agent certificates
- Rotate certificates before expiration (30 days)
- Monitor certificate expiration
- Use strong key sizes (RSA 4096 or ECDSA P-384)
- Revoke compromised certificates immediately
- Keep CRL (Certificate Revocation List) updated

❌ **DON'T:**
- Use self-signed certificates in production (use internal CA)
- Ignore certificate expiration warnings
- Reuse private keys
- Use weak key sizes (< 2048 bits)

---

## Performance Best Practices

### 1. Database Optimization

✅ **DO:**
- Use connection pooling (40+ connections per Core instance)
- Add indexes for frequently queried columns
- Run VACUUM ANALYZE regularly (weekly)
- Monitor query performance
- Use read replicas for reporting queries
- Enable PostgreSQL JIT compilation
- Use prepared statements (enabled by default)

❌ **DON'T:**
- Use a single database connection
- Skip database maintenance
- Run expensive queries during peak hours
- Ignore slow query logs

**Database Configuration:**
```elixir
# config/prod.exs
config :secrethub_core, SecretHub.Core.Repo,
  pool_size: 40,
  queue_target: 50,
  queue_interval: 1000,
  timeout: 15_000,
  prepare: :named,  # Prepared statement caching
  parameters: [
    jit: "on"         # Enable JIT compilation
  ]
```

---

### 2. Caching Strategy

✅ **DO:**
- Enable policy evaluation caching (enabled by default)
- Cache frequently accessed secret metadata
- Use appropriate TTLs (5-10 minutes for most data)
- Monitor cache hit rates (target: > 80%)
- Invalidate cache on updates
- Use distributed caching (Redis) for multi-node

❌ **DON'T:**
- Disable caching to "fix" bugs
- Use infinite TTLs
- Cache sensitive secret values (only metadata)
- Ignore low cache hit rates

**Cache Configuration:**
```elixir
# apps/secrethub_core/lib/secrethub_core/cache.ex
@default_ttl_seconds 300  # 5 minutes
@max_cache_entries 10_000

# Usage:
Cache.fetch(:policy, {policy_id, context}, fn ->
  # Expensive operation only on cache miss
  PolicyEvaluator.evaluate(policy_id, context)
end, ttl: 300)
```

---

### 3. Connection Management

✅ **DO:**
- Use persistent WebSocket connections for agents
- Implement exponential backoff for reconnections
- Set appropriate heartbeat intervals (30 seconds)
- Monitor connection pool utilization
- Configure max_connections appropriately (16k+)
- Use connection draining for graceful shutdowns

❌ **DON'T:**
- Use polling instead of persistent connections
- Reconnect too aggressively (causes thundering herd)
- Ignore connection pool exhaustion warnings
- Kill connections abruptly

**Agent Connection Configuration:**
```elixir
# apps/secrethub_agent/config/config.exs
config :secrethub_agent,
  heartbeat_interval: 30_000,  # 30 seconds
  reconnect_backoff: [1000, 2000, 4000, 8000, 16000, 32000, 60000],  # Exponential
  max_reconnect_attempts: :infinity
```

---

### 4. Monitoring & Alerting

✅ **DO:**
- Monitor all key metrics (latency, throughput, errors)
- Set up alerts for critical conditions
- Use the performance dashboard
- Track trends over time
- Alert on anomalies (spike in failures)
- Monitor certificate expiration

❌ **DON'T:**
- Rely only on logs for monitoring
- Ignore alert fatigue (tune thresholds)
- Alert on everything (only critical issues)
- Skip capacity planning

**Key Metrics to Monitor:**
```yaml
Critical Alerts:
  - Core instance down (1 min)
  - Vault sealed (1 min)
  - Database connection errors (2 min)
  - P95 latency > 200ms (5 min)

Warning Alerts:
  - Database pool > 80% (5 min)
  - Cache hit rate < 70% (10 min)
  - Disk usage > 80% (15 min)
  - Memory usage > 80% (15 min)

Info Alerts:
  - Certificate expiring in 30 days
  - Agents disconnected > 5% (10 min)
  - High failed authentication rate (5 min)
```

---

## Operational Best Practices

### 1. Deployment Strategy

✅ **DO:**
- Use blue-green or rolling deployments
- Test in staging environment first
- Deploy during low-traffic windows
- Have rollback plan ready
- Monitor metrics during deployment
- Deploy one node at a time

❌ **DON'T:**
- Deploy all nodes simultaneously
- Deploy on Friday afternoon
- Skip staging testing
- Deploy without monitoring
- Deploy breaking changes without migration

**Rolling Deployment Process:**
```bash
# 1. Deploy to core-1
ssh core-1 "sudo systemctl stop secrethub-core"
# Upload new release
ssh core-1 "sudo systemctl start secrethub-core"
# Verify health
curl https://core-1.internal:4000/v1/sys/health
# Wait 5 minutes, monitor

# 2. Repeat for core-2
# 3. Repeat for core-3
```

---

### 2. Backup & Disaster Recovery

✅ **DO:**
- Automate daily database backups
- Test backup restoration monthly
- Store backups in multiple locations
- Encrypt backups
- Document recovery procedures
- Practice disaster recovery drills

❌ **DON'T:**
- Rely only on database snapshots
- Skip backup verification
- Store backups on same infrastructure
- Forget to backup configuration

**Backup Strategy:**
```bash
# Daily: Full database backup to S3
pg_dump $DATABASE_URL | gzip > backup-$(date +%Y%m%d).sql.gz
aws s3 cp backup-*.sql.gz s3://secrethub-backups/daily/

# Weekly: Audit log archive to S3 Glacier
# Monthly: Configuration backup to Git + S3

# Retention:
# - Daily backups: 30 days
# - Weekly backups: 1 year
# - Monthly backups: 7 years
```

---

### 3. Change Management

✅ **DO:**
- Use version control for all configuration
- Document all changes in change log
- Require approval for production changes
- Test changes in development first
- Communicate changes to stakeholders
- Keep audit trail of changes

❌ **DON'T:**
- Make ad-hoc production changes
- Skip documentation
- Change multiple things at once
- Deploy without peer review

**Change Request Template:**
```markdown
## Change Request

**Date:** 2025-11-03
**Requester:** John Doe
**Reviewer:** Jane Smith

**Change Description:**
Update database connection pool from 40 to 60 connections

**Reason:**
Database pool utilization consistently > 85% during peak hours

**Impact:**
- Improved API performance during peak load
- Reduced connection wait times
- No downtime required

**Rollback Plan:**
Revert config/prod.exs and restart Core instances

**Testing:**
- Tested in staging with load test
- Verified pool utilization drops to < 70%

**Approval:** ✅ Approved
**Deployed:** 2025-11-03 02:00 UTC
```

---

### 4. Secret Rotation

✅ **DO:**
- Rotate secrets regularly (90-day cycle)
- Use dynamic secrets when possible
- Automate rotation process
- Test rotation in non-production first
- Coordinate with application teams
- Have rollback plan for failed rotations

❌ **DON'T:**
- Rotate all secrets simultaneously
- Skip testing rotation procedure
- Rotate without notifying dependent teams
- Use manual rotation for critical secrets

**Secret Rotation Schedule:**
```
Critical Secrets (every 30 days):
- Admin passwords
- Database root passwords
- API keys for external services

Standard Secrets (every 90 days):
- Application database passwords
- Service-to-service API keys
- Cache passwords

Low-Priority Secrets (every 180 days):
- Development environment secrets
- Non-production credentials
```

---

### 5. Capacity Planning

✅ **DO:**
- Monitor growth trends
- Plan capacity 6 months ahead
- Load test before scaling events
- Review capacity quarterly
- Document capacity limits
- Scale proactively

❌ **DON'T:**
- Wait for resource exhaustion
- Skip load testing
- Ignore growth trends
- Over-provision excessively

**Capacity Planning Metrics:**
```
Current (Week 30):
- Agents: 150
- Secrets: 5,000
- API requests: 50,000/hour
- Database: 50 GB

Projected (6 months):
- Agents: 500 (+233%)
- Secrets: 15,000 (+200%)
- API requests: 150,000/hour (+200%)
- Database: 150 GB (+200%)

Action Items:
- Scale Core to 5 instances (Q1 2026)
- Upgrade database instance (Q1 2026)
- Implement database sharding strategy (Q2 2026)
```

---

## Development Best Practices

### 1. Testing

✅ **DO:**
- Write unit tests for all business logic
- Write integration tests for API endpoints
- Test error handling paths
- Use test fixtures for consistent data
- Run tests in CI/CD pipeline
- Achieve > 80% code coverage

❌ **DON'T:**
- Skip tests to save time
- Test only happy paths
- Use production data in tests
- Commit broken tests

---

### 2. Code Quality

✅ **DO:**
- Use consistent code formatting (`mix format`)
- Run linter (`mix credo --strict`)
- Use static analysis (`mix dialyzer`)
- Write documentation for public APIs
- Review all code before merging
- Follow Elixir style guide

❌ **DON'T:**
- Skip code review
- Ignore linter warnings
- Write undocumented code
- Merge without CI passing

---

## Agent Deployment Best Practices

### 1. Agent Configuration

✅ **DO:**
- Use unique agent IDs for each agent
- Configure local caching (5-10 min TTL)
- Enable template rendering
- Use Unix Domain Socket for app communication
- Monitor agent health
- Deploy agents close to applications

❌ **DON'T:**
- Reuse agent IDs
- Disable caching
- Expose agent API over network
- Deploy agents on Core instances

**Agent Configuration Example:**
```toml
[agent]
id = "agent-prod-web-01"
core_url = "wss://secrethub.company.com"

[auth]
role_id = "abc-123-def-456"
secret_id = "xyz-789-uvw-012"

[cache]
enabled = true
ttl = 300  # 5 minutes
max_size_mb = 100

[templates]
enabled = true
directory = "/etc/secrethub/templates"
output_directory = "/etc/app/config"

[connection]
heartbeat_interval = 30
reconnect_backoff = [1000, 2000, 4000, 8000, 16000, 32000, 60000]
```

---

### 2. Template Usage

✅ **DO:**
- Use templates for config file generation
- Include error handling in templates
- Use atomic file writes
- Set appropriate file permissions
- Trigger application reload on update

❌ **DON'T:**
- Write secrets directly to logs
- Use world-readable file permissions
- Expose secrets in process listing

**Template Example:**
```hcl
# /etc/secrethub/templates/app-config.json.tpl
{{- with secret "prod/db/postgres" -}}
{
  "database": {
    "host": "{{ .Data.host }}",
    "port": {{ .Data.port }},
    "username": "{{ .Data.username }}",
    "password": "{{ .Data.password }}",
    "database": "myapp"
  }
}
{{- end -}}
```

---

## Compliance Best Practices

### 1. Audit & Compliance

✅ **DO:**
- Retain audit logs for required compliance period
- Export logs to compliance-approved storage
- Generate compliance reports regularly
- Document security controls
- Perform regular security audits
- Maintain change documentation

❌ **DON'T:**
- Delete audit logs prematurely
- Skip compliance reviews
- Ignore security findings

---

## Summary Checklist

### Pre-Production Checklist

- [ ] Auto-unseal configured with KMS
- [ ] Database backups automated
- [ ] Monitoring and alerting configured
- [ ] SSL certificates installed
- [ ] Security groups/firewall rules configured
- [ ] Load balancer health checks working
- [ ] Audit logging enabled and exported
- [ ] Disaster recovery procedures documented
- [ ] Load testing completed (1,000+ agents)
- [ ] Security audit completed
- [ ] All documentation up to date
- [ ] On-call procedures documented
- [ ] Team trained on operations

---

## Related Documentation

- [Architecture Overview](./architecture.md)
- [Deployment Runbook](./deployment/production-runbook.md)
- [Operator Manual](./operator-manual.md)
- [Troubleshooting Guide](./troubleshooting.md)
- [Security Model](./security-model.md)

---

**Last Reviewed:** 2025-11-03
**Next Review:** 2026-02-03 (Quarterly)
