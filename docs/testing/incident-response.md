# Incident Response Procedures

**Purpose:** Structured approach to handling SecretHub incidents
**Audience:** On-call engineers, incident commanders
**Last Updated:** 2025-11-04

---

## Incident Severity Levels

| Severity | Definition | Response Time | Examples |
|----------|-----------|---------------|----------|
| **P0 - Critical** | Complete service outage, data loss | Immediate (< 5 min) | Vault sealed all instances, database down, all Core instances down |
| **P1 - High** | Major degradation, security breach | < 15 minutes | Single Core instance down, high latency (> 500ms), security vulnerability |
| **P2 - Medium** | Partial degradation, workaround available | < 1 hour | Minor performance issues, non-critical bugs |
| **P3 - Low** | Minimal impact | < 4 hours | Cosmetic issues, feature requests |

---

## Incident Response Workflow

```
1. DETECT → 2. ASSESS → 3. RESPOND → 4. RESOLVE → 5. REVIEW
```

---

## Phase 1: Detection & Alert

### Automated Detection
- Prometheus alerts → PagerDuty → On-call engineer
- Synthetic monitoring failures → Email + Slack
- User reports → Ticket system

### Manual Detection
```bash
# Quick health check
curl https://secrethub.company.com/v1/sys/health
# Expected: 200 OK, sealed: false

# Check metrics
open https://grafana.company.com/d/secrethub-overview
```

---

## Phase 2: Assessment

### Initial Response (First 5 Minutes)

```bash
# 1. Acknowledge alert
# In PagerDuty: Click "Acknowledge"

# 2. Check system status
curl https://secrethub.company.com/v1/sys/health | jq '.'

# 3. Check Core instances
kubectl get pods -n secrethub -l app=secrethub-core

# 4. Check recent logs
kubectl logs -n secrethub -l app=secrethub-core --tail=50 --since=10m

# 5. Determine severity
```

### Severity Assessment Matrix

| Impact | Users Affected | Severity |
|--------|---------------|----------|
| Complete outage | All | P0 |
| Major degradation | > 50% | P1 |
| Partial degradation | 10-50% | P2 |
| Minimal | < 10% | P3 |

---

## Phase 3: Response by Scenario

### Scenario 1: Vault Sealed **[P0]**

**Symptoms:**
- HTTP 503 Service Unavailable
- API returns "Vault is sealed"

**Response:**
```bash
# 1. Confirm vault sealed
curl https://secrethub.company.com/v1/sys/seal-status | jq '.sealed'
# Returns: true

# 2. Identify sealed instances
kubectl get pods -n secrethub -l app=secrethub-core -o wide

for pod in $(kubectl get pods -n secrethub -l app=secrethub-core -o name); do
  echo "Checking $pod..."
  kubectl exec -n secrethub $pod -- \
    curl -s http://localhost:4000/v1/sys/seal-status | jq '.sealed'
done

# 3. Contact key custodians
# Call script:
echo "
This is [Your Name] from SecretHub operations.
We have a P0 incident - the vault is sealed.
I need your unseal key to restore service.
Can you provide it via secure channel?
"

# 4. Collect 3 of 5 unseal keys
# Keys should be provided via secure channel (encrypted email, password manager)

# 5. Unseal each instance
for pod in $(kubectl get pods -n secrethub -l app=secrethub-core -o name); do
  kubectl exec -n secrethub $pod -- \
    curl -X POST http://localhost:4000/v1/sys/unseal \
    -d '{"key": "KEY1"}'

  kubectl exec -n secrethub $pod -- \
    curl -X POST http://localhost:4000/v1/sys/unseal \
    -d '{"key": "KEY2"}'

  kubectl exec -n secrethub $pod -- \
    curl -X POST http://localhost:4000/v1/sys/unseal \
    -d '{"key": "KEY3"}'
done

# 6. Verify unsealed
curl https://secrethub.company.com/v1/sys/seal-status | jq '.sealed'
# Returns: false

# 7. Monitor for 15 minutes
watch -n 30 'curl -s https://secrethub.company.com/v1/sys/health | jq .'
```

**Resolution Time:** < 15 minutes

---

### Scenario 2: Database Down **[P0]**

**Symptoms:**
- Core logs show database connection errors
- 500 Internal Server Error on API calls

**Response:**
```bash
# 1. Verify database status
aws rds describe-db-instances \
  --db-instance-identifier secrethub-prod \
  --query 'DBInstances[0].DBInstanceStatus'

# 2. If "available" but connections failing
# Check security groups
aws ec2 describe-security-groups --group-ids sg-XXXXXXXX

# Check connection from Core pod
kubectl exec -n secrethub $(kubectl get pod -n secrethub -l app=secrethub-core -o jsonpath='{.items[0].metadata.name}') \
  -- nc -zv $DB_ENDPOINT 5432

# 3. If database not available
# Check for automated failover (Multi-AZ)
# Wait up to 2 minutes for automatic failover

# 4. If failover doesn't occur
# Manual intervention required - escalate to Database Admin

# 5. Once database restored
# Verify Core reconnection
kubectl logs -n secrethub -l app=secrethub-core --tail=20 | grep -i database
```

**Resolution Time:** < 30 minutes (with Multi-AZ failover)

---

### Scenario 3: Core Instance Down **[P1]**

**Symptoms:**
- One pod shows "CrashLoopBackOff" or "Error"
- Grafana shows one instance not reporting metrics

**Response:**
```bash
# 1. Identify failed pod
kubectl get pods -n secrethub -l app=secrethub-core
# Look for non-Running status

# 2. Get pod logs
FAILED_POD=$(kubectl get pod -n secrethub -l app=secrethub-core --field-selector=status.phase!=Running -o jsonpath='{.items[0].metadata.name}')
kubectl logs -n secrethub $FAILED_POD --tail=100

# 3. Describe pod for events
kubectl describe pod -n secrethub $FAILED_POD

# 4. If OOMKilled (Out of Memory)
# Increase memory limits temporarily
kubectl set resources deployment/secrethub-core \
  -n secrethub \
  --limits=memory=4Gi

# 5. If CrashLoopBackOff
# Delete pod, let Kubernetes recreate
kubectl delete pod -n secrethub $FAILED_POD

# 6. Monitor new pod
kubectl logs -n secrethub $FAILED_POD --follow

# 7. If persists, consider rollback (see Rollback Procedures)
```

**Resolution Time:** < 30 minutes

---

### Scenario 4: High Latency **[P1]**

**Symptoms:**
- P95 latency > 500ms
- Alert: "High latency detected"

**Response:**
```bash
# 1. Check current latency
curl -w "@curl-format.txt" -o /dev/null -s https://secrethub.company.com/v1/sys/health

# curl-format.txt:
time_total: %{time_total}

# 2. Check database performance
psql $DATABASE_URL -c "
  SELECT pid, query, state, wait_event_type, wait_event
  FROM pg_stat_activity
  WHERE state != 'idle'
  ORDER BY query_start;
"

# 3. Check for slow queries
psql $DATABASE_URL -c "
  SELECT query, calls, mean_exec_time, max_exec_time
  FROM pg_stat_statements
  ORDER BY mean_exec_time DESC
  LIMIT 10;
"

# 4. Check cache hit rate
curl -s http://prometheus:9090/api/v1/query \
  --data-urlencode 'query=secrethub_cache_hit_rate' | jq '.data.result[0].value[1]'

# 5. Check database connection pool
curl -s http://prometheus:9090/api/v1/query \
  --data-urlencode 'query=secrethub_db_pool_utilization' | jq '.data.result[0].value[1]'

# If > 90%, consider increasing pool size

# 6. Restart high-latency pods one at a time
for pod in $(kubectl get pods -n secrethub -l app=secrethub-core -o name); do
  kubectl delete $pod -n secrethub
  sleep 60  # Wait for pod to restart and stabilize
done
```

**Resolution Time:** < 1 hour

---

### Scenario 5: Security Breach **[P0]**

**Symptoms:**
- Unauthorized access detected
- Unusual audit log patterns
- Security alert triggered

**Response:**
```bash
# 1. IMMEDIATELY seal vault
kubectl exec -n secrethub $(kubectl get pod -n secrethub -l app=secrethub-core -o jsonpath='{.items[0].metadata.name}') \
  -- curl -X POST http://localhost:4000/v1/sys/seal \
  -H "X-Vault-Token: $ADMIN_TOKEN"

# 2. Isolate affected systems
# Block network access if needed
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-secrethub
  namespace: secrethub
spec:
  podSelector:
    matchLabels:
      app: secrethub-core
  policyTypes:
  - Ingress
  - Egress
  ingress: []  # Block all ingress
  egress: []   # Block all egress
EOF

# 3. Collect evidence
# Export audit logs
psql $DATABASE_URL -c "
  COPY (SELECT * FROM audit.events WHERE timestamp > NOW() - INTERVAL '24 hours')
  TO '/tmp/audit-evidence.csv' CSV HEADER;
"

# Upload to secure location
aws s3 cp /tmp/audit-evidence.csv \
  s3://secrethub-security-incidents/$(date +%Y%m%d)/audit-evidence.csv \
  --sse

# 4. Notify security team
curl -X POST $SECURITY_SLACK_WEBHOOK \
  -d '{"text": "🚨 P0 SECURITY INCIDENT: SecretHub - Unauthorized access detected. Vault sealed. Investigation underway."}'

# 5. Preserve logs
kubectl logs -n secrethub -l app=secrethub-core --all-containers --since=24h > /tmp/core-logs.txt
aws s3 cp /tmp/core-logs.txt s3://secrethub-security-incidents/$(date +%Y%m%d)/

# 6. Follow security incident response playbook
# DO NOT unseal vault until security team approves
```

**Resolution Time:** Variable (hours to days)

---

## Phase 4: Communication

### Status Updates

**Initial Alert (< 5 minutes)**
```
🔴 INCIDENT: SecretHub - [Brief Description]
Severity: P[0-3]
Status: Investigating
Impact: [Description]
ETA: [Time]
Incident Commander: [Name]
```

**Progress Updates (Every 30 minutes)**
```
🟡 UPDATE: SecretHub Incident
Status: [In Progress/Identified/Fixing]
Progress: [What's been done]
Next Steps: [What's next]
ETA: [Updated time]
```

**Resolution**
```
🟢 RESOLVED: SecretHub Incident
Duration: [X minutes/hours]
Impact: [Summary]
Root Cause: [Brief explanation]
Follow-up: Post-mortem scheduled for [Date/Time]
```

### Communication Channels
- **#secrethub-incidents** (Slack) - Real-time updates
- **incidents-secrethub@company.com** - Email updates
- **https://status.secrethub.company.com** - Public status page

---

## Phase 5: Post-Incident Review

### Immediate Actions (Within 24 Hours)

```markdown
# Quick Incident Summary

**Date:** YYYY-MM-DD
**Duration:** X hours Y minutes
**Severity:** P[0-3]

## Impact
- Users affected: XXX
- Downtime: X minutes
- Data loss: YES/NO

## Timeline
- HH:MM - Incident detected
- HH:MM - Response initiated
- HH:MM - Root cause identified
- HH:MM - Fix applied
- HH:MM - Incident resolved

## Root Cause
[1-2 sentence description]

## Action Items
1. [ ] [Action] - Owner: [Name] - Due: [Date]
2. [ ] [Action] - Owner: [Name] - Due: [Date]
```

### Post-Mortem (Within 1 Week)

**Attendees:** All involved team members, stakeholders

**Agenda:**
1. Timeline review (10 min)
2. What went well (10 min)
3. What didn't go well (15 min)
4. Root cause analysis (15 min)
5. Action items (10 min)

**Deliverable:** Post-mortem document with action items

---

## Incident Response Tools

```bash
# Health check script
./scripts/health-check.sh

# Log aggregation
./scripts/collect-logs.sh --since=1h

# Database diagnostics
./scripts/db-diagnostics.sh

# Performance snapshot
./scripts/performance-snapshot.sh
```

---

## Emergency Contacts

```
Primary On-Call: [Name] - [Phone] - [Email]
Secondary On-Call: [Name] - [Phone] - [Email]
Incident Commander: [Name] - [Phone] - [Email]

Database Admin: [Name] - [Phone]
Security Lead: [Name] - [Phone]
Infrastructure Lead: [Name] - [Phone]

Escalation Path:
1. Engineering Manager: [Name] - [Phone]
2. VP Engineering: [Name] - [Phone]
```

---

## Related Documentation

- [Rollback Procedures](../deployment/rollback-procedures.md)
- [Disaster Recovery](./disaster-recovery-procedures.md)
- [Troubleshooting Guide](../troubleshooting.md)
- [Production Runbook](../deployment/production-runbook.md)

---

**Last Updated:** 2025-11-04
**Next Review:** Quarterly or after each P0/P1 incident
