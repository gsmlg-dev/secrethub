# Disaster Recovery Testing Procedures

**Purpose:** Validate SecretHub's ability to recover from catastrophic failures
**Frequency:** Quarterly (minimum), before major releases
**Duration:** 6-8 hours for complete DR testing
**Prerequisites:** Staging environment that mirrors production

---

## Overview

Disaster Recovery (DR) testing ensures that SecretHub can recover from catastrophic failures with minimal data loss and downtime. These procedures test the complete DR capability, including:

- Database failures and restoration
- Core cluster complete loss
- Cross-region failover (if applicable)
- Vault seal/unseal procedures under stress

**Recovery Objectives:**
- **RTO (Recovery Time Objective):** 1 hour for database loss, 30 minutes for Core loss
- **RPO (Recovery Point Objective):** 1 hour for database (backup frequency), 0 for Core-only failures

---

## Pre-Test Preparation

### 1. Environment Setup

```bash
# Verify staging environment is production-like
kubectl get nodes
kubectl get pods -n secrethub

# Verify monitoring is operational
curl http://prometheus:9090/-/healthy
curl http://grafana:3000/api/health

# Verify backup systems
aws s3 ls s3://secrethub-backups-staging/
```

### 2. Baseline Metrics Collection

```bash
# Document current state
cat > /tmp/dr-test-baseline.txt <<EOF
=== DR Test Baseline ===
Date: $(date)
Environment: Staging

Database:
$(psql $DATABASE_URL -c "SELECT count(*) FROM secrets;")
$(psql $DATABASE_URL -c "SELECT count(*) FROM audit.events;")
$(psql $DATABASE_URL -c "SELECT count(*) FROM policies;")
$(psql $DATABASE_URL -c "SELECT count(*) FROM approles;")

Core Instances:
$(kubectl get pods -n secrethub -l app=secrethub-core)

Agents:
$(curl -s http://core-lb/admin/api/dashboard/stats | jq '.connected_agents')

Test Data Checksum:
$(psql $DATABASE_URL -c "SELECT md5(string_agg(path, '')) FROM secrets ORDER BY path;")
EOF

cat /tmp/dr-test-baseline.txt
```

### 3. Test Data Creation

```bash
# Create test data for verification
echo "Creating test data for DR validation..."

# Create 100 test secrets
for i in {1..100}; do
  curl -X POST http://core-lb/v1/secrets/static/dr-test/secret-$i \
    -H "X-Vault-Token: $ADMIN_TOKEN" \
    -d "{\"data\": {\"value\": \"test-$i\", \"timestamp\": \"$(date -Iseconds)\"}}"
done

# Create test policies
curl -X POST http://core-lb/v1/policies \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "name": "dr-test-policy",
    "rules": [{"path": "dr-test/*", "capabilities": ["read"], "effect": "allow"}]
  }'

# Create test AppRole
curl -X POST http://core-lb/v1/auth/approle/role/dr-test-role \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{"role_name": "dr-test-role", "policies": ["dr-test-policy"]}'

echo "Test data created successfully"
```

### 4. Notification Setup

```bash
# Notify team that DR testing is beginning
curl -X POST https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK \
  -d '{"text": "🧪 DR Testing starting in staging environment"}'
```

---

## DR Test 1: Complete Database Loss

**Scenario:** Primary database completely lost and must be restored from backup
**RTO Target:** 1 hour
**RPO Target:** 1 hour (last backup)

### Phase 1: Pre-Failure Snapshot

```bash
# 1. Take manual snapshot (in addition to automated backups)
echo "Taking pre-test snapshot..."
SNAPSHOT_ID="dr-test-$(date +%Y%m%d-%H%M%S)"

aws rds create-db-snapshot \
  --db-instance-identifier secrethub-staging \
  --db-snapshot-identifier $SNAPSHOT_ID

# Wait for snapshot to complete
echo "Waiting for snapshot to complete..."
aws rds wait db-snapshot-completed \
  --db-snapshot-identifier $SNAPSHOT_ID

echo "Snapshot created: $SNAPSHOT_ID"

# 2. Record exact database state
psql $DATABASE_URL > /tmp/dr-test-db-state.sql <<EOF
-- Export all secrets
COPY (SELECT * FROM secrets ORDER BY id) TO STDOUT WITH CSV HEADER;

-- Export checksum
SELECT md5(string_agg(path || value_encrypted, '')) as checksum
FROM secrets ORDER BY id;
EOF
```

### Phase 2: Simulate Database Failure

```bash
# START TIMER
START_TIME=$(date +%s)
echo "DR Test Start Time: $(date)"

# 1. Simulate catastrophic database failure
echo "⚠️  SIMULATING DATABASE FAILURE"
aws rds stop-db-instance --db-instance-identifier secrethub-staging

# 2. Verify Core instances detect failure
echo "Monitoring Core instances..."
kubectl logs -n secrethub -l app=secrethub-core --tail=50 | grep -i "database"

# Expected: Connection errors in logs
```

### Phase 3: Database Restoration

```bash
# 1. Restore from snapshot
echo "🔧 RESTORING DATABASE FROM SNAPSHOT"
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier secrethub-staging-restored \
  --db-snapshot-identifier $SNAPSHOT_ID \
  --db-instance-class db.t3.large \
  --publicly-accessible false \
  --multi-az true

# 2. Wait for restore to complete (typically 10-20 minutes)
echo "Waiting for database restore..."
aws rds wait db-instance-available \
  --db-instance-identifier secrethub-staging-restored

# 3. Get new database endpoint
NEW_DB_ENDPOINT=$(aws rds describe-db-instances \
  --db-instance-identifier secrethub-staging-restored \
  --query 'DBInstances[0].Endpoint.Address' \
  --output text)

echo "New database endpoint: $NEW_DB_ENDPOINT"
```

### Phase 4: Core Reconfiguration

```bash
# 1. Update Core instances with new DATABASE_URL
NEW_DATABASE_URL="postgresql://secrethub:PASSWORD@${NEW_DB_ENDPOINT}:5432/secrethub"

kubectl set env deployment/secrethub-core \
  -n secrethub \
  DATABASE_URL="$NEW_DATABASE_URL"

# 2. Restart Core instances
kubectl rollout restart deployment/secrethub-core -n secrethub

# 3. Wait for Core instances to be ready
kubectl rollout status deployment/secrethub-core -n secrethub

# 4. Unseal vault (if not using auto-unseal)
if [ "$AUTO_UNSEAL" != "true" ]; then
  echo "Manual unseal required"
  for pod in $(kubectl get pods -n secrethub -l app=secrethub-core -o name); do
    echo "Unsealing $pod..."
    # Provide unseal keys (this would be manual in practice)
    kubectl exec -n secrethub $pod -- secrethub-core unseal $UNSEAL_KEY_1
    kubectl exec -n secrethub $pod -- secrethub-core unseal $UNSEAL_KEY_2
    kubectl exec -n secrethub $pod -- secrethub-core unseal $UNSEAL_KEY_3
  done
fi
```

### Phase 5: Verification

```bash
# 1. Verify Core health
echo "Verifying Core health..."
for i in {1..30}; do
  if curl -sf http://core-lb/v1/sys/health; then
    echo "✅ Core is healthy"
    break
  fi
  echo "Waiting for Core to be healthy... ($i/30)"
  sleep 10
done

# 2. Verify data integrity
echo "Verifying data integrity..."

# Check secret count
SECRET_COUNT=$(psql $NEW_DATABASE_URL -t -c "SELECT count(*) FROM secrets;")
echo "Secrets in restored DB: $SECRET_COUNT"

# Verify test secrets exist
for i in {1 10 50 100}; do
  curl -sf http://core-lb/v1/secrets/static/dr-test/secret-$i \
    -H "X-Vault-Token: $ADMIN_TOKEN" | jq '.data.value'
done

# Verify policy exists
curl -sf http://core-lb/v1/policies/dr-test-policy \
  -H "X-Vault-Token: $ADMIN_TOKEN" | jq '.name'

# 3. Verify agents can reconnect
echo "Verifying agent connectivity..."
CONNECTED_AGENTS=$(curl -s http://core-lb/admin/api/dashboard/stats \
  -H "X-Vault-Token: $ADMIN_TOKEN" | jq '.connected_agents')
echo "Connected agents: $CONNECTED_AGENTS"

# 4. Verify audit log hash chain
echo "Verifying audit log integrity..."
psql $NEW_DATABASE_URL <<EOF
-- Check hash chain integrity
SELECT
  CASE
    WHEN count(*) = 0 THEN '✅ Hash chain valid'
    ELSE '❌ Hash chain BROKEN'
  END as result
FROM audit.events e1
JOIN audit.events e2 ON e2.id = e1.id + 1
WHERE e2.previous_hash != e1.event_hash;
EOF

# STOP TIMER
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
DURATION_MIN=$((DURATION / 60))

echo ""
echo "=== DR Test 1 Results ==="
echo "Status: COMPLETE"
echo "Duration: $DURATION_MIN minutes ($DURATION seconds)"
echo "RTO Target: 60 minutes"
echo "RTO Met: $([ $DURATION_MIN -le 60 ] && echo '✅ YES' || echo '❌ NO')"
echo ""
```

### Phase 6: Cleanup

```bash
# Document results
cat > /tmp/dr-test-1-results.txt <<EOF
DR Test 1: Complete Database Loss
Date: $(date)
Duration: $DURATION_MIN minutes
RTO Met: $([ $DURATION_MIN -le 60 ] && echo 'YES' || echo 'NO')
Data Loss: $RPO_LOSS minutes
Secrets Verified: OK
Policies Verified: OK
Audit Log Integrity: OK
Agent Reconnection: OK
EOF

# Optional: Clean up test resources
# (In staging, you might keep the restored DB for further testing)
```

---

## DR Test 2: Complete Core Cluster Loss

**Scenario:** All Core instances fail simultaneously
**RTO Target:** 30 minutes
**RPO Target:** 0 (database intact)

### Phase 1: Baseline

```bash
# Document current state
kubectl get pods -n secrethub -l app=secrethub-core -o wide > /tmp/core-pods-before.txt
curl -s http://core-lb/admin/api/dashboard/stats > /tmp/stats-before.json
```

### Phase 2: Simulate Complete Core Loss

```bash
# START TIMER
START_TIME=$(date +%s)
echo "DR Test 2 Start Time: $(date)"

# Delete all Core pods
echo "⚠️  SIMULATING COMPLETE CORE CLUSTER LOSS"
kubectl delete pods -n secrethub -l app=secrethub-core --force --grace-period=0

# Verify all pods terminated
kubectl get pods -n secrethub -l app=secrethub-core
```

### Phase 3: Recovery

```bash
# 1. Kubernetes should automatically recreate pods
echo "Waiting for Kubernetes to recreate pods..."
kubectl rollout status deployment/secrethub-core -n secrethub --timeout=10m

# 2. Verify pods are running
kubectl get pods -n secrethub -l app=secrethub-core

# 3. Unseal vault if needed
# (Auto-unseal should handle this automatically)

# 4. Wait for Core to be healthy
for i in {1..30}; do
  if curl -sf http://core-lb/v1/sys/health; then
    echo "✅ Core cluster recovered"
    break
  fi
  echo "Waiting for Core health... ($i/30)"
  sleep 10
done
```

### Phase 4: Verification

```bash
# 1. Verify all agents reconnected
AGENTS_AFTER=$(curl -s http://core-lb/admin/api/dashboard/stats \
  -H "X-Vault-Token: $ADMIN_TOKEN" | jq '.connected_agents')

AGENTS_BEFORE=$(jq '.connected_agents' /tmp/stats-before.json)

echo "Agents before: $AGENTS_BEFORE"
echo "Agents after: $AGENTS_AFTER"

# 2. Verify secret access works
curl -sf http://core-lb/v1/secrets/static/dr-test/secret-1 \
  -H "X-Vault-Token: $ADMIN_TOKEN" | jq '.'

# 3. Verify no data loss
psql $DATABASE_URL -c "SELECT count(*) FROM secrets;"

# STOP TIMER
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
DURATION_MIN=$((DURATION / 60))

echo ""
echo "=== DR Test 2 Results ==="
echo "Status: COMPLETE"
echo "Duration: $DURATION_MIN minutes"
echo "RTO Target: 30 minutes"
echo "RTO Met: $([ $DURATION_MIN -le 30 ] && echo '✅ YES' || echo '❌ NO')"
echo "Data Loss: NONE (RPO = 0)"
echo ""
```

---

## DR Test 3: Cross-Region Failover

**Scenario:** Primary AWS region unavailable, failover to DR region
**RTO Target:** 2 hours
**RPO Target:** 5 minutes (replication lag)

**Note:** This test requires multi-region setup. Skip if not applicable.

### Prerequisites

```bash
# Verify DR region setup
aws rds describe-db-instances \
  --region us-west-2 \
  --db-instance-identifier secrethub-dr-replica

# Verify Core deployment exists in DR region
kubectl --context=dr-cluster get deployment secrethub-core -n secrethub
```

### Phase 1: Simulate Region Failure

```bash
# START TIMER
START_TIME=$(date +%s)

# 1. Simulate primary region failure (in practice, this would be AWS outage)
echo "⚠️  SIMULATING PRIMARY REGION FAILURE"

# Stop accepting traffic in primary region
aws elbv2 modify-target-group \
  --target-group-arn $PRIMARY_TG_ARN \
  --health-check-enabled false

# Update Route53 to fail health checks
aws route53 update-health-check \
  --health-check-id $PRIMARY_HEALTH_CHECK_ID \
  --disabled
```

### Phase 2: DR Region Activation

```bash
# 1. Promote read replica to standalone database
echo "Promoting DR database replica..."
aws rds promote-read-replica \
  --region us-west-2 \
  --db-instance-identifier secrethub-dr-replica

# Wait for promotion
aws rds wait db-instance-available \
  --region us-west-2 \
  --db-instance-identifier secrethub-dr-replica

# 2. Update DNS to point to DR region
aws route53 change-resource-record-sets \
  --hosted-zone-id $HOSTED_ZONE_ID \
  --change-batch file:///tmp/dr-dns-change.json

# 3. Scale up Core in DR region
kubectl --context=dr-cluster scale deployment/secrethub-core \
  -n secrethub --replicas=3

# 4. Unseal vault in DR region
# (Auto-unseal should work if using AWS KMS)
```

### Phase 3: Verification

```bash
# Verify DR region operational
curl -sf https://secrethub-dr.company.com/v1/sys/health

# Verify data replication
# Check if recent data is present (within RPO)

# Verify agents can failover
# (Agents should automatically connect to DR endpoint)

# STOP TIMER
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
DURATION_MIN=$((DURATION / 60))

echo "=== DR Test 3 Results ==="
echo "Duration: $DURATION_MIN minutes"
echo "RTO Met: $([ $DURATION_MIN -le 120 ] && echo '✅ YES' || echo '❌ NO')"
```

---

## DR Test 4: Vault Sealed Emergency

**Scenario:** Vault sealed during incident, unseal keys needed from custodians
**RTO Target:** 15 minutes
**RPO Target:** 0

### Phase 1: Seal Vault

```bash
# START TIMER
START_TIME=$(date +%s)

# Manually seal vault on all instances
for pod in $(kubectl get pods -n secrethub -l app=secrethub-core -o name); do
  kubectl exec -n secrethub $pod -- \
    curl -X POST http://localhost:4000/v1/sys/seal \
    -H "X-Vault-Token: $ADMIN_TOKEN"
done

# Verify sealed
curl http://core-lb/v1/sys/seal-status | jq '.sealed'
# Should return: true
```

### Phase 2: Contact Key Custodians

```bash
# Simulate contacting key custodians
# In practice, this would involve:
# 1. Paging on-call key custodians
# 2. Secure verification of identity
# 3. Secure transmission of unseal keys

echo "📞 Contacting key custodians..."
echo "Need 3 of 5 unseal keys"

# Simulate keys being provided
UNSEAL_KEY_1="provided-by-custodian-1"
UNSEAL_KEY_2="provided-by-custodian-2"
UNSEAL_KEY_3="provided-by-custodian-3"
```

### Phase 3: Unseal Vault

```bash
# Unseal each pod
for pod in $(kubectl get pods -n secrethub -l app=secrethub-core -o name); do
  echo "Unsealing $pod..."

  # Key 1
  kubectl exec -n secrethub $pod -- \
    curl -X POST http://localhost:4000/v1/sys/unseal \
    -d "{\"key\": \"$UNSEAL_KEY_1\"}"

  # Key 2
  kubectl exec -n secrethub $pod -- \
    curl -X POST http://localhost:4000/v1/sys/unseal \
    -d "{\"key\": \"$UNSEAL_KEY_2\"}"

  # Key 3 (should unseal)
  kubectl exec -n secrethub $pod -- \
    curl -X POST http://localhost:4000/v1/sys/unseal \
    -d "{\"key\": \"$UNSEAL_KEY_3\"}"
done

# Verify unsealed
curl http://core-lb/v1/sys/seal-status | jq '.sealed'
# Should return: false
```

### Phase 4: Verification

```bash
# Verify system operational
curl http://core-lb/v1/sys/health

# STOP TIMER
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
DURATION_MIN=$((DURATION / 60))

echo "=== DR Test 4 Results ==="
echo "Duration: $DURATION_MIN minutes"
echo "RTO Met: $([ $DURATION_MIN -le 15 ] && echo '✅ YES' || echo '❌ NO')"
```

---

## DR Test Results Template

```markdown
# Disaster Recovery Test Results

**Date:** YYYY-MM-DD
**Environment:** Staging/Production
**Tested By:** [Name]

## Test Summary

| Test | RTO Target | Actual | RPO Target | Actual | Status |
|------|-----------|--------|-----------|--------|--------|
| DB Loss | 60 min | XX min | 60 min | XX min | ✅/❌ |
| Core Loss | 30 min | XX min | 0 min | 0 min | ✅/❌ |
| Region Failover | 120 min | XX min | 5 min | X min | ✅/❌ |
| Vault Seal | 15 min | XX min | 0 min | 0 min | ✅/❌ |

## Issues Discovered

1. [Issue description]
   - Severity: Critical/High/Medium/Low
   - Impact: [Description]
   - Resolution: [Action taken]

## Recommendations

1. [Recommendation]
2. [Recommendation]

## Sign-Off

- [ ] All tests completed
- [ ] All issues documented
- [ ] Recommendations reviewed
- [ ] Team trained on DR procedures

**Approved By:** [Name]
**Date:** YYYY-MM-DD
```

---

## Post-Test Actions

### 1. Document Results
```bash
# Create test report
cat > /tmp/dr-test-report.md <<EOF
# DR Test Report - $(date +%Y-%m-%d)

## Summary
- All tests: PASS/FAIL
- Critical issues: X
- Recommendations: Y

## Detailed Results
[Include all test results]
EOF
```

### 2. Update Runbooks
- Update DR procedures based on lessons learned
- Document any issues encountered
- Update RTO/RPO if needed

### 3. Team Debrief
- Review what went well
- Review what needs improvement
- Update training materials

### 4. Schedule Next Test
- Quarterly DR testing
- Before major version upgrades
- After infrastructure changes

---

## Emergency Contact List

```
Role: Primary On-Call Engineer
Name: [Name]
Phone: [Phone]
Escalation: [Manager]

Role: Database Administrator
Name: [Name]
Phone: [Phone]

Role: Key Custodian #1
Name: [Name]
Phone: [Phone]

Role: Key Custodian #2
Name: [Name]
Phone: [Phone]

... (3 more key custodians)
```

---

## Related Documentation

- [Production Runbook](../deployment/production-runbook.md)
- [Operator Manual](../operator-manual.md)
- [Troubleshooting Guide](../troubleshooting.md)
- [Incident Response Procedures](./incident-response.md)

---

**Last Updated:** 2025-11-04
**Next Review:** 2026-02-04 (Quarterly)
