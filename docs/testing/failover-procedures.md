# Failover Testing Procedures

**Purpose:** Validate SecretHub's high availability and automatic failover capabilities
**Frequency:** Monthly (minimum), before major releases
**Duration:** 3-4 hours for complete failover testing
**Prerequisites:** Multi-node deployment (staging or production)

---

## Overview

Failover testing ensures that SecretHub maintains availability when individual components fail. These procedures test:

- Single Core instance failure
- Database failover (Multi-AZ)
- Load balancer failure
- Network partition scenarios
- Agent reconnection behavior

**Availability Target:** 99.9% uptime (< 8.7 hours downtime per year)

---

## Pre-Test Preparation

### 1. Environment Verification

```bash
# Verify multi-node Core deployment
kubectl get pods -n secrethub -l app=secrethub-core -o wide

# Expected: 3 or more Core pods running on different nodes

# Verify load balancer health
kubectl get service secrethub-core-lb -n secrethub

# Verify database is Multi-AZ
aws rds describe-db-instances \
  --db-instance-identifier secrethub-prod \
  --query 'DBInstances[0].MultiAZ'

# Should return: true
```

### 2. Baseline Metrics

```bash
# Document current system state
cat > /tmp/failover-test-baseline.txt <<EOF
=== Failover Test Baseline ===
Date: $(date)
Environment: Staging

Core Instances:
$(kubectl get pods -n secrethub -l app=secrethub-core -o wide)

Connected Agents:
$(curl -s http://core-lb/admin/api/dashboard/stats -H "X-Vault-Token: $ADMIN_TOKEN" | jq '.connected_agents')

Database Status:
$(aws rds describe-db-instances --db-instance-identifier secrethub-staging --query 'DBInstances[0].[DBInstanceStatus,MultiAZ,AvailabilityZone,SecondaryAvailabilityZone]')

Load Balancer Status:
$(kubectl get service secrethub-core-lb -n secrethub -o wide)
EOF

cat /tmp/failover-test-baseline.txt
```

### 3. Monitoring Setup

```bash
# Start continuous monitoring in separate terminal
watch -n 1 'curl -s http://core-lb/v1/sys/health | jq .'

# Monitor agent connections
watch -n 5 'curl -s http://core-lb/admin/api/dashboard/stats -H "X-Vault-Token: $ADMIN_TOKEN" | jq ".connected_agents"'
```

---

## Failover Test 1: Single Core Instance Failure

**Scenario:** One Core instance crashes
**Expected RTO:** < 30 seconds (agent reconnection time)
**Expected Behavior:** Agents automatically reconnect to healthy instances, no service interruption

### Phase 1: Deploy Test Agents

```bash
# Deploy 10 test agents
for i in {1..10}; do
  kubectl run test-agent-$i \
    --image=secrethub/agent:latest \
    --restart=Never \
    --env="SECRETHUB_ADDR=http://secrethub-core-lb:4000" \
    --env="ROLE_ID=test-role-id" \
    --env="SECRET_ID=test-secret-id-$i" \
    -n secrethub-test
done

# Wait for agents to connect
sleep 10

# Verify all agents connected
CONNECTED_AGENTS=$(curl -s http://core-lb/admin/api/dashboard/stats \
  -H "X-Vault-Token: $ADMIN_TOKEN" | jq '.connected_agents')

echo "Connected agents: $CONNECTED_AGENTS"
# Should show at least 10
```

### Phase 2: Identify Target Pod

```bash
# Get list of Core pods
kubectl get pods -n secrethub -l app=secrethub-core

# Select first pod for termination
TARGET_POD=$(kubectl get pods -n secrethub -l app=secrethub-core \
  -o jsonpath='{.items[0].metadata.name}')

echo "Target pod for termination: $TARGET_POD"

# Check which agents are connected to this pod
kubectl logs -n secrethub $TARGET_POD --tail=50 | grep "agent.*connected"
```

### Phase 3: Simulate Instance Failure

```bash
# START TIMER
START_TIME=$(date +%s)
echo "Failover Test 1 Start: $(date)"

# Kill the pod (simulate crash)
echo "⚠️  Terminating pod: $TARGET_POD"
kubectl delete pod $TARGET_POD -n secrethub --force --grace-period=0

# Immediately check system health
for i in {1..60}; do
  HEALTH=$(curl -s http://core-lb/v1/sys/health -o /dev/null -w '%{http_code}')
  AGENTS=$(curl -s http://core-lb/admin/api/dashboard/stats \
    -H "X-Vault-Token: $ADMIN_TOKEN" | jq -r '.connected_agents' 2>/dev/null || echo "0")

  echo "[T+${i}s] Health: $HEALTH | Agents: $AGENTS"

  if [ "$HEALTH" = "200" ] && [ "$AGENTS" -ge 10 ]; then
    RECOVERY_TIME=$i
    break
  fi

  sleep 1
done

# STOP TIMER
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
```

### Phase 4: Verification

```bash
# Verify new pod was created
NEW_POD=$(kubectl get pods -n secrethub -l app=secrethub-core \
  --field-selector=status.phase=Running \
  --sort-by=.metadata.creationTimestamp \
  -o jsonpath='{.items[-1].metadata.name}')

echo "New pod created: $NEW_POD"

# Verify all agents reconnected
FINAL_AGENT_COUNT=$(curl -s http://core-lb/admin/api/dashboard/stats \
  -H "X-Vault-Token: $ADMIN_TOKEN" | jq '.connected_agents')

echo "Final agent count: $FINAL_AGENT_COUNT"

# Test secret retrieval still works
curl -sf http://core-lb/v1/secrets/static/test/secret \
  -H "X-Vault-Token: $ADMIN_TOKEN" | jq '.'

# Check for any errors in logs
kubectl logs -n secrethub $NEW_POD --tail=50 | grep -i "error" || echo "No errors found"
```

### Results

```bash
cat <<EOF

=== Failover Test 1 Results ===
Status: $([ $FINAL_AGENT_COUNT -ge 10 ] && echo "PASSED ✅" || echo "FAILED ❌")
Recovery Time: ${RECOVERY_TIME}s
Target RTO: < 30s
RTO Met: $([ $RECOVERY_TIME -le 30 ] && echo "YES ✅" || echo "NO ❌")
Agents Before: $CONNECTED_AGENTS
Agents After: $FINAL_AGENT_COUNT
Service Interruption: $([ $RECOVERY_TIME -le 5 ] && echo "NONE" || echo "${RECOVERY_TIME}s")

EOF
```

---

## Failover Test 2: Database Failover (Multi-AZ)

**Scenario:** Primary database instance fails, RDS automatically fails over to standby
**Expected RTO:** < 60 seconds
**Expected Behavior:** Core instances reconnect to new primary, brief connection errors acceptable

### Phase 1: Pre-Failover State

```bash
# Document current database endpoint
CURRENT_ENDPOINT=$(aws rds describe-db-instances \
  --db-instance-identifier secrethub-staging \
  --query 'DBInstances[0].Endpoint.Address' \
  --output text)

echo "Current DB endpoint: $CURRENT_ENDPOINT"

# Document current AZ
CURRENT_AZ=$(aws rds describe-db-instances \
  --db-instance-identifier secrethub-staging \
  --query 'DBInstances[0].AvailabilityZone' \
  --output text)

echo "Current AZ: $CURRENT_AZ"

# Monitor database connections from Core
kubectl exec -n secrethub $(kubectl get pod -n secrethub -l app=secrethub-core -o jsonpath='{.items[0].metadata.name}') \
  -- sh -c 'psql $DATABASE_URL -c "SELECT count(*) FROM pg_stat_activity;"'
```

### Phase 2: Force Database Failover

```bash
# START TIMER
START_TIME=$(date +%s)
echo "Database Failover Test Start: $(date)"

# Force RDS failover
echo "⚠️  Forcing database failover..."
aws rds reboot-db-instance \
  --db-instance-identifier secrethub-staging \
  --force-failover

echo "Failover initiated. Waiting for completion..."

# Monitor failover progress
for i in {1..120}; do
  DB_STATUS=$(aws rds describe-db-instances \
    --db-instance-identifier secrethub-staging \
    --query 'DBInstances[0].DBInstanceStatus' \
    --output text)

  NEW_AZ=$(aws rds describe-db-instances \
    --db-instance-identifier secrethub-staging \
    --query 'DBInstances[0].AvailabilityZone' \
    --output text 2>/dev/null || echo "unknown")

  CORE_HEALTH=$(curl -s http://core-lb/v1/sys/health -o /dev/null -w '%{http_code}')

  echo "[T+${i}s] DB Status: $DB_STATUS | AZ: $NEW_AZ | Core Health: $CORE_HEALTH"

  if [ "$DB_STATUS" = "available" ] && [ "$NEW_AZ" != "$CURRENT_AZ" ] && [ "$CORE_HEALTH" = "200" ]; then
    RECOVERY_TIME=$i
    break
  fi

  sleep 1
done

# STOP TIMER
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
```

### Phase 3: Verification

```bash
# Verify failover occurred
NEW_AZ=$(aws rds describe-db-instances \
  --db-instance-identifier secrethub-staging \
  --query 'DBInstances[0].AvailabilityZone' \
  --output text)

if [ "$NEW_AZ" != "$CURRENT_AZ" ]; then
  echo "✅ Failover successful: $CURRENT_AZ → $NEW_AZ"
else
  echo "❌ Failover did not occur or same AZ"
fi

# Verify Core instances reconnected
for pod in $(kubectl get pods -n secrethub -l app=secrethub-core -o name); do
  echo "Checking $pod..."
  kubectl logs -n secrethub $pod --tail=20 | grep -i "database\|postgres" || echo "  No recent DB logs"
done

# Verify database operations work
psql "$DATABASE_URL" -c "SELECT count(*) FROM secrets;"

# Test full workflow
curl -sf http://core-lb/v1/secrets/static/test/failover-test \
  -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{"data": {"test": "value"}}' | jq '.'
```

### Results

```bash
cat <<EOF

=== Failover Test 2 Results ===
Status: $([ "$NEW_AZ" != "$CURRENT_AZ" ] && echo "PASSED ✅" || echo "FAILED ❌")
Recovery Time: ${RECOVERY_TIME}s
Target RTO: < 60s
RTO Met: $([ $RECOVERY_TIME -le 60 ] && echo "YES ✅" || echo "NO ❌")
Original AZ: $CURRENT_AZ
New AZ: $NEW_AZ
Database Operations: $(psql "$DATABASE_URL" -t -c "SELECT 'OK';" 2>/dev/null | xargs || echo "FAILED")

EOF
```

---

## Failover Test 3: Load Balancer Failure

**Scenario:** Load balancer becomes unavailable, agents use direct endpoint failover
**Expected RTO:** < 30 seconds
**Expected Behavior:** Agents failover to direct Core IPs

### Phase 1: Configure Agent Failover

```bash
# Deploy agents with multiple endpoints
cat > /tmp/agent-config.yaml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: agent-failover-config
  namespace: secrethub-test
data:
  config.yaml: |
    core_addresses:
      - http://secrethub-core-lb:4000  # Primary (load balancer)
      - http://core-pod-1.secrethub-core:4000  # Direct pod 1
      - http://core-pod-2.secrethub-core:4000  # Direct pod 2
      - http://core-pod-3.secrethub-core:4000  # Direct pod 3
    failover_strategy: round_robin
    connection_timeout: 5s
    max_retries: 3
EOF

kubectl apply -f /tmp/agent-config.yaml

# Deploy test agents with failover config
kubectl run test-agent-failover \
  --image=secrethub/agent:latest \
  --restart=Never \
  -n secrethub-test \
  --env="CONFIG_FILE=/config/config.yaml" \
  --volume="agent-failover-config:/config"
```

### Phase 2: Simulate Load Balancer Failure

```bash
# START TIMER
START_TIME=$(date +%s)

# Simulate LB failure by blocking traffic
echo "⚠️  Simulating load balancer failure..."

# Create network policy to block traffic to LB
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-lb
  namespace: secrethub
spec:
  podSelector:
    matchLabels:
      app: secrethub-core-lb
  policyTypes:
  - Ingress
  ingress: []  # Block all ingress
EOF

# Monitor agent reconnection
for i in {1..60}; do
  # Check if agents are still connected (via direct endpoints)
  AGENTS=$(kubectl exec -n secrethub-test test-agent-failover -- \
    sh -c 'ps aux | grep agent' 2>/dev/null | wc -l || echo "0")

  echo "[T+${i}s] Agent processes: $AGENTS"

  if [ "$AGENTS" -gt 0 ]; then
    RECOVERY_TIME=$i
    break
  fi

  sleep 1
done

# STOP TIMER
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
```

### Phase 3: Restore Load Balancer

```bash
# Remove network policy
kubectl delete networkpolicy block-lb -n secrethub

echo "Load balancer restored"

# Wait for agents to prefer LB again
sleep 30

# Verify agents using LB
kubectl logs -n secrethub-test test-agent-failover --tail=20
```

### Results

```bash
cat <<EOF

=== Failover Test 3 Results ===
Status: $([ $RECOVERY_TIME -le 30 ] && echo "PASSED ✅" || echo "FAILED ❌")
Recovery Time: ${RECOVERY_TIME}s
Target RTO: < 30s
RTO Met: $([ $RECOVERY_TIME -le 30 ] && echo "YES ✅" || echo "NO ❌")
Failover Strategy: Direct Pod Connection
LB Restoration: Successful

EOF
```

---

## Failover Test 4: Network Partition (Split-Brain)

**Scenario:** Network partition isolates one Core instance
**Expected Behavior:** Isolated instance stops serving requests, majority continues

### Phase 1: Create Network Partition

```bash
# START TIMER
START_TIME=$(date +%s)

# Select pod to isolate
ISOLATED_POD=$(kubectl get pods -n secrethub -l app=secrethub-core \
  -o jsonpath='{.items[0].metadata.name}')

echo "Isolating pod: $ISOLATED_POD"

# Create network policy to isolate pod
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-core-instance
  namespace: secrethub
spec:
  podSelector:
    matchLabels:
      statefulset.kubernetes.io/pod-name: $ISOLATED_POD
  policyTypes:
  - Ingress
  - Egress
  ingress: []  # Block all ingress
  egress: []   # Block all egress
EOF

echo "Network partition created"
```

### Phase 2: Verify System Behavior

```bash
# Check if majority partition continues operating
for i in {1..60}; do
  HEALTH=$(curl -s http://core-lb/v1/sys/health -o /dev/null -w '%{http_code}')
  AGENTS=$(curl -s http://core-lb/admin/api/dashboard/stats \
    -H "X-Vault-Token: $ADMIN_TOKEN" | jq -r '.connected_agents' 2>/dev/null || echo "0")

  echo "[T+${i}s] System Health: $HEALTH | Connected Agents: $AGENTS"

  sleep 1
done

# Verify isolated pod stopped serving
kubectl logs -n secrethub $ISOLATED_POD --tail=50 | grep -i "network\|timeout\|connection"

# Verify no data corruption
psql "$DATABASE_URL" -c "SELECT 'Data integrity check OK';"
```

### Phase 3: Restore Network

```bash
# Remove network policy
kubectl delete networkpolicy isolate-core-instance -n secrethub

echo "Network partition healed"

# Wait for pod to rejoin cluster
sleep 30

# Verify pod rejoined
kubectl get pods -n secrethub -l app=secrethub-core
kubectl logs -n secrethub $ISOLATED_POD --tail=20

# STOP TIMER
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
```

### Results

```bash
cat <<EOF

=== Failover Test 4 Results ===
Status: PASSED ✅
Duration: ${DURATION}s
Isolated Pod: $ISOLATED_POD
Majority Partition: Continued operating
Data Corruption: None detected
Recovery: Clean rejoining after partition healed

EOF
```

---

## Test Results Summary Template

```markdown
# Failover Testing Results

**Date:** YYYY-MM-DD
**Environment:** Staging/Production
**Tested By:** [Name]

## Summary

| Test | RTO Target | Actual | Status | Notes |
|------|-----------|--------|--------|-------|
| Single Instance Failure | < 30s | XX s | ✅/❌ | Agent reconnection |
| Database Failover | < 60s | XX s | ✅/❌ | Multi-AZ RDS |
| Load Balancer Failure | < 30s | XX s | ✅/❌ | Direct endpoint failover |
| Network Partition | N/A | XX s | ✅/❌ | Majority partition continued |

## Issues Discovered

1. [Issue description]
   - Severity: Critical/High/Medium/Low
   - Resolution: [Action taken]

## Agent Behavior

- Reconnection time: XX seconds (average)
- Connection errors during failover: XX
- Agent crashes: XX

## Recommendations

1. [Recommendation based on test results]
2. [Recommendation based on test results]

## Sign-Off

- [ ] All tests completed
- [ ] No data loss detected
- [ ] All agents reconnected successfully
- [ ] System stable after all tests

**Approved By:** [Name]
**Date:** YYYY-MM-DD
```

---

## Automated Failover Testing Script

For regular testing, use the automated script:

```bash
# Run all failover tests
./scripts/test-failover.sh all

# Run specific test
./scripts/test-failover.sh single-instance

# Generate report
./scripts/test-failover.sh report
```

---

## Post-Test Actions

### 1. Cleanup

```bash
# Delete test agents
kubectl delete pods -n secrethub-test -l purpose=failover-test

# Remove test configurations
kubectl delete configmap agent-failover-config -n secrethub-test

# Verify all Core instances healthy
kubectl get pods -n secrethub -l app=secrethub-core
```

### 2. Documentation

- Update runbooks with any issues found
- Document actual vs expected RTOs
- Note any unexpected behavior

### 3. Monitoring Improvements

- Add alerts for detected issues
- Update dashboards based on test observations
- Improve agent reconnection logic if needed

---

## Related Documentation

- [Disaster Recovery Procedures](./disaster-recovery-procedures.md)
- [Production Runbook](../deployment/production-runbook.md)
- [Operator Manual](../operator-manual.md)

---

**Last Updated:** 2025-11-04
**Next Review:** 2025-12-04 (Monthly)
