# Rollback Procedures

**Purpose:** Emergency procedures for reverting failed deployments
**Target Audience:** Operations team, on-call engineers
**Last Updated:** 2025-11-04

---

## Quick Reference

| Rollback Type | RTO Target | Complexity | When to Use |
|--------------|-----------|------------|-------------|
| Quick Rollback | < 15 min | Low | Application issues, no DB changes |
| Database Rollback | < 30 min | Medium | DB migration issues |
| Full Rollback | < 60 min | High | Complete deployment failure |
| DNS Rollback | < 5 min | Low | Routing issues |

---

## Rollback Decision Tree

```
Is there a production incident?
├─ YES → Assess severity
│   ├─ Critical (service down, data loss) → FULL ROLLBACK
│   ├─ High (degraded performance) → Quick Rollback
│   └─ Medium (minor bugs) → Consider forward fix
└─ NO → No rollback needed
```

---

## Rollback 1: Quick Application Rollback

**Scenario:** Application code issues, no database changes
**RTO:** < 15 minutes
**Data Loss:** None

### Prerequisites
- Previous deployment artifacts available
- No database schema changes in current release

### Procedure

```bash
# 1. Verify rollback target version
CURRENT_VERSION=$(kubectl get deployment secrethub-core -n secrethub -o jsonpath='{.spec.template.spec.containers[0].image}')
PREVIOUS_VERSION="secrethub/core:v0.9.0"  # Update with actual previous version

echo "Current: $CURRENT_VERSION"
echo "Rolling back to: $PREVIOUS_VERSION"

# 2. Scale down new deployment
kubectl scale deployment secrethub-core-new -n secrethub --replicas=0

# 3. Scale up previous deployment (if blue-green)
kubectl scale deployment secrethub-core-old -n secrethub --replicas=3

# OR use kubectl rollout undo
kubectl rollout undo deployment/secrethub-core -n secrethub

# 4. Wait for rollout to complete
kubectl rollout status deployment/secrethub-core -n secrethub

# 5. Verify health
curl https://secrethub.company.com/v1/sys/health
# Expected: 200 OK

# 6. Check version
curl https://secrethub.company.com/v1/sys/version
# Expected: Previous version number

# 7. Monitor for 10 minutes
watch -n 10 'curl -s https://secrethub.company.com/v1/sys/health | jq .'
```

### Verification

```bash
# Verify agent connections restored
AGENT_COUNT=$(curl -s https://secrethub.company.com/admin/api/dashboard/stats \
  -H "X-Vault-Token: $ADMIN_TOKEN" | jq '.connected_agents')

echo "Connected agents: $AGENT_COUNT"

# Check error rate
kubectl logs -n secrethub -l app=secrethub-core --tail=100 | grep -i error | wc -l
# Expected: < 5 errors

# Verify no data loss
psql $DATABASE_URL -c "SELECT count(*) FROM secrets;"
```

### Rollback Complete
- [ ] Application rolled back
- [ ] Health checks passing
- [ ] Agents reconnected
- [ ] No increase in errors
- [ ] Incident logged

---

## Rollback 2: Database Rollback

**Scenario:** Database migration issues, schema changes
**RTO:** < 30 minutes
**Data Loss:** Depends on migration (potentially data created after deployment)

### Prerequisites
- Pre-deployment database snapshot exists
- Migration rollback scripts available

### Procedure

```bash
# 1. Stop all Core instances immediately
kubectl scale deployment secrethub-core -n secrethub --replicas=0

# Wait for all pods to terminate
kubectl wait --for=delete pod -l app=secrethub-core -n secrethub --timeout=60s

# 2. Verify database snapshot
SNAPSHOT_ID="pre-deployment-$(date +%Y%m%d)"
aws rds describe-db-snapshots \
  --db-snapshot-identifier $SNAPSHOT_ID

# 3. Option A: Rollback migrations (if possible)
# Connect to database
psql $DATABASE_URL

# Check current migration version
SELECT * FROM schema_migrations ORDER BY version DESC LIMIT 1;

# Rollback specific migrations
mix ecto.rollback --step 3  # Rollback last 3 migrations

# 4. Option B: Restore from snapshot (if rollback not possible)
# Create new database from snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier secrethub-prod-rollback \
  --db-snapshot-identifier $SNAPSHOT_ID

# Wait for restore
aws rds wait db-instance-available \
  --db-instance-identifier secrethub-prod-rollback

# Get new endpoint
NEW_ENDPOINT=$(aws rds describe-db-instances \
  --db-instance-identifier secrethub-prod-rollback \
  --query 'DBInstances[0].Endpoint.Address' \
  --output text)

# 5. Update Core configuration with new database endpoint
kubectl set env deployment/secrethub-core \
  -n secrethub \
  DATABASE_URL="postgresql://secrethub:PASSWORD@${NEW_ENDPOINT}:5432/secrethub_prod"

# 6. Deploy previous application version
kubectl set image deployment/secrethub-core \
  secrethub-core=secrethub/core:v0.9.0 \
  -n secrethub

# 7. Scale up Core instances
kubectl scale deployment/secrethub-core -n secrethub --replicas=3

# 8. Wait for readiness
kubectl rollout status deployment/secrethub-core -n secrethub

# 9. Unseal vault (if needed)
# Manual unseal or auto-unseal should work

# 10. Verify data integrity
psql "postgresql://secrethub:PASSWORD@${NEW_ENDPOINT}:5432/secrethub_prod" \
  -c "SELECT count(*) FROM secrets;"
```

### Data Loss Assessment

```bash
# Compare record counts before and after
echo "Checking data loss..."

# Secrets
SECRETS_BEFORE=XXX  # From pre-deployment
SECRETS_AFTER=$(psql $DATABASE_URL -t -c "SELECT count(*) FROM secrets;" | xargs)
SECRETS_LOST=$((SECRETS_BEFORE - SECRETS_AFTER))

echo "Secrets lost: $SECRETS_LOST"

# Audit events
AUDIT_BEFORE=XXX  # From pre-deployment
AUDIT_AFTER=$(psql $DATABASE_URL -t -c "SELECT count(*) FROM audit.events;" | xargs)
AUDIT_LOST=$((AUDIT_BEFORE - AUDIT_AFTER))

echo "Audit events lost: $AUDIT_LOST"

# RPO met?
echo "RPO: $AUDIT_LOST events (approximately $(($AUDIT_LOST / 60)) minutes)"
```

### Rollback Complete
- [ ] Database restored/rolled back
- [ ] Application on previous version
- [ ] Data loss assessed and documented
- [ ] Agents reconnected
- [ ] Incident logged with data loss metrics

---

## Rollback 3: Full System Rollback

**Scenario:** Complete deployment failure, multiple components affected
**RTO:** < 60 minutes
**Data Loss:** Up to RPO (1 hour for DB backups)

### Procedure

```bash
# This combines Quick + Database rollback

# 1. Stop all Core instances
kubectl scale deployment secrethub-core -n secrethub --replicas=0

# 2. Restore database (see Rollback 2)
# ... (database restoration steps)

# 3. Roll back application (see Rollback 1)
# ... (application rollback steps)

# 4. Verify load balancer
aws elbv2 describe-target-health \
  --target-group-arn $TARGET_GROUP_ARN

# 5. DNS verification (should not need changes)
dig secrethub.company.com

# 6. Full system health check
./scripts/health-check.sh

# 7. Notify stakeholders
curl -X POST $SLACK_WEBHOOK \
  -d '{"text": "🔴 Full system rollback completed. System operational on previous version."}'
```

---

## Rollback 4: DNS Rollback

**Scenario:** DNS change caused issues, need to revert routing
**RTO:** < 5 minutes
**Data Loss:** None

### Procedure

```bash
# 1. Identify current DNS record
dig secrethub.company.com

# 2. Revert DNS to previous target
aws route53 change-resource-record-sets \
  --hosted-zone-id $HOSTED_ZONE_ID \
  --change-batch file:///tmp/dns-rollback.json

# DNS rollback file example:
cat > /tmp/dns-rollback.json <<EOF
{
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "secrethub.company.com",
      "Type": "A",
      "AliasTarget": {
        "HostedZoneId": "Z1234567890ABC",
        "DNSName": "old-lb-XXXXXXXX.us-east-1.elb.amazonaws.com",
        "EvaluateTargetHealth": true
      }
    }
  }]
}
EOF

# 3. Wait for propagation (typically 1-5 minutes due to low TTL)
watch -n 5 'dig secrethub.company.com | grep -A 2 "ANSWER SECTION"'

# 4. Verify traffic routing
curl https://secrethub.company.com/v1/sys/health
```

---

## Post-Rollback Procedures

### 1. Incident Documentation

```markdown
# Rollback Incident Report

**Date:** YYYY-MM-DD HH:MM UTC
**Rollback Type:** [Quick/Database/Full/DNS]
**Duration:** X minutes
**RTO Met:** YES/NO

## Timeline

- HH:MM - Incident detected
- HH:MM - Rollback decision made
- HH:MM - Rollback initiated
- HH:MM - Rollback completed
- HH:MM - System verified healthy

## Impact

- Users affected: XXX
- Downtime: X minutes
- Data loss: XX events/records
- RPO met: YES/NO

## Root Cause

[Description of what went wrong]

## Rollback Steps Taken

1. [Step 1]
2. [Step 2]
...

## Verification

- [ ] System health restored
- [ ] All agents reconnected
- [ ] No ongoing errors
- [ ] Monitoring shows normal metrics

## Follow-Up Actions

1. [ ] Fix root cause - Owner: [Name] - Due: [Date]
2. [ ] Update deployment process - Owner: [Name] - Due: [Date]
3. [ ] Post-mortem scheduled - Date: [Date]

**Incident Commander:** [Name]
**Report By:** [Name]
```

### 2. Communication

```bash
# Notify team
curl -X POST $SLACK_WEBHOOK_INCIDENTS \
  -d '{
    "text": "✅ Rollback completed successfully",
    "attachments": [{
      "color": "good",
      "fields": [
        {"title": "Duration", "value": "15 minutes", "short": true},
        {"title": "Impact", "value": "Minor", "short": true},
        {"title": "Status", "value": "System operational", "short": false}
      ]
    }]
  }'

# Update status page
echo "Update https://status.secrethub.company.com:"
echo "- Incident resolved"
echo "- All systems operational"
echo "- Post-mortem scheduled"
```

### 3. Post-Mortem

- [ ] Schedule post-mortem meeting (within 48 hours)
- [ ] Attendees: All involved team members
- [ ] Agenda:
  - Timeline review
  - Root cause analysis
  - Action items to prevent recurrence
  - Rollback process improvements

---

## Rollback Prevention

### Pre-Deployment Checks

```bash
# Always run before deployment
./scripts/pre-deployment-check.sh

# Checklist:
- [ ] Database backup completed
- [ ] Application tested in staging
- [ ] Migrations tested
- [ ] Rollback plan documented
- [ ] Team on standby
```

### Canary Deployment (Recommended)

```bash
# Deploy to 10% of instances first
kubectl set image deployment/secrethub-core \
  secrethub-core=secrethub/core:v1.0.0 \
  -n secrethub

# Wait and monitor for 30 minutes
# If healthy, roll out to 100%

# If issues detected, rollback is only 10% of traffic
```

---

## Emergency Contacts

```
Incident Commander: [Name] - [Phone]
Database Admin: [Name] - [Phone]
Infrastructure Lead: [Name] - [Phone]
Security Lead: [Name] - [Phone]

Escalation: [Manager Name] - [Phone]
```

---

## Related Documentation

- [Production Runbook](./production-runbook.md)
- [Disaster Recovery Procedures](../testing/disaster-recovery-procedures.md)
- [Incident Response](../testing/incident-response.md)
- [Production Launch Checklist](./production-launch-checklist.md)

---

**Last Updated:** 2025-11-04
**Next Review:** After each rollback incident
