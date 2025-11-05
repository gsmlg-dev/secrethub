# Security Verification Checklist

**Purpose:** Verify all security controls are operational before production launch
**Frequency:** Before every production deployment, quarterly security reviews
**Duration:** 2-3 hours
**Prerequisite:** Security fixes from Week 29 applied

---

## Executive Summary

This checklist verifies that all security controls implemented during Week 29 (Security Audit & Penetration Testing) and throughout the project are functioning correctly. **All items must be verified before production launch.**

**Security Rating Target:** 🟢 GOOD (all critical and high-priority controls operational)

---

## Checklist Overview

- **Total Checks:** 60+
- **Critical Checks:** 15 (must pass 100%)
- **High Priority Checks:** 20 (must pass 100%)
- **Medium Priority Checks:** 20+ (must pass 95%+)
- **Low Priority Checks:** 5+ (best effort)

---

## Section 1: Authentication & Authorization

### 1.1 Admin Authentication **[CRITICAL]**

- [ ] **Admin login requires valid session**
  ```bash
  # Test: Access admin panel without session
  curl -I http://core-lb/admin/dashboard
  # Expected: 302 Redirect to /admin/auth/login
  ```

- [ ] **Session timeout enforced (30 minutes)**
  ```bash
  # Test: Create session, wait 31 minutes, access protected resource
  # Expected: Session expired, redirect to login
  ```

- [ ] **HTTPOnly cookie flag set**
  ```bash
  curl -I http://core-lb/admin/auth/login
  # Expected: Set-Cookie header includes "HttpOnly"
  ```

- [ ] **Secure flag set in production**
  ```bash
  # In production only
  curl -I https://secrethub.company.com/admin/auth/login
  # Expected: Set-Cookie header includes "Secure"
  ```

- [ ] **SameSite attribute set**
  ```bash
  curl -I http://core-lb/admin/auth/login
  # Expected: Set-Cookie header includes "SameSite=Lax" or "SameSite=Strict"
  ```

### 1.2 AppRole Management **[CRITICAL]**

- [ ] **AppRole creation requires admin authentication**
  ```bash
  # Test: Create AppRole without admin auth
  curl -X POST http://core-lb/v1/auth/approle/role/test \
    -d '{"role_name": "test"}'
  # Expected: 401 Unauthorized
  ```

- [ ] **AppRole deletion requires admin authentication**
  ```bash
  # Test: Delete AppRole without admin auth
  curl -X DELETE http://core-lb/v1/auth/approle/role/test
  # Expected: 401 Unauthorized
  ```

- [ ] **Role ID generation requires admin token OR session**
  ```bash
  # Test: Generate Role ID without auth
  curl -X POST http://core-lb/v1/auth/approle/role/test/role-id
  # Expected: 401 Unauthorized
  ```

- [ ] **Secret ID generation protected**
  ```bash
  # Test: Generate Secret ID with valid admin session
  curl -X POST http://core-lb/v1/auth/approle/role/test/secret-id \
    -H "Cookie: _secrethub_web_key=$SESSION_COOKIE"
  # Expected: 200 OK with secret_id
  ```

### 1.3 Rate Limiting **[HIGH]**

- [ ] **Rate limiting active on auth endpoints (5 req/min)**
  ```bash
  # Test: Make 6 requests within 1 minute
  for i in {1..6}; do
    curl -X POST http://core-lb/v1/auth/approle/login \
      -d '{"role_id": "test", "secret_id": "test"}'
    sleep 5
  done
  # Expected: 6th request returns 429 Too Many Requests
  ```

- [ ] **Rate limit per IP address**
  ```bash
  # Verify rate limit is per IP, not global
  # Test from two different IPs simultaneously
  # Both should get 5 requests before rate limit
  ```

- [ ] **Rate limit headers present**
  ```bash
  curl -I http://core-lb/v1/auth/approle/login
  # Expected headers:
  # X-RateLimit-Limit: 5
  # X-RateLimit-Remaining: X
  # X-RateLimit-Reset: TIMESTAMP
  ```

### 1.4 Failed Authentication Attempts **[HIGH]**

- [ ] **Failed login attempts logged**
  ```bash
  # Test: Attempt failed login
  curl -X POST http://core-lb/v1/auth/approle/login \
    -d '{"role_id": "invalid", "secret_id": "invalid"}'

  # Verify in audit log
  psql $DATABASE_URL -c "
    SELECT * FROM audit.events
    WHERE event_type = 'auth.login_failed'
    ORDER BY timestamp DESC LIMIT 1;
  "
  ```

- [ ] **Account lockout after repeated failures (10 attempts)**
  ```bash
  # Test: 11 failed login attempts with same role_id
  for i in {1..11}; do
    curl -X POST http://core-lb/v1/auth/approle/login \
      -d "{\"role_id\": \"test-role\", \"secret_id\": \"invalid-$i\"}"
  done
  # Expected: 11th attempt returns 423 Locked
  ```

- [ ] **No sensitive information in error messages**
  ```bash
  # Test: Invalid credentials
  curl -X POST http://core-lb/v1/auth/approle/login \
    -d '{"role_id": "invalid", "secret_id": "invalid"}'
  # Expected: Generic error "Authentication failed"
  # Not expected: "Role ID not found" or "Secret ID invalid"
  ```

---

## Section 2: Encryption

### 2.1 Data at Rest **[CRITICAL]**

- [ ] **Secrets encrypted in database (AES-256-GCM)**
  ```bash
  # Verify secrets are encrypted
  psql $DATABASE_URL -c "
    SELECT path, length(value_encrypted), substring(value_encrypted, 1, 20)
    FROM secrets LIMIT 5;
  "
  # Expected: value_encrypted should be binary/base64, not plaintext
  ```

- [ ] **Encryption key never stored in database**
  ```bash
  # Search for master key in database
  psql $DATABASE_URL -c "
    SELECT EXISTS (
      SELECT 1 FROM pg_catalog.pg_tables
      WHERE tablename = 'encryption_keys'
    );
  "
  # Expected: false (keys should be in environment or KMS)
  ```

- [ ] **IV (Initialization Vector) unique per secret**
  ```bash
  # Check that IVs are different
  psql $DATABASE_URL -c "
    SELECT COUNT(DISTINCT encryption_iv) as unique_ivs,
           COUNT(*) as total_secrets
    FROM secrets;
  "
  # Expected: unique_ivs == total_secrets
  ```

### 2.2 Data in Transit **[CRITICAL]**

- [ ] **HTTPS enforced in production**
  ```bash
  # Test: HTTP request in production
  curl -I http://secrethub.company.com/v1/sys/health
  # Expected: 301 Redirect to https://
  ```

- [ ] **TLS 1.2+ only**
  ```bash
  # Test: TLS 1.0/1.1 connections
  openssl s_client -connect secrethub.company.com:443 -tls1_1
  # Expected: Connection refused or handshake failure
  ```

- [ ] **Strong cipher suites only**
  ```bash
  nmap --script ssl-enum-ciphers -p 443 secrethub.company.com
  # Expected: Only A-grade ciphers (e.g., ECDHE-RSA-AES256-GCM-SHA384)
  ```

- [ ] **Database connections encrypted (SSL/TLS)**
  ```bash
  psql "$DATABASE_URL" -c "
    SELECT datname, usename, ssl, cipher, version
    FROM pg_stat_ssl
    JOIN pg_stat_activity USING (pid);
  "
  # Expected: ssl = true for all connections
  ```

### 2.3 mTLS (Agent Communication) **[HIGH]**

- [ ] **Core ↔ Agent uses mTLS**
  ```bash
  # Verify agent connection requires client certificate
  # Test: Connect without client cert
  curl -k https://core-lb:4000/v1/agent/connect
  # Expected: 400 Bad Request or TLS handshake failure
  ```

- [ ] **Client certificates validated**
  ```bash
  # Test: Connect with invalid/expired certificate
  # Expected: TLS handshake failure
  ```

- [ ] **Certificate revocation checked (CRL)**
  ```bash
  # Revoke a client certificate
  curl -X POST http://core-lb/v1/pki/revoke \
    -H "X-Vault-Token: $ADMIN_TOKEN" \
    -d '{"serial_number": "XX:XX:XX..."}'

  # Test: Agent with revoked cert cannot connect
  # Expected: Connection refused
  ```

---

## Section 3: Network Security

### 3.1 Access Control **[HIGH]**

- [ ] **Core instances not directly exposed to internet**
  ```bash
  # Verify Core instances only accessible via load balancer
  # Test: Direct connection to Core pod IP from external network
  # Expected: Connection timeout or refused
  ```

- [ ] **Load balancer uses HTTPS only (production)**
  ```bash
  # Test: HTTP request to load balancer
  curl -I http://lb.secrethub.company.com/v1/sys/health
  # Expected: 301 Redirect to https:// or connection refused
  ```

- [ ] **Database in private subnet**
  ```bash
  # Verify database is not publicly accessible
  aws rds describe-db-instances \
    --db-instance-identifier secrethub-prod \
    --query 'DBInstances[0].PubliclyAccessible'
  # Expected: false
  ```

- [ ] **Security groups properly configured**
  ```bash
  # Verify security group rules
  aws ec2 describe-security-groups \
    --group-ids sg-XXXXXXXXX \
    --query 'SecurityGroups[0].IpPermissions'
  # Expected: Only necessary ports open (443, 5432 internal only)
  ```

### 3.2 Port Security **[MEDIUM]**

- [ ] **No unnecessary ports open**
  ```bash
  # Port scan from external network
  nmap secrethub.company.com
  # Expected: Only 443 (HTTPS) and possibly 80 (HTTP redirect)
  ```

- [ ] **Database port not exposed externally**
  ```bash
  nmap -p 5432 secrethub.company.com
  # Expected: Port filtered or closed
  ```

- [ ] **Admin endpoints not exposed externally**
  ```bash
  curl -I https://secrethub.company.com/admin/dashboard
  # Expected: 404 Not Found (should be internal-only domain)
  ```

---

## Section 4: Audit & Compliance

### 4.1 Audit Logging **[CRITICAL]**

- [ ] **All secret access logged**
  ```bash
  # Create and read secret
  curl -X POST http://core-lb/v1/secrets/static/test/audit-test \
    -H "X-Vault-Token: $ADMIN_TOKEN" \
    -d '{"data": {"key": "value"}}'

  curl http://core-lb/v1/secrets/static/test/audit-test \
    -H "X-Vault-Token: $ADMIN_TOKEN"

  # Verify in audit log
  psql $DATABASE_URL -c "
    SELECT event_type, actor, resource, action
    FROM audit.events
    WHERE resource LIKE '%audit-test%'
    ORDER BY timestamp DESC LIMIT 2;
  "
  # Expected: 2 events (create + read)
  ```

- [ ] **Authentication attempts logged (success + failure)**
  ```bash
  psql $DATABASE_URL -c "
    SELECT COUNT(*) FROM audit.events
    WHERE event_type IN ('auth.login_success', 'auth.login_failed');
  "
  # Expected: > 0
  ```

- [ ] **Policy changes logged**
  ```bash
  # Create policy
  curl -X POST http://core-lb/v1/policies \
    -H "X-Vault-Token: $ADMIN_TOKEN" \
    -d '{"name": "audit-test-policy", "rules": []}'

  # Verify logged
  psql $DATABASE_URL -c "
    SELECT * FROM audit.events
    WHERE event_type = 'policy.create'
    ORDER BY timestamp DESC LIMIT 1;
  "
  ```

- [ ] **AppRole operations logged**
  ```bash
  psql $DATABASE_URL -c "
    SELECT COUNT(*) FROM audit.events
    WHERE event_type LIKE 'approle.%';
  "
  # Expected: > 0
  ```

### 4.2 Hash Chain Integrity **[HIGH]**

- [ ] **Hash chain valid**
  ```bash
  # Verify hash chain integrity
  psql $DATABASE_URL -c "
    SELECT
      CASE
        WHEN COUNT(*) = 0 THEN '✅ Hash chain valid'
        ELSE '❌ Hash chain BROKEN (' || COUNT(*) || ' breaks)'
      END as result
    FROM audit.events e1
    JOIN audit.events e2 ON e2.id = e1.id + 1
    WHERE e2.previous_hash != e1.event_hash;
  "
  # Expected: ✅ Hash chain valid
  ```

- [ ] **Audit logs tamper-evident**
  ```bash
  # Attempt to modify an audit event
  psql $DATABASE_URL -c "
    UPDATE audit.events
    SET actor = 'tampered'
    WHERE id = (SELECT MAX(id) FROM audit.events);
  "

  # Re-run hash chain check
  # Expected: Hash chain should now show as broken
  # (This demonstrates tamper-evidence; rollback after test)
  ```

### 4.3 Audit Log Retention **[MEDIUM]**

- [ ] **Audit logs exported to S3**
  ```bash
  # Verify S3 bucket contains audit exports
  aws s3 ls s3://secrethub-audit-logs/
  # Expected: audit-export-YYYYMMDD.json.gz files
  ```

- [ ] **Retention policy enforced (7 years)**
  ```bash
  # Check S3 lifecycle policy
  aws s3api get-bucket-lifecycle-configuration \
    --bucket secrethub-audit-logs
  # Expected: Expiration after 2555 days (7 years)
  ```

---

## Section 5: Secrets Management

### 5.1 Secret Storage **[CRITICAL]**

- [ ] **Secrets never logged in plaintext**
  ```bash
  # Check Core logs for plaintext secrets
  kubectl logs -n secrethub -l app=secrethub-core --tail=1000 | \
    grep -i "password\|secret\|key" | \
    grep -v "encrypted"
  # Expected: No plaintext secrets found
  ```

- [ ] **Secrets encrypted in cache**
  ```bash
  # Verify ETS cache contains encrypted data
  # (This requires Elixir observer or manual inspection)
  # Expected: Cache entries should be encrypted, not plaintext
  ```

- [ ] **Secrets not in error messages**
  ```bash
  # Trigger error with secret path
  curl -X POST http://core-lb/v1/secrets/static/test/error-test \
    -H "X-Vault-Token: invalid-token" \
    -d '{"data": {"password": "secret123"}}'

  # Check response
  # Expected: Error message does NOT contain "secret123"
  ```

### 5.2 Dynamic Secrets **[HIGH]**

- [ ] **Dynamic secrets auto-expire**
  ```bash
  # Generate dynamic secret with 60-second TTL
  CREDS=$(curl -X POST http://core-lb/v1/secrets/dynamic/test-role \
    -H "X-Vault-Token: $ADMIN_TOKEN" \
    -d '{"ttl": "60s"}' | jq -r '.data')

  # Wait 70 seconds
  sleep 70

  # Verify credentials no longer work
  # Expected: Authentication failure
  ```

- [ ] **Lease renewal working**
  ```bash
  # Generate dynamic secret
  LEASE_ID=$(curl -X POST http://core-lb/v1/secrets/dynamic/test-role \
    -H "X-Vault-Token: $ADMIN_TOKEN" | jq -r '.lease_id')

  # Renew lease
  curl -X POST http://core-lb/v1/sys/leases/renew \
    -H "X-Vault-Token: $ADMIN_TOKEN" \
    -d "{\"lease_id\": \"$LEASE_ID\"}"

  # Expected: 200 OK with extended TTL
  ```

- [ ] **Manual revocation working**
  ```bash
  # Revoke lease
  curl -X POST http://core-lb/v1/sys/leases/revoke \
    -H "X-Vault-Token: $ADMIN_TOKEN" \
    -d "{\"lease_id\": \"$LEASE_ID\"}"

  # Verify credentials no longer work
  # Expected: Immediate revocation
  ```

### 5.3 Secret Rotation **[HIGH]**

- [ ] **Static secret rotation scheduled**
  ```bash
  # Check Oban scheduled jobs
  psql $DATABASE_URL -c "
    SELECT * FROM oban_jobs
    WHERE worker = 'SecretHub.Workers.RotationWorker'
    AND state = 'scheduled'
    LIMIT 5;
  "
  # Expected: Rotation jobs scheduled
  ```

- [ ] **Grace period honored during rotation**
  ```bash
  # Trigger rotation with grace period
  # Verify old secret still works during grace period
  # Verify old secret expires after grace period
  ```

- [ ] **Rotation failures logged**
  ```bash
  psql $DATABASE_URL -c "
    SELECT * FROM audit.events
    WHERE event_type = 'secret.rotation_failed'
    LIMIT 5;
  "
  ```

---

## Section 6: Policy Enforcement

### 6.1 Access Control Policies **[CRITICAL]**

- [ ] **Deny-by-default enforced**
  ```bash
  # Test: Access secret without policy
  curl http://core-lb/v1/secrets/static/test/no-policy \
    -H "X-Vault-Token: $UNPRIVILEGED_TOKEN"
  # Expected: 403 Forbidden
  ```

- [ ] **Path-based restrictions work**
  ```bash
  # Create policy: allow read on "allowed/*"
  # Test: Read secret at "allowed/secret" → SUCCESS
  # Test: Read secret at "denied/secret" → FORBIDDEN
  ```

- [ ] **Capability enforcement (read, write, delete)**
  ```bash
  # Policy allows only "read"
  # Test: Read secret → SUCCESS
  # Test: Write secret → FORBIDDEN
  # Test: Delete secret → FORBIDDEN
  ```

### 6.2 Conditional Policies **[HIGH]**

- [ ] **Time-of-day restrictions work**
  ```bash
  # Create policy: allow access only 9 AM - 5 PM
  # Test: Access at 2 PM → SUCCESS
  # Test: Access at 10 PM → FORBIDDEN
  ```

- [ ] **IP-based restrictions work**
  ```bash
  # Create policy: allow access only from 10.0.0.0/8
  # Test: Access from 10.0.0.1 → SUCCESS
  # Test: Access from 192.168.1.1 → FORBIDDEN
  ```

- [ ] **Days-of-week restrictions work**
  ```bash
  # Create policy: allow access only Monday-Friday
  # Test: Access on Wednesday → SUCCESS
  # Test: Access on Sunday → FORBIDDEN
  ```

- [ ] **TTL restrictions enforced**
  ```bash
  # Create policy: max TTL = 1 hour
  # Test: Request token with 30 min TTL → SUCCESS
  # Test: Request token with 2 hour TTL → REJECTED (capped at 1 hour)
  ```

### 6.3 Policy Conflicts **[MEDIUM]**

- [ ] **Policy conflicts detected**
  ```bash
  # Create overlapping policies with conflicting rules
  # Expected: Warning in UI or validation error
  ```

- [ ] **Most restrictive policy wins**
  ```bash
  # Attach two policies: one allows, one denies
  # Expected: Deny wins (most restrictive)
  ```

---

## Section 7: Vulnerability Management

### 7.1 Dependencies **[HIGH]**

- [ ] **No known CVEs in dependencies**
  ```bash
  # Run dependency security scan
  cd /home/gao/Workspace/gsmlg-dev/secrethub
  mix hex.audit

  # Expected: No security vulnerabilities found
  ```

- [ ] **All dependencies up to date**
  ```bash
  mix hex.outdated
  # Expected: No critical outdated packages
  ```

- [ ] **Prometheus updated (if applicable)**
  ```bash
  # Check Prometheus version
  mix deps | grep prometheus
  # Recommended: prometheus >= 5.0
  ```

### 7.2 Security Headers **[MEDIUM]**

- [ ] **X-Frame-Options set**
  ```bash
  curl -I https://secrethub.company.com
  # Expected: X-Frame-Options: DENY or SAMEORIGIN
  ```

- [ ] **X-Content-Type-Options set**
  ```bash
  curl -I https://secrethub.company.com
  # Expected: X-Content-Type-Options: nosniff
  ```

- [ ] **Content-Security-Policy set**
  ```bash
  curl -I https://secrethub.company.com
  # Expected: Content-Security-Policy: default-src 'self'
  ```

- [ ] **Strict-Transport-Security set (production)**
  ```bash
  curl -I https://secrethub.company.com
  # Expected: Strict-Transport-Security: max-age=31536000
  ```

### 7.3 Input Validation **[HIGH]**

- [ ] **SQL injection protection (Ecto parameterized queries)**
  ```bash
  # Test: Attempt SQL injection in secret path
  curl http://core-lb/v1/secrets/static/test' OR '1'='1 \
    -H "X-Vault-Token: $ADMIN_TOKEN"
  # Expected: 404 Not Found or validation error, NOT SQL error
  ```

- [ ] **XSS protection (Phoenix auto-escaping)**
  ```bash
  # Test: Create secret with XSS payload
  curl -X POST http://core-lb/v1/secrets/static/test/xss \
    -H "X-Vault-Token: $ADMIN_TOKEN" \
    -d '{"data": {"value": "<script>alert(1)</script>"}}'

  # View in Web UI
  # Expected: Script tags escaped, not executed
  ```

- [ ] **Path traversal protection**
  ```bash
  # Test: Attempt path traversal
  curl http://core-lb/v1/secrets/static/../../etc/passwd \
    -H "X-Vault-Token: $ADMIN_TOKEN"
  # Expected: 400 Bad Request or normalized path
  ```

---

## Section 8: Operational Security

### 8.1 Vault Seal Status **[CRITICAL]**

- [ ] **Vault sealed by default on start**
  ```bash
  # Restart Core instance
  kubectl delete pod $(kubectl get pod -n secrethub -l app=secrethub-core -o jsonpath='{.items[0].metadata.name}') -n secrethub

  # Check seal status
  sleep 10
  curl http://core-lb/v1/sys/seal-status | jq '.sealed'
  # Expected: true (unless auto-unseal configured)
  ```

- [ ] **Manual unseal requires 3 of 5 keys**
  ```bash
  # Unseal with only 1 key
  curl -X POST http://core-lb/v1/sys/unseal \
    -d '{"key": "KEY1"}'

  curl http://core-lb/v1/sys/seal-status | jq '.sealed'
  # Expected: still sealed (threshold not met)
  ```

- [ ] **Auto-unseal working (if configured)**
  ```bash
  # Restart Core with auto-unseal
  kubectl delete pod ... -n secrethub

  # Wait for startup
  sleep 30

  curl http://core-lb/v1/sys/seal-status | jq '.sealed'
  # Expected: false (auto-unsealed)
  ```

### 8.2 Access Logging **[MEDIUM]**

- [ ] **All admin actions logged**
  ```bash
  psql $DATABASE_URL -c "
    SELECT COUNT(*) FROM audit.events
    WHERE actor LIKE '%admin%'
    AND timestamp > NOW() - INTERVAL '1 day';
  "
  # Expected: > 0
  ```

- [ ] **Sensitive data not in logs**
  ```bash
  # Check application logs
  kubectl logs -n secrethub -l app=secrethub-core --tail=1000 | \
    grep -i "password\|token\|secret_id"
  # Expected: Only references, no actual values
  ```

---

## Security Verification Summary

### Completion Tracking

```bash
# Count completed checks
TOTAL_CHECKS=60
COMPLETED_CHECKS=0  # Update as you go
FAILED_CHECKS=0

COMPLETION_RATE=$(( COMPLETED_CHECKS * 100 / TOTAL_CHECKS ))

echo "Security Verification Progress: ${COMPLETION_RATE}%"
echo "Completed: $COMPLETED_CHECKS / $TOTAL_CHECKS"
echo "Failed: $FAILED_CHECKS"
```

### Pass Criteria

- ✅ **READY FOR PRODUCTION** if:
  - All CRITICAL checks pass (100%)
  - All HIGH priority checks pass (100%)
  - 95%+ of MEDIUM priority checks pass
  - No unresolved CRITICAL or HIGH findings

- ⚠️ **NEEDS REMEDIATION** if:
  - Any CRITICAL check fails
  - More than 1 HIGH check fails
  - Less than 95% of MEDIUM checks pass

### Report Template

```markdown
# Security Verification Report

**Date:** YYYY-MM-DD
**Environment:** Staging/Production
**Verified By:** [Name]

## Results

- Total Checks: 60
- Passed: XX
- Failed: XX
- Pass Rate: XX%

### Failed Checks

1. [Check name] - [Severity]
   - Issue: [Description]
   - Impact: [Impact]
   - Remediation: [Action plan]

## Recommendation

[ ] APPROVED for production
[ ] REQUIRES remediation before production

**Approved By:** [Name]
**Date:** YYYY-MM-DD
```

---

## Related Documentation

- [Security Audit Report](../../SECURITY_AUDIT.md)
- [Security Fixes Applied](../../SECURITY_FIXES_APPLIED.md)
- [Week 29 Summary](../../WEEK_29_SECURITY_AUDIT_SUMMARY.md)
- [Best Practices](../best-practices.md)

---

**Last Updated:** 2025-11-04
**Next Review:** 2025-12-04 (Monthly)
