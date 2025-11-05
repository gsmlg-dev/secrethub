# Application Policies User Guide

This guide explains how to use policies to control application access to secrets in SecretHub.

## Table of Contents

1. [Overview](#overview)
2. [Policy Concepts](#policy-concepts)
3. [Creating App Policies](#creating-app-policies)
4. [Binding Policies to Apps](#binding-policies-to-apps)
5. [Policy Templates](#policy-templates)
6. [Policy Evaluation](#policy-evaluation)
7. [Best Practices](#best-practices)
8. [Examples](#examples)
9. [Troubleshooting](#troubleshooting)

---

## Overview

Application policies control which secrets an application can access and what operations it can perform. Every secret access request is evaluated against the policies bound to the requesting application.

### Key Features

- **Fine-grained access control**: Control access at the secret path level with wildcard patterns
- **Operation-level permissions**: Specify which operations (read, write, delete, renew) are allowed
- **Conditional access**: Add time-based, IP-based, or TTL-based restrictions
- **Policy templates**: Use pre-built templates for common scenarios
- **Deny policies**: Explicitly deny access to specific secrets

---

## Policy Concepts

### Policy Structure

A policy consists of:

```json
{
  "version": "1.0",
  "allowed_secrets": ["prod.db.*", "prod.api.keys.*"],
  "allowed_operations": ["read", "renew"],
  "conditions": {
    "max_ttl": "3600",
    "ip_ranges": ["10.0.0.0/8"]
  }
}
```

**Fields:**
- `version`: Policy document version (currently "1.0")
- `allowed_secrets`: Array of secret path patterns (supports wildcards)
- `allowed_operations`: Array of operations ("read", "write", "delete", "renew")
- `conditions`: Optional conditions for policy evaluation

### Entity Bindings

Policies are bound to applications via **entity bindings**. An application inherits all permissions from its bound policies.

```
Application → Bound Policies → Allowed Secrets
```

### Wildcard Patterns

Secret paths support glob-style wildcards:

- `prod.db.*` - Matches all secrets under `prod.db`
- `prod.*.password` - Matches password secrets in all prod services
- `*.config` - Matches all config secrets in any environment
- `*` - Matches all secrets (use with caution)

---

## Creating App Policies

### Method 1: Using Policy Templates

The easiest way to create policies is using pre-built templates:

```elixir
# Read-only access to database secrets
{:ok, policy} = SecretHub.Core.AppPolicies.create_app_policy(
  "payment-db-readonly",
  :read_only,
  ["prod.db.payment.*", "prod.db.shared.*"]
)
```

**Available Templates:**
- `:read_only` - Read-only access
- `:read_write` - Read and write access
- `:dynamic_secrets` - Dynamic credential access (read + renew)
- `:env_vars` - Environment variable access
- `:config_files` - Configuration file access
- `:full_access` - Full access (admin only)

### Method 2: Custom Policy Document

For advanced use cases, create a custom policy:

```elixir
{:ok, policy} = SecretHub.Core.Policies.create_policy(%{
  name: "payment-service-custom",
  description: "Custom policy for payment service",
  policy_document: %{
    "version" => "1.0",
    "allowed_secrets" => ["prod.payment.*"],
    "allowed_operations" => ["read", "write"],
    "conditions" => %{
      "max_ttl" => "7200",
      "time_of_day" => "08:00-20:00",
      "ip_ranges" => ["10.0.1.0/24"]
    }
  }
})
```

### Method 3: Default Policy Sets

Create a complete set of policies for an application:

```elixir
# Creates read and read-write policies automatically
{:ok, policies} = SecretHub.Core.AppPolicies.create_default_policies(
  "payment-service",
  "prod",
  "db"
)
# Creates:
# - payment-service-prod-db-read
# - payment-service-prod-db-readwrite
```

---

## Binding Policies to Apps

### Register App with Policies

Specify policies during application registration:

```bash
curl -X POST http://localhost:4000/v1/apps \
  -H "Content-Type: application/json" \
  -d '{
    "name": "payment-service",
    "agent_id": "agent-uuid",
    "policies": ["db-readonly", "api-access"],
    "description": "Payment processing service"
  }'
```

### Bind Policy After Registration

Add policies to existing applications:

```elixir
# Bind a single policy
{:ok, _policy} = SecretHub.Core.Apps.bind_policy(app_id, policy_id)

# Update all policies at once
{:ok, _app} = SecretHub.Core.Apps.update_app_policies(
  app_id,
  ["db-readonly", "api-access", "cache-access"]
)
```

### REST API

```bash
# Bind policy
curl -X POST http://localhost:4000/v1/apps/{app_id}/policies \
  -H "Content-Type: application/json" \
  -d '{"policy_id": "policy-uuid"}'

# List app policies
curl http://localhost:4000/v1/apps/{app_id}/policies

# Unbind policy
curl -X DELETE http://localhost:4000/v1/apps/{app_id}/policies/{policy_id}
```

---

## Policy Templates

### Read-Only Template

**Use Case:** Applications that only need to read secrets (most common)

```elixir
AppPolicies.create_app_policy(
  "app-readonly",
  :read_only,
  ["prod.db.*", "prod.api.*"]
)
```

**Operations:** `["read"]`

### Read-Write Template

**Use Case:** Applications that need to update secrets (e.g., secret rotation tools)

```elixir
AppPolicies.create_app_policy(
  "app-readwrite",
  :read_write,
  ["prod.cache.*"]
)
```

**Operations:** `["read", "write"]`

### Dynamic Secrets Template

**Use Case:** Applications using dynamic database credentials

```elixir
AppPolicies.create_app_policy(
  "app-dynamic-db",
  :dynamic_secrets,
  ["dynamic.postgres.*"],
  max_ttl: 3600
)
```

**Operations:** `["read", "renew"]`

**Notes:**
- Allows generating new credentials
- Allows renewing leases before expiry
- Recommended for database access

### Environment Variables Template

**Use Case:** Applications loading env vars from SecretHub

```elixir
AppPolicies.create_app_policy(
  "app-env",
  :env_vars,
  ["prod.env.*"]
)
```

**Operations:** `["read"]`

### Configuration Files Template

**Use Case:** Applications rendering config files from templates

```elixir
AppPolicies.create_app_policy(
  "app-config",
  :config_files,
  ["prod.config.*", "prod.certs.*"]
)
```

**Operations:** `["read"]`

---

## Policy Evaluation

### How Access is Determined

When an application requests a secret, SecretHub:

1. **Identifies the application** from its mTLS certificate
2. **Retrieves all policies** bound to the application
3. **Evaluates each policy** against the request:
   - Check if secret path matches `allowed_secrets` patterns
   - Check if operation is in `allowed_operations`
   - Evaluate `conditions` (time, IP, TTL)
4. **Grants access** if ANY policy allows it
5. **Denies access** if a deny policy matches

### Evaluation Order

1. Deny policies are checked first (if match → deny immediately)
2. Allow policies are checked next (if any match → grant access)
3. If no policies match → deny access

### Policy Conditions

#### Max TTL

Limit the maximum TTL for dynamic secrets:

```json
{
  "conditions": {
    "max_ttl": "3600"
  }
}
```

**Values:**
- Seconds as string: `"3600"`
- With units: `"1h"`, `"30m"`, `"1d"`

#### Time of Day

Restrict access to specific hours:

```json
{
  "conditions": {
    "time_of_day": "08:00-18:00"
  }
}
```

**Format:** `"HH:MM-HH:MM"` (24-hour format)

#### IP Ranges

Restrict access from specific networks:

```json
{
  "conditions": {
    "ip_ranges": ["10.0.0.0/8", "192.168.1.0/24"]
  }
}
```

**Format:** CIDR notation

---

## Best Practices

### 1. Principle of Least Privilege

Grant only the minimum permissions needed:

```elixir
# Good: Specific paths and read-only
create_app_policy("app-db", :read_only, ["prod.db.myapp.*"])

# Bad: Overly broad permissions
create_app_policy("app-all", :full_access, ["*"])
```

### 2. Use Descriptive Policy Names

```elixir
# Good: Clear and descriptive
"payment-service-prod-db-readonly"
"user-service-staging-cache-readwrite"

# Bad: Vague names
"policy1"
"app-access"
```

### 3. Environment Separation

Create separate policies for each environment:

```elixir
# Production
create_app_policy("app-prod-db", :read_only, ["prod.db.*"])

# Staging
create_app_policy("app-staging-db", :read_only, ["staging.db.*"])
```

### 4. Regular Policy Audits

Periodically review policies:

```elixir
# List all app policies
{:ok, policies} = Apps.list_app_policies(app_id)

# Check what secrets an app can access
{:ok, policy} = Apps.evaluate_app_access(
  app_id,
  "prod.db.password",
  "read"
)
```

### 5. Use Templates for Common Patterns

Don't reinvent the wheel:

```elixir
# Use templates for standard scenarios
AppPolicies.create_app_policy("app-db", :dynamic_secrets, ["dynamic.postgres.*"])

# Only use custom policies for special requirements
Policies.create_policy(%{...})
```

### 6. Document Policy Intent

Always include descriptions:

```elixir
create_app_policy(
  "payment-db-readonly",
  :read_only,
  ["prod.payment.db.*"],
  description: "Read-only access for payment service to production database secrets. Used for connection string retrieval."
)
```

---

## Examples

### Example 1: Simple Read-Only App

```elixir
# 1. Create policy
{:ok, policy} = AppPolicies.create_app_policy(
  "webapp-secrets-readonly",
  :read_only,
  ["prod.web.*"]
)

# 2. Register application
{:ok, %{app: app, token: token}} = Apps.register_app(%{
  name: "web-frontend",
  agent_id: agent_id,
  policies: ["webapp-secrets-readonly"]
})

# 3. Application can now read prod.web.* secrets
```

### Example 2: Dynamic Database Credentials

```elixir
# 1. Create policy for dynamic PostgreSQL access
{:ok, policy} = AppPolicies.create_app_policy(
  "api-dynamic-postgres",
  :dynamic_secrets,
  ["dynamic.postgres.api-role"],
  max_ttl: 7200,  # 2 hour max TTL
  description: "Dynamic PostgreSQL credentials for API service"
)

# 2. Register application
{:ok, %{app: app, token: token}} = Apps.register_app(%{
  name: "api-service",
  agent_id: agent_id,
  policies: ["api-dynamic-postgres"]
})

# 3. Application can generate and renew PostgreSQL credentials
# Request: POST /v1/secrets/dynamic/api-role
# Response: {"username": "v-api-abc123", "password": "...", "lease_id": "..."}
```

### Example 3: Multi-Policy Application

```elixir
# Create multiple policies for different secret types
{:ok, db_policy} = AppPolicies.create_app_policy(
  "payment-db-readonly",
  :read_only,
  ["prod.db.payment.*"]
)

{:ok, api_policy} = AppPolicies.create_app_policy(
  "payment-api-keys",
  :read_only,
  ["prod.api.stripe.*", "prod.api.paypal.*"]
)

{:ok, cache_policy} = AppPolicies.create_app_policy(
  "payment-redis-readwrite",
  :read_write,
  ["prod.cache.payment.*"]
)

# Register application with all policies
{:ok, %{app: app, token: token}} = Apps.register_app(%{
  name: "payment-service",
  agent_id: agent_id,
  policies: [
    "payment-db-readonly",
    "payment-api-keys",
    "payment-redis-readwrite"
  ]
})
```

### Example 4: Time-Restricted Access

```elixir
# Create policy with time restrictions
{:ok, policy} = Policies.create_policy(%{
  name: "batch-job-business-hours",
  description: "Batch job access during business hours only",
  policy_document: %{
    "version" => "1.0",
    "allowed_secrets" => ["prod.batch.*"],
    "allowed_operations" => ["read", "write"],
    "conditions" => %{
      "time_of_day" => "06:00-22:00",
      "ip_ranges" => ["10.0.0.0/8"]
    }
  }
})

# Bind to application
Apps.bind_policy(batch_app_id, policy.id)
```

### Example 5: Deny Policy

```elixir
# Create a deny policy to block access to sensitive secrets
{:ok, deny_policy} = Policies.create_policy(%{
  name: "deny-prod-secrets",
  description: "Explicitly deny access to production master secrets",
  deny_policy: true,
  policy_document: %{
    "version" => "1.0",
    "allowed_secrets" => ["prod.master.*", "prod.root.*"],
    "allowed_operations" => ["read", "write", "delete"]
  }
})

# Bind to untrusted applications
Apps.bind_policy(staging_app_id, deny_policy.id)
```

---

## Troubleshooting

### Access Denied Errors

**Problem:** Application receives "Access denied" when requesting secrets

**Solutions:**

1. **Check Policy Binding:**
   ```elixir
   {:ok, policies} = Apps.list_app_policies(app_id)
   IO.inspect(policies, label: "Bound Policies")
   ```

2. **Verify Secret Path Pattern:**
   ```elixir
   # Ensure the secret path matches policy patterns
   # Pattern: "prod.db.*"
   # Matches: "prod.db.postgres", "prod.db.mysql"
   # Does NOT match: "staging.db.postgres", "prod.database.mysql"
   ```

3. **Check Operation Permission:**
   ```elixir
   # Policy with ["read"] operations will deny "write" requests
   # Ensure allowed_operations includes the operation being performed
   ```

4. **Evaluate Access Manually:**
   ```elixir
   {:ok, policy} = Apps.evaluate_app_access(
     app_id,
     "prod.db.password",
     "read"
   )
   ```

### Policy Not Taking Effect

**Problem:** Policy changes don't seem to apply

**Solutions:**

1. **Check Policy Binding:**
   - Ensure the policy is actually bound to the application
   - Policy names in the `policies` array must match exactly

2. **Verify Policy Document:**
   ```elixir
   {:ok, policy} = Policies.get_policy(policy_id)
   IO.inspect(policy.policy_document)
   ```

3. **Check for Deny Policies:**
   - Deny policies override allow policies
   - Remove or modify deny policies if blocking access

### Wildcard Patterns Not Matching

**Problem:** Wildcard patterns don't match expected secrets

**Common Mistakes:**

```elixir
# Wrong: Double wildcard
"prod.db.**.password"  # NOT supported

# Wrong: Regex syntax
"prod\\.db\\..*"  # Use glob syntax, not regex

# Wrong: Missing level
"prod.*.password"  # Doesn't match "prod.db.postgres.password"

# Correct patterns:
"prod.db.*"              # Matches one level
"prod.db.*.password"     # Matches specific pattern
"prod.*.*.password"      # Matches two levels then password
```

### Max TTL Enforcement

**Problem:** Dynamic secrets exceeding max TTL

**Solution:**

Ensure `max_ttl_seconds` is set correctly:

```elixir
{:ok, policy} = AppPolicies.create_app_policy(
  "app-dynamic",
  :dynamic_secrets,
  ["dynamic.postgres.*"],
  max_ttl: 3600  # 1 hour max
)
```

### Condition Evaluation Failures

**Problem:** Conditions not being evaluated correctly

**Solutions:**

1. **Check Time Format:**
   ```json
   {
     "time_of_day": "08:00-18:00"  // Correct: 24-hour format
   }
   ```

2. **Check IP Format:**
   ```json
   {
     "ip_ranges": ["10.0.0.0/8"]  // Correct: CIDR notation
   }
   ```

3. **Verify Context:**
   ```elixir
   # Ensure context includes required fields
   Apps.evaluate_app_access(
     app_id,
     secret_path,
     operation,
     %{
       ip_address: "10.0.1.50",
       timestamp: DateTime.utc_now()
     }
   )
   ```

---

## Advanced Topics

### Policy Versioning

Future versions will support policy versioning. Current version is "1.0".

### Policy Inheritance

Applications inherit all permissions from bound policies:

```
App → Policy 1 (read prod.db.*)
    → Policy 2 (read prod.api.*)
    → Combined: read prod.db.* OR prod.api.*
```

### Policy Caching

Policies are cached in memory for performance. Cache is invalidated when:
- Policy is created, updated, or deleted
- Policy bindings are modified
- Application is updated or deleted

### Audit Logging

All policy evaluations are logged for audit:

```elixir
# Access granted
[info] Access granted: entity_id=app-123 secret_path=prod.db.password operation=read policy=db-readonly

# Access denied
[warning] Access denied - no matching policy: entity_id=app-123 secret_path=prod.admin.key operation=read
```

---

## Related Documentation

- [Application Registration Guide](./app-registration.md)
- [Application Certificate Issuance](../architecture/app-certificate-issuance.md)
- [Policy Management API](../api/policies.md)
- [Dynamic Secrets Guide](./dynamic-secrets.md)
- [Secret Management Guide](./secrets.md)

---

**Need Help?**

If you're having issues with app policies:
1. Check the audit logs for policy evaluation details
2. Review the troubleshooting section above
3. Verify policy bindings with `Apps.list_app_policies/1`
4. Test policy evaluation with `Apps.evaluate_app_access/4`
