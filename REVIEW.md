# SecretHub Code Review Report

**Date:** 2026-02-20
**Scope:** Full architecture, security, API, and OTP review
**Severities:** `CRITICAL` | `MAJOR` | `MINOR` | `NITPICK`

---

## Executive Summary

SecretHub is a well-architected Elixir umbrella application with solid fundamentals: AES-256-GCM encryption, Shamir's Secret Sharing for vault unsealing, hash-chain audit logs, and proper separation into core/web/agent/shared/cli apps. However, the review uncovered **2 critical**, **11 major**, **8 minor**, and **5 nitpick** findings that should be addressed — particularly around authentication token integrity, timing attacks, and incomplete security implementations.

---

## 1. CRITICAL Findings

### C1. Timing Attack in AppRole SecretID Validation
**File:** `apps/secrethub_core/lib/secrethub_core/auth/app_role.ex:305`
**Severity:** CRITICAL

```elixir
bind_secret_id and secret_id != stored_secret_id ->
  {:error, "invalid_secret_id"}
```

The `!=` operator performs byte-by-byte comparison that short-circuits on first mismatch. An attacker can measure response time differences to brute-force the SecretID one byte at a time.

**Fix:** Use `Plug.Crypto.secure_compare/2` for constant-time comparison.

---

### C2. Auth Tokens Are Unsigned (Base64 Only, No Cryptographic Integrity)
**File:** `apps/secrethub_core/lib/secrethub_core/auth/app_role.ex:360-378`
**Severity:** CRITICAL

```elixir
# For now, use simple base64 encoding
# TODO: Implement proper JWT signing
Jason.encode!(payload) |> Base.url_encode64(padding: false)
```

Tokens contain `role_id`, `policies`, and `expires_at` as plain Base64 JSON. Any client can forge a token with arbitrary policies and expiry by simply encoding their own JSON payload. There is no HMAC, no signature, no verification.

**Fix:** Use `Phoenix.Token.sign/4` (already used elsewhere in the codebase) or implement proper HMAC-signed tokens.

---

## 2. MAJOR Findings

### M1. Certificate Chain Verification Not Implemented
**File:** `apps/secrethub_web/lib/secret_hub/web/plugs/verify_client_certificate.ex:304-321`
**Severity:** MAJOR

```elixir
defp verify_against_ca_chain(_cert_der) do
  # FIXME: Implement proper certificate chain validation
  case CA.get_ca_chain() do
    {:ok, _ca_chain_pem} -> :valid  # Just checks CA exists!
```

The mTLS verification plug only checks whether a CA chain *exists* in the database — it does **not** verify the client certificate's signature against the chain. Any certificate from any CA would pass validation.

---

### M2. App Certificate Verification Not Implemented
**File:** `apps/secrethub_web/lib/secret_hub/web/controllers/pki_controller.ex:703-709`
**Severity:** MAJOR

```elixir
defp verify_current_certificate(_current_cert_pem, _app_id) do
  # TODO: Implement certificate verification
  :ok
end
```

Certificate renewal skips all validation — a revoked or expired certificate can be used to obtain a fresh one.

---

### M3. Hardcoded Audit HMAC Secret with Insecure Fallback
**File:** `apps/secrethub_core/lib/secrethub_core/audit.ex:63`
**Severity:** MAJOR

```elixir
@hmac_secret Application.compile_env(:secrethub_core, :audit_hmac_secret, "dev-audit-secret")
```

If `audit_hmac_secret` is not explicitly configured in production, the audit hash chain uses a hardcoded secret. An attacker who knows this (it's in the source code) can forge audit log entries that pass HMAC verification, defeating the tamper-evidence guarantee.

---

### M4. Hardcoded Session Signing/Encryption Salts
**File:** `config/config.exs:37-52`
**Severity:** MAJOR

```elixir
live_view: [signing_salt: "0PScoGoh"],
session_options: [
  signing_salt: "secrethub_signing_salt",
  encryption_salt: "secrethub_encryption_salt"
]
```

Static, predictable salts in a secrets management platform. If `SECRET_KEY_BASE` is ever leaked, sessions can be forged trivially. These should be generated per deployment or derived from strong runtime secrets.

---

### M5. Agent Supervisor Uses `:one_for_one` Despite Ordered Dependencies
**File:** `apps/secrethub_agent/lib/secrethub_agent/application.ex:76`
**Severity:** MAJOR

```elixir
children = [Cache, EndpointManager, ConnectionManager, LeaseRenewer, UDSServer]
opts = [strategy: :one_for_one, ...]
```

With `:one_for_one`, if `ConnectionManager` crashes, `UDSServer` stays alive and serves stale data. Applications connecting via UDS get errors because the Core connection is down. Should be `:rest_for_one` so downstream children restart when an upstream dependency crashes.

---

### M6. LeaseRenewer Blocks GenServer with Synchronous HTTP
**File:** `apps/secrethub_agent/lib/secrethub_agent/lease_renewer.ex`
**Severity:** MAJOR

Renewal HTTP calls (5s timeout each) execute synchronously in the GenServer process. With many leases, the GenServer message queue backs up, renewal deadlines are missed, and the entire agent stalls.

**Fix:** Use `Task.Supervisor` for async HTTP calls with backpressure.

---

### M7. Cache LRU Eviction Copies Entire ETS Table
**File:** `apps/secrethub_core/lib/secrethub_core/cache.ex:243-265`
**Severity:** MAJOR

```elixir
:ets.tab2list(table)  # Full table copy into process memory
|> Enum.sort_by(...)   # O(n log n)
|> Enum.take(entries_to_evict)
```

On a cache with thousands of entries, this creates a full in-memory copy and sorts it, defeating the purpose of ETS (off-heap storage). Under memory pressure, this can crash the process.

---

### M8. EndpointManager Health Check Doesn't Actually Check Health
**File:** `apps/secrethub_agent/lib/secrethub_agent/endpoint_manager.ex:245-252`
**Severity:** MAJOR

`perform_health_checks` only clears expired backoff timers. It never pings endpoints to verify recovery. Unhealthy endpoints remain in backoff until the backoff period expires naturally, regardless of whether they've recovered.

---

### M9. AppRoleAuth `has_admin_policy?` Always Returns False
**File:** `apps/secrethub_web/lib/secret_hub/web/plugs/approle_auth.ex:91-94`
**Severity:** MAJOR

```elixir
defp has_admin_policy?(_policies) do
  # TODO: Check if any policy includes admin privileges
  false
end
```

Token-based admin authentication via AppRole never succeeds. Only session-based admin auth works.

---

### M10. No Exponential Backoff Jitter (Thundering Herd)
**File:** `apps/secrethub_agent/lib/secrethub_agent/connection_manager.ex:244-250`
**Severity:** MAJOR

```elixir
delay = min(:math.pow(2, state.reconnect_attempts) * 1000, 60_000) |> round()
```

No jitter. When Core recovers from an outage, all agents reconnect at exactly the same intervals, creating a thundering herd that can crash Core again.

**Fix:** Add `+ :rand.uniform(delay_jitter)` with ~25% jitter.

---

### M11. CIDR Matching Not Implemented
**File:** `apps/secrethub_core/lib/secrethub_core/auth/app_role.ex:354-357`
**Severity:** MAJOR

```elixir
# TODO: Implement CIDR matching
# For now, just check exact match
Enum.member?(bound_cidr_list, source_ip)
```

IP binding uses exact string match instead of CIDR subnet matching. A policy configured with `10.0.0.0/8` would only match the literal string `"10.0.0.0/8"`, not any IP in that subnet.

---

## 3. MINOR Findings

### m1. UDS Socket Blindly Deleted on Startup
**File:** `apps/secrethub_agent/lib/secrethub_agent/uds_server.ex:313-342`

`File.rm(state.socket_path)` runs without checking if another agent instance holds the socket. Could silently disconnect an existing agent's applications.

### m2. Secrets Context Couples Policy Evaluation and Audit Logging
**File:** `apps/secrethub_core/lib/secrethub_core/secrets.ex:250-282`

`get_secret_for_entity/3` directly calls `Policies.evaluate_access/4` then `Audit.log_event/1`. Cannot evaluate policies without audit side effects, and the Secrets context has dual responsibilities.

### m3. `inspect(reason)` in Error Logs May Leak Sensitive Context
**Files:** `secrets.ex:69`, `audit.ex:143`, `secrets.ex:288`

Generic `inspect()` on error tuples could surface changeset data, secret paths, or internal state into log aggregators.

### m4. Agent Context Is a God Module (630 Lines, 18 Functions)
**File:** `apps/secrethub_core/lib/secrethub_core/agents.ex`

Handles bootstrap, authentication, heartbeat, policy binding, suspension, revocation, AND lease cancellation. Lease cleanup and certificate revocation should be delegated.

### m5. Policy Regex Compiled Per-Request Without Caching
**File:** `apps/secrethub_web/lib/secret_hub/web/controllers/secret_api_controller.ex:301-304`

Regex patterns from policy documents are compiled on every request. For high-throughput secret reads, this adds unnecessary CPU overhead.

### m6. Missing Database Indexes
**Files:** Migration files

- No index on `certificates.issuer` (used in CA chain queries)
- No index on `agents.authenticated_at` (used for recent activity queries)
- No composite index on `agents(agent_id, status)` (used in status reports)

### m7. `Enum.find` for Role Lookup Instead of DB Query
**File:** `apps/secrethub_web/lib/secret_hub/web/controllers/auth_controller.ex:135`

Loads all roles then uses `Enum.find` by name. Should use `Repo.get_by(Role, role_name: name)`.

### m8. Master Key Stored Unencrypted in Process Memory
**File:** `apps/secrethub_core/lib/secrethub_core/vault/seal_state.ex`

The unsealed master key sits in GenServer state as a plain binary. A memory dump (crash dump, core dump, or heap inspection) would reveal it.

---

## 4. NITPICK Findings

### n1. Agent Controller Actions Are All TODOs
**File:** `apps/secrethub_web/lib/secret_hub/web/controllers/agent_controller.ex:12-32`

`disconnect`, `reconnect`, and `restart` all return dummy responses.

### n2. `generate_secret_id/1` Always Returns Error
**File:** `apps/secrethub_core/lib/secrethub_core/auth/app_role.ex:396-403`

Dead code using `if false do` to satisfy typespec while being permanently unreachable.

### n3. Inconsistent DateTime Formats in API Responses
Various controllers use `DateTime.to_iso8601/1` in some places and Unix timestamps in others.

### n4. X-Forwarded-For Parsing Takes First IP
**File:** `apps/secrethub_web/lib/secret_hub/web/plugs/rate_limiter.ex:116`

In multi-proxy environments, the first IP is the client, but a malicious client can prepend fake IPs. Should take the last untrusted IP or use a configured trusted proxy list.

### n5. Auto-Seal Timeout of 30 Seconds Is Aggressive
**File:** `apps/secrethub_core/lib/secrethub_core/vault/seal_state.ex:28`

Long-running operations (bulk secret rotation, certificate issuance batch) may exceed the 30s window, causing the vault to seal mid-operation. Should be configurable.

---

## 5. Architecture Summary

### Strengths
- **Encryption**: AES-256-GCM with random nonces, proper authenticated encryption
- **Key Sharing**: Shamir's Secret Sharing with GF(251) field, backward-compatible encoding
- **Audit Trail**: Hash-chain with SHA-256 + HMAC, sequence numbers, gap detection
- **Token Storage**: Bootstrap tokens stored as SHA-256 hashes, not plaintext
- **Schema Design**: Well-normalized with proper foreign keys and constraints
- **Separation**: Clear umbrella app boundaries (core/web/agent/shared/cli)
- **Background Jobs**: Oban integration for rotation scheduling
- **Health Probes**: Kubernetes-ready liveness/readiness endpoints
- **Rate Limiting**: In-memory ETS-based per-IP rate limiting on auth endpoints

### Weaknesses
- **Incomplete Security**: 4 critical/major TODO items in authentication and cert verification
- **God Modules**: Agents (630L), Apps (602L), Secrets (543L) have too many responsibilities
- **OTP Strategy**: Agent supervisor strategy doesn't match dependency ordering
- **In-Memory State**: LeaseManager and Cache can diverge from database state
- **Missing Property Tests**: Crypto and encoding boundaries lack StreamData coverage
- **LiveView Coverage**: 1 of 30+ LiveView modules has tests

---

## 6. Priority Matrix

| # | Finding | Severity | Effort | Impact |
|---|---------|----------|--------|--------|
| C1 | Timing attack in SecretID | CRITICAL | Low | Auth bypass |
| C2 | Unsigned auth tokens | CRITICAL | Low | Token forgery |
| M1 | No cert chain verification | MAJOR | Medium | mTLS bypass |
| M2 | No cert renewal verification | MAJOR | Low | Cert lifecycle bypass |
| M3 | Hardcoded HMAC secret | MAJOR | Low | Audit log forgery |
| M4 | Hardcoded session salts | MAJOR | Low | Session forgery |
| M5 | Wrong supervisor strategy | MAJOR | Low | Cascade failures |
| M6 | Blocking HTTP in GenServer | MAJOR | Medium | Agent stall |
| M9 | Admin policy check broken | MAJOR | Low | Admin auth gap |
| M11 | CIDR matching missing | MAJOR | Medium | Policy bypass |
| M7 | ETS table copy in cache | MAJOR | Medium | OOM risk |
| M8 | Fake health checks | MAJOR | Medium | Stale failover |
| M10 | No backoff jitter | MAJOR | Low | Thundering herd |
