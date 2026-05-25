# SecretHub Agent-Core Communication Protocol

**Version:** 1.1
**Status:** Draft
**Last Updated:** 2026-05-25

## Overview

This document defines the WebSocket-based communication protocol between SecretHub Agent processes and the SecretHub Core service. The protocol enables secure secret delivery, policy enforcement, and audit logging.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  SecretHub Core Service                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │         Phoenix WebSocket Endpoint           │   │
│  │         /agent/socket/websocket           │   │
│  │                                         │   │
│  │  ┌─────────────┐  ┌─────────────┐   │   │
│  │  │ Agent 1    │  │ Agent 2    │   │   │
│  │  │ Connection  │  │ Connection  │   │   │
│  │  │ Handler    │  │ Handler    │   │   │
│  │  └─────────────┘  └─────────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                 │
└─────────────────────────────────────────────────────────┘
```

Each trusted Agent connects via:
- A Core-issued mTLS client certificate on the trusted Agent endpoint
- Certificate-derived identity assigned by `SecretHub.Web.AgentTrustedSocket`
- A persistent `agent:runtime` channel with automatic reconnection
- Message-based request/response pattern
- Server push notifications for secret rotations

## Connection Establishment

Trusted runtime connection is a two-phase model: enrollment proves host identity and obtains runtime material, then runtime uses only the Core-issued mTLS certificate.

### 1. Enrollment Identity

The Agent uses the host SSH key only to prove stable host identity during enrollment. Enrollment sends `ssh_host_public_key` plus host metadata to Core. After operator approval, the Agent generates a separate TLS keypair with `SecretHub.Agent.TLSIdentity`, builds a CSR, and signs an `AgentCSRProof` with the SSH host private key. The CSR submission includes:

```json
{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "ssh_proof": {
    "algorithm": "rsa",
    "signature": "base64url-signature"
  }
}
```

Core verifies `ssh_proof` against the stored `ssh_host_public_key` before issuing a runtime certificate. The signed payload is the canonical `AgentCSRProof` payload over enrollment ID, Core challenge, and TLS CSR hash. The TLS CSR key must be distinct from the SSH host key.

### 2. Runtime Certificate Policy

Core-issued Agent certificates carry runtime identity and policy:

- Subject CN: `agent_id`
- Organization: `SecretHub Agents`
- URI SAN: `urn:secrethub:agent:<agent_id>`
- URI SAN: `urn:secrethub:hostkey-sha256:<fingerprint-without-SHA256-prefix>`
- DNS SANs: valid enrollment hostnames/FQDNs only
- Extended Key Usage: `clientAuth`
- Key Usage: `digitalSignature`

The default Agent certificate TTL is 30 days. Core caps the maximum TTL at 90 days.

### 3. Trusted WebSocket Handshake

`RuntimeBootstrapper` loads trusted material through `IdentityStore` from the Agent `state_dir` and starts the low-level connection with `TrustedConnection`. The runtime connects to the trusted endpoint from `connect-info.json`:

```text
wss://secrethub.example.com:<trusted-port>/agent/socket/websocket
```

TLS handshake validates Core's server certificate and presents `agent-cert.pem` with `agent-key.pem`. `AgentTrustedSocket.connect/3` verifies the peer certificate through `SecretHub.Core.PKI.Verifier`, then assigns certificate-derived identity fields:

- `agent_id`
- `certificate_serial`
- `certificate_fingerprint`
- `certificate_id`

### 4. Runtime Join

The Agent joins only:

```text
agent:runtime
```

The join payload may include runtime metadata such as hostname, version, and mode, but `AgentRuntimeChannel` ignores client-supplied identity. Accepted joins return certificate-derived identity for the Agent `on_runtime_accepted` callback:

```json
{
  "event": "phx_reply",
  "ref": "join-ref",
  "payload": {
    "status": "accepted",
    "agent_id": "agent-prod-01",
    "certificate_serial": "1234",
    "certificate_fingerprint": "sha256:f3a1...",
    "certificate_id": "certificate-uuid"
  }
}
```

Missing mTLS identity is rejected:

```json
{
  "event": "phx_reply",
  "ref": "join-ref",
  "payload": {
    "status": "error",
    "response": {"reason": "mtls_required"}
  }
}
```

Legacy `UserSocket`/`AgentChannel` rejects direct runtime joins with `trusted_runtime_requires_mtls`.

### 5. Runtime Finalization

For first enrollment, the Agent stores `pending.json` until Core accepts the trusted runtime join. `RuntimeBootstrapper` calls `on_runtime_accepted`, finalizes the pending enrollment through the enrollment API, and then removes `pending.json`.

Trusted material is stored under `state_dir`:

```text
agent-cert.pem
agent-key.pem
ca-chain.pem
connect-info.json
identity.json
pending.json
```

`agent-cert.pem`, `agent-key.pem`, and `ca-chain.pem` are the runtime mTLS material. `connect-info.json` contains the trusted endpoint and expected server name. `identity.json` records Agent, certificate, and host-key metadata. `pending.json` exists only while enrollment finalization is pending.

## Core Message Types

### Server Push Events

#### `secret:rotated`
Notifies agent when a secret it has access to has been rotated.

```json
{
  "event": "secret:rotated",
  "payload": {
    "secret_path": "dev.db.postgres.password",
    "new_version": 3,
    "rotated_at": "2025-10-21T10:30:00Z",
    "reason": "scheduled_rotation"
  }
}
```

#### `policy:updated`
Notifies agent when its access policies have changed.

```json
{
  "event": "policy:updated",
  "payload": {
    "policy_names": ["webapp-secrets", "database-access"],
    "updated_at": "2025-10-21T09:15:00Z",
    "requires_reauth": false
  }
}
```

Core does not currently push a heartbeat event. Runtime liveness is maintained by the Agent-to-Core `agent:heartbeat` request documented below.

## Agent Message Types

### Secret Requests

#### `secret:read`
Request a secret path. The Agent uses this event for static secret reads and dynamic role reads; dynamic requests include an optional `ttl`.

```json
{
  "event": "secret:read",
  "ref": "req-001",
  "payload": {
    "path": "dev.db.postgres.auth.password"
  }
}
```

**Response:**
```json
{
  "event": "phx_reply",
  "ref": "req-001",
  "payload": {
    "status": "ok",
    "response": {
      "path": "dev.db.postgres.auth.password",
      "data": {
        "value": "encrypted_pg_password_456",
        "version": 2
      }
    }
  }
}
```

Dynamic role reads use the same event shape with a role path and optional TTL:

```json
{
  "event": "secret:read",
  "ref": "req-002",
  "payload": {
    "path": "dev.db.postgres.readonly",
    "ttl": 3600
  }
}
```

**Response:**
```json
{
  "event": "phx_reply",
  "ref": "req-002",
  "payload": {
    "status": "ok",
    "response": {
      "path": "dev.db.postgres.readonly",
      "data": {
        "username": "postgres_user_abc123",
        "password": "temp_pass_xyz789",
        "database": "billing",
        "host": "postgres.dev.internal",
        "port": 5432,
        "lease_id": "550e8400-e29b-41d4-a5a0-c276e42c5ca",
        "expires_at": "2025-10-21T11:00:00Z"
      }
    }
  }
}
```

#### `secret:lease_renew`
Renew an existing dynamic credential lease.

```json
{
  "event": "secret:lease_renew",
  "ref": "req-003",
  "payload": {
    "lease_id": "550e8400-e29b-41d4-a5a0-c276e42c5ca"
  }
}
```

**Response:**
```json
{
  "event": "phx_reply",
  "ref": "req-003",
  "payload": {
    "status": "ok",
    "response": {
      "lease_id": "550e8400-e29b-41d4-a5a0-c276e42c5ca",
      "renewed": true
    }
  }
}
```

#### `agent:heartbeat`
Signal that the Agent runtime connection is alive.

```json
{
  "event": "agent:heartbeat",
  "ref": "req-004",
  "payload": {}
}
```

**Response:**
```json
{
  "event": "phx_reply",
  "ref": "req-004",
  "payload": {
    "status": "ok",
    "response": {
      "status": "alive",
      "timestamp": "2026-05-25T05:25:00Z"
    }
  }
}
```

### Error Responses

All error responses follow this structure:

```json
{
  "event": "phx_reply",
  "ref": "request-reference",
  "payload": {
    "status": "error",
    "error": {
      "code": "secret_not_found",
      "message": "Secret path does not exist or access denied",
      "details": {
        "secret_path": "dev.nonexistent.secret",
        "policy_applied": "webapp-secrets"
      }
    }
  }
}
```

## Error Codes

| Error Code | Description | Retry Action |
|------------|-------------|-------------|
| `secret_not_found` | Secret path doesn't exist or access denied | Check secret path and policies |
| `invalid_credentials` | Enrollment credentials failed | Check pending token or enrollment state |
| `mtls_required` | Runtime join did not have verified certificate identity | Connect through `AgentTrustedSocket` with Core-issued material |
| `lease_not_found` | Dynamic lease doesn't exist or expired | Request new credentials |
| `policy_denied` | Access denied by policy | Contact administrator |
| `rate_limited` | Too many requests | Implement exponential backoff |
| `internal_error` | Server internal error | Retry with backoff |
| `invalid_request` | Malformed request | Fix request format |
| `unauthorized` | Authentication required | Authenticate first |

## Security Considerations

### Authentication
- **mTLS Required**: All runtime connections must use mutual TLS on the trusted Agent endpoint
- **Certificate Validation**: Core validates the presented certificate against stored certificate records, status, type, expiry, SAN policy, and EKU
- **Two-Key Enrollment**: The SSH host key proves host identity only; the runtime TLS keypair is separate
- **Rate Limiting**: Implement per-agent rate limiting

### Secret Handling
- **Encryption in Transit**: All WebSocket communication uses TLS 1.3
- **Authorization**: All secret requests validated against policies
- **Audit Logging**: Every access logged with actor identity

### Connection Security
- **Origin Validation**: Verify WebSocket origin header
- **Rate Limiting**: Per-connection and per-agent rate limits
- **Heartbeat**: Regular health checks with timeout handling
- **Graceful Shutdown**: Clean connection closure on both sides

## Performance Considerations

### Message Size
- **Maximum**: 1MB per message (configurable)
- **Compression**: gzip for messages > 1KB
- **Binary Data**: Base64 encoded for JSON compatibility

### Connection Management
- **Heartbeat Interval**: 30 seconds (configurable)
- **Reconnection**: Exponential backoff: 1s, 2s, 4s, 8s, 16s, max 60s
- **Connection Pooling**: Core maintains connection limits per agent
- **Graceful Degradation**: Queue requests during temporary disconnections

## Implementation Notes

### Phoenix Channel Structure
```elixir
# Trusted runtime uses AgentTrustedSocket and a single runtime topic.
channel_topic = "agent:runtime"

# The TLS peer certificate supplies identity before channel join.
PhoenixClient.Channel.join(socket, channel_topic)

# Message handling pattern
def handle_info(%Message{event: event, payload: payload, ref: ref}, state) do
  case event do
    "secret:read" -> handle_secret_read(payload, ref, state)
    "secret:lease_renew" -> handle_lease_renew(payload, ref, state)
    "agent:heartbeat" -> handle_heartbeat(payload, ref, state)
    "secret:rotated" -> handle_secret_rotated(payload, state)
    # ... other events
  end
end
```

### Agent State Management
```elixir
# Connection owns the low-level Phoenix socket. RuntimeBootstrapper owns
# trusted material loading, enrollment, finalization, and startup mode.
defmodule SecretHub.Agent.Connection do
  use GenServer

  defstruct [
    :socket,           # Phoenix WebSocket socket
    :channel,          # Joined channel
    :agent_id,         # Certificate-derived Agent identifier
    :pending_requests, # Request ref -> GenServer.from()
    :connection_status,  # :disconnected | :connecting | :connected
    :last_heartbeat,   # Last heartbeat timestamp
    :reconnect_timer   # Reconnection timer reference
  ]
end
```

`SecretHub.Agent.IdentityStore` persists trusted material under `state_dir`.
`pending.json` is kept only until `RuntimeBootstrapper` receives the
`on_runtime_accepted` payload and finalizes enrollment.

## Testing

### Unit Tests
- Mock WebSocket connections
- Test message serialization/deserialization
- Verify error handling paths
- Test enrollment proof and trusted runtime flows

### Integration Tests
- Full Agent-Core communication
- Database integration
- Policy enforcement validation

### Load Testing
- 100+ concurrent agent connections
- Large secret payloads
- Connection churn and reconnection

## Future Extensions

### Version 1.1 (Planned)
- **Streaming**: Large secret delivery via streaming
- **Batch Operations**: Multiple secret requests in single message
- **Compression**: Additional compression algorithms
- **Metrics**: Per-operation timing and performance metrics

### Version 2.0 (Future)
- **Protocol Buffers**: Binary protocol for performance
- **Connection Pooling**: Advanced connection management
- **Offline Caching**: Agent-side cache with sync capabilities
