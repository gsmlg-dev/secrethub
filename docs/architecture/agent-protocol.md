# SecretHub Agent-Core Communication Protocol

**Version:** 1.0
**Status:** Draft
**Last Updated:** 2025-10-21

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

Each Agent connects via:
- mTLS WebSocket connection to Core
- Persistent connection with automatic reconnection
- Message-based request/response pattern
- Server push notifications for secret rotations
```

## Connection Establishment

### 1. WebSocket Handshake

```javascript
// Agent initiates connection
const socket = new WebSocket('wss://secrethub.example.com/agent/socket/websocket');

// Connection headers
{
  'x-agent-id': 'agent-prod-01',
  'x-agent-version': '1.0.0',
  'x-timestamp': new Date().toISOString()
}
```

### 2. Agent Authentication

After WebSocket connection, Agent must authenticate using one of:

#### Option A: AppRole Credentials (Recommended for production)
```json
{
  "event": "auth:approle",
  "ref": "auth-12345",
  "payload": {
    "role_id": "approle:webapp-prod",
    "secret_id": "8f7e4d2a-3b19-8f0e-e5a1d2efacec"
  }
}
```

#### Option B: Certificate-based (Recommended for automated deployments)
```json
{
  "event": "auth:certificate",
  "ref": "auth-12346",
  "payload": {
    "client_cert": "-----BEGIN CERTIFICATE-----\n...",
    "cert_fingerprint": "SHA256:F3A1...",
    "nonce": "random-string-123"
  }
}
```

### 3. Authentication Response

**Success Response:**
```json
{
  "event": "phx_reply",
  "ref": "auth-12345",
  "payload": {
    "status": "ok",
    "agent_id": "agent-prod-01",
    "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "session_expires_at": "2025-10-21T12:00:00Z",
    "connection_info": {
      "heartbeat_interval": 30000,
      "max_message_size": 1048576,
      "compression": "gzip"
    }
  }
}
```

**Error Response:**
```json
{
  "event": "phx_reply",
  "ref": "auth-12345",
  "payload": {
    "status": "error",
    "error": {
      "code": "invalid_credentials",
      "message": "RoleID not found or SecretID expired",
      "retry_after": 300
    }
  }
}
```

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

#### `connection:heartbeat`
Periodic heartbeat to maintain connection health.

```json
{
  "event": "connection:heartbeat",
  "payload": {
    "timestamp": "2025-10-21T10:00:00Z",
    "server_time": "2025-10-21T10:00:01Z"
  }
}
```

## Agent Message Types

### Secret Requests

#### `secrets:get_static`
Request a static secret value.

```json
{
  "event": "secrets:get_static",
  "ref": "req-001",
  "payload": {
    "secret_path": "dev.db.postgres.auth.password",
    "version": null,  // null for latest version
    "include_metadata": true
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
    "secret": {
      "path": "dev.db.postgres.auth.password",
      "version": 2,
      "value": "encrypted_pg_password_456",
      "created_at": "2025-10-20T14:30:00Z",
      "last_rotated_at": "2025-10-15T02:00:00Z",
      "metadata": {
        "description": "PostgreSQL auth database password"
      }
    }
  }
}
```

#### `secrets:get_dynamic`
Request temporary credentials for a dynamic secret role.

```json
{
  "event": "secrets:get_dynamic",
  "ref": "req-002",
  "payload": {
    "role_path": "dev.db.postgres.readonly",
    "ttl_seconds": 3600,
    "requested_capabilities": ["read", "connect"]
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
    "credentials": {
      "username": "postgres_user_abc123",
      "password": "temp_pass_xyz789",
      "database": "billing",
      "host": "postgres.dev.internal",
      "port": 5432,
      "lease_id": "550e8400-e29b-41d4-a5a0-c276e42c5ca",
      "expires_at": "2025-10-21T11:00:00Z",
      "capabilities": ["read", "connect"]
    }
  }
}
```

#### `lease:renew`
Renew an existing dynamic credential lease.

```json
{
  "event": "lease:renew",
  "ref": "req-003",
  "payload": {
    "lease_id": "550e8400-e29b-41d4-a5a0-c276e42c5ca",
    "extend_ttl_seconds": 1800
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
| `invalid_credentials` | Authentication failed | Check RoleID/SecretID or certificate |
| `lease_not_found` | Dynamic lease doesn't exist or expired | Request new credentials |
| `policy_denied` | Access denied by policy | Contact administrator |
| `rate_limited` | Too many requests | Implement exponential backoff |
| `internal_error` | Server internal error | Retry with backoff |
| `invalid_request` | Malformed request | Fix request format |
| `unauthorized` | Authentication required | Authenticate first |

## Security Considerations

### Authentication
- **mTLS Required**: All connections must use mutual TLS
- **Certificate Validation**: Core validates client certificates against known CAs
- **Session Management**: Sessions expire after configurable time (default 1 hour)
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
# Core implementation uses Phoenix channels
channel_topic = "agent:#{agent_id}"

# Channel joins after authentication
PhoenixClient.Channel.join(socket, channel_topic)

# Message handling pattern
def handle_info(%Message{event: event, payload: payload, ref: ref}, state) do
  case event do
    "secrets:get_static" -> handle_get_static(payload, ref, state)
    "secrets:get_dynamic" -> handle_get_dynamic(payload, ref, state)
    "secret:rotated" -> handle_secret_rotated(payload, state)
    # ... other events
  end
end
```

### Agent State Management
```elixir
# Agent maintains connection state
defmodule SecretHub.Agent.Connection do
  use GenServer

  defstruct [
    :socket,           # Phoenix WebSocket socket
    :channel,          # Joined channel
    :agent_id,         # Agent identifier
    :pending_requests, # Request ref -> GenServer.from()
    :connection_status,  # :disconnected | :connecting | :connected
    :last_heartbeat,   # Last heartbeat timestamp
    :reconnect_timer   # Reconnection timer reference
  ]
end
```

## Testing

### Unit Tests
- Mock WebSocket connections
- Test message serialization/deserialization
- Verify error handling paths
- Test authentication flows

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