# Agent Client API Design

**Date:** 2026-03-25
**Status:** Approved

## Overview

Design for the SecretHub Agent's client-facing API: how applications query secrets from the local agent over a Unix Domain Socket. Includes the wire protocol, RPC methods, authentication, client library APIs (Elixir, Node.js, Go), and agent-side architecture changes.

## Architecture Summary

```
┌─────────────┐    Unix Socket     ┌──────────────┐    mTLS WebSocket    ┌──────────────┐
│  Application │◄─────────────────►│ SecretHub     │◄───────────────────►│ SecretHub     │
│  (Elixir/    │  Length-prefixed  │ Agent         │                     │ Core          │
│   Node/Go)   │  JSON protocol   │               │                     │               │
└─────────────┘                    └──────────────┘                      └──────────────┘
```

Applications connect to the local agent via Unix Domain Socket using a gRPC-style protocol over length-prefixed JSON. The agent handles caching, lease renewal, and Core communication transparently.

## Wire Protocol

### Framing

4-byte big-endian length prefix followed by a JSON payload. Each frame is one message. **Maximum frame size: 1 MB** (1,048,576 bytes). Both sides must reject frames exceeding this limit and close the connection with error code `FRAME_TOO_LARGE`.

```
┌──────────────┬──────────────────────────┐
│ Length (4B)   │ JSON payload (N bytes)   │
│ big-endian    │ max 1 MB                 │
└──────────────┴──────────────────────────┘
```

### Protocol Version

The client's first message must include a `protocol_version` field. The agent echoes its supported version in the response.

```json
// Client's first message includes version:
{"type":"unary_request", "id":"1", "method":"auth.authenticate", "protocol_version":1, "payload":{...}}

// Agent response includes its version:
{"type":"unary_response", "id":"1", "protocol_version":1, "payload":{...}}
```

If the client omits `protocol_version`, the agent assumes v1. If versions are incompatible, the agent responds with error code `INCOMPATIBLE_VERSION` and closes the connection. The `protocol_version` field is only required on the first message of a connection.

### Message Types

Modeled after gRPC semantics:

| Type | Direction | Purpose |
|------|-----------|---------|
| `unary_request` | client -> agent | One-shot RPC (get, auth, ping) |
| `unary_response` | agent -> client | Reply to unary request |
| `stream_request` | client -> agent | Start server-streaming RPC (watch) |
| `stream_data` | agent -> client | Pushed value on a stream |
| `stream_end` | agent -> client | Stream terminated (revoked, error) |
| `stream_cancel` | client -> agent | Client cancels a stream |

### Message Envelope

```json
{
  "type": "unary_request",
  "id": "req-uuid",
  "method": "secrets.get",
  "payload": { "path": "secrets/db/postgres/prod" }
}
```

- `id` - correlates requests with responses, identifies streams for cancel/data/end
- `method` - the RPC name
- `payload` - method-specific data

### Error Shape

Present in any `unary_response` or `stream_end`:

```json
{
  "type": "unary_response",
  "id": "req-uuid",
  "error": { "code": "NOT_FOUND", "message": "secret not found" }
}
```

Error codes: `NOT_FOUND`, `UNAUTHORIZED`, `FORBIDDEN`, `UNAVAILABLE`, `INTERNAL`, `INVALID_ARGUMENT`, `INCOMPATIBLE_VERSION`, `FRAME_TOO_LARGE`

Successful responses use `payload` (no `error` field). Error responses use `error` (no `payload` field). The two are mutually exclusive.

## RPC Methods

### Unary RPCs (request -> single response)

| Method | Description |
|--------|-------------|
| `auth.authenticate` | Authenticate with optional token/cert. Omit payload to use peer credentials. |
| `secrets.get` | One-shot secret fetch. Returns current value + metadata. |
| `secrets.list` | List accessible secret paths under a prefix. Request: `{prefix: "secrets/db/"}`. Response: `{paths: ["secrets/db/postgres/prod", "secrets/db/redis/prod"]}`. |
| `sys.ping` | Health check. Returns `{status: "ok"}`. |
| `sys.info` | Agent version, uptime, connection status to Core. |

### Server-Streaming RPCs (request -> stream of pushes)

| Method | Description |
|--------|-------------|
| `secrets.watch` | Subscribe to a secret path. Sends immediate snapshot, then pushes on every change (rotation/renewal). |
| `secrets.watch_dynamic` | Subscribe to dynamic credentials. Sends initial creds, auto-renews, pushes new creds before expiry. |

### Examples

```json
// One-shot get
-> {"type":"unary_request", "id":"1", "method":"secrets.get", "payload":{"path":"secrets/db/postgres/prod"}}
<- {"type":"unary_response", "id":"1", "payload":{"path":"secrets/db/postgres/prod", "value":"s3cret", "version":3, "metadata":{"created_at":"..."}}}

// Watch dynamic credentials
-> {"type":"stream_request", "id":"2", "method":"secrets.watch_dynamic", "payload":{"path":"dynamic/db/postgres/creds"}}
<- {"type":"stream_data", "id":"2", "payload":{"path":"dynamic/db/postgres/creds", "username":"tmp_abc", "password":"xyz", "lease_id":"lease-1", "ttl":3600, "expires_at":"..."}}
   ... (agent auto-renews, pushes new creds before expiry) ...
<- {"type":"stream_data", "id":"2", "payload":{"username":"tmp_def", "password":"uvw", "lease_id":"lease-2", "ttl":3600, "expires_at":"..."}}

// Cancel watch
-> {"type":"stream_cancel", "id":"2"}
<- {"type":"stream_end", "id":"2", "payload":{"reason":"cancelled"}}
```

### Stream Semantics

**Cancel race condition:** After sending `stream_cancel`, the client must be prepared to receive zero or more `stream_data` frames before the `stream_end` arrives. Clients should silently discard `stream_data` for cancelled streams.

**Backpressure:** If the agent cannot write to a client's socket (buffer full), it queues up to 64 pending messages per connection. If the queue exceeds this limit, the agent closes the connection. The client will auto-reconnect and re-subscribe.

**Agent-initiated keepalive:** The agent sends a `sys.ping` push every 30 seconds on idle connections. If the client does not respond within 10 seconds, the agent closes the connection. This detects silently dead connections (e.g., agent killed without FIN).

### Secret Path Convention

Slash-delimited paths mirroring the REST API:
- `secrets/db/postgres/prod` - static secret
- `dynamic/db/postgres/creds` - dynamic credentials

## Authentication

### Default: Unix Peer Credentials (zero config)

On connect, the agent reads `SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` (macOS) from the socket to get the client's UID/GID/PID. The agent maps UID to an allowed app via its local config or Core policy. No explicit auth message needed.

**Implementation note:** The existing `uds_server.ex` uses `:gen_tcp` which does not expose peer credentials. The new UDS server must use the OTP 24+ `:socket` module (`socket:open/3` + `socket:getopt/2` with `{socket, peercred}`) which provides native access to `SO_PEERCRED`/`LOCAL_PEERCRED`.

### Optional: Explicit Auth

Client sends `auth.authenticate` as the first message to upgrade identity:

```json
// Token auth
-> {"type":"unary_request", "id":"1", "method":"auth.authenticate", "protocol_version":1, "payload":{"type":"token", "token":"app-token-abc"}}
<- {"type":"unary_response", "id":"1", "protocol_version":1, "payload":{"app_id":"my-app", "auth_method":"token", "permissions":[...]}}

// Certificate auth
-> {"type":"unary_request", "id":"1", "method":"auth.authenticate", "protocol_version":1, "payload":{"type":"certificate", "cert_pem":"-----BEGIN CERT..."}}
<- {"type":"unary_response", "id":"1", "protocol_version":1, "payload":{"app_id":"my-app", "auth_method":"certificate", "permissions":[...]}}
```

### Rules

- Peer credentials are always extracted, even when explicit auth is used
- Explicit auth *narrows* permissions (cannot escalate beyond what peer creds allow)
- If no explicit auth and UID is unmapped, agent falls back to a `default` policy (configurable: allow-all in dev, deny-all in prod)
- Auth state is per-connection. Reconnect requires re-auth (peer creds automatic, token/cert must be resent)

## Client Library APIs

### Elixir

```elixir
# Connect (peer creds auto-auth)
{:ok, client} = SecretHub.Client.connect(socket: "/var/run/secrethub/agent.sock")

# Optional explicit auth
{:ok, client} = SecretHub.Client.connect(socket: "...", auth: {:token, "app-token-abc"})

# One-shot get
{:ok, %{value: "s3cret", version: 3}} = SecretHub.Client.get(client, "secrets/db/postgres/prod")

# Watch static secret - sends messages to calling process
{:ok, watch_ref} = SecretHub.Client.watch(client, "secrets/db/postgres/prod")
# Receives: {:secret_changed, ^watch_ref, %{value: "new_value", version: 4}}

# Watch dynamic credentials - auto-renewing handle
{:ok, watch_ref} = SecretHub.Client.watch_dynamic(client, "dynamic/db/postgres/creds")
# Receives: {:credentials_updated, ^watch_ref, %{username: "tmp_abc", password: "xyz", expires_at: ~U[...]}}

# Cancel watch
:ok = SecretHub.Client.cancel(client, watch_ref)

# Lifecycle notifications — sent as messages to the caller (same pattern as watch)
# Configure via connect options:
{:ok, client} = SecretHub.Client.connect(socket: "...", notify: self())
# Receives: {:secrethub_disconnected, client, reason}
# Receives: {:secrethub_reconnected, client}
```

### Node.js (TypeScript)

```typescript
import { SecretHubClient } from '@secrethub/client';

// Connect
const client = await SecretHubClient.connect({ socket: '/var/run/secrethub/agent.sock' });
// With auth: SecretHubClient.connect({ socket: '...', auth: { type: 'token', token: '...' } })

// One-shot get
const secret = await client.get('secrets/db/postgres/prod');
// { value: 's3cret', version: 3 }

// Watch - returns EventEmitter-like handle
const handle = client.watch('secrets/db/postgres/prod');
handle.on('change', (data) => { /* { value, version } */ });
handle.on('error', (err) => { /* stream error */ });

// Watch dynamic - auto-renewing
const creds = client.watchDynamic('dynamic/db/postgres/creds');
creds.on('change', (data) => { /* { username, password, expiresAt } */ });
creds.current(); // synchronous access to latest value

// Cancel
handle.cancel();

// Lifecycle
client.on('disconnect', (reason) => { });
client.on('reconnect', () => { });
```

### Go

```go
import "github.com/gsmlg-dev/secrethub-go/client"

// Connect
c, err := client.Connect(client.Options{Socket: "/var/run/secrethub/agent.sock"})
// With auth: client.Options{Socket: "...", Auth: client.TokenAuth("...")}

// One-shot get
secret, err := c.Get(ctx, "secrets/db/postgres/prod")
// secret.Value, secret.Version

// Watch - returns a channel
handle, err := c.Watch(ctx, "secrets/db/postgres/prod")
for event := range handle.Changes() {
    // event.Value, event.Version
}

// Watch dynamic - auto-renewing, channel-based
creds, err := c.WatchDynamic(ctx, "dynamic/db/postgres/creds")
for event := range creds.Changes() {
    // event.Username, event.Password, event.ExpiresAt
}
creds.Current() // thread-safe access to latest value

// Cancel
handle.Cancel()

// Lifecycle
c.OnDisconnect(func(reason error) { })
c.OnReconnect(func() { })
```

### Common Patterns

- `connect()` - establishes connection, auto-auth via peer creds
- `get(path)` - unary RPC, returns single value
- `watch(path)` - server-streaming, immediate snapshot then pushes on change
- `watchDynamic(path)` - same but for dynamic creds with auto-renewal
- `.current()` - synchronous access to latest cached value on a handle
- `cancel()` - sends `stream_cancel`, cleans up
- Auto-reconnect with re-subscribe on all active handles
- Isolated connection option: `connect(socket: "...", isolated: true)` for critical secrets

## Connection Lifecycle & Reconnect

### State Machine

```
DISCONNECTED -> CONNECTING -> AUTHENTICATING -> READY -> DISCONNECTED
                                                 ^            |
                                                 └────────────┘
                                               (auto-reconnect)
```

### On Connect

1. Client opens Unix socket
2. Agent extracts peer credentials (`SO_PEERCRED`)
3. If explicit auth configured, client sends `auth.authenticate`
4. Connection enters `READY` state

### On Disconnect (agent restart, crash, etc.)

1. Client fires `on_disconnect` callback (if registered)
2. Client enters reconnect loop with exponential backoff (1s, 2s, 4s... cap 30s)
3. On successful reconnect:
   - Re-authenticates (peer creds automatic, token/cert resent if configured)
   - Re-subscribes all active watch/watch_dynamic streams, including the `last_version` seen so the agent can detect if the client missed updates
   - Agent sends fresh snapshot for each re-subscribed stream
   - If a dynamic credential's lease expired during disconnect, agent attempts to generate new credentials; if it cannot, it sends `stream_end` with error code `UNAVAILABLE`
   - Client fires `on_reconnect` callback
4. During disconnect, `handle.current()` returns last known value (stale but usable)

### Isolated Connections

```elixir
# Default: multiplexed (all watches share one connection)
{:ok, client} = SecretHub.Client.connect(socket: "/var/run/secrethub/agent.sock")

# Isolated: dedicated connection for a critical secret
{:ok, client} = SecretHub.Client.connect(socket: "/var/run/secrethub/agent.sock", isolated: true)
```

By default, a single `connect()` call creates one socket connection and all `watch`/`watchDynamic` calls from that client are multiplexed over it. With `isolated: true`, each `connect()` still creates one connection, but the intent is that you create a separate client per critical secret so that one stream's error or slow processing cannot affect others.

## Agent-Side Architecture Changes

### UDS Server Rework

The current `uds_server.ex` needs to be reworked:
- Replace line-delimited JSON with length-prefixed JSON framing
- Add `SO_PEERCRED` extraction on accept
- Track per-connection state: auth identity, active streams, subscriptions
- Each accepted connection spawns a handler process under a `DynamicSupervisor`

### New Modules

| Module | Purpose |
|--------|---------|
| `UDS.Framing` | Encode/decode length-prefixed JSON frames |
| `UDS.ConnectionHandler` | Per-connection GenServer: auth state, dispatch RPCs, manage streams |
| `UDS.StreamRegistry` | ETS-backed registry mapping `{conn_pid, stream_id}` to secret path. Used by Cache to push rotation events to the right connections. |
| `UDS.PeerCredentials` | Extract UID/GID/PID from socket (Linux `SO_PEERCRED`, macOS `LOCAL_PEERCRED`) |
| `UDS.Auth` | Unified auth: peer creds to identity, optional token/cert upgrade, policy lookup |

### Integration with Existing Modules

- **Cache** - when a `secret:rotated` event arrives from Core, Cache notifies StreamRegistry, which pushes `stream_data` to all watching connections
- **LeaseRenewer** - on renewal, pushes updated credentials to watching connections via StreamRegistry
- **ConnectionManager** - no changes, still handles Core <-> Agent WebSocket

### Supervision Tree Addition

```
UDS.Supervisor (one_for_one)
├── UDS.StreamRegistry (named ETS owner)
├── UDS.AcceptorPool (Task.Supervisor for accept loop)
└── UDS.ConnectionSupervisor (DynamicSupervisor for handler processes)
```

## Client Library Structure & Packaging

### Elixir Client

Lives in this repo as an umbrella app, published to Hex:

```
apps/secrethub_client/
├── lib/
│   ├── secrethub_client.ex              # Public API (connect, get, watch, etc.)
│   ├── secrethub_client/
│   │   ├── connection.ex                # Socket connection GenServer
│   │   ├── framing.ex                   # Length-prefixed JSON encode/decode
│   │   ├── stream.ex                    # Stream handle (ref tracking, current value)
│   │   ├── reconnect.ex                 # Backoff + re-subscribe logic
│   │   └── auth.ex                      # Auth payload builder (peer/token/cert)
├── mix.exs
└── test/
```

No runtime dependencies beyond stdlib + JSON. Uses `:socket` for Unix domain socket + peer credentials.

**Note:** `secrethub_client` is not included in the `secrethub_core` or `secrethub_agent` release configurations. It is a standalone library for external consumers only.

### Node.js Client

Separate repo `secrethub-js`, published as `@secrethub/client` on npm:

```
src/
├── index.ts                  # Public API
├── connection.ts             # Socket + framing
├── stream.ts                 # EventEmitter-based handle
├── reconnect.ts              # Backoff logic
└── auth.ts                   # Auth builders
```

Zero dependencies. Uses Node `net.createConnection` for Unix sockets. TypeScript with CommonJS + ESM dual output.

### Go Client

Separate repo `secrethub-go`, module `github.com/gsmlg-dev/secrethub-go`:

```
client/
├── client.go                 # Public API
├── connection.go             # Socket + framing
├── stream.go                 # Channel-based handle
├── reconnect.go              # Backoff logic
├── auth.go                   # Auth builders
└── peercred_linux.go         # SO_PEERCRED (build-tagged, agent-side only)
    peercred_darwin.go        # LOCAL_PEERCRED (build-tagged, agent-side only)
```

Zero dependencies. Uses `net.Dial("unix", path)`. Build tags for OS-specific peer credential extraction.

### Common Properties

- Same wire protocol, same framing, same message shapes
- Each client is independently testable against a mock agent
- Versioned alongside the agent protocol version (v1)
