# PRD: SecretHub Agent Client API

**Date:** 2026-03-26
**Status:** Draft
**Design Spec:** [2026-03-25-agent-client-api-design.md](2026-03-25-agent-client-api-design.md)

## Problem Statement

Applications that need secrets from SecretHub must communicate with the local SecretHub Agent. Currently, the agent exposes a line-delimited JSON protocol over Unix Domain Sockets with limited capabilities: no streaming, no auto-renewal push, and certificate-only authentication. This forces applications to poll for secret changes and manually manage credential lifecycles, leading to:

- **Stale credentials** causing outages when dynamic secrets rotate without notification
- **Boilerplate code** in every application to handle polling, retry, and reconnect
- **High barrier to adoption** since every app needs a client certificate before it can read a single secret

## Goals

1. **Zero-config secret access** — applications connect to the local agent and get secrets with no setup beyond knowing the socket path
2. **Real-time secret delivery** — applications receive credential updates the moment they change, not on the next poll
3. **Multi-language support** — idiomatic client libraries for Elixir, Node.js, and Go
4. **Graceful degradation** — applications continue operating with cached values during agent downtime

## Non-Goals

- Client-side encryption or secret storage (the agent handles this)
- Direct Core-to-application communication (always mediated by the agent)
- Client libraries for languages other than Elixir, Node.js, Go in this phase
- Changes to the Agent-to-Core WebSocket protocol

## Users

| User | Need |
|------|------|
| **Application developers** | Fetch secrets at startup and receive rotation notifications without managing credential lifecycles |
| **Platform/DevOps engineers** | Deploy agents alongside apps with minimal per-app configuration |
| **Security teams** | Layered auth model that defaults to OS-level identity and supports certificate/token upgrade for stricter environments |

## Requirements

### P0 — Must Have

| ID | Requirement | Acceptance Criteria |
|----|-------------|---------------------|
| R1 | **Unix Domain Socket server** with length-prefixed JSON framing | Agent listens on configurable socket path; clients connect and exchange frames with 4-byte big-endian length prefix; max frame 1 MB |
| R2 | **Protocol versioning** | First client message includes `protocol_version`; agent echoes version; incompatible versions rejected with `INCOMPATIBLE_VERSION` error |
| R3 | **Peer credential authentication (default)** | Agent extracts UID/GID/PID via `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) on every connection using OTP 24+ `:socket` module; maps UID to app identity |
| R4 | **One-shot secret fetch** (`secrets.get`) | Client sends unary request with secret path; agent returns current value + version + metadata |
| R5 | **Secret watching** (`secrets.watch`) | Client subscribes to a secret path; receives immediate snapshot; receives push on every rotation/change; client can cancel |
| R6 | **Dynamic credential watching** (`secrets.watch_dynamic`) | Client subscribes to dynamic credential path; receives initial credentials with TTL; agent auto-renews and pushes new credentials before expiry |
| R7 | **Auto-reconnect with re-subscribe** | On disconnect, client reconnects with exponential backoff (1s..30s cap); re-authenticates; re-subscribes all active streams with `last_version`; `handle.current()` returns stale value during disconnect |
| R8 | **Elixir client library** | `SecretHub.Client` module with `connect/1`, `get/2`, `watch/2`, `watch_dynamic/2`, `cancel/2`; message-based notifications; no deps beyond stdlib + JSON; lives in umbrella as `secrethub_client` (not in release configs) |
| R9 | **Node.js client library** | `@secrethub/client` npm package; `connect()`, `get()`, `watch()`, `watchDynamic()`; EventEmitter-based handles with `.current()`; zero dependencies; TypeScript with CJS + ESM |
| R10 | **Go client library** | `github.com/gsmlg-dev/secrethub-go/client` module; `Connect()`, `Get()`, `Watch()`, `WatchDynamic()`; channel-based handles with `.Current()`; zero dependencies |
| R11 | **Keepalive mechanism** | Agent sends `{"type":"keepalive"}` every 30s on idle connections; client responds with `{"type":"keepalive_ack"}`; agent closes connection after 10s timeout |
| R12 | **Backpressure handling** | Agent queues up to 64 pending messages per connection; exceeding limit closes connection; client auto-reconnects |
| R13 | **Stream cancel semantics** | Client sends `stream_cancel`; may receive trailing `stream_data` before `stream_end`; client discards trailing data silently |

### P1 — Should Have

| ID | Requirement | Acceptance Criteria |
|----|-------------|---------------------|
| R14 | **Token-based authentication** | Client sends `auth.authenticate` with `{type: "token", token: "..."}` to upgrade identity; narrows permissions (cannot escalate beyond peer creds) |
| R15 | **Certificate-based authentication** | Client sends `auth.authenticate` with `{type: "certificate", cert_pem: "..."}` to upgrade identity; verified against Core CA |
| R16 | **Secret listing** (`secrets.list`) | Client sends prefix; agent returns list of accessible paths under that prefix |
| R17 | **Agent system info** (`sys.info`) | Returns agent version, uptime, Core connection status |
| R18 | **Isolated connections** | `connect(isolated: true)` creates a dedicated socket per client instance; prevents cross-stream interference for critical secrets |
| R19 | **Configurable default auth policy** | Agent config option to set default policy for unmapped UIDs: allow-all (dev) or deny-all (prod) |

### P2 — Nice to Have

| ID | Requirement | Acceptance Criteria |
|----|-------------|---------------------|
| R20 | **Connection metrics** | Agent exposes per-connection stats: active streams, messages sent/received, auth method |
| R21 | **Mock agent for testing** | Lightweight socket server that speaks the protocol; usable in client library test suites |
| R22 | **Configurable backpressure queue limit** | Agent config option to tune the 64-message queue limit per connection |

## Architecture

```
┌─────────────┐    Unix Socket     ┌──────────────┐    mTLS WebSocket    ┌──────────────┐
│  Application │◄─────────────────►│ SecretHub     │◄───────────────────►│ SecretHub     │
│  (Elixir/    │  Length-prefixed  │ Agent         │                     │ Core          │
│   Node/Go)   │  JSON protocol   │               │                     │               │
└─────────────┘                    └──────────────┘                      └──────────────┘
```

### Agent-Side Components (new/modified)

| Component | Type | Purpose |
|-----------|------|---------|
| `UDS.Supervisor` | Supervisor | Top-level supervisor for the UDS subsystem |
| `UDS.StreamRegistry` | GenServer + ETS | Maps `{conn_pid, stream_id}` to secret path; enables fan-out on rotation events |
| `UDS.AcceptorPool` | Task.Supervisor | Accept loop for incoming socket connections |
| `UDS.ConnectionSupervisor` | DynamicSupervisor | Manages per-connection handler processes |
| `UDS.ConnectionHandler` | GenServer | Per-connection: auth state, RPC dispatch, stream management, keepalive |
| `UDS.Framing` | Module | Encode/decode length-prefixed JSON frames |
| `UDS.PeerCredentials` | Module | Extract UID/GID/PID via `:socket` module (OS-specific) |
| `UDS.Auth` | Module | Unified auth: peer creds lookup, token validation, cert verification |

### Integration Points

- **Cache** receives `secret:rotated` from Core -> notifies StreamRegistry -> pushes to watching connections
- **LeaseRenewer** on renewal -> pushes updated credentials via StreamRegistry
- **ConnectionManager** unchanged (Core <-> Agent WebSocket)

### Client Library Structure

All three clients share the same wire protocol and message shapes. Each is independently packaged:

| Library | Location | Package |
|---------|----------|---------|
| Elixir | `apps/secrethub_client/` (umbrella, not in releases) | Hex: `secrethub_client` |
| Node.js | Separate repo `secrethub-js` | npm: `@secrethub/client` |
| Go | Separate repo `secrethub-go` | `github.com/gsmlg-dev/secrethub-go` |

## Wire Protocol Summary

- **Framing:** 4-byte big-endian length + JSON payload (max 1 MB)
- **Message types:** `unary_request`, `unary_response`, `stream_request`, `stream_data`, `stream_end`, `stream_cancel`, `keepalive`, `keepalive_ack`
- **Versioning:** `protocol_version` field on first message (v1 default)
- **Errors:** `NOT_FOUND`, `UNAUTHORIZED`, `FORBIDDEN`, `UNAVAILABLE`, `INTERNAL`, `INVALID_ARGUMENT`, `INCOMPATIBLE_VERSION`, `FRAME_TOO_LARGE`
- **Paths:** Slash-delimited, mirroring REST API (`secrets/db/postgres/prod`, `dynamic/db/postgres/creds`)

## Success Metrics

| Metric | Target |
|--------|--------|
| Secret fetch latency (cache hit) | < 1ms p99 |
| Secret rotation delivery latency | < 100ms from Core push to client notification |
| Client reconnect + re-subscribe time | < 5s after agent restart |
| Client library adoption | All new internal services use client library instead of direct socket code |

## Milestones

| Phase | Scope | Deliverables |
|-------|-------|-------------|
| **Phase 1: Agent protocol** | Rework UDS server, wire protocol, peer credential auth, unary RPCs | New UDS modules, `secrets.get`, `secrets.list`, `sys.ping`, `sys.info`, `auth.authenticate` (peer creds) |
| **Phase 2: Streaming** | Server-streaming RPCs, StreamRegistry, Cache/LeaseRenewer integration | `secrets.watch`, `secrets.watch_dynamic`, keepalive, backpressure |
| **Phase 3: Elixir client** | Elixir client library with full API | `secrethub_client` umbrella app, tests against mock agent |
| **Phase 4: Node.js + Go clients** | External client libraries | `@secrethub/client` npm package, `secrethub-go` module |
| **Phase 5: Auth upgrade** | Token and certificate authentication | `auth.authenticate` with token/cert, policy narrowing |

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| `SO_PEERCRED` not available on all platforms | Peer credential auth fails on unsupported OS | Fall back to mandatory token/cert auth; document supported platforms |
| OTP `:socket` module API instability | Breaking changes in future OTP versions | Pin minimum OTP version (24+); wrap in `UDS.PeerCredentials` abstraction |
| Stale cached values during long disconnects | Apps operate on expired credentials | `handle.current()` includes `stale: true` flag; apps can check and decide to halt |
| Three client libraries to maintain | Feature drift between languages | Shared protocol test suite (JSON fixtures); protocol version guarantees backward compat |

## Open Questions

1. Should `secrets.list` support pagination for large secret trees, or is a flat list sufficient for v1?
2. Should the agent support Unix socket file permissions (e.g., `0660` owned by a specific group) as an additional access control layer?
3. What is the maximum number of concurrent connections and active streams the agent should support before rejecting new connections?
