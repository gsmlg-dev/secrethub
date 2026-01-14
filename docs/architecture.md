# SecretHub Architecture

This document provides a comprehensive overview of SecretHub's architecture, design decisions, and component interactions.

---

## Table of Contents

1. [Overview](#overview)
2. [Core Components](#core-components)
3. [Communication Patterns](#communication-patterns)
4. [Security Model](#security-model)
5. [Data Flow](#data-flow)
6. [High Availability](#high-availability)
7. [Performance Characteristics](#performance-characteristics)
8. [Technology Stack](#technology-stack)

---

## Overview

SecretHub is a two-tier, machine-to-machine secrets management system designed for enterprise environments. It provides centralized secrets storage with distributed delivery via local agents.

### Design Principles

1. **Security First** - mTLS everywhere, encryption at rest, comprehensive audit logging
2. **High Availability** - Active-active multi-node deployment, automatic failover
3. **Performance** - Sub-100ms latency, support for 10,000+ req/min
4. **Resilience** - Local agent caching, graceful degradation
5. **Simplicity** - Clear architecture, minimal dependencies

### Key Features

- **Static & Dynamic Secrets** - Long-lived and temporary credentials
- **Automatic Rotation** - Zero-downtime secret updates
- **Policy-Based Access Control** - Fine-grained authorization
- **PKI Engine** - Internal certificate authority
- **Audit Logging** - Tamper-evident logs with hash chains
- **Template Rendering** - Inject secrets into configuration files

---

## Core Components

### 1. SecretHub Core

**Responsibility:** Central control plane for secrets management

**Components:**
```
SecretHub Core
├── Web UI (Phoenix LiveView)
├── REST API (Phoenix Controllers)
├── WebSocket Server (Phoenix Channels)
├── Policy Engine
├── Secret Engines
│   ├── Static Secrets
│   ├── Dynamic PostgreSQL
│   ├── Dynamic Redis
│   └── Dynamic AWS
├── PKI Engine
├── Audit Logging
├── Vault (Seal/Unseal)
└── Lease Manager
```

**Technology:**
- Elixir 1.18 + OTP 28
- Phoenix Framework 1.7
- PostgreSQL 16 (primary datastore)
- Bandit (HTTP/2 + WebSocket server)

**Responsibilities:**
- Secret storage and retrieval
- Policy evaluation
- Authentication (AppRole)
- Certificate issuance
- Audit log collection
- Lease management for dynamic secrets

### 2. SecretHub Agent

**Responsibility:** Local daemon for secure secret delivery

**Components:**
```
SecretHub Agent
├── Bootstrap Module (Initial authentication)
├── Connection Manager (Persistent WebSocket)
├── Cache Manager (Local secret caching)
├── Template Engine (Secret rendering)
├── Sinker (Atomic file writes)
└── Unix Domain Socket Server (mTLS)
```

**Technology:**
- Elixir 1.18 + OTP 28
- WebSocket client
- ETS for local caching
- File system monitoring

**Responsibilities:**
- Maintain persistent connection to Core
- Cache secrets locally for resilience
- Render templates with secret injection
- Serve secrets to local applications via UDS
- Trigger application reloads on secret updates

### 3. Database (PostgreSQL)

**Purpose:** Primary datastore for all persistent data

**Schemas:**
- `public` - Main schema (secrets, policies, certificates, etc.)
- `audit` - Separate schema for audit logs (tamper-evident)

**Key Tables:**
- `secrets` - Encrypted secret data
- `secret_versions` - Version history
- `policies` - Access control policies
- `approle_tokens` - AppRole authentication tokens
- `certificates` - Issued certificates
- `leases` - Dynamic secret leases
- `audit.events` - Audit log entries

**Extensions:**
- `uuid-ossp` - UUID generation
- `pgcrypto` - Cryptographic functions

### 4. Cache Layer

**Purpose:** High-performance in-memory caching

**Implementation:**
- ETS tables for policy evaluation results
- ETS tables for secret metadata (not encrypted values)
- ETS tables for query results
- TTL-based expiration (5 minutes default)
- LRU eviction (10,000 entries max)

---

## Communication Patterns

### Core ↔ Agent Communication

**Protocol:** mTLS WebSocket (persistent connection)

```
┌──────────────┐                    ┌──────────────┐
│              │                    │              │
│  Agent       │◄────────mTLS──────►│  Core        │
│              │    WebSocket       │              │
└──────────────┘                    └──────────────┘
      │                                    │
      │  1. Bootstrap (RoleID/SecretID)    │
      │───────────────────────────────────►│
      │                                    │
      │  2. Client Certificate             │
      │◄───────────────────────────────────│
      │                                    │
      │  3. Persistent WS Connection       │
      │◄──────────────────────────────────►│
      │                                    │
      │  4. Heartbeat (every 30s)          │
      │◄──────────────────────────────────►│
      │                                    │
      │  5. Secret Request                 │
      │───────────────────────────────────►│
      │                                    │
      │  6. Secret Response (encrypted)    │
      │◄───────────────────────────────────│
      │                                    │
      │  7. Secret Update Notification     │
      │◄───────────────────────────────────│
```

**Features:**
- Automatic reconnection with exponential backoff
- Heartbeat every 30 seconds
- Bi-directional messaging
- Certificate-based authentication post-bootstrap

### Agent ↔ Application Communication

**Protocol:** Unix Domain Socket with mTLS

```
┌──────────────┐                    ┌──────────────┐
│              │                    │              │
│ Application  │◄────────mTLS──────►│  Agent       │
│              │  Unix Socket       │   (local)    │
└──────────────┘                    └──────────────┘
      │                                    │
      │  1. Connect with Client Cert       │
      │───────────────────────────────────►│
      │                                    │
      │  2. Verify Certificate             │
      │◄───────────────────────────────────│
      │                                    │
      │  3. Request Secret                 │
      │───────────────────────────────────►│
      │                                    │
      │  4. Return from Cache/Fetch        │
      │◄───────────────────────────────────│
```

**Security:**
- mTLS authentication (application certificate required)
- Local-only communication (no network exposure)
- Policy enforcement at agent level

---

## Security Model

### Layers of Security

```
┌────────────────────────────────────────────┐
│  Layer 1: Network Security (mTLS)          │
│  - Certificate-based authentication        │
│  - Encrypted communication                 │
└────────────────────────────────────────────┘
            ↓
┌────────────────────────────────────────────┐
│  Layer 2: Authentication                   │
│  - AppRole (RoleID/SecretID)              │
│  - Admin session authentication            │
└────────────────────────────────────────────┘
            ↓
┌────────────────────────────────────────────┐
│  Layer 3: Authorization (Policy Engine)    │
│  - Path-based access control               │
│  - Time-of-day restrictions                │
│  - IP-based restrictions                   │
│  - TTL limits                              │
└────────────────────────────────────────────┘
            ↓
┌────────────────────────────────────────────┐
│  Layer 4: Encryption at Rest               │
│  - AES-256-GCM for secrets                 │
│  - Master key encryption                   │
│  - Shamir secret sharing for unseal keys   │
└────────────────────────────────────────────┘
            ↓
┌────────────────────────────────────────────┐
│  Layer 5: Audit Logging                    │
│  - All operations logged                   │
│  - Hash chain for tamper evidence          │
│  - Separate audit schema                   │
└────────────────────────────────────────────┘
```

### Encryption

**Secrets Encryption:**
- Algorithm: AES-256-GCM
- Key derivation: PBKDF2 with 100,000 iterations
- Unique IV per secret
- Encrypted data stored in database

**Vault Unsealing:**
- Master key split using Shamir Secret Sharing
- Default: 5 key shares, 3 required to unseal
- Unseal keys never stored (given to operators at init)
- Auto-unseal option using AWS KMS (production)

**Session Security:**
- HTTPOnly cookies (XSS protection)
- Secure flag in production (HTTPS only)
- SameSite attribute (CSRF protection)
- 30-minute session timeout
- Session regeneration on login

### Authentication

**AppRole (for Agents & Applications):**
1. Bootstrap with RoleID + SecretID
2. Receive short-lived token
3. Use token for API requests
4. Token automatically renewed

**Admin (for Web UI):**
1. Username/password login
2. Session-based authentication
3. Bcrypt password hashing
4. Session timeout after 30 minutes

### Authorization (Policy Engine)

**Policy Structure:**
```elixir
%Policy{
  name: "production-read",
  rules: [
    %{
      path: "prod/*",
      capabilities: ["read"],
      effect: "allow",
      conditions: %{
        time_of_day: {9, 17},      # Business hours only
        days_of_week: [1,2,3,4,5],  # Weekdays only
        source_ip: "10.0.0.0/8",    # Internal network only
        ttl_max: 3600               # Max 1-hour token TTL
      }
    }
  ]
}
```

**Evaluation:**
1. Check path match (glob patterns)
2. Check capabilities (read, write, delete)
3. Check conditions (time, IP, TTL)
4. Default deny if no explicit allow
5. Result cached for 5 minutes

---

## Data Flow

### Secret Read Flow

```
┌──────────┐  1. Request     ┌──────────┐
│          │ ───────────────►│          │
│  Client  │                 │  Agent   │
│          │  7. Secret      │          │
│          │◄─────────────── │          │
└──────────┘                 └──────────┘
                               │  │  ▲
                          2.   │  │  │  6.
                        Check  │  │  │ Store
                         Cache │  │  │ Cache
                               ▼  │  │
                             ┌────────┐
                             │ Local  │
                             │ Cache  │
                             └────────┘
                                │  ▲
                           3.   │  │  5.
                         Miss   │  │ Response
                                ▼  │
                           ┌──────────┐
                           │          │
                       4.  │   Core   │
                   Request │          │
                           └──────────┘
                                │
                                │
                           ┌────▼─────┐
                           │ Database │
                           │ (secrets)│
                           └──────────┘
```

### Secret Write Flow

```
┌──────────┐  1. Write   ┌──────────┐
│          │ ───────────►│          │
│  Admin   │             │   Core   │
│          │  5. OK      │          │
│          │◄────────────│          │
└──────────┘             └──────────┘
                              │
                         2.   │
                       Encrypt│
                              ▼
                         ┌──────────┐
                         │ Database │
                    3.   │ (secrets)│
                   Store │          │
                         └──────────┘
                              │
                         4.   │
                       Notify │
                              ▼
                         ┌──────────┐
                         │  Agents  │
                         │(WebSocket│
                         │  push)   │
                         └──────────┘
```

### Dynamic Secret Generation

```
┌──────────┐  1. Request  ┌──────────┐
│          │ ────────────►│          │
│  Agent   │              │   Core   │
│          │  6. Creds    │          │
│          │◄─────────────│          │
└──────────┘              └──────────┘
                               │
                          2.   │
                        Policy │
                         Check │
                               ▼
                          ┌──────────┐
                          │  Policy  │
                          │  Engine  │
                          └──────────┘
                               │
                          3.   │
                       Generate│
                               ▼
                          ┌──────────┐
                          │ Dynamic  │
                     4.   │  Secret  │
                    Store │  Engine  │
                    Lease │          │
                          └──────────┘
                               │
                          5.   │
                        Create │
                         User  │
                               ▼
                          ┌──────────┐
                          │PostgreSQL│
                          │  (target)│
                          └──────────┘
```

---

## High Availability

### Active-Active Cluster

```
                    ┌──────────────┐
                    │Load Balancer │
                    │  (ALB/NLB)   │
                    └───────┬──────┘
                            │
           ┌────────────────┼────────────────┐
           │                │                │
      ┌────▼────┐      ┌────▼────┐     ┌────▼────┐
      │ Core-1  │      │ Core-2  │     │ Core-3  │
      │ Active  │      │ Active  │     │ Active  │
      └────┬────┘      └────┬────┘     └────┬────┘
           │                │                │
           └────────────────┼────────────────┘
                            │
                    ┌───────▼──────┐
                    │  PostgreSQL  │
                    │  Multi-AZ    │
                    │  (Primary +  │
                    │   Standby)   │
                    └──────────────┘
```

**Features:**
- All nodes actively serving requests
- Load balanced WebSocket connections
- Agent automatic failover on node failure
- Shared PostgreSQL database (RDS Multi-AZ)
- No single point of failure

**Configuration:**
- 3+ Core nodes (recommended)
- Load balancer with health checks
- PostgreSQL Multi-AZ (auto-failover)
- Shared Redis for distributed caching (optional)

### Agent Failover

```
Time: T0              Time: T1
Agent connected      Core-1 fails
to Core-1           Agent detects

   Agent                Agent
     │                    │
     │                    X  (connection lost)
     ▼                    │
  Core-1                Core-1
  (Active)              (Dead)


Time: T2             Time: T3
Agent reconnects     Connection
to Core-2           established

   Agent                Agent
     │                    │
     │reconnect           │established
     ▼                    ▼
  Core-2               Core-2
  (Active)             (Active)
```

**Reconnection Logic:**
- Detect connection loss immediately
- Wait 1 second (initial backoff)
- Try next Core node in list
- Exponential backoff (1s, 2s, 4s, 8s, max 60s)
- Retry indefinitely until connection established
- Use local cache during disconnection

---

## Performance Characteristics

### Throughput

| Metric | Single Node | 3-Node Cluster |
|--------|-------------|----------------|
| **API Requests** | 10,000 req/min | 30,000 req/min |
| **Concurrent Agents** | 5,000 | 15,000 |
| **WebSocket Messages** | 50,000 msg/min | 150,000 msg/min |

### Latency

| Operation | P50 | P95 | P99 |
|-----------|-----|-----|-----|
| **Secret Read (cached)** | 2ms | 5ms | 10ms |
| **Secret Read (DB)** | 15ms | 45ms | 80ms |
| **Policy Evaluation (cached)** | 1ms | 3ms | 5ms |
| **Policy Evaluation (fresh)** | 10ms | 30ms | 50ms |
| **WebSocket Message** | 5ms | 15ms | 30ms |
| **Dynamic Secret Generation** | 100ms | 200ms | 350ms |

### Resource Usage (per 1,000 agents)

| Resource | Usage |
|----------|-------|
| **CPU** | 2-4 cores |
| **Memory** | 4-6 GB |
| **Database Connections** | 20-30 |
| **Network** | 50 Mbps |
| **Disk** | 10 GB (logs + database) |

---

## Technology Stack

### Backend
- **Language:** Elixir 1.18
- **Runtime:** Erlang/OTP 28
- **Web Framework:** Phoenix 1.7
- **HTTP Server:** Bandit (HTTP/2 + WebSocket)
- **Database:** PostgreSQL 16
- **Cache:** ETS (in-memory), Redis (optional for multi-node)
- **Job Queue:** Oban

### Frontend
- **UI Framework:** Phoenix LiveView
- **CSS:** Tailwind CSS 4.1
- **JavaScript:** Bun (bundler)
- **Icons:** Heroicons

### Security
- **Encryption:** AES-256-GCM
- **Key Derivation:** PBKDF2
- **Password Hashing:** Bcrypt
- **TLS:** mTLS with X.509 certificates
- **Secret Sharing:** Shamir Secret Sharing

### Operations
- **Metrics:** Telemetry + Prometheus
- **Monitoring:** Grafana
- **Logging:** Elixir Logger
- **Deployment:** Docker, Kubernetes (Helm)

---

## Design Decisions

### Why Elixir/OTP?

1. **Concurrency** - BEAM VM handles 100k+ concurrent connections efficiently
2. **Fault Tolerance** - OTP supervision trees provide resilience
3. **Hot Code Upgrades** - Deploy without downtime
4. **Distributed** - Built-in clustering and distribution
5. **Performance** - Low latency, high throughput

### Why PostgreSQL?

1. **Reliability** - Battle-tested, ACID compliant
2. **JSON Support** - Native JSONB for flexible schema
3. **Performance** - Excellent query performance with proper indexes
4. **Extensions** - `uuid-ossp`, `pgcrypto` for security features
5. **Ecosystem** - Well-supported, many hosting options

### Why WebSocket for Agent Communication?

1. **Persistent Connection** - Eliminates connection overhead
2. **Bi-directional** - Core can push updates to agents
3. **Low Latency** - Real-time secret updates
4. **Efficient** - Minimal protocol overhead
5. **Standard** - Well-supported across languages/platforms

### Why Local Caching in Agent?

1. **Resilience** - Applications continue working if Core is down
2. **Performance** - Sub-millisecond local lookups
3. **Reduced Load** - Fewer requests to Core
4. **Network Efficiency** - Minimize bandwidth usage
5. **Graceful Degradation** - System remains functional during outages

---

## Future Architecture Considerations

### Potential Enhancements

1. **Multi-Region Replication**
   - PostgreSQL logical replication
   - Region-aware routing
   - Eventually consistent model

2. **Distributed Caching**
   - Redis cluster for cross-node cache
   - Cache invalidation coordination
   - Reduced database load

3. **Secrets Replication**
   - Replicate frequently accessed secrets to edge
   - CDN-like distribution
   - Lower latency for global deployments

4. **Advanced Monitoring**
   - Distributed tracing (OpenTelemetry)
   - ML-based anomaly detection
   - Predictive alerts

---

## Related Documentation

- [Deployment Guide](./deployment/README.md) - Production deployment
- [Security Model](./security-model.md) - Detailed security architecture
- [Performance Tuning](./best-practices/performance.md) - Optimization guide
- [High Availability](./ha-architecture.md) - HA deployment details

---

**Last Updated:** 2025-11-03
