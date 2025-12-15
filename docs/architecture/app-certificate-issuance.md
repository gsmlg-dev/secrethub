# Application Certificate Issuance Design

## Overview

This document describes the design for issuing certificates to applications that need to authenticate with SecretHub Agents. Applications use these certificates to establish mTLS connections via Unix Domain Sockets (UDS) to retrieve secrets.

## Goals

1. **Secure Application Identity**: Each application gets a unique certificate for authentication
2. **Certificate Lifecycle Management**: Issue, renew, and revoke app certificates
3. **Policy-Based Access**: Bind applications to policies for fine-grained secret access
4. **Ease of Integration**: Simple flow for applications to obtain certificates
5. **Audit Trail**: Complete visibility into application certificate operations

## Certificate Types Comparison

| Aspect | Agent Certificate | Application Certificate |
|--------|-------------------|-------------------------|
| **Purpose** | Agent authenticates to Core | Application authenticates to Agent |
| **Connection Type** | WebSocket (TCP) | Unix Domain Socket (local) |
| **Certificate Type** | `agent_client` | `app_client` |
| **Issued By** | Core PKI (via AgentChannel) | Core PKI (via REST API) |
| **Common Name Format** | `agent-{agent_id}` | `app-{app_name}` |
| **TTL** | 90 days (renewable) | 30 days (renewable) |
| **Revocation** | Via Core Admin API | Via Core Admin API |
| **SAN (Subject Alt Name)** | Agent UUID | Application name |
| **Key Usage** | Digital Signature, Key Encipherment | Digital Signature, Key Encipherment |
| **Extended Key Usage** | Client Authentication | Client Authentication |

## Application Certificate Request Flow

### 1. Application Registration (One-Time Setup)

```
┌─────────────┐                    ┌─────────────┐
│   Admin     │                    │    Core     │
│   (Human)   │                    │     API     │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │  1. Register App                │
       │  POST /v1/apps                  │
       ├─────────────────────────────────>│
       │  {                               │
       │    "name": "payment-service",    │
       │    "description": "...",         │
       │    "agent_id": "uuid",           │
       │    "policies": ["read-db-creds"] │
       │  }                               │
       │                                  │
       │  2. App Registered               │
       │  Returns: app_id, app_token      │
       │<─────────────────────────────────┤
       │                                  │
```

**Response:**
```json
{
  "app_id": "550e8400-e29b-41d4-a716-446655440000",
  "app_token": "hvs.CAESIJ...",  // One-time bootstrap token
  "agent_id": "agent-uuid",
  "policies": ["read-db-creds"],
  "created_at": "2025-10-27T10:00:00Z"
}
```

### 2. Certificate Issuance (Bootstrap)

```
┌─────────────┐           ┌─────────────┐           ┌─────────────┐
│Application  │           │  Core PKI   │           │   Database  │
└──────┬──────┘           └──────┬──────┘           └──────┬──────┘
       │                         │                         │
       │  1. Generate CSR        │                         │
       │  (app_name, app_token)  │                         │
       │                         │                         │
       │  2. POST /v1/pki/app/issue                        │
       ├────────────────────────>│                         │
       │  {                      │                         │
       │    "app_id": "...",     │                         │
       │    "app_token": "...",  │  3. Validate app_token  │
       │    "csr": "...",        ├────────────────────────>│
       │    "ttl": 2592000       │                         │
       │  }                      │  4. App verified        │
       │                         │<────────────────────────┤
       │                         │                         │
       │                         │  5. Sign CSR            │
       │                         │  (CN=app-payment-service)│
       │                         │                         │
       │                         │  6. Store certificate   │
       │                         ├────────────────────────>│
       │                         │                         │
       │  7. Return certificate  │                         │
       │<────────────────────────┤                         │
       │  {                      │                         │
       │    "certificate": "...",│                         │
       │    "ca_chain": "...",   │                         │
       │    "expires_at": "..."  │                         │
       │  }                      │                         │
       │                         │                         │
       │  8. Store cert locally  │                         │
       │  Save to /etc/app/cert/ │                         │
       │                         │                         │
```

### 3. Application-to-Agent Authentication (Ongoing)

```
┌─────────────┐                    ┌─────────────┐
│Application  │                    │    Agent    │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │  1. Connect via UDS              │
       │  /var/run/secrethub/agent.sock   │
       ├─────────────────────────────────>│
       │                                  │
       │  2. mTLS Handshake               │
       │  Client cert: app-payment-service│
       │<─────────────────────────────────>│
       │                                  │
       │  3. Extract CN from cert         │
       │  Verify against Core CA          │
       │                                  ├─── Validation
       │                                  │
       │  4. Connection established       │
       │<─────────────────────────────────┤
       │                                  │
       │  5. Request secret               │
       │  GET /secrets/prod.db.password   │
       ├─────────────────────────────────>│
       │                                  │
       │  6. Check policies for app       │
       │  app-payment-service allowed?    │
       │                                  ├─── Policy Check
       │                                  │
       │  7. Return secret                │
       │<─────────────────────────────────┤
       │                                  │
```

## Application Certificate Request Format

### CSR Generation (Application Side)

```elixir
# Generate private key
{:ok, key} = :public_key.generate_key({:rsa, 2048, 65537})

# Create certificate request
subject = [
  {:commonName, 'app-payment-service'},
  {:organizationName, 'SecretHub Applications'},
  {:organizationalUnitName, 'Production'}
]

csr_info = :public_key.pkix_cert_request_info(
  subject,
  {:RSAPublicKey, modulus, exponent},
  []
)

csr = :public_key.pkix_sign(csr_info, key)
csr_pem = :public_key.pem_encode([{:CertificationRequest, csr, :not_encrypted}])
```

### API Request Format

**Endpoint:** `POST /v1/pki/app/issue`

**Request:**
```json
{
  "app_id": "550e8400-e29b-41d4-a716-446655440000",
  "app_token": "hvs.CAESIJ...",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "ttl": 2592000,
  "metadata": {
    "hostname": "prod-payment-01",
    "environment": "production",
    "version": "v1.2.3"
  }
}
```

**Response:**
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "ca_chain": [
    "-----BEGIN CERTIFICATE-----\n...",  // Intermediate CA
    "-----BEGIN CERTIFICATE-----\n..."   // Root CA
  ],
  "serial_number": "1A:2B:3C:4D",
  "expires_at": "2025-11-27T10:00:00Z",
  "issued_at": "2025-10-27T10:00:00Z",
  "ttl": 2592000
}
```

## Application Identity Verification

### Bootstrap Token Validation

1. **Token Format**: JWT with claims
   ```json
   {
     "sub": "app:550e8400-e29b-41d4-a716-446655440000",
     "aud": "secrethub-core",
     "iss": "secrethub-core",
     "exp": 1698408000,
     "iat": 1698404400,
     "app_name": "payment-service",
     "agent_id": "agent-uuid",
     "one_time": true
   }
   ```

2. **Validation Steps**:
   - Verify JWT signature
   - Check expiration (default: 1 hour)
   - Verify `app_id` matches token subject
   - Check `one_time` flag - reject if token already used
   - Validate CSR common name matches `app_name`

3. **Token Storage**:
   - Store used tokens in database/cache
   - Mark as "used" after first certificate issuance
   - Cleanup expired tokens after 24 hours

### CSR Validation

1. **Common Name (CN)** must be: `app-{app_name}`
2. **Key Size** minimum: 2048-bit RSA or P-256 ECDSA
3. **Subject Fields** required:
   - CN: `app-{app_name}`
   - O: `SecretHub Applications`
   - OU: `{environment}` (optional)

4. **Prohibited Fields**:
   - Cannot set CA:TRUE
   - Cannot set Key Usage beyond Client Auth
   - No email addresses in SAN

## Certificate Lifecycle

### Issuance

1. Application administrator registers app via Core API
2. Admin receives one-time bootstrap token
3. Admin deploys token to application (env var, file, etc.)
4. Application generates CSR and requests certificate
5. Core validates token and CSR
6. Core signs CSR and returns certificate
7. Application stores certificate locally

**Certificate Details:**
- **Type**: `app_client`
- **Common Name**: `app-{app_name}`
- **TTL**: 30 days (default), configurable 1-365 days
- **SAN**: Application name
- **Key Usage**: Digital Signature, Key Encipherment
- **Extended Key Usage**: TLS Web Client Authentication

### Renewal

**Trigger**: Application detects certificate expires in < 7 days

**Flow:**
```
┌─────────────┐                    ┌─────────────┐
│Application  │                    │  Core PKI   │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │  1. Generate new CSR             │
       │  (same key or new key)           │
       │                                  │
       │  2. POST /v1/pki/app/renew       │
       ├─────────────────────────────────>│
       │  {                               │
       │    "app_id": "...",              │
       │    "current_cert": "...",        │  3. Verify current cert
       │    "csr": "...",                 │  - Valid signature
       │    "ttl": 2592000                │  - Not revoked
       │  }                               │  - Still valid
       │                                  │
       │  4. Return new certificate       │
       │<─────────────────────────────────┤
       │                                  │
```

**Renewal Policy:**
- Can renew anytime with valid current certificate
- No bootstrap token required for renewal
- New certificate issued with same or updated TTL
- Old certificate remains valid until expiry

### Revocation

**Trigger**: Admin action, security incident, app decommission

**Flow:**
```
┌─────────────┐                    ┌─────────────┐                    ┌─────────────┐
│    Admin    │                    │  Core API   │                    │   Agents    │
└──────┬──────┘                    └──────┬──────┘                    └──────┬──────┘
       │                                  │                                  │
       │  1. POST /v1/pki/app/revoke     │                                  │
       ├─────────────────────────────────>│                                  │
       │  {                               │                                  │
       │    "app_id": "...",              │                                  │
       │    "reason": "decommissioned"    │  2. Mark cert as revoked         │
       │  }                               │  Update CRL                      │
       │                                  │                                  │
       │  3. Cert revoked                 │  4. Notify agents                │
       │<─────────────────────────────────┤  (via WebSocket or CRL refresh)  │
       │                                  ├─────────────────────────────────>│
       │                                  │                                  │
       │                                  │  5. Agents refresh CRL            │
       │                                  │  Reject connections from app     │
       │                                  │<─────────────────────────────────┤
```

**Revocation Reasons:**
- `unspecified` - Default
- `key_compromise` - Private key exposed
- `affiliation_changed` - App moved to different agent
- `superseded` - New certificate issued
- `cessation_of_operation` - App decommissioned

**CRL Distribution:**
- Core publishes CRL at `/v1/pki/crl`
- Agents fetch CRL every 5 minutes
- Revoked certificates cached in Agent for fast lookup

## App Certificate vs Agent Certificate Differences

### Common Name Format

**Agent Certificate:**
```
CN=agent-a1b2c3d4-e5f6-7890-abcd-ef1234567890
O=SecretHub Agents
```

**App Certificate:**
```
CN=app-payment-service
O=SecretHub Applications
OU=Production
```

### Certificate Extensions

**Agent Certificate:**
- Basic Constraints: `CA:FALSE, pathlen:0`
- Key Usage: `Digital Signature, Key Encipherment`
- Extended Key Usage: `TLS Web Client Authentication`
- SAN: `DNS:agent-{id}.secrethub.internal, URI:spiffe://secrethub/agent/{id}`

**App Certificate:**
- Basic Constraints: `CA:FALSE, pathlen:0`
- Key Usage: `Digital Signature, Key Encipherment`
- Extended Key Usage: `TLS Web Client Authentication`
- SAN: `DNS:app-{name}.local, URI:spiffe://secrethub/app/{name}`

### Issuance Method

**Agent Certificate:**
- Issued via `AgentChannel` WebSocket handler
- Requires agent authentication with AppRole
- Endpoint: `certificate:request` message on WebSocket

**App Certificate:**
- Issued via REST API
- Requires app bootstrap token
- Endpoint: `POST /v1/pki/app/issue`

### Storage Location

**Agent Certificate:**
- Stored in Agent memory and cache
- Persisted to: `/etc/secrethub/agent/cert.pem`
- Key stored in: `/etc/secrethub/agent/key.pem`

**App Certificate:**
- Application-managed storage
- Recommended: `/etc/{app_name}/secrethub/cert.pem`
- Key: `/etc/{app_name}/secrethub/key.pem`

### Default TTL

**Agent Certificate:**
- Default: 90 days
- Maximum: 365 days
- Renewable: Yes (automatic by Agent)

**App Certificate:**
- Default: 30 days
- Maximum: 90 days
- Renewable: Yes (manual by application)

## Security Considerations

### Bootstrap Token Security

1. **One-Time Use**: Token can only be used once for certificate issuance
2. **Short Expiry**: Default 1 hour, maximum 24 hours
3. **Secure Delivery**:
   - Pass via environment variable (preferred)
   - Store in secure volume mount
   - Never log token value
   - Never embed in application code

4. **Token Rotation**: Generate new token if unused token expires

### Private Key Security

1. **Key Generation**: Must be generated on application server, never on Core
2. **Key Storage**:
   - File permissions: `0400` (read-only by app user)
   - Encrypted at rest if possible
   - Never transmitted over network

3. **Key Rotation**:
   - Rotate on certificate renewal (optional)
   - Rotate if key compromise suspected
   - Use new key for each environment

### Certificate Storage

1. **File Permissions**:
   - Certificate: `0444` (world-readable)
   - Private key: `0400` (owner read-only)
   - CA chain: `0444` (world-readable)

2. **Directory Structure**:
   ```
   /etc/{app_name}/secrethub/
   ├── cert.pem         (0444)
   ├── key.pem          (0400)
   ├── ca-chain.pem     (0444)
   └── app_token.txt    (0400, deleted after cert issued)
   ```

## Implementation Checklist

### Core PKI Module

- [ ] Add `app_client` certificate type to PKI.CA
- [ ] Implement `POST /v1/pki/app/issue` endpoint
- [ ] Implement `POST /v1/pki/app/renew` endpoint
- [ ] Implement `POST /v1/pki/app/revoke` endpoint
- [ ] Add app certificate validation logic
- [ ] Implement bootstrap token generation and validation
- [ ] Add app certificate storage and tracking
- [ ] Update CRL to include revoked app certificates

### Application Registration Module

- [ ] Create `SecretHub.Core.Apps` module
- [ ] Implement `POST /v1/apps` (register app)
- [ ] Implement `GET /v1/apps` (list apps)
- [ ] Implement `GET /v1/apps/:id` (get app details)
- [ ] Implement `DELETE /v1/apps/:id` (deregister app)
- [ ] Add app-to-agent binding
- [ ] Add app-to-policy binding

### Database Schema

```sql
CREATE TABLE applications (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) NOT NULL UNIQUE,
  description TEXT,
  agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
  status VARCHAR(50) NOT NULL DEFAULT 'active',
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE app_certificates (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  app_id UUID REFERENCES applications(id) ON DELETE CASCADE,
  certificate_id UUID REFERENCES certificates(id) ON DELETE CASCADE,
  issued_at TIMESTAMP NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP,
  revocation_reason VARCHAR(100),
  UNIQUE(app_id, certificate_id)
);

CREATE TABLE app_bootstrap_tokens (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  app_id UUID REFERENCES applications(id) ON DELETE CASCADE,
  token_hash VARCHAR(255) NOT NULL UNIQUE,
  used BOOLEAN NOT NULL DEFAULT FALSE,
  used_at TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_apps_agent_id ON applications(agent_id);
CREATE INDEX idx_app_certs_app_id ON app_certificates(app_id);
CREATE INDEX idx_app_tokens_hash ON app_bootstrap_tokens(token_hash);
```

### Agent Module

- [ ] Update Agent to accept app client certificates
- [ ] Implement app certificate validation in UDS handler
- [ ] Add app identity extraction from certificate CN
- [ ] Update policy evaluation to handle app identities
- [ ] Implement CRL caching and refresh

## Example Usage

### 1. Register Application (Admin)

```bash
curl -X POST https://core.secrethub.internal/v1/apps \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "payment-service",
    "description": "Payment processing service",
    "agent_id": "550e8400-e29b-41d4-a716-446655440000",
    "policies": ["prod-payment-db-read"]
  }'
```

**Response:**
```json
{
  "app_id": "app-uuid",
  "app_token": "hvs.CAESIJ...",
  "expires_at": "2025-10-27T11:00:00Z"
}
```

### 2. Request Certificate (Application)

```bash
# Generate CSR
openssl req -new -newkey rsa:2048 -nodes \
  -keyout /etc/payment-service/secrethub/key.pem \
  -out /tmp/app.csr \
  -subj "/CN=app-payment-service/O=SecretHub Applications/OU=Production"

# Request certificate
curl -X POST https://core.secrethub.internal/v1/pki/app/issue \
  -H "Content-Type: application/json" \
  -d "{
    \"app_id\": \"$APP_ID\",
    \"app_token\": \"$APP_TOKEN\",
    \"csr\": \"$(cat /tmp/app.csr | base64 -w0)\",
    \"ttl\": 2592000
  }" | jq -r '.certificate' > /etc/payment-service/secrethub/cert.pem
```

### 3. Connect to Agent (Application)

```elixir
# Elixir application code
defmodule PaymentService.SecretHub do
  def connect_to_agent do
    cert_file = "/etc/payment-service/secrethub/cert.pem"
    key_file = "/etc/payment-service/secrethub/key.pem"
    ca_file = "/etc/payment-service/secrethub/ca-chain.pem"

    {:ok, cert} = File.read(cert_file)
    {:ok, key} = File.read(key_file)
    {:ok, ca_chain} = File.read(ca_file)

    # Connect via UDS with mTLS
    {:ok, conn} = :gen_tcp.connect(
      {:local, "/var/run/secrethub/agent.sock"},
      0,
      [
        :binary,
        active: false,
        certfile: cert_file,
        keyfile: key_file,
        cacertfile: ca_file,
        verify: :verify_peer
      ]
    )

    {:ok, conn}
  end
end
```

## References

- [PKI Management Design](./pki-management.md)
- [Agent Architecture](./agent-architecture.md)
- [Policy Engine Design](./policy-engine.md)
- [Unix Domain Socket Protocol](./uds-protocol.md)
