# SecretHub Agent Deployment Guide

This guide explains how to deploy and configure SecretHub Agents to enable secure secret delivery to your applications.

## Overview

SecretHub Agents are lightweight daemons that run alongside your applications to:
- Enroll with SecretHub Core using host identity and a Core-issued challenge
- Authenticate runtime traffic with a Core-issued mTLS client certificate
- Maintain persistent WebSocket connections to Core
- Fetch and cache secrets locally
- Render secrets into configuration files
- Handle automatic secret rotation

## Prerequisites

- SecretHub Core is deployed and operational
- Vault is initialized and unsealed
- Network connectivity between Agent and Core
- Root CA and Intermediate CA generated (for mTLS)

## Deployment Options

### Option 1: Docker Container (Recommended)

```bash
docker run -d \
  --name secrethub-agent \
  --restart unless-stopped \
  -v /app/config:/app/config \
  -v /var/lib/secrethub-agent:/var/lib/secrethub-agent \
  -v /var/run/secrethub:/var/run/secrethub \
  -e SECRET_HUB_AGENT_CORE_URL=https://secrethub.example.com \
  -e SECRET_HUB_AGENT_STATE_DIR=/var/lib/secrethub-agent \
  secrethub/agent:latest
```

### Option 2: Kubernetes DaemonSet

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: secrethub-agent
  namespace: default
spec:
  selector:
    matchLabels:
      app: secrethub-agent
  template:
    metadata:
      labels:
        app: secrethub-agent
    spec:
      containers:
      - name: agent
        image: secrethub/agent:latest
        env:
        - name: SECRET_HUB_AGENT_CORE_URL
          value: "https://secrethub-core.secrethub.svc.cluster.local"
        - name: SECRET_HUB_AGENT_STATE_DIR
          value: /var/lib/secrethub-agent
        volumeMounts:
        - name: config
          mountPath: /app/config
        - name: state
          mountPath: /var/lib/secrethub-agent
        - name: secrets
          mountPath: /var/run/secrethub
      volumes:
      - name: config
        configMap:
          name: secrethub-agent-config
      - name: state
        hostPath:
          path: /var/lib/secrethub-agent
          type: DirectoryOrCreate
      - name: secrets
        emptyDir: {}
```

### Option 3: Systemd Service

```bash
# Install agent binary
sudo wget -O /usr/local/bin/secrethub-agent \
  https://releases.secrethub.io/agent/latest/secrethub-agent-linux-amd64
sudo chmod +x /usr/local/bin/secrethub-agent

# Create systemd unit file
sudo tee /etc/systemd/system/secrethub-agent.service <<EOF
[Unit]
Description=SecretHub Agent
After=network.target

[Service]
Type=simple
User=secrethub
Group=secrethub
Environment="SECRET_HUB_AGENT_CORE_URL=https://secrethub.example.com"
Environment="SECRET_HUB_AGENT_STATE_DIR=/var/lib/secrethub-agent"
ExecStart=/usr/local/bin/secrethub-agent
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable secrethub-agent
sudo systemctl start secrethub-agent
```

## Agent Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_HUB_AGENT_CORE_URL` | Yes | HTTPS URL of SecretHub Core for enrollment; trusted WebSocket details come from `connect-info.json` |
| `SECRET_HUB_AGENT_CORE_ENDPOINTS` | No | Comma-separated Core enrollment endpoints for startup failover; defaults to `SECRET_HUB_AGENT_CORE_URL` |
| `SECRET_HUB_AGENT_STATE_DIR` | No | Directory for trusted runtime material; default: `/var/lib/secrethub-agent` |
| `SECRET_HUB_AGENT_ID` | Optional | Unique identifier for legacy explicit certificate-path mode |
| `SECRET_HUB_AGENT_CERT_PATH` | No | Legacy override path to client certificate |
| `SECRET_HUB_AGENT_KEY_PATH` | No | Legacy override path to client private key |
| `SECRET_HUB_AGENT_CA_PATH` | No | Legacy override path to CA certificate chain |

Trusted enrollment no longer uses AppRole credentials for runtime authorization. AppRole values may exist for older deployments, but new Agents should use the pending enrollment flow.

### Configuration Sources

The Agent reads the supported `SECRET_HUB_AGENT_*` environment variables at application startup. Elixir release configuration may also set the matching application keys directly under `:secrethub_agent` (`:core_url`, `:state_dir`, `:agent_id`, `:cert_path`, `:key_path`, and `:ca_path`). Environment variables take precedence over application config.

### Local State and Startup Modes

`RuntimeBootstrapper` selects the startup mode from local state and configuration:

- `trusted_runtime`: `IdentityStore` loads trusted material from `state_dir` and starts the mTLS runtime.
- `enrollment`: trusted material is missing, so the Agent creates a pending enrollment, waits for approval, receives certificate material, and then starts trusted runtime.
- `legacy_certificate_paths`: explicit `SECRET_HUB_AGENT_ID`, `SECRET_HUB_AGENT_CERT_PATH`, `SECRET_HUB_AGENT_KEY_PATH`, and `SECRET_HUB_AGENT_CA_PATH` are configured for older deployments.

The default `state_dir` is `/var/lib/secrethub-agent`. Development can override it with `SECRET_HUB_AGENT_STATE_DIR`.

| File | Purpose | Permissions |
|------|---------|------|
| `agent-cert.pem` | Core-issued Agent client certificate | `0644` |
| `agent-key.pem` | TLS client private key generated by `TLSIdentity` | `0600` |
| `ca-chain.pem` | CA chain used to verify the trusted Core endpoint | `0644` |
| `connect-info.json` | Trusted WebSocket endpoint, expected server name, heartbeat, and timeout settings | `0644` |
| `identity.json` | Agent ID, certificate metadata, SSH host-key fingerprint, and host metadata | `0644` |
| `pending.json` | Pending enrollment token and enrollment URL kept until runtime acceptance is finalized | `0600` |

## Bootstrap Process

### Step 1: Start Agent Enrollment

Start the Agent with `SECRET_HUB_AGENT_CORE_URL` and a writable `state_dir`. On first boot, `RuntimeBootstrapper` enters enrollment mode because trusted material is not present.

### Step 2: Pending Enrollment

The Agent discovers its SSH host key, hostname, FQDN, and machine identity, then creates a pending enrollment. The enrollment request includes `ssh_host_public_key`; the private SSH host key never leaves the host.

```bash
docker run -d \
  --name secrethub-agent \
  -e SECRET_HUB_AGENT_CORE_URL=https://secrethub.example.com \
  -e SECRET_HUB_AGENT_STATE_DIR=/var/lib/secrethub-agent \
  -v /var/lib/secrethub-agent:/var/lib/secrethub-agent \
  secrethub/agent:latest
```

An operator approves the pending enrollment in Core.

### Step 3: CSR, SSH Proof, and Runtime Material

After approval, the Agent will:

1. Generate a separate TLS keypair with `TLSIdentity`
2. Create a CSR using the required subject and SAN fields from Core
3. Sign an `AgentCSRProof` over the CSR, enrollment ID, and Core challenge with the SSH host private key
4. Submit the CSR and `ssh_proof` to Core
5. Core verifies `ssh_proof` against the stored `ssh_host_public_key`
6. Core issues a clientAuth Agent certificate with Agent and host-key SANs
7. The Agent stores `agent-cert.pem`, `agent-key.pem`, `ca-chain.pem`, `connect-info.json`, `identity.json`, and `pending.json` under `state_dir`
8. The Agent connects to the trusted runtime endpoint with the Core-issued mTLS certificate

`pending.json` remains until the runtime WebSocket is accepted.

### Step 4: Runtime Acceptance and Finalization

The Agent joins `agent:runtime` over `AgentTrustedSocket`. Core derives `agent_id`, `certificate_serial`, `certificate_fingerprint`, and `certificate_id` from the verified certificate and returns them in the accepted join reply. The Agent's `on_runtime_accepted` callback finalizes enrollment and deletes `pending.json` only after that accepted reply.

### Step 5: Verify Agent Connection

Check agent status in SecretHub Admin UI:
- Navigate to **Agent Monitoring** (`/admin/agents`)
- Find your agent by ID
- Verify status is "Connected" with green indicator
- Check last heartbeat timestamp

## Certificate Management

### Certificate Lifecycle

- **Initial issuance**: During enrollment, after Core verifies `ssh_proof`
- **Default validity**: 30 days
- **Maximum validity**: 90 days
- **Renewal**: Not implemented in this slice; monitor expiry and re-enroll before expiration
- **Revocation**: Manual via Admin UI if needed

### Certificate Replacement

Automatic and manual certificate renewal endpoints are not part of this first trusted-connection slice. Until renewal is implemented, replace an expiring Agent certificate by creating and approving a new enrollment for the host. Treat unexpected replacement requests as suspicious and verify the SSH host-key fingerprint before approval.

### Certificate Revocation

If an agent is compromised:

1. Navigate to **Certificates** in Admin UI
2. Find the agent's certificate
3. Click **Revoke**
4. Agent will be automatically disconnected
5. Re-bootstrap the agent with new credentials

## Secret Access

### Requesting Secrets

Applications request secrets through the local Agent Unix Domain Socket. The Agent runtime uses the `secret:read` channel event for both static secret reads and dynamic role reads.

### Secret Caching

Agents cache secrets locally for resilience:

- **Cache TTL**: Configurable (default: 5 minutes)
- **Fallback mode**: Use cached secrets if Core is unavailable
- **Invalidation**: On secret rotation notification from Core

### Dynamic Secrets

For dynamic secrets (temporary credentials):

```yaml
secrets:
  - name: postgres-readonly
    path: prod.db.postgres.readonly  # Dynamic secret engine path
    type: dynamic
    ttl: 3600  # 1 hour
    destination: /app/config/db-temp.yml
    template: |
      username: {{ .username }}
      password: {{ .password }}
      expires_at: {{ .lease_expires_at }}
```

## Monitoring & Troubleshooting

### Health Check

```bash
# Check agent process
systemctl status secrethub-agent

# Check logs
journalctl -u secrethub-agent -f

# Docker logs
docker logs -f secrethub-agent
```

### Common Issues

**Agent fails to connect to Core:**
- Verify `SECRET_HUB_AGENT_CORE_URL` is correct and accessible
- Check network connectivity: `ping secrethub.example.com`
- Verify firewall rules allow outbound HTTPS to Core and outbound WebSocket to the trusted Agent endpoint from `connect-info.json`

**Authentication failed:**
- Verify the pending enrollment is approved and not expired
- Check that `ssh_host_public_key` matches the host key fingerprint shown in Core
- Verify `ssh_proof` was generated from the SSH host key and current TLS CSR
- Re-enroll if the local certificate fingerprint is unknown to Core

**Certificate errors:**
- Verify CA certificate chain is valid
- Check certificate expiration: `openssl x509 -in agent-cert.pem -noout -dates`
- Confirm the certificate has `clientAuth` EKU and Agent/host-key URI SANs
- Ensure system time is synchronized (NTP)

**Secrets not updating:**
- Check agent cache settings
- Verify secret path exists in Core
- Check agent has policy permissions for the secret path
- Review agent logs for errors

### Debug Logging

Configure Logger level through the Elixir release/runtime configuration. The Agent does not currently read an Agent-specific logging environment variable.

### Metrics & Observability

Agent exposes metrics on `:9091/metrics`:

```
# Connection status
secrethub_agent_connected{agent_id="..."} 1
secrethub_agent_last_heartbeat_timestamp_seconds 1698765432

# Secret operations
secrethub_agent_secrets_fetched_total{path="..."} 42
secrethub_agent_secret_cache_hits_total 128
secrethub_agent_secret_cache_misses_total 5

# Certificate status
secrethub_agent_certificate_expiry_timestamp_seconds 1706541432
```

## Security Best Practices

### Credential Management

1. **Never commit trusted material to version control**
   - Keep `state_dir` outside application source trees
   - Protect `agent-key.pem` and `pending.json` with `0600` permissions

2. **Protect enrollment state**
   - Treat `pending.json` as an enrollment credential until finalization
   - Delete stale pending enrollments instead of reusing them

3. **Rotate certificates**
   - Default validity is 30 days
   - Core caps Agent certificates at 90 days
   - Monitor certificate expiration

### Network Security

1. **Use mTLS for all connections**
   - Enrollment uses HTTPS with Core server verification
   - Runtime uses the trusted Agent endpoint with Core-issued mTLS material
   - Plain HTTP bootstrap is development-only and must be explicit

2. **Restrict network access**
   - Agent should only connect to Core (outbound)
   - Applications connect to Agent via Unix socket (not TCP)

3. **Enable TLS 1.3**
   - Disable older TLS versions
   - Use strong cipher suites

### Least Privilege

1. **Assign minimal policies**
   - Only grant access to needed secret paths
   - Use path-based policies: `prod.app.*`

2. **Isolate agents**
   - One agent per application/service
   - Avoid sharing agents between environments

## Production Checklist

Before deploying to production:

- [ ] Core is deployed with HA configuration
- [ ] Vault is initialized and unsealed
- [ ] Root CA and Intermediate CA generated
- [ ] Trusted Agent endpoint configured with server certificate material
- [ ] Agent `state_dir` is persistent, owned by the Agent user, and mode `0700`
- [ ] Agent configuration tested in staging
- [ ] Certificate expiration monitoring configured
- [ ] Agent metrics collection enabled
- [ ] Backup and disaster recovery tested
- [ ] Security review completed
- [ ] Documentation updated with environment-specific details

## Support

For issues or questions:
- **Documentation**: https://docs.secrethub.io
- **GitHub Issues**: https://github.com/secrethub/secrethub/issues
- **Community**: https://discuss.secrethub.io
