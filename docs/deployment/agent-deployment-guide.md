# SecretHub Agent Deployment Guide

This guide explains how to deploy and configure SecretHub Agents to enable secure secret delivery to your applications.

## Overview

SecretHub Agents are lightweight daemons that run alongside your applications to:
- Authenticate with SecretHub Core using AppRole or mTLS
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
  -v /var/run/secrethub:/var/run/secrethub \
  -e AGENT_ID=production-app-01 \
  -e CORE_URL=wss://secrethub.example.com:4001 \
  -e ROLE_ID=<your-role-id> \
  -e SECRET_ID=<your-secret-id> \
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
        - name: AGENT_ID
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: CORE_URL
          value: "wss://secrethub-core.secrethub.svc.cluster.local:4001"
        - name: ROLE_ID
          valueFrom:
            secretKeyRef:
              name: secrethub-agent-credentials
              key: role_id
        - name: SECRET_ID
          valueFrom:
            secretKeyRef:
              name: secrethub-agent-credentials
              key: secret_id
        volumeMounts:
        - name: config
          mountPath: /app/config
        - name: secrets
          mountPath: /var/run/secrethub
      volumes:
      - name: config
        configMap:
          name: secrethub-agent-config
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
Environment="AGENT_ID=production-app-01"
Environment="CORE_URL=wss://secrethub.example.com:4001"
Environment="ROLE_ID=<your-role-id>"
Environment="SECRET_ID=<your-secret-id>"
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
| `AGENT_ID` | Yes | Unique identifier for this agent |
| `CORE_URL` | Yes | WebSocket URL of SecretHub Core (wss://host:port) |
| `ROLE_ID` | Yes* | AppRole Role ID for initial bootstrap |
| `SECRET_ID` | Yes* | AppRole Secret ID for initial bootstrap |
| `CERT_PATH` | No | Path to client certificate (for mTLS) |
| `KEY_PATH` | No | Path to client private key (for mTLS) |
| `CA_PATH` | No | Path to CA certificate chain |
| `LOG_LEVEL` | No | Logging level (debug, info, warn, error) - default: info |
| `CONFIG_PATH` | No | Path to configuration file - default: /app/config/agent.yml |

\* Required for initial bootstrap; optional if mTLS certificates exist

### Configuration File

Create `/app/config/agent.yml`:

```yaml
agent:
  id: production-app-01
  core_url: wss://secrethub.example.com:4001
  log_level: info

authentication:
  # Initial bootstrap with AppRole
  approle:
    role_id: ${ROLE_ID}
    secret_id: ${SECRET_ID}

  # mTLS configuration (after initial bootstrap)
  mtls:
    cert_path: /app/config/certs/agent-cert.pem
    key_path: /app/config/certs/agent-key.pem
    ca_path: /app/config/certs/ca-chain.pem

secrets:
  # Secret templates to render
  - name: database-credentials
    path: prod.db.postgres.readonly
    destination: /app/config/database.yml
    template: |
      database:
        host: {{ .host }}
        port: {{ .port }}
        username: {{ .username }}
        password: {{ .password }}
        database: {{ .database }}

  - name: api-keys
    path: prod.api.keys
    destination: /app/config/api-keys.env
    template: |
      STRIPE_API_KEY={{ .stripe_key }}
      SENDGRID_API_KEY={{ .sendgrid_key }}
      AWS_ACCESS_KEY_ID={{ .aws_access_key }}
      AWS_SECRET_ACCESS_KEY={{ .aws_secret_key }}

cache:
  enabled: true
  ttl: 300  # 5 minutes
  fallback: true  # Use cached secrets if Core is unavailable
```

## Bootstrap Process

### Step 1: Create AppRole in SecretHub Core

1. Log in to SecretHub Admin UI
2. Navigate to **AppRole Management** (`/admin/approles`)
3. Click **Create New AppRole**
4. Enter role name (e.g., "production-app")
5. Add policies: `secret-read,lease-renew`
6. Click **Create AppRole**
7. **Save the RoleID and SecretID** - they will only be shown once!

### Step 2: Deploy Agent with AppRole Credentials

Deploy the agent with the RoleID and SecretID from Step 1.

```bash
docker run -d \
  --name secrethub-agent \
  -e AGENT_ID=production-app-01 \
  -e CORE_URL=wss://secrethub.example.com:4001 \
  -e ROLE_ID=a1b2c3d4-e5f6-... \
  -e SECRET_ID=z9y8x7w6-v5u4-... \
  secrethub/agent:latest
```

### Step 3: Agent Automatic Bootstrap

On first run, the agent will:

1. Connect to Core via WebSocket
2. Authenticate using RoleID/SecretID (AppRole)
3. Generate RSA-2048 key pair
4. Create Certificate Signing Request (CSR)
5. Submit CSR to Core for signing
6. Receive signed certificate and CA chain
7. Store certificate in `/app/config/certs/`
8. Reconnect using mTLS authentication

After successful bootstrap, the agent no longer needs RoleID/SecretID.

### Step 4: Verify Agent Connection

Check agent status in SecretHub Admin UI:
- Navigate to **Agent Monitoring** (`/admin/agents`)
- Find your agent by ID
- Verify status is "Active" with green indicator
- Check last heartbeat timestamp

## Certificate Management

### Certificate Lifecycle

- **Initial issuance**: During bootstrap (90-day validity)
- **Automatic renewal**: 7 days before expiration
- **Revocation**: Manual via Admin UI if needed

### Manual Certificate Renewal

If needed, trigger manual renewal:

```bash
# Via agent CLI
secrethub-agent renew-certificate

# Via Core API
curl -X POST https://secrethub.example.com/v1/pki/certificates/renew \
  -H "Authorization: Bearer <agent-token>" \
  -d '{"agent_id": "production-app-01"}'
```

### Certificate Revocation

If an agent is compromised:

1. Navigate to **Certificates** in Admin UI
2. Find the agent's certificate
3. Click **Revoke**
4. Agent will be automatically disconnected
5. Re-bootstrap the agent with new credentials

## Secret Access

### Requesting Secrets

Agents automatically request secrets configured in `agent.yml`:

```yaml
secrets:
  - name: my-secret
    path: prod.app.database  # Secret path in SecretHub
    destination: /app/config/db.yml  # Where to write
    template: |  # Template for rendering
      host: {{ .host }}
      password: {{ .password }}
```

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
- Verify `CORE_URL` is correct and accessible
- Check network connectivity: `ping secrethub.example.com`
- Verify firewall rules allow outbound WebSocket (port 4001)

**Authentication failed:**
- Verify RoleID and SecretID are correct
- Check if SecretID has already been used (single-use by default)
- Generate new SecretID from Admin UI

**Certificate errors:**
- Verify CA certificate chain is valid
- Check certificate expiration: `openssl x509 -in agent-cert.pem -noout -dates`
- Ensure system time is synchronized (NTP)

**Secrets not updating:**
- Check agent cache settings
- Verify secret path exists in Core
- Check agent has policy permissions for the secret path
- Review agent logs for errors

### Debug Logging

Enable debug logging:

```bash
# Environment variable
export LOG_LEVEL=debug

# Configuration file
agent:
  log_level: debug
```

### Metrics & Observability

Agent exposes Prometheus metrics on `:9091/metrics`:

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

1. **Never commit credentials to version control**
   - Use environment variables or secrets management
   - Rotate SecretIDs regularly

2. **Limit SecretID usage**
   - Use single-use SecretIDs when possible
   - Set short TTLs for SecretIDs (10-15 minutes)

3. **Rotate certificates**
   - Default 90-day validity is recommended
   - Monitor certificate expiration

### Network Security

1. **Use mTLS for all connections**
   - Initial AppRole bootstrap only
   - Switch to mTLS after certificate issuance

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
- [ ] AppRole created with appropriate policies
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
