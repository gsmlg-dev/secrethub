# SecretHub Helm Chart

Enterprise-grade Machine-to-Machine secrets management platform for Kubernetes.

## Introduction

This chart bootstraps a high-availability SecretHub deployment on a Kubernetes cluster using the Helm package manager.

## Prerequisites

- Kubernetes 1.23+
- Helm 3.8+
- PV provisioner support in the underlying infrastructure (for persistent storage)
- External PostgreSQL database (recommended for production)
- External Redis instance (recommended for production)
- AWS KMS key (optional, for auto-unseal)

## Installing the Chart

### Quick Start (Development)

```bash
# Create namespace
kubectl create namespace secrethub

# Generate secrets
export SECRET_KEY_BASE=$(openssl rand -base64 48)
export LIVE_VIEW_SALT=$(openssl rand -base64 32)

# Install with bundled databases (NOT for production)
helm install secrethub ./secrethub \
  --namespace secrethub \
  --set postgresql.external=false \
  --set postgresql.bundled.enabled=true \
  --set redis.external=false \
  --set redis.bundled.enabled=true \
  --set secrets.secretKeyBase="$SECRET_KEY_BASE" \
  --set secrets.liveViewSigningSalt="$LIVE_VIEW_SALT"
```

### Production Installation

#### 1. Prepare External Databases

Create PostgreSQL database:
```sql
CREATE DATABASE secrethub;
CREATE USER secrethub WITH ENCRYPTED PASSWORD 'your-secure-password';
GRANT ALL PRIVILEGES ON DATABASE secrethub TO secrethub;
```

Create values file for production:
```bash
cat > secrethub-values.yaml <<EOF
# Production configuration
core:
  replicaCount: 3

  image:
    repository: your-registry.example.com/secrethub/core
    tag: "0.1.0"

  resources:
    limits:
      cpu: 2000m
      memory: 2Gi
    requests:
      cpu: 1000m
      memory: 1Gi

  persistence:
    enabled: true
    size: 50Gi
    storageClass: gp3

# External PostgreSQL (RDS Multi-AZ)
postgresql:
  external: true
  externalHost: secrethub.cluster-xxx.us-east-1.rds.amazonaws.com
  externalPort: 5432
  externalDatabase: secrethub
  externalUsername: secrethub
  sslMode: require
  poolSize: 20

# External Redis (ElastiCache)
redis:
  external: true
  externalHost: secrethub-redis.xxx.cache.amazonaws.com
  externalPort: 6379
  sslEnabled: true

# AWS KMS for auto-unseal
kms:
  enabled: true
  region: us-east-1
  keyId: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"

# Service Account with IRSA
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/secrethub-core"

# Load Balancer
loadBalancer:
  enabled: true
  type: LoadBalancer
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    service.beta.kubernetes.io/aws-load-balancer-scheme: "internal"

# Secrets (use from external secret manager or sealed secrets)
secrets:
  create: true
  secretKeyBase: "<generated-secret-key-base>"
  liveViewSigningSalt: "<generated-live-view-salt>"
  postgresqlPassword: "<postgresql-password>"
  redisPassword: "<redis-password>"

# Monitoring
monitoring:
  prometheus:
    enabled: true
  serviceMonitor:
    enabled: true
    interval: 30s

# Audit retention
audit:
  hotRetentionDays: 30
  warmRetentionDays: 90
  coldRetentionDays: 365
EOF
```

#### 2. Install the Chart

```bash
# Install with production values
helm install secrethub ./secrethub \
  --namespace secrethub \
  --create-namespace \
  --values secrethub-values.yaml \
  --wait \
  --timeout 10m
```

## Configuration

The following table lists the configurable parameters of the SecretHub chart and their default values.

### Global Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.imagePullSecrets` | Docker registry secret names | `[]` |
| `global.storageClass` | Global storage class for PVCs | `""` |

### Core Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `core.replicaCount` | Number of Core replicas | `3` |
| `core.image.repository` | Core image repository | `secrethub/core` |
| `core.image.tag` | Core image tag | `0.1.0` |
| `core.image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `core.resources.limits.cpu` | CPU limit | `1000m` |
| `core.resources.limits.memory` | Memory limit | `1Gi` |
| `core.resources.requests.cpu` | CPU request | `500m` |
| `core.resources.requests.memory` | Memory request | `512Mi` |
| `core.persistence.enabled` | Enable persistent storage | `true` |
| `core.persistence.size` | PVC size | `10Gi` |
| `core.persistence.storageClass` | Storage class | `""` |

### Database Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `postgresql.external` | Use external PostgreSQL | `true` |
| `postgresql.externalHost` | External PostgreSQL host | `""` |
| `postgresql.externalPort` | External PostgreSQL port | `5432` |
| `postgresql.externalDatabase` | Database name | `secrethub` |
| `postgresql.externalUsername` | Database username | `secrethub` |
| `postgresql.sslMode` | SSL mode | `require` |
| `postgresql.poolSize` | Connection pool size | `10` |
| `postgresql.bundled.enabled` | Enable bundled PostgreSQL | `false` |

### Load Balancer Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `loadBalancer.enabled` | Enable LoadBalancer service | `true` |
| `loadBalancer.type` | Service type | `LoadBalancer` |
| `loadBalancer.sessionAffinity` | Session affinity | `ClientIP` |
| `loadBalancer.sessionAffinityTimeout` | Session timeout (seconds) | `10800` |

### Secret Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `secrets.create` | Create secret resource | `true` |
| `secrets.secretKeyBase` | Phoenix secret key base | `""` |
| `secrets.liveViewSigningSalt` | LiveView signing salt | `""` |
| `secrets.postgresqlPassword` | PostgreSQL password | `""` |
| `secrets.redisPassword` | Redis password | `""` |

## Upgrading

### To 0.2.0

No breaking changes.

## Uninstalling

```bash
helm uninstall secrethub --namespace secrethub
```

This removes all Kubernetes components associated with the chart and deletes the release.

To also delete the PVCs:

```bash
kubectl delete pvc -l app.kubernetes.io/instance=secrethub -n secrethub
```

## Backup and Restore

### Backup

Use Velero or your preferred Kubernetes backup solution:

```bash
velero backup create secrethub-backup \
  --include-namespaces secrethub \
  --wait
```

### Restore

```bash
velero restore create --from-backup secrethub-backup --wait
```

## Troubleshooting

### Pods not starting

Check pod status:
```bash
kubectl get pods -n secrethub
kubectl describe pod <pod-name> -n secrethub
kubectl logs <pod-name> -n secrethub
```

### Database connection issues

Verify database connectivity:
```bash
kubectl run -it --rm debug --image=postgres:16 --restart=Never -n secrethub -- \
  psql -h <db-host> -U secrethub -d secrethub
```

### Check health status

```bash
kubectl port-forward svc/secrethub-lb 4000:80 -n secrethub
curl http://localhost:4000/v1/sys/health/ready
```

## Further Documentation

See the main [SecretHub documentation](../../README.md) for more details on:
- Architecture and components
- Security best practices
- API usage
- Agent deployment
