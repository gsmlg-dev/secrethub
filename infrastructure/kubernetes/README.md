# SecretHub Kubernetes Deployment

This directory contains Kubernetes manifests for deploying SecretHub Core in a high-availability configuration.

## Architecture

- **3-node StatefulSet** for SecretHub Core
- **Headless Service** for pod discovery
- **Load Balancer Service** for external access
- **Pod Anti-Affinity** to spread pods across nodes/zones
- **Auto-unseal** with AWS KMS integration
- **Health Probes** for liveness, readiness, and startup
- **Graceful Shutdown** with 30s termination grace period

## Prerequisites

### AWS (EKS)

1. **EKS Cluster** (1.28+)
2. **Storage Class**: gp3 EBS volumes
3. **IAM Role for Service Account (IRSA)** for KMS access
4. **AWS KMS Key** for auto-unseal
5. **RDS PostgreSQL** (or in-cluster PostgreSQL)
6. **ElastiCache Redis** (or in-cluster Redis)

### Required Permissions

The IAM role for the service account needs:
- `kms:Encrypt`
- `kms:Decrypt`
- Access to the specified KMS key

## Deployment

### 1. Create Namespace

```bash
kubectl apply -f namespace.yaml
```

### 2. Generate Secrets

```bash
# Generate Phoenix secret key base
SECRET_KEY_BASE=$(mix phx.gen.secret)

# Generate Erlang cookie
ERLANG_COOKIE=$(openssl rand -base64 32)

# Create Kubernetes secret
kubectl create secret generic secrethub-secrets \
  --namespace=secrethub \
  --from-literal=secret_key_base="$SECRET_KEY_BASE" \
  --from-literal=erlang_cookie="$ERLANG_COOKIE" \
  --from-literal=database_url="postgresql://secrethub:PASSWORD@postgres.secrethub.svc.cluster.local:5432/secrethub_prod"
```

### 3. Configure ConfigMap

Edit `secrethub-configmap.yaml` with your environment settings:
- PostgreSQL host and port
- Redis URL
- AWS region for KMS
- Auto-unseal settings

```bash
kubectl apply -f secrethub-configmap.yaml
```

### 4. Deploy StatefulSet

```bash
kubectl apply -f secrethub-core-statefulset.yaml
```

### 5. Deploy Load Balancer Service

```bash
kubectl apply -f secrethub-loadbalancer.yaml
```

## Verification

### Check Pod Status

```bash
kubectl get pods -n secrethub -l app=secrethub-core
```

Expected output:
```
NAME                READY   STATUS    RESTARTS   AGE
secrethub-core-0    1/1     Running   0          2m
secrethub-core-1    1/1     Running   0          2m
secrethub-core-2    1/1     Running   0          2m
```

### Check Logs

```bash
# All pods
kubectl logs -n secrethub -l app=secrethub-core --tail=100

# Specific pod
kubectl logs -n secrethub secrethub-core-0 -f
```

### Check Health

```bash
# Port forward to test health endpoints
kubectl port-forward -n secrethub secrethub-core-0 4000:4000

# Test liveness
curl http://localhost:4000/v1/sys/health/live

# Test readiness
curl http://localhost:4000/v1/sys/health/ready

# Test detailed health
curl http://localhost:4000/v1/sys/health
```

### Check StatefulSet

```bash
kubectl describe statefulset secrethub-core -n secrethub
```

### Check PersistentVolumeClaims

```bash
kubectl get pvc -n secrethub
```

## Initialization

### First Time Setup

On first deployment, you need to initialize the vault:

```bash
# Port forward to one pod
kubectl port-forward -n secrethub secrethub-core-0 4000:4000

# Initialize (in another terminal)
curl -X POST http://localhost:4000/v1/sys/init \
  -H "Content-Type: application/json" \
  -d '{"threshold": 3, "shares": 5}'

# Save the unseal keys and root token securely!
```

### Enable Auto-Unseal

After initialization, configure auto-unseal:

```bash
# Configure auto-unseal with AWS KMS
curl -X POST http://localhost:4000/v1/sys/auto-unseal \
  -H "Content-Type: application/json" \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -d '{
    "provider": "aws_kms",
    "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/your-key-id",
    "region": "us-east-1"
  }'
```

## Scaling

### Scale Up

```bash
kubectl scale statefulset secrethub-core -n secrethub --replicas=5
```

### Scale Down

```bash
kubectl scale statefulset secrethub-core -n secrethub --replicas=3
```

**Note**: Always maintain odd number of replicas for quorum-based operations.

## Monitoring

### Prometheus Integration

The pods are annotated for Prometheus scraping:
```yaml
prometheus.io/scrape: "true"
prometheus.io/port: "4000"
prometheus.io/path: "/metrics"
```

### Metrics Endpoints

- `/metrics` - Prometheus metrics
- `/v1/sys/health` - Detailed health status
- `/v1/sys/health/ready` - Readiness status
- `/v1/sys/health/live` - Liveness status

## Troubleshooting

### Pod Not Starting

```bash
# Check pod events
kubectl describe pod secrethub-core-0 -n secrethub

# Check logs
kubectl logs secrethub-core-0 -n secrethub

# Check init container logs
kubectl logs secrethub-core-0 -n secrethub -c wait-for-postgres
```

### Pod Not Ready

```bash
# Check readiness probe
kubectl get pod secrethub-core-0 -n secrethub -o jsonpath='{.status.conditions}'

# Test readiness endpoint manually
kubectl exec -it secrethub-core-0 -n secrethub -- curl localhost:4000/v1/sys/health/ready
```

### Auto-Unseal Not Working

```bash
# Check logs for KMS errors
kubectl logs secrethub-core-0 -n secrethub | grep -i kms

# Verify IAM role annotation
kubectl get sa secrethub-core -n secrethub -o yaml

# Check AWS credentials in pod
kubectl exec -it secrethub-core-0 -n secrethub -- env | grep AWS
```

### Database Connection Issues

```bash
# Test PostgreSQL connectivity from pod
kubectl exec -it secrethub-core-0 -n secrethub -- nc -zv postgres.secrethub.svc.cluster.local 5432

# Check database URL secret
kubectl get secret secrethub-secrets -n secrethub -o jsonpath='{.data.database_url}' | base64 -d
```

## Backup and Restore

### Backup

```bash
# Backup PostgreSQL data
kubectl exec -it postgres-0 -n secrethub -- pg_dump -U secrethub secrethub_prod > backup.sql

# Backup PersistentVolumes (if using snapshots)
kubectl get pvc -n secrethub
# Use cloud provider's snapshot feature
```

### Restore

```bash
# Restore PostgreSQL data
kubectl exec -i postgres-0 -n secrethub -- psql -U secrethub secrethub_prod < backup.sql
```

## Cleanup

```bash
# Delete StatefulSet (keeps PVCs)
kubectl delete statefulset secrethub-core -n secrethub

# Delete all resources
kubectl delete namespace secrethub

# Delete PVCs if needed
kubectl delete pvc -n secrethub -l app=secrethub-core
```

## Security Best Practices

1. **Use IRSA** instead of storing AWS credentials in secrets
2. **Enable Pod Security Standards** (restricted mode)
3. **Use Network Policies** to restrict pod-to-pod communication
4. **Rotate secrets regularly** (erlang_cookie, secret_key_base)
5. **Enable audit logging** in Kubernetes
6. **Use encrypted storage** for PersistentVolumes
7. **Implement RBAC** for kubectl access
8. **Use separate namespaces** for different environments

## References

- [Kubernetes StatefulSets](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/)
- [Pod Disruption Budgets](https://kubernetes.io/docs/tasks/run-application/configure-pdb/)
- [AWS IAM Roles for Service Accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [Kubernetes Health Checks](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
