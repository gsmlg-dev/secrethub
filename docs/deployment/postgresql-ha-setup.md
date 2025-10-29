# PostgreSQL High Availability Setup for SecretHub

This guide covers setting up a highly available PostgreSQL database for SecretHub using AWS RDS Multi-AZ deployments or other HA PostgreSQL solutions.

## Table of Contents

- [Overview](#overview)
- [AWS RDS Multi-AZ Setup](#aws-rds-multi-az-setup)
- [Connection Configuration](#connection-configuration)
- [Failover Testing](#failover-testing)
- [Monitoring and Alerts](#monitoring-and-alerts)
- [Backup and Recovery](#backup-and-recovery)
- [Alternative HA Solutions](#alternative-ha-solutions)
- [Troubleshooting](#troubleshooting)

## Overview

SecretHub requires a reliable PostgreSQL database for storing:
- Vault metadata and encrypted secrets
- PKI certificates and CRLs
- Audit logs
- Dynamic secret leases
- Policy definitions

For production deployments, a highly available PostgreSQL setup is essential to prevent data loss and minimize downtime.

## AWS RDS Multi-AZ Setup

### Architecture

AWS RDS Multi-AZ provides:
- **Synchronous replication** to a standby instance in a different Availability Zone
- **Automatic failover** (typically 60-120 seconds)
- **Single endpoint** - no application changes needed during failover
- **Automated backups** with point-in-time recovery

### Prerequisites

- AWS account with appropriate IAM permissions
- VPC with at least 2 subnets in different AZs
- Security group for database access
- KMS key for encryption at rest (recommended)

### Step 1: Create DB Subnet Group

```bash
# Create subnet group spanning multiple AZs
aws rds create-db-subnet-group \
  --db-subnet-group-name secrethub-db-subnet-group \
  --db-subnet-group-description "SecretHub database subnet group" \
  --subnet-ids subnet-12345678 subnet-87654321 \
  --tags Key=Name,Value=secrethub-db-subnet-group
```

### Step 2: Create Security Group

```bash
# Create security group
aws ec2 create-security-group \
  --group-name secrethub-db-sg \
  --description "Security group for SecretHub database" \
  --vpc-id vpc-12345678

# Allow PostgreSQL access from EKS cluster security group
aws ec2 authorize-security-group-ingress \
  --group-id sg-secrethub-db \
  --protocol tcp \
  --port 5432 \
  --source-group sg-eks-cluster
```

### Step 3: Create RDS Instance

Using AWS CLI:

```bash
aws rds create-db-instance \
  --db-instance-identifier secrethub-db \
  --db-instance-class db.r6g.large \
  --engine postgres \
  --engine-version 16.1 \
  --master-username secrethub \
  --master-user-password <secure-password> \
  --allocated-storage 100 \
  --storage-type gp3 \
  --iops 3000 \
  --storage-encrypted \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012 \
  --db-subnet-group-name secrethub-db-subnet-group \
  --vpc-security-group-ids sg-secrethub-db \
  --multi-az \
  --backup-retention-period 7 \
  --preferred-backup-window "03:00-04:00" \
  --preferred-maintenance-window "mon:04:00-mon:05:00" \
  --enable-cloudwatch-logs-exports '["postgresql","upgrade"]' \
  --deletion-protection \
  --tags Key=Name,Value=secrethub-db Key=Environment,Value=production
```

Using Terraform:

```hcl
resource "aws_db_instance" "secrethub" {
  identifier = "secrethub-db"

  # Instance configuration
  instance_class        = "db.r6g.large"
  engine                = "postgres"
  engine_version        = "16.1"

  # Storage configuration
  allocated_storage     = 100
  storage_type          = "gp3"
  iops                  = 3000
  storage_encrypted     = true
  kms_key_id           = aws_kms_key.db_encryption.arn

  # Database credentials
  db_name              = "secrethub"
  username             = "secrethub"
  password             = random_password.db_password.result

  # High availability
  multi_az             = true

  # Network configuration
  db_subnet_group_name   = aws_db_subnet_group.secrethub.name
  vpc_security_group_ids = [aws_security_group.secrethub_db.id]
  publicly_accessible    = false

  # Backup configuration
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "mon:04:00-mon:05:00"

  # Monitoring
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  monitoring_interval            = 60
  monitoring_role_arn           = aws_iam_role.rds_monitoring.arn

  # Protection
  deletion_protection = true
  skip_final_snapshot = false
  final_snapshot_identifier = "secrethub-db-final-snapshot"

  tags = {
    Name        = "secrethub-db"
    Environment = "production"
  }
}

# Random password for database
resource "random_password" "db_password" {
  length  = 32
  special = true
}

# Store password in Secrets Manager
resource "aws_secretsmanager_secret" "db_password" {
  name = "secrethub/db/password"
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db_password.result
}
```

### Step 4: Initialize Database

After the RDS instance is created and available:

```bash
# Get the endpoint
DB_ENDPOINT=$(aws rds describe-db-instances \
  --db-instance-identifier secrethub-db \
  --query 'DBInstances[0].Endpoint.Address' \
  --output text)

# Connect and create database
psql -h $DB_ENDPOINT -U secrethub -d postgres << EOF
CREATE DATABASE secrethub;
\c secrethub;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE SCHEMA IF NOT EXISTS audit;
EOF
```

### Step 5: Configure Connection Pooling (Optional)

For production workloads, consider using PgBouncer or RDS Proxy:

**RDS Proxy Configuration:**

```bash
aws rds create-db-proxy \
  --db-proxy-name secrethub-proxy \
  --engine-family POSTGRESQL \
  --auth '[{"AuthScheme":"SECRETS","SecretArn":"arn:aws:secretsmanager:us-east-1:123456789012:secret:secrethub/db/password"}]' \
  --role-arn arn:aws:iam::123456789012:role/RDSProxyRole \
  --vpc-subnet-ids subnet-12345678 subnet-87654321 \
  --require-tls
```

## Connection Configuration

### Connection String Format

For Multi-AZ RDS, use the **cluster endpoint**, not individual instance endpoints:

```bash
# Standard format
DATABASE_URL=postgresql://secrethub:PASSWORD@secrethub-db.cluster-xxx.us-east-1.rds.amazonaws.com:5432/secrethub?sslmode=require&pool_size=20

# With RDS Proxy
DATABASE_URL=postgresql://secrethub:PASSWORD@secrethub-proxy.proxy-xxx.us-east-1.rds.amazonaws.com:5432/secrethub?sslmode=require&pool_size=20
```

### Helm Values Configuration

```yaml
# values.yaml
postgresql:
  external: true
  externalHost: "secrethub-db.cluster-xxx.us-east-1.rds.amazonaws.com"
  externalPort: 5432
  externalDatabase: "secrethub"
  externalUsername: "secrethub"
  sslMode: "require"
  poolSize: 20

secrets:
  postgresqlPassword: "<password-from-secrets-manager>"
```

### SSL/TLS Configuration

AWS RDS requires SSL connections. Download the RDS CA certificate:

```bash
# Download RDS CA bundle
wget https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem -O /tmp/rds-ca-bundle.pem

# Create Kubernetes secret with CA bundle
kubectl create secret generic rds-ca-bundle \
  --from-file=ca-bundle.pem=/tmp/rds-ca-bundle.pem \
  -n secrethub
```

Update connection string to verify server certificate:

```bash
DATABASE_URL=postgresql://secrethub:PASSWORD@secrethub-db.cluster-xxx.us-east-1.rds.amazonaws.com:5432/secrethub?sslmode=verify-full&sslrootcert=/etc/ssl/certs/rds-ca-bundle.pem
```

## Failover Testing

### Manual Failover Test

AWS RDS Multi-AZ failover can be triggered manually for testing:

```bash
# Trigger failover
aws rds reboot-db-instance \
  --db-instance-identifier secrethub-db \
  --force-failover

# Monitor failover progress
aws rds describe-db-instances \
  --db-instance-identifier secrethub-db \
  --query 'DBInstances[0].[DBInstanceStatus,AvailabilityZone]'
```

**Expected behavior:**
- Failover typically completes in 60-120 seconds
- DNS endpoint remains the same
- Applications automatically reconnect (with proper retry logic)
- Brief connection interruption during switchover

### Application-Level Failover Testing

Test SecretHub's behavior during database failover:

```bash
# 1. Start monitoring connection status
kubectl logs -f secrethub-core-0 -n secrethub | grep -i "database\|connection"

# 2. Trigger failover (in another terminal)
aws rds reboot-db-instance \
  --db-instance-identifier secrethub-db \
  --force-failover

# 3. Monitor SecretHub health endpoints
watch -n 1 'kubectl exec secrethub-core-0 -n secrethub -- wget -qO- http://localhost:4000/v1/sys/health/ready'

# 4. Verify operations resume after failover
kubectl exec secrethub-core-0 -n secrethub -- \
  bin/secrethub rpc "SecretHub.Core.Secrets.list_secrets()"
```

**Checklist:**
- [ ] Existing connections gracefully handle disconnection
- [ ] New connections establish successfully after failover
- [ ] Health checks return to healthy state within 2 minutes
- [ ] No data loss or corruption
- [ ] Audit logs recorded correctly during and after failover
- [ ] No manual intervention required

### Automated Failover Testing

Use chaos engineering tools like Chaos Monkey or AWS Fault Injection Simulator:

```yaml
# AWS FIS experiment template
apiVersion: fis.aws.amazon.com/v1
kind: ExperimentTemplate
metadata:
  name: rds-failover-test
spec:
  description: "Test SecretHub RDS failover"
  targets:
    - name: secrethub-db
      resourceType: "aws:rds:db"
      selectionMode: "ALL"
      resourceTags:
        Name: "secrethub-db"
  actions:
    - name: reboot-rds
      actionId: "aws:rds:reboot-db-instances"
      parameters:
        forceFailover: "true"
  stopConditions:
    - source: "aws:cloudwatch:alarm"
      value: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:secrethub-critical-errors"
```

## Monitoring and Alerts

### CloudWatch Metrics

Monitor these RDS metrics:

```bash
# CPU Utilization
aws cloudwatch put-metric-alarm \
  --alarm-name secrethub-db-cpu-high \
  --alarm-description "CPU > 80% for 5 minutes" \
  --metric-name CPUUtilization \
  --namespace AWS/RDS \
  --statistic Average \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=DBInstanceIdentifier,Value=secrethub-db

# Database Connections
aws cloudwatch put-metric-alarm \
  --alarm-name secrethub-db-connections-high \
  --alarm-description "Connections > 80% of max" \
  --metric-name DatabaseConnections \
  --namespace AWS/RDS \
  --statistic Average \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=DBInstanceIdentifier,Value=secrethub-db

# Replication Lag (for read replicas)
aws cloudwatch put-metric-alarm \
  --alarm-name secrethub-db-replication-lag \
  --alarm-description "Replication lag > 60 seconds" \
  --metric-name ReplicaLag \
  --namespace AWS/RDS \
  --statistic Average \
  --period 60 \
  --evaluation-periods 2 \
  --threshold 60 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=DBInstanceIdentifier,Value=secrethub-db
```

### PostgreSQL-Specific Monitoring

Enable Enhanced Monitoring for OS-level metrics:

```bash
aws rds modify-db-instance \
  --db-instance-identifier secrethub-db \
  --monitoring-interval 60 \
  --monitoring-role-arn arn:aws:iam::123456789012:role/rds-monitoring-role
```

### Grafana Dashboard

Create a Grafana dashboard for RDS metrics:

```json
{
  "dashboard": {
    "title": "SecretHub PostgreSQL HA",
    "panels": [
      {
        "title": "Database Connections",
        "targets": [
          {
            "namespace": "AWS/RDS",
            "metricName": "DatabaseConnections",
            "dimensions": {
              "DBInstanceIdentifier": "secrethub-db"
            }
          }
        ]
      },
      {
        "title": "CPU Utilization",
        "targets": [
          {
            "namespace": "AWS/RDS",
            "metricName": "CPUUtilization"
          }
        ]
      },
      {
        "title": "Disk Queue Depth",
        "targets": [
          {
            "namespace": "AWS/RDS",
            "metricName": "DiskQueueDepth"
          }
        ]
      }
    ]
  }
}
```

## Backup and Recovery

### Automated Backups

RDS automatically creates daily backups:

```bash
# List available backups
aws rds describe-db-snapshots \
  --db-instance-identifier secrethub-db

# Restore from snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier secrethub-db-restored \
  --db-snapshot-identifier rds:secrethub-db-2025-10-29-03-00 \
  --db-instance-class db.r6g.large \
  --multi-az
```

### Point-in-Time Recovery

Restore to any point within the backup retention period:

```bash
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier secrethub-db \
  --target-db-instance-identifier secrethub-db-pitr \
  --restore-time 2025-10-29T12:00:00Z \
  --multi-az
```

### Manual Snapshots

Create manual snapshots before major changes:

```bash
# Create snapshot
aws rds create-db-snapshot \
  --db-instance-identifier secrethub-db \
  --db-snapshot-identifier secrethub-db-pre-upgrade-$(date +%Y%m%d)

# Copy snapshot to another region (disaster recovery)
aws rds copy-db-snapshot \
  --source-db-snapshot-identifier arn:aws:rds:us-east-1:123456789012:snapshot:secrethub-db-pre-upgrade-20251029 \
  --target-db-snapshot-identifier secrethub-db-pre-upgrade-20251029 \
  --region us-west-2
```

## Alternative HA Solutions

### Self-Managed PostgreSQL with Patroni

For on-premises or other cloud providers:

```yaml
# Patroni configuration
scope: secrethub
name: postgres1

restapi:
  listen: 0.0.0.0:8008
  connect_address: postgres1.example.com:8008

etcd:
  hosts:
    - etcd1.example.com:2379
    - etcd2.example.com:2379
    - etcd3.example.com:2379

bootstrap:
  dcs:
    ttl: 30
    loop_wait: 10
    retry_timeout: 10
    maximum_lag_on_failover: 1048576
    postgresql:
      use_pg_rewind: true
      parameters:
        max_connections: 200
        shared_buffers: 2GB
        effective_cache_size: 6GB
        maintenance_work_mem: 512MB
        wal_level: replica
        max_wal_senders: 10
        max_replication_slots: 10

postgresql:
  listen: 0.0.0.0:5432
  connect_address: postgres1.example.com:5432
  data_dir: /var/lib/postgresql/16/main
  authentication:
    replication:
      username: replicator
      password: <password>
    superuser:
      username: postgres
      password: <password>
```

### Cloud-Specific Solutions

**Google Cloud SQL:**
- Enable HA with automatic failover
- Use Private Service Connect for VPC connectivity
- Configure connection pooling with Cloud SQL Proxy

**Azure Database for PostgreSQL:**
- Choose "Zone-redundant HA" deployment
- Configure VNet integration
- Use Azure Private Link for secure connectivity

### Kubernetes Operators

For Kubernetes-native deployments:

**CloudNativePG Operator:**
```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: secrethub-db
spec:
  instances: 3
  storage:
    size: 100Gi
    storageClass: premium-ssd
  postgresql:
    version: 16
    parameters:
      max_connections: "200"
      shared_buffers: "2GB"
  backup:
    barmanObjectStore:
      destinationPath: s3://secrethub-backups/
      s3Credentials:
        accessKeyId:
          name: aws-creds
          key: ACCESS_KEY_ID
        secretAccessKey:
          name: aws-creds
          key: SECRET_ACCESS_KEY
```

## Troubleshooting

### Connection Timeouts

**Symptom:** Database connections timing out

**Solutions:**
1. Check security group rules allow PostgreSQL port (5432)
2. Verify DNS resolution of RDS endpoint
3. Check connection pool settings in application
4. Review RDS instance status in AWS console

```bash
# Test connectivity
telnet secrethub-db.cluster-xxx.us-east-1.rds.amazonaws.com 5432

# Check DNS resolution
nslookup secrethub-db.cluster-xxx.us-east-1.rds.amazonaws.com

# Verify security group rules
aws ec2 describe-security-groups --group-ids sg-secrethub-db
```

### Slow Queries

**Symptom:** Database queries taking longer than expected

**Solutions:**
1. Enable Performance Insights in RDS
2. Review slow query logs
3. Analyze and optimize query execution plans
4. Consider scaling up instance class or adding IOPS

```bash
# Enable slow query log
aws rds modify-db-parameter-group \
  --db-parameter-group-name secrethub-pg16 \
  --parameters "ParameterName=log_min_duration_statement,ParameterValue=1000,ApplyMethod=immediate"
```

### Failover Issues

**Symptom:** Failover takes longer than expected or applications don't recover

**Solutions:**
1. Verify Multi-AZ is enabled
2. Check application retry logic
3. Review connection timeout settings
4. Ensure DNS caching is not too aggressive

```bash
# Check Multi-AZ status
aws rds describe-db-instances \
  --db-instance-identifier secrethub-db \
  --query 'DBInstances[0].MultiAZ'

# Review failover events
aws rds describe-events \
  --source-identifier secrethub-db \
  --source-type db-instance \
  --duration 60
```

### Replication Lag

**Symptom:** Standby instance falling behind primary

**Solutions:**
1. Check network connectivity between AZs
2. Review write workload intensity
3. Consider upgrading instance class
4. Monitor `ReplicaLag` CloudWatch metric

---

## Summary

PostgreSQL High Availability for SecretHub:

✅ **Recommended Setup:** AWS RDS Multi-AZ with automated backups
✅ **Minimum Requirements:** 2 AZs, encryption at rest, SSL connections
✅ **Monitoring:** CloudWatch alarms, Performance Insights, Enhanced Monitoring
✅ **Failover Testing:** Regular automated tests with FIS
✅ **Backup Strategy:** Automated daily backups + manual snapshots before changes

For questions or issues, refer to:
- [AWS RDS Multi-AZ Documentation](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html)
- [PostgreSQL Replication Documentation](https://www.postgresql.org/docs/16/high-availability.html)
- [SecretHub GitHub Issues](https://github.com/gsmlg-dev/secrethub/issues)
