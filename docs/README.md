# SecretHub Documentation

Welcome to the SecretHub documentation. This guide provides comprehensive information for deploying, operating, and using SecretHub.

---

## Quick Links

- **[Quickstart Guide](./quickstart.md)** - Get started in 5 minutes
- **[Architecture Overview](./architecture.md)** - System design and components
- **[Operator Manual](./operator-manual.md)** - Day-to-day operations
- **[Troubleshooting](./troubleshooting.md)** - Common issues and solutions
- **[Best Practices](./best-practices.md)** - Security and performance recommendations

---

## Documentation Structure

### Getting Started
- [Quickstart Guide](./quickstart.md) - 5-minute introduction

### Architecture & Design
- [Architecture Overview](./architecture.md) - System design, components, and technology stack
- [Agent-Core Communication Protocol](./architecture/agent-protocol.md) - WebSocket protocol specification
- [Application Certificate Issuance](./architecture/app-certificate-issuance.md) - App cert lifecycle design

### Deployment
- [MVP Deployment Guide](./deployment/mvp-deployment-guide.md) - Docker Compose and Kubernetes deployment
- [Agent Deployment Guide](./deployment/agent-deployment-guide.md) - Agent configuration and deployment
- [PostgreSQL HA Setup](./deployment/postgresql-ha-setup.md) - Database high availability
- [Production Runbook](./deployment/production-runbook.md) - Step-by-step production deployment
- [Production Launch Checklist](./deployment/production-launch-checklist.md) - Pre-launch verification
- [Rollback Procedures](./deployment/rollback-procedures.md) - Emergency rollback steps

### Operations
- [Operator Manual](./operator-manual.md) - Day-to-day operations, maintenance, and emergency procedures
- [Troubleshooting Guide](./troubleshooting.md) - Common issues and solutions
- [Best Practices](./best-practices.md) - Security, performance, and operational recommendations

### Security
- [Authentication Flows Review](./security/authentication_flows_review.md) - Security assessment of auth mechanisms

### Testing & Resilience
- [Disaster Recovery Procedures](./testing/disaster-recovery-procedures.md) - DR testing and validation
- [Failover Procedures](./testing/failover-procedures.md) - HA failover testing
- [Incident Response](./testing/incident-response.md) - Incident handling procedures
- [Security Verification Checklist](./testing/security-verification-checklist.md) - Pre-launch security checks

### User Guides
- [Application Policies](./user-guides/app-policies.md) - Policy-based access control for applications
- [Dynamic Secrets](./user-guides/dynamic-secrets.md) - On-demand credential generation
- [Templates](./guides/templates.md) - Secret injection into configuration files
