# SecretHub - Development TODO List

**Last Updated:** 2025-10-20
**Current Sprint:** Week 1 (Phase 1: Foundation & MVP)
**Current Focus:** Database Schema Design & Basic Infrastructure

> This TODO list tracks implementation progress against the [PLAN.md](./PLAN.md) timeline.
> For detailed technical specifications, see [DESIGN.md](./DESIGN.md).

---

## 📊 Overall Progress

### Phase 1: Foundation & MVP (Weeks 1-12)
- **Week 1**: 🟡 In Progress (40% complete)
- **Week 2-3**: ⚪ Not Started
- **Week 4-5**: ⚪ Not Started
- **Week 6-7**: ⚪ Not Started
- **Week 8-9**: ⚪ Not Started
- **Week 10-11**: ⚪ Not Started
- **Week 12**: ⚪ Not Started

### Phase 2: Production Hardening (Weeks 13-24)
- ⚪ Not Started

### Phase 3: Advanced Features (Weeks 25-28)
- ⚪ Not Started

### Phase 4: Production Launch (Weeks 29-32)
- ⚪ Not Started

---

## 🎯 Current Sprint: Week 1 - Project Setup & Infrastructure Bootstrap

**Sprint Goal:** Set up development environment, CI/CD, and basic project structure

**Team Assignments:**
- **Engineer 1 (Core Lead)**: Database schema design, Core service setup
- **Engineer 2 (Agent/Infra Lead)**: Infrastructure, Agent protocol design
- **Engineer 3 (Full-stack)**: UI structure, CI/CD, documentation

### Engineer 1 (Core Lead) - Tasks

- [x] Initialize Elixir/Phoenix project for Core service
- [ ] Set up PostgreSQL schema design
  - [ ] Design secrets table schema
  - [ ] Design policies table schema
  - [ ] Design audit_logs table schema
  - [ ] Design certificates table schema
  - [ ] Design leases table schema
  - [ ] Design roles table schema (AppRole)
- [ ] Create Ecto schemas for core entities
  - [ ] `SecretHub.Shared.Schemas.Secret`
  - [ ] `SecretHub.Shared.Schemas.Policy`
  - [ ] `SecretHub.Shared.Schemas.AuditLog`
  - [ ] `SecretHub.Shared.Schemas.Certificate`
  - [ ] `SecretHub.Shared.Schemas.Lease`
  - [ ] `SecretHub.Shared.Schemas.Role`
- [ ] Write database migrations
  - [ ] Create initial secrets migration
  - [ ] Create policies migration
  - [ ] Create audit_logs migration with hash chain fields
  - [ ] Create certificates migration
  - [ ] Create leases migration
  - [ ] Create roles migration
- [ ] Set up Repo configuration in secrethub_core
  - [ ] Configure `SecretHub.Core.Repo`
  - [ ] Add repo to supervision tree
  - [ ] Test database connection

### Engineer 2 (Agent/Infra Lead) - Tasks

- [x] Initialize Elixir/OTP project for Agent
- [ ] Set up Terraform for AWS infrastructure (VPC, RDS, S3)
  - [ ] Define VPC module
  - [ ] Define RDS PostgreSQL module
  - [ ] Define S3 bucket for audit logs
  - [ ] Create development environment config
- [ ] Create Kubernetes manifests (development cluster)
  - [ ] Core service deployment
  - [ ] PostgreSQL StatefulSet (dev)
  - [ ] Redis deployment (dev)
  - [ ] Service definitions
  - [ ] ConfigMaps and Secrets
- [ ] Set up Docker build pipeline
  - [ ] Dockerfile for secrethub_core
  - [ ] Dockerfile for secrethub_agent
  - [ ] Docker Compose for local development
  - [ ] Multi-stage builds for optimization
- [ ] Design Agent <-> Core communication protocol spec
  - [ ] Define WebSocket message formats
  - [ ] Design authentication handshake flow
  - [ ] Define secret request/response protocol
  - [ ] Design lease renewal protocol
  - [ ] Document protocol in `/docs/architecture/agent-protocol.md`

### Engineer 3 (Full-stack) - Tasks

- [x] Set up Phoenix LiveView project structure
- [x] Create basic UI layout and navigation
- [x] Set up CI/CD pipeline (GitHub Actions / GitLab CI)
- [x] Initialize documentation repository
- [x] Create project README and contribution guidelines
- [ ] Enhance UI with authentication placeholder
  - [ ] Add login page scaffold
  - [ ] Add navigation sidebar
  - [ ] Create dashboard layout
- [ ] Create additional documentation
  - [ ] Add API documentation structure
  - [ ] Add deployment guide template
  - [ ] Add troubleshooting guide template

### Week 1 Deliverables

- [x] Git repositories initialized
- [x] Development environment running locally (devenv)
- [x] CI/CD pipeline building and testing (pre-commit hooks)
- [ ] Database schemas created
- [ ] Docker development environment validated
- [ ] Agent-Core protocol specification documented

---

## 📅 Upcoming: Week 2-3 - Core Service: Authentication & Basic Storage

**Goals:** Implement basic authentication and secret storage

### Engineer 1 Tasks (Not Started)

- [ ] Implement Shamir Secret Sharing for unsealing
- [ ] Build encryption/decryption module (AES-256-GCM)
- [ ] Create seal/unseal state machine
- [ ] Implement basic secret storage (CRUD operations)
- [ ] Write unit tests for encryption and storage
- [ ] API endpoint: POST /v1/sys/init
- [ ] API endpoint: POST /v1/sys/unseal

### Engineer 2 Tasks (Not Started)

- [ ] Design Agent bootstrap flow
- [ ] Create AppRole authentication backend
- [ ] Implement basic WebSocket connection handler
- [ ] Set up Phoenix Channels for Agent communication
- [ ] Write integration tests for WebSocket

### Engineer 3 Tasks (Not Started)

- [ ] Create admin login page (certificate-based)
- [ ] Build unsealing UI component
- [ ] Design dashboard layout
- [ ] Implement certificate upload for admin auth
- [ ] Write E2E tests for unsealing flow

---

## 📅 Week 4-5: PKI Engine - Certificate Authority

**Status:** ⚪ Not Started

### High-Level Goals
- [ ] Implement Root CA generation
- [ ] Implement Intermediate CA generation
- [ ] Build CSR signing logic
- [ ] Create certificate storage (PostgreSQL)
- [ ] Implement mTLS handshake for Agent connections
- [ ] Build PKI management UI

**Details:** See PLAN.md lines 98-131

---

## 📅 Week 6-7: Agent Bootstrap & Basic Functionality

**Status:** ⚪ Not Started

### High-Level Goals
- [ ] Implement AppRole authentication backend
- [ ] Agent can bootstrap with AppRole
- [ ] Agent maintains persistent WebSocket connection
- [ ] Web UI shows connected agents

**Details:** See PLAN.md lines 134-166

---

## 📅 Week 8-9: Static Secrets & Basic Policy Engine

**Status:** ⚪ Not Started

### High-Level Goals
- [ ] Static secret engine implementation
- [ ] Basic policy evaluation logic
- [ ] Agent secret request handler
- [ ] Secret management UI (CRUD)
- [ ] Policy editor component

**Details:** See PLAN.md lines 169-201

---

## 📅 Week 10-11: Basic Audit Logging

**Status:** ⚪ Not Started

### High-Level Goals
- [ ] Audit log schema with hash chain
- [ ] Audit event collection module
- [ ] HMAC signing for logs
- [ ] Audit log viewer UI
- [ ] Search and filter functionality

**Details:** See PLAN.md lines 204-235

---

## 📅 Week 12: MVP Integration & Testing

**Status:** ⚪ Not Started

### High-Level Goals
- [ ] End-to-end integration testing
- [ ] Fix critical bugs
- [ ] Performance testing (100 agents)
- [ ] Security review of authentication flows
- [ ] MVP deployment guide

**Details:** See PLAN.md lines 238-257

---

## 🔧 Technical Debt & Future Improvements

### Known Issues
- None yet (project just started)

### Performance Optimizations
- To be identified during Week 12 testing

### Security Reviews
- [ ] Week 12: Initial security review
- [ ] Week 29: Comprehensive security audit
- [ ] Week 29: Penetration testing

---

## 📝 Notes & Decisions

### 2025-10-20
- ✅ Completed initial project setup
- ✅ Created CLAUDE.md for AI-assisted development
- ✅ Development environment using devenv with Nix
- ✅ Frontend uses Bun instead of npm
- 🎯 Next focus: Database schema design (Week 1 remaining tasks)

### Architecture Decisions
- Using Elixir umbrella project structure
- PostgreSQL 16 with uuid-ossp and pgcrypto extensions
- mTLS for all Core ↔ Agent communication
- Audit logs use hash chains for tamper-evidence
- Oban for background job processing

---

## 🚀 Quick Reference

### How to Update This File

When completing a task:
1. Change `[ ]` to `[x]`
2. Update the progress percentage in Overall Progress
3. Add notes in the Notes section if significant
4. Commit with message: `docs(todo): mark [task-name] as complete`

### Related Documents
- [PLAN.md](./PLAN.md) - Detailed 32-week project plan
- [DESIGN.md](./DESIGN.md) - Technical design specifications
- [CLAUDE.md](./CLAUDE.md) - AI development guidance
- [README.md](./README.md) - Project overview and quick start

### Sprint Planning
- Sprint length: 2 weeks
- Current sprint: Week 1 (single week setup sprint)
- Next sprint review: End of Week 1
- Next sprint planning: Start of Week 2

---

**Status Legend:**
- ⚪ Not Started
- 🟡 In Progress
- 🟢 Completed
- 🔴 Blocked
- ⏸️ On Hold
