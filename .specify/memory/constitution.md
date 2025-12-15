<!--
  SYNC IMPACT REPORT
  ==================
  Version change: N/A → 1.0.0 (initial ratification)

  Added sections:
  - Core Principles: Security-First, Test-First, Audit Everything, OTP Reliability, Simplicity
  - Security Requirements section
  - Development Workflow section
  - Governance section

  Templates requiring updates:
  - .specify/templates/plan-template.md: ✅ Compatible (Constitution Check section exists)
  - .specify/templates/spec-template.md: ✅ Compatible (no constitution-specific references)
  - .specify/templates/tasks-template.md: ✅ Compatible (no constitution-specific references)
  - .specify/templates/checklist-template.md: ✅ Compatible (no constitution-specific references)
  - .specify/templates/agent-file-template.md: ✅ Compatible (no constitution-specific references)

  Follow-up TODOs: None
-->

# SecretHub Constitution

## Core Principles

### I. Security-First
All features MUST prioritize security over convenience. This is non-negotiable for a secrets management platform.

- All communications between Core and Agents MUST use mTLS
- Secrets MUST be encrypted at rest using envelope encryption
- Authentication backends MUST implement the principle of least privilege
- No plaintext secrets in logs, error messages, or debug output
- Secret exposure MUST trigger immediate revocation capabilities

**Rationale**: SecretHub's core purpose is protecting sensitive credentials. A security vulnerability undermines the entire value proposition.

### II. Test-First (NON-NEGOTIABLE)
TDD is mandatory for all security-critical code paths. Tests document expected behavior and prevent regressions.

- Write tests BEFORE implementation for authentication, authorization, and crypto operations
- Red-Green-Refactor cycle enforced for all secret engine implementations
- Integration tests required for Core-Agent communication
- Contract tests required for API endpoints
- All PRs MUST pass `mix test` and `quality` checks before merge

**Rationale**: In a secrets management system, bugs can expose credentials. Tests are the first line of defense.

### III. Audit Everything
Every operation touching secrets MUST be logged to the audit subsystem with tamper-evident hash chains.

- Audit logs MUST include: timestamp, actor, action, target, outcome
- Hash chain integrity MUST be verifiable
- Audit logs MUST NOT contain secret values (only references)
- Failed access attempts MUST be logged with full context
- Audit log retention MUST follow configured policy (hot/warm/cold tiers)

**Rationale**: Compliance requirements and incident response depend on comprehensive, trustworthy audit trails.

### IV. OTP Reliability
Leverage OTP/BEAM patterns for fault tolerance. The system MUST remain operational even when components fail.

- Use supervision trees for all long-running processes
- Agent connections MUST auto-reconnect with exponential backoff
- Local caching in Agents MUST allow operation during Core unavailability
- Lease management MUST handle graceful degradation
- GenServer state MUST be recoverable after crashes

**Rationale**: Applications depend on SecretHub for credentials. Downtime means application failures across the infrastructure.

### V. Simplicity
Start simple, avoid premature abstraction. Every added complexity MUST be justified.

- YAGNI: Do not implement features before they are needed
- Avoid unnecessary abstractions—three similar lines are better than a premature helper
- Configuration MUST have sensible defaults
- New dependencies require justification and security review
- Prefer standard library solutions over external packages

**Rationale**: Complexity is the enemy of security. Every line of code is a potential vulnerability.

## Security Requirements

These requirements apply to ALL code changes:

- **Cryptography**: Use `pgcrypto` and Erlang `:crypto` module only. No custom crypto implementations.
- **Secrets Handling**: Memory containing secrets MUST be zeroed after use where possible
- **Input Validation**: All external input MUST be validated at system boundaries
- **Certificate Management**: PKI operations MUST follow X.509 standards with proper chain validation
- **Authentication**: Support AppRole and Kubernetes ServiceAccount authentication backends
- **Authorization**: Policy engine MUST evaluate before any secret access
- **Network**: Unix Domain Sockets for local Agent-Application communication (no TCP exposure)

## Development Workflow

### Code Quality Gates
All code MUST pass these gates before merge:

1. `mix format --check-formatted` - Code formatting
2. `mix compile --warnings-as-errors` - Clean compilation
3. `mix credo --strict` - Linting
4. `mix dialyzer` - Static type analysis
5. `mix test` - All tests pass

Use `./scripts/quality-check.sh` to run all gates locally.

### Commit Standards
Follow conventional commits:
```
type(scope): subject

body

footer
```
Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### Review Requirements
- Security-critical changes require review from security-aware team member
- Database migrations require rollback testing
- API changes require contract test updates
- PKI/crypto changes require additional scrutiny

## Governance

This Constitution supersedes all other development practices for SecretHub. Deviations require explicit justification.

### Amendment Process
1. Propose amendment with rationale
2. Document impact on existing code
3. Update affected templates and documentation
4. Version bump according to semantic versioning:
   - MAJOR: Principle removal or incompatible redefinition
   - MINOR: New principle or material expansion
   - PATCH: Clarifications and wording fixes

### Compliance Verification
- All PRs MUST verify compliance with these principles
- CI pipeline enforces quality gates
- Security-critical violations block merge
- Complexity additions require documented justification

### Runtime Guidance
See `CLAUDE.md` for development environment setup and runtime guidance.

**Version**: 1.0.0 | **Ratified**: 2025-12-15 | **Last Amended**: 2025-12-15
