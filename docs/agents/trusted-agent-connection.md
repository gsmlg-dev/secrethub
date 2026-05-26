# Trusted Agent-Core Connection Design

**Date:** 2026-05-24
**Status:** First implementation slice implemented

This note records the agreed design for the trusted connection between SecretHub Agents and SecretHub Core. It supersedes older agent runtime documentation that describes AppRole or pending-token runtime access.

## Problem

Before this implementation slice, the mTLS path was partially implemented but not wired end to end. Core had a dedicated trusted Agent endpoint, enrollment could issue a certificate, and the runtime socket could derive identity from a peer certificate. The Agent startup path still relied on static `core_url`, `cert_path`, `key_path`, and `ca_path` configuration and did not have one owner for enrollment, material loading, trusted runtime startup, finalization, and renewal scheduling.

The result was that the trusted Agent-to-Core runtime connection did not work reliably as the single production path.

## Decisions

1. Runtime identity is the Core-issued client certificate only. AppRole, pending token, and approval state are enrollment mechanisms only. They never authorize runtime secret access.
2. Trusted Agent runtime uses a dedicated mTLS listener separate from the normal web/API endpoint. Normal browser/API traffic stays on the standard endpoint and does not require a client certificate.
3. First boot runs enrollment mode. The Agent discovers host identity, creates a pending enrollment through the normal Core API, waits for approval, submits a CSR, receives trusted material, connects over mTLS, and finalizes only after the runtime WebSocket is accepted.
4. The Agent generates a separate TLS client keypair for runtime. The SSH host key proves stable host identity and signs a CSR-binding challenge, but it is not reused as the TLS client private key.
5. Agent certificates have explicit identity fields:
   - Subject CN: `agent_id`
   - Organization: `SecretHub Agents`
   - URI SAN: `urn:secrethub:agent:<agent_id>`
   - URI SAN: `urn:secrethub:hostkey-sha256:<fingerprint-without-SHA256-prefix>`
   - DNS SANs: enrollment hostname/FQDN values only when valid
   - Extended Key Usage: `clientAuth`
   - Key Usage: `digitalSignature`
6. Agent certificate TTL defaults to 30 days. The maximum is 90 days. Renewal begins around 70 percent of lifetime.
7. Production enrollment bootstrap uses HTTPS with server verification. Plain HTTP is allowed only when explicit development mode is enabled.
8. The same internal SecretHub CA can issue trusted Agent endpoint server certificates and Agent client certificates for now, but verification must enforce EKU separation:
   - Core server certificate: `serverAuth`
   - Agent client certificate: `clientAuth`
9. Recovery behavior is explicit:
   - Missing local material: enter enrollment mode.
   - Expired certificate: attempt renewal when the current material is still known to Core; otherwise re-enroll.
   - Revoked certificate: do not silently recover. Require operator approval for a new enrollment.
   - Unknown certificate fingerprint: re-enroll and surface the event as suspicious for operator approval.
   - Changed machine identity: create a new pending enrollment.
10. Enrollment finalizes only after the Agent connects over mTLS, joins `agent:runtime`, and receives an accepted reply from Core.
11. The Agent persists trusted material in a state directory and auto-loads it on startup. Explicit path configuration remains an override.
12. Renewal uses only the dedicated mTLS trust surface. Primary renewal is an `agent:runtime` channel RPC.
13. TLS handshake and application authorization have separate responsibilities:
   - TLS handshake requires and chain-validates the client certificate.
   - Phoenix/Core verification checks stored fingerprint, certificate state, certificate type, EKU, SANs, enrollment binding, and Agent status.
14. A single Agent startup coordinator owns material loading, enrollment, runtime startup, finalization, and renewal scheduling.
15. `SecretHub.Agent.Connection` remains the low-level Phoenix Socket client. Lifecycle orchestration moves out of `SecretHub.Agent.ConnectionManager` into the startup coordinator.

## Current Code Touchpoints

- Agent enrollment client: `apps/secrethub_agent/lib/secrethub_agent/enrollment.ex`
- Agent host-key discovery: `apps/secrethub_agent/lib/secrethub_agent/host_key.ex`
- Agent runtime connection: `apps/secrethub_agent/lib/secrethub_agent/connection.ex`
- Agent application supervisor: `apps/secrethub_agent/lib/secrethub_agent/application.ex`
- Core enrollment workflow: `apps/secrethub_core/lib/secrethub_core/agents/enrollment.ex`
- Core certificate issuer: `apps/secrethub_core/lib/secrethub_core/pki/issuer.ex`
- Core certificate verifier: `apps/secrethub_core/lib/secrethub_core/pki/verifier.ex`
- Trusted endpoint: `apps/secrethub_web/lib/secret_hub/web/agent_endpoint.ex`
- Trusted socket: `apps/secrethub_web/lib/secret_hub/web/channels/agent_trusted_socket.ex`
- Runtime channel: `apps/secrethub_web/lib/secret_hub/web/channels/agent_runtime_channel.ex`
- Enrollment controller: `apps/secrethub_web/lib/secret_hub/web/controllers/agent_enrollment_controller.ex`

## First Implementation Slice

Build the vertical happy path:

1. Store the SSH host public key during pending enrollment.
2. Generate a separate TLS keypair in the Agent.
3. Submit a CSR plus an SSH-host-key proof over a Core-issued challenge.
4. Verify the proof in Core before issuing an Agent client certificate.
5. Enforce certificate type, status, EKU, SANs, revocation, expiry, and Agent status during trusted socket connect.
6. Persist trusted material and identity metadata in an Agent state directory.
7. Add a startup coordinator that loads material or enrolls, then starts trusted runtime.
8. Finalize enrollment only after `agent:runtime` join returns accepted.

Out of scope for this first slice: automatic renewal implementation, multi-endpoint failover rewrite, and operator UX for suspicious re-enrollment. Those items depend on the vertical path being reliable first.

## State Directory

Default path: `/var/lib/secrethub-agent`

Development override: `SECRET_HUB_AGENT_STATE_DIR`

Files:

```text
agent-cert.pem
agent-key.pem
ca-chain.pem
connect-info.json
identity.json
pending.json
```

Permissions:

- State directory: `0700`
- Private key: `0600`
- Certificate, CA chain, connect-info, identity: `0644`
- Pending token: `0600`

`identity.json` contains:

```json
{
  "agent_id": "agent-example",
  "enrollment_id": "00000000-0000-0000-0000-000000000000",
  "certificate_fingerprint": "sha256-fingerprint",
  "certificate_serial": "serial",
  "valid_until": "2026-06-23T00:00:00Z",
  "ssh_host_key_fingerprint": "SHA256:example",
  "hostname": "agent-host",
  "fqdn": "agent-host.example.internal",
  "machine_id": "machine-id"
}
```

## Runtime Protocol

The Agent connects to:

```text
wss://<trusted-agent-endpoint-host>:<trusted-agent-endpoint-port>/agent/socket/websocket
```

Then it joins:

```text
agent:runtime
```

Core accepts the join only when `AgentTrustedSocket.connect/3` has assigned identity derived from the verified TLS peer certificate. `AgentRuntimeChannel.join/3` ignores any client-supplied `agent_id` and registers the connection under the certificate-derived Agent identity.

The accepted join reply includes the certificate-derived fields used by the Agent `on_runtime_accepted` callback:

```json
{
  "status": "accepted",
  "agent_id": "agent-example",
  "certificate_serial": "serial",
  "certificate_fingerprint": "sha256-fingerprint",
  "certificate_id": "00000000-0000-0000-0000-000000000000"
}
```

## Security Invariants

- Pending tokens authorize only enrollment polling, CSR submission, connect-info fetch, and finalization.
- Runtime secret access requires mTLS identity.
- Client-supplied Agent identity never overrides certificate-derived identity.
- Revocation wins over local state and retry policy.
- A TLS key compromise does not compromise the SSH host identity.
- HTTP bootstrap is development-only and must be explicit.
