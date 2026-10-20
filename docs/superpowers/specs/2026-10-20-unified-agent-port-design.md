# One Agent listener for enrollment and runtime

The approved deployment has two service listeners: the existing management
listener and one Agent TLS listener, normally 4665. Agent enrollment, approval
polling, CSR submission, connection information, finalization, and trusted
WebSocket runtime all use the Agent listener. There is no separate enrollment
listener on 4668. Management remains behind the existing Caddy operator mTLS
boundary.

## TLS and authorization

The Agent listener uses a server certificate and key and verifies any presented
client certificate against the configured internal CA (`verify_peer`). TLS
permits a missing client certificate so a new machine can enroll. An invalid
presented certificate still fails the handshake. Do not install a permissive
verification callback.

The trusted socket continues to obtain the real certificate from TLS peer data
and validate it through `SecretHub.Core.PKI.Verifier`. Missing, expired, revoked,
wrong-type, unrecognized, or inactive-machine identities cannot authenticate.
Enrollment tokens, request headers, URL parameters, and approval status never
substitute for the runtime certificate. Existing approval, SSH host-key proof,
CSR binding, and finalization checks remain in force.

Existing machine HTTP APIs retain their explicit route set and existing token
or proof authorization on the Agent listener. Reuse `MachineRouter` rather than
copying route definitions. No management routes or browser sockets are mounted
on that listener. `MachineEndpoint` is no longer a supervised listener.

## Startup and configuration

Use the existing `SECRET_HUB_AGENT_ENDPOINT_*` server, host, port, certificate,
key, and CA settings. The existing management and Agent ports must differ.
Retire the separate `SECRET_HUB_MACHINE_ENDPOINT_*` listener settings. Retain
the old endpoint module only as an inert compatibility module where needed.

Configured TLS material takes precedence over development CA issuance so the
listener can start before enrollment. Development fallback may generate server
material from an already initialized, unsealed CA. A fresh development setup
must initialize/unseal the Vault and set up its CA before restarting Core to
start this listener; it must not rely on an unreachable connect-info request.

The Agent TOML has one enrollment address, for example
`core_url = "https://core.example.net:4665"`. With an internal CA, provision
`enrollment_ca_path` out of band. Continue verifying the server certificate and
hostname. Core advertises the runtime WebSocket address on the same host/port.
Already enrolled Agents keep their saved identity and connection information;
no state is silently removed or rewritten.

## Acceptance

- Only management and Agent listeners are supervised; the separate machine
  listener cannot be started by the retired production enable setting.
- A real HTTPS connection without a client certificate reaches enrollment.
- Enrollment before approval and without correct pending-token/SSH proof fails.
- The same TLS listener serves trusted WSS; missing or invalid runtime identity
  cannot join, and a valid approved machine identity can.
- Unknown presented client certificates fail TLS; untrusted server chains and
  incorrect server names fail Agent-side verification.
- Existing machine API authorization and rate limits remain in force;
  management paths are absent from the Agent listener.
- Scoped configuration, preflight, enrollment, and certificate/runtime tests
  pass. Document actual TLS test evidence and any unexecuted checks.

No release, deployment, service restart, Vault mutation, protocol expansion, or
management authentication change is included in this implementation.
