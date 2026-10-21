# Gaoxy migration preflight

Date: 2026-10-22. Status: **BLOCKED_UPSTREAM** for complete Bandit replacement.

This report records compatibility findings and the proposed migration boundary.
It does not implement the replacement. The upstream prerequisite is
[gsmlg-dev/gaoxy#5](https://github.com/gsmlg-dev/gaoxy/issues/5), a Feature labeled
`internal request` with severity `blocker`.

## Agent skills

- [$elixir-thinking](/home/gao/.agents/skills/elixir-thinking/SKILL.md) -- keep dependency and configuration changes explicit.
- [$phoenix-thinking](/home/gao/.agents/skills/phoenix-thinking/SKILL.md) -- preserve Endpoint supervision and WebSocket peer data.
- [$test-driven-development](/home/gao/.agents/skills/test-driven-development/SKILL.md) -- retain meaningful listener and certificate regressions.
- [$verification-before-completion](/home/gao/.agents/skills/verification-before-completion/SKILL.md) -- qualify actual package, network, and release behavior separately.

## Verified snapshots

- SecretHub `main`: `e1d09953bc1393e389e7fea1d03827c5358a5e1c`.
- Gaoxy `main`: `0f8b777590c16f3d3a2a334b5653a4c817f7b79a`, checkout version 0.8.0.
- Live Hex latest for `gaoxy`, `gaoxy_http`, and `gaoxy_websock_adapter`: 0.7.0.
  Version 0.8.0 was unavailable from the Hex release API at inspection time.
- SecretHub currently locks Phoenix 1.8.15, Bandit 1.12.5,
  WebsockAdapter 0.6.0, and ThousandIsland 1.5.0.

The local Gaoxy version and its documentation must not be treated as proof that
the same version is available to a Hex consumer. Neither the inspected main
source nor the local v0.7.0 source supports the required client-verification
options.

## Blocking contract

The approved [unified Agent listener design](../superpowers/specs/2026-10-20-unified-agent-port-design.md)
uses one HTTPS listener for enrollment and runtime. Its contract is:

1. A connection without a client certificate can reach enrollment.
2. Any supplied client certificate must be verified against the configured CA;
   an untrusted certificate fails TLS.
3. A trusted runtime WebSocket must receive the real peer certificate through
   `connect_info.peer_data.ssl_cert`, then pass Core PKI identity and revocation
   checks. A missing certificate or forged HTTP header cannot authorize runtime.

SecretHub configures `verify: :verify_peer`, `cacertfile`, and
`fail_if_no_peer_cert: false`. Requiring certificate presence at TLS handshake
would break first enrollment.

Gaoxy currently rejects all three option names in both its public service TLS
configuration and Phoenix HTTPS configuration. Its backend construction also
does not forward them, and its capabilities declare `mtls: :unsupported`.
Pure configuration probes against the cited main SHA returned
`{:error, {:unknown_options, [key]}}` for each key; Phoenix listener construction
also rejected each option. These probes opened no sockets.

Hell already accepts public OTP SSL options. Gaoxy already has peer-certificate
propagation seams for H1 and H2, but that does not prove verified client identity
works over a real connection. The upstream request covers public option support,
forwarding, handshake/peer-data qualification, documentation, and a published
package cohort. No local transport patch or weakened verification is allowed.

## Proposed migration boundary

The recommended approach is a complete replacement after the upstream fix is
released. A preliminary management/Human-only migration could proceed as a
separate phase, but would retain Bandit for Agent TLS and would not complete the
requested replacement. That mixed-server phase has not been selected or started.

| Area | Required change after the blocker is resolved |
| --- | --- |
| Dependencies | Replace direct Bandit dependencies in `apps/secrethub_web/mix.exs` and `apps/secrethub_human/mix.exs`; resolve a published Gaoxy cohort containing the fix. |
| Phoenix WebSocket bridge | Use application `:websock_adapter` with `hex: :gaoxy_websock_adapter` and the compatible Gaoxy version. Update Human's existing direct adapter requirement and keep the umbrella dependency graph consistent. |
| Endpoint adapters | Switch management, Human, Agent, and the inert Machine compatibility configuration to `Gaoxy.PhoenixAdapter`. The retired Machine listener remains disabled. |
| Agent TLS configuration | Migrate production and generated development options from the Bandit/ThousandIsland layout to supported public Gaoxy options. Preserve optional certificate presence, peer verification, TLS versions, and IPv4/IPv6 binding behavior. |
| Startup checks | Update both `AgentEndpointManager` and `SecretHub.Core.Preflight` to validate the new option layout without weakening the existing trust contract. |
| Certificate renewal | Preserve the manager's terminate/delete/restart Endpoint lifecycle and qualify replacement TLS material. Do not assume an undocumented in-place Gaoxy certificate reload. |
| Fixtures and callers | Migrate adapter child specifications, listener-port lookups, direct `Bandit.start_link/1` fixtures, and the OpenSSH qualification listener. |
| Runtime and packaging | Verify ordinary HTTP, body handling, standard WebSocket Upgrade, listener startup, and Core release assembly with the resolved dependencies. |
| Documentation | Update current server/configuration guidance; preserve historical plans and acceptance evidence. |

The published Gaoxy integration uses the forked WebsockAdapter package because
Phoenix expects the `:websock_adapter` application name. The fork declares Bandit
as optional. Removing direct dependencies and resolving the effective graph must
confirm that Bandit and ThousandIsland are no longer required or started.

This replacement does not add HTTP/3 or H2 extended CONNECT. Gaoxy's WebSocket
message limit and unsupported compression options need comparison with actual
SecretHub usage during implementation. Existing routes, machine identity,
management proxy authentication, enrollment state, and the previously excluded
configuration scope remain outside the migration's behavioral changes.

## Focused acceptance after the dependency update

- Adapt and run the unified Agent TLS fixture and
  `apps/secrethub_web/test/secrethub_web/unified_agent_tls_test.exs`: anonymous
  enrollment, approval/proof enforcement, valid runtime identity, forged/missing
  identity rejection, unknown CA, revoked/wrong-type certificates, TLS 1.3, and
  server trust/hostname verification.
- Run the isolated
  `apps/secrethub_core/test/secrethub_core/agent_listener_runtime_config_test.exs`
  and `apps/secrethub_core/test/secrethub_core/preflight_listener_test.exs`.
- Adapt and run Human's endpoint isolation test with Gaoxy's public listener
  information API. Add focused adapter regressions only where existing tests do
  not cover application behavior.
- Qualify certificate replacement and port rebinding through the existing
  supervisor lifecycle in an isolated fixture. Run only selected manager cases;
  do not run that entire test file or broaden into previously excluded tests.
- Verify the effective dependency graph, scoped formatting/compilation, and Core
  release assembly. Run live listener checks only in an isolated fixture.

## Evidence and stop condition

| Check | Result |
| --- | --- |
| SecretHub adapter/dependency/configuration inventory | PASS, source inspection |
| Gaoxy public configuration rejection | PASS, no-socket reproduction of the blocker |
| Public Hex availability and WebSocket package alias | PASS, live metadata inspection |
| Complete Bandit replacement | BLOCKED_UPSTREAM, gaoxy#5 |
| SecretHub regression tests with Gaoxy | NOT RUN |
| Real TLS/WebSocket behavior with Gaoxy | NOT RUN |
| SecretHub release/package qualification with Gaoxy | NOT RUN |

Stop the blocked replacement until gaoxy#5 is resolved and SecretHub can consume
a published dependency version containing the fix. Then finalize the migration
design against that version and implement the scoped changes. This preflight
does not authorize service restarts, deployment, Vault operations, or database
changes.
