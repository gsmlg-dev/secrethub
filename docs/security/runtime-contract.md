# Qualified runtime contract

This work qualifies Linux amd64 OCI Core and Agent releases with PostgreSQL 16.
Builds and source tests alone do not establish artifact acceptance. The final
candidate report must identify the exact accepted images. Other platforms and
the standalone embedded-database image are not qualified by this work.

## Runtime inputs

`config/core_runtime.exs` and `config/agent_runtime.exs` remain separate release
inputs. A required value may be supplied as `NAME` or `NAME_FILE`, never both.
Files are read at runtime; trailing line endings are removed. Missing, empty,
oversized, unreadable and Nix-store inputs fail with a bounded error containing
the input name, never its value or file path. Do not put deployment secrets in
source, build arguments, image layers, the Nix store, or exported test evidence.

Core requires `DATABASE_URL`, `SECRET_KEY_BASE` (at least 64 bytes), stable
`SECRET_HUB_CLUSTER_NODE_ID`, `AUDIT_HMAC_KEY`, `AUDIT_HMAC_KEY_ID`, and
`SECRET_HUB_MANAGEMENT_ORIGIN` (canonical HTTPS origin). `AUDIT_HMAC_KEY` is
standard Base64 for 32–64 random key bytes. Signing uses signature version 2 and
authenticates its key ID and hash version. These signature versions are separate
from audit hash versions.

`AUDIT_HMAC_VERIFICATION_KEYS[_FILE]` is optional JSON mapping historical key IDs
to Base64 key bytes. Historical unsigned metadata/version-1 signatures require
an explicitly supplied `legacy` key. Preserve the actual historical signing
material independently of SecretHub; the active key never substitutes for an
unknown historical key. Do not rotate a production key until old entries have
been verified with the proposed keyring. No rotation operation is implemented
or authorized by this change.

Agent accepts these required settings from `/etc/secrethub/agent.toml`, or a
file selected with `SECRET_HUB_AGENT_CONFIG_FILE`: `core_url` (HTTPS
enrollment/machine URL), `host_key_path`, `state_dir`, `socket_path`, and
`client_auth_bundle_dir`. Existing environment inputs
`SECRET_HUB_AGENT_CORE_URL`, `SECRET_HUB_AGENT_HOST_KEY_PATH`,
`SECRET_HUB_AGENT_STATE_DIR`, `SECRET_HUB_AGENT_SOCKET_PATH`, and
`SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR` (including their `_FILE` forms) override
the corresponding file values. If the default file is absent, environment-only
configuration remains supported. Explicitly selected missing files and invalid
files fail startup with bounded, redacted errors. See the
[Agent configuration guide](../deployment/agent-deployment-guide.md) for all
options and precedence. Agent does not read Core database, Phoenix signing, or
Human subsystem secrets. An optional TOML `enrollment_ca_path` or environment
`SECRET_HUB_AGENT_ENROLLMENT_CA_PATH` supplies an existing private enrollment TLS
CA bundle; HTTPS still verifies the peer. Otherwise the existing operating-system
trust store is used. Agent preflight rejects unreadable/malformed configured CA
material. This CA input does not replace the persisted Core-issued runtime chain. The host
key must be an existing supported RSA/ECDSA identity readable by the service UID
without world access. Agent preflight refuses partially present identity files;
it never fixes damaged identity by re-enrolling automatically.

The selected profile explicitly uses `RELEASE_DISTRIBUTION=none`. Its release
environment sets that default and disables VM crash dumps, which can contain
process secrets. Distributed launch is unsupported by this qualification.

## Listener boundary

Management HTTP binds `127.0.0.1:4664` by default. The existing Caddy mTLS ingress
authenticates the operator; SecretHub uses its transport peer, CSRF, and exact
public Origin. `SECRET_HUB_MANAGEMENT_BIND_IP` and `SECRET_HUB_TRUSTED_PROXY_IP`
may select an explicit private IPv4 address. Wildcard/public management binding
is rejected. Never expose a loopback proxy tunnel to untrusted callers.

### HTTPS termination and LiveView origins

Set `SECRET_HUB_MANAGEMENT_ORIGIN` to the public HTTPS origin, including a port
when it differs from 443. The backend remains HTTP; `PHX_HOST`, its private port,
and forwarded headers do not define the allowed browser origins. For example:

```sh
SECRET_HUB_MANAGEMENT_ORIGIN=https://secrethub.example.com
SECRET_HUB_MANAGEMENT_ALLOWED_ORIGINS=https://admin.example.com
SECRET_HUB_MANAGEMENT_BIND_IP=127.0.0.1
SECRET_HUB_TRUSTED_PROXY_IP=127.0.0.1
PORT=4664
```

`SECRET_HUB_MANAGEMENT_ALLOWED_ORIGINS[_FILE]` is an optional comma-separated list
of additional exact HTTPS origins. The canonical origin is always included.
Both the private ingress check and Phoenix's WebSocket/longpoll origin checks
use this list before socket dispatch. Wildcard hosts, HTTP, credentials, paths,
queries, fragments and invalid ports are rejected at startup. Without the
optional list, only the canonical origin is accepted. Origin checking stays
enabled even when Caddy terminates HTTPS.

Caddy must require client certificates on **every** configured public hostname
and proxy only to the private backend. For host-networked Core, the existing
`reverse_proxy 127.0.0.1:4664` can serve both hostnames. Only the configured proxy
transport peer may reach management routes; forwarding headers cannot authorize
another peer or allow an unrelated browser origin. This setting does not add an
application login or a native admin TLS listener.

Machine enrollment/token HTTPS and Agent runtime WSS share one Agent listener,
enabled with `SECRET_HUB_AGENT_ENDPOINT_SERVER=true`, normally port `4665`.
Its host, port, server certificate, private key, and client CA use the existing
`SECRET_HUB_AGENT_ENDPOINT_HOST`, `SECRET_HUB_AGENT_ENDPOINT_PORT`,
`SECRET_HUB_AGENT_ENDPOINT_CERT_PATH`, `SECRET_HUB_AGENT_ENDPOINT_KEY_PATH`, and
`SECRET_HUB_AGENT_ENDPOINT_CA_CERT_PATH` inputs. TLS 1.2/1.3 verifies presented
client certificates while allowing bootstrap HTTPS without one. Runtime socket
admission still requires a valid Core-issued Agent certificate; machine API
token/proof authorization is unchanged and does not grant runtime identity.
Management routes are absent on this listener. Core has two service listeners:
the existing management port `4664` and the Agent port `4665`, which must differ.
There is no `4668` listener; retired `SECRET_HUB_MACHINE_*` flags cannot start one.
The former extra Core admin TLS listener is refused; Human endpoints are disabled.
See the [Agent deployment guide](../deployment/agent-deployment-guide.md#configure-the-core-agent-listener)
for certificate provisioning, enrollment CA trust, and development startup steps.

## Preflight and probes

Run the built release as its real service UID with final persistent mounts:

```
bin/secrethub_core eval 'SecretHub.Core.Release.migrate()'
bin/secrethub_core eval 'SecretHub.Core.Release.preflight()'
bin/secrethub_agent eval 'SecretHub.Agent.Preflight.run()'
```

Migration is explicit and never resets/seeds at boot. Preflight prints only
boolean checks and role; a failed check exits nonzero. Core requires the exact
artifact migration set, readable mTLS material, configured required listeners,
runtime signing material, intended features, and writable temporary directory.
An empty database fails preflight until explicitly migrated. Agent tests its
directory writeability, existing host-key access and identity integrity.

The Core container probe uses process liveness, so an expected sealed restart
does not cause a restart loop. Secret readiness is a separate operator/consumer
gate. Persistent Agent identity, PKI bundle and consumer watermark locations
must survive replacement of containers. A healthy Agent socket proves local
responsiveness, not connection to Core or consumer convergence.

## Current limitations

Agent proof authentication, fresh Core authorization and revision-scoped caching
are implemented. The [combined candidate report](prelaunch/candidate11/acceptance-report.json)
records scoped source regressions and actual final-artifact enrollment, static
consumer, cache and PKI checks. Missing CA trust and offline authorization fail
closed in the selected checks. Implementation and isolated qualification are
complete. Production preflight/cutover remain operator-owned; the existing
backup system owns PostgreSQL backup delivery and requires no agent verification.
Console output is forwarded by Docker to the existing remote logging system; its forwarding and alert configuration are externally managed.
Source checks alone do not qualify static delivery or PKI consumer enforcement for launch.
Historical dynamic leases and rotation jobs need an operator inventory before
adopting the restricted profile; disabling unfinished features does not revoke
credentials already issued by older configurations.
