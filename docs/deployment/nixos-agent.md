# Deploy an Agent with NixOS flakes

Import `secrethub.nixosModules.agent` into the existing NixOS host configuration.
It builds the native Agent release and runs `secrethub-agent.service` as an
unprivileged dynamic user. Supported module targets are `x86_64-linux` and
`aarch64-linux`.

## Core prerequisites

Core must be initialized, unsealed, and configured with its Agent PKI. The host
needs outbound access to both of these endpoints:

- **Enrollment HTTPS URL**, such as `https://enroll.secrethub.example.com`.
  Route it to Core's machine listener (`SECRET_HUB_MACHINE_ENDPOINT_SERVER=true`,
  private backend port `4668` by default). It must serve `/v1/agent/enrollments`.
  A fresh Agent cannot use the operator-only management URL protected by Caddy
  client-certificate authentication.
- **Agent runtime mTLS endpoint**, such as `agents.secrethub.example.com:4665`.
  Enable `SECRET_HUB_AGENT_ENDPOINT_SERVER=true` and set
  `SECRET_HUB_AGENT_ENDPOINT_HOST` to a hostname reachable from the Agent, with
  matching server certificate SANs and the endpoint's certificate/key/client CA
  paths. Preserve TLS through to Core, directly or through TCP passthrough.

Core advertises the runtime WebSocket endpoint during enrollment. `coreUrl` is
the enrollment URL; the Agent obtains its runtime URL, client certificate, and
Agent ID from Core. See the [runtime contract](../security/runtime-contract.md)
for the full Core configuration and listener boundaries.

## Host flake

Add the input and module to your existing host flake. Keep the host's existing
hardware, boot, and filesystem configuration in `configuration.nix`.

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    secrethub.url = "github:gsmlg-dev/secrethub";
  };

  outputs = { nixpkgs, secrethub, ... }: {
    nixosConfigurations.agent-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux"; # or aarch64-linux
      modules = [
        ./configuration.nix
        secrethub.nixosModules.agent
        {
          services.secrethub-agent = {
            enable = true;
            coreUrl = "https://enroll.secrethub.example.com";
            hostKeyPath = "/etc/ssh/ssh_host_rsa_key";

            # For an enrollment server signed by a private CA:
            # enrollmentCaPath = "/etc/secrethub/enrollment-ca.pem";
          };
        }
      ];
    };
  };
}
```

Pin the SecretHub input in `flake.lock` to a revision containing this module
update. To try an unpublished local checkout, override the input when building:

```bash
nixos-rebuild build --flake .#agent-host \
  --override-input secrethub git+file:///absolute/path/to/secrethub
```

The configured host key must already exist and be an unencrypted RSA or ECDSA
SSH private key. Ed25519 is not supported for Agent enrollment. When NixOS
OpenSSH is enabled, the Agent waits for its host-key generation service. For
hosts without OpenSSH, provision a stable supported host key before activation.
Keep its source permissions private; systemd `LoadCredential` makes a private
copy readable by the Agent. Always use a **quoted runtime path**, as above,
rather than a Nix path literal or `builtins.readFile` for the private key.

The optional enrollment CA also uses a credential copy. Omitting it uses the
normal trust store; configuring it retains HTTPS peer verification. It is
separate from the Core-issued CA chain used for runtime mTLS.

## Activate and enroll

Build the host configuration first, then activate it on the target host:

```bash
nixos-rebuild build --flake .#agent-host
sudo nixos-rebuild switch --flake .#agent-host
sudo systemctl status secrethub-agent.service
sudo journalctl -u secrethub-agent.service -f
```

For a local checkout, use the same `--override-input` on both commands.

1. The Agent submits a pending enrollment using the host's SSH public identity.
2. Open `/admin/pending-agents` through the existing Caddy mTLS management URL.
   Verify the hostname and SSH fingerprint, then approve the enrollment.
3. The Agent generates its own TLS keypair, obtains its certificate, connects to
   Core's advertised mTLS endpoint, and finalizes enrollment.
4. Confirm the Agent is connected in `/admin/agents` and its heartbeat advances.
   A running systemd unit or local socket alone does not prove Core connectivity.

No AppRole credentials or manually selected `agentId` are required. The old
`agentId` option is accepted with a deprecation warning and ignored.

## State and local consumers

| Path | Purpose |
|------|---------|
| `/var/lib/secrethub-agent` | Persistent identity, certificate, key, CA chain, and connect-info; mode `0700` |
| `/var/lib/secrethub-agent/client-auth` | Persistent client-auth PKI bundles |
| `/run/secrethub-agent/agent.sock` | Local Agent socket |
| `/run/secrethub-agent` | Writable release runtime files; recreated on boot |

systemd owns these directories. Enrollment identity survives restarts and
package upgrades; preserve the state directory when replacing a host. Damaged
or partial identity fails preflight and is not automatically replaced by a new
enrollment. Erlang distribution is disabled and the service creates a temporary
process cookie outside the Nix store.

The Agent socket is mode `0600`, and its runtime directory is private. Local
consumers need the Agent UID or root access as well as their existing application
certificate/proof authorization. Adding a consumer to a group does not grant
socket access. No inbound Agent firewall port is opened.

## Verify the package and module

From the SecretHub checkout:

```bash
nix build .#secrethub-agent
nix build .#checks.x86_64-linux.agent-module
```

Use `aarch64-linux` for the check on an ARM host. The scoped check evaluates the
NixOS service and runs the packaged Agent's real preflight with temporary test
host keys, both with and without a private enrollment CA. It does not contact
Core; live enrollment and runtime connection still need the activation checks
above.
