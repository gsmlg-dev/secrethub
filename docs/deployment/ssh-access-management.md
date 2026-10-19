# Managed SSH access

SSH signing and public lookups have passed native Linux x86_64 qualification
with `phoenix_socket_client` 0.8.7 and `http_web_socket` 0.21.14, including real
Core/Agent/OpenSSH login and revocation. These fixed dependency versions are
required for private-response confidentiality. SSH remains disabled by default.
See the [qualification record](../testing/ssh-access-evidence.md) for exact
evidence, remaining lint debt and unexecuted target-runtime checks. Installation
examples do not establish deployment acceptance.

SecretHub manages source signing identities, destination authorized keys and host
trust from one directed policy. A rule binds a source machine/group **and Unix
user** to a destination machine/group **and Unix user**. Default is deny; any
matching enabled deny overrides every allow. Group membership remains live, so
membership changes preview the access gained or lost before confirmation.

This feature requires Linux peer credentials, an enrolled Agent with a current
Core-issued runtime certificate, and an unsealed reachable Core. See the
[trusted Agent contract](../agents/trusted-agent-connection.md) and
[Agent deployment guide](agent-deployment-guide.md) for enrollment and release
installation. Management remains behind the existing Caddy mTLS proxy.

## Enable the local sockets

SSH is disabled by default. Add these optional fields to the Agent TOML, keeping
the existing five required settings:

```toml
ssh_lookup_enabled = true
ssh_lookup_socket_path = "/run/secrethub-ssh/lookup.sock"
ssh_lookup_socket_group = "secrethub-ssh-lookup"
ssh_signing_enabled = true
ssh_signing_socket_path = "/run/secrethub-ssh-signing/agent.sock"
ssh_signing_socket_group = "secrethub-ssh-signing"
```

A destination that only accepts SSH connections can enable lookup alone. A source
needs lookup for host trust and signing for its SSH-agent identities. Each field
also has a corresponding `SECRET_HUB_AGENT_SSH_*` environment override, for
example `SECRET_HUB_AGENT_SSH_LOOKUP_SOCKET_PATH`.

Provision separate static groups and runtime directories before Agent startup.
Parents must be owned by root or the Agent service UID, mode `0750`, with their
respective group. Group members may traverse the directory but must not be able
to replace its socket. The Agent creates each socket with mode `0660`. Keep both
sockets outside private Agent state and outside the existing application socket
directory. Ancestor directories must not be symlinks or group/world writable.

Add source Unix users to both groups. Add `nobody` only to the lookup group;
never give this public helper account access to the signing group. The Agent
service needs both enabled groups as supplementary groups. Existing processes
need refreshed supplementary groups after local account configuration changes.
Group access permits a request; Core still decides authorization for that exact
machine and kernel-derived user. A Core rule does not create OS accounts or
modify their group membership.

Restarting Agents to apply configuration is an operator deployment step. Private
state, TLS keys and TOML keep their existing restrictive permissions. The public
helper account must be able to execute the root-owned release and its runtime
libraries, without reading those private files.

### NixOS

The Agent module provisions separate runtime directories, static socket groups,
source-user membership and lookup access for `nobody`, while retaining
`DynamicUser` and private state:

```nix
services.secrethub-agent = {
  enable = true;
  coreUrl = "https://enroll.example.com";
  hostKeyPath = "/etc/ssh/ssh_host_rsa_key";
  ssh.lookup.enable = true;
  ssh.signing.enable = true;
  ssh.sourceUsers = [ "deploy" "builder" ];
};
```

`ssh.lookup.socketPath` / `.group` and `ssh.signing.socketPath` / `.group` can
override the defaults above. The module installs
`secrethub-fetch-ssh-keys` and `secrethub-fetch-ssh-host-keys` wrappers with the
configured public socket path. It does not install a permissive sshd policy or
replace managed account configuration. Generate and validate profiles separately.

## Approve inventory and directed rules

Open `/admin/ssh-access` through the protected management proxy:

1. Create server groups and preview/confirm their member lists. Existing
   enrolled Agents are the machine inventory.
2. Set each destination's host aliases/IPs, SSH port and actual served public host
   keys. Agent-reported candidates are advisory and require explicit approval.
   Approve only keys whose binding to that host you have verified. Endpoint
   aliases and ports cannot silently be claimed by another machine.
3. Create one source identity per machine/Unix user with its approved numeric
   UID. Generate Ed25519/RSA or import one unencrypted supported private key.
   Core encrypts it in dedicated storage; public views contain no private key.
   The same private key cannot be reused by another source identity. Duplicate
   UID aliases and changed username/UID bindings fail closed.
4. Select source machines/groups, source user, destination machines/groups and
   destination user. Preview the gained/lost concrete edges, then confirm. For
   example `build:builder → app:deploy` grants no reverse or other-user access.
   Matrix cells support batch allow/deny; existing rules can be edited, disabled
   or removed in a batch. Another matching allow can survive removal of one
   allow; use an explicit deny when that is the intended result.
5. Review prerequisite observations. A configured allow still needs current
   certificates, enabled capabilities, the local user/UID and socket access.
   Missing observations are shown as unverified. Observations do not grant access.

All changes commit atomically against the previewed revision. A changed revision
requires a fresh preview. Private import input is cleared after submission and
never rendered in the preview. Replacing a source key immediately revokes its
previous public-key grants; graceful overlapping user-key rotation is not
implemented. Host-key rotation supports explicit overlap: approve the new host
key alongside the old, deploy/verify it, then remove the old approved key.

## Install dedicated OpenSSH profiles

Generate client/server profiles in the management page using the actual
root-owned release base, socket paths, managed endpoint aliases/IPs and explicit
managed destination users. Only listed aliases receive the client restrictions;
regenerate the profile when adding managed endpoints.
The default commands preserve the requested sshd interface:

```sshconfig
AuthorizedKeysCommand /opt/secrethub-agent/bin/secrethub_agent fetch-ssh-keys %u %k
AuthorizedKeysCommandUser nobody
```

The default lookup socket is `/run/secrethub-ssh/lookup.sock`. If changed, use
`fetch-ssh-keys --socket /absolute/path %u %k`. Helpers run before Agent application
startup; they read no private TOML, TLS material or release cookie and do not
write into the release. Success prints only OpenSSH lines, a policy denial
prints nothing with exit `0`, and an unavailable/invalid lookup exits nonzero.

The generated destination profile additionally scopes `Match User` and sets:

```sshconfig
AuthorizedKeysFile none
AuthenticationMethods publickey
PubkeyAuthentication yes
TrustedUserCAKeys none
```

These restrictions make managed sshd accounts enforce Core denial even if local
key files or another user-certificate CA would otherwise authorize the key.
Validate the complete configuration, including earlier `Match` precedence:

```sh
sshd -t -f /path/to/complete_sshd_config
sshd -T -f /path/to/complete_sshd_config -C user=deploy,host=localhost,addr=127.0.0.1
```

`SecretHub.Shared.SSH.Profiles.verify_server/2` checks those effective restrictions
and the managed command. Validate every managed user and each relevant `Match`
context before installing. Profile generation does not reload sshd.

Use the generated dedicated client profile through `ssh -F`:

```sshconfig
Host destination.example 192.0.2.10
  IdentityAgent /run/secrethub-ssh-signing/agent.sock
  KnownHostsCommand /opt/secrethub-agent/bin/secrethub_agent fetch-ssh-host-keys --socket /run/secrethub-ssh/lookup.sock %I %H %p
  StrictHostKeyChecking yes
  VerifyHostKeyDNS no
  UserKnownHostsFile /dev/null
  GlobalKnownHostsFile /dev/null
  UpdateHostKeys no
  ForwardAgent no
```

`ORDER`, `HOSTNAME` and `ADDRESS` lookups are supported. Nondefault ports use
`[host]:port`; approved IPv6 aliases are supported. No lookup learns a key from
whatever a remote server presents. Check effective client settings with
`ssh -G -F /path/to/managed_ssh_config destination.example`. Both alternate
known-host files must remain disabled in this profile, and DNS trust must remain
off. Existing unrelated SSH configurations are outside this managed profile.

For tools using the SSH-agent environment:

```sh
export SSH_AUTH_SOCK=/run/secrethub-ssh-signing/agent.sock
ssh-add -l
ssh-add -L
ssh -F /path/to/managed_ssh_config deploy@destination.example
```

Identity listing and signing require an active identity and at least one
effective outgoing grant. The binary socket supports listing and signing;
`ssh-add` mutation/import operations fail. Destination account permission is
enforced by destination sshd. A signature is not bound to a destination; agent
forwarding and destination-constrained signing are outside this delivery.

## Failure, revocation and evidence

Every list/sign/lookup obtains fresh Core authorization through the certificate
authenticated runtime. The Agent fetches a private signing key only for that
request and holds no cross-request private-key cache. Seal, disconnection, audit
failure, expired/revoked credentials, missing capability and mismatched identity
all fail closed. Removing rules, membership, identities or approved endpoints
affects the next authorization even if a change notification is delayed.
An already authorized in-flight operation can finish. Established SSH sessions
continue; this feature does not terminate them. Dropping BEAM references does
not guarantee physical memory zeroization.

Audit records distinguish a signing authorization or key lookup from a completed
signature or SSH login. sshd owns actual login/session evidence. Never place
private keys or raw signing payloads in troubleshooting logs.

See the [implementation evidence](../testing/ssh-access-evidence.md) for scoped
tests, packaged consumer and actual Core/Agent/OpenSSH results, and explicit
platform/build limitations.
