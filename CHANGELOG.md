# Changelog

## Unreleased

- Add Agent-scoped host credentials (`host_credentials_v1`): Core credential
  bindings with typed `credential_*` grants and audit schema v2, local Agent
  `credential_*` actions, `git-credential-secrethub`,
  `docker-credential-secrethub`, `secrethub credential`, `secrethub exec` with
  the native `secrethub-exec` launcher, systemd `LoadCredential=` provider
  sockets with NixOS options, and the `keyrings.secrethub` Python backend.
  Requires the new Core migration before upgraded Agents connect. See the
  [user guide](docs/user-guides/host-keyring.md) and
  [evidence](docs/testing/host-keyring-evidence.md).

- Package a Mozilla-derived public TLS root catalogue and a separate pinned
  Let's Encrypt staging issuance profile, with offline release inspection and
  explicit peer/hostname verification for ACME and DNS-provider HTTPS.
- Manage public server certificates through native ACME v2 DNS-01, Cloudflare
  and AWS Route 53, with durable Core jobs, authoritative DNS checks, recoverable
  cleanup, ARI renewal scheduling and explicit revocation.
- Publish coherent certificate/key generations to encrypted, versioned static
  secrets; protect managed history and quarantine revoked versions from new
  exports, delivery and cache revalidation.
- Add private management views/API and an
  [operator guide](docs/pki/managed-public-certificates.md). Upgrade requires the
  new Core Oban/ACME migrations. See
  [execution evidence](docs/pki/secrethub-pki-acme-execution.md) for qualification
  and release status; existing internal identity trust remains separate.
