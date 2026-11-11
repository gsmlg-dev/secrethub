# Changelog

## Unreleased

- Add Agent-scoped static secret publication (`secret_write_v1`): a local
  process on an Agent host writes or deletes Core static secrets through the
  Agent socket (`secret_put`, `secret_delete`). Writes are versioned and
  support compare-and-set. Core authorizes them only with the new dedicated
  `secret_write`/`secret_delete` policy operations; the generic `write`/`delete`
  never apply. Every decision is audited without values.
- Add the `secrethub_sdk` Elixir package (`SecretHub.SDK.put_secret/3`,
  `delete_secret/2`, `get_secret/2`, `path/1`), published to Hex.pm with each
  release. See [apps/secrethub_sdk/README.md](apps/secrethub_sdk/README.md).
- Remove the admin secret page's non-functional "rotate" handler.

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
