# SecretHub Human

Human owns accounts, devices, sessions, client-encrypted vault data, organizations, collections,
attachments, its PostgreSQL Repo, Phoenix Endpoint and Oban instance. It calls only the public
`SecretHub.Access` Core boundary. Core management remains behind Caddy mTLS; Human authentication
is separate and does not add a Core admin login.

## Supported surface

- Personal login, note, API credential, identity, card and SSH key items; encrypted TOTP fields,
  folders, ciphertext history (20 versions by default), revision cursors and deletion tombstones.
- Personal Bitwarden identity, cipher/folder CRUD, full sync and user-scoped SignalR notifications.
  Tested clients: official CLI **2026.9.1**, Chrome extension **2026.9.3**. Desktop/mobile clients,
  enterprise features, Send, password reset/recovery and full Bitwarden parity are not qualified.
- Native organization/collection APIs with encrypted member key envelopes, collection permissions,
  client re-encrypted shared items, shared dynamic references and membership-removal revocation.
  Organizations and attachments are not exposed through the Bitwarden compatibility routes.
- Native PostgreSQL dynamic credential requests, one-time reveal, lease renewal/revocation,
  expiring approvals and a browser UI at `/human/ui`.
- Native encrypted attachment upload/download, private filesystem storage, per-user quotas,
  deleted-item cleanup and explicitly confirmed, audited ciphertext item export.

Clients derive the master key and authentication verifier locally. The server salts and hashes
that verifier; it never receives the master password or decrypts vault payloads. Type-2 AES-CBC
plus HMAC envelope validation is structural: authentication/decryption and independent attachment
key generation remain client responsibilities. Core's master key is never involved. Member keys
may use type-2 symmetric or type-3/4 RSA envelopes. Password sessions never assert MFA; policies
requiring MFA fail closed until a real MFA integration is implemented.

Access and refresh tokens are stored only as digests. Refresh rotates both tokens; previously
issued access tokens retain their own original expiry so official-client requests already in
flight remain valid. Refresh never extends an earlier access token's lifetime. Session or device
revocation, disabled users and refresh-token replay invalidate the entire session immediately,
including all previously issued access tokens. Expired access-digest and refresh-replay evidence
is cleaned up by the periodic Human job.

Dynamic credential values exist only in a bounded, private, supervised ETS reveal store, then
in the recipient's response. Tokens are digest-only, single-use, user/session/device-bound and
expire after 30–60 seconds. A failed handoff schedules backend revocation. Restarting Human
loses unrevealed values; durable Core reservations/leases remain eligible for cleanup. The UI
holds access tokens in memory and clears revealed values after 30 seconds, page exit or sign-out.

## Runtime and configuration

Initial production topology is **one Human node co-hosted with Core in the combined release**.
A standalone remote Human deployment needs an authenticated Core transport; multiple Human nodes
need an explicit reveal routing/distribution strategy. Neither topology is qualified here.

Local ports are Core `4664`, trusted Agent mTLS `4665`, Human `4666`. Human exposes `/identity/*`,
`/api/*`, `/notifications/hub`, `/human/*`, `/health` and `/health/ready`. Serve Human through its
own HTTPS proxy origin. Bearer authentication supports official extensions; CORS does not use
cookies or credentialed browser sessions.

Production preserves the Core-only default. Enable Human explicitly:

```sh
HUMAN_ENABLED=true
SECRETHUB_ROLE=all
PHX_SERVER=true
```

The combined release retains the existing Core runtime variables. Human additionally requires:

| Variable | Meaning |
| --- | --- |
| `HUMAN_DATABASE_URL` | Independent database name **and database username** |
| `HUMAN_SECRET_KEY_BASE` | At least 64 characters, distinct from Core's signing secret |
| `HUMAN_ENDPOINT_ORIGIN` | Independent public HTTPS origin |
| `HUMAN_ATTACHMENT_DIRECTORY` | Private writable ciphertext volume |
| `HUMAN_ENDPOINT_HOST` | Local/dev host setting; production uses `HUMAN_ENDPOINT_ORIGIN` |
| `HUMAN_ENDPOINT_BIND_IP` | Private listener IP, default `127.0.0.1` |
| `HUMAN_ENDPOINT_PORT` | Default `4666`; must not conflict with Core listeners |
| `HUMAN_DB_POOL_SIZE` | Default `20`, range `1..100` |
| `HUMAN_SESSION_TTL` | Access session seconds: default `900`, range `60..3600` |
| `HUMAN_REVEAL_TTL` | Default `30`, range `30..60` |
| `HUMAN_SIGNUPS_ENABLED` | Closed by default; provision through trusted operator tooling |
| `HUMAN_ENCRYPTION_CONFIG` | Optional fixed value `client-type2-v1` |
| `HUMAN_ATTACHMENT_MAX_BYTES` | Ciphertext bytes: default 10 MiB, maximum 100 MiB |
| `HUMAN_ATTACHMENT_QUOTA_BYTES` | Per-user ciphertext bytes: default 100 MiB, maximum 1 GiB |
| `HUMAN_DYNAMIC_ENABLED` | Separate, explicit opt-in; defaults to false |
| `HUMAN_DYNAMIC_MOUNTS_FILE` | Required trusted PostgreSQL catalog when dynamic access is enabled |

Dynamic access uses additive Core Human grants and leases. It does not enable the legacy dynamic
engine/credential-persisting lease manager. Load the trusted mount catalog at every startup so
backend revocation remains possible after restart. Keep backend connection credentials in the
operator's secret configuration, not in Human items or request bodies. Provision grants through
`SecretHub.Core.HumanAccess.provision_grant/1`; clients cannot configure mounts, grants, principals,
MFA strength or approvers. Self-approval is denied. Disabling a grant or removing membership denies
future access and marks existing leases for retryable revocation.

Example catalog shape (substitute operator-managed connection configuration):

```json
{
  "postgres-production": {
    "engine": "postgresql",
    "connection": {
      "hostname": "postgres.internal",
      "port": 5432,
      "database": "application",
      "username": "credential_issuer",
      "password": "REPLACE_IN_PRIVATE_CONFIG"
    },
    "roles": {"reader": {"schema": "public", "privileges": ["select"]}}
  }
}
```

`configure_mounts/1` is a trusted runtime override; persist changes in the startup catalog before
restart. Configure the issuer's PostgreSQL privileges externally. Password expiry, renewal,
NOLOGIN, connection termination and role removal are performed against the actual backend.

In development/test, roles `all` and `human` enable Human; `core` and `agent` disable its children.
Those roles currently gate Human only. Production Human requires role `all`; it does not promise
an isolated Human-only release.

## Database and storage lifecycle

Migrate **both Repos before starting the enabled application**: Human Oban validates its tables
at startup. Development databases are `secrethub_dev` and `secrethub_human_dev`; test databases are
`secrethub_test` and `secrethub_human_test`, with `MIX_TEST_PARTITION` suffixes for isolated fixtures.

```sh
mix ecto.create -r SecretHub.Core.Repo -r SecretHub.Human.Repo
mix ecto.migrate -r SecretHub.Core.Repo -r SecretHub.Human.Repo
```

For an already-built release, supply its configured Core and Human runtime variables, then run:

```sh
bin/secrethub_core eval 'SecretHub.Core.Release.migrate()'
bin/secrethub_core eval 'SecretHub.Human.Release.migrate()'
```

Human tables and migrations are independent of Core. Attachment filenames/keys are encrypted;
storage paths are server UUIDs, directories mode `0700`, files mode `0600`. Limits count encoded
ciphertext bytes, not plaintext file bytes. HTTP limits allow that ciphertext and bounded envelope
metadata. Cleanup reclaims deleted-item quota, retries file deletion and removes orphan files
older than one hour.

`POST /human/vault/export` requires a valid current actor and `{"confirm":true}` and audits the
export. Its `secrethub-encrypted-v1` format contains active personal item ciphertext/metadata;
folders and attachment files are retrieved separately. Local export/decryption performed by an
authorized official client cannot be controlled by a server export endpoint.

Logs go to console for Docker's existing logging pipeline. Database backup/restore and attachment
volume backup belong to the operator's existing backup system. No remote logging or backup
integration is installed by this subsystem.

## Health, metrics and audit

`/health` is liveness; `/health/ready` returns readiness for Human Repo, public Core boundary,
reveal store and notification PubSub. The endpoint response itself establishes listener readiness.
`SecretHub.Human.Metrics.snapshot/0` returns aggregate session/login/item/request/denial/reveal/
lease/approval counts. The periodic Human job emits telemetry without actor IDs or payloads and
invokes Core lease cleanup. Human's separate Oban instance also delivers sanitized audit outbox
entries and performs attachment cleanup. Outbox delivery is eventual across the two databases,
with canonical Core evidence and retry-safe event UUIDs; credentials are never job arguments.
Human Repo SQL logging is disabled and HTTP responses are `no-store`.

## Verification

Run only the subsystem and public-boundary suites on a migrated dedicated test partition:

```sh
MIX_ENV=test MIX_TEST_PARTITION=_humanvaultcheck mix ecto.create -r SecretHub.Core.Repo -r SecretHub.Human.Repo
MIX_ENV=test MIX_TEST_PARTITION=_humanvaultcheck mix ecto.migrate -r SecretHub.Core.Repo -r SecretHub.Human.Repo
MIX_ENV=test MIX_TEST_PARTITION=_humanvaultcheck mix test apps/secrethub_human/test apps/secrethub_core/test/human_access
node --test apps/secrethub_human/test/native_ui_test.mjs
```

Official-client fixture/acceptance scripts live in `scripts/human/`; they require disposable test
accounts, dedicated fixture databases, a trusted local TLS certificate, and the pinned unmodified
official artifacts. Browser scripts require Playwright and Chromium. Never point the fixture at
production. Sanitized executed reports and client artifact hashes are recorded in
`docs/subsystem/evidence/human-vault/` and `docs/subsystem/human-vault-execution.md`.
