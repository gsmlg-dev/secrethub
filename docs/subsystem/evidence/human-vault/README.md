# Human Vault qualification evidence

These reports contain only client versions, check names and outcomes. Passwords, tokens,
keys, encrypted payloads and dynamic credentials remain in disposable private fixtures.

| Report | Executed check |
| --- | --- |
| `official-cli.json` | Unmodified official CLI 2026.9.1; login/unlock, initial sync, folder/login creation and updates, deletion, re-login |
| `official-browser.json` | Unmodified Chrome extension 2026.9.3 loaded in isolated Chromium; HTTPS login and unlocked initial sync |
| `official-signalr.json` | Real TLS websockets decoded by Microsoft's `@microsoft/signalr-protocol-msgpack` 10.0.0; user isolation and revoked-session closure |
| `native-browser.json` | Chromium native UI with disposable SCRAM PostgreSQL backend; request/reveal/clear, renewal/revocation, distinct approver and sign-out |
| `release-smoke.json` | Extracted locally built production archive; independent database migrations, concurrent Core/Human listeners, readiness and packaged native assets |

The refreshed Chrome run uses an empty personal vault. Its loaded empty state verifies
authentication and initial sync; encrypted item and folder round trips are exercised by
the unmodified official CLI.

Pinned official release artifacts:

```text
bitwarden-cli-2026.9.1-npm-build.zip
sha256 199d15bc494c54df20897d5ca266fd61922785b6f48996962facb8295e8624db

dist-chrome-2026.9.3.zip
sha256 7185bad74d44b1d7e81b3dc9858a206bf9debff272d7e5bfc7f56a4b9d942ca0
```

References: official Bitwarden client release artifacts and protocol definitions. CLI source
revision `8246ae9c9a484a0a69f8b27203034555fb872523`; no Vaultwarden implementation was copied.

Fixtures bind only `https://127.0.0.1:14666`, use synthetic client-encrypted accounts and a private
local CA. Browser trust is pinned to the fixture certificate's public key. CLI uses
`NODE_EXTRA_CA_CERTS`. Test backend PostgreSQL requires SCRAM; wrong-password failures, role
expiry/renewal/revocation and cleanup races are additionally exercised by the Core test suite.

Reproduction tools are in `scripts/human/`. Generate two private fixture JSON files with
`official-client-fixture.cjs`. Migrate both Repos in an isolated test partition **before**
starting `official-client-fixture.exs` with `mix run --no-start --no-halt`. Supply
`HUMAN_CLIENT_FIXTURE`, `HUMAN_OTHER_FIXTURE`, `HUMAN_CLIENT_CERT`, `HUMAN_CLIENT_KEY` and
optionally `HUMAN_UI_BACKEND=true` plus `HUMAN_UI_BACKEND_DIRECTORY`. The latter records only
the owned temporary PostgreSQL directory for teardown. Run clients using separate fresh
profiles; never reuse a production vault or profile. Shut down that fixture listener and its
recorded temporary PostgreSQL server after acceptance.

This evidence qualifies the implemented personal-vault protocol subset and co-hosted, single
Human-node topology. It does not qualify desktop/mobile, full Bitwarden parity, remote Human
transport, multiple Human reveal nodes or a production deployment.

The packaged smoke uses separate disposable PostgreSQL databases and usernames, generated
runtime keys, private loopback listeners and explicit Human opt-in. It executes both release
migration functions through `bin/secrethub_core eval`, then starts the extracted combined release.
The Core vault stays uninitialized and sealed, so Core reports degraded health as expected.
The report records the exact archive SHA256 and teardown of every owned listener/backend.
It proves local packaging and startup; production proxy TLS, deployment and unseal are separate.
