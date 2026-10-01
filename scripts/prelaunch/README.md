# Isolated production-artifact acceptance

These tools use disposable credentials and explicitly selected fixture processes.
They never publish/deploy an image or configure production Caddy. Supply an
existing-mechanism isolated Caddy mTLS ingress and real PostgreSQL/Core/Agent
processes. Do not aim them at existing production data or reuse production keys.

`acceptance.py` executes the Core Vault/management checks G01–G10 and G20,
and records compatibility/log evidence for G18/G19. G18 remains partial: it does
not claim an older binary upgrade or compatible binary rollback. With independent
fixture shares and `isolated_fixture: true`, G19 also runs a transient isolated
VM fault while holding fixture shares/plaintext in memory. It verifies that the
image's existing `ERL_CRASH_DUMP=/dev/null` suppresses a retained VM dump and
scans captured diagnostics for fixture secrets. It does not change the dump
configuration to make the test pass. Without shares this coverage stays partial.
The crash process exposes no listeners, accesses no application database and
is removed after diagnostics; existing Core is never crashed. Omitted gates stay `unexecuted`; partial
or provisional results never make a report complete. The other harnesses below
exercise the static consumer and recovery paths separately.

G08 also requires `rejected_operator_cert` and `rejected_operator_key` pointing
to a disposable certificate/key pair rejected by the existing ingress trust
policy. Without them, no-certificate/machine/backend denials are recorded but
the wrong-certificate case remains partial.

Build and start the candidate outside the checkout under production configuration
as UID1001/1002, with runtime-only inputs and explicit migrations. For a frozen
build set `org.opencontainers.image.revision` to its committed source SHA and
record exact immutable image IDs. The harness verifies container image and UID;
provisional source/build results cannot transfer to a rebuilt candidate.

Place fixture configuration in a private JSON file. Required fields:

```json
{
  "isolated_fixture": true,
  "core_container": "secrethub-prelaunch-<unique-fixture>",
  "core_image_id": "sha256:<exact-64-digit-image-id>",
  "source_sha": "<committed-source-sha>",
  "platform": "linux/amd64",
  "management_origin": "https://localhost:<fixture-mtls-port>",
  "management_ca": "/private/fixture/existing-management-ca.crt",
  "operator_cert": "/private/fixture/operator.crt",
  "operator_key": "/private/fixture/operator.key",
  "machine_backend": "http://127.0.0.1:<fixture-machine-port>",
  "external_backend": "http://<fixture-host-private-ip>:<management-backend-port>",
  "fixture_postgres_container": "secrethub-prelaunch-<unique-postgres-fixture>",
  "fixture_postgres_socket": "/socket",
  "fixture_database": "<source-isolated-fixture-database>"
}
```

Set `provisional: true` only for diagnostic images whose source is not frozen.
The result then explicitly remains provisional and incomplete. Use a genuinely
new migrated fixture database for each full run. The harness performs protected
initialization and Core restart; it never resets or drops a database to rerun.

```sh
python3 -B scripts/prelaunch/acceptance.py \
  --config /private/fixture/config.json \
  --output /private/fixture/new-result-directory
```

The output directory is private and must not already exist. `report.json`
contains redacted outcomes/timing and explicitly unexecuted gates. Capture
`recovery-shares.private.json` in the independently held private fixture recovery
inventory; **never export it with acceptance evidence**. The harness suppresses
raw HTTP bodies and release diagnostics. Copy only a reviewed redacted report.

Use `--gates G01,G03,G18,G19,G20` to run independent Core checks against an
already initialized fixture. `--shares-file /private/fixture/shares.json` loads
existing fixture recovery material for share/restart checks; it does not reset or
reinitialize the database. G05/G06 require successful G02 or these private shares.
Do not select G02 against an existing Vault. G05/G10 require a sealed fixture.
G06 creates the fixed disposable `prelaunch.static` secret and restarts Core;
run it only on its original fresh fixture, not on a consumer/recovery fixture.

G01 creates a uniquely named database, explicitly migrates it, signs an audit
entry, and verifies the same persisted entry with both runtime keys. It also
runs normal startup with missing/known development keys and requires rejection.
Keys are mounted runtime files, not changed through application configuration.
G03 probes runtime Repo/Vault in a separate production `eval` for unavailable,
missing and malformed schema cases. G18 restores a database copy into a new
isolated database before migration/rollback checks. These checks never modify
the configured source database. G20 starts a separate Core-only release process,
observes a healthy CRL worker, stops that child, and observes failing background
readiness. The serving Core stays running.

New database names appear in the report and remain in the explicitly selected
disposable PostgreSQL fixture for investigation; the harness never drops them.
Owned temporary containers are removed on exit. Runtime-key fixture files remain
under the private output directory and must be excluded from evidence exports,
along with recovery shares. Exit zero means all **selected** gates passed; a
partial result exits nonzero and is not a release acceptance claim.

For G19, optional `additional_private_logs` is a list of private diagnostic
paths retained before a disposable container is replaced. Their contents are
scanned without being copied into the report. Retain complete stdout/stderr and
exclude these raw files from evidence exports.

Distribution is disabled. Fixture DB/introspection operations use a separate
Core-only release `eval`, not live `rpc`. Where a fixture read needs the key,
shares travel over process stdin and authenticate independently against the same
Vault envelope. Serving initialization/unseal and connected LiveView use actual
HTTP/WebSocket through Caddy. Source tests are separate evidence.

## Actual static consumer

`static-consumer.py` is an independent disposable application using the real UDS
v2 challenge/private-key proof and OpenSSL RSA-PSS/SHA256 or ECDSA/SHA256. Run it
as the authorized local service UID with access to the owner-only Agent socket.
Use an issued application certificate and matching private key, not an Agent
certificate. It prints only version/revision and application booleans.

```sh
python3 -B scripts/prelaunch/static-consumer.py \
  --socket /fixture/run/agent.sock \
  --cert /fixture/consumer/app.crt --key /fixture/consumer/app.key \
  --path prelaunch.static --output /fixture/consumer/config.private.json \
  --expect /fixture/consumer/expected.private.json
```

The optional expected file contains private fixture JSON; it is read before any
application. Output is atomically replaced, fsynced, owner-only and read back by
the consumer. A denied/outage/invalid proof or unexpected value exits nonzero and
preserves existing application configuration. Never export output/expected files
or key material. This helper is a fixture consumer, not a new production secret
engine or deployment platform.

The source fixture exercise uses the actual UDSServer and an isolated Core
response sequence. It verifies initial/update readback and unchanged private
configuration on denial/outage. Final acceptance must additionally use the exact
Core/Agent images, real policy/identity changes, persistence, Caddy certificate
allow/reject/revoke behavior and the full restore drill.
