# Isolated production-artifact acceptance

These tools use disposable credentials and explicitly selected fixture processes.
They never publish/deploy an image or configure production Caddy. Supply an
existing-mechanism isolated Caddy mTLS ingress and real PostgreSQL/Core/Agent
processes. Do not aim them at existing production data or reuse production keys.

`acceptance.py` currently executes the Core Vault/management portion of G01–G20.
It records the remaining gates as `unexecuted`; a successful selected subset
never makes its report complete. Full static/PKI/recovery orchestration is still
pending. The report distinguishes a provisional artifact from a frozen candidate.

Build and start the candidate outside the checkout under production configuration
as UID1001/1002, with runtime-only inputs and explicit migrations. For a frozen
build set `org.opencontainers.image.revision` to its committed source SHA and
record exact immutable image IDs. The harness verifies container image and UID;
provisional source/build results cannot transfer to a rebuilt candidate.

Place fixture configuration in a private JSON file. Required fields:

```json
{
  "core_container": "secrethub-prelaunch-<unique-fixture>",
  "core_image_id": "sha256:<exact-64-digit-image-id>",
  "source_sha": "<committed-source-sha>",
  "platform": "linux/amd64",
  "management_origin": "https://localhost:<fixture-mtls-port>",
  "management_ca": "/private/fixture/existing-management-ca.crt",
  "operator_cert": "/private/fixture/operator.crt",
  "operator_key": "/private/fixture/operator.key",
  "machine_backend": "http://127.0.0.1:<fixture-machine-port>",
  "external_backend": "http://<fixture-host-private-ip>:<management-backend-port>"
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
