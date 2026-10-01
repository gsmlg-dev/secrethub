# Isolated Client Auth PKI artifact checks

`pki_acceptance.py` uses the protected management ingress already configured for
the disposable Core fixture. It expects an unsealed Core and a Client Auth
authority that has never been initialized in that dedicated fixture database.
It creates test identities/certificates and revokes them. Never target operator
data or reuse operator keys. It does not configure the operator's Caddy or publish
images.

Start with the private `acceptance.py` configuration and add:

```json
{
  "isolated_fixture": true,
  "agent_image_id": "sha256:<exact-image-id>",
  "pki_caddy_binary": "/private/fixture/caddy",
  "pki_caddy_carrier_image_id": "sha256:<exact-existing-carrier-image-id>",
  "pki_caddy_runtime_paths": [],
  "pki_consumer_port": 15767,
  "pki_enforcement_bound_seconds": 30,
  "pki_distribution_delay_seconds": 1
}
```

For a dynamically linked Nix-built Caddy, list only its required immutable
`/nix/store/<hash>-<package>` runtime directories. They are mounted read-only.
The carrier starts only the supplied Caddy executable as UID1002 on loopback;
it never starts a database. The report records its image ID, Caddy executable
hash and runtime paths. Caddy uses the existing SecretHub TLS verifier and HTTP
middleware APIs, an independent consumer watermark and a 200ms fixture poll.
Generated certificates and keys belong only to this disposable consumer.
Caddy 2.9.1 uses `ca` for the JSON client-authentication CA provider;
`trust_pool` is the Caddyfile directive. Mandatory `require_and_verify` and
the SecretHub TLS verifier and HTTP middleware remain enabled together.

To observe actual enrolled Agent delivery, also supply:

```json
{
  "agent_container": "secrethub-prelaunch-<owned-runtime-agent>",
  "agent_bundle_dir": "/private/fixture/agent/pki/client-auth"
}
```

The running Agent must match `agent_image_id`; its configured bundle path must
map to this exact host bind directory. The consumer mounts that directory
read-only and waits for the published generation and bundle hash. This helper
never injects bundles into the running Agent. To measure delayed distribution
and reconnect, set `pki_runtime_disconnect_seconds` to an explicit positive
interval (at most 30 seconds). This opts in to stopping only that owned fixture
Agent before revocation, observing the prior consumer behavior, and starting it
with the same persistent state. Installed publication/hash and all five
identity-file digests must match after reconnect. Failure cleanup restores the
Agent's running state. Select an enforcement bound that includes this interval,
actual Agent startup, transport and consumer polling.

By default the dedicated authority must be absent. An existing disposable
authority can be explicitly selected with `existing_authority_ca_fingerprint`
equal to its exact pinned fingerprint. Each invocation creates new unique test
identities/certificates; it retains all prior certificates, revocations and
generation history. This never resets or replaces an authority. It cannot be
combined with `--resume-output`.

Without these two fields, normal delivery uses a separate Agent release `eval`
process invoking the actual `TrustBundleManager.process_bundle` API. This proves
artifact validation and atomic disk application, while WebSocket distribution
remains unexecuted. A deliberately withheld bundle demonstrates continued use of
the prior valid CRL before delivery. The selected enforcement bound must include
that delay, container startup and consumer polling; this fixture bound does not
establish a deployment bound.

```sh
python3 -B scripts/prelaunch/pki_acceptance.py \
  --config /private/fixture/pki-config.json \
  --output /private/fixture/new-pki-result-directory
```

The new output directory is owner-only. Export only a reviewed `report.json`;
never export `consumer.private` or a trust volume. Raw HTTP bodies, subprocess
diagnostics and exception messages are suppressed. Fixture volumes remain in
Docker with invocation-specific names. Do not delete watermarks to retry a
rollback rejection. A full rerun needs a separate fresh fixture database, not
destructive reinitialization of the existing database.

The checks cover actual valid/untrusted/missing-certificate requests, issuance,
revocation, forced CRL refresh and replay of old/corrupt bundles. TLS1.2 session
resumption must succeed before revocation for a resumed-session observation to
count. Caddy 2.9.1 disables session tickets when client authentication is
configured. The harness records the missing ticket and fresh handshake on the
baseline reuse attempt, then requires rejection of a post-revocation attempt
using that prior session object. It does not claim resumed-session revocation
when the consumer disables resumption.
Fresh handshakes, attempted session reuse and requests on the already-open
connection are recorded separately. HTTP middleware rejection on an open
connection does not prove immediate connection termination.

Old/corrupt replay always uses an isolated artifact manager and its retained
monotonic volume. It compares both the watermark hash and current-generation
symlink before and after rejection, including after manager recreation. It
never mutates the running Agent. An actual old database restore, consumer file
corruption and operator-gated damaged-state recovery are separate unexecuted
cases. G14 remains partial unless enrolled delivery plus the explicit disconnect
scenario pass; G15 remains partial and G17 unexecuted. `complete` is always false. Diagnostic
images must use `provisional: true`; their evidence cannot transfer to rebuilt
or frozen artifacts.
