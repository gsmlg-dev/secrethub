# Application UDS authentication and static reads

This contract implements Tasks 5–9 of the [application authorization plan](../superpowers/plans/2026-07-16-app-pki-uds-authorization.md). Core-to-Agent transport uses mTLS. Applications connect to the Agent's owner-only Unix socket and prove possession of their certificate's private key using a signed challenge.

## Authentication

The socket is mode `0600`, accepts newline JSON frames up to 64 KiB, and allows one outstanding challenge per connection. Trust starts unavailable until the persisted Core CA chain is loaded or enrollment commits it. Certificates require canonical application UUID CN, organization `SecretHub Applications`, exact URI SAN `urn:secrethub:app:<uuid>`, and explicit `clientAuth`. Chain validity and certificate expiry are checked before a challenge is issued.

`authenticate` takes `auth_version: 2` and a padded Base64 PEM certificate. Its response includes `auth_version`, `agent_id`, server-generated `connection_id` and `challenge_id`, a Base64 32-byte `challenge`, lowercase DER-SHA256 `certificate_fingerprint`, `signature_algorithm`, and `expires_at` no more than 30 seconds ahead.

The signed transcript is:

```text
lp("secrethub-uds-auth") || lp(<<2>>) || lp(signature_algorithm)
|| lp(agent_id) || lp(connection_id) || lp(challenge_id)
|| lp(raw_nonce_32) || lp(raw_der_sha256_32) || lp("authenticate")
```

`lp` prefixes bytes with their unsigned big-endian 32-bit length. Algorithms are `rsa-pss-sha256` (SHA256, MGF1 SHA256, salt length 32) and `ecdsa-sha256` (DER signature). `authenticate_proof` echoes version, connection ID, challenge ID, algorithm, and padded Base64 signature. Proof failure, expiry, replay, or reauthentication closes the connection. Three failed certificate attempts also close it. Secret requests require successful proof.

The CLI requires both files:

```sh
secrethub secret get prod.db.password \
  --agent-socket /var/run/secrethub/agent.sock \
  --agent-cert ./app.pem --agent-key ./app-key.pem
```

## Core authorization and cache

Every static read sends `path`, proof-derived `app_id`, `certificate_fingerprint`, `local_auth_version`, and optional `known_revision` over `agent:runtime`. Core derives the Agent from its trusted socket certificate, resolves the current app/certificate association, and checks separate Agent and application policy gates. Multiple applications can share an Agent.

Cache keys contain application ID, canonical fingerprint, and path. An existing value is released only after fresh Core authorization returns `not_modified` for that exact monotonic revision. Returned version and revision are preserved. Outage, sealed Vault, or denial never releases cached plaintext; denials invalidate the entry. Path notifications invalidate all applications' entries and retain revision tombstones against delayed older writes. Policy changes and reconnects clear cached entries. Process status formatting omits cache values and runtime key material.

## Monotonic cutover

Trusted joins advertise `uds_auth_v2` and return Core's authoritative `minimum_uds_auth_version`. Core rejects incapable joins after cutover and checks the floor inside static authorization, including the notification race window. The launch profile rejects Agent-only reads without application context.

Connection persists the maximum observed floor in `identity.json` before accepting runtime/finalizing enrollment. Writes use an exclusive temporary file, file synchronization, atomic rename, and directory synchronization. Runtime notifications update the live UDS server; stale lower notifications, material rewrite, and restart cannot lower the persisted floor. Missing or invalid Core floor, damaged trusted state, or persistence failure prevents runtime acceptance. Dual-accept legacy authentication exists only while the Core-issued floor remains 1; floor 2 permanently refuses it.

Gate activation is an explicit operator/Core operation. This implementation does not activate a production gate. Future removal of legacy paths requires a separately reviewed contract release, all deployed nodes advertising canonical capability, and repeated zero-finding preflights.

## Scoped evidence

Focused tests cover an independently encoded transcript vector, RSA/ECDSA proof, cross-connection/Agent replay, expiry, certificate trust/identity, frame limits, cache outage/denial/isolation, exact `not_modified`, revision tombstones, durable floor, and CLI signing. An independent Python/OpenSSL consumer is also exercised against the actual UDS server with a fixture Core: initial/update delivery writes a private `0600` file and reads it back; denial and outage preserve the prior file.

These source tests supplement the real Core/Agent artifact rehearsal. They do not establish production gate activation, artifact deployment, or acceptance of dynamic secret lifecycle or template delivery.
