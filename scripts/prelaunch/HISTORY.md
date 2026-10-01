# Old restored bundle against retained trust history

`history_acceptance.py` executes one restricted G17 scenario using the existing
recovery and PKI artifact helpers. It does not initialize, issue, revoke, refresh,
unseal the restored Vault, publish to Agents or reopen service. Its report always
marks G17 partial, authoritative reconciliation/full-service reopen unexecuted,
`recovery_hold: true` and `complete: false`. Exit 0 means only the selected old
rejection and retained-revocation enforcement checks passed.

Use the private recovery configuration documented in [RECOVERY.md](RECOVERY.md)
and the private PKI configuration documented in [PKI.md](PKI.md). Both must select
the same immutable Core/Agent artifacts, source SHA, platform and provisional mode.
The existing PostgreSQL fixture remains isolated. No shares file is required:
`ClientAuth.current_bundle/0` reads the public CA and existing signed CRL while
sealed. Schema v1 has a deterministic transcript hash and signed CA/CRL, not a
separate signature authenticating all generation metadata. The helper exports the
unchanged database bundle; it creates no new signature or generation.

Add these explicit fields to the private PKI configuration:

```json
{
  "isolated_fixture": true,
  "history_retained_volume": "secrethub-prelaunch-pki-<12 lowercase hex digits>",
  "history_consumer_fixture_dir": "/private/prior-pki-result/consumer.private",
  "pki_consumer_port": 15767
}
```

Select an available loopback port. The prior owner-only result directory must
contain its redacted `report.json` identifying this retained volume and the exact
Core/Agent/Caddy/carrier artifacts. The volume must already exist; the helper
never creates a replacement or removes retained history. Use an explicitly owned
fixture, quiesce other processes that mutate its trust volume, and preserve the
original Agent identity and live bundle directory. `agent_bundle_dir` from the
PKI config is intentionally omitted from this consumer's mounts.

```sh
python3 -B scripts/prelaunch/history_acceptance.py \
  --recovery-config /private/fixture/recovery-config.json \
  --pki-config /private/fixture/history-pki-config.json \
  --output /private/fixture/new-history-result
```

Both config files are owner-only regular files outside the checkout; the new
owner-only output directory must be beside the PKI config. Do not export
`consumer.private`, keys, certificates, CRLs, bundles or raw process diagnostics.
The redacted report contains only counters, public fingerprints/hashes, fixed
booleans, artifact identities, elapsed time and incomplete gate status.

The selected sequence is:

1. Snapshot the restored Vault/ClientAuth/certificate/identity/issuance/receipt
   and historical audit inventory using read-only SQL. Start one Core eval as
   UID1001 with no network, read-only socket/input mounts, no web applications
   or TCP/UDP sockets. Immediately stop the supervised CRL refresher, wait for
   initialized sealed state, retrieve the existing public bundle and verify
   Core remains sealed and restricted. Compare inventory after exit. Normal
   Core startup can write fixture cluster bookkeeping; the claimed unchanged
   inventory is Vault, PKI and audit, not every database table.
2. Read and validate the actual retained artifact-manager bundle, its watermark
   and current symlink plus independent Caddy TLS/HTTP watermark files through
   a read-only volume mount. These counters are observed from persisted state,
   not copied from operator-supplied configuration. Require the same original
   CA and currently valid signed CRLs; do not waive time checks or refresh an
   expired old CRL to make the replay pass.
3. Require the prior client, control and server leaves to remain valid for at
   least 180 seconds, and verify client/control chains with `openssl verify`
   against the retained CA. Verify the revoked client's serial occurs in the
   retained signed CRL and is absent from the older CRL; the control serial must
   remain unrevoked. Expiry, an unrelated CA or an expired old bundle cannot stand
   in for the revocation/replay checks. Recheck certificate expiry immediately
   after the actual denied/allowed request pair. If credentials have expired, stop; this
   helper never issues replacements.
4. Use the exact Agent release's `TrustBundleManager.process_bundle` first with
   the unchanged retained bundle and then the actual exported old DB bundle.
   Require `generation_downgrade_rejected` and byte-identical manager watermark
   and current-generation symlink. Each manager instance uses the established
   explicit fixture identity only for this negative replay, never the running
   Agent identity. Manager observations/outbox may append rejection evidence;
   persisted trust generation, CA pin and active bundle must remain unchanged.
5. Start one uniquely owned Caddy consumer as UID1002 against the retained
   artifact-manager volume, without the live Agent directory override. Copy only
   the prior server certificate/key into the new private serving fixture and
   generate its Caddy configuration there. Prior client/control keys remain in
   their original private directory and are used only by the Python TLS clients.
   Probe readiness with the unrevoked control; require a fresh revoked-client
   request denied and control request allowed.
6. Independently inspect manager and TLS/HTTP watermarks again. Manager trust
   watermark/current must remain identical. Caddy may legitimately advance its
   retained counters, for example 4 to the already retained bundle 5; require
   monotonic counters, the unchanged original CA and the exact retained bundle
   hash. Preserve and report before/after provenance. No watermarks, generations
   or identity files are reset or deleted. Compare restored inventory again.

Timeouts and cleanup apply only to newly owned Core/inspection/apply/consumer
containers. The source trust volume, private certificate material, database and
consumer history remain retained. Raw stdout/stderr remain in memory and only a
combined digest enters the report; exception messages and raw diagnostics never
print. A cleanup failure fails the selected checks.

This demonstrates rejection of an actual stale restored bundle at the artifact
manager and continued enforcement of retained revocation history by the consumer.
It does not apply old bundle files to a running consumer, reconcile authoritative
post-snapshot decisions into restored Core, measure resumed/open-session recovery,
or establish full Agent/consumer restore. Keep the [hold/reopen procedure](../../docs/security/launch-operations.md#backup-and-full-restore)
in force until the remaining evidence is reviewed and completed.
