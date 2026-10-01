# Serving static consumer after an operator-prepared restore

`static_restore_acceptance.py` collects selected G16 static-consumer evidence
from restored Core/Agent services already prepared by the operator. It performs
no backup, restore, migration, initialization, enrollment, secret update, policy
mutation, service restart/pause or unseal. The operator owns consistent backup,
restoring into a new empty database, preserved identity/trust copies, restricted
integrity checks, service startup and protected manual unseal.

Use the private [static configuration](STATIC.md) with the restored Core/Agent
container names, their exact immutable images and preserved copied fixture paths.
Supply the current regranted application-policy IDs. The private consumer fixture
must be UID1002/mode0700 with copied app certificate/key, expected1/expected2 JSON
and applied output files at mode0600. `expected_versions` remains `[1, 2]`; the
restored fixture secret must already hold expected2, version2 and its retained
actual revision. Add the independently preserved public baseline:

```json
{
  "service_restore_started_at": "<timezone-aware ISO8601 service-start boundary>",
  "recovery_baseline": {
    "agent_identity": {
      "agent_id": "agent-<preserved lowercase UUID>",
      "certificate_sha256": "<preserved lowercase SHA256>",
      "key_sha256": "<preserved strong-key SHA256>",
      "ca_sha256": "<preserved CA SHA256>",
      "minimum_uds_auth_version": 1
    },
    "enrollment_ids": ["<preserved finalized enrollment UUID>"],
    "certificate_id": "<preserved Core Agent certificate UUID>",
    "version": 2,
    "revision": 3
  }
}
```

The public runtime ID has the enrollment-generated `agent-<UUID>` format;
`static_fixture.agent_uuid` is the separate bare database UUID.
Use the actual preserved floor and revision. Do not generate a new baseline from
the restored services to hide identity or history drift. The identity map comes
from the accepted `StaticHarness.snapshot`; it contains only public identifiers
and certificate/key/CA digests, not the private key. All config inputs are an
owner-only JSON file outside the checkout; the new output directory must be
beside that file. No shares file is accepted or needed because the helper cannot
unseal Core.

```sh
python3 -B scripts/prelaunch/static_restore_acceptance.py \
  --config /private/restore/static-restore-config.private.json \
  --output /private/restore/new-static-restore-result
```

The helper verifies:

1. Protected mTLS management reports the restored Core initialized and unsealed.
   This observes the operator-prepared state; the helper supplies no shares.
2. A finalized enrollment has a real heartbeat later than the supplied service
   restore boundary. Agent certificate/key/CA digests, runtime ID, local auth
   floor, all enrollment IDs and the Core Agent certificate UUID match baseline.
3. Read-only metadata shows the retained static secret version/revision and
   application policy bindings. The typed-runtime-authorization report has zero
   findings, its existing persisted gate matches the canonical report hash and
   has a positive verification generation, and the Core floor equals the
   preserved Agent floor. No verification, activation or backfill API is called.
4. The actual immutable UID1002 consumer uses auth-v2 proof over the owner-only
   restored Agent socket, reads expected2 at the retained version/revision and
   atomically applies a private file. Independent inspection requires exact
   value match, mode0600, changed inode when replacing existing output, and no
   remaining temporary file. Secret values and output digests stay private.
5. Metadata, typed authorization, floor and identity checks still match after
   consumer readback, and the protected restored Core remains unsealed.

The helper reuses the accepted owned evaluator lifecycle. Core evaluations use
the exact image/UID, inspected read-only input mounts, private environment and
stdin, no network/web startup, an immediately stopped CRL refresher and a unique
invocation-owned cluster node ID. Timeout cleanup confirms VM absence before
continuation. Identity reads use the owned Agent image with read-only copied
state. Serving node incarnation/start time/hostname/version/capabilities are
checked across evaluations, while naturally mutable heartbeat/status fields are
excluded from identity comparisons. Incidental evaluator cluster rows remain
retained and are disclosed; no SQL cleanup runs. Normal serving consumer reads
can create audit records. This is read-only for restored Vault/secret/policy/
identity provisioning; it is not a byte-identical inventory check of every table.

Cleanup stops only invocation-owned transient containers. It never unseals,
restarts or repairs services or policies on failure. All restored persistent
state, trust watermarks, keys and private consumer output remain for inspection.
Raw diagnostics stay in memory; only a combined digest enters the redacted
`static-restore-report.json`. Exclude private environment copies and fixture
files from exports. A cleanup failure fails selected checks.

Every report says G16 partial, G17 unexecuted, `complete:false`, provisional
status and `recovery_hold:true`. Exit0 means these selected static-consumer checks
passed. It does not prove full restore, RTO, audit-chain recovery, PKI consumer
restore, old-database/new-watermark reconciliation or launch acceptance. Keep the
[hold/reopen procedure](../../docs/security/launch-operations.md#backup-and-full-restore)
until those separately required checks are reviewed.
