# Copy-only consumer disk corruption

`corruption_acceptance.py` collects selected G15 artifact evidence with the exact
Agent release and Caddy binary. It runs no Core process, API call or database
command. It never mounts the live Agent bundle directory. The source retained
fixture volume is mounted read-only and copied into a new, uniquely named volume;
only that copy is damaged. Both volumes remain for inspection after cleanup.

Every report says `complete: false`, G15 partial and `recovery_hold: true`. Exit 0
means the selected negative checks passed; it does not approve reopening or prove
successful recovery. A same-generation forced-recovery limitation is reported
separately as `unsupported`, after observing the exact error, rather than treated
as failure of the safe-rejection checks.

Use an owner-only JSON config outside the checkout, carrying the existing private
PKI config fields and the provenance fields documented in [HISTORY.md](HISTORY.md):

```json
{
  "isolated_fixture": true,
  "history_retained_volume": "secrethub-prelaunch-pki-<12 lowercase hex digits>",
  "history_consumer_fixture_dir": "/private/prior-pki-result/consumer.private",
  "existing_authority_ca_fingerprint": "<existing lowercase SHA256 CA pin>",
  "corruption_source_quiesced": true,
  "pki_consumer_port": 15768
}
```

The prior owner-only result directory must contain a redacted `report.json`
identifying that volume and the exact source/Core/Agent/Caddy/carrier artifacts.
The config also supplies `management_origin` for the offline Agent eval environment,
`source_sha`, `platform`, `core_image_id`, `agent_image_id`, `pki_caddy_binary`,
`pki_caddy_carrier_image_id`, optional `pki_caddy_runtime_paths`, and `provisional`.
No management credentials, recovery shares or recovery/database config are needed.
The existing artifacts and volume must already exist. The source must be quiescent:
the helper compares its complete file/link inventory before and after, and stops
on any mismatch. Select an available loopback port.

Client, control and server certificate/key files are taken from the prior private
fixture. If those certificates have expired, supply
`corruption_consumer_fixture_dir` pointing to a separate owner-only directory with
fresh operator-prepared `client.crt/key`, `control.crt/key` and `server.crt/key`.
The helper does not issue certificates or refresh CRLs. Both client leaves must
chain to the retained CA, remain valid for at least 180 seconds and have verified
revoked/unrevoked membership respectively in the retained currently valid signed
CRL. A newly revoked fixture needs its actual updated bundle already installed in
the explicitly owned source fixture; old counters cannot be supplied as substitutes.
Manager and independent TLS/HTTP watermarks must all match the retained high-water
tuple before copying. The known CA pin must match independently supplied config.

```sh
python3 -B scripts/prelaunch/corruption_acceptance.py \
  --config /private/fixture/corruption-config.json \
  --output /private/fixture/new-corruption-result
```

The new output directory must be beside the config. Its outer permissions are
0700. Only server material is copied into the private serving subdirectory; client
keys remain at their supplied paths. Do not export certificates, keys, bundles,
raw logs or the private serving directory. The report contains only fixed scenario
descriptions, allowlisted error codes/text, public hashes/counters, artifact IDs,
volume names, elapsed time and gate status. Process output stays in memory and is
represented only by a combined digest. Failed commands print no exception detail.

The selected sequence is:

1. Validate artifact provenance, actual persisted high-water state, currently
   valid signed CRL, CA pin and the revoked/control certificate membership. Copy
   the source volume and require identical complete file/link inventory.
2. Start the actual Caddy consumer against the copy. Require fresh revoked-client
   requests denied and the unrevoked control allowed.
3. Overwrite only the copied current-generation `crl.pem` with malformed bytes.
   Wait five configured 200ms poll intervals, observe the actual failed reload
   diagnostic with `calculated transcript hash does not match bundle_sha256`,
   and require revoked denial/control allowance with last-known-good
   trust retained. All three watermarks, current link and copied Agent identity
   files must remain unchanged. This does not claim immediate connection termination.
   Caddy verifies the transcript hash before parsing the CRL; changing CRL bytes
   without rewriting the manifest must fail that hash check first. A generic
   reload failure or a different cause does not satisfy this deliberate damage case.
4. Stop only that consumer and try a new process against the damaged copy. Require
   a nonzero startup exit, initial-bundle load failure with the same transcript
   mismatch cause and control requests denied.
   Watermarks and identity must remain unchanged; connection errors alone are
   insufficient evidence of fail-closed startup.
5. Damage the copied manager watermark and every retained generation's CRL so
   there is no surviving trusted bundle. Delete or rename no file or generation.
   Start the artifact manager with the established fixture identity. Require
   durable quarantine, two consecutive unforced candidate rejections with
   `damaged_state_recovery_required`, and unchanged trust state. Receipt/outbox
   observation records may append; they are not monotonic trust counters.
6. Optionally attempt the existing operator API with explicit authorization and
   the exact independently approved original high-water bundle. Never lower a
   counter, remove a watermark, replace the CA or manufacture a new generation.
   Finally require the original source inventory unchanged and stop every
   invocation-owned container. Retain every copy even on failure.

To select step 6, add `corruption_operator_recovery_authorized: true` and
`corruption_approved_bundle_sha256: "<exact retained bundle hash>"` to the private
config, then also pass `--attempt-operator-recovery`. A flag alone or config alone
cannot authorize forced recovery. Inputs travel only on stdin to the existing
`TrustBundleManager.process_bundle(manager, bundle, force: true,
pinned_ca_fingerprint: existing_pin)` API. No new product recovery API is added.

The current implementation has a narrower force contract than this damage case:
`TrustBundleManager` passes the bundle to `AtomicStore.write_bundle`, whose
`publish_generation_dir` rejects a damaged existing same-generation directory as
`corrupted_existing_generation`, even with `force: true`. Tests covering force
recovery from a corrupt watermark with no generation directory do not establish
repair of damaged retained generation contents. If the exact collision occurs,
the helper records it as unsupported and stops that recovery path with the hold
still active. Repairing this shape needs a separately reviewed recovery design;
this helper does not erase or move the evidence, increment generation to escape
the collision, or reinstall files outside the operator API. A different error
fails the selected checks. Successful recovery, if supported by a future exact
artifact, additionally requires the original pin/hash/counters, preserved consumer
watermarks and fresh revoked denial/control allowance.

These checks establish real consumer rejection or held last-known-good behavior
for the selected damage case. They do not establish recovery/reopening of live
Agents, production consumers, sessions or Core after authority loss. Keep the
[hold/reopen procedure](../../docs/security/launch-operations.md#backup-and-full-restore)
in force pending the remaining acceptance evidence.
