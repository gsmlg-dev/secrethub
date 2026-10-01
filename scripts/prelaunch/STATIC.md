# Real static consumer acceptance

`static_acceptance.py` exercises selected G12/G13 scenarios through the independent
`static-consumer.py` image, the actual owner-only Agent socket, application
certificate/private-key proof with UDS auth version 2, and the selected Core/Agent
release images. It does not initialize a Vault, enroll an Agent, issue an
application certificate, activate an authentication floor or provision policies.
Prepare those disposable fixtures through their existing APIs first.

Use the private [runtime config](RUNTIME.md) and add an immutable
`consumer_image_id` plus:

```json
{
  "static_fixture": {
    "directory": "/private/fixture/static-consumer",
    "secret_id": "<existing disposable static secret UUID>",
    "app_id": "<existing application UUID>",
    "policy_ids": ["<sole application allow-policy UUID>"],
    "agent_policy_id": "<separate Agent allow-policy UUID>",
    "agent_uuid": "<database Agent UUID>",
    "path": "prelaunch.static.consumer",
    "denied_path": "prelaunch.static.denied",
    "cache_ttl_seconds": 300,
    "expected_versions": [1, 2]
  }
}
```

The directory belongs to UID/GID1002 with mode0700. It contains `app.crt`,
`app.key`, `expected1.json`, `expected2.json` and optionally an existing
`output.json`, each owned by UID1002 with mode0600. JSON expected values are
private and must differ. The initial secret contains `secret_data:
%{"value" => expected1}`. The update uses the supported `secret_data` map API
with `%{"value" => expected2}`; the virtual string `value` attribute is not used.
The consumer unwraps this value and compares it to the expected JSON before
application. The harness leaves the disposable secret at version2 after execution.
The actual revision is read from Core metadata and the real consumer response;
it must advance after update and need not equal the version.

All `policy_ids` must identify disposable allow policies whose sole typed binding
is exactly `application:<app_id>`. The separate Agent policy is never changed.
The harness compares the complete original policy attributes before deletion,
deletes those application policies through `Policies.delete_policy/1`, then
regrants through `Policies.create_policy/1` with the original name, document,
conditions and binding. This changes policy UUIDs, reported as an old-to-new map.
An empty binding would make a policy global; a nonexistent typed application is
rejected by the current API. Neither is used. Regrant also runs on failure; a
restoration mismatch fails the checks rather than overwriting another policy.

The config and independently held shares JSON are owner-only regular files
outside the checkout. The output directory must be new and beside the config:

```sh
python3 -B scripts/prelaunch/static_acceptance.py \
  --config /private/fixture/static-config.private.json \
  --shares-file /private/fixture/recovery-shares.private.json \
  --output /private/fixture/new-static-result
```

Only the explicitly configured fixture Core/Agent containers are restarted; only
that Core is paused/unpaused. Its inspected immutable image must match config.
The consumer image must run as UID1002 on the selected platform and contain the
exact repository `static-consumer.py` program, independently checked by hash.
The Agent's inspected bind mapping must place the socket at `run/agent.sock`.
The harness mounts that directory read-only at `/agent-fixture` and the consumer
fixture at `/consumer-fixture`. Transient consumers have no network, a read-only
root filesystem, dropped capabilities and private output bind access.

The selected checks cover:

1. Initial version1 readback and denied-path rejection through real UDS requests.
   The consumer fsyncs a private temporary file, atomically replaces output and
   fsyncs its directory. Independent file inspection requires mode0600, exact
   expected JSON, no remaining consumer temporary file and a changed inode on
   replacement. A denied request must preserve file bytes, inode, mode and value.
2. A fixture-only secret update to version2 and a larger actual revision, followed
   by successful consumer readback of that exact metadata and expected value.
3. A successful warm-up read, real application-policy deletion, denied read with
   output preserved, original-binding regrant and successful version2 readback.
4. Agent restart with the same certificate/key/CA digests and authentication
   floor, no new enrollment, a heartbeat later than restart completion and
   successful version2 consumer readback.
5. Core restart, observed sealed state, manual protected-mTLS unseal with held
   shares, a fresh reconnect heartbeat, unchanged Agent identity/enrollments and
   successful version2 consumer readback.
6. Successful warm-up, fixture Core pause, actual denied consumer request with
   private output preserved, bounded unpause in `finally`, and restored readback.
   The current UDS server reports unavailable reads as `UNAVAILABLE`, which the
   existing consumer intentionally collapses to `REQUEST_DENIED`; the harness
   records that actual code and the independently observed paused state. It does
   not infer an outage from a generic socket or readback exception.

Every cached release requires fresh Core authorization of the exact revision in
the current implementation. The selected warm-up/revocation/outage requests test
that external behavior. The current production consumer response does not expose
cache-hit or TTL provenance, and a separate release `eval` process cannot observe
the live Agent cache when distribution is disabled. Therefore G13 remains partial:
live TTL expiry and direct cache-hit provenance are explicitly unexecuted. No
sleep, unrelated evaluation or repeated outage read is presented as expiry proof.
The default configured TTL is recorded as300 seconds, with no offline fallback
success claimed. A future scoped live observable requires review before adding an
expiry assertion or changing the report status.

Private expected values are read through a UID1002 consumer process into harness
memory, excluded from diagnostic stdout capture, then sent with shares on stdin
to a bounded, named, invocation-owned Core-only release container for the update. They never
appear in command arguments, report values or exported files. That evaluation
immediately stops its supervised Client Auth CRL refresher; the serving Core and
its management unseal remain separate. All Core operations, including heartbeat
and enrollment queries, use that owned lifetime rather than `docker exec`.
Identity snapshots use an owned Agent-image evaluator with read-only state mounts.
Each evaluator uses the exact selected image, service UID, inspected runtime bind
mounts and private environment, with no network, web startup or distribution.
Each Core evaluator overrides `SECRET_HUB_CLUSTER_NODE_ID` after its environment
file with its unique owned container name. The borrowed raw/file node-ID source
is removed from that file and retained under a separate private observer input;
conflicting raw-plus-file sources fail setup. The running evaluator verifies its
actual configured node ID equals the override and differs from the serving ID.
Normal Core startup and termination retain incidental unique evaluator rows in
`cluster_nodes`; this helper neither deletes those rows nor bypasses cluster
startup. Evaluations must preserve the serving node's incarnation, started time,
hostname, version and capabilities. Before/after observations also record status;
heartbeat/status/leader/sealed changes are excluded from identity comparisons.
Cross-evaluation identity comparisons use separate before/after baselines around
the intentional serving Core restart and manual unseal. Pre-existing stale
serving-node metadata is recorded as observed rather than backfilled by this
helper; the intentional service restart establishes its next incarnation.
The host CLI timeout always runs daemon-side force cleanup and confirms container
absence before any operation returns or policy restoration proceeds. Failed
absence confirmation blocks continuation and keeps cleanup unconfirmed.
Runtime environment copies remain in owner-only `core-eval.private.env` and
`agent-eval.private.env` files under the private result directory; exclude those
files from evidence exports alongside keys and shares. Raw process diagnostics stay in memory
and only a combined digest is reported. Inspection digests of low-entropy secret
output stay internal; the report contains booleans and public version/revision
metadata, not a reusable secret-value hash.

`static-report.json` always says `complete:false`, provisional status and recovery
hold. Exit0 means only the selected checks passed. G12 may pass while G13 remains
partial; neither establishes the full launch gate. Cleanup stops invocation-owned
consumer and evaluator processes before restoration, unpauses the fixture Core, restores its application policy
binding and completes manual unseal if a restart interrupted execution. It retains
the consumer configuration, keys, expected files and updated secret for inspection.
Cleanup failure fails selected checks. Never export the private fixture, held
shares or raw logs with this redacted report.
