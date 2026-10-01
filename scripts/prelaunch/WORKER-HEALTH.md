# Required CRL worker failure and recovery on a copied fixture

`worker_health_acceptance.py` collects selected WP5/G20 health evidence using the
exact Core image. It observes a healthy required CRL refresher, terminates that
supervised child, observes failed background health and secret readiness while
the Vault remains unsealed, explicitly restarts the child, and observes recovery.
It invokes the real `SecretHub.Core.Health` APIs and records bounded, allowlisted
worker-state observations. It does not exercise host alert delivery.

The operator must first prepare a **quiesced copy** of an isolated fixture database
with the candidate schema, initialized Vault, active ClientAuth authority and
persisted current CRL. Use a separate PostgreSQL container, database name and
socket directory. Quiesce all other clients of the copy. Preserve the original
fixture services and state. This helper performs no copying, migration, database
repair, initialization, enrollment or secret retrieval. In particular, legacy
SQL `text[]` policy repair remains outside this helper's authorization.

Unlike the restricted [recovery helper](RECOVERY.md), this helper permits normal
CRL reconciliation **only on the copied database**. Reconciliation may refresh
the CRL and publish a new generation there. Manual unseal appends audit records,
and Core startup/heartbeats may write cluster bookkeeping. All copied persistent
state remains retained for review; there is no inventory-unchanged claim or SQL
cleanup. Never point this helper at the original database or production.

Use the private configuration schema in [RECOVERY.md](RECOVERY.md), retaining its
Core/Agent image metadata fields, source SHA, Linux amd64 platform, absolute
copied socket/runtime-input paths and retained-consumer counter fields. The
retained counters are required by the shared configuration validator and are
unused by this drill. Add these explicit operator assertions and original public
identifiers:

```json
{
  "copied_database": true,
  "quiesced_fixture": true,
  "fixture_prefix": "secrethub-prelaunch-worker-copy",
  "fixture_postgres_container": "secrethub-prelaunch-worker-copy-db",
  "fixture_database": "secrethub_prelaunch_worker_copy",
  "original_fixture_postgres_container": "secrethub-prelaunch-original-db",
  "original_fixture_database": "secrethub_prelaunch_original",
  "provisional": true
}
```

The original identifiers must differ from the copied container/database names.
They are guards and documentation, not proof that a backup was copied correctly.
Artifact inspection checks that the copied PostgreSQL container is running and
binds the supplied `/socket` directory. A read-only `pg_stat_activity` preflight
requires no other copied-database sessions. It does not stop clients; keeping
the copy quiesced throughout the drill is the operator's responsibility.

The fixture root must be owner-only and outside the checkout. Config, environment
and shares files must be owner-only regular files, with no symlinks in any path
component. The copied Core input directory/files must be owned by the operator
or service UID1001. The input directory may be mode0755 inside the owner-only
fixture root, but must not be group/other writable. Input files may use read-only service-group
access (GID1001, mode0640), with no other access or group write/execute bits.
They must already be readable by UID1001 through the bind mount. The helper
never changes permissions. Every runtime `*_FILE`
source must remain inside the copied Core input mount. The database URL must
select the copied database, `localhost` and `socket_dir=/socket` as specified in
RECOVERY.md. No URL, environment content or exception message is printed.

Prepare this helper's Core environment without `SECRET_HUB_CLUSTER_NODE_ID_FILE`.
Each evaluator overrides the direct node ID with its unique invocation-owned
container name. A conflicting node-ID file source, including one inherited from
the image, is rejected. Other copied runtime inputs include the preserved audit
key/keyring required by the candidate. No serving node identity is reused.

Independently held shares must be outside both the checkout and copied fixture
root. Supply a separate private JSON file containing a nonempty array of distinct
encoded shares, sufficient for the persisted threshold. Shares are read locally
and sent to the release program over stdin; they never enter Docker command
arguments, environment or image configuration. No expected-secret file is used.

```sh
python3 -B scripts/prelaunch/worker_health_acceptance.py \
  --config /private/copied-fixture/worker-health-config.json \
  --shares-file /independent/private/recovery-shares.json \
  --output /private/copied-fixture/new-worker-health-report.json
```

The output must be a new owner-only JSON file beside the config. The helper
inspects immutable Core/Agent image IDs, platform and configured service users;
nonprovisional input additionally requires the revision/source/license labels
used by the recovery harness. Agent metadata is inspected; no Agent starts.
The report always remains provisional regardless of label inspection.

The evaluator is tracked before `docker create`, labeled with its invocation
owner, and started attached with private stdin. It uses the exact Core image,
UID1001, `--network none`, a read-only root, read-only Unix-socket/input binds,
dropped capabilities and a private temporary directory. Only Core and its
dependencies start. The program verifies its UID and the absence of
web/Agent/human applications and TCP/UDP sockets before and after the drill.
There are no management, machine, Agent or distribution listeners.

After waiting at most 15 seconds for initialized sealed state without recovery
required, it manually submits only the persisted threshold of shares. It then
requires an actual active authority/current CRL and waits at most 20 seconds for
healthy required-worker background health and ready secret-serving health.
The initial snapshot records a running supervised enabled worker, a reconciliation
heartbeat, live next-check timer, retry count and absence of worker error.

`Supervisor.terminate_child/2` stops that child without automatic restart. The
stopped snapshot must show no running/supervised worker,
`crl_worker_unavailable`, failed background health, failed secret readiness and
degraded overall health. Seal health must still pass with `sealed:false`.
Liveness and management readiness must remain available through the internal
Health API. Protected HTTP/Caddy availability is unexecuted in this network-free
drill. `Supervisor.restart_child/2` must return a new PID; another bounded
20-second wait and snapshot require complete worker/readiness recovery.
The attached evaluator command has an overall 90-second timeout.

On success, failure or timeout, cleanup removes only the uniquely tracked
container after inspecting its owner label and confirms its absence with another
Docker query. An unconfirmed absence or ownership mismatch fails selected checks;
the helper does not remove an unrelated container or restart any fixture service.
If cleanup cannot be confirmed, the operator must inspect the retained owned
container before any further drill. The database and private inputs are retained.
Raw subprocess output stays in memory and contributes only a diagnostic digest;
result parsing accepts only exact phase schemas and known status/reason values.
Failures report a fixed code and stage, with no raw diagnostics or private values.

Exit0 means only the selected worker-health lifecycle passed, with confirmed
cleanup. Every report records G20 partial, `alert_delivery:unexecuted`,
`monitoring:partial`, `complete:false`, `provisional:true` and `recovery_hold:true`.
Existing host alert routing, delivery and recovery notification still require a
separate operator drill. No selected pass completes WP5, reopens recovery,
authorizes publication/deployment or establishes launch acceptance.
