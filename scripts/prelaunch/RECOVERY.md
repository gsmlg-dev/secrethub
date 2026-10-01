# Isolated partial recovery artifact checks

`recovery_acceptance.py` collects a restricted portion of WP5/G16/G17 from an
already restored, explicitly owned PostgreSQL fixture. It does not restore,
migrate, initialize, issue certificates, refresh CRLs, publish bundles, reconnect
Agents or authorize reopening. Every report says G16 partial, G17 partial and
`complete: false`, including when every selected check passes.

Use independently preserved shares, audit runtime keys/keyring and a private
expected pre-backup static value. Keep these outside the checkout and separate
from backup archives. Do not print their content. Prepare an owner-only fixture
root and owner-only config/env/share/expected files. The mounted input directory
and files must already be readable by service UID1001 through the container bind;
the harness never changes permissions. Existing runtime inputs must reference
files below `core_input_mount`, and the database URL must select the explicit
fixture database with `socket_dir=/socket` and hostname `localhost`.

Private configuration schema (all paths absolute; no actual keys or values here):

```json
{
  "isolated_fixture": true,
  "fixture_prefix": "secrethub-prelaunch-restore-example",
  "fixture_root": "/private/owned-fixture",
  "fixture_postgres_container": "secrethub-prelaunch-restore-example-db",
  "fixture_database": "secrethub_prelaunch_restore_example",
  "fixture_postgres_user": "secrethub",
  "fixture_postgres_socket": "/socket",
  "fixture_socket_dir": "/private/owned-fixture/socket",
  "core_env_file": "/private/owned-fixture/core.env",
  "core_input_dir": "/private/owned-fixture/core-inputs",
  "core_input_mount": "/prelaunch-input",
  "core_image_id": "sha256:<64 lowercase hex digits>",
  "agent_image_id": "sha256:<64 lowercase hex digits>",
  "source_sha": "<40 lowercase hex digits>",
  "platform": "linux/amd64",
  "provisional": true,
  "retained_consumer_generation": 3,
  "retained_consumer_crl_number": 3
}
```

`fixture_postgres_user`, `fixture_postgres_socket`, `core_input_mount` and
`provisional` have the defaults shown except `provisional` defaults to false.
The fixture prefix must begin `secrethub-prelaunch-`; the existing PostgreSQL
container must have that prefix. This is explicit operator ownership, not
permission to use a live database with a similar name. Quiesce all other fixture
clients first. The helper reads inventory through existing `docker exec psql`
with read-only transactions and bounded statement/command timeouts.

The shares file is a JSON array of encoded shares. The independent expected file
is a JSON object with exactly `secret_path` (string) and `secret_data` (object),
using the persisted static data shape. Config, shares and expected files must be
different owner-only regular files. Supply enough distinct correct shares for
the restored threshold; the program submits only that threshold. It never
stores shares in environment variables or image configuration. Both shares and
expected content travel to the release eval on stdin, never command arguments.

```sh
python3 -B scripts/prelaunch/recovery_acceptance.py \
  --config /private/owned-fixture/recovery-config.json \
  --shares-file /independent/private/recovery-shares.json \
  --expected-file /independent/private/pre-backup-static.json \
  --output /private/owned-fixture/new-recovery-report.json
```

The output must be a new file beside the private config. Exit 0 means only the
selected partial checks passed. A failed check returns nonzero; it never prints
exception messages, SQL output, secret values or release diagnostics. Raw
stdout/stderr stay in process memory, are checked for share/static-value strings,
and contribute only a digest to the private report.

The helper inspects the exact Core/Agent IDs and Linux amd64 platform. Final mode
also requires the exact source revision/source/MIT image labels. Configured image
users must be `secrethub` or the respective numeric service user (1001 for Core,
1002 for Agent). The Core eval verifies `id -u` equals 1001. Agent metadata is
validated, but Agent is never started or reconnected; its actual default numeric
UID proof belongs to the real G11 lifecycle drill. Freeze compatible artifacts
and complete those independent checks before claiming candidate acceptance.

One uniquely named transient Core eval runs as UID1001 with `--network none`, a
read-only filesystem, read-only PostgreSQL Unix socket and runtime-input binds,
no published ports, no capabilities and a private ephemeral temp directory. It
starts only Core and its dependencies. Immediately after Core starts it
terminates the supervised `SecretHub.Core.Workers.ClientAuthCRLRefresher` child;
this is essential because normal Core eval starts that worker and unseal triggers
reconciliation. Only then does it wait at most 15 seconds for initialized sealed
Vault state and manually submit the shares. It verifies the worker remains absent,
no web/Agent/human application started, and no TCP/UDP sockets exist before and
after retrieval. This restricted process cannot pass normal serving readiness.

Retrieval compares a static secret using `Secrets.read_decrypted/1`, verifies the
historical Audit chain using the preserved signing/verification inputs and uses
`ClientAuth.get_active_ca_and_key/0` to sign and verify a random in-memory
challenge against the original CA public key. It creates no certificate or CRL.
Before startup and after exit, it compares the complete persisted Vault,
ClientAuth authority/CRL, certificate, identity, issuance-request and receipt
inventory. Historical audit rows must remain identical; manual unseal appends
new audit rows, and Core startup may write fixture cluster bookkeeping. The DB
and all persistent fixture/consumer state remain retained. The harness removes
only its own unique container and verifies ownership before forced cleanup.

G17's partial check compares restored publication generation/CRL number with
operator-supplied consumer counters. For example restored generation/CRL 1 is
below supplied consumer 3, conditional on the accuracy of that supplied history.
The helper does not inspect live consumer watermarks, and the report records
that limitation and the counters' source explicitly. Actual
old-bundle refusal, authoritative revocation reconciliation, revoked denial and
an unrevoked control request are still unexecuted. No selected pass lifts the
recovery hold. Follow the [hold/reopen procedure](../../docs/security/launch-operations.md#backup-and-full-restore).
