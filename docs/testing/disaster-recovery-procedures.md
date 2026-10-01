# Database backup and recovery rehearsal

This document defines the supported backup tooling and its isolated database
checks. The launch operations runbook and exact-artifact harness own service and
consumer acceptance. A database restore alone does not establish application
recovery, RPO, or RTO.

## Supported contract and tools

Use the operator's existing local destination through `BACKUP_DIR`. S3 is
optional and uses only an explicitly supplied `AWS_S3_BACKUP_BUCKET` and
`S3_PREFIX`; there is no default bucket, lifecycle mutation, storage-provider
setup, retention deletion, or notification. Existing infrastructure owns storage
policy and backup cadence.

The host running these scripts needs Bash, Python 3.8 or newer, and PostgreSQL
`pg_dump`, `pg_restore`, and `psql`. Select pinned executables with `PG_DUMP`,
`PG_RESTORE`, and `PSQL` when needed. The clients must match the source/target
server major version; a PostgreSQL 16 backup requires PostgreSQL 16 restore
clients and server. AWS CLI is needed only for an explicitly selected S3 path.
Tool overrides are executable paths, not shell command strings. A container
wrapper must forward database variables and stdin and correctly map input and
output files to its container filesystem.

Supported archives are PostgreSQL custom-format dumps with a version 1
SecretHub JSON manifest. Unversioned legacy `.sql.gz` files do not enter this
path; migrate them only through an independently reviewed recovery procedure.
The scripts do not reset or erase unknown existing data.

## Independently held recovery inventory

Keep these available independently of SecretHub and its database dump:

- The unseal shares and their supported Vault/share generation and format.
- All current and historical audit verification keys and key IDs, including the
  legacy verification key when historical signatures require it.
- The exact deployment configuration and image/artifact digest, database role
  setup, and required extension provisioning.
- Required listener private keys, certificates, trust roots, and protected Caddy
  ingress configuration, in the existing secure configuration system.
- Agent identity and persisted Agent/consumer trust history, including Caddy
  applied generation/digest watermarks and revocation evidence.

`BACKUP_RECOVERY_INVENTORY_REF` identifies the independently held inventory; it
must contain a nonsecret reference, never key bytes, shares, or credentials.
The manifest records required categories and explicitly states that unlock
material is excluded. Do not bundle a dump with the material needed to unlock
it, and do not store the only copy of recovery material inside SecretHub.

The custom dump contains database schema and data. It does not contain
cluster-global role provisioning, deployment secrets, or local Agent/consumer
state. The manifest records database roles and extension versions as inventory,
not as a claim that cluster-global role definitions or passwords were backed up.
Provision the selected runtime's owner/application roles and required extensions
separately before recovery. Dumps use `--no-owner --no-privileges`; the restore
role must match the reviewed runtime's intended object ownership and grants.

## Backup

Supply `DATABASE_URL` through the existing protected environment mechanism. Do
not paste credentials into commands or logs. Configure `BACKUP_DIR`,
`BACKUP_DEPLOYMENT_REF`, an exact `BACKUP_ARTIFACT_DIGEST` of the form
`sha256:<64 lowercase hex digits>`, and `BACKUP_RECOVERY_INVENTORY_REF`.

```bash
scripts/backup-database.sh
```

Each successful backup creates a private `.dump` and `.manifest.json` pair and
atomically updates `latest-backup.json`. The manifest records UTC start/finish
times, dump SHA-256 and length, selected artifact/deployment references,
PostgreSQL major, schema migration versions, Vault ID/format/generation and
sharing parameters, extension/role inventory, audit signature versions/key IDs,
and PKI generation/CRL metadata. It contains no shares, data keys, signing keys,
listener keys, or connection credentials.

The script checks recovery metadata before and after the consistent PostgreSQL
snapshot and fails if that metadata changes. Stabilize migrations, key changes,
and relevant trust changes before retrying. Ordinary secret writes remain
covered by PostgreSQL's consistent dump snapshot. Backups do not include writes
committed after that snapshot. Checksums detect corruption; they are not
independent proof of an archive's origin. Use a trusted existing destination.

If an optional S3 upload fails, the command fails and does not advance the latest
backup marker; the private local archive/manifest remain available. The script
never changes bucket policies. Storage retention belongs to the existing
configuration system, with dumps and manifests retained together.

## Empty-target restore

Keep Core and consumers offline or isolated from production traffic. Explicitly
select a newly provisioned empty database through `RESTORE_DATABASE_URL`; the
script never defaults the target to source `DATABASE_URL`. Select the pinned
PostgreSQL clients and the local manifest, or an explicit S3 manifest URL:

```bash
scripts/restore-database.sh /operator/existing/destination/backup.manifest.json
```

The script validates the supported manifest, local filename, checksum, archive
length, archive framing, and matching server/client major before importing. It
requires an empty target with no other clients. Required preprovisioned extension
objects are allowed; unrelated tables, sequences, types, routines, or schemas
are rejected. Empty-target verification and import occur in one transaction;
a late SQL failure rolls back imported objects. There is no schema drop,
connection termination, verification bypass, or automatic retry that overwrites
state. `--yes` is only a compatibility flag; verification is always enforced.
A repeated restore to a populated target fails without replacing its contents.

Restore clients receive credentials through process environment instead of
command arguments. The helper suppresses PostgreSQL diagnostics because errors
can include connection credentials or COPY values. Logs identify the failed
operation generically; investigate only in the protected isolated environment.

After import, the script compares the restored schema/security inventory with
the manifest. Persistent private `restore-<id>.json` and `latest-restore.json`
reports record the measured database duration, backup checksum/time, and
`status=database_restored`. They explicitly list application checks still
required. Choose `RESTORE_REPORT_DIR` or `--report-dir` for reports when needed;
local restores default to the manifest directory, and remote restores use
`BACKUP_DIR` or the current directory. Reports outlive temporary restore files.
The next backup incorporates the last successful database restore summary,
using `BACKUP_LAST_RESTORE_REPORT` when it is held in a different directory.

## Full application recovery gate

Run the release/image harness against the isolated restored database and the
independently held recovery material. Before allowing service, prove all of:

1. Explicit schema/role/extension restoration and production runtime startup.
2. Restart-sealed behavior and authenticated manual unseal using the preserved
   shares. Legacy recovery must satisfy [Vault key integrity](../security/vault-key-integrity.md).
3. A pre-backup static secret read and historical audit signature verification,
   including old key IDs after audit-key rotation.
4. PKI private-key use and safe interpretation of certificate revocation and CRL
   state, without creating a replacement authority.
5. Existing Agents and consumers reconnect with the same identities and persisted
   monotonic trust history.

Rehearse the difficult case using a database older than an independently retained
Agent/Caddy watermark or a later revocation. Keep affected issuance/publication
restricted and consumers offline until known authoritative evidence or an
explicit reviewed operator procedure safely reconciles the missing state.
Never lower consumer watermarks, wipe Agent state, automatically create a fresh
CA, or bump generation to make older state appear current. Database restoration
does not restore later security decisions. Preserve independent revocation and
trust evidence; a manifest cannot replace it.

## Compatibility, timing, and evidence

A binary downgrade is supported only across compatible database schema, key
formats, share formats, and audit-signature contracts. The Vault migration refuses
downgrade once new authenticated envelope/generation metadata exists; bare
legacy schema downgrade/reupgrade is separately tested without rewriting its
key material. Stop writes and use a reviewed migration/recovery path when a
binary/schema pair is incompatible. An older dump loses later writes and
possibly later revocations; it is not a risk-free rollback.

Do not claim a recovery objective before measuring it. Record both database
restore time and the full elapsed time through consumer acceptance. Compute the
observed data-loss window from the snapshot time and incident/recovery evidence;
a configured daily cadence alone cannot prove an RPO. The manifest/report
provide timing evidence, not an automatic RPO/RTO target.

The scoped test command uses fake tools by default and never touches an existing
source database. Real PostgreSQL tests require explicit opt-in, the private
isolated Unix socket, pinned tool paths, and an already migrated test template:

```bash
scripts/test-backup-restore.sh
# Set SECRET_HUB_BACKUP_TEST_ADMIN_URL, SECRET_HUB_BACKUP_TEST_TEMPLATE,
# PG_DUMP, PG_RESTORE and PSQL to isolated fixture settings, then run again.
```

The real fixture clones the migrated test template into uniquely named,
test-owned databases, adds only test data, restores to another empty fixture,
checks inventory and opaque bytes, rejects repeated restore, and proves rollback
on a late injected SQL failure. It removes only its own newly created fixtures.
No S3/bucket policy or production data is accessed. Report these checks as
scoped database/tooling evidence; the full application gate remains separate.
