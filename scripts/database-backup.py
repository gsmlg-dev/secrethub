#!/usr/bin/env python3
"""Fail-closed SecretHub database backups. Python 3 standard library only."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, unquote, urlsplit
import uuid


class BackupError(Exception):
    pass


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "ERROR: Unsupported arguments; see --help (values redacted)\n")


INVENTORY_SQL = """
SELECT json_build_object(
  'database', current_database(),
  'server_version_num', current_setting('server_version_num')::integer,
  'migration_versions', COALESCE((SELECT json_agg(version ORDER BY version) FROM schema_migrations), '[]'::json),
  'vault', COALESCE((SELECT json_agg(json_build_object('id', id, 'envelope_version', envelope_version, 'share_version', share_version, 'share_set_id', encode(share_set_id, 'hex'), 'threshold', threshold, 'total_shares', total_shares) ORDER BY id) FROM vault_config), '[]'::json),
  'extensions', COALESCE((SELECT json_agg(json_build_object('name', extname, 'version', extversion) ORDER BY extname) FROM pg_extension), '[]'::json),
  'required_roles', COALESCE((SELECT json_agg(role ORDER BY role) FROM (
    SELECT DISTINCT pg_get_userbyid(c.relowner) AS role FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp)'
    UNION SELECT current_user
  ) roles), '[]'::json),
  'pki_authorities', COALESCE((SELECT json_agg(json_build_object('id', a.id, 'generation', a.current_generation, 'crl_number', a.current_crl_number, 'crl_sha256', c.crl_der_sha256, 'revoked_count', c.revoked_count, 'crl_next_update', c.next_update) ORDER BY a.id) FROM client_auth_authorities a LEFT JOIN client_auth_crls c ON c.id = a.current_crl_id), '[]'::json),
  'audit_signature_versions', COALESCE((SELECT json_agg(signature_version ORDER BY signature_version) FROM (SELECT DISTINCT signature_version FROM audit_logs) signatures), '[]'::json),
  'audit_signing_key_ids', COALESCE((SELECT json_agg(signing_key_id ORDER BY signing_key_id) FROM (SELECT DISTINCT signing_key_id FROM audit_logs WHERE signing_key_id IS NOT NULL) keys), '[]'::json)
);
"""

EMPTY_TARGET_SQL = """
SELECT pg_advisory_xact_lock(hashtext('SecretHub empty-target restore'));
DO $restore_guard$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname NOT IN ('public', 'pg_catalog', 'information_schema') AND nspname !~ '^pg_(toast|temp)')
     OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp)'
       AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e'))
     OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp)'
       AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e'))
     OR EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
       WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp)' AND t.typtype IN ('e', 'd', 'c', 'r')
       AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e'))
  THEN RAISE EXCEPTION 'Restore target must be empty'; END IF;
  IF EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid())
  THEN RAISE EXCEPTION 'Restore target has other clients'; END IF;
END $restore_guard$;
"""

EXTERNAL_MATERIAL = ["unseal_shares", "audit_verification_keys_and_key_ids", "deployment_configuration", "listener_material", "agent_identity", "agent_consumer_monotonic_trust_state", "authoritative_revocation_evidence"]
REMAINING_ACCEPTANCE = ["manual_unseal", "pre_backup_static_secret_read", "historical_audit_signature_verification", "pki_key_and_revocation_verification", "agent_consumer_identity_and_watermark_reconciliation"]


def now():
    return datetime.now(timezone.utc).isoformat()


def execute(args, env=None):
    # Never forward tool diagnostics: PostgreSQL errors can include credentials or COPY values.
    try:
        result = subprocess.run(args, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=3600)
    except (OSError, subprocess.SubprocessError):
        raise BackupError("Required database/storage tool failed or is unavailable") from None
    if result.returncode:
        raise BackupError("Database/storage operation failed; no sensitive tool diagnostics emitted")
    return result.stdout


def db_environment(url):
    if not url:
        raise BackupError("An explicit database URL is required")
    try:
        parsed = urlsplit(url)
        query = parse_qs(parsed.query, strict_parsing=True)
        if parsed.scheme not in ("postgres", "postgresql") or not parsed.path.strip("/"):
            raise ValueError()
        mapping = {"host": "PGHOST", "port": "PGPORT", "user": "PGUSER", "password": "PGPASSWORD", "dbname": "PGDATABASE", "sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT", "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY", "sslcrl": "PGSSLCRL", "sslcrldir": "PGSSLCRLDIR", "channel_binding": "PGCHANNELBINDING", "connect_timeout": "PGCONNECT_TIMEOUT", "options": "PGOPTIONS"}
        if set(query) - set(mapping) or any(len(value) != 1 for value in query.values()):
            raise ValueError()
        env = dict(os.environ)
        for key in mapping.values():
            env.pop(key, None)
        env.update(PGDATABASE=unquote(parsed.path[1:]), PGCONNECT_TIMEOUT="10", PGAPPNAME="secrethub-backup-restore")
        if parsed.hostname:
            env["PGHOST"] = parsed.hostname
        if parsed.port:
            env["PGPORT"] = str(parsed.port)
        if parsed.username:
            env["PGUSER"] = unquote(parsed.username)
        if parsed.password:
            env["PGPASSWORD"] = unquote(parsed.password)
        for key, value in query.items():
            env[mapping[key]] = value[0]
        return env
    except (ValueError, TypeError):
        raise BackupError("Invalid or unsupported database URL; use documented libpq parameters") from None


def tool(name):
    return os.environ.get({"pg_dump": "PG_DUMP", "pg_restore": "PG_RESTORE", "psql": "PSQL"}[name], name)


def client_major(name):
    version = execute([tool(name), "--version"])
    match = re.search(r"PostgreSQL\)?\s+(\d+)\.", version)
    if not match:
        raise BackupError("Cannot establish PostgreSQL client version")
    return int(match.group(1))


def inventory(env):
    try:
        return json.loads(execute([tool("psql"), "--no-psqlrc", "-qAt", "--set=ON_ERROR_STOP=1", "-c", INVENTORY_SQL], env))
    except json.JSONDecodeError:
        raise BackupError("Cannot establish database recovery inventory") from None


def checksum(path):
    with path.open("rb") as file:
        digest = hashlib.sha256()
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
        return digest.hexdigest()


def write_json(path, value):
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    try:
        with temporary.open("x") as file:
            json.dump(value, file, indent=2, sort_keys=True)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def reference(name):
    value = os.environ.get(name, "")
    if not value or len(value) > 512 or any(c in value for c in ("\n", "\r", "secrethub-share-", "PRIVATE KEY")):
        raise BackupError("Nonsecret deployment and external recovery inventory references are required")
    if "://" in value and urlsplit(value).username:
        raise BackupError("Recovery references must not contain credentials")
    return value


def last_restore(directory):
    path = Path(os.environ.get("BACKUP_LAST_RESTORE_REPORT", str(directory / "latest-restore.json")))
    if not path.exists():
        return None
    try:
        report = json.loads(path.read_text())
        if report["status"] != "database_restored":
            raise ValueError()
        return {key: report[key] for key in ("status", "finished_at", "duration_seconds", "backup_sha256", "remaining_acceptance")}
    except (ValueError, KeyError, OSError):
        raise BackupError("Last restore report is invalid; no restore success assumed") from None


def backup():
    directory = Path(os.environ.get("BACKUP_DIR", "/var/backups/secrethub"))
    env = db_environment(os.environ.get("DATABASE_URL"))
    deployment = {"reference": reference("BACKUP_DEPLOYMENT_REF"), "artifact_digest": reference("BACKUP_ARTIFACT_DIGEST")}
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", deployment["artifact_digest"]):
        raise BackupError("Exact sha256 artifact digest is required")
    recovery_ref = reference("BACKUP_RECOVERY_INVENTORY_REF")
    before = inventory(env)
    major = before["server_version_num"] // 10000
    if client_major("pg_dump") != major:
        raise BackupError("pg_dump major must match the source server; select PG_DUMP explicitly")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    started = now()
    name = "secrethub-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix=".backup-", dir=directory) as scratch:
        pending = Path(scratch) / (name + ".dump")
        execute([tool("pg_dump"), "--format=custom", "--no-owner", "--no-privileges", "--file=" + str(pending)], env)
        after = inventory(env)
        if before != after:
            raise BackupError("Recovery inventory changed during backup; retry after stabilizing migrations and security state")
        manifest = {"manifest_version": 1, "kind": "secrethub-database-backup", "started_at": started, "finished_at": now(), "deployment": deployment, "inventory": before,
                    "dump": {"file": pending.name, "format": "custom", "sha256": checksum(pending), "size_bytes": pending.stat().st_size, "client_major": major},
                    "external_recovery": {"inventory_ref": recovery_ref, "material_included": False, "required": EXTERNAL_MATERIAL}, "last_successful_restore": last_restore(directory)}
        destination = directory / pending.name
        os.replace(pending, destination)
        manifest_path = directory / (name + ".manifest.json")
        write_json(manifest_path, manifest)
        bucket = os.environ.get("AWS_S3_BACKUP_BUCKET")
        if bucket:
            prefix = os.environ.get("S3_PREFIX", "database-backups").strip("/")
            base = "s3://" + bucket + "/" + prefix + "/"
            execute(["aws", "s3", "cp", str(destination), base + destination.name, "--server-side-encryption", "AES256"])
            execute(["aws", "s3", "cp", str(manifest_path), base + manifest_path.name, "--server-side-encryption", "AES256"])
        write_json(directory / "latest-backup.json", manifest)
    print("Database backup committed: " + str(manifest_path))


def read_manifest(path):
    try:
        if path.stat().st_size > 1024 * 1024:
            raise ValueError()
        value = json.loads(path.read_text())
        dump = value["dump"]
        if value["manifest_version"] != 1 or value["kind"] != "secrethub-database-backup" or dump["format"] != "custom":
            raise ValueError()
        if not isinstance(dump["file"], str) or Path(dump["file"]).name != dump["file"] or not dump["file"].endswith(".dump"):
            raise ValueError()
        if not re.fullmatch(r"[0-9a-f]{64}", dump["sha256"]) or value["external_recovery"]["material_included"] is not False:
            raise ValueError()
        return value
    except (ValueError, TypeError, KeyError, OSError):
        raise BackupError("Unsupported or invalid backup manifest; unversioned dumps require a reviewed recovery procedure") from None


def restore(source, target, report_dir):
    env = db_environment(target)
    started = now()
    clock_start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="secrethub-restore-") as scratch:
        scratch = Path(scratch)
        remote = source.startswith("s3://")
        if remote:
            manifest_path = scratch / "source.manifest.json"
            execute(["aws", "s3", "cp", source, str(manifest_path)])
        else:
            manifest_path = Path(source)
        manifest = read_manifest(manifest_path)
        if remote:
            dump_path = scratch / manifest["dump"]["file"]
            execute(["aws", "s3", "cp", source.rsplit("/", 1)[0] + "/" + dump_path.name, str(dump_path)])
        else:
            dump_path = manifest_path.parent / manifest["dump"]["file"]
        if not dump_path.is_file() or dump_path.stat().st_size != manifest["dump"]["size_bytes"] or checksum(dump_path) != manifest["dump"]["sha256"]:
            raise BackupError("Backup checksum or length mismatch; target was not accessed")
        major = manifest["dump"]["client_major"]
        if client_major("pg_restore") != major or client_major("psql") != major:
            raise BackupError("Restore clients must match the backup server major")
        target_version = execute([tool("psql"), "--no-psqlrc", "-qAt", "--set=ON_ERROR_STOP=1", "-c", "SELECT current_setting('server_version_num')::integer"], env)
        if int(target_version.strip()) // 10000 != major:
            raise BackupError("Target PostgreSQL major is incompatible with this backup")
        execute([tool("pg_restore"), "--list", str(dump_path)])
        sql_path = scratch / "restore.sql"
        execute([tool("pg_restore"), "--no-owner", "--no-privileges", "--file=" + str(sql_path), str(dump_path)])
        guard_path = scratch / "empty-target.sql"
        guard_path.write_text(EMPTY_TARGET_SQL)
        execute([tool("psql"), "--no-psqlrc", "--quiet", "--single-transaction", "--set=ON_ERROR_STOP=1", "--file=" + str(guard_path), "--file=" + str(sql_path)], env)
        restored = inventory(env)
        for key in ("migration_versions", "vault", "extensions", "audit_signature_versions", "audit_signing_key_ids", "pki_authorities"):
            if restored[key] != manifest["inventory"][key]:
                raise BackupError("Restored security/schema inventory mismatch; application acceptance remains blocked")
        directory = Path(report_dir or os.environ.get("RESTORE_REPORT_DIR") or (manifest_path.parent if not remote else os.environ.get("BACKUP_DIR", ".")))
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        report = {"report_version": 1, "status": "database_restored", "started_at": started, "finished_at": now(), "duration_seconds": round(time.monotonic() - clock_start, 3), "target_database": restored["database"], "backup_sha256": manifest["dump"]["sha256"], "backup_started_at": manifest["started_at"], "remaining_acceptance": REMAINING_ACCEPTANCE}
        report_path = directory / ("restore-" + uuid.uuid4().hex + ".json")
        write_json(report_path, report)
        write_json(directory / "latest-restore.json", report)
    print("Database restored; manual application recovery checks remain required. Report: " + str(report_path))


def main():
    os.umask(0o077)
    parser = SafeArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("backup")
    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("source", help="Versioned local manifest or explicit S3 manifest URL")
    restore_parser.add_argument("--target", "-t", default=os.environ.get("RESTORE_DATABASE_URL"), help="Prefer RESTORE_DATABASE_URL environment variable to keep credentials out of argv")
    restore_parser.add_argument("--report-dir")
    restore_parser.add_argument("--yes", "-y", action="store_true", help="Compatibility flag; empty-target verification is always enforced")
    args = parser.parse_args()
    try:
        if args.action == "backup":
            backup()
        else:
            restore(args.source, args.target, args.report_dir)
    except (BackupError, OSError, ValueError, KeyError, TypeError):
        # Do not interpolate arbitrary exceptions; they may include credentials or database contents.
        message = "Backup/restore failed; no database contents or connection credentials emitted"
        exception = sys.exc_info()[1]
        if isinstance(exception, BackupError):
            message = str(exception)
        print("ERROR: " + message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
