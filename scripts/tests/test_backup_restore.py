"""Scoped backup contract tests. All process tools are fakes unless explicitly opted in."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BackupContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.events = self.directory / "events"
        self.inventory = {
            "database": "fixture", "server_version_num": 160014,
            "migration_versions": [20261001000001, 20261001000002],
            "vault": [{"id": "fixture-vault", "envelope_version": 1, "share_version": 4, "share_set_id": "00" * 16, "threshold": 3, "total_shares": 5}],
            "extensions": [{"name": "pgcrypto", "version": "1.3"}],
            "required_roles": ["secrethub"], "audit_signature_versions": [1, 2],
            "audit_signing_key_ids": ["fixture-audit"],
            "pki_authorities": [{"id": "fixture-authority", "generation": 7, "crl_number": 9, "crl_sha256": None, "revoked_count": None, "crl_next_update": None}],
        }
        inventory_file = self.directory / "inventory.json"
        inventory_file.write_text(json.dumps(self.inventory))
        tool = '''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
with open(os.environ["FAKE_EVENTS"], "a") as events: events.write(name + "\\n")
args = sys.argv[1:]
if "--version" in args:
    print(name + " (PostgreSQL) " + os.environ.get("FAKE_CLIENT_VERSION", "16.14")); sys.exit(0)
if name == "aws": sys.exit(0 if os.environ.get("FAKE_AWS_OK") == "1" else 91)
if name == "pg_dump":
    output = next((a.split("=", 1)[1] for a in args if a.startswith("--file=")), None)
    if output is None and "--file" in args: output = args[args.index("--file") + 1]
    if output:
        pathlib.Path(output).write_bytes(b"PGDMP fixture dump"); print("Dump complete")
    else: sys.stdout.buffer.write(b"PGDMP fixture dump")
elif name == "pg_restore":
    if "--list" in args: print("fixture archive")
    else:
        output = next((a.split("=", 1)[1] for a in args if a.startswith("--file=")), None)
        if output: pathlib.Path(output).write_text("CREATE TABLE fixture (id integer);")
        else: print("CREATE TABLE fixture (id integer);")
elif name == "psql":
    query = args[args.index("-c") + 1] if "-c" in args else sys.stdin.read()
    if "json_build_object" in query: print(pathlib.Path(os.environ["FAKE_INVENTORY"]).read_text())
    elif "server_version_num" in query: print("160014")
    elif os.environ.get("FAKE_TARGET_POPULATED") == "1":
        print("private-db-password should never be logged", file=sys.stderr); sys.exit(42)
'''
        for name in ["pg_dump", "pg_restore", "psql", "aws"]:
            file = self.bin / name
            file.write_text(tool)
            file.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        DATABASE_URL="postgresql://secrethub:private-db-password@localhost/fixture",
                        RESTORE_DATABASE_URL="postgresql://secrethub:private-db-password@localhost/target",
                        BACKUP_DIR=str(self.directory / "backups"),
                        BACKUP_DEPLOYMENT_REF="fixture-source-revision",
                        BACKUP_ARTIFACT_DIGEST="sha256:" + "a" * 64,
                        BACKUP_RECOVERY_INVENTORY_REF="independently-held-fixture-inventory",
                        FAKE_EVENTS=str(self.events), FAKE_INVENTORY=str(inventory_file),
                        PG_DUMP=str(self.bin / "pg_dump"), PG_RESTORE=str(self.bin / "pg_restore"), PSQL=str(self.bin / "psql"))
        self.env.pop("AWS_S3_BACKUP_BUCKET", None)
        self.env.pop("SLACK_WEBHOOK_URL", None)

    def run_script(self, script, *args, **extra):
        return subprocess.run([str(ROOT / "scripts" / script), *args], env=dict(self.env, **extra), text=True, capture_output=True, timeout=15)

    def backup(self):
        result = self.run_script("backup-database.sh")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return Path(self.env["BACKUP_DIR"]) / "latest-backup.json"

    def test_local_backup_has_checksum_inventory_and_no_network_or_unlock_material(self):
        manifest_path = self.backup()
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest["manifest_version"], 1)
        self.assertEqual(manifest["inventory"], self.inventory)
        self.assertRegex(manifest["dump"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(manifest["external_recovery"]["material_included"])
        self.assertIsNone(manifest["last_successful_restore"])
        self.assertNotIn("aws", self.events.read_text())
        self.assertNotIn("private-db-password", manifest_path.read_text())
        self.assertEqual(manifest_path.stat().st_mode & 0o777, 0o600)

    def test_restore_requires_explicit_separate_target(self):
        manifest = self.backup()
        self.env.pop("RESTORE_DATABASE_URL")
        result = self.run_script("restore-database.sh", str(manifest), "--yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("private-db-password", result.stdout + result.stderr)

    def test_checksum_mismatch_is_rejected_before_target_access(self):
        manifest = self.backup()
        payload = json.loads(manifest.read_text())
        (manifest.parent / payload["dump"]["file"]).write_bytes(b"tampered")
        self.events.write_text("")
        result = self.run_script("restore-database.sh", str(manifest), "--yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("psql", self.events.read_text())

    def test_populated_target_refuses_without_dropping_or_leaking_diagnostics(self):
        manifest = self.backup()
        result = self.run_script("restore-database.sh", str(manifest), "--yes", FAKE_TARGET_POPULATED="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("private-db-password", result.stdout + result.stderr)
        self.assertFalse((manifest.parent / "latest-restore.json").exists())

    def test_success_report_persists_and_does_not_claim_full_recovery(self):
        manifest = self.backup()
        result = self.run_script("restore-database.sh", str(manifest), "--yes")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads((manifest.parent / "latest-restore.json").read_text())
        self.assertEqual(report["status"], "database_restored")
        self.assertIn("manual_unseal", report["remaining_acceptance"])
        manifest = self.backup()
        self.assertEqual(json.loads(manifest.read_text())["last_successful_restore"]["status"], "database_restored")

    def test_incompatible_client_and_unversioned_dump_fail_closed(self):
        result = self.run_script("backup-database.sh", FAKE_CLIENT_VERSION="17.11")
        self.assertNotEqual(result.returncode, 0)
        unversioned = self.directory / "old.sql.gz"
        unversioned.write_bytes(b"not-a-supported-backup")
        result = self.run_script("restore-database.sh", str(unversioned), "--yes")
        self.assertNotEqual(result.returncode, 0)

    def test_optional_existing_s3_uploads_only_archive_and_manifest(self):
        result = self.run_script("backup-database.sh", AWS_S3_BACKUP_BUCKET="configured-fixture-only", FAKE_AWS_OK="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events.read_text().splitlines().count("aws"), 2)
        self.assertTrue((Path(self.env["BACKUP_DIR"]) / "latest-backup.json").exists())

    def test_s3_failure_retains_local_pair_without_advancing_latest_marker(self):
        result = self.run_script("backup-database.sh", AWS_S3_BACKUP_BUCKET="configured-fixture-only")
        self.assertNotEqual(result.returncode, 0)
        directory = Path(self.env["BACKUP_DIR"])
        self.assertFalse((directory / "latest-backup.json").exists())
        self.assertEqual(len(list(directory.glob("*.dump"))), 1)
        self.assertEqual(len(list(directory.glob("*.manifest.json"))), 1)

    def test_unknown_arguments_do_not_echo_credentials(self):
        result = self.run_script("backup-database.sh", "private-db-password")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("private-db-password", result.stdout + result.stderr)

    def test_manifest_paths_cannot_escape_backup_directory(self):
        manifest = self.backup()
        payload = json.loads(manifest.read_text())
        payload["dump"]["file"] = "../outside.dump"
        manifest.write_text(json.dumps(payload))
        result = self.run_script("restore-database.sh", str(manifest), "--yes")
        self.assertNotEqual(result.returncode, 0)


@unittest.skipUnless(os.environ.get("SECRET_HUB_BACKUP_TEST_ADMIN_URL"), "set an isolated fixture admin URL for real PostgreSQL tests")
class DatabaseRestoreIntegrationTest(unittest.TestCase):
    def setUp(self):
        import importlib.util
        import uuid
        spec = importlib.util.spec_from_file_location("backup_helper", ROOT / "scripts/database-backup.py")
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        self.admin_env = self.helper.db_environment(os.environ["SECRET_HUB_BACKUP_TEST_ADMIN_URL"])
        self.assertTrue(self.admin_env.get("PGHOST", "").startswith("/tmp/secrethub-prelaunch-"), "real tests require the isolated private Unix socket")
        template = os.environ.get("SECRET_HUB_BACKUP_TEST_TEMPLATE", "secrethub_test_vault")
        self.assertRegex(template, r"^secrethub_test_[a-z0-9_]+$")
        suffix = uuid.uuid4().hex[:12]
        self.source = "secrethub_backup_src_" + suffix
        self.target = "secrethub_backup_dst_" + suffix
        self.run_sql(self.admin_env, 'CREATE DATABASE "' + self.source + '" TEMPLATE "' + template + '"')
        self.addCleanup(self.run_sql, self.admin_env, 'DROP DATABASE "' + self.source + '"')
        self.run_sql(self.admin_env, 'CREATE DATABASE "' + self.target + '" TEMPLATE template0')
        self.addCleanup(self.run_sql, self.admin_env, 'DROP DATABASE "' + self.target + '"')
        self.source_env = dict(self.admin_env, PGDATABASE=self.source)
        self.target_env = dict(self.admin_env, PGDATABASE=self.target)
        self.run_sql(self.source_env, "CREATE TABLE backup_contract_fixture (id integer PRIMARY KEY, opaque_value bytea); INSERT INTO backup_contract_fixture VALUES (1, decode('001122ff', 'hex'))")
        self.run_sql(self.source_env, "INSERT INTO client_auth_authorities (id, slug, name, status, key_algorithm, current_generation, current_crl_number, default_ttl_seconds, max_ttl_seconds, inserted_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000001', 'client-auth', 'backup fixture', 'initializing', 'ecdsa_p384', 7, 9, 3600, 7200, now(), now())")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        directory = Path(self.temp.name)
        self.env = dict(os.environ, BACKUP_DIR=str(directory), BACKUP_DEPLOYMENT_REF="isolated-test-fixture", BACKUP_ARTIFACT_DIGEST="sha256:" + "b" * 64, BACKUP_RECOVERY_INVENTORY_REF="test-material-held-outside-backup")
        self.env.pop("AWS_S3_BACKUP_BUCKET", None)
        from urllib.parse import quote
        base = "postgresql://" + quote(self.admin_env.get("PGUSER", "secrethub")) + "@localhost/"
        query = "?host=" + quote(self.admin_env["PGHOST"], safe="/") + "&port=" + self.admin_env.get("PGPORT", "5432")
        self.env["DATABASE_URL"] = base + self.source + query
        self.env["RESTORE_DATABASE_URL"] = base + self.target + query
        self.manifest_path = directory / "latest-backup.json"

    def run_sql(self, env, sql):
        return self.helper.execute([self.helper.tool("psql"), "--no-psqlrc", "-qAt", "--set=ON_ERROR_STOP=1", "-c", sql], env)

    def run_script(self, name):
        args = [str(ROOT / "scripts" / name)]
        if name == "restore-database.sh": args += [str(self.manifest_path), "--yes"]
        return subprocess.run(args, env=self.env, capture_output=True, text=True, timeout=180)

    def test_real_database_restore_preserves_inventory_and_refuses_nonempty_target(self):
        backup = self.run_script("backup-database.sh")
        self.assertEqual(backup.returncode, 0, backup.stderr)
        manifest = json.loads(self.manifest_path.read_text())
        self.assertEqual(manifest["inventory"]["pki_authorities"][0]["generation"], 7)
        restored = self.run_script("restore-database.sh")
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(self.run_sql(self.target_env, "SELECT encode(opaque_value, 'hex') FROM backup_contract_fixture WHERE id = 1").strip(), "001122ff")
        report = json.loads((self.manifest_path.parent / "latest-restore.json").read_text())
        self.assertGreater(report["duration_seconds"], 0)
        repeated = self.run_script("restore-database.sh")
        self.assertNotEqual(repeated.returncode, 0)
        self.assertEqual(self.run_sql(self.target_env, "SELECT count(*) FROM backup_contract_fixture").strip(), "1")

    def test_late_sql_failure_rolls_back_all_imported_objects(self):
        backup = self.run_script("backup-database.sh")
        self.assertEqual(backup.returncode, 0, backup.stderr)
        # A deliberately malformed archive can execute SQL before failing. Its checksum alone
        # is not authenticity; the empty-target transaction must still roll back all changes.
        manifest = json.loads(self.manifest_path.read_text())
        dump = self.manifest_path.parent / manifest["dump"]["file"]
        # The archive is valid, so inject a database-independent failure after exported SQL
        # via an isolated test pg_restore wrapper; the production restore remains unchanged.
        wrapper = self.manifest_path.parent / "pg_restore_fail.py"
        real_tool = self.env.get("PG_RESTORE", "pg_restore")
        wrapper.write_text("#!/usr/bin/env python3\nimport pathlib,subprocess,sys\nargs=sys.argv[1:]\nr=subprocess.run([" + repr(real_tool) + "]+args)\nif r.returncode: sys.exit(r.returncode)\nfor a in args:\n if a.startswith('--file='):\n  with open(a.split('=',1)[1], 'a') as f: f.write('\\nSELECT 1 / 0;\\n')\nsys.exit(0)\n")
        wrapper.chmod(0o755)
        self.env["PG_RESTORE"] = str(wrapper)
        restored = self.run_script("restore-database.sh")
        self.assertNotEqual(restored.returncode, 0)
        self.assertEqual(self.run_sql(self.target_env, "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'").strip(), "0")
        self.assertFalse((self.manifest_path.parent / "latest-restore.json").exists())


if __name__ == "__main__":
    unittest.main()
