"""Release packaging contracts; no publication, containers, or runtime secrets."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReleasePackagingTest(unittest.TestCase):
    def test_pinned_staging_roots_are_present_with_manifest_checksums(self):
        directory = ROOT / "apps/secrethub_core/priv/pki"
        manifest = json.loads((directory / "letsencrypt-staging-manifest.json").read_text())
        self.assertTrue(manifest["roots"], "Staging root manifest must not be empty")
        for root in manifest["roots"]:
            with self.subTest(root=root["file"]):
                path = directory / root["file"]
                self.assertEqual(path.parent, directory)
                self.assertTrue(path.is_file(), f"Missing pinned staging root: {path}")
                pem = path.read_bytes()
                self.assertEqual(hashlib.sha256(pem).hexdigest(), root["pem_sha256"])
                self.assertEqual(pem.count(b"-----BEGIN CERTIFICATE-----"), 1)
                der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
                self.assertEqual(hashlib.sha256(der).hexdigest(), root["der_sha256"])

    def test_image_trust_guard_gates_publication(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        images = workflow.split("  build-docker-images:\n", 1)[1].split("  create-release:\n", 1)[0]
        self.assertIn("scripts/verify-pki-trust-image.sh", images)
        guard = images.split("      - name: Verify packaged Core trust offline\n", 1)[1]
        self.assertIn("matrix.image != 'agent'", guard)
        self.assertNotIn("continue-on-error", guard)
        self.assertIn("steps.image.outputs.digest", guard)
        self.assertIn("needs.prepare-release.outputs.tag", guard)
        self.assertIn("needs.prepare-release.outputs.release_sha", guard)
        for job in ["publish-cli-hex", "create-release"]:
            section = workflow.split("  " + job + ":\n", 1)[1].split("\n    steps:", 1)[0]
            self.assertIn("      - build-docker-images\n", section)
            self.assertNotIn("always()", section)

    def image_guard(self, profile="core-standalone", failure=None):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            stub = fixture / "docker"
            stub.write_text('''#!/usr/bin/env python3
import base64, json, os, sys
args = sys.argv[1:]
with open(os.environ["DOCKER_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
if args[:2] == ["image", "inspect"]:
    print(json.dumps([{"Architecture": "amd64", "Os": "linux", "Config": {"Labels": {
        "org.opencontainers.image.version": "wrong" if os.environ.get("FAILURE") == "version" else "v1.0.0-rc.22",
        "org.opencontainers.image.revision": "a" * 40,
        "org.opencontainers.image.source": "https://github.com/gsmlg-dev/secrethub"}}}]))
elif args[0] == "run":
    assert os.environ["SECRET_KEY_BASE"] != "must-not-inherit"
    assert len(base64.b64decode(os.environ["SECRET_KEY_BASE"])) == 64
    assert len(base64.b64decode(os.environ["AUDIT_HMAC_KEY"])) == 32
    if os.environ.get("FAILURE") == "probe":
        print(":staging_trust_unavailable", file=sys.stderr)
        sys.exit(1)
    print(json.dumps({"result": "PASS", "services_started": False, "release": "1.0.0-rc.22"}))
''')
            stub.chmod(0o755)
            environment = dict(os.environ, PATH=f"{fixture}{os.pathsep}{os.environ['PATH']}",
                               DOCKER_LOG=str(fixture / "docker.log"), FAILURE=failure or "",
                               SECRET_KEY_BASE="must-not-inherit", AUDIT_HMAC_KEY="must-not-inherit")
            reference = f"ghcr.io/gsmlg-dev/secrethub/{profile}@sha256:" + "b" * 64
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/verify-pki-trust-image.sh"), reference,
                 "v1.0.0-rc.22", "a" * 40], env=environment, text=True, capture_output=True,
            )
            calls = [json.loads(line) for line in (fixture / "docker.log").read_text().splitlines()]
            return result, calls, reference

    def test_image_trust_guard_runs_only_isolated_eval_of_digest_pulled_image(self):
        result, calls, reference = self.image_guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls[0], ["pull", "--platform", "linux/amd64", reference])
        run = next(call for call in calls if call[0] == "run")
        for argument in ["--network=none", "--read-only", "--cap-drop=ALL",
                         "--security-opt=no-new-privileges", "--no-healthcheck"]:
            self.assertIn(argument, run)
        self.assertIn("/data:ro,noexec,nosuid,size=1m", run)
        self.assertEqual(run[run.index("--entrypoint") + 1], "/app/bin/secrethub_core")
        self.assertEqual(run[-3:], [reference, "eval", 'Code.eval_file("/qualification/probe.exs")'])
        self.assertTrue(any("/qualification/probe.exs,readonly" in arg for arg in run))
        self.assertNotIn("must-not-inherit", result.stdout + result.stderr + str(calls))

    def test_image_trust_guard_rejects_wrong_version_before_eval(self):
        result, calls, _ = self.image_guard(failure="version")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[0] == "run" for call in calls))

    def test_core_image_guard_does_not_add_a_data_volume(self):
        result, calls, _ = self.image_guard(profile="core")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        run = next(call for call in calls if call[0] == "run")
        self.assertFalse(any(argument.startswith("/data:") for argument in run))

    def test_image_trust_guard_propagates_probe_failure_and_removes_owned_container(self):
        result, calls, _ = self.image_guard(failure="probe")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(":staging_trust_unavailable", result.stderr)
        run = next(call for call in calls if call[0] == "run")
        self.assertIn(["rm", "--force", run[run.index("--name") + 1]], calls)

    def write_app(self, release, name, version):
        path = release / "lib" / f"{name}-{version}" / "ebin" / f"{name}.app"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{application, %s, [{vsn, "%s"}]}.\n' % (name, version))
        return path

    def verify_versions(self, release):
        return subprocess.run(
            ["elixir", str(ROOT / "scripts/verify_release_versions.exs"), str(release), "1.0.0-rc.15"],
            text=True,
            capture_output=True,
        )

    def test_release_version_validator_accepts_own_apps_and_independent_x509(self):
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory)
            self.write_app(release, "secrethub_core", "1.0.0-rc.15")
            self.write_app(release, "secrethub_shared", "1.0.0-rc.15")
            self.write_app(release, "x509", "0.9.2")
            result = self.verify_versions(release)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_release_version_validator_rejects_old_cached_own_apps(self):
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory)
            self.write_app(release, "secrethub_core", "1.0.0-rc.15")
            old_app = self.write_app(release, "secrethub_core", "1.0.0-rc11")
            result = self.verify_versions(release)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(str(old_app), result.stderr)
            self.assertIn("1.0.0-rc11", result.stderr)
            self.assertIn("1.0.0-rc.15", result.stderr)

    def test_release_version_validator_rejects_missing_own_apps(self):
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory)
            self.write_app(release, "x509", "0.9.2")
            result = self.verify_versions(release)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("No SecretHub applications", result.stderr)

    def test_release_build_steps_remove_stale_assembly_before_rebuilding(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        for role in ["Core", "Agent"]:
            with self.subTest(role=role), tempfile.TemporaryDirectory() as directory:
                step = workflow.split(f"      - name: Build {role} release\n", 1)[1]
                step = step.split("\n      - name:", 1)[0]
                run = re.search(r"        run: (.*)\n", step).group(1)
                if run == "|":
                    script = "\n".join(line[10:] for line in step.split("        run: |\n", 1)[1].splitlines())
                else:
                    script = run
                script = re.sub(r"\$\{\{.*?\}\}", "1.0.0-rc.15", script)
                fixture = Path(directory)
                release_name = f"secrethub_{role.lower()}"
                stale = fixture / "_build/prod/rel" / release_name / "lib/stale-sentinel"
                stale.parent.mkdir(parents=True)
                stale.write_text("cached assembly")
                compiled = fixture / "_build/prod/lib" / release_name / "ebin/keep"
                compiled.parent.mkdir(parents=True)
                compiled.write_text("compiled application")
                (fixture / "scripts").mkdir()
                validator = ROOT / "scripts/verify_release_versions.exs"
                shutil.copyfile(validator, fixture / "scripts" / validator.name)
                stub = fixture / "mix"
                stub.write_text('''#!/bin/sh
set -eu
[ "$1" = release ]
target="_build/prod/rel/$2"
if [ -e "$target/lib/stale-sentinel" ]; then
  echo "stale assembly survived before mix release" >&2
  exit 1
fi
mkdir -p "$target/lib/$2-1.0.0-rc.15/ebin"
printf '{application, %s, [{vsn, "1.0.0-rc.15"}]}.\\n' "$2" > "$target/lib/$2-1.0.0-rc.15/ebin/$2.app"
''')
                stub.chmod(0o755)
                environment = dict(os.environ, PATH=f"{fixture}{os.pathsep}{os.environ['PATH']}")
                environment.update(RELEASE_VERSION="1.0.0-rc.15", RELEASE_TAG="v1.0.0-rc.15")
                result = subprocess.run(["bash", "-e", "-c", script], cwd=fixture, env=environment,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(stale.exists())
                self.assertTrue(compiled.exists(), "compiled application outputs must be retained")
                self.assertIn("        shell: bash\n", step)
                self.assertIn("elixir scripts/verify_release_versions.exs", script)

    def test_workflow_assets_do_not_load_production_runtime_config(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        core = workflow.split("  build-core-release:", 1)[1].split("  build-agent-release:", 1)[0]
        self.assertNotIn("mix assets.deploy", core)
        self.assertNotIn("BUILD_SECRET_KEY_BASE", workflow)
        self.assertIn("bun install --frozen-lockfile --ignore-scripts", core)
        self.assertIn("@tailwindcss/cli/dist/index.mjs", core)
        self.assertIn("bun build assets/js/app.js", core)
        self.assertIn("mix phx.digest --no-compile", core)

    def test_standalone_assembly_does_not_need_deployment_secrets(self):
        dockerfile = (ROOT / "Dockerfile.core-standalone").read_text()
        builder = dockerfile.split(" AS runtime", 1)[0]
        self.assertIn("COPY rel ./rel", builder)
        self.assertIn("bun install --frozen-lockfile --ignore-scripts", builder)
        self.assertIn("mix phx.digest --no-compile", builder)
        self.assertNotIn("mix assets.", builder)
        self.assertNotIn("DATABASE_URL=", builder)
        self.assertNotIn("SECRET_KEY_BASE=", builder)

    def test_standalone_boot_uses_service_uid_and_local_liveness(self):
        dockerfile = (ROOT / "Dockerfile.core-standalone").read_text()
        self.assertIn("RELEASE_DISTRIBUTION=none", dockerfile)
        self.assertIn("su-exec secrethub /app/bin/secrethub_core eval", dockerfile)
        self.assertIn("http://127.0.0.1:4737/v1/sys/health/live", dockerfile)
        self.assertNotIn("RELEASE_COOKIE=change-me-in-production", dockerfile)

    def test_release_notes_link_runtime_and_upgrade_requirements(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        notes = workflow.split("cat > release_notes.md <<EOF", 1)[1].split("          EOF", 1)[0]
        self.assertIn("docs/security/runtime-contract.md", notes)
        self.assertIn("docs/security/shamir-v4.md", notes)
        self.assertIn("AUDIT_HMAC_KEY", notes)
        self.assertIn("SECRET_HUB_MANAGEMENT_ORIGIN", notes)
        self.assertIn("RELEASE_DISTRIBUTION=none", notes)
        self.assertIn("standalone", notes)
        self.assertNotIn("docker run", notes)

    def test_core_latest_is_promoted_after_successful_release(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        concurrency = workflow.split("concurrency:\n", 1)[1].split("\nenv:", 1)[0]
        self.assertNotIn("github.ref", concurrency)
        self.assertIn("cancel-in-progress: false", concurrency)
        self.assertTrue("  publish-core-latest:\n" in workflow, "Core latest promotion is missing")
        build, promotion = workflow.split("  publish-core-latest:", 1)
        images = build.split("  build-docker-images:", 1)[1].split("  create-release:", 1)[0]
        self.assertNotIn(":latest", images)
        self.assertIn("      - create-release\n", promotion)
        self.assertIn("      - prepare-release\n", promotion)
        self.assertNotIn("always()", promotion)
        self.assertNotIn("prerelease", promotion)
        self.assertIn("packages: write", promotion)
        self.assertIn(
            'SOURCE: ghcr.io/${{ github.repository }}/core:${{ needs.prepare-release.outputs.tag }}',
            promotion,
        )
        self.assertIn('TARGET: ghcr.io/${{ github.repository }}/core:latest', promotion)
        self.assertIn('imagetools create --tag "$TARGET" "$SOURCE"', promotion)
        self.assertIn('cmp source-manifest.json latest-manifest.json', promotion)
        self.assertNotIn("/agent:latest", promotion)

    def test_embedded_shell_scripts_parse(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        blocks = []
        for step in re.split(r"(?m)^      - ", workflow)[1:]:
            shell = re.search(r"(?m)^        shell: (.+)$", step)
            if shell and shell.group(1).strip() not in {"bash", "sh"}:
                continue
            blocks.extend(re.findall(r"        run: \|\n((?:          .*\n|\n)+)", step))
        self.assertTrue(blocks, "No Bash or default Unix run blocks were found")
        for block in blocks:
            script = "\n".join(line[10:] for line in block.splitlines())
            script = re.sub(r"\$\{\{.*?\}\}", "fixture", script)
            result = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        dockerfile = (ROOT / "Dockerfile.core-standalone").read_text()
        script = dockerfile.split("<<'EOF' /usr/local/bin/entrypoint.sh\n", 1)[1].split("\nEOF", 1)[0]
        result = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
