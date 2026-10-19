"""Release packaging contracts; no publication, containers, or runtime secrets."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReleasePackagingTest(unittest.TestCase):
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
