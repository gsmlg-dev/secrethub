"""Release packaging contracts; no publication, containers, or runtime secrets."""
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReleasePackagingTest(unittest.TestCase):
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

    def test_embedded_shell_scripts_parse(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        blocks = re.findall(r"        run: \|\n((?:          .*\n|\n)+)", workflow)
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
