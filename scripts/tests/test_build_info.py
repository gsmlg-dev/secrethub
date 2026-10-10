"""Build provenance regressions against the real source in isolated Mix projects."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BuildInfoTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="secrethub-build-info-")
        self.addCleanup(directory.cleanup)
        self.project = Path(directory.name)
        (self.project / "lib").mkdir()
        (self.project / "config").mkdir()
        (self.project / "mix.exs").write_text("""defmodule Fixture.MixProject do
  use Mix.Project
  def project, do: [app: :secrethub_web, version: "1.0.0"]
end
""")
        (self.project / "config/config.exs").write_text(
            'import Config\nimport_config "build_info.exs"\n'
        )
        shutil.copyfile(ROOT / "config/build_info.exs", self.project / "config/build_info.exs")
        shutil.copyfile(
            ROOT / "apps/secrethub_web/lib/secret_hub/web/build_info.ex",
            self.project / "lib/build_info.ex",
        )
        self.env = dict(os.environ)
        for key in ("SECRET_HUB_GIT_REF", "SECRET_HUB_GIT_SHA", "SECRET_HUB_BUILD_TIME",
                    "SOURCE_DATE_EPOCH", "MIX_BUILD_PATH"):
            self.env.pop(key, None)
        self.env.update(MIX_ENV="prod", ERL_FLAGS="+S 2")

    def run_command(self, *args):
        result = subprocess.run(
            args, cwd=self.project, env=self.env, text=True, capture_output=True, timeout=60
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def read_info(self):
        output = self.run_command("mix", "run", "--no-start", "-e", """
info = SecretHub.Web.BuildInfo.info()
for field <- [:version, :git_ref, :git_sha, :built_at, :source_date] do
  IO.puts("#{field}=#{Map.get(info, field)}")
end
""")
        return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)

    def commit(self):
        self.run_command("git", "-c", "user.name=Fixture", "-c",
                         "user.email=fixture@example.invalid", "commit", "--allow-empty",
                         "-m", "metadata fixture")
        return self.run_command("git", "rev-parse", "HEAD").strip()

    def test_cached_development_build_refreshes_after_git_head_changes(self):
        self.env["MIX_ENV"] = "dev"
        self.run_command("git", "init", "-b", "main")
        original_sha = self.commit()
        self.run_command("mix", "compile", "--warnings-as-errors")
        self.assertEqual(self.read_info()["git_sha"], original_sha)

        new_sha = self.commit()
        self.assertNotEqual(original_sha, new_sha)
        info = self.read_info()
        self.assertEqual(info["git_sha"], new_sha)
        self.assertEqual(info["git_ref"], "main")

    def test_cached_build_without_git_refreshes_metadata_environment(self):
        self.env.update(SECRET_HUB_GIT_REF="v1.0.0-rc13", SECRET_HUB_GIT_SHA="old-sha",
                        SECRET_HUB_BUILD_TIME="2026-10-09T12:00:00Z")
        self.run_command("mix", "compile", "--warnings-as-errors")
        self.assertEqual(self.read_info()["git_sha"], "old-sha")

        self.env.update(SECRET_HUB_GIT_REF="v1.0.0-rc14", SECRET_HUB_GIT_SHA="new-sha",
                        SECRET_HUB_BUILD_TIME="2026-10-10T12:00:00Z")
        info = self.read_info()
        self.assertEqual(info["git_ref"], "v1.0.0-rc14")
        self.assertEqual(info["git_sha"], "new-sha")
        self.assertEqual(info["built_at"], "2026-10-10T12:00:00Z")

    def test_unchanged_metadata_preserves_cached_build(self):
        first = self.read_info()
        beam = self.project / "_build/prod/lib/secrethub_web/ebin/Elixir.SecretHub.Web.BuildInfo.beam"
        modified_at = beam.stat().st_mtime_ns
        second = self.read_info()
        self.assertEqual(first, second)
        self.assertEqual(beam.stat().st_mtime_ns, modified_at)


if __name__ == "__main__":
    unittest.main()
