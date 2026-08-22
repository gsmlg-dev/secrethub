defmodule SecretHub.Core.ReleaseRuntimeConfigTest do
  use ExUnit.Case, async: true

  @repo_root Path.expand("../../../..", __DIR__)

  test "releases select role-specific runtime configuration" do
    releases = SecretHub.MixProject.project()[:releases]

    assert releases[:secrethub_core][:runtime_config_path] == "config/core_runtime.exs"
    assert releases[:secrethub_agent][:runtime_config_path] == "config/agent_runtime.exs"
  end

  test "default runtime configuration evaluates the Core runtime configuration" do
    assert File.read!(Path.join(@repo_root, "config/runtime.exs")) ==
             "import Config\n\nCode.eval_file(Path.join(__DIR__, \"core_runtime.exs\"))\n"
  end
end
