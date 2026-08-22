defmodule SecretHub.CLI.RuntimeConfigIsolationTest do
  use ExUnit.Case, async: true

  @cli_root Path.expand("../..", __DIR__)

  test "uses app-local config path" do
    project = SecretHub.CLI.MixProject.project()

    assert project
           |> Keyword.fetch!(:config_path)
           |> Path.expand(@cli_root) == Path.join(@cli_root, "config/config.exs")
  end

  test "provides an app-local runtime config" do
    assert File.regular?(Path.join(@cli_root, "config/runtime.exs"))
  end

  test "packages the app-local config" do
    project = SecretHub.CLI.MixProject.project()

    assert "config" in get_in(project, [:package, :files])
  end
end
