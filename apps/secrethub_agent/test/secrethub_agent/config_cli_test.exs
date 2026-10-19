defmodule SecretHub.Agent.ConfigCLITest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias SecretHub.Agent.{Config, ConfigCLI}

  @moduletag :tmp_dir
  @template Path.expand("../../../../rel/agent/overlays/config/agent.example.toml", __DIR__)

  test "generate writes only the canonical template to stdout", %{tmp_dir: dir} do
    {status, stdout, stderr} = run(["generate"])
    assert status == 0
    assert stderr == ""
    assert stdout == File.read!(@template)

    path = Path.join(dir, "generated.toml")
    File.write!(path, stdout)
    assert Config.validate!(path) == :ok
  end

  test "validate accepts paths with spaces without starting the Agent", %{tmp_dir: dir} do
    path = Path.join(dir, "agent config.toml")
    contents = String.replace(File.read!(@template), "/var/lib/secrethub-agent", "state")
    File.write!(path, contents)
    supervisor = Process.whereis(SecretHub.Agent.Supervisor)

    assert run(["validate", path]) == {0, "Agent configuration is valid.\n", ""}
    assert Process.whereis(SecretHub.Agent.Supervisor) == supervisor
    refute File.exists?(Path.join(dir, "state"))
  end

  test "invalid configuration returns a redacted error on stderr", %{tmp_dir: dir} do
    path = Path.join(dir, "private.toml")

    for {content, reason} <- [
          {"private = \"secret-content\n", "invalid_toml"},
          {"private = \"secret-content\"\n", "unknown_option"},
          {"state_dir = 42\n", "invalid_value"},
          {"", "SECRET_HUB_AGENT_CORE_URL: missing"}
        ] do
      File.write!(path, content)
      {status, stdout, stderr} = run(["validate", path])
      assert status == 1
      assert stdout == ""
      assert stderr =~ reason
      refute stderr =~ path
      refute stderr =~ "secret-content"
    end
  end

  test "validation rejects absent files", %{tmp_dir: dir} do
    {status, stdout, stderr} = run(["validate", Path.join(dir, "absent.toml")])
    assert status == 1
    assert stdout == ""
    assert stderr =~ "SECRET_HUB_AGENT_CONFIG_FILE: invalid_file"
  end

  test "unsupported arguments return usage on stderr" do
    for args <- [[], ["unknown"], ["generate", "extra"], ["validate", "a", "b"]] do
      {status, stdout, stderr} = run(args)
      assert status == 2
      assert stdout == ""
      assert stderr =~ "secrethub_agent config generate"
      assert stderr =~ "secrethub_agent config validate [file]"
    end
  end

  defp run(args) do
    {{status, stderr}, stdout} =
      with_io(fn -> with_io(:stderr, fn -> ConfigCLI.run(args) end) end)

    {status, stdout, stderr}
  end
end
