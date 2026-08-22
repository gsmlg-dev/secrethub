defmodule SecretHub.Agent.RuntimeConfigIntegrationTest do
  use ExUnit.Case, async: true

  @project_root Path.expand("../../../..", __DIR__)
  @runtime_config Path.join(@project_root, "config/agent_runtime.exs")
  @result_prefix "SECRET_HUB_AGENT_RUNTIME_CONFIG="

  @probe """
  config = Config.Reader.read!(#{inspect(@runtime_config)}, env: :prod)
  payload = %{
    agent: Keyword.fetch!(config, :secrethub_agent),
    core?: Keyword.has_key?(config, :secrethub_core),
    human?: Keyword.has_key?(config, :secrethub_human),
    web?: Keyword.has_key?(config, :secrethub_web)
  }
  IO.puts(#{inspect(@result_prefix)} <> Base.encode64(:erlang.term_to_binary(payload)))
  """

  test "standalone Agent config requires only a non-empty Core URL" do
    assert %{
             agent: [core_url: "https://core.example.test"],
             core?: false,
             human?: false,
             web?: false
           } = read_runtime_config("https://core.example.test")
  end

  test "standalone Agent config rejects a missing or blank Core URL" do
    for core_url <- [nil, ""] do
      {output, status} = run_runtime_config(core_url)
      assert status != 0
      assert output =~ "environment variable SECRET_HUB_AGENT_CORE_URL is missing"
    end
  end

  defp read_runtime_config(core_url) do
    {output, status} = run_runtime_config(core_url)
    assert status == 0, output
    assert [_, encoded] = String.split(output, @result_prefix, parts: 2)
    assert {:ok, payload} = encoded |> String.trim() |> Base.decode64()
    :erlang.binary_to_term(payload, [:safe])
  end

  defp run_runtime_config(core_url) do
    runtime_env =
      [{"PATH", System.fetch_env!("PATH")}, {"SECRET_HUB_AGENT_CORE_URL", core_url}]
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Enum.map(fn {key, value} -> "#{key}=#{value}" end)

    System.cmd(
      System.find_executable("env"),
      ["-i" | runtime_env] ++
        [System.find_executable("elixir"), "--erl", "+S 2:2", "-e", @probe],
      cd: @project_root,
      stderr_to_stdout: true
    )
  end
end
