defmodule SecretHub.Agent.ConfigCLI do
  @moduledoc "Offline configuration commands for the standalone Agent release."

  alias SecretHub.Agent.Config

  @template_path Path.expand("../../../../rel/agent/overlays/config/agent.example.toml", __DIR__)
  @external_resource @template_path
  @template File.read!(@template_path)

  @doc false
  def main(args), do: System.halt(run(args))

  @doc false
  def run(["generate"]) do
    IO.write(@template)
    0
  end

  def run(["validate"]), do: validate(nil)
  def run(["validate", path]), do: validate(path)

  def run(_args) do
    IO.puts(:stderr, """
    Usage:
      secrethub_agent config generate
      secrethub_agent config validate [file]
    """)

    2
  end

  defp validate(path) do
    Config.validate!(path)
    IO.puts("Agent configuration is valid.")
    0
  rescue
    error in ArgumentError ->
      IO.puts(:stderr, "Invalid Agent configuration: #{Exception.message(error)}")
      1
  end
end
