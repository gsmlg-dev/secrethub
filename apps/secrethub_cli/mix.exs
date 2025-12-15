defmodule SecretHub.CLI.MixProject do
  use Mix.Project

  def project do
    [
      app: :secrethub_cli,
      version: "0.1.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      escript: escript(),
      aliases: aliases()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      # Umbrella dependencies
      {:secrethub_shared, in_umbrella: true},

      # HTTP client for API calls
      {:req, "~> 0.5"},

      # JSON encoding/decoding
      {:jason, "~> 1.4"},

      # Terminal UI
      {:owl, "~> 0.12"},

      # Configuration management
      {:toml, "~> 0.7"},

      # Testing
      {:mox, "~> 1.0", only: :test}
    ]
  end

  defp escript do
    [
      main_module: SecretHub.CLI,
      name: "secrethub",
      comment: "SecretHub CLI - Enterprise secrets management",
      embed_elixir: true
    ]
  end

  defp aliases do
    [
      test: "test --no-start"
    ]
  end
end
