defmodule SecretHub.CLI.MixProject do
  use Mix.Project

  def project do
    [
      app: :secrethub_cli,
      version: "1.0.0-rc8",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      escript: escript(),
      aliases: aliases(),
      description: description(),
      package: package(),
      source_url: "https://github.com/gsmlg-dev/secrethub",
      homepage_url: "https://github.com/gsmlg-dev/secrethub"
    ]
    |> Keyword.merge(umbrella_paths())
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
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

  defp description do
    "Command-line interface for SecretHub secrets management."
  end

  defp package do
    [
      files: [
        "lib",
        "priv",
        "mix.exs",
        "README.md",
        "COMPLETION.md",
        "COMPLETION_QUICKSTART.md",
        "COMPLETION_SUMMARY.md"
      ],
      links: %{
        "GitHub" => "https://github.com/gsmlg-dev/secrethub"
      },
      licenses: ["LicenseRef-Proprietary"],
      build_tools: ["mix"]
    ]
  end

  defp umbrella_paths do
    if File.exists?(Path.expand("../../mix.exs", __DIR__)) do
      [
        build_path: "../../_build",
        config_path: "../../config/config.exs",
        deps_path: "../../deps",
        lockfile: "../../mix.lock"
      ]
    else
      []
    end
  end
end
