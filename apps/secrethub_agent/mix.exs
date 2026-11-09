defmodule SecretHub.Agent.MixProject do
  use Mix.Project

  def project do
    [
      app: :secrethub_agent,
      version: "1.0.0-rc.30",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      test_coverage: [summary: [threshold: 0]],
      deps: deps(),
      aliases: aliases()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :ssh, :ssl, :public_key],
      mod: {SecretHub.Agent.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:phoenix_socket_client, "~> 0.9.0"},
      {:http_web_socket, "~> 1.0.0-rc.8"},
      {:jason, "~> 1.4"},
      {:toml, "~> 0.7"},
      {:http_fetch, "~> 1.0.0-rc.8"},
      {:plug_crypto, "~> 2.2"},
      {:plug, "~> 1.14", only: :test},
      {:x509, in_umbrella: true},
      {:secrethub_shared, in_umbrella: true},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases do
    [
      lint: ["credo --strict", "dialyzer"]
    ]
  end
end
