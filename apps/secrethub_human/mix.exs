defmodule SecretHub.Human.MixProject do
  use Mix.Project

  def project do
    [
      app: :secrethub_human,
      version: "1.0.0-rc9",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      mod: {SecretHub.Human.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      {:phoenix, "~> 1.8.1"},
      {:phoenix_ecto, "~> 4.6"},
      {:ecto_sql, "~> 3.13"},
      {:postgrex, "~> 0.19"},
      {:bandit, "~> 1.5"},
      {:jason, "~> 1.4"},
      {:secrethub_core, in_umbrella: true},
      {:secrethub_web, in_umbrella: true, only: :test, runtime: false}
    ]
  end
end
