defmodule SecretHub.SDK.MixProject do
  use Mix.Project

  def project do
    [
      app: :secrethub_sdk,
      version: "1.0.0-rc.32",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: [main: "SecretHub.SDK", extras: ["README.md"]],
      source_url: "https://github.com/gsmlg-dev/secrethub",
      homepage_url: "https://github.com/gsmlg-dev/secrethub"
    ]
    |> Keyword.merge(umbrella_paths())
  end

  def application do
    [extra_applications: [:logger, :crypto]]
  end

  defp deps do
    [{:jason, "~> 1.4"}]
  end

  defp description do
    "Elixir client for publishing and reading SecretHub secrets through the local SecretHub Agent."
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README.md", ".formatter.exs"],
      links: %{"GitHub" => "https://github.com/gsmlg-dev/secrethub"},
      licenses: ["LicenseRef-Proprietary"],
      build_tools: ["mix"]
    ]
  end

  defp umbrella_paths do
    if File.exists?(Path.expand("../../mix.exs", __DIR__)) do
      [
        build_path: "../../_build",
        deps_path: "../../deps",
        lockfile: "../../mix.lock"
      ]
    else
      []
    end
  end
end
