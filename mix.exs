defmodule SecretHub.MixProject do
  use Mix.Project

  def project do
    [
      apps_path: "apps",
      version: "0.1.0",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      releases: releases(),
      
      # Documentation
      name: "SecretHub",
      docs: docs(),
      
      # Testing
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ]
    ]
  end

  # Dependencies listed here are available to all child apps
  defp deps do
    [
      # Development & Testing
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:mix_test_watch, "~> 1.1", only: [:dev, :test], runtime: false},
      
      # Shared utilities
      {:jason, "~> 1.4"},
      {:telemetry, "~> 1.2"}
    ]
  end

  defp aliases do
    [
      # Setup
      setup: ["deps.get", "cmd cd apps/secrethub_web/assets && bun install"],
      
      # Testing
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"],
      "test.watch": ["test.watch --stale"],
      
      # Code quality
      quality: ["format", "credo --strict", "dialyzer"],
      
      # Database
      "ecto.setup": ["ecto.create", "ecto.migrate", "run apps/secrethub_core/priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"]
    ]
  end

  defp releases do
    [
      secrethub_core: [
        applications: [
          secrethub_core: :permanent,
          secrethub_web: :permanent,
          secrethub_shared: :permanent
        ],
        include_executables_for: [:unix],
        steps: [:assemble, :tar]
      ],
      secrethub_agent: [
        applications: [
          secrethub_agent: :permanent,
          secrethub_shared: :permanent
        ],
        include_executables_for: [:unix],
        steps: [:assemble, :tar]
      ]
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md",
        "docs/architecture/overview.md",
        "docs/api/authentication.md"
      ],
      groups_for_extras: [
        "Architecture": Path.wildcard("docs/architecture/*.md"),
        "API": Path.wildcard("docs/api/*.md")
      ],
      groups_for_modules: [
        "Core - Authentication": [
          SecretHub.Core.Auth,
          SecretHub.Core.Auth.AppRole
        ],
        "Core - Engines": [
          SecretHub.Core.Engines.Static,
          SecretHub.Core.Engines.Dynamic.PostgreSQL
        ],
        "Agent": [
          SecretHub.Agent.Connection,
          SecretHub.Agent.Cache
        ]
      ]
    ]
  end
end
