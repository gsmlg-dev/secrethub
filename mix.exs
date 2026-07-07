defmodule SecretHub.MixProject do
  use Mix.Project

  def project do
    [
      apps_path: "apps",
      version: "1.0.0-rc8",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      releases: releases(),

      # Documentation
      name: "SecretHub",
      docs: docs(),

      # Testing
      test_coverage: [tool: ExCoveralls, summary: [threshold: 0]],
      preferred_cli_env: [
        test: :test,
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ],

      # Phoenix code reloader listener (required for Phoenix 1.8+)
      listeners: [Phoenix.CodeReloader]
    ]
  end

  # Dependencies listed here are available to all child apps
  defp deps do
    [
      # Development & Testing
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.31", runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:mix_test_watch, "~> 1.1", only: [:dev, :test], runtime: false},
      # Required by Phoenix LiveView tests; must include :dev since devenv sets MIX_ENV=dev
      {:lazy_html, ">= 0.1.0", only: [:dev, :test]},

      # Shared utilities
      {:jason, "~> 1.4"},
      {:telemetry, "~> 1.2"},
      {:oban, "~> 2.18"},
      {:crontab, "~> 1.1"},
      {:sweet_xml, "~> 0.7"}
    ]
  end

  defp aliases do
    [
      # Setup
      setup: ["deps.get", "cmd cd apps/secrethub_web/assets && bun install"],
      "agent.run": &run_agent/1,

      # Testing
      "test.watch": ["test.watch --stale"],

      # Code quality
      quality: ["format", "credo --strict", "dialyzer --halt-exit-status"],
      lint: ["credo --strict"],

      # Assets
      "assets.deploy": [
        "phx.digest.clean",
        "tailwind secrethub_web --minify",
        "bun secrethub_web --minify",
        "phx.digest"
      ],

      # Database
      "ecto.setup": ["ecto.create", "ecto.migrate", "run apps/secrethub_core/priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop --force", "ecto.setup"]
    ]
  end

  defp run_agent(args) do
    Mix.Task.run("compile", args)
    Mix.Task.run("app.config")

    core_url =
      System.get_env("SECRET_HUB_AGENT_CORE_URL") ||
        Application.get_env(:secrethub_agent, :core_url) ||
        "https://localhost:4664"

    state_dir =
      System.get_env("SECRET_HUB_AGENT_STATE_DIR") ||
        System.get_env("SECRET_HUB_AGENT_STORAGE_DIR") ||
        Application.get_env(:secrethub_agent, :state_dir) ||
        "priv/cert"

    Application.put_env(:secrethub_agent, :enabled, true)
    Application.put_env(:secrethub_agent, :core_url, core_url)
    Application.put_env(:secrethub_agent, :state_dir, state_dir)

    Application.put_env(
      :secrethub_agent,
      :enrollment_opts,
      [
        approval_timeout_ms: agent_approval_timeout(),
        on_pending: fn pending ->
          Mix.shell().info(
            "SecretHub agent pending approval: #{pending["enrollment_id"]}. " <>
              "Approve it in /admin/pending-agents."
          )

          :ok
        end
      ] ++ host_key_opts(state_dir)
    )

    Mix.shell().info("SecretHub agent starting with state directory #{state_dir}")
    {:ok, _apps} = Application.ensure_all_started(:secrethub_agent)

    Process.sleep(:infinity)
  end

  defp agent_approval_timeout do
    case System.get_env("SECRET_HUB_AGENT_APPROVAL_TIMEOUT_MS") do
      nil -> :infinity
      "infinity" -> :infinity
      value -> String.to_integer(value)
    end
  end

  defp host_key_opts(storage_dir) do
    case System.get_env("SECRET_HUB_AGENT_HOST_KEY_PATH") do
      nil ->
        key_path = Path.join(storage_dir, "local-dev-ssh-host-rsa-key")
        ensure_local_dev_host_key!(key_path)
        [paths: [rsa: key_path]]

      path ->
        [paths: [ecdsa: path, rsa: path]]
    end
  end

  defp ensure_local_dev_host_key!(path) do
    unless File.exists?(path) do
      File.mkdir_p!(Path.dirname(path))

      {_output, 0} =
        System.cmd("ssh-keygen", [
          "-q",
          "-t",
          "rsa",
          "-b",
          "2048",
          "-N",
          "",
          "-f",
          path
        ])
    end
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
        runtime_config_path: "config/agent_runtime.exs",
        include_executables_for: [:unix, :windows],
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
        Architecture: Path.wildcard("docs/architecture/*.md"),
        API: Path.wildcard("docs/api/*.md")
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
        Agent: [
          SecretHub.Agent.Connection,
          SecretHub.Agent.Cache
        ]
      ]
    ]
  end
end
