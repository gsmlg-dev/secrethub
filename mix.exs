defmodule SecretHub.MixProject do
  use Mix.Project

  def project do
    [
      apps_path: "apps",
      version: "1.0.0-rc4",
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
      quality: ["format", "cmd mix lint"],
      lint: ["cmd mix lint"],
      credo: ["cmd mix credo --strict"],
      dialyzer: ["cmd mix dialyzer"],

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
        "ws://localhost:4664"

    enrollment_url = enrollment_http_url(core_url)
    storage_dir = System.get_env("SECRET_HUB_AGENT_STORAGE_DIR") || "priv/cert"

    {:ok, _apps} = Application.ensure_all_started(:req)
    {:ok, _apps} = Application.ensure_all_started(:x509)

    Mix.shell().info("SecretHub agent requesting pending enrollment at #{enrollment_url}")

    enrollment_opts =
      [
        core_url: enrollment_url,
        storage_dir: storage_dir,
        approval_timeout_ms: agent_approval_timeout(),
        on_pending: fn pending ->
          Mix.shell().info(
            "SecretHub agent pending approval: #{pending["enrollment_id"]}. " <>
              "Approve it in /admin/pending-agents."
          )

          :ok
        end
      ] ++ host_key_opts(storage_dir)

    case SecretHub.Agent.Enrollment.enroll(enrollment_opts) do
      {:ok, enrolled} ->
        Mix.shell().info(
          "SecretHub agent approved as #{enrolled.agent_id}; connecting to trusted runtime"
        )

        {:ok, _apps} = start_enrolled_agent(enrolled)
        finalize_runtime_connection(enrollment_url, enrolled)

      {:error, reason} ->
        Mix.raise("SecretHub agent enrollment failed: #{inspect(reason)}")
    end

    Process.sleep(:infinity)
  end

  defp enrollment_http_url(core_url) do
    core_url
    |> URI.parse()
    |> then(fn uri ->
      scheme =
        case uri.scheme do
          "ws" -> "http"
          "wss" -> "https"
          other -> other || "http"
        end

      %{uri | scheme: scheme, path: nil, query: nil}
    end)
    |> URI.to_string()
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

  defp start_enrolled_agent(enrolled) do
    trusted_endpoint =
      Map.get(enrolled.connect_info, "trusted_websocket_endpoint") ||
        Map.fetch!(enrolled.connect_info, :trusted_websocket_endpoint)

    Application.put_env(:secrethub_agent, :enabled, true)
    Application.put_env(:secrethub_agent, :agent_id, enrolled.agent_id)
    Application.put_env(:secrethub_agent, :core_url, trusted_endpoint)
    Application.put_env(:secrethub_agent, :core_endpoints, [trusted_endpoint])

    Application.put_env(
      :secrethub_agent,
      :cert_path,
      Path.join(enrolled.storage_dir, "agent-cert.pem")
    )

    Application.put_env(
      :secrethub_agent,
      :key_path,
      Path.join(enrolled.storage_dir, "agent-key.pem")
    )

    Application.put_env(
      :secrethub_agent,
      :ca_path,
      Path.join(enrolled.storage_dir, "ca-chain.pem")
    )

    Application.ensure_all_started(:secrethub_agent)
  end

  defp finalize_runtime_connection(enrollment_url, enrolled) do
    case wait_for_runtime_connection(10_000) do
      :ok ->
        SecretHub.Agent.Enrollment.finalize_success(
          enrollment_url,
          enrolled.pending,
          enrolled.storage_dir
        )

        Mix.shell().info("SecretHub agent trusted runtime connected")

      {:error, :timeout} ->
        error = %{
          "phase" => "trusted_runtime_connect",
          "message" => "timed out waiting for trusted runtime connection"
        }

        SecretHub.Agent.Enrollment.finalize_failure(enrollment_url, enrolled.pending, error)
        Mix.raise("SecretHub agent trusted runtime did not connect")
    end
  end

  defp wait_for_runtime_connection(timeout_ms) do
    deadline = System.monotonic_time(:millisecond) + timeout_ms
    wait_for_runtime_connection_until(deadline)
  end

  defp wait_for_runtime_connection_until(deadline) do
    if SecretHub.Agent.ConnectionManager.status() == :connected do
      :ok
    else
      if System.monotonic_time(:millisecond) >= deadline do
        {:error, :timeout}
      else
        Process.sleep(100)
        wait_for_runtime_connection_until(deadline)
      end
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
