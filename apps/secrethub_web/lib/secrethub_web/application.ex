defmodule SecretHub.Web.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    # Trap exits to enable graceful shutdown
    Process.flag(:trap_exit, true)

    children = [
      SecretHub.Web.Telemetry,
      {DNSCluster, query: Application.get_env(:secrethub_web, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: SecretHub.Web.PubSub},
      # Start a worker by calling: SecretHub.Web.Worker.start_link(arg)
      # {SecretHub.Web.Worker, arg},
      # Start to serve requests, typically the last entry
      SecretHub.Web.Endpoint
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: SecretHub.Web.Supervisor]
    result = Supervisor.start_link(children, opts)

    Logger.info("SecretHub.Web.Application started")
    result
  end

  @impl true
  def stop(_state) do
    Logger.info("SecretHub.Web.Application stopping...")

    # Trigger graceful shutdown with connection draining
    # This is the primary shutdown handler for HTTP connections
    SecretHub.Core.Shutdown.graceful_shutdown(
      timeout_ms: 25_000,
      drain_connections: true,
      wait_for_jobs: false
    )

    Logger.info("SecretHub.Web.Application stopped")
    :ok
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    SecretHub.Web.Endpoint.config_change(changed, removed)
    :ok
  end
end
