defmodule SecretHub.Core.Application do
  @moduledoc false

  use Application
  require Logger

  alias SecretHub.Core.Shutdown

  @impl true
  def start(_type, _args) do
    # Trap exits to enable graceful shutdown
    Process.flag(:trap_exit, true)

    opts = [strategy: :one_for_one, name: SecretHub.Core.Supervisor]
    result = Supervisor.start_link(children(), opts)

    Logger.info("SecretHub.Core.Application started")
    result
  end

  # Start Cache system early (doesn't depend on DB)
  defp cache_children do
    [SecretHub.Core.Cache]
  end

  @doc false
  def children do
    cache_children() ++
      repo_children() ++
      seal_state_children() ++
      cluster_state_children() ++
      lease_manager_children() ++
      agent_connection_children() ++
      client_auth_children()
  end

  @impl true
  def stop(_state) do
    Logger.info("SecretHub.Core.Application stopping...")

    # Trigger graceful shutdown
    # Use shorter timeout for Core since Web will handle connection draining
    Shutdown.graceful_shutdown(
      timeout_ms: 15_000,
      drain_connections: false,
      wait_for_jobs: true
    )

    Logger.info("SecretHub.Core.Application stopped")
    :ok
  end

  # In test mode, Repo is started manually after Sandbox configuration.
  # A missing environment is treated as an incomplete umbrella bootstrap, so
  # database-backed children wait rather than starting with the wrong pool.
  defp repo_children do
    if runtime_environment?() do
      [SecretHub.Core.Repo]
    else
      []
    end
  end

  # Only start SealState in non-test environments (it tries to write to DB on init)
  defp seal_state_children do
    if runtime_environment?() do
      [SecretHub.Core.Vault.SealState]
    else
      []
    end
  end

  # ClusterState owns a database-backed node registration, so it starts only
  # after Repo and SealState. Tests start it explicitly after sandbox checkout.
  defp cluster_state_children do
    if runtime_environment?() do
      [SecretHub.Core.ClusterState]
    else
      []
    end
  end

  # Start LeaseManager for dynamic secret lease tracking
  defp lease_manager_children do
    if runtime_environment?() do
      [SecretHub.Core.LeaseManager]
    else
      []
    end
  end

  defp agent_connection_children do
    if runtime_environment?() do
      [SecretHub.Core.Agents.ConnectionManager]
    else
      []
    end
  end

  defp client_auth_children do
    if runtime_environment?() do
      [SecretHub.Core.Workers.ClientAuthCRLRefresher]
    else
      []
    end
  end

  defp runtime_environment? do
    Application.get_env(:secrethub_core, :env) in [:dev, :prod]
  end
end
