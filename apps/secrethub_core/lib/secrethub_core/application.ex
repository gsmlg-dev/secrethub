defmodule SecretHub.Core.Application do
  @moduledoc false

  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    # Trap exits to enable graceful shutdown
    Process.flag(:trap_exit, true)

    children =
      cache_children() ++
        repo_children() ++
        seal_state_children() ++
        lease_manager_children()

    opts = [strategy: :one_for_one, name: SecretHub.Core.Supervisor]
    result = Supervisor.start_link(children, opts)

    Logger.info("SecretHub.Core.Application started")
    result
  end

  # Start Cache system early (doesn't depend on DB)
  defp cache_children do
    [SecretHub.Core.Cache]
  end

  @impl true
  def stop(_state) do
    Logger.info("SecretHub.Core.Application stopping...")

    # Trigger graceful shutdown
    # Use shorter timeout for Core since Web will handle connection draining
    SecretHub.Core.Shutdown.graceful_shutdown(
      timeout_ms: 15_000,
      drain_connections: false,
      wait_for_jobs: true
    )

    Logger.info("SecretHub.Core.Application stopped")
    :ok
  end

  # Conditionally start Repo based on environment
  # In test mode, Repo is started manually after Sandbox configuration
  defp repo_children do
    if Application.get_env(:secrethub_core, :env) == :test do
      []
    else
      [SecretHub.Core.Repo]
    end
  end

  # Only start SealState in non-test environments (it tries to write to DB on init)
  defp seal_state_children do
    # Check if SealState should start (disabled in test to avoid DB writes during init)
    start_seal_state = Application.get_env(:secrethub_core, :start_seal_state, true)

    if start_seal_state do
      [SecretHub.Core.Vault.SealState]
    else
      []
    end
  end

  # Start LeaseManager for dynamic secret lease tracking
  defp lease_manager_children do
    # Only start LeaseManager when Repo is available (not in test mode)
    if Application.get_env(:secrethub_core, :env) == :test do
      []
    else
      [SecretHub.Core.LeaseManager]
    end
  end
end
