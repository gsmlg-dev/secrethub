defmodule SecretHub.Core.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = repo_children() ++ seal_state_children() ++ lease_manager_children()

    opts = [strategy: :one_for_one, name: SecretHub.Core.Supervisor]
    Supervisor.start_link(children, opts)
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
