defmodule SecretHub.Core.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Start the Ecto repository
      SecretHub.Core.Repo
    ] ++ seal_state_children()

    opts = [strategy: :one_for_one, name: SecretHub.Core.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Only start SealState in non-test environments (it tries to write to DB on init)
  defp seal_state_children do
    # Check if we're in test mode using the Repo pool configuration
    repo_config = Application.get_env(:secrethub_core, SecretHub.Core.Repo, [])
    pool = Keyword.get(repo_config, :pool)

    if pool == Ecto.Adapters.SQL.Sandbox do
      # We're in test mode - don't start SealState
      []
    else
      [SecretHub.Core.Vault.SealState]
    end
  end
end
