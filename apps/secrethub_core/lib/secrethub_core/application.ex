defmodule SecretHub.Core.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children =
      [
        # Start the Ecto repository
        SecretHub.Core.Repo
      ] ++ seal_state_children()

    opts = [strategy: :one_for_one, name: SecretHub.Core.Supervisor]
    Supervisor.start_link(children, opts)
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
end
