ExUnit.start()

# Start the Repo manually for test mode if not already started
# In test, the application doesn't start Repo to avoid timing issues with Sandbox
case SecretHub.Core.Repo.start_link() do
  {:ok, _pid} -> :ok
  {:error, {:already_started, _pid}} -> :ok
end

# Set up Ecto Sandbox for testing
Ecto.Adapters.SQL.Sandbox.mode(SecretHub.Core.Repo, :manual)

# Stop SealState if it's running (it shouldn't start in test but might be running from previous session)
case Process.whereis(SecretHub.Core.Vault.SealState) do
  nil -> :ok
  pid -> GenServer.stop(pid, :normal)
end
