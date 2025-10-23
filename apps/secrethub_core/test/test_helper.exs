ExUnit.start()

# Stop SealState if it's running (it shouldn't start in test but might be running from previous session)
case Process.whereis(SecretHub.Core.Vault.SealState) do
  nil -> :ok
  pid -> GenServer.stop(pid, :normal)
end

# Set up Ecto Sandbox for testing
Ecto.Adapters.SQL.Sandbox.mode(SecretHub.Core.Repo, :manual)
