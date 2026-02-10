ExUnit.start()

# When running from the umbrella root, the application config may not be loaded
# at the time the Core application starts (Application.get_env returns nil).
# This causes the Repo to start with DBConnection.ConnectionPool instead of
# Ecto.Adapters.SQL.Sandbox. We detect and fix this by setting the correct config
# and restarting the affected processes within the supervisor.

repo_config = Application.get_env(:secrethub_core, SecretHub.Core.Repo) || []
pool = Keyword.get(repo_config, :pool)

if pool != Ecto.Adapters.SQL.Sandbox do
  # Set the correct test config
  test_config = [
    socket_dir: System.get_env("PGHOST") || System.get_env("DEVENV_STATE", "/tmp") <> "/postgres",
    username: System.get_env("PGUSER", "secrethub"),
    password: System.get_env("PGPASSWORD", "secrethub_dev_password"),
    database: "secrethub_test#{System.get_env("MIX_TEST_PARTITION")}",
    pool: Ecto.Adapters.SQL.Sandbox,
    pool_size: System.schedulers_online() * 2
  ]

  Application.put_env(:secrethub_core, SecretHub.Core.Repo, test_config)
  Application.put_env(:secrethub_core, :env, :test)

  # Stop LeaseManager and SealState first (they depend on Repo)
  sup = SecretHub.Core.Supervisor

  for child_id <- [SecretHub.Core.LeaseManager, SecretHub.Core.Vault.SealState] do
    case Supervisor.terminate_child(sup, child_id) do
      :ok -> Supervisor.delete_child(sup, child_id)
      {:error, :not_found} -> :ok
    end
  end

  # Now stop the Repo and remove it from the supervisor
  case Supervisor.terminate_child(sup, SecretHub.Core.Repo) do
    :ok -> Supervisor.delete_child(sup, SecretHub.Core.Repo)
    {:error, :not_found} -> :ok
  end

  Process.sleep(100)
end

# Start the Repo manually (outside supervisor in test mode)
case SecretHub.Core.Repo.start_link() do
  {:ok, _pid} -> :ok
  {:error, {:already_started, _pid}} -> :ok
end

# Set up Ecto Sandbox for testing
Ecto.Adapters.SQL.Sandbox.mode(SecretHub.Core.Repo, :manual)

# Stop SealState if it's still running
case Process.whereis(SecretHub.Core.Vault.SealState) do
  nil -> :ok
  pid -> GenServer.stop(pid, :normal)
end

# Stop LeaseManager if it's still running
case Process.whereis(SecretHub.Core.LeaseManager) do
  nil -> :ok
  pid -> GenServer.stop(pid, :normal)
end
