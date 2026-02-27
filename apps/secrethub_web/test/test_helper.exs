ExUnit.start()

# When running from the umbrella root via the test alias, the Repo may already
# be started with DBConnection.ConnectionPool instead of Ecto.Adapters.SQL.Sandbox.
# Detect this and reconfigure if needed.
repo_config = Application.get_env(:secrethub_core, SecretHub.Core.Repo) || []
pool = Keyword.get(repo_config, :pool)

if pool != Ecto.Adapters.SQL.Sandbox do
  test_config = [
    socket_dir: System.get_env("PGHOST") || System.get_env("DEVENV_STATE", "/tmp") <> "/postgres",
    username: System.get_env("PGUSER", "secrethub"),
    password: System.get_env("PGPASSWORD", "secrethub_dev_password"),
    database: "secrethub_test#{System.get_env("MIX_TEST_PARTITION")}",
    pool: Ecto.Adapters.SQL.Sandbox,
    pool_size: System.schedulers_online() * 2
  ]

  Application.put_env(:secrethub_core, SecretHub.Core.Repo, test_config)

  # Stop dependent GenServers before stopping Repo
  sup = SecretHub.Core.Supervisor

  for child_id <- [SecretHub.Core.LeaseManager, SecretHub.Core.Vault.SealState] do
    case Supervisor.terminate_child(sup, child_id) do
      :ok -> Supervisor.delete_child(sup, child_id)
      {:error, :not_found} -> :ok
    end
  end

  case Supervisor.terminate_child(sup, SecretHub.Core.Repo) do
    :ok -> Supervisor.delete_child(sup, SecretHub.Core.Repo)
    {:error, :not_found} -> :ok
  end

  Process.sleep(100)
end

# Start the Repo manually for test mode if not already started
case SecretHub.Core.Repo.start_link() do
  {:ok, _pid} -> :ok
  {:error, {:already_started, _pid}} -> :ok
end

# Set up Ecto Sandbox for database isolation in tests
Ecto.Adapters.SQL.Sandbox.mode(SecretHub.Core.Repo, :manual)

# Stop SealState if it's running (it shouldn't start in test but might be running from previous session)
case Process.whereis(SecretHub.Core.Vault.SealState) do
  nil -> :ok
  pid -> GenServer.stop(pid, :normal)
end

# Import support modules
Code.require_file("support/conn_case.ex", __DIR__)
Code.require_file("support/channel_case.ex", __DIR__)
