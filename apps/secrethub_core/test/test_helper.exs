# Ensure test support modules are loaded (needed for umbrella test runs)
unless Code.ensure_loaded?(SecretHub.Core.DataCase) do
  Code.require_file("support/data_case.ex", __DIR__)
end

ExUnit.start()

# Defensively repair an already-started Repo that did not receive the sandbox
# configuration by restarting affected processes in dependency order.

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

  # Stop database-backed children first (they depend on Repo)
  sup = SecretHub.Core.Supervisor

  repair_child_ids = [
    SecretHub.Core.Agents.ConnectionManager,
    SecretHub.Core.LeaseManager,
    SecretHub.Core.ClusterState,
    SecretHub.Core.Vault.SealState
  ]

  for child_id <- repair_child_ids do
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
