defmodule SecretHub.Core.RuntimeDatabaseFixture do
  @moduledoc false
  import ExUnit.Callbacks
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState

  # Route the Vault's separate process and its audit appends to the same real
  # database pool as the caller, without sharing a Sandbox connection.
  defmodule VaultRepo do
    alias SecretHub.Core.Repo

    for {name, arity} <- [all: 1, all: 2, query: 3, transaction: 1, insert: 1, rollback: 1] do
      args = Macro.generate_arguments(arity, __MODULE__)

      def unquote(name)(unquote_splicing(args)) do
        Repo.put_dynamic_repo(:runtime_authorization_fixture)
        apply(Repo, unquote(name), [unquote_splicing(args)])
      end
    end
  end

  # Migrate once, close every connection, and clone this pristine fixture for
  # each test. Floor monotonicity is never reset or bypassed between assertions.
  def prepare_template do
    database = database_name()
    admin_query!("CREATE DATABASE " <> database)
    {:ok, repo} = start_repo(database, :runtime_authorization_template)
    original = Repo.put_dynamic_repo(:runtime_authorization_template)

    try do
      migrate()
    after
      Repo.put_dynamic_repo(original)
      Supervisor.stop(repo)
    end

    on_exit(fn -> admin_query!("DROP DATABASE " <> database) end)
    %{runtime_database_template: database}
  end

  def setup(tags \\ %{}, opts \\ []) do
    database = database_name()
    template = tags[:runtime_database_template]

    admin_query!(
      "CREATE DATABASE " <> database <> if(template, do: " TEMPLATE " <> template, else: "")
    )

    default_repo? = Keyword.get(opts, :default_repo, false)
    original_config = Repo.config()
    repo_name = if default_repo?, do: Repo, else: :runtime_authorization_fixture

    if default_repo?, do: Supervisor.stop(Process.whereis(Repo), :normal, 5_000)
    {:ok, fixture} = start_repo(database, repo_name)
    original = Repo.put_dynamic_repo(repo_name)

    on_exit(fn ->
      try do
        stop_process(Process.whereis(SealState))
      after
        stop_process(fixture)
        Repo.put_dynamic_repo(original)

        if default_repo? do
          {:ok, restored} = Repo.start_link(original_config)
          Process.unlink(restored)
          Ecto.Adapters.SQL.Sandbox.mode(Repo, :manual)
        end

        admin_query!("DROP DATABASE " <> database)
      end
    end)

    unless template, do: migrate()
    :ok
  end

  defp stop_process(nil), do: :ok

  defp stop_process(pid) do
    GenServer.stop(pid, :normal, 5_000)
  catch
    # Test-linked Vault processes may exit between whereis and stop. A process
    # already gone has completed shutdown; teardown must still close its pool.
    :exit, {:noproc, _} -> :ok
  end

  defp migrate do
    Ecto.Migrator.run(Repo, Application.app_dir(:secrethub_core, "priv/repo/migrations"), :up,
      all: true,
      log: false
    )
  end

  defp start_repo(database, name) do
    opts =
      Repo.config()
      |> Keyword.merge(
        name: name,
        database: database,
        pool: DBConnection.ConnectionPool,
        pool_size: 8
      )

    {:ok, repo} = Repo.start_link(opts)
    Process.unlink(repo)
    {:ok, repo}
  end

  defp database_name,
    do: "secrethub_runtime_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

  defp admin_query!(sql) do
    # Database cloning and removal can wait for a checkpoint and disk work.
    Ecto.Adapters.SQL.Sandbox.unboxed_run(Repo, fn -> Repo.query!(sql, [], timeout: 45_000) end)
  end
end
