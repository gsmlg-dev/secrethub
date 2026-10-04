defmodule SecretHub.Core.RuntimeDatabaseFixture do
  @moduledoc false
  import ExUnit.Callbacks
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState

  # Route the Vault's separate process and its audit appends to the same real
  # database pool as the caller, without sharing a Sandbox connection.
  defmodule VaultRepo do
    alias SecretHub.Core.Repo

    for {name, arity} <- [all: 1, all: 2, transaction: 1, insert: 1, rollback: 1] do
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

  def setup(tags \\ %{}) do
    database = database_name()
    template = tags[:runtime_database_template]

    admin_query!(
      "CREATE DATABASE " <> database <> if(template, do: " TEMPLATE " <> template, else: "")
    )

    {:ok, fixture} = start_repo(database, :runtime_authorization_fixture)
    original = Repo.put_dynamic_repo(:runtime_authorization_fixture)

    on_exit(fn ->
      if pid = Process.whereis(SealState), do: GenServer.stop(pid)
      Supervisor.stop(fixture)
      Repo.put_dynamic_repo(original)
      admin_query!("DROP DATABASE " <> database)
    end)

    unless template, do: migrate()
    :ok
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
    Ecto.Adapters.SQL.Sandbox.unboxed_run(Repo, fn -> Repo.query!(sql) end)
  end
end
