defmodule SecretHub.Core.StyxMigrationTest do
  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias SecretHub.Core.Repo

  @transition_version 20_261_107_000_001
  @migrations [
    {:secrethub_core, 20_261_022_000_001, "20261022000001_install_core_oban.exs",
     SecretHub.Core.Repo.Migrations.InstallCoreOban,
     SecretHub.Core.Repo.Migrations.ReplaceObanWithStyx},
    {:secrethub_human, 20_261_008_000_001, "20261008000001_create_human_jobs.exs",
     SecretHub.Human.Repo.Migrations.CreateHumanJobs,
     SecretHub.Human.Repo.Migrations.ReplaceObanWithStyx}
  ]

  defmodule Worker do
    use Styx.Worker, queue: :migration

    @impl Styx.Worker
    def perform(%Styx.Job{args: %{"notify" => value}}) do
      send(Process.whereis(SecretHub.Core.StyxMigrationTest), {:performed, value})
      :ok
    end
  end

  setup_all do
    for {app, _, historical_file, _, _} <- @migrations,
        file <- [historical_file, "20261107000001_replace_oban_with_styx.exs"] do
      Code.require_file(Application.app_dir(app, "priv/repo/migrations/#{file}"))
    end

    :ok
  end

  setup do
    owner = Sandbox.start_owner!(Repo, shared: true)
    on_exit(fn -> Sandbox.stop_owner(owner) end)
    schema = "styx_transition_#{System.unique_integer([:positive])}"
    Repo.query!("CREATE SCHEMA #{schema}")
    %{schema: schema, opts: [prefix: schema, log: false, migration_lock: false]}
  end

  for {app, initial_version, _, initial, transition} <- @migrations do
    @initial_version initial_version
    @initial initial
    @transition transition

    test "#{app} preserves every job state, payload, peer and sequence through rollback", %{
      schema: schema,
      opts: opts
    } do
      legacy_schema(schema)
      states = ~w(available suspended scheduled executing retryable completed discarded cancelled)

      for state <- states do
        Repo.query!("""
        INSERT INTO #{schema}.oban_jobs
          (state, worker, args, meta, errors, attempt, priority, tags, attempted_by,
           attempted_at, completed_at, cancelled_at, discarded_at)
        VALUES ('#{state}', '#{Worker}', '{"notify":"legacy"}', '{"source":"legacy"}',
          ARRAY['{"attempt":1,"error":"retry"}'::jsonb], 1, 4, ARRAY['rotation'],
          ARRAY['node@host'], now(), now(), now(), now())
        """)
      end

      Repo.query!("""
      INSERT INTO #{schema}.oban_peers (name, node, started_at, expires_at)
      VALUES ('SecretHub.Core.Oban', 'node@host', now(), now() + interval '1 minute')
      """)

      Repo.query!("COMMENT ON TABLE #{schema}.oban_peers IS 'keep peer comment'")
      Repo.query!("SELECT setval('#{schema}.oban_jobs_id_seq', 100)")
      jobs = rows(schema, "oban_jobs", "id")
      peers = rows(schema, "oban_peers", "name")
      identities = identities(schema, "oban")

      assert :ok = Ecto.Migrator.up(Repo, @transition_version, @transition, opts)
      assert rows(schema, "styx_jobs", "id") == jobs
      assert rows(schema, "styx_peers", "name") == peers
      assert identities(schema, "styx") == identities
      assert [["keep peer comment"]] = table_comment(schema, "styx_peers")
      assert [["1"]] = table_comment(schema, "styx_jobs")
      assert [[1]] = Repo.query!("SELECT #{schema}.styx_wrap_id(2147483648)").rows

      assert {:ok, %Styx.Job{id: 101}} =
               Repo.insert(Worker.new(%{notify: "new"}), prefix: schema)

      assert :ok = Ecto.Migrator.down(Repo, @transition_version, @transition, opts)
      assert Enum.take(rows(schema, "oban_jobs", "id"), 8) == jobs
      assert rows(schema, "oban_peers", "name") == peers
      assert identities(schema, "oban") == identities
      assert [["14"]] = table_comment(schema, "oban_jobs")
      assert [["keep peer comment"]] = table_comment(schema, "oban_peers")

      assert [[nil]] =
               Repo.query!("SELECT to_regprocedure('#{schema}.styx_wrap_id(bigint)')").rows

      assert :ok = Ecto.Migrator.up(Repo, @transition_version, @transition, opts)
      assert [[9]] = Repo.query!("SELECT count(*) FROM #{schema}.styx_jobs").rows
    end

    test "#{app} fresh chain supports transition rollback, full rollback and reapplication", %{
      schema: schema,
      opts: opts
    } do
      assert :ok = Ecto.Migrator.up(Repo, @initial_version, @initial, opts)
      Repo.insert!(Worker.new(%{notify: "fresh"}), prefix: schema)
      assert :ok = Ecto.Migrator.up(Repo, @transition_version, @transition, opts)
      assert :ok = Ecto.Migrator.down(Repo, @transition_version, @transition, opts)
      assert [[1]] = Repo.query!("SELECT count(*) FROM #{schema}.styx_jobs").rows
      assert :ok = Ecto.Migrator.down(Repo, @initial_version, @initial, opts)
      assert_storage_absent(schema)
      assert :ok = Ecto.Migrator.up(Repo, @initial_version, @initial, opts)
      assert :ok = Ecto.Migrator.up(Repo, @transition_version, @transition, opts)
    end

    test "#{app} legacy full rollback removes old storage before a fresh reapplication", %{
      schema: schema,
      opts: opts
    } do
      assert :ok = Ecto.Migrator.up(Repo, @initial_version, @initial, opts)
      assert :ok = Ecto.Migrator.down(Repo, @initial_version, @initial, opts)
      legacy_schema(schema)

      Repo.query!("""
      INSERT INTO #{schema}.schema_migrations (version, inserted_at)
      VALUES (#{@initial_version}, now())
      """)

      assert :ok = Ecto.Migrator.up(Repo, @transition_version, @transition, opts)
      assert :ok = Ecto.Migrator.down(Repo, @transition_version, @transition, opts)
      assert :ok = Ecto.Migrator.down(Repo, @initial_version, @initial, opts)
      assert_storage_absent(schema)
      assert :ok = Ecto.Migrator.up(Repo, @initial_version, @initial, opts)
      assert :ok = Ecto.Migrator.up(Repo, @transition_version, @transition, opts)
    end
  end

  test "refuses ambiguous dual queue storage", %{schema: schema, opts: opts} do
    legacy_schema(schema)
    Repo.query!("CREATE TABLE #{schema}.styx_jobs (id bigint)")

    assert_raise Ecto.MigrationError, ~r/both oban_jobs and styx_jobs exist/, fn ->
      Ecto.Migrator.up(
        Repo,
        @transition_version,
        SecretHub.Core.Repo.Migrations.ReplaceObanWithStyx,
        opts
      )
    end
  end

  test "refuses unsupported legacy schema versions", %{schema: schema, opts: opts} do
    legacy_schema(schema)
    Repo.query!("COMMENT ON TABLE #{schema}.oban_jobs IS '13'")

    assert_raise Ecto.MigrationError, ~r/Oban schema must be version 14/, fn ->
      Ecto.Migrator.up(
        Repo,
        @transition_version,
        SecretHub.Core.Repo.Migrations.ReplaceObanWithStyx,
        opts
      )
    end
  end

  test "Styx executes migrated work and new work after its instance restarts", %{
    schema: schema,
    opts: opts
  } do
    Process.register(self(), __MODULE__)
    legacy_schema(schema)

    Repo.query!("""
    INSERT INTO #{schema}.oban_jobs (worker, queue, args)
    VALUES ('#{Worker}', 'migration', '{"notify":"legacy"}')
    """)

    assert :ok =
             Ecto.Migrator.up(
               Repo,
               @transition_version,
               SecretHub.Core.Repo.Migrations.ReplaceObanWithStyx,
               opts
             )

    config = [
      name: __MODULE__.Queue,
      repo: Repo,
      prefix: schema,
      testing: :disabled,
      # Sandbox never commits, so Postgres notifications cannot reach the queue.
      notifier: Styx.Notifiers.PG,
      peer: false,
      plugins: false,
      queues: [migration: [limit: 1, paused: true]]
    ]

    start_supervised!({Styx, config})
    assert {:ok, _} = Styx.insert(__MODULE__.Queue, Worker.new(%{notify: "new"}))
    stop_supervised!(__MODULE__.Queue)
    start_supervised!({Styx, Keyword.put(config, :queues, migration: 1)})
    assert_receive {:performed, "legacy"}, 5_000
    assert_receive {:performed, "new"}, 5_000
    assert {:ok, _} = Styx.insert(__MODULE__.Queue, Worker.new(%{notify: "after_restart"}))
    assert_receive {:performed, "after_restart"}, 5_000
    assert completed?(schema, 100)
  end

  defp completed?(_schema, 0), do: false

  defp completed?(schema, attempts) do
    if Repo.query!("SELECT count(*) FROM #{schema}.styx_jobs WHERE state = 'completed'").rows ==
         [[3]] do
      true
    else
      Process.sleep(50)
      completed?(schema, attempts - 1)
    end
  end

  defp legacy_schema(schema) do
    Path.expand("../fixtures/oban_v14.sql", __DIR__)
    |> File.read!()
    |> String.replace("__PREFIX__", schema)
    |> String.split(";", trim: true)
    |> Enum.reject(&(String.trim(&1) == ""))
    |> Enum.each(&Repo.query!(&1))
  end

  defp rows(schema, table, order),
    do: Repo.query!("SELECT * FROM #{schema}.#{table} ORDER BY #{order}").rows

  defp table_comment(schema, table),
    do: Repo.query!("SELECT obj_description('#{schema}.#{table}'::regclass)").rows

  defp identities(schema, name) do
    Repo.query!("""
    SELECT '#{schema}.#{name}_jobs'::regclass::oid,
      pg_get_serial_sequence('#{schema}.#{name}_jobs', 'id')::regclass::oid,
      '#{schema}.#{name}_peers'::regclass::oid
    """).rows
  end

  defp assert_storage_absent(schema) do
    for table <- ~w(oban_jobs oban_peers styx_jobs styx_peers) do
      assert [[nil]] = Repo.query!("SELECT to_regclass('#{schema}.#{table}')").rows
    end

    assert [[0]] =
             Repo.query!("""
             SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
             WHERE n.nspname = '#{schema}' AND t.typname IN ('oban_job_state', 'styx_job_state')
             """).rows
  end
end
