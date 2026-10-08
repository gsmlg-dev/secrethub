defmodule SecretHub.Human.VaultConcurrencyTest do
  alias SecretHub.Human.Attachments.FileStorage
  use SecretHub.Human.DataCase, async: false
  alias SecretHub.Human.{Accounts, Attachments, Vault}

  defp encrypted(size \\ 16),
    do: "2." <> Enum.map_join([16, size, 32], "|", &Base.encode64(:crypto.strong_rand_bytes(&1)))

  setup do
    {:ok, dynamic_repo} =
      Repo.start_link(name: nil, pool: DBConnection.ConnectionPool, pool_size: 4)

    Process.unlink(dynamic_repo)
    previous = Repo.get_dynamic_repo()
    Repo.put_dynamic_repo(dynamic_repo)

    attrs = %{
      email: "concurrency-#{Ecto.UUID.generate()}@example.test",
      password_hash: Base.encode64(:crypto.strong_rand_bytes(32)),
      encrypted_key: encrypted()
    }

    {:ok, user} = Accounts.provision(attrs, server_iterations: 1000)

    {:ok, session} =
      Accounts.authenticate(attrs.email, attrs.password_hash, %{identifier: "concurrency"})

    root = Path.join(System.tmp_dir!(), "human-concurrency-#{user.id}")

    on_exit(fn ->
      Repo.put_dynamic_repo(dynamic_repo)

      ids =
        Repo.all(
          from(e in SecretHub.Human.Audit.Event,
            where: e.actor_id == ^user.id or fragment("?->>'user_id'", e.metadata) == ^user.id,
            select: e.id
          )
        )

      Repo.delete_all(from(j in Oban.Job, where: fragment("?->>'event_id'", j.args) in ^ids))
      Repo.delete_all(from(e in SecretHub.Human.Audit.Event, where: e.id in ^ids))
      Repo.delete_all(from(u in SecretHub.Human.Schemas.User, where: u.id == ^user.id))
      GenServer.stop(dynamic_repo)
      File.rm_rf!(root)
    end)

    %{actor: session.actor, dynamic_repo: dynamic_repo, previous: previous, root: root}
  end

  defp concurrently(ctx, inputs, command) do
    inputs
    |> Task.async_stream(
      fn input ->
        Repo.put_dynamic_repo(ctx.dynamic_repo)
        command.(input)
      end,
      max_concurrency: 4,
      timeout: 15_000,
      on_timeout: :kill_task
    )
    |> Enum.map(fn {:ok, result} -> result end)
  end

  test "concurrent quota reservations allow exactly one upload across independent connections",
       ctx do
    {:ok, first} =
      Vault.create_item(ctx.actor, %{type: "login", ciphertext: %{"name" => encrypted()}})

    {:ok, second} =
      Vault.create_item(ctx.actor, %{type: "login", ciphertext: %{"name" => encrypted()}})

    payload = %{filename: encrypted(), encrypted_key: encrypted(80), ciphertext: encrypted(512)}
    opts = [directory: ctx.root, max_bytes: 1024, quota_bytes: 1500]

    results =
      concurrently(ctx, [first.id, second.id], &Attachments.upload(ctx.actor, &1, payload, opts))

    assert [{:ok, attachment}] = Enum.filter(results, &match?({:ok, _}, &1))
    assert [{:error, :quota_exceeded}] = Enum.filter(results, &match?({:error, _}, &1))

    assert Repo.get!(SecretHub.Human.Attachments.Usage, ctx.actor.user_id).bytes ==
             byte_size(payload.ciphertext)

    assert {:ok, files} = FileStorage.list(opts)
    assert [{id, _}] = files
    assert id == attachment.id
    Repo.put_dynamic_repo(ctx.previous)
  end

  test "concurrent mutations assign unique committed revisions visible through paginated sync",
       ctx do
    results =
      concurrently(ctx, 1..12, fn _ ->
        Vault.create_item(ctx.actor, %{type: "login", ciphertext: %{"name" => encrypted()}})
      end)

    revisions = Enum.map(results, fn {:ok, item} -> item.revision end)
    assert Enum.sort(revisions) == Enum.to_list(1..12)

    {items, cursor} =
      Enum.reduce(1..4, {[], 0}, fn _, {acc, cursor} ->
        assert {:ok, %{items: page, folders: [], cursor: next}} =
                 Vault.sync(ctx.actor, cursor, limit: 3)

        {acc ++ page, next}
      end)

    assert Enum.map(items, & &1.revision) == Enum.to_list(1..12)
    assert cursor == 12
    assert {:ok, %{items: [], folders: [], cursor: 12}} = Vault.sync(ctx.actor, cursor)
    Repo.put_dynamic_repo(ctx.previous)
  end
end
