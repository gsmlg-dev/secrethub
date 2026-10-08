defmodule SecretHub.Human.AttachmentsTest do
  use SecretHub.Human.DataCase, async: false
  alias SecretHub.Human.{Accounts, Attachments, Vault}

  defmodule FailingDeletionStorage do
    @behaviour SecretHub.Human.Attachments.Storage
    defdelegate put(id, ciphertext, opts), to: SecretHub.Human.Attachments.FileStorage
    defdelegate get(id, opts), to: SecretHub.Human.Attachments.FileStorage
    defdelegate list(opts), to: SecretHub.Human.Attachments.FileStorage
    def delete(_, _), do: {:error, :storage_unavailable}
  end

  defp encrypted(size \\ 16),
    do: "2." <> Enum.map_join([16, size, 32], "|", &Base.encode64(:crypto.strong_rand_bytes(&1)))

  setup do
    root = Path.join(System.tmp_dir!(), "human-attachments-#{Ecto.UUID.generate()}")
    on_exit(fn -> File.rm_rf!(root) end)

    attrs = %{
      email: "attachments-#{System.unique_integer([:positive])}@example.test",
      password_hash: Base.encode64(:crypto.strong_rand_bytes(32)),
      encrypted_key: encrypted()
    }

    {:ok, _} = Accounts.provision(attrs, server_iterations: 1000)

    {:ok, session} =
      Accounts.authenticate(attrs.email, attrs.password_hash, %{identifier: "attachments"})

    {:ok, item} =
      Vault.create_item(session.actor, %{type: "login", ciphertext: %{"name" => encrypted()}})

    %{
      actor: session.actor,
      item: item,
      opts: [directory: root, max_bytes: 1024, quota_bytes: 1500],
      payload: %{filename: encrypted(), encrypted_key: encrypted(80), ciphertext: encrypted(512)}
    }
  end

  test "independent encrypted content has authorized reads and safe delete", %{
    actor: actor,
    item: item,
    opts: opts,
    payload: payload
  } do
    assert {:ok, attachment} = Attachments.upload(actor, item.id, payload, opts)
    assert {:ok, content} = Attachments.download(actor, attachment.id, opts)
    assert content == payload.ciphertext
    refute inspect(attachment) =~ payload.ciphertext

    assert {:error, :invalid_ciphertext} =
             Attachments.upload(actor, item.id, %{payload | ciphertext: "unencrypted file"}, opts)

    assert :ok = Accounts.revoke_session(actor, actor.session_id)
    assert {:error, :unauthenticated} = Attachments.download(actor, attachment.id, opts)
  end

  test "size and cumulative quota are enforced transactionally", %{
    actor: actor,
    item: item,
    opts: opts,
    payload: payload
  } do
    assert {:error, :attachment_too_large} =
             Attachments.upload(actor, item.id, %{payload | ciphertext: encrypted(2048)}, opts)

    assert {:ok, _} = Attachments.upload(actor, item.id, payload, opts)
    assert {:error, :quota_exceeded} = Attachments.upload(actor, item.id, payload, opts)
    assert {:ok, [first]} = Attachments.list(actor, item.id)
    assert :ok = Attachments.delete(actor, first.id, opts)
    assert {:error, :not_found} = Attachments.download(actor, first.id, opts)
    assert {:ok, _} = Attachments.upload(actor, item.id, payload, opts)
  end

  test "export requires explicit consent and excludes dynamic credentials", %{
    actor: actor,
    item: item
  } do
    assert {:error, :confirmation_required} = Vault.export(actor, %{})

    assert {:ok, %{format: "secrethub-encrypted-v1", items: [exported]}} =
             Vault.export(actor, %{confirm: true})

    assert exported.id == item.id
    assert exported.ciphertext == item.ciphertext
  end

  test "deleting a vault item reclaims its attachment storage and quota", ctx do
    assert {:ok, attachment} = Attachments.upload(ctx.actor, ctx.item.id, ctx.payload, ctx.opts)
    assert {:ok, _} = Vault.delete_item(ctx.actor, ctx.item.id)
    assert {:error, :not_found} = Attachments.download(ctx.actor, attachment.id, ctx.opts)
    assert :ok = Attachments.cleanup(ctx.opts)
    refute File.exists?(Path.join(ctx.opts[:directory], attachment.id))
    assert Repo.get!(SecretHub.Human.Attachments.Usage, ctx.actor.user_id).bytes == 0
    assert Repo.get!(SecretHub.Human.Attachments.Attachment, attachment.id).deleted_at
    assert :ok = Attachments.cleanup(ctx.opts)
    assert Repo.get!(SecretHub.Human.Attachments.Usage, ctx.actor.user_id).bytes == 0

    assert {:ok, next} =
             Vault.create_item(ctx.actor, %{type: "login", ciphertext: %{"name" => encrypted()}})

    assert {:ok, _} = Attachments.upload(ctx.actor, next.id, ctx.payload, ctx.opts)
  end

  test "attachment identifiers cannot cross ownership boundaries", ctx do
    attrs = %{
      email: "other-#{Ecto.UUID.generate()}@example.test",
      password_hash: Base.encode64(:crypto.strong_rand_bytes(32)),
      encrypted_key: encrypted()
    }

    {:ok, _} = Accounts.provision(attrs, server_iterations: 1000)

    {:ok, session} =
      Accounts.authenticate(attrs.email, attrs.password_hash, %{identifier: "other"})

    assert {:ok, attachment} = Attachments.upload(ctx.actor, ctx.item.id, ctx.payload, ctx.opts)
    assert {:error, :not_found} = Attachments.list(session.actor, ctx.item.id)

    assert {:error, :not_found} =
             Attachments.upload(session.actor, ctx.item.id, ctx.payload, ctx.opts)

    assert {:error, :not_found} = Attachments.download(session.actor, attachment.id, ctx.opts)
    assert {:error, :not_found} = Attachments.delete(session.actor, attachment.id, ctx.opts)
    assert {:ok, content} = Attachments.download(ctx.actor, attachment.id, ctx.opts)
    assert content == ctx.payload.ciphertext
  end

  test "orphan cleanup removes old interrupted writes but preserves live and recent files", ctx do
    alias SecretHub.Human.Attachments.FileStorage
    assert {:ok, attachment} = Attachments.upload(ctx.actor, ctx.item.id, ctx.payload, ctx.opts)
    old = Ecto.UUID.generate()
    recent = Ecto.UUID.generate()
    assert :ok = FileStorage.put(old, ctx.payload.ciphertext, ctx.opts)
    assert :ok = FileStorage.put(recent, ctx.payload.ciphertext, ctx.opts)
    past = System.system_time(:second) - 3601
    assert :ok = File.touch(Path.join(ctx.opts[:directory], old), past)
    assert :ok = File.touch(Path.join(ctx.opts[:directory], attachment.id), past)
    assert :ok = Attachments.cleanup(ctx.opts)
    refute File.exists?(Path.join(ctx.opts[:directory], old))
    assert File.exists?(Path.join(ctx.opts[:directory], recent))
    assert {:ok, content} = Attachments.download(ctx.actor, attachment.id, ctx.opts)
    assert content == ctx.payload.ciphertext
  end

  test "failed file deletion retries without reclaiming quota twice", ctx do
    assert {:ok, attachment} = Attachments.upload(ctx.actor, ctx.item.id, ctx.payload, ctx.opts)
    assert {:ok, _} = Vault.delete_item(ctx.actor, ctx.item.id)

    assert {:error, :storage_unavailable} =
             Attachments.cleanup(Keyword.put(ctx.opts, :storage, FailingDeletionStorage))

    assert File.exists?(Path.join(ctx.opts[:directory], attachment.id))
    assert Repo.get!(SecretHub.Human.Attachments.Usage, ctx.actor.user_id).bytes == 0
    assert :ok = Attachments.cleanup(ctx.opts)
    refute File.exists?(Path.join(ctx.opts[:directory], attachment.id))
    assert Repo.get!(SecretHub.Human.Attachments.Usage, ctx.actor.user_id).bytes == 0
  end
end
