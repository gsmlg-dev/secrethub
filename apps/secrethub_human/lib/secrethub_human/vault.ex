defmodule SecretHub.Human.Vault do
  @moduledoc "Ownership-scoped encrypted personal vault with serialized revision cursors and retained history."
  import Ecto.Query
  alias Ecto.Changeset
  alias SecretHub.Human.{Accounts, Audit, Repo}
  alias SecretHub.Human.Vault.{Envelope, Folder, Head, Item, Version}
  @types ~w(login secure_note api_credential identity card ssh_key)

  def create_item(actor, attrs) do
    command(actor, fn ->
      type = value(attrs, :type)

      unless type in @types and is_boolean(value(attrs, :favorite, false)),
        do: Repo.rollback(:invalid_input)

      ciphertext = value(attrs, :ciphertext)
      unless Envelope.valid_payload?(ciphertext), do: Repo.rollback(:invalid_ciphertext)
      folder_id = folder!(actor, value(attrs, :folder_id))

      item =
        Repo.insert!(%Item{
          user_id: actor.user_id,
          type: type,
          ciphertext: ciphertext,
          folder_id: folder_id,
          favorite: value(attrs, :favorite, false),
          revision: next_revision!(actor)
        })

      audit!("human.vault.item.created", actor, %{item_id: item.id, revision: item.revision})
      item
    end)
  end

  def get_item(actor, id) do
    command(actor, fn -> owned!(Item, actor, id) end)
  end

  def update_item(actor, id, attrs) do
    command(actor, fn ->
      item = owned!(Item, actor, id)
      expected = value(attrs, :expected_revision)
      unless is_nil(expected) or expected == item.revision, do: Repo.rollback(:conflict)
      ciphertext = value(attrs, :ciphertext, item.ciphertext)
      unless Envelope.valid_payload?(ciphertext), do: Repo.rollback(:invalid_ciphertext)
      favorite = value(attrs, :favorite, item.favorite)
      unless is_boolean(favorite), do: Repo.rollback(:invalid_input)
      folder_id = folder!(actor, value(attrs, :folder_id, item.folder_id))
      retain_version!(item)

      updated =
        Repo.update!(
          Changeset.change(item,
            ciphertext: ciphertext,
            folder_id: folder_id,
            favorite: favorite,
            revision: next_revision!(actor)
          )
        )

      audit!("human.vault.item.updated", actor, %{item_id: id, revision: updated.revision})
      updated
    end)
  end

  def delete_item(actor, id) do
    command(actor, fn ->
      item = owned!(Item, actor, id)
      retain_version!(item)

      deleted =
        Repo.update!(
          Changeset.change(item, deleted_at: DateTime.utc_now(), revision: next_revision!(actor))
        )

      audit!("human.vault.item.deleted", actor, %{item_id: item.id, revision: deleted.revision})
      deleted
    end)
  end

  def item_history(actor, id) do
    command(actor, fn ->
      item = owned!(Item, actor, id)
      Repo.all(from(v in Version, where: v.item_id == ^item.id, order_by: [desc: v.revision]))
    end)
  end

  def create_folder(actor, attrs) do
    command(actor, fn ->
      name = value(attrs, :name)
      unless Envelope.valid?(name), do: Repo.rollback(:invalid_ciphertext)

      folder =
        Repo.insert!(%Folder{user_id: actor.user_id, name: name, revision: next_revision!(actor)})

      audit!("human.vault.folder.created", actor, %{folder_id: folder.id})
      folder
    end)
  end

  def update_folder(actor, id, attrs) do
    command(actor, fn ->
      folder = owned!(Folder, actor, id)
      name = value(attrs, :name)
      unless Envelope.valid?(name), do: Repo.rollback(:invalid_ciphertext)

      updated =
        Repo.update!(Changeset.change(folder, name: name, revision: next_revision!(actor)))

      audit!("human.vault.folder.updated", actor, %{folder_id: folder.id})
      updated
    end)
  end

  def delete_folder(actor, id) do
    command(actor, fn ->
      folder = owned!(Folder, actor, id)

      Repo.all(
        from(i in Item,
          where: i.user_id == ^actor.user_id and i.folder_id == ^folder.id,
          lock: "FOR UPDATE"
        )
      )
      |> Enum.each(fn item ->
        retain_version!(item)
        Repo.update!(Changeset.change(item, folder_id: nil, revision: next_revision!(actor)))
      end)

      deleted =
        Repo.update!(
          Changeset.change(folder,
            deleted_at: DateTime.utc_now(),
            revision: next_revision!(actor)
          )
        )

      audit!("human.vault.folder.deleted", actor, %{folder_id: folder.id})
      deleted
    end)
  end

  def sync(actor, cursor \\ 0, opts \\ []) do
    limit = Keyword.get(opts, :limit, 1000)

    if is_integer(cursor) and cursor >= 0 and is_integer(limit) and limit in 1..1000 do
      command(actor, fn -> sync_page(actor, cursor, limit) end)
    else
      {:error, :invalid_input}
    end
  end

  defp sync_page(actor, cursor, limit) do
    head = lock_head!(actor)
    if cursor > head.revision, do: Repo.rollback(:invalid_input)

    items =
      Repo.all(
        from(i in Item,
          where: i.user_id == ^actor.user_id and i.revision > ^cursor,
          order_by: [asc: i.revision],
          limit: ^(limit + 1)
        )
      )

    folders =
      Repo.all(
        from(f in Folder,
          where: f.user_id == ^actor.user_id and f.revision > ^cursor,
          order_by: [asc: f.revision],
          limit: ^(limit + 1)
        )
      )

    page = Enum.sort_by(items ++ folders, & &1.revision) |> Enum.take(limit)

    next =
      if length(items) + length(folders) > limit,
        do: List.last(page).revision,
        else: head.revision

    %{
      items: Enum.filter(page, &match?(%Item{}, &1)),
      folders: Enum.filter(page, &match?(%Folder{}, &1)),
      cursor: next
    }
  end

  def export(actor, %{confirm: true}) do
    command(actor, fn ->
      items =
        Repo.all(from(i in Item, where: i.user_id == ^actor.user_id and is_nil(i.deleted_at)))

      audit!("human.vault.exported", actor, %{item_count: length(items)})
      %{format: "secrethub-encrypted-v1", items: Enum.map(items, &dto/1)}
    end)
  end

  def export(_, _), do: {:error, :confirmation_required}

  def snapshot(actor) do
    command(actor, fn ->
      %{
        items:
          Repo.all(
            from(i in Item, where: i.user_id == ^actor.user_id, order_by: [asc: i.revision])
          ),
        folders:
          Repo.all(
            from(f in Folder, where: f.user_id == ^actor.user_id, order_by: [asc: f.revision])
          ),
        revision: lock_head!(actor).revision
      }
    end)
  end

  def dto(%Item{} = item),
    do:
      Map.take(item, [
        :id,
        :type,
        :ciphertext,
        :folder_id,
        :favorite,
        :revision,
        :deleted_at,
        :inserted_at,
        :updated_at
      ])

  def dto(%Folder{} = folder),
    do: Map.take(folder, [:id, :name, :revision, :deleted_at, :inserted_at, :updated_at])

  @doc false
  def deleted_item_ids_query, do: from(i in Item, where: not is_nil(i.deleted_at), select: i.id)

  defp command(actor, fun) do
    Repo.transaction(fn ->
      case Accounts.authorize_actor(actor) do
        {:ok, _} ->
          lock_head!(actor)
          fun.()

        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
  end

  defp lock_head!(actor) do
    Repo.insert!(%Head{user_id: actor.user_id}, on_conflict: :nothing)
    Repo.one!(from(h in Head, where: h.user_id == ^actor.user_id, lock: "FOR UPDATE"))
  end

  defp next_revision!(actor) do
    head = lock_head!(actor)
    Repo.update!(Changeset.change(head, revision: head.revision + 1)).revision
  end

  defp owned!(schema, actor, id) do
    with {:ok, id} <- Ecto.UUID.cast(id),
         record when not is_nil(record) <-
           Repo.one(
             from(r in schema,
               where: r.id == ^id and r.user_id == ^actor.user_id and is_nil(r.deleted_at),
               lock: "FOR UPDATE"
             )
           ) do
      record
    else
      _ -> Repo.rollback(:not_found)
    end
  end

  defp folder!(_actor, nil), do: nil
  defp folder!(actor, id), do: owned!(Folder, actor, id).id

  defp retain_version!(item) do
    Repo.insert!(%Version{item_id: item.id, revision: item.revision, ciphertext: item.ciphertext})
    retained = Application.get_env(:secrethub_human, :item_history_limit, 20)

    old_ids =
      Repo.all(
        from(v in Version,
          where: v.item_id == ^item.id,
          order_by: [desc: v.revision],
          offset: ^retained,
          select: v.id
        )
      )

    Repo.delete_all(from(v in Version, where: v.id in ^old_ids))
  end

  defp audit!(event, actor, data) do
    case Audit.record(event, actor, data) do
      {:ok, _} -> :ok
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp value(attrs, key, default \\ nil),
    do: Map.get(attrs, key, Map.get(attrs, Atom.to_string(key), default))
end
