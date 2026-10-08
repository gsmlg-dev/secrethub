defmodule SecretHub.Human.Attachments do
  @moduledoc "Independently encrypted attachments with ownership checks and transactional quota reservations."
  import Ecto.Query
  alias Ecto.Changeset
  alias SecretHub.Human.Accounts
  alias SecretHub.Human.Attachments.Attachment
  alias SecretHub.Human.Attachments.Cleanup
  alias SecretHub.Human.Attachments.FileStorage
  alias SecretHub.Human.Attachments.Usage
  alias SecretHub.Human.Audit
  alias SecretHub.Human.Repo
  alias SecretHub.Human.Vault
  alias SecretHub.Human.Vault.Envelope

  def upload(actor, item_id, attrs, opts \\ []) do
    opts = options(opts)
    id = Ecto.UUID.generate()
    content = get(attrs, :ciphertext)

    result =
      Repo.transaction(fn ->
        check!(Accounts.authorize_actor(actor))
        check!(Vault.get_item(actor, item_id))
        unless is_binary(content), do: Repo.rollback(:invalid_ciphertext)
        if byte_size(content) > opts[:max_bytes], do: Repo.rollback(:attachment_too_large)

        unless Envelope.valid_blob?(content, opts[:max_bytes]) and
                 Envelope.valid?(get(attrs, :filename)) and
                 Envelope.valid?(get(attrs, :encrypted_key)),
               do: Repo.rollback(:invalid_ciphertext)

        Repo.insert!(%Usage{user_id: actor.user_id}, on_conflict: :nothing)

        usage =
          Repo.one!(from(u in Usage, where: u.user_id == ^actor.user_id, lock: "FOR UPDATE"))

        if usage.bytes + byte_size(content) > opts[:quota_bytes],
          do: Repo.rollback(:quota_exceeded)

        check!(opts[:storage].put(id, content, opts))
        Repo.update!(Changeset.change(usage, bytes: usage.bytes + byte_size(content)))

        row =
          Repo.insert!(%Attachment{
            id: id,
            user_id: actor.user_id,
            item_id: item_id,
            filename: get(attrs, :filename),
            encrypted_key: get(attrs, :encrypted_key),
            byte_size: byte_size(content)
          })

        check!(
          Audit.record("human.attachment.created", actor, %{
            attachment_id: id,
            item_id: item_id,
            byte_size: byte_size(content)
          })
        )

        dto(row)
      end)

    if match?({:error, _}, result), do: opts[:storage].delete(id, opts)
    result
  end

  def list(actor, item_id) do
    with {:ok, _} <- Vault.get_item(actor, item_id),
         do:
           {:ok,
            Repo.all(
              from(a in Attachment,
                where:
                  a.user_id == ^actor.user_id and a.item_id == ^item_id and is_nil(a.deleted_at)
              )
            )
            |> Enum.map(&dto/1)}
  end

  def download(actor, id, opts \\ []) do
    Repo.transaction(fn ->
      row = owned!(actor, id)
      check!(Vault.get_item(actor, row.item_id))
      check!(options(opts)[:storage].get(row.id, options(opts)))
    end)
  end

  def delete(actor, id, opts \\ []) do
    result =
      Repo.transaction(fn ->
        row = owned!(actor, id)
        # Deleted items still permit their owner to remove stored attachment data.
        Repo.update!(Changeset.change(row, deleted_at: DateTime.utc_now()))

        usage =
          Repo.one!(from(u in Usage, where: u.user_id == ^actor.user_id, lock: "FOR UPDATE"))

        Repo.update!(Changeset.change(usage, bytes: max(usage.bytes - row.byte_size, 0)))

        check!(
          Audit.record("human.attachment.deleted", actor, %{
            attachment_id: id,
            item_id: row.item_id
          })
        )

        check!(Oban.insert(SecretHub.Human.Oban, Cleanup.new(%{})))
        row.id
      end)

    case result do
      {:ok, id} ->
        opts = options(opts)
        opts[:storage].delete(id, opts)
        :ok

      {:error, _} = error ->
        error
    end
  end

  @doc "Reclaims deleted-item quota, removes tombstoned files and old interrupted writes, and reports retryable storage failures."
  def cleanup(opts \\ []) do
    opts = options(opts)

    with {:ok, reclaimed} <- reclaim_deleted_items(),
         :ok <- delete_files(reclaimed, opts),
         {:ok, files} <- opts[:storage].list(opts) do
      cutoff = System.system_time(:second) - 3600

      Enum.reduce_while(files, :ok, fn file, :ok -> cleanup_file(file, cutoff, opts) end)
    end
  end

  defp cleanup_file({id, modified}, cutoff, opts) do
    row = Repo.get(Attachment, id)

    removable =
      case row do
        %Attachment{deleted_at: nil} -> false
        %Attachment{} -> true
        nil -> modified < cutoff
      end

    result = if removable, do: opts[:storage].delete(id, opts), else: :ok

    case result do
      :ok -> {:cont, :ok}
      {:error, _} = error -> {:halt, error}
    end
  end

  defp reclaim_deleted_items do
    Repo.transaction(fn ->
      rows =
        Repo.all(
          from(a in Attachment,
            where: is_nil(a.deleted_at) and a.item_id in subquery(Vault.deleted_item_ids_query()),
            order_by: [asc: a.user_id, asc: a.id],
            limit: 200,
            lock: "FOR UPDATE SKIP LOCKED"
          )
        )

      Enum.map(rows, fn row ->
        usage = Repo.one!(from(u in Usage, where: u.user_id == ^row.user_id, lock: "FOR UPDATE"))
        Repo.update!(Changeset.change(row, deleted_at: DateTime.utc_now()))
        Repo.update!(Changeset.change(usage, bytes: max(usage.bytes - row.byte_size, 0)))

        check!(
          Audit.record("human.attachment.deleted", %{user_id: row.user_id}, %{
            attachment_id: row.id,
            item_id: row.item_id
          })
        )

        row.id
      end)
    end)
  end

  defp delete_files(ids, opts) do
    Enum.reduce_while(ids, :ok, fn id, :ok ->
      case opts[:storage].delete(id, opts) do
        :ok -> {:cont, :ok}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp owned!(actor, id) do
    check!(Accounts.authorize_actor(actor))

    with {:ok, id} <- Ecto.UUID.cast(id),
         %Attachment{} = row <-
           Repo.one(
             from(a in Attachment,
               where: a.id == ^id and a.user_id == ^actor.user_id and is_nil(a.deleted_at),
               lock: "FOR UPDATE"
             )
           ),
         do: row,
         else: (_ -> Repo.rollback(:not_found))
  end

  defp options(opts),
    do:
      Keyword.merge(
        [
          storage: Application.get_env(:secrethub_human, :attachment_storage, FileStorage),
          directory:
            Application.get_env(
              :secrethub_human,
              :attachment_directory,
              "/tmp/secrethub-human-attachments-dev"
            ),
          max_bytes: Application.get_env(:secrethub_human, :attachment_max_bytes, 10_485_760),
          quota_bytes: Application.get_env(:secrethub_human, :attachment_quota_bytes, 104_857_600)
        ],
        opts
      )

  defp get(attrs, key), do: Map.get(attrs, key, Map.get(attrs, Atom.to_string(key)))
  defp check!({:ok, value}), do: value
  defp check!(:ok), do: :ok
  defp check!({:error, reason}), do: Repo.rollback(reason)

  defp dto(row),
    do: Map.take(row, [:id, :item_id, :filename, :encrypted_key, :byte_size, :inserted_at])
end
