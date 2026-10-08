defmodule SecretHub.Human.Attachments.FileStorage do
  @moduledoc false
  @behaviour SecretHub.Human.Attachments.Storage
  def put(id, ciphertext, opts) do
    root = Keyword.fetch!(opts, :directory)

    with :ok <- File.mkdir_p(root),
         :ok <- File.chmod(root, 0o700),
         :ok <- File.write(path(id, opts), ciphertext, [:binary, :exclusive]),
         :ok <- File.chmod(path(id, opts), 0o600),
         do: :ok,
         else: (_ -> {:error, :storage_unavailable})
  end

  def get(id, opts) do
    with {:ok, %{type: :regular, size: size}} <- File.lstat(path(id, opts)),
         true <- size <= Keyword.fetch!(opts, :max_bytes),
         {:ok, data} <- File.read(path(id, opts)),
         do: {:ok, data},
         else: (_ -> {:error, :storage_unavailable})
  end

  def delete(id, opts) do
    case File.rm(path(id, opts)) do
      :ok -> :ok
      {:error, :enoent} -> :ok
      _ -> {:error, :storage_unavailable}
    end
  end

  def list(opts) do
    root = Keyword.fetch!(opts, :directory)

    case File.ls(root) do
      {:ok, ids} ->
        {:ok,
         Enum.flat_map(ids, fn id ->
           with {:ok, _} <- Ecto.UUID.cast(id),
                {:ok, %{type: :regular, mtime: time}} <-
                  File.lstat(Path.join(root, id), time: :posix),
                do: [{id, time}],
                else: (_ -> [])
         end)}

      {:error, :enoent} ->
        {:ok, []}

      _ ->
        {:error, :storage_unavailable}
    end
  end

  defp path(id, opts) do
    case Ecto.UUID.cast(id) do
      {:ok, ^id} -> Path.join(Keyword.fetch!(opts, :directory), id)
      _ -> raise ArgumentError, "invalid attachment storage identifier"
    end
  end
end
