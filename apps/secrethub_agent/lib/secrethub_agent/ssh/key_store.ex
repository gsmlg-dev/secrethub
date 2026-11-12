defmodule SecretHub.Agent.SSH.KeyStore do
  @moduledoc """
  Device-local SSH identity keys under <state_dir>/ssh-identities/<uid>/<generation>.key.
  Owner-only files; private keys never leave this directory.
  """
  alias SecretHub.Shared.SSH.Key

  def root do
    state_dir =
      System.get_env(
        "SECRET_HUB_AGENT_STATE_DIR",
        Application.get_env(:secrethub_agent, :state_dir)
      ) || Path.expand("~/.local/state/secrethub/agent")

    Path.join(state_dir, "ssh-identities")
  end

  def uids(root \\ root()) do
    case File.ls(root) do
      {:ok, names} ->
        names
        |> Enum.flat_map(&integer/1)
        |> Enum.filter(&File.dir?(Path.join(root, to_string(&1))))
        |> Enum.sort()

      _ ->
        []
    end
  end

  def generations(uid, root \\ root()) do
    case File.ls(dir(uid, root)) do
      {:ok, names} ->
        names
        |> Enum.flat_map(fn name ->
          case String.split(name, ".") do
            [number, "key"] -> integer(number)
            _ -> []
          end
        end)
        |> Enum.filter(&match?({:ok, _}, load(uid, &1, root)))
        |> Enum.sort()

      _ ->
        []
    end
  end

  def load(uid, generation, root \\ root()) do
    with {:ok, %{type: :regular, mode: mode}} <- File.lstat(path(uid, generation, root)),
         0o600 <- Bitwise.band(mode, 0o777),
         {:ok, pem} <- File.read(path(uid, generation, root)),
         {:ok, imported} <- Key.import_private(pem) do
      {:ok, %{generation: generation, private_pem: imported.private_pem, public: imported.public}}
    else
      _ -> {:error, :not_found}
    end
  end

  def find_by_blob(uid, blob, root \\ root()) do
    uid
    |> generations(root)
    |> Enum.find_value({:error, :not_found}, fn generation ->
      case load(uid, generation, root) do
        {:ok, %{public: %{blob: ^blob}} = key} -> {:ok, key}
        _ -> nil
      end
    end)
  end

  def create(uid, generation, root \\ root())
      when is_integer(uid) and uid >= 0 and is_integer(generation) and generation >= 1 do
    directory = dir(uid, root)
    :ok = File.mkdir_p(directory)
    :ok = File.chmod(directory, 0o700)
    {:ok, key} = Key.generate("ed25519")
    target = path(uid, generation, root)

    temporary =
      target <> ".tmp." <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

    result =
      with {:ok, fd} <- :file.open(to_charlist(temporary), [:write, :binary, :raw, :exclusive]) do
        try do
          with :ok <- File.chmod(temporary, 0o600),
               :ok <- :file.write(fd, key.private_pem),
               do: :file.sync(fd)
        after
          :file.close(fd)
        end
      end

    with :ok <- result,
         :ok <- discard_invalid(uid, generation, root),
         :ok <- publish(temporary, target) do
      {:ok, %{generation: generation, private_pem: key.private_pem, public: key.public}}
    else
      error ->
        File.rm(temporary)
        error
    end
  end

  # A corrupt, empty or unsafe leftover must not wedge the uid forever.
  defp discard_invalid(uid, generation, root) do
    case {File.lstat(path(uid, generation, root)), load(uid, generation, root)} do
      {{:ok, _}, {:error, _}} -> File.rm(path(uid, generation, root))
      _ -> :ok
    end
  end

  # link/unlink refuses to replace an existing target, unlike rename.
  defp publish(temporary, target) do
    case :file.make_link(to_charlist(temporary), to_charlist(target)) do
      :ok ->
        File.rm(temporary)
        :ok

      {:error, :eexist} ->
        {:error, :exists}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def prune(uid, keep, root \\ root()) do
    for generation <- generations(uid, root), generation not in keep do
      File.rm(path(uid, generation, root))
    end

    :ok
  end

  defp dir(uid, root), do: Path.join(root, Integer.to_string(uid))
  defp path(uid, generation, root), do: Path.join(dir(uid, root), "#{generation}.key")

  defp integer(text) do
    case Integer.parse(text) do
      {number, ""} when number >= 0 -> [number]
      _ -> []
    end
  end
end
