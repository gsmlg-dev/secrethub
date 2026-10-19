defmodule SecretHub.Agent.SSH.SocketPath do
  @moduledoc "Validates controlled Linux socket ancestors and safely reclaims owned stale sockets."
  import Bitwise

  def prepare(path) do
    with {:ok, %{uid: uid}} <- File.stat("/proc/self"),
         :ok <- parent(path, uid),
         :ok <- vacant_or_stale(path, uid) do
      {:ok, uid}
    end
  end

  def identity(stat), do: {stat.inode, stat.major_device, stat.minor_device, stat.uid}

  def cleanup(path, expected) do
    with {:ok, %{uid: uid}} <- File.stat("/proc/self"),
         :ok <- parent(path, uid),
         {:ok, stat} <- File.lstat(path),
         true <- stat.uid == uid and identity(stat) == expected do
      File.rm(path)
    else
      _ -> {:error, :socket_path_changed}
    end
  end

  # A public helper derives its expected service UID only from a delegation below
  # non-writable root-owned directories. Sticky /tmp cannot establish that trust.
  def lookup_identity(path) do
    with :ok <- valid_path(path),
         {:ok, uid, parents} <- ancestors(path, 0, false),
         {:ok, stat} <- File.lstat(path),
         true <- socket?(stat) and stat.uid == uid do
      {:ok, %{uid: uid, socket: identity(stat), parents: parents}}
    else
      _ -> {:error, :untrusted_lookup_socket}
    end
  end

  def verify_lookup(path, expected) do
    case lookup_identity(path) do
      {:ok, ^expected} -> :ok
      _ -> {:error, :lookup_socket_changed}
    end
  end

  defp parent(path, uid) do
    with :ok <- valid_path(path),
         {:ok, _, _} <- ancestors(path, uid, true) do
      :ok
    else
      _ -> {:error, :uncontrolled_socket_parent}
    end
  end

  defp valid_path(path) when is_binary(path) and byte_size(path) in 2..107 do
    if String.valid?(path) and String.starts_with?(path, "/") and
         not String.contains?(path, <<0>>) and Path.expand(path) == path,
       do: :ok,
       else: {:error, :invalid_socket_path}
  end

  defp valid_path(_), do: {:error, :invalid_socket_path}

  defp ancestors(path, uid, listener?) do
    path
    |> Path.dirname()
    |> Path.split()
    |> Enum.scan(&Path.join(&2, &1))
    |> Enum.reduce_while({:ok, uid, []}, &ancestor(&1, &2, listener?))
  end

  defp ancestor(path, {:ok, owner, snapshots}, listener?) do
    with {:ok, stat} <- File.lstat(path),
         true <- stat.type == :directory,
         true <- safe_mode?(stat, listener?),
         true <- stat.uid in [0, owner] or (not listener? and owner == 0) do
      delegated = if owner == 0, do: stat.uid, else: owner
      snapshot = {path, identity(stat), stat.mode}
      {:cont, {:ok, delegated, [snapshot | snapshots]}}
    else
      _ -> {:halt, {:error, :uncontrolled_socket_parent}}
    end
  end

  defp safe_mode?(stat, listener?) do
    band(stat.mode, 0o022) == 0 or
      (listener? and stat.uid == 0 and band(stat.mode, 0o1000) != 0)
  end

  defp socket?(stat), do: band(stat.mode, 0o170000) == 0o140000

  defp vacant_or_stale(path, uid) do
    case File.lstat(path) do
      {:error, :enoent} -> :ok
      {:ok, stat} -> reclaim(path, uid, stat)
      _ -> {:error, :socket_path_unavailable}
    end
  end

  defp reclaim(path, uid, stat) do
    with true <- stat.uid == uid and socket?(stat),
         {:error, :econnrefused} <- probe(path),
         :ok <- parent(path, uid),
         {:ok, current} <- File.lstat(path),
         true <- identity(current) == identity(stat) do
      File.rm(path)
    else
      _ -> {:error, :socket_path_exists}
    end
  end

  defp probe(path) do
    case :gen_tcp.connect({:local, path}, 0, [:binary, active: false], 100) do
      {:ok, socket} ->
        :gen_tcp.close(socket)
        {:error, :live_socket}

      error ->
        error
    end
  end
end
