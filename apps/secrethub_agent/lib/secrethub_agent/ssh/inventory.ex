defmodule SecretHub.Agent.SSH.Inventory do
  @moduledoc "Bounded advisory public host keys and local OS prerequisites; never grants access."
  import Bitwise
  alias SecretHub.Agent.Connection
  alias SecretHub.Agent.SSH.Identity
  alias SecretHub.Shared.SSH.Key

  def report(connection) do
    settings = Application.get_all_env(:secrethub_agent)

    with {:ok, passwd} <- Identity.command("getent", ["passwd"]),
         {:ok, groups} <- Identity.command("getent", ["group"]) do
      available = %{
        lookup:
          available?(
            settings[:ssh_lookup_socket_path],
            settings[:ssh_lookup_socket_group],
            groups
          ),
        signing:
          available?(
            settings[:ssh_signing_socket_path],
            settings[:ssh_signing_socket_group],
            groups
          )
      }

      payload = %{
        "users" => users(passwd, groups, settings, available),
        "host_keys" => host_keys(settings)
      }

      Connection.ssh_request(connection, "inventory", payload, 5000)
    end
  end

  def users(passwd, groups, settings, available) do
    accounts = passwd |> String.split("\n", trim: true) |> Enum.flat_map(&account/1)
    uid_counts = Enum.frequencies_by(accounts, & &1.uid)
    name_counts = Enum.frequencies_by(accounts, & &1.username)
    groups = groups |> String.split("\n", trim: true) |> Enum.flat_map(&group/1)

    accounts
    |> Enum.take(1024)
    |> Enum.map(fn user ->
      %{
        "username" => user.username,
        "uid" => user.uid,
        "unambiguous" => uid_counts[user.uid] == 1 and name_counts[user.username] == 1,
        "lookup_access" =>
          available.lookup and settings[:ssh_lookup_enabled] == true and
            member?(user, groups, settings[:ssh_lookup_socket_group]),
        "signing_access" =>
          available.signing and settings[:ssh_signing_enabled] == true and
            member?(user, groups, settings[:ssh_signing_socket_group])
      }
    end)
  end

  defp account(line) do
    with [name, _, uid, gid, _, _, _] <- String.split(line, ":"),
         true <- Identity.username?(name),
         {uid, ""} when uid >= 0 <- Integer.parse(uid),
         {gid, ""} when gid >= 0 <- Integer.parse(gid) do
      [%{username: name, uid: uid, gid: gid}]
    else
      _ -> []
    end
  end

  defp group(line) do
    with [name, _, gid, members] <- String.split(line, ":"),
         {gid, ""} when gid >= 0 <- Integer.parse(gid) do
      [%{name: name, gid: gid, members: String.split(members, ",", trim: true)}]
    else
      _ -> []
    end
  end

  defp member?(user, groups, name) do
    case Enum.filter(groups, &(&1.name == name)) do
      [group] -> user.uid == 0 or user.gid == group.gid or user.username in group.members
      _ -> false
    end
  end

  defp available?(path, group_name, groups) when is_binary(path) do
    with [expected] <-
           groups
           |> String.split("\n", trim: true)
           |> Enum.flat_map(&group/1)
           |> Enum.filter(&(&1.name == group_name)),
         {:ok, socket} <- File.lstat(path),
         true <- socket.gid == expected.gid,
         true <- socket.type == :other and band(socket.mode, 0o777) == 0o660,
         {:ok, directory} <- File.stat(Path.dirname(path)),
         true <- directory.type == :directory and directory.gid == socket.gid,
         true <- band(directory.mode, 0o070) == 0o050 do
      true
    else
      _ -> false
    end
  end

  defp available?(_, _, _), do: false

  defp host_keys(settings) do
    configured =
      case settings[:host_key_path] do
        path when is_binary(path) -> [path <> ".pub"]
        _ -> []
      end

    (configured ++
       [
         "/etc/ssh/ssh_host_ed25519_key.pub",
         "/etc/ssh/ssh_host_rsa_key.pub",
         "/etc/ssh/ssh_host_ecdsa_key.pub"
       ])
    |> Enum.uniq()
    |> Enum.flat_map(fn path ->
      with {:ok, %{type: :regular, size: size}} when size <= 16_384 <- File.stat(path),
           {:ok, contents} <- File.read(path),
           {:ok, public} <- Key.decode_public(contents) do
        [public.public_line]
      else
        _ -> []
      end
    end)
    |> Enum.uniq()
  end
end
