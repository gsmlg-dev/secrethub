defmodule SecretHub.Agent.SSH.Helper do
  @moduledoc "Public-only OpenSSH helpers, runnable before configuration and application startup."
  alias SecretHub.Agent.SSH.{Identity, Lookup, SocketPath}
  @default_socket "/run/secrethub-ssh/lookup.sock"
  @spec main([String.t()]) :: no_return()
  def main(args), do: System.halt(run(args))
  def run([command, "--socket", path | args]), do: execute(command, args, path)
  def run([command | args]), do: execute(command, args, @default_socket)
  def run(_), do: 2

  defp execute(command, args, path) do
    with {:ok, operation, payload} <- arguments(command, args),
         {:ok, lines} <- lookup(path, payload),
         {:ok, lines} <- Lookup.validate_lines(operation, lines) do
      Enum.each(lines, &IO.puts/1)
      0
    else
      _ ->
        IO.puts(:stderr, "SSH lookup unavailable")
        1
    end
  end

  defp arguments("fetch-ssh-keys", [user, key]),
    do:
      {:ok, "authorized_keys",
       %{"operation" => "authorized_keys", "username" => user, "key" => key}}

  defp arguments("fetch-ssh-host-keys", [reason, host, port]) do
    case Integer.parse(port) do
      {number, ""} ->
        {:ok, "known_hosts",
         %{"operation" => "known_hosts", "reason" => reason, "host" => host, "port" => number}}

      _ ->
        {:error, :usage}
    end
  end

  defp arguments(_, _), do: {:error, :usage}

  def lookup(path, payload) do
    with {:ok, expected} <- SocketPath.lookup_identity(path),
         {:ok, socket} <-
           :gen_tcp.connect(
             {:local, path},
             0,
             [
               :binary,
               active: false,
               packet: 4,
               packet_size: 1_048_576,
               send_timeout: 2000,
               send_timeout_close: true
             ],
             2000
           ) do
      try do
        with {:ok, uid} <- Identity.peer_uid(socket),
             true <- uid == expected.uid,
             :ok <- SocketPath.verify_lookup(path, expected),
             :ok <- :gen_tcp.send(socket, Jason.encode!(payload)),
             {:ok, response} <- :gen_tcp.recv(socket, 0, 5000),
             {:ok, %{"ok" => true, "lines" => lines}} <- Jason.decode(response),
             :ok <- SocketPath.verify_lookup(path, expected) do
          {:ok, lines}
        else
          _ -> {:error, :lookup_unavailable}
        end
      after
        :gen_tcp.close(socket)
      end
    end
    |> case do
      {:ok, _} = result -> result
      _ -> {:error, :lookup_unavailable}
    end
  end
end
