defmodule SecretHub.Agent.SSH.Identity do
  @moduledoc "Linux kernel peer credentials and unambiguous NSS account bindings."

  def peer_uid(socket) do
    case :inet.getopts(socket, [{:raw, 1, 17, 12}]) do
      {:ok, [{:raw, 1, 17, <<_pid::native-32, uid::native-unsigned-32, _gid::native-32>>}]} ->
        {:ok, uid}

      _ ->
        {:error, :peer_identity_unavailable}
    end
  end

  def current do
    with {:ok, output} <- command("id", ["-u"]),
         {uid, ""} <- Integer.parse(String.trim(output)),
         do: account(uid)
  end

  def account(uid, timeout \\ 2000) do
    deadline = System.monotonic_time(:millisecond) + timeout

    with {:ok, entries} <- command("getent", ["passwd"], min(2000, remaining(deadline))),
         {:ok, identity} <- resolve(uid, entries),
         {:ok, named} <-
           command("getent", ["passwd", identity.username], min(2000, remaining(deadline))),
         {:ok, ^identity} <- resolve(uid, named),
         do: {:ok, identity}
  end

  def resolve(uid, entries) when is_integer(uid) and uid >= 0 and is_binary(entries) do
    accounts =
      entries
      |> String.split("\n", trim: true)
      |> Enum.flat_map(&matching_account(&1, uid))

    case accounts do
      [%{username: name} = account] ->
        if username?(name), do: {:ok, account}, else: {:error, :invalid_account}

      _ ->
        {:error, :ambiguous_or_missing_account}
    end
  end

  defp matching_account(line, uid) do
    with [name, _, number, _, _, _, _] <- String.split(line, ":"),
         {^uid, ""} <- Integer.parse(number) do
      [%{uid: uid, username: name}]
    else
      _ -> []
    end
  end

  def username?(name) when is_binary(name),
    do: Regex.match?(~r/\A[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?\z/, name)

  def username?(_), do: false

  # Port arguments bypass shell parsing. Bound output and total execution time,
  # including remote NSS modules; never include account data in errors or logs.
  def command(executable, args, timeout \\ 2000)

  def command(_executable, _args, timeout) when timeout <= 0,
    do: {:error, :account_service_unavailable}

  def command(executable, args, timeout) do
    case System.find_executable(executable) do
      nil ->
        {:error, :account_service_unavailable}

      path ->
        port =
          Port.open({:spawn_executable, path}, [
            :binary,
            :exit_status,
            :use_stdio,
            :stderr_to_stdout,
            args: args
          ])

        collect(port, [], 0, System.monotonic_time(:millisecond) + min(timeout, 2000))
    end
  end

  defp collect(port, chunks, size, deadline) do
    remaining = max(0, deadline - System.monotonic_time(:millisecond))

    receive do
      {^port, {:data, data}} when size + byte_size(data) <= 1_048_576 ->
        collect(port, [data | chunks], size + byte_size(data), deadline)

      {^port, {:exit_status, 0}} ->
        {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}

      {^port, _} ->
        close(port)
        {:error, :account_service_unavailable}
    after
      remaining ->
        close(port)
        {:error, :account_service_unavailable}
    end
  end

  defp remaining(deadline), do: max(0, deadline - System.monotonic_time(:millisecond))

  defp close(port) do
    Port.close(port)
  rescue
    ArgumentError -> :ok
  end
end
