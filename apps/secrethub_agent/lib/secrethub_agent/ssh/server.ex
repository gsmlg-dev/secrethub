defmodule SecretHub.Agent.SSH.Server do
  @moduledoc "Separate bounded SSH signing and public lookup Unix listeners."
  use GenServer
  alias SecretHub.Agent.Connection
  alias SecretHub.Agent.SSH.{Identity, KeyStore, Lookup, Protocol, Reconciler, SocketPath}
  alias SecretHub.Shared.SSH.Key

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  def child_spec(opts),
    do: %{id: {__MODULE__, Keyword.fetch!(opts, :kind)}, start: {__MODULE__, :start_link, [opts]}}

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    path = Keyword.fetch!(opts, :path)
    group = Keyword.get(opts, :group)

    with {:ok, _uid} <- SocketPath.prepare(path),
         {:ok, listener, socket_identity} <- listen(path, group) do
      config = %{
        kind: Keyword.fetch!(opts, :kind),
        timeout: Keyword.get(opts, :timeout, 5000),
        request: Keyword.get(opts, :request),
        key_root: Keyword.get(opts, :key_root)
      }

      task_supervisor = Keyword.fetch!(opts, :task_supervisor)

      Enum.each(1..8, fn _ -> start_acceptor(task_supervisor, listener, config) end)
      {:ok, %{listener: listener, path: path, socket_identity: socket_identity}}
    else
      _ -> {:stop, :ssh_listener_unavailable}
    end
  end

  defp listen(path, group) do
    with {:ok, socket} <-
           :gen_tcp.listen(0, [
             :binary,
             active: false,
             packet: :raw,
             ifaddr: {:local, path},
             backlog: 32,
             send_timeout: 5000,
             send_timeout_close: true
           ]) do
      {:ok, stat} = File.lstat(path)
      identity = SocketPath.identity(stat)

      case permissions(path, group) do
        :ok ->
          {:ok, socket, identity}

        _ ->
          :gen_tcp.close(socket)
          SocketPath.cleanup(path, identity)
          {:error, :socket_permissions_unavailable}
      end
    end
  end

  defp start_acceptor(tasks, listener, config) do
    {:ok, _} = Task.Supervisor.start_child(tasks, fn -> accept(listener, config) end)
  end

  defp permissions(path, nil), do: File.chmod(path, 0o660)

  defp permissions(path, group) do
    with {:ok, output} <- Identity.command("getent", ["group", group]),
         [^group, _, gid, _] <- String.split(String.trim(output), ":"),
         {gid, ""} <- Integer.parse(gid),
         :ok <- File.chgrp(path, gid),
         do: File.chmod(path, 0o660)
  end

  @impl true
  def terminate(_, state) do
    :gen_tcp.close(state.listener)
    SocketPath.cleanup(state.path, state.socket_identity)
  end

  @impl true
  def format_status(status),
    do: status |> Map.put(:state, :redacted) |> Map.put(:message, :redacted)

  defp accept(listener, config) do
    case :gen_tcp.accept(listener) do
      {:ok, socket} ->
        try do
          with {:ok, uid} <- Identity.peer_uid(socket), do: serve(socket, uid, config)
        rescue
          _ -> :ok
        catch
          _, _ -> :ok
        after
          :gen_tcp.close(socket)
        end

        accept(listener, config)

      {:error, _} ->
        :ok
    end
  end

  defp receive_frame(socket, deadline) do
    with {:ok, <<length::32>>} when length in 1..1_048_576 <-
           :gen_tcp.recv(socket, 4, remaining(deadline)),
         {:ok, payload} <- :gen_tcp.recv(socket, length, remaining(deadline)) do
      {:ok, payload}
    else
      _ -> {:error, :invalid_frame}
    end
  end

  defp send_frame(socket, payload, deadline) when byte_size(payload) <= 1_048_576 do
    with timeout when timeout > 0 <- remaining(deadline),
         :ok <- :inet.setopts(socket, send_timeout: timeout) do
      :gen_tcp.send(socket, <<byte_size(payload)::32, payload::binary>>)
    else
      _ -> {:error, :timeout}
    end
  end

  defp serve(socket, uid, %{kind: :lookup} = config) do
    deadline = System.monotonic_time(:millisecond) + config.timeout
    request = request(config, deadline)

    response =
      with {:ok, payload} <- receive_frame(socket, deadline),
           {:ok, input} <- Jason.decode(payload),
           {:ok, lines} <- Lookup.request(input, uid, request, remaining(deadline)) do
        %{"ok" => true, "lines" => lines}
      else
        _ -> %{"ok" => false, "error" => "lookup_unavailable"}
      end

    send_frame(socket, Jason.encode!(response), deadline)
  end

  defp serve(socket, uid, %{kind: :signing} = config) do
    deadline = System.monotonic_time(:millisecond) + config.timeout

    case receive_frame(socket, deadline) do
      {:ok, payload} ->
        reply = signing(payload, uid, request(config, deadline), deadline, config.key_root)
        :erlang.garbage_collect()
        if send_frame(socket, reply, deadline) == :ok, do: serve(socket, uid, config)

      _ ->
        :ok
    end
  end

  defp signing(payload, uid, request, deadline, key_root) do
    with {:ok, identity} <- Identity.account(uid, remaining(deadline)),
         {:ok, operation} <- Protocol.decode(payload),
         {:ok, result} <-
           sign_operation(operation, identity, request, key_root || KeyStore.root()) do
      result
    else
      _ -> Protocol.failure()
    end
  end

  defp sign_operation(:identities, identity, request, key_root) do
    with :ok <- Reconciler.ensure_enrolled(identity, request, key_root),
         {:ok, reply} <- request.("identities", identity_payload(identity)),
         identities when is_list(identities) and length(identities) <= 128 <-
           Lookup.value(reply, "identities") do
      encode_identities(identities)
    else
      _ -> {:error, :identities_unavailable}
    end
  end

  defp sign_operation({:sign, blob, data, flags}, identity, request, key_root) do
    with {:ok, public} <- Key.decode_public(Base.encode64(blob)),
         {:ok, local} <- KeyStore.find_by_blob(identity.uid, blob, key_root),
         {:ok, reply} <-
           request.(
             "authorize_sign",
             Map.put(identity_payload(identity), "public_key", public.encoded)
           ),
         true <- Lookup.value(reply, "allowed") == true,
         {:ok, returned} <- Key.decode_public(Lookup.value(reply, "public_key")),
         true <- returned.blob == blob,
         {:ok, signature} <- Key.sign(local.private_pem, data, flags) do
      {:ok, Protocol.signature(signature)}
    else
      _ -> {:error, :signing_unavailable}
    end
  end

  defp encode_identities(identities) do
    case Enum.reduce_while(identities, {:ok, []}, &decode_identity/2) do
      {:ok, keys} -> {:ok, Protocol.identities(Enum.reverse(keys))}
      error -> error
    end
  end

  defp decode_identity(item, {:ok, keys}) do
    case Key.decode_public(Lookup.value(item, "public_key")) do
      {:ok, %{blob: blob}} -> {:cont, {:ok, [blob | keys]}}
      _ -> {:halt, {:error, :invalid_response}}
    end
  end

  defp identity_payload(identity), do: %{"uid" => identity.uid, "username" => identity.username}

  defp request(config, deadline) do
    fn operation, payload ->
      case remaining(deadline) do
        timeout when timeout > 0 -> runtime_request(config.request, operation, payload, timeout)
        _ -> {:error, :timeout}
      end
    end
  end

  defp runtime_request(nil, operation, payload, timeout),
    do: Connection.ssh_request(Connection, operation, payload, timeout)

  defp runtime_request(callback, operation, payload, _timeout), do: callback.(operation, payload)
  defp remaining(deadline), do: max(0, deadline - System.monotonic_time(:millisecond))
end
