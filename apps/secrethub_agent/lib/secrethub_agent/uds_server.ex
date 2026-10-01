defmodule SecretHub.Agent.UDSServer do
  @moduledoc "Owner-only newline UDS with connection-bound app private-key proof and Core-authorized reads."
  use GenServer
  alias SecretHub.Agent.{Cache, CertVerifier, Connection, IdentityStore, UDSAuth}

  @frame_limit 65_536

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  def get_stats, do: GenServer.call(__MODULE__, :get_stats)
  def shutdown, do: GenServer.call(__MODULE__, :shutdown)

  def configure_runtime(agent_id, floor),
    do: GenServer.call(__MODULE__, {:configure_runtime, agent_id, floor})

  @impl true
  def init(opts) do
    path = Keyword.get(opts, :socket_path, "/var/run/secrethub/agent.sock")
    File.mkdir_p!(Path.dirname(path))
    File.rm(path)

    with {:ok, listener} <-
           :gen_tcp.listen(0, [
             :binary,
             ifaddr: {:local, to_charlist(path)},
             packet: :line,
             packet_size: @frame_limit,
             active: false,
             reuseaddr: true
           ]),
         :ok <- File.chmod(path, 0o600) do
      {agent_id, floor} = persisted_runtime(Keyword.get(opts, :state_dir))
      send(self(), :accept)

      {:ok,
       %{
         socket_path: path,
         listener: listener,
         agent_id: agent_id,
         minimum_uds_auth_version: floor,
         connections: %{},
         max_connections: Keyword.get(opts, :max_connections, 100),
         connection_timeout: Keyword.get(opts, :connection_timeout, 30_000),
         request_timeout: Keyword.get(opts, :request_timeout, 10_000),
         stats: %{
           total_connections: 0,
           active_connections: 0,
           total_requests: 0,
           failed_requests: 0,
           auth_failures: 0,
           auth_successes: 0
         }
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state), do: {:reply, {:ok, state.stats}, state}
  def handle_call(:shutdown, _from, state), do: {:stop, :normal, :ok, state}

  def handle_call({:configure_runtime, agent_id, floor}, _from, state)
      when is_binary(agent_id) and floor in [1, 2] do
    floor = max(floor, state.minimum_uds_auth_version)
    state = %{state | agent_id: agent_id, minimum_uds_auth_version: floor}

    state =
      Enum.reduce(state.connections, state, fn {socket, connection}, acc ->
        if connection.auth_version < floor and connection.auth_state == :authenticated,
          do: close_connection(acc, socket),
          else: acc
      end)

    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:accept, state) do
    next =
      case :gen_tcp.accept(state.listener, 50) do
        {:ok, socket} when map_size(state.connections) < state.max_connections ->
          :ok = :inet.setopts(socket, active: :once, packet: :line, packet_size: @frame_limit)

          timer =
            Process.send_after(
              self(),
              {:authentication_timeout, socket},
              state.connection_timeout
            )

          connection = %{
            connection_id: Ecto.UUID.generate(),
            auth_state: :unauthenticated,
            auth_version: 0,
            principal: nil,
            challenge: nil,
            attempts: 0,
            timer: timer
          }

          state
          |> put_in([:connections, socket], connection)
          |> count(:total_connections)
          |> count(:active_connections)

        {:ok, socket} ->
          :gen_tcp.close(socket)
          state

        {:error, :timeout} ->
          state

        {:error, _} ->
          state
      end

    send(self(), :accept)
    {:noreply, next}
  end

  def handle_info({:tcp, socket, frame}, state) do
    state = handle_frame(socket, frame, state)
    if Map.has_key?(state.connections, socket), do: :inet.setopts(socket, active: :once)
    {:noreply, state}
  end

  def handle_info({:tcp_closed, socket}, state), do: {:noreply, close_connection(state, socket)}

  def handle_info({:tcp_error, socket, _reason}, state),
    do: {:noreply, close_connection(state, socket)}

  def handle_info({:authentication_timeout, socket}, state) do
    case state.connections[socket] do
      %{auth_state: :authenticated} -> {:noreply, state}
      nil -> {:noreply, state}
      _ -> {:noreply, close_connection(state, socket)}
    end
  end

  def handle_info(_, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    :gen_tcp.close(state.listener)
    Enum.each(state.connections, fn {socket, _} -> :gen_tcp.close(socket) end)
    File.rm(state.socket_path)
    :ok
  end

  @impl true
  def format_status(status),
    do: status |> Map.put(:state, :redacted) |> Map.put(:message, :redacted)

  defp persisted_runtime(nil), do: {nil, 1}

  defp persisted_runtime(dir) do
    case IdentityStore.load(dir) do
      {:ok, material} ->
        :ok = CertVerifier.configure_trust(material.ca_chain_pem)
        {material.agent_id, Map.get(material.identity, "minimum_uds_auth_version", 1)}

      _ ->
        {nil, 1}
    end
  end

  defp handle_frame(socket, frame, state) when byte_size(frame) > @frame_limit,
    do: close_connection(state, socket)

  defp handle_frame(socket, frame, state) do
    case Jason.decode(frame) do
      {:ok, %{"request_id" => id, "action" => action, "params" => params}}
      when is_binary(id) and is_binary(action) and is_map(params) ->
        state = count(state, :total_requests)

        case state.connections[socket] do
          nil -> state
          connection -> dispatch(socket, id, action, params, connection, state)
        end

      _ ->
        close_connection(state, socket)
    end
  end

  defp dispatch(
         socket,
         id,
         "authenticate",
         params,
         %{auth_state: :unauthenticated} = connection,
         state
       ) do
    version = params["auth_version"]

    cond do
      version not in [nil, 1, 2] or (version != 2 and state.minimum_uds_auth_version == 2) ->
        fail(state, socket, id, "INCOMPATIBLE_VERSION", true)

      is_nil(state.agent_id) ->
        fail(state, socket, id, "ENROLLMENT_IN_PROGRESS", false)

      true ->
        authenticate(socket, id, params, connection, state, version || 1)
    end
  end

  defp dispatch(
         socket,
         id,
         "authenticate_proof",
         params,
         %{auth_state: :challenge} = connection,
         state
       ) do
    challenge = connection.challenge

    with 2 <- params["auth_version"],
         true <- params["connection_id"] == challenge.connection_id,
         true <- params["challenge_id"] == challenge.challenge_id,
         true <- params["signature_algorithm"] == challenge.signature_algorithm,
         {:ok, signature} <- decode_base64(params["signature"]),
         :ok <- UDSAuth.verify_proof(challenge, signature, challenge.principal.public_key) do
      connection = %{
        connection
        | auth_state: :authenticated,
          auth_version: 2,
          principal: Map.take(challenge.principal, [:app_id, :canonical_fingerprint]),
          challenge: nil
      }

      Process.cancel_timer(connection.timer)

      reply(socket, id, %{
        authenticated: true,
        app_id: connection.principal.app_id,
        auth_version: 2
      })

      state |> put_in([:connections, socket], connection) |> count(:auth_successes)
    else
      _ -> fail(state, socket, id, "PROOF_FAILED", true)
    end
  end

  defp dispatch(socket, id, action, _params, _connection, state)
       when action in ["authenticate", "authenticate_proof"],
       do: fail(state, socket, id, "PROOF_FAILED", true)

  defp dispatch(socket, id, "ping", _params, _connection, state) do
    reply(socket, id, %{message: "pong"})
    state
  end

  defp dispatch(
         socket,
         id,
         "get_secret",
         params,
         %{auth_state: :authenticated} = connection,
         state
       ) do
    case read_secret(params["path"], connection, state.request_timeout) do
      {:ok, data} ->
        reply(socket, id, data)
        state

      {:error, code} ->
        fail(state, socket, id, code, false)
    end
  end

  defp dispatch(socket, id, _action, _params, %{auth_state: :authenticated}, state),
    do: fail(state, socket, id, "UNAVAILABLE", false)

  defp dispatch(socket, id, _action, _params, _connection, state),
    do: fail(state, socket, id, "PROOF_REQUIRED", false)

  defp authenticate(socket, id, params, connection, state, version) do
    with {:ok, pem} <- decode_base64(params["certificate"]),
         {:ok, metadata} <- CertVerifier.verify_app_cert_pem(pem) do
      if version == 2 do
        {:ok, challenge} =
          UDSAuth.new_challenge(state.agent_id, connection.connection_id, metadata)

        reply(socket, id, %{
          auth_version: 2,
          agent_id: challenge.agent_id,
          connection_id: challenge.connection_id,
          challenge_id: challenge.challenge_id,
          challenge: Base.encode64(challenge.nonce),
          certificate_fingerprint: challenge.certificate_fingerprint,
          signature_algorithm: challenge.signature_algorithm,
          expires_at: DateTime.to_iso8601(challenge.expires_at)
        })

        put_in(state, [:connections, socket], %{
          connection
          | auth_state: :challenge,
            challenge: challenge
        })
      else
        principal = Map.take(metadata, [:app_id, :canonical_fingerprint])
        reply(socket, id, %{authenticated: true, app_id: principal.app_id, auth_version: 1})

        state
        |> put_in([:connections, socket], %{
          connection
          | auth_state: :authenticated,
            auth_version: 1,
            principal: principal
        })
        |> count(:auth_successes)
      end
    else
      {:error, "CA_UNAVAILABLE"} -> fail_auth(state, socket, id, "CA_UNAVAILABLE")
      _ -> fail_auth(state, socket, id, "INVALID_CERTIFICATE")
    end
  end

  defp read_secret(path, connection, timeout) when is_binary(path) and path != "" do
    principal = connection.principal
    key = {principal.app_id, principal.canonical_fingerprint, path}
    cached = Cache.get_entry(key)

    revision =
      case cached do
        {:ok, entry} -> entry.revision
        _ -> nil
      end

    claims = %{
      app_id: principal.app_id,
      certificate_fingerprint: principal.canonical_fingerprint,
      local_auth_version: connection.auth_version
    }

    result = Connection.get_static_secret_for_app(Connection, path, claims, revision, timeout)
    read_result(result, cached, key)
  catch
    :exit, _ -> {:error, "UNAVAILABLE"}
  end

  defp read_secret(_, _, _), do: {:error, "FORBIDDEN"}

  defp read_result(result, cached, key) do
    case result do
      {:ok, %{"not_modified" => true, "revision" => revision}} ->
        case cached do
          {:ok, %{revision: ^revision} = entry} ->
            {:ok, %{value: secret_value(entry.data), version: entry.version, revision: revision}}

          _ ->
            {:error, "UNAVAILABLE"}
        end

      {:ok, %{"value" => value, "version" => version, "revision" => revision}}
      when is_integer(version) and is_integer(revision) ->
        Cache.put(key, value, version: version, revision: revision)
        {:ok, %{value: secret_value(value), version: version, revision: revision}}

      {:error, %{"reason" => code}} when is_binary(code) ->
        Cache.invalidate(key)
        {:error, public_code(code)}

      _ ->
        Cache.invalidate(key)
        {:error, "UNAVAILABLE"}
    end
  end

  defp secret_value(%{"value" => value}), do: value
  defp secret_value(value), do: value

  defp decode_base64(value) when is_binary(value), do: Base.decode64(value)
  defp decode_base64(_), do: :error

  defp public_code(code)
       when code in ~w(INCOMPATIBLE_VERSION UNAUTHORIZED FORBIDDEN VAULT_SEALED UNAVAILABLE),
       do: code

  defp public_code(_), do: "UNAVAILABLE"

  defp fail_auth(state, socket, id, code) do
    attempts = state.connections[socket].attempts + 1
    state = put_in(state, [:connections, socket, :attempts], attempts) |> count(:auth_failures)
    fail(state, socket, id, code, attempts >= 3)
  end

  defp fail(state, socket, id, code, close?) do
    :gen_tcp.send(
      socket,
      Jason.encode!(%{request_id: id, status: "error", error: %{code: code, message: code}}) <>
        "\n"
    )

    state = count(state, :failed_requests)
    if close?, do: close_connection(state, socket), else: state
  end

  defp reply(socket, id, data),
    do: :gen_tcp.send(socket, Jason.encode!(%{request_id: id, status: "ok", data: data}) <> "\n")

  defp count(state, counter), do: update_in(state, [:stats, counter], &(&1 + 1))

  defp close_connection(state, socket) do
    case Map.pop(state.connections, socket) do
      {nil, _} ->
        state

      {connection, connections} ->
        Process.cancel_timer(connection.timer)
        :gen_tcp.close(socket)

        %{
          state
          | connections: connections,
            stats: %{state.stats | active_connections: map_size(connections)}
        }
    end
  end
end
