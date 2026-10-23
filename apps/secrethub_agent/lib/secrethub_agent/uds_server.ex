defmodule SecretHub.Agent.UDSServer do
  @moduledoc "Owner-only newline UDS with connection-bound app private-key proof and Core-authorized reads."
  use GenServer
  alias SecretHub.Agent.AccessAudit.Journal
  alias SecretHub.Agent.{Cache, CertVerifier, Connection, IdentityStore, UDSAuth}
  alias SecretHub.Shared.AccessAudit.{Event, Telemetry}

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

  def handle_info({:tcp_error, socket, _reason}, state) do
    record_invalid(state)
    {:noreply, close_connection(state, socket)}
  end

  def handle_info({:authentication_timeout, socket}, state) do
    case state.connections[socket] do
      %{auth_state: :authenticated} ->
        {:noreply, state}

      nil ->
        {:noreply, state}

      _ ->
        record_auth_rejection(state, nil, "timeout")
        {:noreply, close_connection(state, socket)}
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

  defp handle_frame(socket, frame, state) when byte_size(frame) > @frame_limit do
    record_invalid(state)
    close_connection(state, socket)
  end

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
        record_invalid(state)
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
        reject_auth(state, socket, id, "INCOMPATIBLE_VERSION", true, "incompatible_version")

      is_nil(state.agent_id) ->
        reject_auth(state, socket, id, "ENROLLMENT_IN_PROGRESS", false, "invalid_identity")

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
      _ -> reject_auth(state, socket, id, "PROOF_FAILED", true, "proof_failed")
    end
  end

  defp dispatch(socket, id, action, _params, _connection, state)
       when action in ["authenticate", "authenticate_proof"],
       do: reject_auth(state, socket, id, "PROOF_FAILED", true, "proof_failed")

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
    audited_read(socket, id, params, connection, state)
  end

  defp dispatch(socket, id, "get_secret", params, _connection, state) do
    audited_reject(socket, id, params, state, "PROOF_REQUIRED", "proof_required")
  end

  defp dispatch(socket, id, _action, _params, %{auth_state: :authenticated}, state) do
    record_invalid(state)
    fail(state, socket, id, "UNAVAILABLE", false)
  end

  defp dispatch(socket, id, _action, _params, _connection, state) do
    record_invalid(state)
    fail(state, socket, id, "PROOF_REQUIRED", false)
  end

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

  defp audited_read(socket, id, params, connection, state) do
    started = System.monotonic_time(:microsecond)
    Telemetry.emit(:request_start, %{count: 1}, %{source: "agent", operation: "read"})
    attrs = audit_attrs(Map.put_new(params, "client_correlation_id", id), state, connection)

    with {:ok, audit} <- Journal.admit(attrs),
         {:ok, _} <- Journal.append(audit.reservation, Map.put(attrs, :phase, "attempt")) do
      result =
        if is_nil(attrs.secret_path),
          do: {:error, "FORBIDDEN", nil, {"denied", "invalid_path"}},
          else: read_secret(params["path"], connection, state.request_timeout, audit)

      case result do
        {:ok, data, cache_status, core_event_id} ->
          release =
            Map.merge(attrs, %{
              phase: "release_intent",
              secret_version: data.version,
              cache_status: cache_status,
              core_event_id: core_event_id
            })

          release_response(socket, id, data, audit, release, started, state)

        {:error, code, core_event_id, {outcome, reason}} ->
          attrs = Map.put(attrs, :core_event_id, core_event_id)
          sent = send_error(socket, id, code)
          record_transport(audit, attrs, sent, outcome, reason, started)
          count(state, :failed_requests)
      end
    else
      _ -> audit_unavailable(state, socket, id, started)
    end
  end

  defp release_response(socket, id, data, audit, release, started, state) do
    case Journal.append(audit.reservation, release) do
      {:ok, _} ->
        sent = reply(socket, id, data)
        record_transport(audit, release, sent, "success", "allowed", started)
        state

      _ ->
        audit_unavailable(state, socket, id, started)
    end
  end

  defp audit_unavailable(state, socket, id, started) do
    Telemetry.emit(
      :request_stop,
      %{count: 1, duration_us: max(System.monotonic_time(:microsecond) - started, 0)},
      %{source: "agent", operation: "read", outcome: "error", reason_code: "audit_unavailable"}
    )

    fail(state, socket, id, "AUDIT_UNAVAILABLE", false)
  end

  defp record_transport(audit, attrs, sent, outcome, reason, started) do
    {phase, outcome, reason} =
      case sent do
        :ok -> {"response_sent", outcome, reason}
        _ -> {"response_failed", "error", "transport_error"}
      end

    duration = max(System.monotonic_time(:microsecond) - started, 0)

    metadata = %{
      source: "agent",
      operation: "read",
      outcome: outcome,
      reason_code: reason,
      cache_status: attrs.cache_status
    }

    Telemetry.emit(:response_observation, %{count: 1}, metadata)
    Telemetry.emit(:request_stop, %{count: 1, duration_us: duration}, metadata)

    Journal.finish(
      audit.reservation,
      Map.merge(attrs, %{
        phase: phase,
        outcome: outcome,
        reason_code: reason,
        duration_us: duration
      })
    )
  end

  defp audited_reject(socket, id, params, state, code, reason) do
    attrs = audit_attrs(Map.put_new(params, "client_correlation_id", id), state, nil)

    with {:ok, audit} <- Journal.admit(attrs),
         {:ok, _} <-
           Journal.finish(
             audit.reservation,
             Map.merge(attrs, %{phase: "rejected", outcome: "denied", reason_code: reason})
           ) do
      fail(state, socket, id, code, false)
    else
      _ -> fail(state, socket, id, "AUDIT_UNAVAILABLE", false)
    end
  end

  defp record_invalid(state) do
    attrs = audit_attrs(%{}, state, nil) |> Map.put(:operation, "invalid")

    with {:ok, audit} <- Journal.admit(attrs) do
      Journal.finish(
        audit.reservation,
        Map.merge(attrs, %{phase: "rejected", outcome: "denied", reason_code: "invalid_request"})
      )
    end
  end

  defp audit_attrs(params, state, connection) do
    principal = if connection, do: connection.principal, else: nil

    correlation =
      case Ecto.UUID.cast(params["client_correlation_id"]) do
        {:ok, id} -> id
        _ -> nil
      end

    %{
      operation: "read",
      outcome: "unknown",
      reason_code: "none",
      cache_status: "none",
      agent_id: state.agent_id,
      application_id: if(principal, do: principal.app_id, else: nil),
      identity_status: if(principal, do: "verified", else: "unverified"),
      attribution: if(principal, do: "agent_certificate", else: "none"),
      secret_path: Event.safe_path(params["path"]),
      client_correlation_id: correlation
    }
  end

  defp audit_reason("UNAUTHORIZED"), do: "unauthorized"
  defp audit_reason("FORBIDDEN"), do: "permission_denied"
  defp audit_reason("INCOMPATIBLE_VERSION"), do: "incompatible_version"
  defp audit_reason("VAULT_SEALED"), do: "sealed"
  defp audit_reason(_), do: "core_unavailable"

  defp audit_classification(
         {:error, %{"audit_outcome" => outcome, "audit_reason_code" => reason}},
         code
       )
       when outcome in ~w(success denied error unknown) and is_binary(reason) do
    if Event.reason(reason) == reason,
      do: {outcome, reason},
      else: audit_classification(nil, code)
  end

  defp audit_classification(_, code) do
    outcome =
      if code in ~w(UNAUTHORIZED FORBIDDEN INCOMPATIBLE_VERSION), do: "denied", else: "error"

    {outcome, audit_reason(code)}
  end

  defp read_secret(path, connection, timeout, audit) when is_binary(path) and path != "" do
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
      local_auth_version: connection.auth_version,
      audit_request_id: audit.request_id,
      audit_attempt_id: audit.attempt_id
    }

    result = Connection.get_static_secret_for_app(Connection, path, claims, revision, timeout)

    cache_status =
      case cached do
        {:ok, _} -> "validated"
        _ -> "miss"
      end

    case read_result(result, cached, key) do
      {:ok, data} -> {:ok, data, cache_status, core_event_id(result)}
      {:error, code} -> {:error, code, core_event_id(result), audit_classification(result, code)}
    end
  catch
    :exit, _ -> {:error, "UNAVAILABLE", nil, {"error", "core_unavailable"}}
  end

  defp read_secret(_, _, _, _), do: {:error, "FORBIDDEN", nil, {"denied", "invalid_path"}}

  defp core_event_id({status, %{"audit_event_id" => id}}) when status in [:ok, :error] do
    case Ecto.UUID.cast(id) do
      {:ok, normalized} -> normalized
      _ -> nil
    end
  end

  defp core_event_id(_), do: nil

  defp read_result({:ok, %{"not_modified" => true, "revision" => revision}}, cached, key) do
    with {:ok, %{revision: ^revision} = entry} <- cached,
         {:ok, value} <- secret_value(entry.data, Map.get(entry, :value_format)) do
      {:ok, %{value: value, version: entry.version, revision: revision}}
    else
      _ -> unavailable_read(key)
    end
  end

  defp read_result(
         {:ok, %{"value" => value, "version" => version, "revision" => revision} = response},
         _cached,
         key
       )
       when is_integer(version) and is_integer(revision) do
    format = response["value_format"]

    case secret_value(value, format) do
      {:ok, payload} ->
        Cache.put(key, value, version: version, revision: revision, value_format: format)
        {:ok, %{value: payload, version: version, revision: revision}}

      :error ->
        unavailable_read(key)
    end
  end

  defp read_result({:error, %{"reason" => code}}, _cached, key) when is_binary(code) do
    Cache.invalidate(key)
    {:error, public_code(code)}
  end

  defp read_result(_, _cached, key), do: unavailable_read(key)

  defp unavailable_read(key) do
    Cache.invalidate(key)
    {:error, "UNAVAILABLE"}
  end

  defp secret_value(value, "structured") when is_map(value), do: {:ok, value}

  defp secret_value(%{"value" => value} = data, "text")
       when map_size(data) == 1 and is_binary(value),
       do: {:ok, value}

  defp secret_value(%{"value" => value}, nil), do: {:ok, value}
  defp secret_value(value, nil), do: {:ok, value}
  defp secret_value(_, _), do: :error

  defp decode_base64(value) when is_binary(value), do: Base.decode64(value)
  defp decode_base64(_), do: :error

  defp public_code(code)
       when code in ~w(INCOMPATIBLE_VERSION UNAUTHORIZED FORBIDDEN VAULT_SEALED UNAVAILABLE),
       do: code

  defp public_code(_), do: "UNAVAILABLE"

  defp fail_auth(state, socket, id, code) do
    attempts = state.connections[socket].attempts + 1
    state = put_in(state, [:connections, socket, :attempts], attempts) |> count(:auth_failures)
    reject_auth(state, socket, id, code, attempts >= 3, "invalid_identity")
  end

  defp reject_auth(state, socket, id, code, close?, reason) do
    case record_auth_rejection(state, id, reason) do
      {:ok, _} -> fail(state, socket, id, code, close?)
      _ -> fail(state, socket, id, "AUDIT_UNAVAILABLE", close?)
    end
  end

  defp record_auth_rejection(state, id, reason) do
    attrs =
      audit_attrs(%{"client_correlation_id" => id}, state, nil)
      |> Map.put(:operation, "authenticate")
      |> Map.put(:secret_path, nil)

    with {:ok, audit} <- Journal.admit(attrs) do
      Journal.finish(
        audit.reservation,
        Map.merge(attrs, %{phase: "rejected", outcome: "denied", reason_code: reason})
      )
    end
  end

  defp send_error(socket, id, code) do
    :gen_tcp.send(
      socket,
      Jason.encode!(%{request_id: id, status: "error", error: %{code: code, message: code}}) <>
        "\n"
    )
  end

  defp fail(state, socket, id, code, close?) do
    send_error(socket, id, code)
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
