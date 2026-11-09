defmodule SecretHub.Agent.HostCredentials.LocalAPI do
  @moduledoc """
  Local `credential_*` request execution for the Agent's owner-only socket.

  Each request runs in its own supervised task so a slow Core call never
  blocks unrelated Git, Docker or keyring requests. The task owns its durable
  audit reservation (admission, attempt, release intent and transport outcome)
  and writes exactly one correlated response frame. Plaintext is released only
  after a fresh Core decision: a cached value is used only when Core confirms
  its exact binding and source revisions.
  """
  alias SecretHub.Agent.AccessAudit.Journal
  alias SecretHub.Agent.{Cache, Connection}
  alias SecretHub.Shared.AccessAudit.Event
  alias SecretHub.Shared.HostCredentials, as: Contract

  @frame_limit 65_536
  @public_codes ~w(NOT_FOUND AMBIGUOUS READ_ONLY INVALID_REQUEST INVALID_VALUE SOURCE_UNAVAILABLE
    FORBIDDEN UNAUTHORIZED INCOMPATIBLE_VERSION VAULT_SEALED UNAVAILABLE)
  @denied_codes ~w(FORBIDDEN UNAUTHORIZED INVALID_REQUEST READ_ONLY INCOMPATIBLE_VERSION)

  def frame_limit, do: @frame_limit

  @doc "Handles one validated-by-dispatch action and writes its response to `socket`."
  def handle(socket, request_id, action, params, ctx) do
    {:ok, operation} = Contract.operation(action)
    started = System.monotonic_time(:microsecond)

    case Contract.validate(action, params) do
      {:ok, request} ->
        admitted(json_responder(socket, request_id), request_id, operation, request, ctx, started)

      {:error, _} ->
        reject(socket, request_id, action, ctx.agent_id, "INVALID_REQUEST")
    end
  end

  @doc "Records a locally rejected credential request and returns its error frame."
  def reject(socket, request_id, action, agent_id, code) do
    operation =
      case Contract.operation(action) do
        {:ok, operation} -> operation
        :error -> "credential_read"
      end

    attrs = attrs(operation, agent_id, request_id)
    {outcome, reason} = classify(nil, code)

    with {:ok, audit} <- Journal.admit(attrs),
         {:ok, _} <-
           Journal.finish(
             audit.reservation,
             Map.merge(attrs, %{phase: "rejected", outcome: outcome, reason_code: reason})
           ) do
      send_error(socket, request_id, code)
    else
      _ -> send_error(socket, request_id, "AUDIT_UNAVAILABLE")
    end
  end

  @doc """
  systemd provider delivery: resolves one binding field with the same audit
  and Core decision as a local read. On success the raw bytes of `field` are
  written; on any failure nothing is written, so the caller closes the socket
  without credential data. Empty values are refused.
  """
  def deliver_raw(socket, entry_id, field, ctx) when field in ["value", "username"] do
    started = System.monotonic_time(:microsecond)
    responder = raw_responder(socket, field)
    request = %{"entry_id" => entry_id, "known" => nil}
    admitted(responder, nil, "credential_read", request, ctx, started)
  end

  defp json_responder(socket, request_id) do
    %{
      ok: &reply(socket, request_id, &1),
      error: &send_error(socket, request_id, &1)
    }
  end

  defp raw_responder(socket, field) do
    %{
      ok: fn data ->
        case data[field] do
          value when is_binary(value) and value != "" -> :gen_tcp.send(socket, value)
          _ -> {:error, :empty}
        end
      end,
      error: fn _code -> :ok end
    }
  end

  defp admitted(responder, request_id, operation, request, ctx, started) do
    attrs = attrs(operation, ctx.agent_id, request_id)

    with {:ok, audit} <- Journal.admit(attrs),
         {:ok, _} <- Journal.append(audit.reservation, Map.put(attrs, :phase, "attempt")) do
      operation
      |> forward(request, audit, ctx)
      |> respond(responder, audit, attrs, started)
    else
      _ -> responder.error.("AUDIT_UNAVAILABLE")
    end
  end

  defp respond({:ok, data, release}, responder, audit, attrs, started) do
    release = Map.merge(attrs, Map.put(release, :phase, "release_intent"))

    case Journal.append(audit.reservation, release) do
      {:ok, _} ->
        sent = responder.ok.(data)
        finish(audit, release, sent, "success", "allowed", started)

      _ ->
        responder.error.("AUDIT_UNAVAILABLE")
    end
  end

  defp respond({:error, code, details}, responder, audit, attrs, started) do
    {outcome, reason} = Map.fetch!(details, :classification)
    failed = attrs |> Map.merge(details) |> Map.delete(:classification)
    sent = responder.error.(code)
    finish(audit, failed, sent, outcome, reason, started)
  end

  defp finish(audit, attrs, sent, outcome, reason, started) do
    {phase, outcome, reason} =
      case sent do
        :ok -> {"response_sent", outcome, reason}
        _ -> {"response_failed", "error", "transport_error"}
      end

    Journal.finish(
      audit.reservation,
      Map.merge(attrs, %{
        phase: phase,
        outcome: outcome,
        reason_code: reason,
        duration_us: max(System.monotonic_time(:microsecond) - started, 0)
      })
    )
  end

  ## Core forwarding

  defp forward("credential_read", request, audit, ctx) do
    key = cache_key(ctx.agent_id, request)
    cached = Cache.get_entry(key)

    known =
      case cached do
        {:ok, %{data: data}} -> Map.take(data, ~w(entry_id binding_revision source_revision))
        _ -> nil
      end

    payload = request |> Map.put("known", known) |> correlate(audit)

    case Connection.credential_request("get", payload, ctx.timeout) do
      {:ok, %{"not_modified" => true} = response} ->
        with {:ok, %{data: data}} <- cached,
             true <- same_revision?(data, response) do
          {:ok, public_get(data), release(response, "validated")}
        else
          _ ->
            Cache.invalidate(key)
            unavailable(response)
        end

      {:ok, %{"value" => value, "username" => username} = response}
      when is_binary(value) and is_binary(username) ->
        data =
          Map.take(
            response,
            ~w(entry_id namespace source_kind binding_revision source_revision username value)
          )

        Cache.put(key, data, version: response["secret_version"])
        {:ok, public_get(data), release(response, "miss")}

      other ->
        Cache.invalidate(key)
        failure(other, "credential_read")
    end
  end

  defp forward(operation, request, audit, ctx) do
    action =
      Map.fetch!(
        %{
          "credential_write" => "put",
          "credential_delete" => "delete",
          "credential_list" => "list"
        },
        operation
      )

    case Connection.credential_request(action, correlate(request, audit), ctx.timeout) do
      {:ok, %{"status" => _} = response} ->
        {:ok,
         Map.take(response, ~w(status entry_id source_kind binding_revision source_revision)),
         release(response, "none")}

      {:ok, %{"entries" => entries} = response} when is_list(entries) ->
        {:ok, %{"entries" => entries, "next_cursor" => response["next_cursor"]},
         release(response, "none")}

      other ->
        failure(other, operation)
    end
  end

  defp correlate(payload, audit),
    do:
      Map.merge(payload, %{
        "audit_request_id" => audit.request_id,
        "audit_attempt_id" => audit.attempt_id
      })

  defp same_revision?(data, response),
    do:
      Enum.all?(
        ~w(entry_id binding_revision source_revision),
        &(Map.get(data, &1) == Map.get(response, &1))
      )

  defp public_get(data),
    do:
      Map.take(
        data,
        ~w(entry_id namespace source_kind username value binding_revision source_revision)
      )

  defp release(response, cache_status) do
    %{
      cache_status: cache_status,
      secret_path: Event.safe_path(response["resource"]),
      core_event_id: core_event_id(response)
    }
  end

  defp unavailable(response) do
    {:error, "UNAVAILABLE",
     %{core_event_id: core_event_id(response), classification: {"error", "core_unavailable"}}}
  end

  # An ambiguous transport outcome for a mutation is reported as unconfirmed.
  defp failure({:error, :timeout}, operation)
       when operation in ~w(credential_write credential_delete),
       do: {:error, "UNCONFIRMED", %{classification: {"unknown", "unconfirmed"}}}

  defp failure({:error, :busy}, _operation),
    do: {:error, "BUSY", %{classification: {"error", "busy"}}}

  defp failure({:error, %{"reason" => code} = response}, _operation) when is_binary(code) do
    code = if code in @public_codes, do: code, else: "UNAVAILABLE"

    {:error, code,
     %{core_event_id: core_event_id({:error, response}), classification: classify(response, code)}}
  end

  defp failure(_other, _operation),
    do: {:error, "UNAVAILABLE", %{classification: {"error", "core_unavailable"}}}

  defp classify(%{"audit_outcome" => outcome, "audit_reason_code" => reason}, code)
       when outcome in ~w(success denied error unknown) and is_binary(reason) do
    if Event.reason(reason, 2) == reason, do: {outcome, reason}, else: classify(nil, code)
  end

  defp classify(_, code) do
    outcome = if code in @denied_codes, do: "denied", else: "error"

    reason =
      %{
        "NOT_FOUND" => "not_found",
        "AMBIGUOUS" => "ambiguous",
        "READ_ONLY" => "read_only",
        "INVALID_REQUEST" => "invalid_request",
        "INVALID_VALUE" => "invalid_value",
        "FORBIDDEN" => "permission_denied",
        "UNAUTHORIZED" => "unauthorized",
        "INCOMPATIBLE_VERSION" => "incompatible_version",
        "VAULT_SEALED" => "sealed",
        "ENROLLMENT_IN_PROGRESS" => "invalid_identity",
        "AGENT_SCOPE_REQUIRED" => "invalid_identity",
        "BUSY" => "busy"
      }
      |> Map.get(code, "core_unavailable")

    {outcome, reason}
  end

  defp core_event_id({_, %{"audit_event_id" => id}}), do: core_event_id(%{"audit_event_id" => id})

  defp core_event_id(%{"audit_event_id" => id}) do
    case Ecto.UUID.cast(id) do
      {:ok, normalized} -> normalized
      :error -> nil
    end
  end

  defp core_event_id(_), do: nil

  # Lookup fields are data. The key cannot collide with static secret paths.
  defp cache_key(agent_id, request) do
    selector =
      request
      |> Map.delete("known")
      |> Enum.sort()
      |> Jason.OrderedObject.new()
      |> Jason.encode!()

    {:host_credential, agent_id, "host-credential:" <> selector}
  end

  defp attrs(operation, agent_id, request_id) do
    correlation =
      case Ecto.UUID.cast(request_id) do
        {:ok, id} -> id
        _ -> nil
      end

    %{
      operation: operation,
      outcome: "unknown",
      reason_code: "none",
      cache_status: "none",
      agent_id: agent_id,
      application_id: nil,
      identity_status: "unverified",
      attribution: "none",
      secret_path: nil,
      client_correlation_id: correlation
    }
  end

  ## Framing

  defp reply(socket, request_id, %{"entries" => entries} = data) do
    case encode_ok(request_id, data) do
      {:ok, frame} -> :gen_tcp.send(socket, frame)
      :too_large -> reply(socket, request_id, shrink(entries))
    end
  end

  defp reply(socket, request_id, data) do
    case encode_ok(request_id, data) do
      {:ok, frame} -> :gen_tcp.send(socket, frame)
      :too_large -> send_error(socket, request_id, "RESPONSE_TOO_LARGE")
    end
  end

  # Keep the page within one frame: drop trailing entries and resume after the
  # last returned entry, so no entry is skipped.
  defp shrink(entries) do
    kept = Enum.drop(entries, -max(div(length(entries), 2), 1))
    %{"entries" => kept, "next_cursor" => List.last(kept)["entry_id"]}
  end

  defp encode_ok(request_id, data) do
    frame = Jason.encode!(%{request_id: request_id, status: "ok", data: data}) <> "\n"
    if byte_size(frame) <= @frame_limit, do: {:ok, frame}, else: :too_large
  end

  defp send_error(socket, request_id, code) do
    :gen_tcp.send(
      socket,
      Jason.encode!(%{
        request_id: request_id,
        status: "error",
        error: %{code: code, message: code}
      }) <>
        "\n"
    )
  end
end
