defmodule SecretHub.Web.SecretApiController do
  @moduledoc """
  REST API controller for secret CRUD operations via Vault-style paths.

  Routes:
  - POST /v1/secret/data/*path — Create or update a secret
  - GET /v1/secret/data/*path — Read a secret
  - DELETE /v1/secret/data/*path — Delete a secret
  - GET /v1/secret/metadata/*path — Get secret metadata

  Vault-style URL paths (e.g., `test-app/database`) are converted to
  dot-notation (e.g., `test-app.database`) for internal storage, since the
  Secret schema validates paths as reverse domain notation.
  """

  use SecretHub.Web, :controller
  require Logger

  alias SecretHub.Core.{AccessAudit, Audit, Policies, Repo}
  alias SecretHub.Core.Secrets
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.AccessAudit.{Event, Telemetry}
  alias SecretHub.Shared.Schemas.Secret

  @doc """
  POST /v1/secret/data/*path

  Create or update a secret at the given path.
  """
  def create_or_update(conn, params) do
    if vault_sealed?() do
      sealed_response(conn)
    else
      path = extract_path(params)
      secret_path = vault_path_to_dot(path)
      # Keep Vault-style path for policy check (policies use Vault patterns)
      vault_path = "secret/data/" <> path

      # Check policy allows write/create
      with :ok <- check_policy(conn, vault_path, "create"),
           {:ok, format} <- validate_value_format(params["value_format"]),
           {:ok, data} <- validate_data_param(params["data"], format) do
        do_create_or_update(conn, path, secret_path, data, format)
      else
        {:error, :invalid_data} ->
          conn
          |> put_status(:bad_request)
          |> json(%{error: "Missing or empty 'data' field"})

        {:error, :invalid_value_format} ->
          conn
          |> put_status(:bad_request)
          |> json(%{error: "Value format must be 'text' or 'structured'"})

        {:error, _reason} ->
          forbidden_response(conn)
      end
    end
  end

  @doc """
  GET /v1/secret/data/*path

  Read a secret at the given path.
  """
  def read(conn, params) do
    path = extract_path(params)
    started = System.monotonic_time(:microsecond)

    evidence = %{
      request_id: Ecto.UUID.generate(),
      attempt_id: Ecto.UUID.generate(),
      agent_id: verified_token_agent(conn),
      application_id: nil,
      identity_status: "unverified",
      attribution: "token",
      operation: "read",
      secret_path: Event.safe_path(vault_path_to_dot(path)),
      phase: "admitted",
      outcome: "unknown",
      reason_code: "none",
      cache_status: "none"
    }

    result =
      Repo.transaction(fn ->
        checked_read_observation!(evidence)
        Telemetry.emit(:request_start, %{count: 1}, %{source: "core", operation: "read"})
        response = read_response(conn, path, params["version"])

        attrs =
          Map.merge(evidence, %{
            phase: "core_decision",
            outcome: response.outcome,
            reason_code: response.reason,
            secret_id: response.secret_id,
            secret_version: response.version,
            duration_us: System.monotonic_time(:microsecond) - started
          })

        decision = checked_read_observation!(attrs)
        checked_legacy_read_audit!(conn, attrs)

        if response.outcome == "success" do
          checked_read_observation!(
            %{attrs | phase: "core_access"}
            |> Map.put(:core_event_id, decision.event_id)
          )

          checked_read_observation!(%{attrs | phase: "release_intent", outcome: "unknown"})
        end

        {response, attrs}
      end)

    case result do
      {:ok, {response, attrs}} ->
        send_read_response(conn, response, attrs, started)

      {:error, _} ->
        audit_unavailable_response(conn)
    end
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError] -> audit_unavailable_response(conn)
  catch
    :exit, _ -> audit_unavailable_response(conn)
  end

  @doc """
  DELETE /v1/secret/data/*path

  Delete a secret at the given path.
  """
  def delete(conn, params) do
    if vault_sealed?() do
      sealed_response(conn)
    else
      path = extract_path(params)
      secret_path = vault_path_to_dot(path)
      vault_path = "secret/data/" <> path

      case check_policy(conn, vault_path, "delete") do
        :ok ->
          delete_secret_at_path(conn, secret_path)

        {:error, _reason} ->
          forbidden_response(conn)
      end
    end
  end

  @doc """
  GET /v1/secret/metadata/*path

  Get metadata for secrets at the given path.
  """
  def metadata(conn, params) do
    if vault_sealed?() do
      sealed_response(conn)
    else
      path = extract_path(params)
      secret_path = vault_path_to_dot(path)
      vault_path = "secret/metadata/" <> path

      case check_policy(conn, vault_path, "read") do
        :ok ->
          fetch_metadata(conn, secret_path, params["list"] == "true")

        {:error, _reason} ->
          forbidden_response(conn)
      end
    end
  end

  # Private helpers — create_or_update

  defp validate_value_format(format) when format in [nil, "text", "structured"], do: {:ok, format}
  defp validate_value_format(_), do: {:error, :invalid_value_format}

  defp validate_data_param(data, format)
       when is_map(data) and (map_size(data) > 0 or format == "structured"),
       do: {:ok, data}

  defp validate_data_param(_, _), do: {:error, :invalid_data}

  defp do_create_or_update(conn, path, secret_path, data, format) do
    case Secrets.get_secret_by_path(secret_path) do
      {:ok, existing} ->
        update_existing_secret(conn, existing, data, format)

      {:error, _} ->
        create_new_secret(conn, path, secret_path, data, format)
    end
  end

  defp update_existing_secret(conn, existing, data, format) do
    attrs = put_value_format(%{"secret_data" => data}, format)

    case Secrets.update_secret(existing.id, attrs,
           created_by: current_actor_id(conn),
           change_description: "Updated via API",
           via_rotator_slug: "api"
         ) do
      {:ok, updated} ->
        json(conn, %{version: updated.version})

      {:error, reason} ->
        write_error(conn, reason)
    end
  end

  defp create_new_secret(conn, path, secret_path, data, format) do
    name =
      path
      |> String.split("/")
      |> List.last()
      |> String.replace(~r/[^a-zA-Z0-9\s\-_]/, "_")

    attrs = %{
      "name" => name,
      "secret_path" => secret_path,
      "secret_data" => data,
      "secret_type" => "static",
      "engine_type" => "static",
      "rotator_slug" => "api",
      "ttl_seconds" => 0,
      "description" => "Created via API",
      "created_by" => current_actor_id(conn)
    }

    case Secrets.create_secret(put_value_format(attrs, format)) do
      {:ok, secret} ->
        json(conn, %{version: secret.version || 1})

      {:error, reason} ->
        Logger.error("Secret creation failed", path: secret_path)

        write_error(conn, reason)
    end
  end

  defp put_value_format(attrs, nil), do: attrs
  defp put_value_format(attrs, format), do: Map.put(attrs, "value_format", format)

  defp write_error(conn, reason) do
    message =
      case reason do
        :invalid_text_value -> "Text requires exactly one string-valued 'value' field"
        :invalid_structured_value -> "Structured data must be a JSON object"
        :invalid_value_format -> "Value format must be 'text' or 'structured'"
        :format_change_requires_replacement -> "Changing value format requires a replacement"
        _ -> "Invalid secret attributes"
      end

    conn |> put_status(:unprocessable_entity) |> json(%{error: message})
  end

  # Private helpers — read

  defp send_read_response(conn, response, attrs, started) do
    sent = conn |> put_status(response.status) |> json(response.body)
    # Adapter success proves a write only. If this append fails, committed
    # release intent remains incomplete and operational health records failure.
    record_response(%{attrs | phase: "response_sent"})

    Telemetry.emit(
      :request_stop,
      %{count: 1, duration_us: System.monotonic_time(:microsecond) - started},
      %{
        source: "core",
        operation: "read",
        outcome: response.outcome,
        reason_code: response.reason
      }
    )

    sent
  rescue
    _ -> failed_read_response(attrs)
  catch
    :exit, _ -> failed_read_response(attrs)
  end

  defp failed_read_response(attrs) do
    record_response(%{
      attrs
      | phase: "response_failed",
        outcome: "error",
        reason_code: "transport_error"
    })

    Telemetry.emit(:request_exception, %{count: 1}, %{
      source: "core",
      operation: "read",
      outcome: "error",
      reason_code: "transport_error"
    })

    # Adapter exceptions may contain response data; never propagate their text.
    raise Plug.Conn.NotSentError, "Secret response transport failed"
  end

  defp record_response(attrs) do
    case AccessAudit.record_core(attrs) do
      {:ok, _} ->
        :ok

      {:error, _} ->
        Telemetry.emit(:request_exception, %{count: 1}, %{
          source: "core",
          operation: "read",
          outcome: "error",
          reason_code: "audit_unavailable"
        })
    end
  end

  defp read_response(conn, path, version) do
    cond do
      vault_sealed?() ->
        read_error(503, "error", "sealed", "Vault is sealed")

      is_nil(Event.safe_path(vault_path_to_dot(path))) ->
        read_error(400, "denied", "invalid_path", "Invalid secret path")

      check_policy(conn, "secret/data/" <> path, "read") != :ok ->
        read_error(403, "denied", "permission_denied", "permission denied")

      true ->
        read_secret_result(vault_path_to_dot(path), version)
    end
  end

  defp read_secret_result(path, version) when is_binary(version),
    do: read_specific_version(path, version)

  defp read_secret_result(path, _) do
    case Secrets.read_decrypted(path) do
      {:ok, data, secret} ->
        %{
          status: 200,
          outcome: "success",
          reason: "allowed",
          secret_id: secret.id,
          version: secret.version || 1,
          body: %{
            data: data,
            metadata: %{
              version: secret.version || 1,
              value_format: secret.value_format,
              created_time: secret.inserted_at,
              updated_time: secret.updated_at
            }
          }
        }

      {:error, :sealed} ->
        read_error(503, "error", "sealed", "Vault is sealed")

      {:error, _} ->
        read_error(404, "error", "not_found", "Secret not found")
    end
  end

  defp read_error(status, outcome, reason, message),
    do: %{
      status: status,
      outcome: outcome,
      reason: reason,
      secret_id: nil,
      version: nil,
      body: %{error: message}
    }

  defp checked_read_observation!(attrs) do
    case AccessAudit.record_core(attrs) do
      {:ok, event} -> event
      {:error, _} -> Repo.rollback(:audit_unavailable)
    end
  end

  defp checked_legacy_read_audit!(conn, attrs) do
    actor = current_actor(conn)

    case Audit.log_event(%{
           event_type:
             if(attrs.outcome == "success", do: "secret.accessed", else: "secret.access_denied"),
           actor_type: actor.type,
           actor_id: actor.id,
           agent_id: actor.agent_id,
           secret_id: attrs.secret_id,
           access_granted: attrs.outcome == "success",
           event_data: %{secret_path: attrs.secret_path, reason_code: attrs.reason_code}
         }) do
      {:ok, _} -> :ok
      {:error, _} -> Repo.rollback(:audit_unavailable)
    end
  end

  defp verified_token_agent(conn) do
    case conn.assigns[:current_agent] do
      %{agent_id: public_id} -> public_id
      _ -> nil
    end
  end

  defp audit_unavailable_response(conn),
    do: conn |> put_status(:service_unavailable) |> json(%{error: "audit_unavailable"})

  # Private helpers — delete

  defp delete_secret_at_path(conn, secret_path) do
    case Secrets.get_secret_by_path(secret_path) do
      {:ok, secret} ->
        perform_delete(conn, secret)

      {:error, _} ->
        not_found_response(conn, "Secret not found")
    end
  end

  defp perform_delete(conn, secret) do
    case Secrets.delete_secret(secret.id) do
      {:ok, _} ->
        send_resp(conn, :no_content, "")

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  # Private helpers — metadata

  defp fetch_metadata(conn, secret_path, true = _list) do
    list_secrets_at_path(conn, secret_path)
  end

  defp fetch_metadata(conn, secret_path, _list) do
    case Secrets.get_secret_by_path(secret_path) do
      {:ok, secret} ->
        json(conn, %{
          versions: %{
            "#{secret.version || 1}" => %{
              created_time: secret.inserted_at,
              version: secret.version || 1
            }
          },
          created_time: secret.inserted_at,
          updated_time: secret.updated_at,
          value_format: secret.value_format,
          current_version: secret.version || 1
        })

      {:error, _} ->
        not_found_response(conn, "Secret not found")
    end
  end

  # Shared response helpers

  defp forbidden_response(conn) do
    actor = current_actor(conn)

    Audit.log_event(%{
      event_type: "secret.access_denied",
      actor_type: actor.type,
      actor_id: actor.id,
      agent_id: actor.agent_id,
      access_granted: false,
      denial_reason: "policy_denied"
    })

    conn
    |> put_status(:forbidden)
    |> json(%{error: "permission denied"})
  end

  defp not_found_response(conn, message) do
    conn
    |> put_status(:not_found)
    |> json(%{error: message})
  end

  # Private helpers — path and policy

  defp extract_path(%{"path" => path_parts}) when is_list(path_parts) do
    Enum.join(path_parts, "/")
  end

  defp extract_path(%{"path" => path}) when is_binary(path), do: path
  defp extract_path(_), do: ""

  # Convert Vault-style slash paths to dot-notation for DB storage.
  # "test-app/database" -> "test-app.database"
  defp vault_path_to_dot(path) do
    path
    |> String.replace("/", ".")
  end

  defp check_policy(conn, vault_path, operation) do
    policies = conn.assigns[:current_policies] || []
    candidate_paths = policy_candidate_paths(vault_path)

    case Policies.evaluate_policies(policies, candidate_paths, operation, policy_context(conn)) do
      {:ok, _policy} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp policy_context(conn) do
    %{ip_address: get_client_ip(conn)}
  end

  defp policy_candidate_paths("secret/data/" <> path) do
    [path, dot_path(path), "secret/data/" <> path, "secret/data/" <> dot_path(path)]
    |> Enum.uniq()
  end

  defp policy_candidate_paths("secret/metadata/" <> path) do
    [path, dot_path(path), "secret/metadata/" <> path, "secret/metadata/" <> dot_path(path)]
    |> Enum.uniq()
  end

  defp policy_candidate_paths(path), do: [path, dot_path(path)] |> Enum.uniq()

  defp dot_path(path), do: String.replace(path, "/", ".")

  defp get_client_ip(conn) do
    case get_req_header(conn, "x-forwarded-for") do
      [ip | _] ->
        ip |> String.split(",") |> List.first() |> String.trim()

      _ ->
        conn.remote_ip
        |> :inet.ntoa()
        |> to_string()
    end
  rescue
    _ -> "unknown"
  end

  defp current_actor(conn) do
    actor = conn.assigns[:current_actor] || %{}

    %{
      type: Map.get(actor, :type, "unknown"),
      id: Map.get(actor, :id),
      agent_id: current_agent_id(conn)
    }
  end

  defp current_actor_id(conn) do
    actor = current_actor(conn)
    actor.id || "unknown"
  end

  defp current_agent_id(conn) do
    case conn.assigns[:current_agent] do
      %{id: id} -> id
      _ -> nil
    end
  end

  defp read_specific_version(secret_path, version_str) do
    with {version_num, ""} <- Integer.parse(version_str),
         {:ok, secret} <- Secrets.get_secret_by_path(secret_path),
         {:ok, data, format} <- Secrets.read_exact_material_with_format(secret.id, version_num) do
      created_time =
        if secret.version == version_num do
          secret.updated_at
        else
          {:ok, version} = Secrets.get_secret_version(secret.id, version_num)
          version.inserted_at
        end

      %{
        status: 200,
        outcome: "success",
        reason: "allowed",
        secret_id: secret.id,
        version: version_num,
        body: %{
          data: data,
          metadata: %{version: version_num, value_format: format, created_time: created_time}
        }
      }
    else
      _ ->
        read_error(404, "error", "not_found", "Version not found")
    end
  end

  defp list_secrets_at_path(conn, prefix) do
    import Ecto.Query

    secrets =
      from(s in Secret,
        where: like(s.secret_path, ^"#{prefix}%"),
        select: s.secret_path
      )
      |> Repo.all()

    # Extract relative keys
    keys =
      Enum.map(secrets, fn full_path ->
        String.replace_prefix(full_path, prefix <> ".", "")
      end)

    json(conn, %{keys: keys})
  end

  defp vault_sealed? do
    case SealState.status() do
      %{sealed: true} -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  defp sealed_response(conn) do
    conn
    |> put_status(:service_unavailable)
    |> json(%{error: "Vault is sealed"})
  end
end
