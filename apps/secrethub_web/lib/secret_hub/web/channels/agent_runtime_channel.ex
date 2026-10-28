defmodule SecretHub.Web.AgentRuntimeChannel do
  @moduledoc """
  Trusted Agent runtime protocol channel.
  """

  use SecretHub.Web, :channel
  import Ecto.Query
  require Logger

  alias SecretHub.Core.AccessAudit
  alias SecretHub.Core.Agents
  alias SecretHub.Core.Agents.ConnectionManager
  alias SecretHub.Core.Repo
  alias SecretHub.Core.RuntimeAuthorization
  alias SecretHub.Core.RuntimePrincipal
  alias SecretHub.Core.Secrets
  alias SecretHub.Core.UpgradeGates
  alias SecretHub.Shared.AccessAudit.{Event, Telemetry}
  alias SecretHub.Shared.LaunchProfile
  alias SecretHub.Shared.Schemas.AuthorizationEpoch

  @impl true
  def join("agent:runtime", payload, socket) when is_map(payload) do
    with {:ok, agent_id} <- fetch_assign(socket, :agent_id),
         {:ok, cert_serial} <- fetch_assign(socket, :certificate_serial),
         {:ok, cert_fingerprint} <- fetch_assign(socket, :certificate_fingerprint),
         {:ok, cert_id} <- fetch_assign(socket, :certificate_id),
         :ok <- authorize_join(agent_id, cert_id, Map.get(payload, "runtime_capabilities", [])) do
      metadata = %{
        certificate_id: cert_id,
        certificate_fingerprint: cert_fingerprint,
        certificate_serial: cert_serial,
        peer: socket.assigns[:peer]
      }

      :ok = ConnectionManager.register_connection(agent_id, cert_serial, self(), metadata)
      :ok = SecretHub.Core.PKI.ClientAuth.Notifier.subscribe()
      :ok = Phoenix.PubSub.subscribe(SecretHub.Web.PubSub, "authorization:uds_auth_floor")
      :ok = Phoenix.PubSub.subscribe(SecretHub.Web.PubSub, "ssh:policy")

      capabilities =
        payload
        |> Map.get("runtime_capabilities", [])
        |> Enum.filter(
          &(&1 in [
              "uds_auth_v2",
              "ssh_lookup_v1",
              "ssh_signing_v1",
              "access_audit_v1",
              "local_socket_read_v1"
            ])
        )
        |> Enum.uniq()
        |> Enum.sort()

      socket = assign(socket, :runtime_capabilities, capabilities)

      {:ok,
       %{
         status: "accepted",
         minimum_uds_auth_version: UpgradeGates.minimum_uds_auth_version(),
         runtime_capabilities: capabilities,
         agent_id: agent_id,
         certificate_serial: cert_serial,
         certificate_fingerprint: cert_fingerprint,
         certificate_id: cert_id
       }, socket}
    else
      {:error, :missing_assign} -> {:error, %{reason: "mtls_required"}}
      {:error, :incompatible_version} -> {:error, %{reason: "INCOMPATIBLE_VERSION"}}
      {:error, :invalid_capabilities} -> {:error, %{reason: "INCOMPATIBLE_VERSION"}}
      {:error, reason} -> {:error, runtime_unauthorized_payload(reason)}
    end
  rescue
    _ -> {:error, %{reason: "UNAVAILABLE"}}
  end

  def join(_topic, _payload, _socket), do: {:error, %{reason: "unknown_topic"}}

  @impl true
  def handle_in("agent:hello", payload, socket) do
    with_runtime_authorized(socket, fn ->
      agent_id = socket.assigns.agent_id
      Agents.update_agent_config(agent_id, %{"runtime_info" => payload})
      {:reply, {:ok, %{event: "agent:accepted"}}, socket}
    end)
  end

  def handle_in("agent:heartbeat", _payload, socket) do
    with_runtime_authorized(socket, fn ->
      agent_id = socket.assigns.agent_id
      :ok = ConnectionManager.heartbeat(agent_id)
      Agents.update_heartbeat(agent_id)

      {:reply,
       {:ok, %{status: "alive", timestamp: DateTime.utc_now() |> DateTime.truncate(:second)}},
       socket}
    end)
  end

  def handle_in("audit:batch", payload, socket) do
    with_runtime_authorized(socket, fn ->
      cond do
        "access_audit_v1" not in (socket.assigns[:runtime_capabilities] || []) ->
          {:reply, {:error, %{reason: "unsupported_schema"}}, socket}

        not is_map(payload) or Enum.any?(Map.keys(payload), &(&1 not in ["events", "health"])) ->
          {:reply, {:error, %{reason: "invalid_event"}}, socket}

        true ->
          audit_batch_reply(socket, payload)
      end
    end)
  rescue
    error ->
      # Exception messages can contain request data; expose only the bounded
      # operational failure and the exception type to the server log.
      Logger.error("Access audit ingestion failed (#{inspect(error.__struct__)})")
      {:reply, {:error, %{reason: "audit_unavailable"}}, socket}
  end

  def handle_in("secret:read_local", payload, socket) do
    with_runtime_authorized(socket, fn ->
      allowed = ~w(path known_revision audit_request_id audit_attempt_id)

      cond do
        "local_socket_read_v1" not in (socket.assigns[:runtime_capabilities] || []) ->
          rejected_read_reply(socket, nil, audit_correlation(payload), :incompatible_version)

        not is_map(payload) or Enum.any?(Map.keys(payload), &(&1 not in allowed)) ->
          rejected_read_reply(socket, nil, audit_correlation(payload), :invalid_request)

        not is_binary(payload["path"]) or payload["path"] == "" ->
          rejected_read_reply(socket, nil, audit_correlation(payload), :invalid_request)

        true ->
          local_read_reply(socket, payload)
      end
    end)
  rescue
    _ -> {:reply, {:error, %{reason: "UNAVAILABLE"}}, socket}
  end

  def handle_in("secret:read", %{"path" => secret_path} = payload, socket)
      when is_binary(secret_path) and secret_path != "" do
    with_runtime_authorized(socket, fn ->
      static_read_reply(socket, secret_path, payload)
    end)
  rescue
    _ -> {:reply, {:error, %{reason: "UNAVAILABLE"}}, socket}
  end

  def handle_in("secret:read", payload, socket) do
    with_runtime_authorized(socket, fn ->
      rejected_read_reply(socket, nil, audit_correlation(payload), :invalid_request)
    end)
  rescue
    _ -> {:reply, {:error, %{reason: "UNAVAILABLE"}}, socket}
  end

  def handle_in("secret:lease_renew", %{"lease_id" => lease_id}, socket) do
    with_runtime_authorized(socket, fn ->
      case LaunchProfile.check(:dynamic_secrets) do
        :ok ->
          {:reply, {:ok, %{lease_id: lease_id, renewed: true}}, socket}

        {:error, :feature_unavailable} ->
          {:reply, {:error, %{reason: "feature_unavailable"}}, socket}
      end
    end)
  end

  def handle_in("pki:client_auth_bundle:get", _payload, socket) do
    with_runtime_authorized(socket, fn ->
      case SecretHub.Core.PKI.ClientAuth.current_bundle() do
        {:ok, bundle} ->
          last_seq =
            case socket.assigns[:agent_id] do
              agent_id when is_binary(agent_id) ->
                case SecretHub.Core.PKI.ClientAuth.get_agent_receipt(agent_id) do
                  {:ok, receipt} -> receipt.observation_sequence
                  _ -> nil
                end

              _ ->
                nil
            end

          payload =
            if is_integer(last_seq) do
              Map.put(bundle, "last_accepted_sequence", last_seq)
            else
              bundle
            end

          {:reply, {:ok, payload}, socket}

        {:error, reason} ->
          {:reply, {:error, %{reason: to_string(reason)}}, socket}
      end
    end)
  end

  def handle_in("pki:client_auth_bundle:receipt", payload, socket) do
    with_runtime_authorized(socket, fn ->
      attrs = Map.put(payload, "agent_id", socket.assigns.agent_id)

      case SecretHub.Core.PKI.ClientAuth.record_bundle_receipt(attrs) do
        {:ok, _receipt} ->
          {:reply, {:ok, %{status: "recorded"}}, socket}

        {:error, reason} ->
          {:reply, {:error, %{reason: to_string(reason)}}, socket}
      end
    end)
  end

  def handle_in("agent:status", _payload, socket) do
    with_runtime_authorized(socket, fn ->
      Logger.info("Agent status event", agent_id: socket.assigns.agent_id)
      {:reply, :ok, socket}
    end)
  end

  def handle_in("error:reported", _payload, socket) do
    with_runtime_authorized(socket, fn ->
      Logger.warning("Agent reported error", agent_id: socket.assigns.agent_id)
      {:reply, :ok, socket}
    end)
  end

  def handle_in("ssh:" <> operation, payload, socket)
      when operation in [
             "identities",
             "authorize_sign",
             "authorized_keys",
             "known_hosts",
             "inventory"
           ] do
    with_runtime_authorized(socket, fn ->
      negotiated = Map.get(socket.assigns, :runtime_capabilities, [])

      supported =
        case operation do
          "inventory" -> Enum.any?(["ssh_lookup_v1", "ssh_signing_v1"], &(&1 in negotiated))
          op when op in ["identities", "authorize_sign"] -> "ssh_signing_v1" in negotiated
          _ -> "ssh_lookup_v1" in negotiated
        end

      cond do
        not supported ->
          {:reply, {:error, %{reason: "SSH_UNAVAILABLE"}}, socket}

        not is_map(payload) ->
          {:reply, {:error, %{reason: "FORBIDDEN"}}, socket}

        true ->
          identity = %{
            agent_id: socket.assigns.agent_id,
            certificate_id: socket.assigns.certificate_id
          }

          case SecretHub.Core.SSH.runtime_operation(identity, operation, payload) do
            {:ok, result} ->
              with_runtime_authorized(socket, fn -> {:reply, {:ok, result}, socket} end)

            {:error, :sealed} ->
              {:reply, {:error, %{reason: "VAULT_SEALED"}}, socket}

            {:error, :capability_unavailable} ->
              {:reply, {:error, %{reason: "SSH_UNAVAILABLE"}}, socket}

            {:error, reason} when reason in [:denied, :invalid_request] ->
              {:reply, {:error, %{reason: "FORBIDDEN"}}, socket}

            _ ->
              {:reply, {:error, %{reason: "UNAVAILABLE"}}, socket}
          end
      end
    end)
  rescue
    _ -> {:reply, {:error, %{reason: "UNAVAILABLE"}}, socket}
  end

  def handle_in(event, _payload, socket) do
    {:reply, {:error, %{reason: "unknown_event", event: event}}, socket}
  end

  @impl true
  def handle_info({:ssh_policy_changed, revision}, socket) do
    push(socket, "ssh:policy_changed", %{revision: revision})
    {:noreply, socket}
  end

  def handle_info({:uds_auth_floor_changed, payload}, socket) do
    push(socket, "agent:uds_auth_floor", payload)
    {:noreply, socket}
  end

  @impl true
  def handle_info({:client_auth_bundle_updated, payload}, socket) do
    push(socket, "pki:client_auth_bundle:updated", payload)
    {:noreply, socket}
  end

  @impl true
  def handle_info({:secrethub_agent_disconnect, reason}, socket) do
    {:stop, {:shutdown, reason}, socket}
  end

  @impl true
  def terminate(reason, socket) do
    if agent_id = socket.assigns[:agent_id] do
      case ConnectionManager.unregister_connection_for_pid(agent_id, self(), reason) do
        :ok -> Agents.mark_disconnected(agent_id)
        :missing -> Agents.mark_disconnected(agent_id)
        :stale -> :ok
      end
    end

    :ok
  end

  defp fetch_assign(socket, key) do
    case socket.assigns[key] do
      nil -> {:error, :missing_assign}
      value -> {:ok, value}
    end
  end

  defp authorize_join(agent_id, cert_id, capabilities) do
    Repo.transaction(fn ->
      with {:ok, _} <- Agents.mark_trusted_connected(agent_id, cert_id),
           :ok <-
             UpgradeGates.record_agent_runtime_capabilities(
               %{agent_id: agent_id, certificate_id: cert_id},
               capabilities
             ) do
        :ok
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, :ok} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp local_read_reply(socket, payload) do
    identity = %{agent_id: socket.assigns.agent_id, certificate_id: socket.assigns.certificate_id}
    correlation = audit_correlation(payload)

    with {:ok, principal} <-
           RuntimePrincipal.resolve_agent_runtime_principal(identity, correlation),
         {:ok, result} <-
           RuntimeAuthorization.authorize_agent_static_read(
             principal,
             payload["path"],
             payload["known_revision"],
             correlation
           ) do
      {:reply, {:ok, result}, socket}
    else
      {:error, reason} -> {:reply, {:error, application_failure(reason)}, socket}
    end
  end

  defp application_read_reply(socket, path, payload) do
    identity = %{agent_id: socket.assigns.agent_id, certificate_id: socket.assigns.certificate_id}
    correlation = audit_correlation(payload)

    with version when version in [1, 2] <- payload["local_auth_version"],
         {:ok, principal} <-
           RuntimePrincipal.resolve_runtime_principal(
             identity,
             payload["app_id"],
             payload["certificate_fingerprint"],
             correlation
           ),
         {:ok, result} <-
           RuntimeAuthorization.authorize_static_read(
             %{principal | local_auth_version: version},
             path,
             payload["known_revision"],
             correlation
           ) do
      {:reply, {:ok, result}, socket}
    else
      {:error, reason} -> {:reply, {:error, application_failure(reason)}, socket}
      _ -> rejected_read_reply(socket, path, correlation, :incompatible_version)
    end
  rescue
    _ -> {:reply, {:error, %{reason: "UNAVAILABLE"}}, socket}
  end

  defp static_read_reply(socket, path, payload) do
    cond do
      Map.has_key?(payload, "app_id") or Map.has_key?(payload, "certificate_fingerprint") ->
        application_read_reply(socket, path, payload)

      Application.get_env(:secrethub_core, :launch_profile) == :single_operator ->
        rejected_read_reply(socket, path, audit_correlation(payload), :incompatible_version)

      true ->
        legacy_read_reply(socket, path, audit_correlation(payload))
    end
  end

  defp legacy_read_reply(socket, path, correlation) do
    Repo.transaction(fn ->
      # Serialize the floor check and legacy authorization with cutover writers,
      # holding the shared epoch until the authorized read result commits.
      epoch = Repo.one!(from(e in AuthorizationEpoch, where: e.id == 1, lock: "FOR SHARE"))

      legacy_read_at_floor(epoch, socket, path, correlation)
    end)
    |> case do
      {:ok, reply} -> reply
      {:error, _} -> {:reply, {:error, %{reason: "UNAVAILABLE"}}, socket}
    end
  end

  defp legacy_read_at_floor(%{minimum_uds_auth_version: 2}, socket, path, correlation),
    do: rejected_read_reply(socket, path, correlation, :incompatible_version)

  defp legacy_read_at_floor(_, socket, path, correlation),
    do: with_runtime_authorized(socket, fn -> read_secret_reply(socket, path, correlation) end)

  defp application_error(:incompatible_version), do: "INCOMPATIBLE_VERSION"
  defp application_error(:sealed), do: "VAULT_SEALED"
  defp application_error(:permission_denied), do: "FORBIDDEN"

  defp application_error(reason) when reason in [:revoked, :disabled, :expired],
    do: "UNAUTHORIZED"

  defp application_error(reason)
       when reason in [
              :invalid_principal,
              :invalid_fingerprint,
              :invalid_application,
              :invalid_agent,
              :invalid_certificate
            ],
       do: "UNAUTHORIZED"

  defp application_error(reason)
       when reason in [:invalid_request, :invalid_path, :invalid_revision, :not_found],
       do: "FORBIDDEN"

  defp application_error(_), do: "UNAVAILABLE"

  defp application_failure(reason) do
    denied =
      reason in [
        :permission_denied,
        :invalid_path,
        :invalid_revision,
        :invalid_principal,
        :invalid_fingerprint,
        :invalid_application,
        :invalid_agent,
        :invalid_certificate,
        :incompatible_version,
        :revoked,
        :disabled,
        :expired
      ]

    %{
      reason: application_error(reason),
      audit_reason_code: Event.reason(reason),
      audit_outcome: if(denied, do: "denied", else: "error")
    }
  end

  defp read_secret_reply(socket, secret_path, correlation) do
    # The original helper has independent policy and Vault checks. Require the
    # new observation transaction to commit before any of its data is released.
    case audited_legacy_read(socket, secret_path, correlation) do
      {:ok, secret_data} ->
        # Deliberate second check: authorization may have been revoked
        # while the secret was being read; never release decrypted data
        # past a revocation.
        with_runtime_authorized(socket, fn ->
          {:reply, {:ok, %{path: secret_path, data: secret_data}}, socket}
        end)

      {:error, reason} ->
        {:reply, {:error, %{reason: application_error(reason), path: secret_path}}, socket}
    end
  end

  defp audited_legacy_read(socket, path, correlation) do
    attrs =
      Map.merge(correlation, %{
        agent_id: socket.assigns.agent_id,
        secret_path: Event.safe_path(path),
        phase: "core_decision",
        identity_status: "unverified",
        attribution: "none",
        outcome: "unknown",
        reason_code: "none",
        operation: "read",
        cache_status: "none"
      })

    Repo.transaction(fn ->
      # Acquire access/chain locks before the legacy helper's unchecked append.
      record_legacy_observation!(%{attrs | phase: "admitted"})

      result = Secrets.get_secret_for_entity(socket.assigns.agent_id, path, %{})
      {outcome, reason} = legacy_read_outcome(result)
      decision = %{attrs | outcome: outcome, reason_code: reason}
      record_legacy_observation!(decision)

      if outcome == "success" do
        record_legacy_observation!(%{decision | phase: "core_access"})
      end

      result
    end)
    |> case do
      {:ok, result} -> result
      {:error, _} -> {:error, :audit_unavailable}
    end
  end

  defp record_legacy_observation!(attrs) do
    case AccessAudit.record_core(attrs) do
      {:ok, _} -> :ok
      _ -> Repo.rollback(:audit_unavailable)
    end
  end

  defp legacy_read_outcome({:ok, _}), do: {"success", "allowed"}
  defp legacy_read_outcome({:error, :permission_denied}), do: {"denied", "permission_denied"}
  defp legacy_read_outcome({:error, reason}), do: {"error", Event.reason(reason)}

  defp rejected_read_reply(socket, path, correlation, reason) do
    attrs =
      Map.merge(correlation, %{
        agent_id: socket.assigns.agent_id,
        secret_path: Event.safe_path(path),
        phase: "core_decision",
        identity_status: "unverified",
        attribution: "none",
        outcome: "denied",
        reason_code: Event.reason(reason)
      })

    case AccessAudit.record_core(attrs) do
      {:ok, _} -> {:reply, {:error, %{reason: application_error(reason)}}, socket}
      {:error, _} -> {:reply, {:error, %{reason: "UNAVAILABLE"}}, socket}
    end
  end

  defp audit_correlation(payload) when is_map(payload) do
    Map.new([request_id: "audit_request_id", attempt_id: "audit_attempt_id"], fn {field, key} ->
      id =
        case Ecto.UUID.cast(payload[key]) do
          {:ok, id} -> id
          :error -> Ecto.UUID.generate()
        end

      {field, id}
    end)
  end

  defp audit_correlation(_), do: audit_correlation(%{})

  defp audit_batch_reply(socket, payload) do
    identity = %{
      agent_id: socket.assigns.agent_id,
      certificate_id: socket.assigns.certificate_id
    }

    case AccessAudit.ingest(identity, payload["events"], payload["health"]) do
      {:ok, acknowledgement} ->
        Telemetry.emit(
          :ingestion_result,
          %{count: 1, duplicates: length(acknowledgement.duplicates)},
          %{source: "core", outcome: "success"}
        )

        {:reply, {:ok, acknowledgement}, socket}

      {:error, reason} ->
        disposition = audit_error(reason)

        Telemetry.emit(:ingestion_result, %{count: 1}, %{
          source: "core",
          outcome: "error",
          reason_code: disposition
        })

        {:reply, {:error, %{reason: disposition}}, socket}
    end
  end

  defp audit_error(reason) when reason in [:event_conflict, :sequence_conflict],
    do: "event_conflict"

  defp audit_error(:outside_retention), do: "outside_retention"

  defp audit_error(reason) when reason in [:storage_unavailable, :audit_unavailable],
    do: "audit_unavailable"

  defp audit_error(_), do: "invalid_event"

  defp with_runtime_authorized(socket, callback) do
    case Agents.authorize_runtime(socket.assigns.agent_id, socket.assigns.certificate_id) do
      :ok ->
        callback.()

      {:error, reason} ->
        {:stop, {:shutdown, reason}, {:error, runtime_unauthorized_payload(reason)}, socket}
    end
  end

  defp runtime_unauthorized_payload(_reason) do
    %{reason: "runtime_not_authorized"}
  end
end
