defmodule SecretHub.Web.AgentRuntimeChannel do
  @moduledoc """
  Trusted Agent runtime protocol channel.
  """

  use SecretHub.Web, :channel
  import Ecto.Query
  require Logger

  alias SecretHub.Core.Agents
  alias SecretHub.Core.Agents.ConnectionManager
  alias SecretHub.Core.Repo
  alias SecretHub.Core.RuntimeAuthorization
  alias SecretHub.Core.RuntimePrincipal
  alias SecretHub.Core.Secrets
  alias SecretHub.Core.UpgradeGates
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

      {:ok,
       %{
         status: "accepted",
         minimum_uds_auth_version: UpgradeGates.minimum_uds_auth_version(),
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

  def handle_in("secret:read", %{"path" => secret_path} = payload, socket)
      when is_binary(secret_path) and secret_path != "" do
    with_runtime_authorized(socket, fn ->
      static_read_reply(socket, secret_path, payload)
    end)
  rescue
    _ -> {:reply, {:error, %{reason: "UNAVAILABLE"}}, socket}
  end

  def handle_in("secret:read", _payload, socket) do
    with_runtime_authorized(socket, fn -> {:reply, {:error, %{reason: "FORBIDDEN"}}, socket} end)
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

  def handle_in(event, _payload, socket) do
    {:reply, {:error, %{reason: "unknown_event", event: event}}, socket}
  end

  @impl true
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

  defp application_read_reply(socket, path, payload) do
    identity = %{agent_id: socket.assigns.agent_id, certificate_id: socket.assigns.certificate_id}

    with version when version in [1, 2] <- payload["local_auth_version"],
         {:ok, principal} <-
           RuntimePrincipal.resolve_runtime_principal(
             identity,
             payload["app_id"],
             payload["certificate_fingerprint"]
           ),
         {:ok, result} <-
           RuntimeAuthorization.authorize_static_read(
             %{principal | local_auth_version: version},
             path,
             payload["known_revision"]
           ) do
      {:reply, {:ok, result}, socket}
    else
      {:error, reason} -> {:reply, {:error, %{reason: application_error(reason)}}, socket}
      _ -> {:reply, {:error, %{reason: "INCOMPATIBLE_VERSION"}}, socket}
    end
  rescue
    _ -> {:reply, {:error, %{reason: "UNAVAILABLE"}}, socket}
  end

  defp static_read_reply(socket, path, payload) do
    cond do
      Map.has_key?(payload, "app_id") or Map.has_key?(payload, "certificate_fingerprint") ->
        application_read_reply(socket, path, payload)

      Application.get_env(:secrethub_core, :launch_profile) == :single_operator ->
        {:reply, {:error, %{reason: "INCOMPATIBLE_VERSION"}}, socket}

      true ->
        legacy_read_reply(socket, path)
    end
  end

  defp legacy_read_reply(socket, path) do
    Repo.transaction(fn ->
      # Serialize the floor check and legacy authorization with cutover writers,
      # holding the shared epoch until the authorized read result commits.
      epoch = Repo.one!(from(e in AuthorizationEpoch, where: e.id == 1, lock: "FOR SHARE"))

      if epoch.minimum_uds_auth_version == 2 do
        {:reply, {:error, %{reason: "INCOMPATIBLE_VERSION"}}, socket}
      else
        with_runtime_authorized(socket, fn -> read_secret_reply(socket, path) end)
      end
    end)
    |> case do
      {:ok, reply} -> reply
      {:error, _} -> {:reply, {:error, %{reason: "UNAVAILABLE"}}, socket}
    end
  end

  defp application_error(:incompatible_version), do: "INCOMPATIBLE_VERSION"
  defp application_error(:sealed), do: "VAULT_SEALED"
  defp application_error(:permission_denied), do: "FORBIDDEN"

  defp application_error(reason)
       when reason in [
              :invalid_principal,
              :invalid_fingerprint,
              :invalid_application,
              :invalid_agent,
              :invalid_certificate
            ],
       do: "UNAUTHORIZED"

  defp application_error(reason) when reason in [:invalid_path, :invalid_revision, :not_found],
    do: "FORBIDDEN"

  defp application_error(_), do: "UNAVAILABLE"

  defp read_secret_reply(socket, secret_path) do
    case Secrets.get_secret_for_entity(socket.assigns.agent_id, secret_path, %{}) do
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
