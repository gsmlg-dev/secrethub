defmodule SecretHub.Web.AgentRuntimeChannel do
  @moduledoc """
  Trusted Agent runtime protocol channel.
  """

  use SecretHub.Web, :channel
  require Logger

  alias SecretHub.Core.Agents
  alias SecretHub.Core.Agents.ConnectionManager
  alias SecretHub.Core.Secrets

  @impl true
  def join("agent:runtime", _payload, socket) do
    with {:ok, agent_id} <- fetch_assign(socket, :agent_id),
         {:ok, cert_serial} <- fetch_assign(socket, :certificate_serial),
         {:ok, cert_fingerprint} <- fetch_assign(socket, :certificate_fingerprint),
         {:ok, cert_id} <- fetch_assign(socket, :certificate_id),
         {:ok, _agent} <- Agents.mark_trusted_connected(agent_id, cert_id) do
      metadata = %{
        certificate_id: cert_id,
        certificate_fingerprint: cert_fingerprint,
        certificate_serial: cert_serial,
        peer: socket.assigns[:peer]
      }

      :ok = ConnectionManager.register_connection(agent_id, cert_serial, self(), metadata)

      {:ok,
       %{
         status: "accepted",
         agent_id: agent_id,
         certificate_serial: cert_serial,
         certificate_fingerprint: cert_fingerprint,
         certificate_id: cert_id
       }, socket}
    else
      {:error, :missing_assign} -> {:error, %{reason: "mtls_required"}}
      {:error, reason} -> {:error, runtime_unauthorized_payload(reason)}
    end
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

  def handle_in("secret:read", %{"path" => secret_path}, socket) do
    with_runtime_authorized(socket, fn ->
      agent_id = socket.assigns.agent_id

      case Secrets.get_secret_for_entity(agent_id, secret_path, %{}) do
        {:ok, secret_data} ->
          # Deliberate second check: authorization may have been revoked
          # while the secret was being read; never release decrypted data
          # past a revocation.
          with_runtime_authorized(socket, fn ->
            {:reply, {:ok, %{path: secret_path, data: secret_data}}, socket}
          end)

        {:error, reason} ->
          {:reply, {:error, %{reason: inspect(reason), path: secret_path}}, socket}
      end
    end)
  end

  def handle_in("secret:lease_renew", %{"lease_id" => lease_id}, socket) do
    with_runtime_authorized(socket, fn ->
      {:reply, {:ok, %{lease_id: lease_id, renewed: true}}, socket}
    end)
  end

  def handle_in("agent:status", payload, socket) do
    with_runtime_authorized(socket, fn ->
      Logger.info("Agent status event", agent_id: socket.assigns.agent_id, payload: payload)
      {:reply, :ok, socket}
    end)
  end

  def handle_in("error:reported", payload, socket) do
    with_runtime_authorized(socket, fn ->
      Logger.warning("Agent reported error", agent_id: socket.assigns.agent_id, payload: payload)
      {:reply, :ok, socket}
    end)
  end

  def handle_in(event, _payload, socket) do
    {:reply, {:error, %{reason: "unknown_event", event: event}}, socket}
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

  defp with_runtime_authorized(socket, callback) do
    case Agents.authorize_runtime(socket.assigns.agent_id, socket.assigns.certificate_id) do
      :ok ->
        callback.()

      {:error, reason} ->
        {:stop, {:shutdown, reason}, {:error, runtime_unauthorized_payload(reason)}, socket}
    end
  end

  defp runtime_unauthorized_payload(reason) do
    %{reason: "runtime_not_authorized", detail: inspect(reason)}
  end
end
