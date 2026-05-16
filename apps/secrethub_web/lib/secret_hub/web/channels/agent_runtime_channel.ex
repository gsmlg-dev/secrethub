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
         {:ok, cert_serial} <- fetch_assign(socket, :certificate_serial) do
      metadata = %{
        certificate_fingerprint: socket.assigns[:certificate_fingerprint],
        peer: socket.assigns[:peer]
      }

      :ok = ConnectionManager.register_connection(agent_id, cert_serial, self(), metadata)

      {:ok, %{status: "accepted", agent_id: agent_id}, socket}
    else
      {:error, :missing_assign} -> {:error, %{reason: "mtls_required"}}
    end
  end

  def join(_topic, _payload, _socket), do: {:error, %{reason: "unknown_topic"}}

  @impl true
  def handle_in("agent:hello", payload, socket) do
    agent_id = socket.assigns.agent_id
    Agents.update_agent_config(agent_id, %{"runtime_info" => payload})
    {:reply, {:ok, %{event: "agent:accepted"}}, socket}
  end

  def handle_in("agent:heartbeat", _payload, socket) do
    agent_id = socket.assigns.agent_id
    :ok = ConnectionManager.heartbeat(agent_id)
    Agents.update_heartbeat(agent_id)

    {:reply,
     {:ok, %{status: "alive", timestamp: DateTime.utc_now() |> DateTime.truncate(:second)}},
     socket}
  end

  def handle_in("secret:read", %{"path" => secret_path}, socket) do
    agent_id = socket.assigns.agent_id

    case Secrets.get_secret_for_entity(agent_id, secret_path, %{}) do
      {:ok, secret_data} ->
        {:reply, {:ok, %{path: secret_path, data: secret_data}}, socket}

      {:error, reason} ->
        {:reply, {:error, %{reason: inspect(reason), path: secret_path}}, socket}
    end
  end

  def handle_in("secret:lease_renew", %{"lease_id" => lease_id}, socket) do
    {:reply, {:ok, %{lease_id: lease_id, renewed: true}}, socket}
  end

  def handle_in("agent:status", payload, socket) do
    Logger.info("Agent status event", agent_id: socket.assigns.agent_id, payload: payload)
    {:reply, :ok, socket}
  end

  def handle_in("error:reported", payload, socket) do
    Logger.warning("Agent reported error", agent_id: socket.assigns.agent_id, payload: payload)
    {:reply, :ok, socket}
  end

  def handle_in(event, _payload, socket) do
    {:reply, {:error, %{reason: "unknown_event", event: event}}, socket}
  end

  @impl true
  def terminate(reason, socket) do
    if agent_id = socket.assigns[:agent_id] do
      ConnectionManager.unregister_connection(agent_id, reason)
      Agents.mark_disconnected(agent_id)
    end

    :ok
  end

  defp fetch_assign(socket, key) do
    case socket.assigns[key] do
      nil -> {:error, :missing_assign}
      value -> {:ok, value}
    end
  end
end
