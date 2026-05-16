defmodule SecretHub.Web.AgentChannel do
  @moduledoc """
  Phoenix Channel for Agent WebSocket communication.

  Manages persistent WebSocket connections between agents and the core service.
  Agents use this channel to:
  - Authenticate and maintain connection
  - Request secrets
  - Receive secret updates and rotation notifications
  - Send heartbeats

  ## Message Types

  ### From Agent to Core
  - `authenticate` - Initial authentication with RoleID/SecretID or certificate
  - `secret:request` - Request a secret by path
  - `secret:renew` - Renew a lease for a secret
  - `heartbeat` - Keep-alive message

  ### From Core to Agent
  - `authenticated` - Confirmation of successful authentication
  - `secret:granted` - Secret data response
  - `secret:denied` - Access denied response
  - `secret:rotated` - Notification that a secret was rotated
  - `disconnect` - Server-initiated disconnect
  """

  use SecretHub.Web, :channel
  require Logger

  alias SecretHub.Core.Agents
  alias SecretHub.Core.Secrets

  # 90 seconds (3 missed heartbeats)
  @heartbeat_timeout 90_000

  @doc """
  Joins the agent channel.

  Agents must authenticate before they can request secrets.
  """
  def join("agent:lobby", _payload, socket) do
    Logger.info("Agent attempting to join lobby channel")

    # Set up heartbeat monitoring
    schedule_heartbeat_check()

    socket =
      socket
      |> assign(:authenticated, false)
      |> assign(:agent_id, nil)
      |> assign(:last_heartbeat, DateTime.utc_now() |> DateTime.truncate(:second))

    {:ok, %{status: "connected", authenticated: false}, socket}
  end

  def join("agent:" <> agent_id, _payload, _socket) do
    Logger.warning("Rejected direct agent channel join without mTLS", requested_topic: agent_id)
    {:error, %{reason: "trusted_runtime_requires_mtls"}}
  end

  @doc """
  Handles authentication messages from agents.

  Legacy channel authentication is disabled. Trusted runtime traffic must use
  `SecretHub.Web.AgentTrustedSocket` over the mTLS listener.
  """
  def handle_in(event, payload, socket)

  def handle_in("authenticate", _payload, socket) do
    {:reply, {:error, %{reason: "trusted_runtime_requires_mtls"}}, socket}
  end

  # Handles secret request messages from authenticated agents.
  def handle_in("secret:request", %{"path" => secret_path}, socket) do
    if socket.assigns.authenticated do
      handle_secret_request(socket, secret_path)
    else
      {:reply, {:error, %{reason: "not_authenticated"}}, socket}
    end
  end

  # Handles heartbeat messages to keep connection alive.
  def handle_in("heartbeat", _payload, socket) do
    if socket.assigns.authenticated do
      agent_id = socket.assigns.agent_id
      Agents.update_heartbeat(agent_id)
      socket = assign(socket, :last_heartbeat, DateTime.utc_now() |> DateTime.truncate(:second))

      {:reply,
       {:ok, %{status: "alive", timestamp: DateTime.utc_now() |> DateTime.truncate(:second)}},
       socket}
    else
      {:reply, {:error, %{reason: "not_authenticated"}}, socket}
    end
  end

  # Handles lease renewal requests.
  def handle_in("secret:renew", %{"lease_id" => lease_id}, socket) do
    if socket.assigns.authenticated do
      # FIXME: Implement lease renewal logic
      Logger.info("Lease renewal requested: #{lease_id}")

      {:reply,
       {:ok,
        %{
          lease_id: lease_id,
          renewed: true,
          lease_duration: 3600
        }}, socket}
    else
      {:reply, {:error, %{reason: "not_authenticated"}}, socket}
    end
  end

  def handle_in("certificate:request", _payload, socket) do
    {:reply, {:error, %{reason: "trusted_runtime_requires_mtls"}}, socket}
  end

  # Catch-all clause for unknown messages
  def handle_in(event, payload, socket) do
    Logger.warning("Unknown event received: #{event} with payload: #{inspect(payload)}")
    {:reply, {:error, %{reason: "unknown_event"}}, socket}
  end

  @doc """
  Handles agent disconnect.
  """
  def terminate(reason, socket) do
    if socket.assigns.authenticated do
      agent_id = socket.assigns.agent_id
      Logger.info("Agent disconnected: #{agent_id} (reason: #{inspect(reason)})")

      # Mark agent as disconnected
      Agents.mark_disconnected(agent_id)
    end

    :ok
  end

  # Private helper functions

  defp handle_secret_request(socket, secret_path) do
    agent_id = socket.assigns.agent_id
    Logger.debug("Agent #{agent_id} requesting secret: #{secret_path}")

    case find_secret_by_path(secret_path) do
      nil ->
        Logger.warning("Secret not found: #{secret_path}")
        {:reply, {:error, %{reason: "secret_not_found", path: secret_path}}, socket}

      secret ->
        process_secret_access(socket, agent_id, secret_path, secret)
    end
  end

  defp process_secret_access(socket, agent_id, secret_path, secret) do
    case Secrets.get_secret_for_entity(agent_id, secret_path, %{}) do
      {:ok, secret_data} ->
        Logger.info("Secret access granted: #{agent_id} -> #{secret_path}")

        {:reply,
         {:ok,
          %{
            path: secret.secret_path,
            data: secret_data,
            lease_id: Ecto.UUID.generate(),
            lease_duration: secret_ttl_seconds(secret),
            renewable: true
          }}, socket}

      {:error, reason} ->
        Logger.warning("Secret access denied: #{agent_id} -> #{secret_path} (#{reason})")
        {:reply, {:error, %{reason: "access_denied", path: secret_path}}, socket}
    end
  end

  defp schedule_heartbeat_check do
    Process.send_after(self(), :check_heartbeat, @heartbeat_timeout)
  end

  defp secret_ttl_seconds(%{ttl_seconds: seconds}) when is_integer(seconds), do: seconds
  defp secret_ttl_seconds(%{ttl_hours: hours}) when is_integer(hours), do: hours * 3600
  defp secret_ttl_seconds(_secret), do: 0

  def handle_info(:check_heartbeat, socket) do
    if socket.assigns.authenticated do
      last_heartbeat = socket.assigns.last_heartbeat

      cutoff =
        DateTime.add(
          DateTime.utc_now() |> DateTime.truncate(:second),
          -@heartbeat_timeout,
          :millisecond
        )

      if DateTime.compare(last_heartbeat, cutoff) == :lt do
        # No heartbeat received in timeout period
        agent_id = socket.assigns.agent_id
        Logger.warning("Agent heartbeat timeout: #{agent_id}")

        push(socket, "disconnect", %{reason: "heartbeat_timeout"})
        {:stop, :normal, socket}
      else
        # Schedule next check
        schedule_heartbeat_check()
        {:noreply, socket}
      end
    else
      {:noreply, socket}
    end
  end

  defp find_secret_by_path(secret_path) do
    # Query secrets by path
    secrets = Secrets.list_secrets()
    Enum.find(secrets, fn secret -> secret.secret_path == secret_path end)
  end
end
