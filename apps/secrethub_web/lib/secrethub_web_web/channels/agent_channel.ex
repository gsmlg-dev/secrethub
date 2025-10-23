defmodule SecretHub.WebWeb.AgentChannel do
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

  use SecretHub.WebWeb, :channel
  require Logger

  alias SecretHub.Core.Auth.AppRole
  alias SecretHub.Core.Agents
  alias SecretHub.Core.Secrets

  # 30 seconds
  @heartbeat_interval 30_000
  # 90 seconds (3 missed heartbeats)
  @heartbeat_timeout 90_000

  @doc """
  Joins the agent channel.

  Agents must authenticate before they can request secrets.
  """
  def join("agent:lobby", _payload, socket) do
    Logger.info("Agent attempting to join channel")

    # Set up heartbeat monitoring
    schedule_heartbeat_check()

    socket =
      socket
      |> assign(:authenticated, false)
      |> assign(:agent_id, nil)
      |> assign(:last_heartbeat, DateTime.utc_now())

    {:ok, %{status: "connected", authenticated: false}, socket}
  end

  def join("agent:" <> _agent_id, _payload, _socket) do
    {:error, %{reason: "unauthorized"}}
  end

  @doc """
  Handles authentication messages from agents.

  Supports both AppRole (RoleID/SecretID) and certificate-based authentication.
  """
  def handle_in("authenticate", %{"role_id" => role_id, "secret_id" => secret_id}, socket) do
    source_ip = get_source_ip(socket)

    case AppRole.login(role_id, secret_id, source_ip) do
      {:ok, auth_result} ->
        # Create or update agent record
        case Agents.bootstrap_agent(role_id, secret_id, %{
               "name" => auth_result.role_name,
               "ip_address" => source_ip,
               "user_agent" => "SecretHub Agent v1.0"
             }) do
          {:ok, agent} ->
            socket =
              socket
              |> assign(:authenticated, true)
              |> assign(:agent_id, agent.agent_id)
              |> assign(:role_name, auth_result.role_name)
              |> assign(:policies, auth_result.policies)
              |> assign(:token, auth_result.token)
              |> assign(:last_heartbeat, DateTime.utc_now())

            Logger.info("Agent authenticated: #{agent.agent_id} (#{auth_result.role_name})")

            {:reply,
             {:ok,
              %{
                status: "authenticated",
                agent_id: agent.agent_id,
                role_name: auth_result.role_name,
                policies: auth_result.policies,
                token: auth_result.token
              }}, socket}

          {:error, reason} ->
            Logger.warning("Agent bootstrap failed: #{inspect(reason)}")
            {:reply, {:error, %{reason: "authentication_failed"}}, socket}
        end

      {:error, reason} ->
        Logger.warning("AppRole login failed: #{reason}")
        {:reply, {:error, %{reason: "invalid_credentials"}}, socket}
    end
  end

  def handle_in("authenticate", _payload, socket) do
    {:reply, {:error, %{reason: "invalid_authentication_payload"}}, socket}
  end

  @doc """
  Handles secret request messages from authenticated agents.
  """
  def handle_in("secret:request", %{"path" => secret_path}, socket) do
    unless socket.assigns.authenticated do
      {:reply, {:error, %{reason: "not_authenticated"}}, socket}
    else
      agent_id = socket.assigns.agent_id

      Logger.debug("Agent #{agent_id} requesting secret: #{secret_path}")

      # Find secret by path
      case find_secret_by_path(secret_path) do
        nil ->
          Logger.warning("Secret not found: #{secret_path}")
          {:reply, {:error, %{reason: "secret_not_found", path: secret_path}}, socket}

        secret ->
          # Check agent access via policies
          case Agents.check_secret_access(agent_id, secret) do
            :ok ->
              # TODO: Decrypt secret value using unsealed master key
              # For now, return mock data
              Logger.info("Secret access granted: #{agent_id} -> #{secret_path}")

              {:reply,
               {:ok,
                %{
                  path: secret.secret_path,
                  data: %{
                    # TODO: Return actual decrypted secret data
                    value: "mock_secret_value",
                    metadata: secret.metadata
                  },
                  lease_id: Ecto.UUID.generate(),
                  lease_duration: secret.ttl_hours * 3600,
                  renewable: true
                }}, socket}

            {:error, reason} ->
              Logger.warning("Secret access denied: #{agent_id} -> #{secret_path} (#{reason})")
              {:reply, {:error, %{reason: "access_denied", path: secret_path}}, socket}
          end
      end
    end
  end

  @doc """
  Handles heartbeat messages to keep connection alive.
  """
  def handle_in("heartbeat", _payload, socket) do
    unless socket.assigns.authenticated do
      {:reply, {:error, %{reason: "not_authenticated"}}, socket}
    else
      agent_id = socket.assigns.agent_id

      # Update agent heartbeat
      Agents.update_heartbeat(agent_id)

      socket = assign(socket, :last_heartbeat, DateTime.utc_now())

      {:reply, {:ok, %{status: "alive", timestamp: DateTime.utc_now()}}, socket}
    end
  end

  @doc """
  Handles lease renewal requests.
  """
  def handle_in("secret:renew", %{"lease_id" => lease_id}, socket) do
    unless socket.assigns.authenticated do
      {:reply, {:error, %{reason: "not_authenticated"}}, socket}
    else
      # TODO: Implement lease renewal logic
      Logger.info("Lease renewal requested: #{lease_id}")

      {:reply,
       {:ok,
        %{
          lease_id: lease_id,
          renewed: true,
          lease_duration: 3600
        }}, socket}
    end
  end

  @doc """
  Handles unknown messages.
  """
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

  defp schedule_heartbeat_check do
    Process.send_after(self(), :check_heartbeat, @heartbeat_timeout)
  end

  def handle_info(:check_heartbeat, socket) do
    if socket.assigns.authenticated do
      last_heartbeat = socket.assigns.last_heartbeat
      cutoff = DateTime.add(DateTime.utc_now(), -@heartbeat_timeout, :millisecond)

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

  defp get_source_ip(socket) do
    # Extract source IP from socket transport
    case Phoenix.Socket.get_transport_pid(socket) do
      pid when is_pid(pid) ->
        # TODO: Extract actual IP from transport
        "unknown"

      _ ->
        "unknown"
    end
  end

  defp find_secret_by_path(secret_path) do
    # Query secrets by path
    secrets = Secrets.list_secrets()
    Enum.find(secrets, fn secret -> secret.secret_path == secret_path end)
  end
end
