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
  alias SecretHub.Core.Auth.AppRole
  alias SecretHub.Core.Secrets

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
      |> assign(:last_heartbeat, DateTime.utc_now() |> DateTime.truncate(:second))

    {:ok, %{status: "connected", authenticated: false}, socket}
  end

  def join("agent:" <> _agent_id, _payload, _socket) do
    {:error, %{reason: "unauthorized"}}
  end

  @doc """
  Handles authentication messages from agents.

  Supports both AppRole (RoleID/SecretID) and certificate-based authentication.
  """
  def handle_in(event, payload, socket)

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
              |> assign(:last_heartbeat, DateTime.utc_now() |> DateTime.truncate(:second))

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

  # Handles CSR submission from agents during bootstrap.
  # Agents submit CSR after authenticating with AppRole to receive a client certificate.
  def handle_in("certificate:request", %{"csr" => csr_pem}, socket) do
    if socket.assigns.authenticated do
      agent_id = socket.assigns.agent_id
      Logger.info("Agent #{agent_id} requesting certificate signing")

      case sign_agent_csr(csr_pem, agent_id) do
        {:ok, signed_cert, ca_chain} ->
          Logger.info("Certificate issued for agent: #{agent_id}")

          {:reply,
           {:ok,
            %{
              certificate: signed_cert,
              ca_chain: ca_chain,
              valid_until: extract_validity(signed_cert)
            }}, socket}

        {:error, reason} ->
          Logger.error("Failed to sign CSR for agent #{agent_id}: #{inspect(reason)}")
          {:reply, {:error, %{reason: "certificate_signing_failed"}}, socket}
      end
    else
      {:reply, {:error, %{reason: "not_authenticated"}}, socket}
    end
  end

  def handle_in("certificate:request", _payload, socket) do
    {:reply, {:error, %{reason: "invalid_csr_payload"}}, socket}
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
            lease_duration: secret.ttl_hours * 3600,
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

  defp get_source_ip(_socket) do
    # Extract source IP from socket transport
    # FIXME: Implement proper IP extraction from Phoenix.Socket
    # Phoenix.Socket doesn't expose get_transport_pid/1, need alternative approach
    "unknown"
  end

  defp find_secret_by_path(secret_path) do
    # Query secrets by path
    secrets = Secrets.list_secrets()
    Enum.find(secrets, fn secret -> secret.secret_path == secret_path end)
  end

  defp sign_agent_csr(csr_pem, agent_id) do
    alias SecretHub.Core.PKI.CA

    with {:ok, agent} <- fetch_agent(agent_id),
         {:ok, certificate} <- sign_csr_for_agent(csr_pem, agent, agent_id),
         {:ok, ca_chain} <- fetch_ca_chain() do
      {:ok, certificate.certificate_pem, ca_chain}
    end
  end

  defp fetch_agent(agent_id) do
    case Agents.get_agent(agent_id) do
      nil -> {:error, "Agent not found"}
      agent -> {:ok, agent}
    end
  end

  defp sign_csr_for_agent(csr_pem, agent, agent_id) do
    alias SecretHub.Core.PKI.CA

    # Get the CA certificate ID - for now use nil as placeholder
    # TODO: Implement proper CA certificate selection
    ca_cert_id = nil

    CA.sign_csr(
      csr_pem,
      ca_cert_id,
      :agent_client,
      entity_id: agent.id,
      entity_type: "agent",
      common_name: agent_id,
      organization: "SecretHub Agents",
      ttl_days: 90
    )
  end

  defp fetch_ca_chain do
    alias SecretHub.Core.PKI.CA

    case CA.get_ca_chain() do
      {:ok, ca_chain} ->
        {:ok, ca_chain}

      {:error, reason} = error ->
        Logger.error("Failed to retrieve CA chain: #{inspect(reason)}")
        error
    end
  end

  defp extract_validity(_cert_pem) do
    # Parse certificate and extract expiration date
    # FIXME: Implement actual certificate parsing
    # For now, return 90 days from now
    DateTime.utc_now()
    |> DateTime.truncate(:second)
    |> DateTime.add(90 * 24 * 3600, :second)
    |> DateTime.to_iso8601()
  end
end
