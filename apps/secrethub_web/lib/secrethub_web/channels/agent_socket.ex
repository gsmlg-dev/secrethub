defmodule SecretHub.Web.AgentSocket do
  @moduledoc """
  Phoenix Socket for Agent connections.

  Handles WebSocket connections from SecretHub Agents with mTLS authentication.
  Agents connect using client certificates issued by the SecretHub PKI.

  ## Authentication Flow

  1. Agent establishes mTLS WebSocket connection
  2. Socket extracts client certificate from connection
  3. Certificate is verified (stubbed for now, real PKI in Week 4-5)
  4. Agent ID is extracted from certificate CN (Common Name)
  5. Agent ID is stored in socket assigns for authorization

  ## Security

  - mTLS authentication required
  - Certificate validation (stubbed)
  - Agent ID bound to socket session
  """

  use Phoenix.Socket

  require Logger

  ## Channels
  channel "agent:*", SecretHub.Web.AgentChannel

  @doc """
  Connect callback for Agent socket.

  Extracts and verifies the agent's mTLS certificate, then assigns the agent_id
  to the socket for use in authorization.

  ## Parameters

  - `params` - Connection parameters (unused for now)
  - `socket` - Phoenix.Socket struct
  - `connect_info` - Connection metadata including peer_data with SSL certificate

  ## Returns

  - `{:ok, socket}` with agent_id assigned on success
  - `:error` on authentication failure
  """
  @impl true
  def connect(_params, socket, connect_info) do
    Logger.info("Agent attempting to connect",
      peer: inspect(connect_info[:peer_data])
    )

    # Extract mTLS certificate from connection
    # In development without real certs, we'll use a default agent_id
    # In production with mTLS, extract from connect_info.peer_data.ssl_cert
    case extract_agent_id(connect_info) do
      {:ok, agent_id} ->
        Logger.info("Agent authenticated successfully", agent_id: agent_id)

        socket =
          socket
          |> assign(:agent_id, agent_id)
          |> assign(:connected_at, DateTime.utc_now())

        {:ok, socket}

      {:error, reason} ->
        Logger.warning("Agent authentication failed", reason: reason)
        :error
    end
  end

  @doc """
  Socket ID callback.

  Returns a unique identifier for this socket connection, used for
  tracking and broadcasting to specific agents.
  """
  @impl true
  def id(socket), do: "agent:#{socket.assigns.agent_id}"

  # Private Functions

  defp extract_agent_id(connect_info) do
    # FIXME: Implement real PKI verification in Week 4-5
    # For now, check for agent_id in connection headers or use default

    case List.keyfind(connect_info[:x_headers] || [], "x-agent-id", 0) do
      {"x-agent-id", agent_id} when is_binary(agent_id) ->
        {:ok, agent_id}

      nil ->
        # Default agent for development
        {:ok, "agent-dev-01"}

      _ ->
        {:error, :invalid_agent_id}
    end

    # Future implementation with real mTLS:
    # case connect_info[:peer_data][:ssl_cert] do
    #   nil ->
    #     {:error, :no_certificate}
    #
    #   cert ->
    #     verify_and_extract_agent_id(cert)
    # end
  end

  # Future implementation
  # defp verify_and_extract_agent_id(cert) do
  #   # 1. Verify certificate is signed by our CA
  #   # 2. Check certificate is not revoked
  #   # 3. Validate expiry
  #   # 4. Extract CN (Common Name) as agent_id
  #   # Will be implemented with SecretHub.Core.PKI module
  # end
end
