defmodule SecretHub.Web.UserSocket do
  @moduledoc """
  WebSocket handler for agent connections.

  Agents connect via WebSocket to maintain persistent connections for:
  - Authentication and bootstrap
  - Secret requests and updates
  - Heartbeat and health monitoring
  - Real-time notifications
  """

  use Phoenix.Socket

  # Channel routes
  channel "agent:*", SecretHub.Web.AgentChannel

  # Socket params are passed from the client and can be used to verify and authenticate a user.
  # After verification, you can put default assigns into the socket that will be set for all channels.
  @impl true
  def connect(_params, socket, _connect_info) do
    # For now, accept all connections
    # Authentication happens at the channel level
    {:ok, socket}
  end

  # Socket ID is used to identify all sockets for a given user:
  #
  #     def id(socket), do: "user_socket:#{socket.assigns.user_id}"
  #
  # Would allow you to broadcast a "disconnect" event and terminate all active sockets for a given user:
  #
  #     Elixir.SecretHub.Web.Endpoint.broadcast("user_socket:#{user.id}", "disconnect", %{})
  #
  # Returning `nil` makes this socket anonymous.
  @impl true
  def id(socket) do
    # Use agent_id if authenticated, otherwise nil for anonymous
    if socket.assigns[:agent_id] do
      "agent_socket:#{socket.assigns.agent_id}"
    else
      nil
    end
  end
end
