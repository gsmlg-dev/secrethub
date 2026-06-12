defmodule SecretHub.Web.AgentEndpoint do
  @moduledoc """
  Dedicated mTLS endpoint for trusted Agent runtime connections.
  """

  use Phoenix.Endpoint, otp_app: :secrethub_web

  socket "/agent/socket", SecretHub.Web.AgentTrustedSocket,
    websocket: [
      connect_info: [:peer_data]
    ],
    longpoll: false

  plug Plug.RequestId
  plug Plug.Telemetry, event_prefix: [:phoenix, :agent_endpoint]
end
