defmodule SecretHub.Web.AgentEndpoint do
  use Phoenix.Endpoint, otp_app: :secrethub_web

  socket "/agent/socket", SecretHub.Web.AgentTrustedSocket,
    websocket: [
      connect_info: [:peer_data]
    ],
    longpoll: false

  plug Plug.RequestId
  plug Plug.Telemetry, event_prefix: [:phoenix, :agent_endpoint]
end
