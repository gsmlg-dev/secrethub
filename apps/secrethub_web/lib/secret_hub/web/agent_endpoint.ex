defmodule SecretHub.Web.AgentEndpoint do
  @moduledoc """
  Agent HTTPS enrollment and certificate-authenticated WebSocket runtime endpoint.
  """

  use Phoenix.Endpoint, otp_app: :secrethub_web

  socket "/agent/socket", SecretHub.Web.AgentTrustedSocket,
    websocket: [
      connect_info: [:peer_data]
    ],
    longpoll: false

  plug SecretHub.Web.Plugs.NoStore
  plug Plug.RequestId
  plug Plug.Telemetry, event_prefix: [:phoenix, :agent_endpoint]

  plug Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Phoenix.json_library()

  plug Plug.Head
  plug SecretHub.Web.MachineRouter
end
