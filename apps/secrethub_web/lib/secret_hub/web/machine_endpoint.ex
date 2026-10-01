defmodule SecretHub.Web.MachineEndpoint do
  @moduledoc "Machine HTTP ingress with no management routes or browser socket."
  use Phoenix.Endpoint, otp_app: :secrethub_web

  plug SecretHub.Web.Plugs.NoStore
  plug Plug.RequestId
  plug Plug.Telemetry, event_prefix: [:phoenix, :machine_endpoint]

  plug Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Phoenix.json_library()

  plug Plug.Head
  plug SecretHub.Web.MachineRouter
end
