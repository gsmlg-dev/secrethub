defmodule SecretHub.HumanWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :secrethub_human

  plug(Plug.Static,
    at: "/human/assets",
    from: {:secrethub_human, "priv/static"},
    only: ~w(human.js human.css)
  )

  plug(Plug.RequestId)
  plug(SecretHub.HumanWeb.Plugs.CORS)
  plug(Plug.Telemetry, event_prefix: [:phoenix, :endpoint])

  plug(Plug.Parsers,
    parsers: [:urlencoded, :json],
    pass: ["*/*"],
    json_decoder: Phoenix.json_library(),
    body_reader: {SecretHub.HumanWeb.Plugs.AttachmentBodyReader, :read_body, []}
  )

  plug(Plug.MethodOverride)
  plug(Plug.Head)
  plug(SecretHub.HumanWeb.Router)
end
