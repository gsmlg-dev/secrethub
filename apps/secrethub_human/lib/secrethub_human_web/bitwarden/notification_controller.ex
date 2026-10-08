defmodule SecretHub.HumanWeb.Bitwarden.NotificationController do
  use SecretHub.HumanWeb, :controller
  alias SecretHub.HumanWeb.Bitwarden.NotificationSocket
  alias SecretHub.HumanWeb.Bitwarden.Token

  def connect(conn, params) do
    token =
      case get_req_header(conn, "authorization") do
        ["Bearer " <> token] -> token
        _ -> params["access_token"]
      end

    case Token.authenticate(token) do
      {:ok, actor} ->
        conn
        |> WebSockAdapter.upgrade(NotificationSocket, actor,
          timeout: 60_000,
          max_frame_size: 4096
        )
        |> halt()

      {:error, _} ->
        conn |> put_status(401) |> json(%{error: "unauthorized"})
    end
  end
end
