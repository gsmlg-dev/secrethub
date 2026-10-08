defmodule SecretHub.HumanWeb.Plugs.Authenticate do
  alias SecretHub.HumanWeb.Bitwarden.Token
  @moduledoc false
  import Plug.Conn
  def init(opts), do: opts

  def call(conn, _opts) do
    with ["Bearer " <> token] <- get_req_header(conn, "authorization"),
         {:ok, actor} <- Token.authenticate(token) do
      conn |> assign(:human_actor, actor) |> assign(:human_access_token, token)
    else
      _ ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(401, Jason.encode!(%{error: "unauthorized"}))
        |> halt()
    end
  end
end
