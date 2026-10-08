defmodule SecretHub.HumanWeb.Plugs.CORS do
  @moduledoc false
  import Plug.Conn
  def init(opts), do: opts

  def call(conn, _opts) do
    conn =
      conn
      |> put_resp_header("access-control-allow-origin", "*")
      |> put_resp_header("access-control-allow-methods", "GET,POST,PUT,DELETE,OPTIONS")
      |> put_resp_header(
        "access-control-allow-headers",
        "authorization,content-type,bitwarden-client-name,bitwarden-client-version,device-type"
      )
      |> put_resp_header("cache-control", "no-store")

    if conn.method == "OPTIONS", do: conn |> send_resp(204, "") |> halt(), else: conn
  end
end
