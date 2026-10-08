defmodule SecretHub.HumanWeb.Native.UIController do
  use SecretHub.HumanWeb, :controller

  def index(conn, _) do
    conn
    |> put_resp_header(
      "content-security-policy",
      "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    |> put_resp_content_type("text/html")
    |> send_resp(200, File.read!(Application.app_dir(:secrethub_human, "priv/static/human.html")))
  end
end
