defmodule SecretHub.Web.ErrorController do
  use SecretHub.Web, :controller

  def not_found(conn, _params), do: send_resp(conn, 404, "Not Found")
end
