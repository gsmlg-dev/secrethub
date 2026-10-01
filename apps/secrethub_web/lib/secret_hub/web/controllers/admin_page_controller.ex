defmodule SecretHub.Web.AdminPageController do
  @moduledoc "Opens management behind the existing Caddy mTLS ingress."
  use SecretHub.Web, :controller

  def index(conn, _params), do: redirect(conn, to: "/admin/dashboard")
end
