defmodule SecretHub.Web.PageController do
  use SecretHub.Web, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
