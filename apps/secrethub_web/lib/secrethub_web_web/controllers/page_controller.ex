defmodule SecretHub.WebWeb.PageController do
  use SecretHub.WebWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
