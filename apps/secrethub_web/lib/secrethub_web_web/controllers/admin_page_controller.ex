defmodule SecretHub.WebWeb.AdminPageController do
  @moduledoc """
  Controller for rendering admin pages with authentication check.
  """

  use SecretHub.WebWeb, :controller
  require Logger

  def index(conn, _params) do
    if get_session(conn, :admin_id) do
      conn
      |> redirect(to: "/admin/dashboard")
    else
      conn
      |> redirect(to: "/admin/auth/login")
    end
  end

  def login_form(conn, _params) do
    conn
    |> put_layout(false)
    |> render(:login)
  end
end