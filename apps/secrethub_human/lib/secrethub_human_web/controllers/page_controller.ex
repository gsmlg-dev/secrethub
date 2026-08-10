defmodule SecretHub.HumanWeb.PageController do
  use SecretHub.HumanWeb, :controller

  def index(conn, _params) do
    json(conn, %{service: "secrethub_human"})
  end
end
