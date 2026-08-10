defmodule SecretHub.HumanWeb.HealthController do
  use SecretHub.HumanWeb, :controller

  def show(conn, _params) do
    json(conn, %{service: "secrethub_human", status: "ok"})
  end
end
