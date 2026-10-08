defmodule SecretHub.HumanWeb.HealthController do
  alias SecretHub.Human.Health
  use SecretHub.HumanWeb, :controller

  def ready(conn, _) do
    checks = Health.checks()
    ready = Enum.all?(checks, fn {_key, value} -> value end)

    conn
    |> put_status(if(ready, do: 200, else: 503))
    |> json(%{status: if(ready, do: "ready", else: "unavailable"), checks: checks})
  end

  def show(conn, _params) do
    json(conn, %{service: "secrethub_human", status: "ok"})
  end
end
