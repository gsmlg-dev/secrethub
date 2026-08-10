defmodule SecretHub.HumanWeb.RootControllerTest do
  use SecretHub.HumanWeb.ConnCase, async: true

  test "GET / identifies the Human service", %{conn: conn} do
    assert %{"service" => "secrethub_human"} = conn |> get("/") |> json_response(200)
  end

  test "GET /health reports liveness", %{conn: conn} do
    assert %{"service" => "secrethub_human", "status" => "ok"} =
             conn |> get("/health") |> json_response(200)
  end
end
