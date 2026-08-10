defmodule SecretHub.HumanWeb.RootControllerTest do
  use SecretHub.HumanWeb.ConnCase, async: true

  test "GET / identifies the Human service", %{conn: conn} do
    assert %{"service" => "secrethub_human"} = conn |> get("/") |> json_response(200)
  end

  test "GET /health reports liveness", %{conn: conn} do
    assert %{"service" => "secrethub_human", "status" => "ok"} =
             conn |> get("/health") |> json_response(200)
  end

  test "unknown routes return the JSON error boundary", %{conn: conn} do
    conn = get(conn, "/not-found")

    assert [content_type] = get_resp_header(conn, "content-type")
    assert String.starts_with?(content_type, "application/json")
    assert %{"errors" => %{"detail" => "Not Found"}} = json_response(conn, 404)
  end
end
