defmodule SecretHub.Web.UnifiedAgentEndpointTest do
  use SecretHub.Web.ConnCase, async: false

  @endpoint SecretHub.Web.AgentEndpoint

  setup_all do
    start_supervised!({@endpoint, server: false})
    :ok
  end

  test "enrollment JSON reaches the machine controller without a client certificate", %{
    conn: conn
  } do
    conn = post(conn, "/v1/agent/enrollments", %{})
    assert %{"error" => "invalid_enrollment"} = json_response(conn, 400)
    assert get_resp_header(conn, "cache-control") == ["no-store"]
    assert [_] = get_resp_header(conn, "x-request-id")
  end

  test "machine bearer authorization remains required", %{conn: conn} do
    conn = get(conn, "/v1/secret/data/unified-port-test")
    assert conn.status == 401
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  test "enrollment keeps its machine rate limit", %{conn: conn} do
    conn = %{conn | remote_ip: {198, 51, 100, 141}}

    for _ <- 1..30 do
      assert post(conn, "/v1/agent/enrollments", %{}).status == 400
    end

    limited = post(conn, "/v1/agent/enrollments", %{})
    assert limited.status == 429
    assert [_] = get_resp_header(limited, "retry-after")
    assert get_resp_header(limited, "cache-control") == ["no-store"]
  end

  test "machine application bootstrap still requires its token and proof request", %{conn: conn} do
    assert %{"error" => "INVALID_REQUEST"} =
             conn |> post("/v1/pki/app/issue", %{}) |> json_response(400)
  end

  test "HEAD requests use the machine liveness route", %{conn: conn} do
    response = head(conn, "/v1/sys/health/live")
    assert response.status == 200
    assert response.resp_body == ""
    assert get_resp_header(response, "cache-control") == ["no-store"]
  end

  test "only machine routes are mounted", %{conn: conn} do
    for path <- ["/admin", "/v1/sys/init", "/v1/sys/unseal", "/socket/websocket"] do
      response = get(conn, path)
      assert response.status == 404
    end

    for path <- ["/v1/sys/init", "/v1/sys/unseal"] do
      assert post(conn, path, %{}).status == 404
    end
  end
end
