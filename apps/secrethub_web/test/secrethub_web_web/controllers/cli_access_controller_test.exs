defmodule SecretHub.Web.CliAccessControllerTest do
  use SecretHub.Web.ConnCase, async: false

  alias SecretHub.Core.Auth.{AppRole, CliAccess}
  alias SecretHub.Core.Repo

  @rate_limiter_table :rate_limiter_table

  setup do
    ensure_current_audit_partition!()

    cleanup_rate_limit_scope(:auth)
    cleanup_rate_limit_scope(:cli_access_poll)

    on_exit(fn ->
      cleanup_rate_limit_scope(:auth)
      cleanup_rate_limit_scope(:cli_access_poll)
    end)

    :ok
  end

  test "creates a CLI access request and polls pending status", %{conn: conn} do
    conn =
      post(conn, "/v1/auth/cli-access", %{
        "client_name" => "gao-laptop",
        "cli_version" => "0.1.0"
      })

    body = json_response(conn, 201)

    assert %{
             "request_id" => request_id,
             "user_code" => user_code,
             "status" => "pending",
             "interval" => interval
           } = body

    assert user_code =~ ~r/^[A-Z2-7]{6}$/
    assert interval > 0

    poll_conn = get(build_conn(), "/v1/auth/cli-access/#{request_id}")
    assert %{"status" => "pending"} = json_response(poll_conn, 202)
  end

  test "pending CLI access polling does not hit the AppRole login rate limit", %{conn: conn} do
    conn =
      post(conn, "/v1/auth/cli-access", %{
        "client_name" => "polling-client",
        "cli_version" => "0.1.0"
      })

    %{"request_id" => request_id} = json_response(conn, 201)

    statuses =
      Enum.map(1..10, fn _index ->
        build_conn()
        |> get("/v1/auth/cli-access/#{request_id}")
        |> Map.fetch!(:status)
      end)

    assert statuses == List.duplicate(202, 10)
  end

  test "poll returns the approved AppRole token", %{conn: conn} do
    {:ok, role} =
      AppRole.create_role("cli-access-api-role",
        policies: ["secret-read"],
        secret_id_num_uses: 0
      )

    {:ok, request} = CliAccess.create_request(%{}, "127.0.0.1")
    {:ok, _approved} = CliAccess.approve_request(request.id, role.role_id, "admin")

    conn = get(conn, "/v1/auth/cli-access/#{request.request_id}")
    body = json_response(conn, 200)

    assert %{
             "auth" => %{
               "client_token" => token,
               "lease_duration" => lease_duration,
               "policies" => ["secret-read"]
             },
             "token" => token,
             "token_type" => "approle",
             "role_name" => "cli-access-api-role"
           } = body

    assert lease_duration == AppRole.token_ttl_seconds()
    assert {:ok, payload} = AppRole.verify_token(token)
    assert payload.role_id == role.role_id
  end

  defp ensure_current_audit_partition! do
    today = Date.utc_today()
    month = String.pad_leading(to_string(today.month), 2, "0")
    partition_name = "audit_logs_y#{today.year}m#{month}"
    from_date = %Date{today | day: 1}
    to_date = Date.add(from_date, Date.days_in_month(from_date))

    Repo.query!("""
    CREATE TABLE IF NOT EXISTS #{partition_name} PARTITION OF audit_logs
    FOR VALUES FROM ('#{Date.to_iso8601(from_date)}') TO ('#{Date.to_iso8601(to_date)}')
    """)
  end

  defp cleanup_rate_limit_scope(scope) do
    case :ets.whereis(@rate_limiter_table) do
      :undefined -> :ok
      _table -> :ets.match_delete(@rate_limiter_table, {{scope, :_}, :_, :_})
    end
  end
end
