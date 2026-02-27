defmodule SecretHub.Web.Plugs.RateLimiterTest do
  use SecretHub.Web.ConnCase, async: false

  alias SecretHub.Web.Plugs.RateLimiter

  @table_name :rate_limiter_table

  describe "RateLimiter plug" do
    setup do
      # Ensure the ETS table exists (init creates it if not present)
      opts = RateLimiter.init(max_requests: 3, window_ms: 60_000, scope: :test)

      # Clean up any existing entries for our test scope before each test
      cleanup_test_entries(:test)

      on_exit(fn ->
        cleanup_test_entries(:test)
      end)

      %{opts: opts}
    end

    test "allows requests under the limit", %{conn: conn, opts: opts} do
      conn1 = RateLimiter.call(conn, opts)
      refute conn1.halted

      conn2 = build_conn() |> RateLimiter.call(opts)
      refute conn2.halted

      conn3 = build_conn() |> RateLimiter.call(opts)
      refute conn3.halted
    end

    test "returns 429 after exceeding max_requests", %{conn: conn, opts: opts} do
      # Use up the allowed requests
      _conn1 = RateLimiter.call(conn, opts)
      _conn2 = build_conn() |> RateLimiter.call(opts)
      _conn3 = build_conn() |> RateLimiter.call(opts)

      # Fourth request should be rate limited
      conn4 = build_conn() |> RateLimiter.call(opts)

      assert conn4.halted
      assert conn4.status == 429
      body = Jason.decode!(conn4.resp_body)
      assert body["error"] == "Too many requests"
      assert is_integer(body["retry_after"])
    end

    test "resets counter after window expires", %{conn: _conn} do
      # Use a very short window so it expires quickly
      short_opts =
        RateLimiter.init(max_requests: 1, window_ms: 1, scope: :test_reset)

      cleanup_test_entries(:test_reset)

      conn1 = build_conn() |> RateLimiter.call(short_opts)
      refute conn1.halted

      # Wait for the window to pass
      Process.sleep(10)

      # Next request should be allowed because window has expired
      conn2 = build_conn() |> RateLimiter.call(short_opts)
      refute conn2.halted

      cleanup_test_entries(:test_reset)
    end

    test "includes retry-after header in response", %{conn: conn, opts: opts} do
      # Use up the allowed requests
      _conn1 = RateLimiter.call(conn, opts)
      _conn2 = build_conn() |> RateLimiter.call(opts)
      _conn3 = build_conn() |> RateLimiter.call(opts)

      # Fourth request should be rate limited with retry-after header
      conn4 = build_conn() |> RateLimiter.call(opts)

      assert conn4.halted
      assert conn4.status == 429

      retry_after_values = Plug.Conn.get_resp_header(conn4, "retry-after")
      assert length(retry_after_values) == 1

      {retry_after_int, _} = Integer.parse(List.first(retry_after_values))
      assert retry_after_int > 0
    end

    test "uses X-Forwarded-For for client IP when present" do
      forwarded_opts =
        RateLimiter.init(max_requests: 1, window_ms: 60_000, scope: :test_forwarded)

      cleanup_test_entries(:test_forwarded)

      # First request with X-Forwarded-For
      conn1 =
        build_conn()
        |> put_req_header("x-forwarded-for", "10.0.0.1")
        |> RateLimiter.call(forwarded_opts)

      refute conn1.halted

      # Second request from same forwarded IP should be rate limited
      conn2 =
        build_conn()
        |> put_req_header("x-forwarded-for", "10.0.0.1")
        |> RateLimiter.call(forwarded_opts)

      assert conn2.halted
      assert conn2.status == 429

      # Request from a different forwarded IP should be allowed
      conn3 =
        build_conn()
        |> put_req_header("x-forwarded-for", "10.0.0.2")
        |> RateLimiter.call(forwarded_opts)

      refute conn3.halted

      cleanup_test_entries(:test_forwarded)
    end
  end

  describe "cleanup_old_entries/1" do
    setup do
      # Ensure the ETS table exists
      _opts = RateLimiter.init(scope: :test_cleanup)
      cleanup_test_entries(:test_cleanup)

      on_exit(fn ->
        cleanup_test_entries(:test_cleanup)
      end)

      :ok
    end

    test "removes stale entries" do
      now = System.monotonic_time(:millisecond)

      # Insert an old entry (timestamped well in the past)
      old_time = now - 7_200_000
      :ets.insert(@table_name, {{:test_cleanup, "old-ip"}, old_time, 5})

      # Insert a recent entry
      :ets.insert(@table_name, {{:test_cleanup, "new-ip"}, now, 2})

      # Clean entries older than 1 hour (3_600_000 ms)
      {:ok, deleted} = RateLimiter.cleanup_old_entries(3_600_000)

      assert deleted == 1

      # Old entry should be gone
      assert :ets.lookup(@table_name, {:test_cleanup, "old-ip"}) == []

      # Recent entry should remain
      assert [{_, _, 2}] = :ets.lookup(@table_name, {:test_cleanup, "new-ip"})

      # Clean up
      :ets.delete(@table_name, {:test_cleanup, "new-ip"})
    end
  end

  # Helper to clean up test-scoped ETS entries
  defp cleanup_test_entries(scope) do
    case :ets.whereis(@table_name) do
      :undefined ->
        :ok

      _ ->
        # Use match_delete to remove entries for the given scope
        :ets.match_delete(@table_name, {{scope, :_}, :_, :_})
    end
  end
end
