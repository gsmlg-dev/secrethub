defmodule SecretHub.Web.Plugs.RateLimiterTest do
  use SecretHub.Web.ConnCase, async: false

  alias SecretHub.Web.Plugs.RateLimiter

  @table_name :rate_limiter_table

  describe "supervised lifecycle" do
    test "the supervised limiter owns the table after a short-lived caller initializes the plug" do
      limiter = Process.whereis(RateLimiter)

      assert is_pid(limiter)
      assert :ets.info(@table_name, :owner) == limiter

      task =
        Task.async(fn ->
          RateLimiter.init(max_requests: 1, window_ms: 1_000, scope: :short_lived)
        end)

      assert %{
               max_requests: 1,
               window_ms: 1_000,
               scope: :short_lived
             } = Task.await(task)

      refute Process.alive?(task.pid)
      assert :ets.info(@table_name, :owner) == limiter
    end
  end

  describe "RateLimiter plug" do
    setup do
      # Build Plug options; the application-supervised limiter owns the table.
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
      # The application-supervised limiter owns the ETS table.
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

  describe "application certificate bootstrap route" do
    setup do
      cleanup_test_entries(:app_certificate_bootstrap)

      on_exit(fn ->
        cleanup_test_entries(:app_certificate_bootstrap)
      end)

      :ok
    end

    test "has exactly one public issuance route" do
      routes =
        SecretHub.Web.Router
        |> Phoenix.Router.routes()
        |> Enum.filter(&(&1.verb == :post and &1.path == "/v1/pki/app/issue"))

      assert [
               %{
                 plug: SecretHub.Web.PKIController,
                 plug_opts: :issue_app_certificate,
                 verb: :post
               }
             ] = routes
    end

    test "is public and rate limited without a Vault-token bypass" do
      remote_ip = {198, 51, 100, 42}

      for request <- 1..5 do
        response =
          build_conn()
          |> Map.put(:remote_ip, remote_ip)
          |> put_req_header("x-forwarded-for", "203.0.113.#{request}")
          |> post("/v1/pki/app/issue", %{})

        assert json_response(response, 400) == %{"error" => "INVALID_REQUEST"}
      end

      response =
        build_conn()
        |> Map.put(:remote_ip, remote_ip)
        |> put_req_header("x-forwarded-for", "203.0.113.250")
        |> put_req_header("x-vault-token", "vault-token-bypass-attempt")
        |> post("/v1/pki/app/issue", %{})

      assert json_response(response, 429)["error"] == "Too many requests"
    end

    test "atomically limits concurrent requests from one remote peer" do
      remote_ip = {198, 51, 100, 99}
      test_process = self()

      tasks =
        for request <- 1..20 do
          Task.async(fn ->
            send(test_process, :ready)

            receive do
              :go ->
                build_conn()
                |> Map.put(:remote_ip, remote_ip)
                |> put_req_header("x-forwarded-for", "203.0.113.#{request}")
                |> post("/v1/pki/app/issue", %{})
                |> Map.fetch!(:status)
            end
          end)
        end

      for _task <- tasks do
        assert_receive :ready, 5_000
      end

      Enum.each(tasks, &send(&1.pid, :go))
      statuses = Task.await_many(tasks, 15_000)

      assert %{400 => 5, 429 => 15} = Enum.frequencies(statuses)
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
