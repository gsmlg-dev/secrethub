defmodule SecretHub.Agent.EndpointManagerTest do
  use ExUnit.Case, async: false

  alias SecretHub.Agent.EndpointManager

  @endpoints [
    "wss://core-0.secrethub.local:4000",
    "wss://core-1.secrethub.local:4000",
    "wss://core-2.secrethub.local:4000"
  ]

  setup do
    # Stop any existing EndpointManager to avoid name conflicts
    case Process.whereis(EndpointManager) do
      nil -> :ok
      pid -> GenServer.stop(pid, :normal, 1000)
    end

    :ok
  end

  defp start_manager(opts \\ []) do
    defaults = [
      core_endpoints: @endpoints,
      # Use a long interval so the periodic health check does not fire during tests
      health_check_interval: 60_000,
      failover_threshold: 3
    ]

    start_supervised!({EndpointManager, Keyword.merge(defaults, opts)})
  end

  # ------------------------------------------------------------------
  # 1. Initialization
  # ------------------------------------------------------------------
  describe "init/1" do
    test "starts successfully with a list of endpoints" do
      pid = start_manager()
      assert Process.alive?(pid)
    end

    test "stops when no endpoints are configured" do
      # init returns {:stop, :no_endpoints_configured} which sends an EXIT to the caller.
      # Trap exits so we can match the error tuple from start_link.
      Process.flag(:trap_exit, true)

      assert {:error, :no_endpoints_configured} =
               EndpointManager.start_link(core_endpoints: [])
    end

    test "all endpoints begin as healthy" do
      start_manager()

      statuses = EndpointManager.get_health_status()
      assert length(statuses) == 3

      Enum.each(statuses, fn s ->
        assert s.status == :healthy
        assert s.consecutive_failures == 0
        assert s.consecutive_successes == 0
        assert s.last_success == nil
        assert s.last_failure == nil
        assert s.backoff_until == nil
      end)
    end
  end

  # ------------------------------------------------------------------
  # 2. get_next_endpoint/0 — round-robin selection
  # ------------------------------------------------------------------
  describe "get_next_endpoint/0" do
    test "returns the first endpoint on initial call" do
      start_manager()

      assert {:ok, endpoint} = EndpointManager.get_next_endpoint()
      assert endpoint == Enum.at(@endpoints, 0)
    end

    test "cycles through endpoints in round-robin order" do
      start_manager()

      assert {:ok, ep0} = EndpointManager.get_next_endpoint()
      assert {:ok, ep1} = EndpointManager.get_next_endpoint()
      assert {:ok, ep2} = EndpointManager.get_next_endpoint()
      assert {:ok, ep3} = EndpointManager.get_next_endpoint()

      assert ep0 == Enum.at(@endpoints, 0)
      assert ep1 == Enum.at(@endpoints, 1)
      assert ep2 == Enum.at(@endpoints, 2)
      # Wraps around
      assert ep3 == Enum.at(@endpoints, 0)
    end

    test "skips unhealthy endpoints" do
      start_manager()

      # Mark the first endpoint as unhealthy
      EndpointManager.mark_unhealthy(Enum.at(@endpoints, 0))
      # Allow the cast to be processed
      _ = EndpointManager.get_health_status()

      assert {:ok, ep} = EndpointManager.get_next_endpoint()
      assert ep == Enum.at(@endpoints, 1)
    end

    test "returns error when all endpoints are unhealthy" do
      start_manager()

      Enum.each(@endpoints, &EndpointManager.mark_unhealthy/1)
      # Synchronize by issuing a call
      _ = EndpointManager.get_health_status()

      assert {:error, :no_healthy_endpoints} = EndpointManager.get_next_endpoint()
    end

    test "works with a single endpoint" do
      start_manager(core_endpoints: ["wss://single.local:4000"])

      assert {:ok, "wss://single.local:4000"} = EndpointManager.get_next_endpoint()
      assert {:ok, "wss://single.local:4000"} = EndpointManager.get_next_endpoint()
    end
  end

  # ------------------------------------------------------------------
  # 3. report_failure/1
  # ------------------------------------------------------------------
  describe "report_failure/1" do
    test "increments consecutive failure count" do
      start_manager()

      endpoint = Enum.at(@endpoints, 0)
      EndpointManager.report_failure(endpoint)
      # Synchronize
      statuses = EndpointManager.get_health_status()
      status = Enum.find(statuses, &(&1.url == endpoint))

      assert status.consecutive_failures == 1
      assert status.last_failure != nil
    end

    test "marks endpoint as degraded before reaching threshold" do
      start_manager(failover_threshold: 3)

      endpoint = Enum.at(@endpoints, 0)

      EndpointManager.report_failure(endpoint)
      EndpointManager.report_failure(endpoint)
      statuses = EndpointManager.get_health_status()
      status = Enum.find(statuses, &(&1.url == endpoint))

      assert status.status == :degraded
      assert status.consecutive_failures == 2
    end

    test "marks endpoint as unhealthy after reaching failover threshold" do
      start_manager(failover_threshold: 3)

      endpoint = Enum.at(@endpoints, 0)

      for _ <- 1..3, do: EndpointManager.report_failure(endpoint)
      statuses = EndpointManager.get_health_status()
      status = Enum.find(statuses, &(&1.url == endpoint))

      assert status.status == :unhealthy
      assert status.consecutive_failures == 3
      assert status.backoff_until != nil
    end

    test "resets consecutive successes on failure" do
      start_manager()

      endpoint = Enum.at(@endpoints, 0)

      # Build up successes first
      EndpointManager.report_success(endpoint)
      EndpointManager.report_success(endpoint)
      # Synchronize and verify successes
      s1 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s1.consecutive_successes == 2

      # Now report a failure
      EndpointManager.report_failure(endpoint)
      s2 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))

      assert s2.consecutive_successes == 0
      assert s2.consecutive_failures == 1
    end
  end

  # ------------------------------------------------------------------
  # 4. report_success/1
  # ------------------------------------------------------------------
  describe "report_success/1" do
    test "increments consecutive success count" do
      start_manager()

      endpoint = Enum.at(@endpoints, 0)
      EndpointManager.report_success(endpoint)
      statuses = EndpointManager.get_health_status()
      status = Enum.find(statuses, &(&1.url == endpoint))

      assert status.consecutive_successes == 1
      assert status.last_success != nil
    end

    test "resets consecutive failures on success" do
      start_manager()

      endpoint = Enum.at(@endpoints, 0)

      EndpointManager.report_failure(endpoint)
      EndpointManager.report_failure(endpoint)
      s1 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s1.consecutive_failures == 2

      EndpointManager.report_success(endpoint)
      s2 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))

      assert s2.consecutive_failures == 0
      assert s2.consecutive_successes == 1
    end

    test "restores healthy status after 3 consecutive successes" do
      start_manager(failover_threshold: 2)

      endpoint = Enum.at(@endpoints, 0)

      # Drive the endpoint to unhealthy
      for _ <- 1..2, do: EndpointManager.report_failure(endpoint)
      s1 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s1.status == :unhealthy

      # First two successes should leave it as :degraded
      EndpointManager.report_success(endpoint)
      EndpointManager.report_success(endpoint)
      s2 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s2.status == :degraded

      # Third success promotes to :healthy
      EndpointManager.report_success(endpoint)
      s3 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s3.status == :healthy
      assert s3.backoff_until == nil
    end

    test "clears backoff_until on success" do
      start_manager(failover_threshold: 1)

      endpoint = Enum.at(@endpoints, 0)

      # Trigger backoff
      EndpointManager.report_failure(endpoint)
      s1 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s1.backoff_until != nil

      # Success should clear backoff
      EndpointManager.report_success(endpoint)
      s2 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s2.backoff_until == nil
    end
  end

  # ------------------------------------------------------------------
  # 5. get_health_status/0
  # ------------------------------------------------------------------
  describe "get_health_status/0" do
    test "returns a list with one entry per endpoint" do
      start_manager()

      statuses = EndpointManager.get_health_status()
      assert is_list(statuses)
      assert length(statuses) == length(@endpoints)

      urls = Enum.map(statuses, & &1.url) |> Enum.sort()
      assert urls == Enum.sort(@endpoints)
    end

    test "each entry contains expected keys" do
      start_manager()

      expected_keys =
        [
          :url,
          :status,
          :last_success,
          :last_failure,
          :consecutive_failures,
          :consecutive_successes,
          :backoff_until
        ]
        |> Enum.sort()

      for status <- EndpointManager.get_health_status() do
        assert Map.keys(status) |> Enum.sort() == expected_keys
      end
    end

    test "reflects mixed health states across endpoints" do
      start_manager(failover_threshold: 2)

      [ep0, ep1, ep2] = @endpoints

      # ep0 stays healthy (default)
      # ep1 becomes degraded (1 failure, below threshold)
      EndpointManager.report_failure(ep1)
      # ep2 becomes unhealthy (reaches threshold)
      for _ <- 1..2, do: EndpointManager.report_failure(ep2)

      statuses = EndpointManager.get_health_status()

      status_map = Map.new(statuses, fn s -> {s.url, s} end)

      assert status_map[ep0].status == :healthy
      assert status_map[ep1].status == :degraded
      assert status_map[ep2].status == :unhealthy
    end
  end

  # ------------------------------------------------------------------
  # mark_unhealthy/1 and mark_healthy/1 (manual overrides)
  # ------------------------------------------------------------------
  describe "mark_unhealthy/1 and mark_healthy/1" do
    test "mark_unhealthy sets status and consecutive failures to threshold" do
      start_manager(failover_threshold: 3)

      endpoint = Enum.at(@endpoints, 0)
      EndpointManager.mark_unhealthy(endpoint)

      status =
        EndpointManager.get_health_status()
        |> Enum.find(&(&1.url == endpoint))

      assert status.status == :unhealthy
      assert status.consecutive_failures == 3
    end

    test "mark_healthy restores endpoint and clears backoff" do
      start_manager(failover_threshold: 1)

      endpoint = Enum.at(@endpoints, 0)

      # Drive to unhealthy with backoff
      EndpointManager.report_failure(endpoint)
      s1 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s1.status == :unhealthy

      EndpointManager.mark_healthy(endpoint)
      s2 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))

      assert s2.status == :healthy
      assert s2.consecutive_failures == 0
      assert s2.backoff_until == nil
    end
  end
end
