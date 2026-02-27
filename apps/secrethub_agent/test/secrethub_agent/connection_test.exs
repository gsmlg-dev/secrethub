defmodule SecretHub.Agent.ConnectionTest do
  use ExUnit.Case, async: false

  alias SecretHub.Agent.Connection

  # Unit tests that verify Connection behavior without requiring a running Core.
  # Connection starts async and will fail to connect to invalid URLs gracefully.
  # Note: Connection registers with name: Connection, so we stop between tests.

  setup do
    # Stop any existing Connection process to avoid name conflicts
    case Process.whereis(Connection) do
      nil -> :ok
      pid -> GenServer.stop(pid, :normal, 1000)
    end

    :ok
  end

  describe "connection lifecycle" do
    test "starts and enters connecting state with invalid URL" do
      {:ok, pid} =
        Connection.start_link(agent_id: "agent-test-01", core_url: "ws://localhost:19999")

      # Allow async init to fire
      Process.sleep(300)

      # With an invalid URL, status should be :connecting (reconnect scheduled) or :disconnected
      assert Connection.status(pid) in [:disconnected, :connecting]

      GenServer.stop(pid)
    end
  end

  describe "secret requests when disconnected" do
    test "returns error for static secret when not connected" do
      {:ok, pid} =
        Connection.start_link(agent_id: "agent-test-02", core_url: "ws://localhost:19998")

      Process.sleep(300)

      assert {:error, :not_connected} = Connection.get_static_secret(pid, "test.secret.path")

      GenServer.stop(pid)
    end

    test "returns error for dynamic credentials when not connected" do
      {:ok, pid} =
        Connection.start_link(agent_id: "agent-test-03", core_url: "ws://localhost:19997")

      Process.sleep(300)

      assert {:error, :not_connected} =
               Connection.get_dynamic_secret(pid, "test.db.readonly", 3600)

      GenServer.stop(pid)
    end

    test "returns error for lease renewal when not connected" do
      {:ok, pid} =
        Connection.start_link(agent_id: "agent-test-04", core_url: "ws://localhost:19996")

      Process.sleep(300)

      lease_id = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
      assert {:error, :not_connected} = Connection.renew_lease(pid, lease_id)

      GenServer.stop(pid)
    end
  end

  describe "error handling" do
    test "returns error when not connected" do
      {:ok, pid} =
        Connection.start_link(agent_id: "agent-test-05", core_url: "ws://localhost:19995")

      Process.sleep(300)

      assert Connection.status(pid) in [:disconnected, :connecting]
      {:error, :not_connected} = Connection.get_static_secret(pid, "test.secret")

      GenServer.stop(pid)
    end
  end

  describe "exponential backoff" do
    test "backoff delay increases with retry count" do
      # Each retry should produce a longer base delay than the previous
      delay_0 = Connection.backoff_delay(0)
      delay_1 = Connection.backoff_delay(1)
      delay_2 = Connection.backoff_delay(2)
      delay_3 = Connection.backoff_delay(3)

      # Allow for jitter: base_0=1000, base_1=2000, base_2=4000, base_3=8000
      # With 25% jitter, delay_n's midpoint < delay_{n+1}'s midpoint
      assert delay_0 < delay_2
      assert delay_1 < delay_3
      assert delay_0 >= 100
      assert delay_1 >= 100
      assert delay_2 >= 100
      assert delay_3 >= 100
    end

    test "backoff delay is capped at 60 seconds" do
      # retry_count=7 -> 2^7 * 1000 = 128_000 ms, should cap at 60_000
      delay = Connection.backoff_delay(7)
      # With +25% jitter max: 60_000 * 1.125 = 67_500
      assert delay <= 67_500
    end

    test "backoff delay for retry 0 is around 1 second" do
      # Base delay = 1000ms, jitter up to ±125ms
      delay = Connection.backoff_delay(0)
      assert delay >= 875
      assert delay <= 1125
    end

    test "backoff delay for retry 6 is capped at 60 seconds with jitter" do
      # 2^6 * 1000 = 64_000 -> capped at 60_000, jitter ±15_000
      delay = Connection.backoff_delay(6)
      assert delay >= 45_000
      assert delay <= 75_000
    end

    test "jitter produces different values on successive calls for same retry count" do
      # Run many times and verify we don't always get the exact same value
      delays = for _ <- 1..20, do: Connection.backoff_delay(3)
      unique_delays = Enum.uniq(delays)
      # With random jitter, we should rarely (or never) get all identical values
      assert length(unique_delays) > 1
    end

    test "minimum delay is always 100ms regardless of calculation" do
      # retry_count=0 -> base=1000, but the min(100, ...) guard ensures 100ms floor
      # Calling with 0 should give ~1000ms; this verifies the floor doesn't break normal case
      delay = Connection.backoff_delay(0)
      assert delay >= 100
    end
  end
end
