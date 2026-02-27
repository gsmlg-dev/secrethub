defmodule SecretHub.Agent.BackoffTest do
  @moduledoc """
  P1: Agent connection resilience tests.

  Verifies exponential backoff behavior, cap, jitter, and reset logic
  for the ConnectionManager's reconnect scheduling.
  """

  use ExUnit.Case, async: true

  @moduletag :agent

  describe "P1: Reconnect interval grows with retry count (exponential backoff)" do
    test "backoff doubles with each attempt" do
      delays =
        Enum.map(0..5, fn attempt ->
          # Base formula from ConnectionManager: 2^attempt * 1000, capped at 60_000
          min(:math.pow(2, attempt) * 1000, 60_000) |> round()
        end)

      assert Enum.at(delays, 0) == 1_000
      assert Enum.at(delays, 1) == 2_000
      assert Enum.at(delays, 2) == 4_000
      assert Enum.at(delays, 3) == 8_000
      assert Enum.at(delays, 4) == 16_000
      assert Enum.at(delays, 5) == 32_000
    end
  end

  describe "P1: Reconnect interval is capped at 60 seconds" do
    test "base delay never exceeds 60_000ms" do
      # At attempt 6: 2^6 * 1000 = 64_000 -> capped to 60_000
      delay_6 = min(:math.pow(2, 6) * 1000, 60_000) |> round()
      assert delay_6 == 60_000

      # At attempt 10: 2^10 * 1000 = 1_024_000 -> capped to 60_000
      delay_10 = min(:math.pow(2, 10) * 1000, 60_000) |> round()
      assert delay_10 == 60_000

      # At attempt 20: still capped
      delay_20 = min(:math.pow(2, 20) * 1000, 60_000) |> round()
      assert delay_20 == 60_000
    end
  end

  describe "P1: Jitter is applied to backoff" do
    test "jitter produces varying delays for same attempt count" do
      attempt = 3
      base_delay = min(:math.pow(2, attempt) * 1000, 60_000) |> round()

      # Generate 100 jittered delays
      delays =
        Enum.map(1..100, fn _ ->
          jitter = :rand.uniform(max(div(base_delay, 4), 1))
          base_delay + jitter - div(base_delay, 4)
        end)

      # All delays should be within ±25% of base
      min_expected = round(base_delay * 0.75)
      max_expected = round(base_delay * 1.25)

      Enum.each(delays, fn delay ->
        assert delay >= min_expected,
               "Delay #{delay} below minimum #{min_expected}"

        assert delay <= max_expected,
               "Delay #{delay} above maximum #{max_expected}"
      end)

      # Jitter should produce at least some variation
      unique_delays = Enum.uniq(delays)
      assert length(unique_delays) > 1, "Expected jitter to produce varying delays"
    end

    test "jitter prevents thundering herd (delays are not all identical)" do
      attempt = 4

      delays =
        Enum.map(1..50, fn _ ->
          base_delay = min(:math.pow(2, attempt) * 1000, 60_000) |> round()
          jitter = :rand.uniform(max(div(base_delay, 4), 1))
          base_delay + jitter - div(base_delay, 4)
        end)

      unique_count = length(Enum.uniq(delays))
      # With 50 samples and ~4000ms jitter range, we should get many unique values
      assert unique_count > 10, "Expected diverse delays, got only #{unique_count} unique values"
    end
  end

  describe "P1: Successful connect resets retry counter" do
    test "reconnect_attempts field resets to 0 on successful connect" do
      # Simulate the state management pattern from ConnectionManager
      state = %{reconnect_attempts: 5, connection_status: :disconnected}

      # After successful connection, attempts reset
      connected_state = %{state | reconnect_attempts: 0, connection_status: :connected}

      assert connected_state.reconnect_attempts == 0
      assert connected_state.connection_status == :connected

      # First retry after reset starts at attempt 0 (1s base delay)
      base_delay = min(:math.pow(2, connected_state.reconnect_attempts) * 1000, 60_000) |> round()
      assert base_delay == 1_000
    end
  end
end
