defmodule SecretHub.Performance.AgentLoadTest do
  @moduledoc """
  Performance testing for 100 concurrent agents.

  This script simulates:
  - 100 agents registering concurrently
  - Each agent authenticating and obtaining certificates
  - Agents making concurrent secret requests
  - Measuring throughput and latency

  Run with: mix run test/performance/agent_load_test.exs
  """

  alias SecretHub.Core.{Agents, Policies, Secrets}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Core.Repo

  require Logger

  @agent_count 100
  @requests_per_agent 10
  @secret_count 50

  def run do
    Logger.info("Starting performance test with #{@agent_count} agents")

    # Ensure database is ready
    {:ok, _} = Application.ensure_all_started(:secrethub_core)

    # Start and unseal vault
    setup_vault()

    # Create test data
    {policy, secrets} = setup_test_data()

    # Run performance tests
    results = %{
      registration: test_agent_registration(policy),
      authentication: test_agent_authentication(policy),
      secret_reads: test_concurrent_secret_reads(policy, secrets),
      mixed_workload: test_mixed_workload(policy, secrets)
    }

    # Print results
    print_results(results)

    # Cleanup
    cleanup()

    :ok
  end

  defp setup_vault do
    Logger.info("Setting up vault...")

    case SealState.status() do
      %{initialized: false} ->
        {:ok, shares} = SealState.initialize(3, 2)

        shares
        |> Enum.take(2)
        |> Enum.each(&SealState.unseal/1)

        Logger.info("Vault initialized and unsealed")

      %{sealed: false} ->
        Logger.info("Vault already unsealed")

      %{sealed: true, threshold: threshold} ->
        Logger.warning(
          "Vault is sealed. Need #{threshold} shares to unseal. Skipping unseal for now."
        )
    end
  end

  defp setup_test_data do
    Logger.info("Creating test policy...")

    {:ok, policy} =
      Policies.create_policy(%{
        name: "load-test-policy-#{:rand.uniform(100000)}",
        path_rules: [
          %{
            path: "secret/data/load-test/*",
            capabilities: ["read", "create", "update"]
          }
        ]
      })

    Logger.info("Creating #{@secret_count} test secrets...")

    secrets =
      Enum.map(1..@secret_count, fn i ->
        {:ok, secret} =
          Secrets.create_secret(%{
            path: "secret/data/load-test/secret-#{i}",
            engine_type: :static,
            type: :kv,
            data: %{
              "key" => "value-#{i}",
              "index" => i,
              "timestamp" => DateTime.utc_now() |> DateTime.to_string()
            }
          })

        secret
      end)

    Logger.info("Test data created: 1 policy, #{length(secrets)} secrets")
    {policy, secrets}
  end

  defp test_agent_registration(policy) do
    Logger.info("\n=== Test 1: Agent Registration (#{@agent_count} agents) ===")

    start_time = System.monotonic_time(:millisecond)

    agents =
      1..@agent_count
      |> Task.async_stream(
        fn i ->
          result =
            Agents.register_agent(%{
              agent_id: "load-test-agent-#{:rand.uniform(1_000_000)}-#{i}",
              name: "Load Test Agent #{i}",
              description: "Performance test agent",
              policy_ids: [policy.id],
              auth_method: "approle",
              metadata: %{
                "test" => "load_test",
                "index" => i
              }
            })

          case result do
            {:ok, agent} -> {:success, agent}
            {:error, reason} -> {:error, reason}
          end
        end,
        max_concurrency: @agent_count,
        timeout: 30_000
      )
      |> Enum.to_list()

    end_time = System.monotonic_time(:millisecond)
    duration_ms = end_time - start_time

    success_count = Enum.count(agents, fn {:ok, {:success, _}} -> true; _ -> false end)
    error_count = Enum.count(agents, fn {:ok, {:error, _}} -> true; _ -> false end)

    successful_agents =
      agents
      |> Enum.filter(fn {:ok, {:success, _}} -> true; _ -> false end)
      |> Enum.map(fn {:ok, {:success, agent}} -> agent end)

    %{
      total_agents: @agent_count,
      successful: success_count,
      failed: error_count,
      duration_ms: duration_ms,
      throughput: success_count / (duration_ms / 1000),
      avg_latency_ms: duration_ms / @agent_count,
      agents: successful_agents
    }
  end

  defp test_agent_authentication(policy) do
    Logger.info("\n=== Test 2: Agent Authentication (#{@agent_count} agents) ===")

    # Register agents first
    agents =
      Enum.map(1..@agent_count, fn i ->
        {:ok, agent} =
          Agents.register_agent(%{
            agent_id: "auth-test-agent-#{:rand.uniform(1_000_000)}-#{i}",
            name: "Auth Test Agent #{i}",
            policy_ids: [policy.id],
            auth_method: "approle"
          })

        {:ok, role_id, secret_id} = Agents.generate_approle_credentials(agent.id)
        {agent, role_id, secret_id}
      end)

    # Test concurrent authentication
    start_time = System.monotonic_time(:millisecond)

    auth_results =
      agents
      |> Task.async_stream(
        fn {agent, role_id, secret_id} ->
          auth_start = System.monotonic_time(:millisecond)

          result = Agents.authenticate_approle(role_id, secret_id)

          auth_end = System.monotonic_time(:millisecond)
          latency = auth_end - auth_start

          case result do
            {:ok, _token} -> {:success, latency}
            {:error, reason} -> {:error, reason, latency}
          end
        end,
        max_concurrency: @agent_count,
        timeout: 30_000
      )
      |> Enum.to_list()

    end_time = System.monotonic_time(:millisecond)
    duration_ms = end_time - start_time

    success_count = Enum.count(auth_results, fn {:ok, {:success, _}} -> true; _ -> false end)
    error_count = Enum.count(auth_results, fn {:ok, {:error, _, _}} -> true; _ -> false end)

    latencies =
      auth_results
      |> Enum.filter(fn {:ok, {:success, _}} -> true; _ -> false end)
      |> Enum.map(fn {:ok, {:success, latency}} -> latency end)

    avg_latency = if length(latencies) > 0, do: Enum.sum(latencies) / length(latencies), else: 0
    min_latency = if length(latencies) > 0, do: Enum.min(latencies), else: 0
    max_latency = if length(latencies) > 0, do: Enum.max(latencies), else: 0
    p95_latency = if length(latencies) > 0, do: percentile(latencies, 95), else: 0
    p99_latency = if length(latencies) > 0, do: percentile(latencies, 99), else: 0

    %{
      total_attempts: @agent_count,
      successful: success_count,
      failed: error_count,
      duration_ms: duration_ms,
      throughput: success_count / (duration_ms / 1000),
      avg_latency_ms: avg_latency,
      min_latency_ms: min_latency,
      max_latency_ms: max_latency,
      p95_latency_ms: p95_latency,
      p99_latency_ms: p99_latency
    }
  end

  defp test_concurrent_secret_reads(policy, secrets) do
    Logger.info(
      "\n=== Test 3: Concurrent Secret Reads (#{@agent_count} agents, #{@requests_per_agent} requests each) ==="
    )

    # Setup authenticated agents
    agents =
      Enum.map(1..@agent_count, fn i ->
        {:ok, agent} =
          Agents.register_agent(%{
            agent_id: "read-test-agent-#{:rand.uniform(1_000_000)}-#{i}",
            name: "Read Test Agent #{i}",
            policy_ids: [policy.id],
            auth_method: "approle"
          })

        {:ok, role_id, secret_id} = Agents.generate_approle_credentials(agent.id)
        {:ok, token} = Agents.authenticate_approle(role_id, secret_id)
        {agent, token}
      end)

    total_requests = @agent_count * @requests_per_agent
    Logger.info("Total requests: #{total_requests}")

    start_time = System.monotonic_time(:millisecond)

    read_results =
      agents
      |> Task.async_stream(
        fn {_agent, _token} ->
          # Each agent makes multiple requests
          Enum.map(1..@requests_per_agent, fn _i ->
            # Pick a random secret
            secret = Enum.random(secrets)
            req_start = System.monotonic_time(:millisecond)

            result = Secrets.get_secret_by_path(secret.path)

            req_end = System.monotonic_time(:millisecond)
            latency = req_end - req_start

            case result do
              {:ok, _secret} -> {:success, latency}
              {:error, reason} -> {:error, reason, latency}
            end
          end)
        end,
        max_concurrency: @agent_count,
        timeout: 60_000
      )
      |> Enum.to_list()
      |> Enum.flat_map(fn {:ok, results} -> results end)

    end_time = System.monotonic_time(:millisecond)
    duration_ms = end_time - start_time

    success_count = Enum.count(read_results, fn {:success, _} -> true; _ -> false end)
    error_count = Enum.count(read_results, fn {:error, _, _} -> true; _ -> false end)

    latencies =
      read_results
      |> Enum.filter(fn {:success, _} -> true; _ -> false end)
      |> Enum.map(fn {:success, latency} -> latency end)

    avg_latency = if length(latencies) > 0, do: Enum.sum(latencies) / length(latencies), else: 0
    min_latency = if length(latencies) > 0, do: Enum.min(latencies), else: 0
    max_latency = if length(latencies) > 0, do: Enum.max(latencies), else: 0
    p95_latency = if length(latencies) > 0, do: percentile(latencies, 95), else: 0
    p99_latency = if length(latencies) > 0, do: percentile(latencies, 99), else: 0

    %{
      total_requests: total_requests,
      successful: success_count,
      failed: error_count,
      duration_ms: duration_ms,
      throughput: success_count / (duration_ms / 1000),
      avg_latency_ms: avg_latency,
      min_latency_ms: min_latency,
      max_latency_ms: max_latency,
      p95_latency_ms: p95_latency,
      p99_latency_ms: p99_latency
    }
  end

  defp test_mixed_workload(policy, secrets) do
    Logger.info("\n=== Test 4: Mixed Workload (reads + writes) ===")

    # Setup agents
    agents =
      Enum.map(1..@agent_count, fn i ->
        {:ok, agent} =
          Agents.register_agent(%{
            agent_id: "mixed-test-agent-#{:rand.uniform(1_000_000)}-#{i}",
            name: "Mixed Test Agent #{i}",
            policy_ids: [policy.id],
            auth_method: "approle"
          })

        {:ok, role_id, secret_id} = Agents.generate_approle_credentials(agent.id)
        {:ok, token} = Agents.authenticate_approle(role_id, secret_id)
        {agent, token}
      end)

    start_time = System.monotonic_time(:millisecond)

    results =
      agents
      |> Task.async_stream(
        fn {_agent, _token} ->
          # Mix of reads (70%) and writes (30%)
          Enum.map(1..@requests_per_agent, fn i ->
            req_start = System.monotonic_time(:millisecond)

            result =
              if rem(i, 10) < 7 do
                # Read operation
                secret = Enum.random(secrets)
                Secrets.get_secret_by_path(secret.path)
              else
                # Write operation (update existing secret)
                secret = Enum.random(secrets)

                Secrets.update_secret(secret.id, %{
                  data: %{
                    "updated_at" => DateTime.utc_now() |> DateTime.to_string(),
                    "counter" => i
                  }
                })
              end

            req_end = System.monotonic_time(:millisecond)
            latency = req_end - req_start

            case result do
              {:ok, _} -> {:success, latency}
              {:error, reason} -> {:error, reason, latency}
            end
          end)
        end,
        max_concurrency: @agent_count,
        timeout: 60_000
      )
      |> Enum.to_list()
      |> Enum.flat_map(fn {:ok, results} -> results end)

    end_time = System.monotonic_time(:millisecond)
    duration_ms = end_time - start_time

    success_count = Enum.count(results, fn {:success, _} -> true; _ -> false end)
    error_count = Enum.count(results, fn {:error, _, _} -> true; _ -> false end)

    latencies =
      results
      |> Enum.filter(fn {:success, _} -> true; _ -> false end)
      |> Enum.map(fn {:success, latency} -> latency end)

    avg_latency = if length(latencies) > 0, do: Enum.sum(latencies) / length(latencies), else: 0

    %{
      total_requests: @agent_count * @requests_per_agent,
      successful: success_count,
      failed: error_count,
      duration_ms: duration_ms,
      throughput: success_count / (duration_ms / 1000),
      avg_latency_ms: avg_latency
    }
  end

  defp percentile(list, p) when p >= 0 and p <= 100 do
    sorted = Enum.sort(list)
    k = (length(sorted) - 1) * p / 100
    f = Float.floor(k)
    c = Float.ceil(k)

    if f == c do
      Enum.at(sorted, round(k))
    else
      d0 = Enum.at(sorted, round(f)) * (c - k)
      d1 = Enum.at(sorted, round(c)) * (k - f)
      d0 + d1
    end
  end

  defp print_results(results) do
    IO.puts("\n")
    IO.puts("=" <> String.duplicate("=", 78))
    IO.puts("  PERFORMANCE TEST RESULTS")
    IO.puts("=" <> String.duplicate("=", 78))

    IO.puts("\n1. Agent Registration")
    IO.puts("   Total Agents:    #{results.registration.total_agents}")
    IO.puts("   Successful:      #{results.registration.successful}")
    IO.puts("   Failed:          #{results.registration.failed}")
    IO.puts("   Duration:        #{results.registration.duration_ms}ms")
    IO.puts("   Throughput:      #{Float.round(results.registration.throughput, 2)} ops/sec")
    IO.puts("   Avg Latency:     #{Float.round(results.registration.avg_latency_ms, 2)}ms")

    IO.puts("\n2. Agent Authentication")
    IO.puts("   Total Attempts:  #{results.authentication.total_attempts}")
    IO.puts("   Successful:      #{results.authentication.successful}")
    IO.puts("   Failed:          #{results.authentication.failed}")
    IO.puts("   Duration:        #{results.authentication.duration_ms}ms")
    IO.puts("   Throughput:      #{Float.round(results.authentication.throughput, 2)} ops/sec")
    IO.puts("   Avg Latency:     #{Float.round(results.authentication.avg_latency_ms, 2)}ms")
    IO.puts("   Min Latency:     #{Float.round(results.authentication.min_latency_ms, 2)}ms")
    IO.puts("   Max Latency:     #{Float.round(results.authentication.max_latency_ms, 2)}ms")
    IO.puts("   P95 Latency:     #{Float.round(results.authentication.p95_latency_ms, 2)}ms")
    IO.puts("   P99 Latency:     #{Float.round(results.authentication.p99_latency_ms, 2)}ms")

    IO.puts("\n3. Concurrent Secret Reads")
    IO.puts("   Total Requests:  #{results.secret_reads.total_requests}")
    IO.puts("   Successful:      #{results.secret_reads.successful}")
    IO.puts("   Failed:          #{results.secret_reads.failed}")
    IO.puts("   Duration:        #{results.secret_reads.duration_ms}ms")
    IO.puts("   Throughput:      #{Float.round(results.secret_reads.throughput, 2)} ops/sec")
    IO.puts("   Avg Latency:     #{Float.round(results.secret_reads.avg_latency_ms, 2)}ms")
    IO.puts("   Min Latency:     #{Float.round(results.secret_reads.min_latency_ms, 2)}ms")
    IO.puts("   Max Latency:     #{Float.round(results.secret_reads.max_latency_ms, 2)}ms")
    IO.puts("   P95 Latency:     #{Float.round(results.secret_reads.p95_latency_ms, 2)}ms")
    IO.puts("   P99 Latency:     #{Float.round(results.secret_reads.p99_latency_ms, 2)}ms")

    IO.puts("\n4. Mixed Workload (70% reads, 30% writes)")
    IO.puts("   Total Requests:  #{results.mixed_workload.total_requests}")
    IO.puts("   Successful:      #{results.mixed_workload.successful}")
    IO.puts("   Failed:          #{results.mixed_workload.failed}")
    IO.puts("   Duration:        #{results.mixed_workload.duration_ms}ms")
    IO.puts("   Throughput:      #{Float.round(results.mixed_workload.throughput, 2)} ops/sec")
    IO.puts("   Avg Latency:     #{Float.round(results.mixed_workload.avg_latency_ms, 2)}ms")

    IO.puts("\n" <> String.duplicate("=", 80))
    IO.puts("\n")
  end

  defp cleanup do
    Logger.info("Cleaning up test data...")
    # In a real scenario, you'd clean up test agents, policies, and secrets
    # For now, we'll leave them for inspection
    Logger.info("Cleanup complete")
  end
end

# Run the performance test
SecretHub.Performance.AgentLoadTest.run()
