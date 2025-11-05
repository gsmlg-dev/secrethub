defmodule SecretHub.WebWeb.Telemetry do
  use Supervisor
  import Telemetry.Metrics

  def start_link(arg) do
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  @impl true
  def init(_arg) do
    children = [
      # Telemetry poller will execute the given period measurements
      # every 10_000ms. Learn more here: https://hexdocs.pm/telemetry_metrics
      {:telemetry_poller, measurements: periodic_measurements(), period: 10_000}
      # Add reporters as children of your supervision tree.
      # {Telemetry.Metrics.ConsoleReporter, metrics: metrics()}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  def metrics do
    [
      # Phoenix Metrics
      summary("phoenix.endpoint.start.system_time",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.endpoint.stop.duration",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.start.system_time",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.exception.duration",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.stop.duration",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.socket_connected.duration",
        unit: {:native, :millisecond}
      ),
      sum("phoenix.socket_drain.count"),
      summary("phoenix.channel_joined.duration",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.channel_handled_in.duration",
        tags: [:event],
        unit: {:native, :millisecond}
      ),

      # Database Metrics
      summary("secrethub.repo.query.total_time",
        unit: {:native, :millisecond},
        tags: [:source],
        description: "Total time spent executing database queries"
      ),
      summary("secrethub.repo.query.queue_time",
        unit: {:native, :millisecond},
        description: "Time spent waiting for database connection from pool"
      ),
      summary("secrethub.repo.query.decode_time",
        unit: {:native, :millisecond},
        description: "Time spent decoding database results"
      ),
      counter("secrethub.repo.query.count",
        tags: [:source],
        description: "Total number of database queries executed"
      ),

      # Agent Connection Metrics
      last_value("secrethub.agents.connected.count",
        description: "Current number of connected agents"
      ),
      counter("secrethub.agents.connect.count",
        description: "Total agent connection attempts"
      ),
      counter("secrethub.agents.disconnect.count",
        tags: [:reason],
        description: "Total agent disconnections"
      ),
      summary("secrethub.agents.connection.duration",
        unit: {:native, :millisecond},
        description: "Time to establish agent connection"
      ),

      # Secret Operations Metrics
      counter("secrethub.secrets.read.count",
        tags: [:status],
        description: "Total secret read operations"
      ),
      counter("secrethub.secrets.write.count",
        tags: [:status],
        description: "Total secret write operations"
      ),
      summary("secrethub.secrets.read.duration",
        unit: {:native, :millisecond},
        description: "Time to read secret including decryption"
      ),
      summary("secrethub.secrets.write.duration",
        unit: {:native, :millisecond},
        description: "Time to write secret including encryption"
      ),

      # Policy Evaluation Metrics
      counter("secrethub.policy.eval.count",
        tags: [:result],
        description: "Total policy evaluations"
      ),
      summary("secrethub.policy.eval.duration",
        unit: {:native, :millisecond},
        description: "Time to evaluate policy"
      ),
      counter("secrethub.policy.cache.hit",
        description: "Policy evaluation cache hits"
      ),
      counter("secrethub.policy.cache.miss",
        description: "Policy evaluation cache misses"
      ),

      # Cache Metrics
      counter("secrethub.cache.hit",
        tags: [:cache_type],
        description: "Cache hit count by cache type"
      ),
      counter("secrethub.cache.miss",
        tags: [:cache_type],
        description: "Cache miss count by cache type"
      ),
      last_value("secrethub.cache.size",
        tags: [:cache_type],
        unit: :byte,
        description: "Current cache size in bytes"
      ),

      # WebSocket Metrics
      summary("secrethub.websocket.message.duration",
        unit: {:native, :millisecond},
        tags: [:message_type],
        description: "WebSocket message handling time"
      ),
      counter("secrethub.websocket.message.count",
        tags: [:message_type],
        description: "Total WebSocket messages processed"
      ),
      counter("secrethub.websocket.error.count",
        tags: [:error_type],
        description: "WebSocket errors"
      ),

      # Rate Limiter Metrics
      counter("secrethub.rate_limit.check.count",
        tags: [:scope, :result],
        description: "Rate limit checks performed"
      ),
      counter("secrethub.rate_limit.exceeded.count",
        tags: [:scope],
        description: "Rate limit violations"
      ),

      # VM Metrics
      summary("vm.memory.total", unit: {:byte, :kilobyte}),
      summary("vm.memory.processes", unit: {:byte, :kilobyte}),
      summary("vm.memory.ets", unit: {:byte, :kilobyte}),
      summary("vm.total_run_queue_lengths.total"),
      summary("vm.total_run_queue_lengths.cpu"),
      summary("vm.total_run_queue_lengths.io"),
      last_value("vm.process_count",
        description: "Current number of processes"
      ),
      last_value("vm.port_count",
        description: "Current number of ports"
      )
    ]
  end

  defp periodic_measurements do
    [
      # VM measurements
      {__MODULE__, :measure_vm_metrics, []},
      # Custom measurements
      {__MODULE__, :measure_cache_stats, []},
      {__MODULE__, :measure_agent_connections, []}
    ]
  end

  @doc """
  Measure VM metrics periodically.
  """
  def measure_vm_metrics do
    # VM memory metrics
    memory = :erlang.memory()
    :telemetry.execute([:vm, :memory], %{
      total: memory[:total],
      processes: memory[:processes],
      ets: memory[:ets]
    }, %{})

    # Process and port counts
    :telemetry.execute([:vm, :process_count], %{count: :erlang.system_info(:process_count)}, %{})
    :telemetry.execute([:vm, :port_count], %{count: :erlang.system_info(:port_count)}, %{})
  end

  @doc """
  Measure cache statistics periodically.
  """
  def measure_cache_stats do
    # Measure ETS table sizes for various caches
    cache_tables = [
      :rate_limiter_table,
      :policy_cache,
      :secret_cache
    ]

    Enum.each(cache_tables, fn table_name ->
      case :ets.whereis(table_name) do
        :undefined ->
          :ok

        _table ->
          info = :ets.info(table_name)
          size_bytes = info[:memory] * :erlang.system_info(:wordsize)

          :telemetry.execute(
            [:secrethub, :cache, :size],
            %{bytes: size_bytes},
            %{cache_type: table_name}
          )
      end
    end)
  end

  @doc """
  Measure connected agent count periodically.
  """
  def measure_agent_connections do
    # This will need to be implemented based on how agents are tracked
    # For now, we'll check for Phoenix.PubSub subscribers
    try do
      # Count subscribers to agent channels
      count = Phoenix.PubSub.subscribers(SecretHub.Web.PubSub, "agents")
              |> length()

      :telemetry.execute(
        [:secrethub, :agents, :connected],
        %{count: count},
        %{}
      )
    rescue
      _ -> :ok
    end
  end
end
