# Week 30: Performance Testing & Optimization

**Date:** 2025-11-03
**Status:** 🚀 IN PROGRESS
**Goal:** Achieve production-grade performance targets

---

## Performance Targets

### Primary Goals
- ✅ **Support 1,000+ concurrent agents** - WebSocket connections
- ✅ **Handle 10,000 requests/minute** - API throughput
- ✅ **P95 latency < 100ms** - Response time
- ✅ **Memory usage stable under load** - No leaks

### Secondary Goals
- Database connection pooling optimized
- Query caching implemented
- Web UI pagination for large lists
- Real-time performance monitoring dashboard

---

## Current Baseline Configuration

### Database (PostgreSQL 16)
```elixir
# config/dev.exs
pool_size: 10
port: 5432
```

### Web Server (Bandit)
```elixir
# Phoenix Endpoint - default configuration
```

### Telemetry
- Basic Phoenix metrics (endpoint, router, channels)
- VM metrics (memory, run queue lengths)
- Telemetry poller: 10 second intervals

---

## Performance Testing Strategy

### Phase 1: Baseline Measurements (Engineer 1)
1. **Database Performance**
   - [ ] Measure current query execution times
   - [ ] Identify N+1 queries
   - [ ] Profile slow queries (> 100ms)
   - [ ] Measure connection pool utilization

2. **Core Service Performance**
   - [ ] Profile CPU usage under normal load
   - [ ] Measure memory consumption per request
   - [ ] Identify GenServer bottlenecks
   - [ ] Measure ETS table performance

3. **API Performance**
   - [ ] Baseline latency for all endpoints
   - [ ] Measure throughput (req/min)
   - [ ] Profile serialization overhead

### Phase 2: Load Testing (Engineer 2)
1. **WebSocket Connection Testing**
   - [ ] Create load testing tool for Agent connections
   - [ ] Test with 100 concurrent agents (baseline)
   - [ ] Test with 1,000 concurrent agents (target)
   - [ ] Test with 5,000 concurrent agents (stress)
   - [ ] Measure connection stability over 1 hour
   - [ ] Test reconnection storms (500 agents reconnecting simultaneously)

2. **API Stress Testing**
   - [ ] Load test authentication endpoints (AppRole login)
   - [ ] Load test secret retrieval endpoints
   - [ ] Load test policy evaluation
   - [ ] Test rate limiter under load
   - [ ] Measure P50, P95, P99 latencies

3. **Agent Performance**
   - [ ] Profile Agent memory usage
   - [ ] Test local caching effectiveness
   - [ ] Measure template rendering performance
   - [ ] Test graceful degradation on Core downtime

### Phase 3: Optimization (Engineer 1 & 2)
1. **Database Optimizations**
   - [ ] Add missing indexes
   - [ ] Optimize N+1 queries (preloading)
   - [ ] Implement query result caching (ETS/Redis)
   - [ ] Tune connection pool size
   - [ ] Enable prepared statements caching

2. **Core Service Optimizations**
   - [ ] Implement policy result caching
   - [ ] Optimize encryption/decryption hot paths
   - [ ] Use binary matching for performance
   - [ ] Reduce process message passing overhead

3. **Agent Optimizations**
   - [ ] Optimize local cache size and eviction
   - [ ] Reduce memory allocations in hot paths
   - [ ] Implement connection pooling for HTTP clients
   - [ ] Batch multiple requests when possible

### Phase 4: UI Optimization (Engineer 3)
1. **Frontend Performance**
   - [ ] Implement pagination for audit logs (100 per page)
   - [ ] Implement pagination for agent list (50 per page)
   - [ ] Implement pagination for secret list (50 per page)
   - [ ] Add lazy loading for certificate list
   - [ ] Optimize LiveView mount times

2. **API Call Optimization**
   - [ ] Reduce API calls with data consolidation
   - [ ] Implement client-side caching
   - [ ] Use Phoenix.PubSub for real-time updates
   - [ ] Optimize JSON serialization

### Phase 5: Monitoring Dashboard (Engineer 3)
1. **Performance Dashboard**
   - [ ] Real-time connection count
   - [ ] Request rate (req/sec)
   - [ ] P95/P99 latency graphs
   - [ ] Memory usage trends
   - [ ] Database pool utilization
   - [ ] Cache hit/miss rates

---

## Load Testing Tools

### K6 (Grafana K6) - Recommended
```javascript
// test-api-load.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '1m', target: 100 },   // Ramp up to 100 users
    { duration: '5m', target: 1000 },  // Ramp up to 1000 users
    { duration: '10m', target: 1000 }, // Stay at 1000 users
    { duration: '1m', target: 0 },     // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<100'], // 95% of requests must complete below 100ms
  },
};

export default function() {
  const res = http.get('http://localhost:4000/v1/sys/health');
  check(res, {
    'status is 200': (r) => r.status === 200,
    'response time < 100ms': (r) => r.timings.duration < 100,
  });
  sleep(1);
}
```

### WebSocket Load Testing (Custom Elixir Tool)
```elixir
# apps/secrethub_load_test/lib/agent_simulator.ex
defmodule SecretHub.LoadTest.AgentSimulator do
  @moduledoc """
  Simulates multiple Agent connections for load testing.
  """

  def spawn_agents(count) do
    1..count
    |> Task.async_stream(fn i ->
      connect_agent("agent-load-test-#{i}")
    end, max_concurrency: 100, timeout: 60_000)
    |> Enum.to_list()
  end

  defp connect_agent(agent_id) do
    # Implement WebSocket connection
    # Measure connection time, memory usage, message latency
  end
end
```

---

## Database Query Optimizations

### Identify Slow Queries

Enable query logging in dev.exs:
```elixir
config :secrethub_core, SecretHub.Core.Repo,
  log: :info  # Log all queries
```

Add telemetry for query timing:
```elixir
# apps/secrethub_core/lib/secrethub_core/telemetry.ex
def handle_event([:my_app, :repo, :query], measurements, metadata, _config) do
  if measurements.total_time > 100_000_000 do  # 100ms in nanoseconds
    Logger.warning("Slow query detected",
      query: metadata.query,
      source: metadata.source,
      time: System.convert_time_unit(measurements.total_time, :native, :millisecond)
    )
  end
end
```

### Common Query Patterns to Optimize

1. **N+1 Queries** - Use `Repo.preload/2`:
```elixir
# SLOW (N+1):
secrets = Repo.all(Secret)
Enum.map(secrets, fn secret -> secret.versions end)

# FAST (preload):
Repo.all(Secret) |> Repo.preload(:versions)
```

2. **Missing Indexes**:
```sql
-- Find missing indexes
CREATE INDEX IF NOT EXISTS secrets_path_idx ON secrets(path);
CREATE INDEX IF NOT EXISTS audit_logs_timestamp_idx ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS policies_entity_id_idx ON policies(entity_id);
```

3. **Expensive Aggregations** - Cache results:
```elixir
# Use ETS for caching expensive counts
def get_secret_count() do
  case :ets.lookup(:stats_cache, :secret_count) do
    [{:secret_count, count, timestamp}] when System.system_time(:second) - timestamp < 60 ->
      count
    _ ->
      count = Repo.aggregate(Secret, :count)
      :ets.insert(:stats_cache, {:secret_count, count, System.system_time(:second)})
      count
  end
end
```

---

## Connection Pool Tuning

### Current Configuration
```elixir
# config/dev.exs
pool_size: 10
```

### Recommended Production Configuration
```elixir
# config/prod.exs (or runtime.exs)
config :secrethub_core, SecretHub.Core.Repo,
  pool_size: String.to_integer(System.get_env("DB_POOL_SIZE") || "40"),
  queue_target: 50,
  queue_interval: 1000,
  timeout: 15000,
  ownership_timeout: 60000
```

**Formula for pool_size:**
- Rule of thumb: `(total_connections / number_of_nodes) * 0.8`
- For single node: 40 connections is good for moderate load
- For HA (3 nodes): `(120 / 3) = 40` connections per node

**Monitor pool usage:**
```elixir
:sys.get_state(SecretHub.Core.Repo)
|> elem(1)
|> Map.get(:queue)
|> :queue.len()
```

---

## Memory Profiling

### Using :observer
```bash
# In IEx console:
iex> :observer.start()
```

### Using :recon
```elixir
# Add to mix.exs dependencies:
{:recon, "~> 2.5"}

# Profile memory usage:
:recon.proc_count(:memory, 10)  # Top 10 processes by memory
:recon.proc_count(:reductions, 10)  # Top 10 by CPU
```

### Memory Leak Detection
```elixir
# Monitor process count
:erlang.system_info(:process_count)

# Monitor ETS table memory
:ets.i()  # Interactive ETS info
```

---

## WebSocket Connection Optimization

### Current Configuration
```elixir
# Phoenix Channel default settings
```

### Recommended Optimizations
```elixir
# apps/secrethub_web/lib/secrethub_web_web/channels/agent_channel.ex
defmodule SecretHub.WebWeb.AgentChannel do
  use Phoenix.Channel

  # Set heartbeat interval to detect dead connections
  @heartbeat_interval 30_000  # 30 seconds

  def join("agent:" <> agent_id, _params, socket) do
    # Start heartbeat timer
    Process.send_after(self(), :heartbeat, @heartbeat_interval)

    {:ok, socket}
  end

  def handle_info(:heartbeat, socket) do
    push(socket, "ping", %{})
    Process.send_after(self(), :heartbeat, @heartbeat_interval)
    {:noreply, socket}
  end
end
```

### Connection Limits
```elixir
# config/prod.exs
config :secrethub_web, SecretHub.WebWeb.Endpoint,
  http: [
    port: 4000,
    transport_options: [
      num_acceptors: 100,
      max_connections: 16_384
    ]
  ]
```

---

## Performance Monitoring Metrics

### Custom Telemetry Events

Add to `apps/secrethub_web/lib/secrethub_web_web/telemetry.ex`:

```elixir
def metrics do
  [
    # Existing Phoenix metrics...

    # Database metrics
    summary("secrethub.repo.query.total_time",
      unit: {:native, :millisecond},
      tags: [:source]
    ),
    summary("secrethub.repo.query.queue_time",
      unit: {:native, :millisecond}
    ),
    counter("secrethub.repo.query.count"),

    # Agent connection metrics
    last_value("secrethub.agents.connected.count"),
    counter("secrethub.agents.connect.count"),
    counter("secrethub.agents.disconnect.count"),

    # Secret operations
    counter("secrethub.secrets.read.count"),
    counter("secrethub.secrets.write.count"),
    summary("secrethub.secrets.read.duration",
      unit: {:native, :millisecond}
    ),

    # Policy evaluation
    counter("secrethub.policy.eval.count"),
    summary("secrethub.policy.eval.duration",
      unit: {:native, :millisecond}
    ),
    counter("secrethub.policy.cache.hit"),
    counter("secrethub.policy.cache.miss"),

    # Cache metrics
    counter("secrethub.cache.hit"),
    counter("secrethub.cache.miss"),
    last_value("secrethub.cache.size"),

    # WebSocket metrics
    summary("secrethub.websocket.message.duration",
      unit: {:native, :millisecond}
    ),
    counter("secrethub.websocket.message.count")
  ]
end
```

---

## Benchmarking Checklist

### Pre-Optimization Baseline
- [ ] Record all metrics with current configuration
- [ ] Document query execution times (P50, P95, P99)
- [ ] Measure API endpoint latencies
- [ ] Test WebSocket connection stability (100 agents, 1 hour)
- [ ] Profile memory usage (baseline)
- [ ] Document database pool utilization

### Post-Optimization Verification
- [ ] Re-run all baseline tests
- [ ] Compare improvements (% reduction in latency, memory, etc.)
- [ ] Verify no regressions in functionality
- [ ] Load test with 1,000 concurrent agents
- [ ] Stress test with 5,000 concurrent agents
- [ ] Document final performance metrics

---

## Performance Test Results

### Baseline (Before Optimization)

**To be measured...**

| Metric | Target | Baseline | After Optimization |
|--------|--------|----------|-------------------|
| Max concurrent agents | 1,000+ | TBD | TBD |
| API throughput (req/min) | 10,000 | TBD | TBD |
| P95 latency (ms) | < 100 | TBD | TBD |
| Memory per agent (KB) | < 100 | TBD | TBD |
| Database pool usage (%) | < 80 | TBD | TBD |
| WebSocket message latency (ms) | < 50 | TBD | TBD |

---

## Known Bottlenecks (To be identified)

### Database
- [ ] TBD after profiling

### Core Service
- [ ] TBD after profiling

### Agent
- [ ] TBD after profiling

### Web UI
- [ ] TBD after profiling

---

## Optimization Implementation Tracker

### Database Optimizations
- [ ] Add indexes for frequently queried columns
- [ ] Implement ETS caching for policy evaluation
- [ ] Implement Redis caching for secret metadata
- [ ] Optimize N+1 queries with preloading
- [ ] Tune connection pool size

### Core Service Optimizations
- [ ] Profile and optimize encryption hot paths
- [ ] Implement policy evaluation caching
- [ ] Optimize GenServer message handling
- [ ] Use binary pattern matching for performance

### Agent Optimizations
- [ ] Implement connection pooling for HTTP
- [ ] Optimize local cache implementation
- [ ] Reduce memory allocations in hot paths
- [ ] Batch requests when possible

### Web UI Optimizations
- [ ] Add pagination to audit logs (100/page)
- [ ] Add pagination to agent list (50/page)
- [ ] Add pagination to secret list (50/page)
- [ ] Implement lazy loading for large data
- [ ] Reduce API calls with data consolidation

### Monitoring
- [ ] Create performance dashboard LiveView
- [ ] Add real-time metrics visualization
- [ ] Implement alerting for performance degradation

---

## Next Steps

1. **Immediate Actions:**
   - Create load testing tool for WebSocket connections
   - Set up database query profiling
   - Measure baseline performance metrics

2. **Week 30 Deliverables:**
   - Performance testing report
   - Optimized database configuration
   - Query caching implementation
   - Web UI pagination
   - Performance monitoring dashboard
   - Load test results (1,000 agents)

---

**Status:** Ready to begin baseline measurements
**Next:** Set up query profiling and measure current performance
