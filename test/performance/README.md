# Performance Testing

This directory contains performance and load testing scripts for SecretHub.

## Overview

Performance tests simulate real-world scenarios with many concurrent agents accessing the system. These tests help ensure SecretHub can handle production loads and identify bottlenecks.

## Tests

### Agent Load Test (`agent_load_test.exs`)

Simulates 100 concurrent agents performing various operations:

1. **Agent Registration**: All agents register simultaneously
2. **Authentication**: All agents authenticate with AppRole credentials
3. **Secret Reads**: Agents make concurrent read requests
4. **Mixed Workload**: 70% reads, 30% writes

**Metrics Collected:**
- Throughput (operations/second)
- Latency (average, min, max, P95, P99)
- Success/failure rates
- Duration of each test phase

## Running Performance Tests

### Prerequisites

1. Database must be running and migrated:
   ```bash
   db-setup
   ```

2. Ensure vault is initialized (or script will initialize it):
   ```bash
   mix run -e "SecretHub.Core.Vault.SealState.initialize(3, 2)"
   ```

### Run Tests

```bash
# Run the main agent load test
mix run test/performance/agent_load_test.exs

# Or with specific Mix environment
MIX_ENV=dev mix run test/performance/agent_load_test.exs
```

### Configuration

Edit the test script to adjust parameters:

```elixir
@agent_count 100              # Number of concurrent agents
@requests_per_agent 10        # Requests each agent makes
@secret_count 50              # Number of test secrets
```

## Expected Results (MVP Baseline)

Target performance metrics for MVP:

| Metric | Target | Notes |
|--------|--------|-------|
| Agent Registration | > 50 ops/sec | Concurrent registration |
| Authentication | > 100 ops/sec | AppRole auth throughput |
| Secret Reads | > 500 ops/sec | Concurrent read operations |
| Mixed Workload | > 200 ops/sec | 70% read, 30% write |
| P95 Latency (Auth) | < 100ms | 95th percentile |
| P99 Latency (Auth) | < 200ms | 99th percentile |
| P95 Latency (Reads) | < 50ms | 95th percentile |

## Interpreting Results

### Good Performance Indicators

- ✅ High throughput (meets or exceeds targets)
- ✅ Low P95/P99 latencies
- ✅ 100% success rate (no errors)
- ✅ Consistent latencies across test phases

### Performance Issues

- ⚠️ High P99 latency (indicates outliers/bottlenecks)
- ⚠️ Low throughput (< 50% of target)
- ❌ Errors or timeouts
- ❌ Increasing latency over time (memory leaks)

### Common Bottlenecks

1. **Database Connection Pool**: Increase pool size if you see connection timeouts
2. **Ecto Sandbox**: Tests may be slower due to transaction rollbacks
3. **Crypto Operations**: Certificate generation and Shamir operations are CPU-intensive
4. **Audit Logging**: High-volume audit writes can slow down operations

## Profiling

To profile performance bottlenecks:

```bash
# Install profiling tools
mix deps.get

# Profile with fprof
iex -S mix
> :fprof.apply(&SecretHub.Performance.AgentLoadTest.run/0, [])
> :fprof.profile()
> :fprof.analyse()

# Or use :eprof for lighter profiling
> :eprof.start()
> :eprof.profile([], &SecretHub.Performance.AgentLoadTest.run/0, [])
> :eprof.analyze()
```

## Production Considerations

Performance test results in development may differ from production:

- **Development**: Uses Ecto Sandbox, local PostgreSQL, single node
- **Production**: Uses connection pools, managed PostgreSQL, potentially clustered

Production will likely have:
- ✅ Better database performance (managed service, optimized config)
- ✅ Better network latency (services in same VPC)
- ✅ Better caching (Redis for sessions/tokens)
- ❌ More network overhead (mTLS between services)
- ❌ More audit logging overhead

## Continuous Performance Testing

Integrate performance tests into CI/CD:

```yaml
# .github/workflows/performance.yml
name: Performance Tests
on: [push]
jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: erlef/setup-beam@v1
      - run: mix deps.get
      - run: db-setup
      - run: mix run test/performance/agent_load_test.exs
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: performance-results
          path: test/performance/results/
```

## Future Tests

Additional performance tests to implement:

- [ ] WebSocket connection scaling (1000+ concurrent agents)
- [ ] Certificate renewal under load
- [ ] Dynamic secret generation (PostgreSQL/AWS)
- [ ] Audit log write throughput
- [ ] Policy evaluation performance
- [ ] Lease management at scale
- [ ] Cluster failover and recovery

## Resources

- [Elixir Performance Best Practices](https://hexdocs.pm/elixir/performance.html)
- [Phoenix Performance Guide](https://hexdocs.pm/phoenix/performance.html)
- [Ecto Performance Tips](https://hexdocs.pm/ecto/Ecto.html#module-performance-tips)
