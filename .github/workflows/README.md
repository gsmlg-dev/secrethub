# GitHub Actions Workflows

This directory contains CI/CD workflows for SecretHub.

## Workflows

### 1. CI (`ci.yml`)

**Triggers**: Push to any branch

**Purpose**: Static analysis, linting, and code quality checks

**Jobs** (run in parallel):
1. **Compile**: Compiles code with `--warnings-as-errors`
2. **Format**: Checks code formatting with `mix format --check-formatted`
3. **Credo**: Runs Credo in strict mode for linting
4. **Dialyzer**: Runs static type analysis

**Dependencies**: None (all jobs run independently in parallel)

**Typical Duration**:
- Individual jobs: 2-5 minutes each
- Total wall time: ~5 minutes (with parallelization)
- Sequential equivalent: ~15 minutes

**Caching**:
- Dependencies cache (`deps`, `_build`) - shared across all jobs
- Dialyzer PLT cache (`priv/plts`) - specific to Dialyzer job

**Performance Benefits**:
- 3x faster than sequential execution
- Each job can fail independently
- Clear separation of concerns
- Easy to identify which check failed

---

### 2. Test (`test.yml`)

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main`

**Purpose**: Run test suite with database and Redis

**Jobs**:
- **Test**: Runs full test suite
  - Sets up PostgreSQL 16 service
  - Sets up Redis 7 service
  - Creates and migrates test database
  - Runs `mix test`
  - Generates coverage report (HTML)
  - Uploads coverage artifacts

**Services**:
- PostgreSQL 16 (`secrethub:secrethub_test_password`)
- Redis 7 (port 6379)

**Environment Variables**:
```
MIX_ENV=test
DATABASE_URL=postgresql://secrethub:secrethub_test_password@localhost:5432/secrethub_test
REDIS_URL=redis://localhost:6379
```

**Artifacts**:
- Coverage report (`cover/` directory)

**Typical Duration**: 10-15 minutes

---

## Workflow Dependencies

```
┌──────────────────────────────────────────┐
│            Push to any branch            │
└────────────────┬─────────────────────────┘
                 │
    ┌────────────┴────────────────┐
    │                             │
    │   CI Workflow (parallel)    │
    │                             │
    ├─────────┬────────┬──────────┤
    │         │        │          │
┌───▼───┐ ┌──▼───┐ ┌──▼────┐ ┌───▼──────┐
│Compile│ │Format│ │ Credo │ │ Dialyzer │
└───────┘ └──────┘ └───────┘ └──────────┘
                 │
                 │ (if main/develop)
                 │
            ┌────▼─────┐
            │   Test   │
            │ (with DB)│
            └──────────┘
```

**Benefits of Parallel Execution:**
- All CI jobs run simultaneously
- Fastest feedback (limited by slowest job, not sum of all jobs)
- Easy to identify specific failures
- Independent caching per job
- Can continue even if one job fails (soft failure)

## Caching Strategy

All workflows use GitHub Actions cache to speed up builds:

### Dependencies Cache
- **Key**: `${{ runner.os }}-mix-${{ hashFiles('**/mix.lock') }}`
- **Paths**: `deps/`, `_build/`
- **Invalidation**: When `mix.lock` changes

### Dialyzer PLT Cache
- **Key**: `dialyzer-${{ hashFiles('mix.lock') }}`
- **Path**: `priv/plts/`
- **Invalidation**: When `mix.lock` changes

## Status Badges

Add these to your README.md:

```markdown
![CI](https://github.com/YOUR_USERNAME/secrethub/workflows/CI/badge.svg)
![Test](https://github.com/YOUR_USERNAME/secrethub/workflows/Test/badge.svg)
```

The CI badge shows the combined status of all four parallel jobs (Compile, Format, Credo, Dialyzer).

## Local Testing

To run the same checks locally before pushing:

```bash
# Format check
mix format --check-formatted

# Compile with warnings as errors
mix compile --warnings-as-errors

# Run Credo
mix credo --strict

# Run Dialyzer
mix dialyzer

# Run tests
mix test

# Generate coverage
mix coveralls.html
```

Or use the convenience script:

```bash
# Run all quality checks
./scripts/quality-check.sh
```

## Troubleshooting

### CI Workflow Failures

#### Compilation Errors
```
Error: mix compile --warnings-as-errors failed
```

**Solution**: Fix compilation warnings locally:
```bash
mix compile --warnings-as-errors
```

#### Credo Failures
```
Error: mix credo --strict failed
```

**Solution**: Fix Credo issues:
```bash
mix credo --strict
# Or auto-fix where possible
mix credo suggest --format=oneline
```

#### Dialyzer Failures
```
Error: mix dialyzer --halt-exit-status failed
```

**Solution**: Fix type errors:
```bash
mix dialyzer
# Add type specs or fix type inconsistencies
```

### Test Workflow Failures

#### Database Connection Errors
```
Error: could not connect to database
```

**Cause**: PostgreSQL service not ready

**Solution**: The workflow includes health checks, but if issues persist:
- Check PostgreSQL service configuration
- Verify DATABASE_URL environment variable
- Ensure migrations are running

#### Test Failures
```
Error: mix test failed with N failures
```

**Solution**: Run tests locally with same setup:
```bash
MIX_ENV=test mix ecto.create
MIX_ENV=test mix ecto.migrate
MIX_ENV=test mix test
```

### Format Check Failures

```
Error: mix format --check-formatted failed
```

**Solution**: Format code locally:
```bash
mix format
git add .
git commit -m "style: format code"
```

## Performance Optimization

### Faster CI Runs

1. **Use cache effectively**: The workflows cache dependencies and PLT
2. **Run Dialyzer incrementally**: PLT is cached between runs
3. **Parallel jobs**: Format check runs in parallel with CI

### Reducing False Positives

If Dialyzer reports false positives, add to `dialyzer_ignore.exs`:

```elixir
[
  {"lib/some_file.ex", :pattern_match_cov},
  {"lib/other_file.ex", :no_return}
]
```

## Security Considerations

### Secrets Management

**DO NOT** commit secrets to workflows. Use GitHub Secrets:

1. Go to repository Settings → Secrets and variables → Actions
2. Add secrets (e.g., `DATABASE_PASSWORD`)
3. Reference in workflow:
   ```yaml
   env:
     DATABASE_PASSWORD: ${{ secrets.DATABASE_PASSWORD }}
   ```

### Dependency Security

The workflows use specific versions:
- `actions/checkout@v4`
- `erlef/setup-beam@v1`
- `actions/cache@v4`
- `actions/upload-artifact@v4`

**Update regularly** to get security patches.

## Future Enhancements

Planned workflow additions:

- [ ] **Security Scanning**: Add Sobelow security scanner
- [ ] **Dependency Audit**: Check for vulnerable dependencies
- [ ] **Performance Testing**: Run performance benchmarks on PRs
- [ ] **E2E Tests**: Run E2E integration tests in isolated environment
- [ ] **Release**: Automated release creation and Docker image publishing
- [ ] **Deploy**: Automated deployment to staging/production

## Contributing

When adding new workflows:

1. Follow naming convention: `kebab-case.yml`
2. Add comprehensive documentation
3. Use appropriate caching
4. Add status checks to branch protection rules
5. Test locally before committing

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [erlef/setup-beam](https://github.com/erlef/setup-beam)
- [Elixir CI Best Practices](https://hexdocs.pm/elixir/writing-documentation.html)
