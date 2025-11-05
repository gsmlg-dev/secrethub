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


┌──────────────────────────────────────────┐
│         Push version tag (v1.0.0)        │
└────────────────┬─────────────────────────┘
                 │
    ┌────────────┴────────────────────────────────┐
    │       Release Workflow (4 parallel jobs)    │
    │                                             │
    ├──────────┬────────────┬─────────┬──────────┤
    │          │            │         │          │
┌───▼───┐  ┌──▼───┐  ┌─────▼────┐ ┌─▼─────────┐
│ Build │  │Build │  │  Build   │ │  Build    │
│ Core  │  │Agent │  │   Core   │ │  Agent    │
│Release│  │Release│ │  Docker  │ │  Docker   │
└───┬───┘  └──┬───┘  └────┬─────┘ └─────┬─────┘
    │         │            │             │
    └─────────┴────────────┴─────────────┘
                     │
              ┌──────▼───────┐
              │   Create     │
              │   GitHub     │
              │   Release    │
              └──────────────┘
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
![CI](https://github.com/gsmlg-dev/secrethub/workflows/CI/badge.svg)
![Test](https://github.com/gsmlg-dev/secrethub/workflows/Test/badge.svg)
![Release](https://github.com/gsmlg-dev/secrethub/workflows/Release/badge.svg)
```

- **CI badge**: Combined status of all four parallel jobs (Compile, Format, Credo, Dialyzer)
- **Test badge**: Test suite execution status
- **Release badge**: Latest release build status

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

### 3. Release (`release.yml`)

**Triggers**:
- Push to version tags (e.g., `v1.0.0`, `v1.2.3`)
- Manual dispatch via GitHub Actions UI

**Purpose**: Build production releases and Docker images

**Jobs** (4 parallel jobs + final job):

1. **Build Core Release**
   - Compiles Core + Web + Shared apps
   - Builds frontend assets with npm
   - Creates OTP release tarball
   - **Output**: `secrethub_core-vX.Y.Z.tar.gz`

2. **Build Agent Release**
   - Compiles Agent + Shared apps
   - Creates OTP release tarball
   - **Output**: `secrethub_agent-vX.Y.Z.tar.gz`

3. **Build Core Docker Image**
   - Multi-stage Docker build
   - Multi-architecture (amd64, arm64)
   - Published to GitHub Container Registry
   - **Image**: `ghcr.io/gsmlg-dev/secrethub/core:vX.Y.Z`

4. **Build Agent Docker Image**
   - Multi-stage Docker build
   - Multi-architecture (amd64, arm64)
   - Published to GitHub Container Registry
   - **Image**: `ghcr.io/gsmlg-dev/secrethub/agent:vX.Y.Z`

5. **Create GitHub Release** (final job)
   - Waits for all 4 build jobs to complete
   - Downloads all artifacts
   - Generates release notes
   - Creates GitHub release with:
     - Binary tarballs
     - Docker image references
     - Quick start instructions

**Docker Tags**:
Each Docker image is tagged with:
- Full version: `v1.0.0`
- Major.Minor: `1.0`
- Major: `1`
- Git SHA: `sha-abc1234`
- Latest: `latest` (only for default branch tags)

**Typical Duration**: 20-25 minutes (parallel execution)

**Usage**:
```bash
# Tag-based release (recommended)
git tag v1.0.0
git push origin v1.0.0

# Manual release via GitHub UI
# Go to Actions → Release → Run workflow
```

**Artifacts**:
- Binary releases downloadable from GitHub Releases
- Docker images published to `ghcr.io/gsmlg-dev/secrethub/`

---

## Future Enhancements

Planned workflow additions:

- [ ] **Security Scanning**: Add Sobelow security scanner
- [ ] **Dependency Audit**: Check for vulnerable dependencies
- [ ] **Performance Testing**: Run performance benchmarks on PRs
- [ ] **E2E Tests**: Run E2E integration tests in isolated environment
- [x] **Release**: Automated release creation and Docker image publishing ✅
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
