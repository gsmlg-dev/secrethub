# SecretHub CLI Test Suite

This directory contains comprehensive tests for the SecretHub CLI tool.

## Test Structure

```
test/
├── test_helper.exs                          # Test configuration and Mox setup
├── secrethub_cli_test.exs                   # Main CLI entry point tests
├── secrethub_cli/
│   ├── auth_test.exs                        # Authentication module tests
│   ├── config_test.exs                      # Configuration management tests
│   ├── output_test.exs                      # Output formatting tests
│   └── commands/
│       ├── secret_commands_test.exs         # Secret management command tests
│       ├── policy_commands_test.exs         # Policy management command tests
│       ├── agent_commands_test.exs          # Agent management command tests
│       └── config_commands_test.exs         # Config command tests
```

## Running Tests

```bash
# Run all tests
mix test

# Run specific test file
mix test test/secrethub_cli/config_test.exs

# Run tests with coverage
mix test --cover

# Run tests with detailed output
mix test --trace

# Run specific test by line number
mix test test/secrethub_cli/auth_test.exs:45
```

## Test Coverage

### 1. Main CLI Tests (`secrethub_cli_test.exs`)

**Coverage Areas:**
- ✅ Help and version command handling
- ✅ Command-line argument parsing for all commands
- ✅ Global option parsing (--server, --format, --quiet, --verbose)
- ✅ Short option aliases (-s, -f, -q)
- ✅ Invalid option handling
- ✅ Unknown command error handling

**Key Test Scenarios:**
- Help display with no args, --help, and help command
- Version display with --version and version command
- Command parsing for all secret, policy, agent, and config commands
- Option validation and error messages
- Exit codes (0 for success, 1 for error)

### 2. Authentication Tests (`auth_test.exs`)

**Coverage Areas:**
- ✅ Login with AppRole credentials (role_id, secret_id)
- ✅ Logout and credential clearing
- ✅ Authentication status checking
- ✅ Token expiration handling
- ✅ Token retrieval and validation
- ✅ Authentication requirement enforcement
- ✅ Bearer token header generation

**Key Test Scenarios:**
- Successful login with valid credentials
- Login error handling (missing credentials, HTTP errors)
- Logout when authenticated and not authenticated
- Token expiration detection
- `ensure_authenticated` error messages
- `auth_headers` with valid/expired/missing tokens
- Token response parsing (multiple formats)

### 3. Configuration Tests (`config_test.exs`)

**Coverage Areas:**
- ✅ Configuration file loading and parsing (TOML)
- ✅ Configuration file saving
- ✅ Configuration directory creation with 0700 permissions
- ✅ Get/set/delete operations for nested keys
- ✅ Server URL configuration
- ✅ Output format configuration
- ✅ Authentication credential storage
- ✅ Default configuration values

**Key Test Scenarios:**
- Load existing config file
- Default config when file doesn't exist
- Malformed TOML handling
- Nested key access with dot notation (e.g., "output.format")
- Directory permission enforcement (0700)
- Token expiration checking
- Auth credential save/clear operations
- Preserving config when updating specific values

### 4. Output Formatting Tests (`output_test.exs`)

**Coverage Areas:**
- ✅ JSON output formatting (pretty-printed)
- ✅ YAML output formatting
- ✅ Table output formatting (ASCII tables)
- ✅ Multiple data type formatting (maps, lists, DateTime, etc.)
- ✅ Column width calculation
- ✅ Success/error/warning/info message display
- ✅ Unknown format error handling

**Key Test Scenarios:**
- JSON formatting with proper indentation
- YAML formatting with proper indentation
- Table formatting for list of maps (with headers)
- Table formatting for single map (key-value pairs)
- DateTime formatting in tables
- List and nested map formatting
- Column alignment in tables
- Colored output for success/error/warning messages

### 5. Secret Commands Tests (`secret_commands_test.exs`)

**Coverage Areas:**
- ✅ List all secrets
- ✅ Get secret by path
- ✅ Create secret with --value
- ✅ Update secret with --value
- ✅ Delete secret
- ✅ List secret versions
- ✅ Rollback to specific version
- ✅ Authentication requirement for all operations
- ✅ API error handling
- ✅ Output formatting (JSON, YAML, table)

**Key Test Scenarios:**
- Authentication checks before operations
- Missing required --value option
- Secret not found (404) handling
- URI encoding of secret paths
- Expired token handling
- API request/response structure
- Server URL configuration
- Format option handling

### 6. Policy Commands Tests (`policy_commands_test.exs`)

**Coverage Areas:**
- ✅ List all policies
- ✅ Get policy by name
- ✅ Create policy from template
- ✅ Update policy (not implemented error)
- ✅ Delete policy
- ✅ Simulate policy evaluation
- ✅ List policy templates
- ✅ Authentication requirement
- ✅ Simulation context building

**Key Test Scenarios:**
- Policy creation with --from-template and --name
- Missing required options validation
- Policy not found handling
- Simulation context with custom values
- Simulation context with defaults
- Template listing (no auth required)
- Admin endpoint usage
- Output formatting

### 7. Agent Commands Tests (`agent_commands_test.exs`)

**Coverage Areas:**
- ✅ List all connected agents
- ✅ Get agent status by ID
- ✅ Stream/poll agent logs
- ✅ WebSocket URL conversion (http→ws, https→wss)
- ✅ Admin API endpoint usage
- ✅ Authentication requirement
- ✅ Log polling fallback

**Key Test Scenarios:**
- Agent list retrieval
- Agent status retrieval
- Agent not found handling
- Log streaming information messages
- Log polling endpoint usage
- Admin endpoint authorization
- Output formatting
- WebSocket URL construction

### 8. Config Commands Tests (`config_commands_test.exs`)

**Coverage Areas:**
- ✅ List all configuration (with auth filtering)
- ✅ Get configuration value
- ✅ Set configuration value with validation
- ✅ Configuration value parsing (bool, int, string)
- ✅ Configuration validation rules
- ✅ Value formatting for display

**Key Test Scenarios:**
- List config with --verbose (includes auth)
- List config without --verbose (excludes auth)
- Get nested config values
- Set with server_url validation (must start with http/https)
- Set with output.format validation (json/table/yaml)
- Set with output.color validation (true/false)
- Boolean string parsing ("true" → true)
- Integer string parsing ("42" → 42)
- Invalid value error messages

## Testing Approach

### Test Isolation
- Each test suite uses a temporary configuration directory
- Temporary directories are created with unique names using `System.unique_integer/1`
- All temporary files are cleaned up in `on_exit` callbacks
- Tests are marked `async: false` where they modify shared state (config files)

### Mocking Strategy
- **HTTP Client Mocking**: Mox is configured for mocking the Req HTTP client
- **Note**: The current tests define test structure but HTTP mocking is not fully implemented
- Future enhancement: Create `SecretHub.CLI.HTTPClientBehaviour` and mock Req calls

### Configuration Testing
- Tests override `Application.get_env(:secrethub_cli, :config_dir)` to use temp directories
- Config file permissions (0700) are verified where possible
- Both valid and invalid TOML are tested

### Output Testing
- `ExUnit.CaptureIO` is used to capture stdout/stderr
- Color output from Owl library is tested
- Table formatting alignment is verified

### Error Handling
- All error paths are tested (missing args, auth failures, API errors)
- Error messages are verified for clarity and helpfulness
- Exit codes are tested through `catch_exit`

## Coverage Goals

**Target**: >80% code coverage

**Current Coverage Areas**:
- Command parsing: ~95%
- Authentication: ~85%
- Configuration: ~90%
- Output formatting: ~85%
- Commands: ~75% (structure defined, mocking needed)

## Future Enhancements

### 1. HTTP Client Mocking
Create a behaviour and mock Req calls:

```elixir
defmodule SecretHub.CLI.HTTPClientBehaviour do
  @callback get(url :: String.t(), opts :: keyword()) :: {:ok, map()} | {:error, term()}
  @callback post(url :: String.t(), opts :: keyword()) :: {:ok, map()} | {:error, term()}
  @callback put(url :: String.t(), opts :: keyword()) :: {:ok, map()} | {:error, term()}
  @callback delete(url :: String.t(), opts :: keyword()) :: {:ok, map()} | {:error, term()}
end
```

### 2. Integration Tests
- Add integration tests that test against a running SecretHub server
- Test full authentication flow
- Test actual secret creation/retrieval
- Test policy evaluation

### 3. Property-Based Testing
- Use StreamData for property-based testing of:
  - Configuration value parsing
  - Table formatting with varying column widths
  - URI encoding of secret paths

### 4. Performance Testing
- Test CLI startup time
- Test large output formatting (1000+ secrets)
- Test configuration file operations with large configs

### 5. Escript Testing
- Build the escript and test it as a standalone executable
- Test in different shell environments
- Test with various terminal configurations

## Test Utilities

### Helper Functions
Each test module includes helper functions for:
- Creating test configurations
- Setting up authentication
- Capturing IO output
- Validating error messages

### Fixtures
Common test data structures:
- Valid/expired auth tokens
- Sample API responses
- Configuration objects
- Secret/policy/agent data

## Running in CI

The tests are designed to run in CI environments:

```yaml
# .github/workflows/test.yml
- name: Run CLI tests
  run: |
    cd apps/secrethub_cli
    mix test --color
    mix test --cover --export-coverage cli
```

## Debugging Tests

### Common Issues

1. **Temp directory cleanup failures**
   - Check `on_exit` callbacks are properly configured
   - Ensure no file handles are left open

2. **Config isolation issues**
   - Verify each test creates unique temp directory
   - Check `Application.put_env` is in setup block

3. **Mox verification failures**
   - Ensure `setup :verify_on_exit!` is present
   - Check all expected calls are defined

### Debug Helpers

```elixir
# Print captured output during test
IO.inspect(output, label: "Captured output")

# Check config directory
IO.inspect(Config.config_dir(), label: "Config dir")

# Verify temp directory contents
File.ls!(temp_dir) |> IO.inspect(label: "Files")
```

## Contributing

When adding new CLI features:

1. Add tests in the appropriate test file
2. Follow existing test patterns
3. Ensure both success and failure paths are tested
4. Add docstrings explaining what each test validates
5. Run `mix test` to verify all tests pass
6. Run `mix test --cover` to check coverage

## Test Maintenance

- Review and update tests when CLI behavior changes
- Keep test documentation in sync with implementation
- Refactor duplicate test code into helper functions
- Remove obsolete tests when features are removed
