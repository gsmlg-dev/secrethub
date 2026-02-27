defmodule SecretHub.CLI do
  @moduledoc """
  SecretHub CLI - Command-line interface for SecretHub secrets management.

  ## Usage

      secrethub [command] [options]

  ## Commands

  ### Authentication
  - `login` - Authenticate with SecretHub server
  - `logout` - Clear authentication credentials
  - `whoami` - Show current authentication status

  ### Secrets Management
  - `secret list` - List all secrets
  - `secret get <path>` - Get a secret value
  - `secret create <path>` - Create a new secret
  - `secret update <path>` - Update an existing secret
  - `secret delete <path>` - Delete a secret
  - `secret versions <path>` - Show version history
  - `secret rollback <path> <version>` - Rollback to a version

  ### Policy Management
  - `policy list` - List all policies
  - `policy get <name>` - Get policy details
  - `policy create` - Create a new policy
  - `policy update <name>` - Update a policy
  - `policy delete <name>` - Delete a policy
  - `policy simulate <name>` - Simulate policy evaluation
  - `policy templates` - List available policy templates

  ### Agent Management
  - `agent list` - List connected agents
  - `agent status <id>` - Get agent status
  - `agent logs <id>` - Stream agent logs

  ### Configuration
  - `config set <key> <value>` - Set configuration value
  - `config get <key>` - Get configuration value
  - `config list` - List all configuration

  ## Global Options

  - `--server <url>` - SecretHub server URL (default: http://localhost:4000)
  - `--format <json|table|yaml>` - Output format (default: table)
  - `--quiet` - Suppress non-error output
  - `--verbose` - Show detailed output
  - `--help` - Show help message

  ## Examples

      # Login to SecretHub
      secrethub login --role-id <role-id> --secret-id <secret-id>

      # Get a secret
      secrethub secret get prod.db.postgres.password

      # Create a secret
      secrethub secret create dev.api.key --value "sk-1234"

      # List policies
      secrethub policy list

      # Create policy from template
      secrethub policy create --from-template business_hours --name "Dev Access"

  ## Configuration

  The CLI stores configuration in `~/.secrethub/config.toml`:

      server_url = "https://secrethub.example.com"
      default_format = "table"
      [auth]
      token = "..."
      expires_at = "2024-12-31T23:59:59Z"
  """

  alias SecretHub.CLI.{Auth, Completion}

  alias SecretHub.CLI.Commands.{
    AgentCommands,
    ConfigCommands,
    LoginCommand,
    PolicyCommands,
    SecretCommands
  }

  @version Mix.Project.config()[:version]

  @doc """
  Main entry point for the CLI (called by escript).
  """
  def main(args) do
    args
    |> parse_args()
    |> execute()
    |> handle_result()
  end

  @doc false
  def parse_args(args) do
    {opts, remaining, invalid} =
      OptionParser.parse(args,
        strict: [
          help: :boolean,
          version: :boolean,
          server: :string,
          format: :string,
          quiet: :boolean,
          verbose: :boolean,
          role_id: :string,
          secret_id: :string,
          value: :string,
          from_template: :string,
          name: :string
        ],
        aliases: [
          h: :help,
          v: :version,
          s: :server,
          f: :format,
          q: :quiet
        ]
      )

    if invalid != [] do
      {:error, "Invalid options: #{inspect(invalid)}"}
    else
      command = parse_command(remaining)
      {:ok, command, opts}
    end
  end

  defp parse_command([]), do: :help
  defp parse_command(["help"]), do: :help
  defp parse_command(["version"]), do: :version
  defp parse_command(["completion", shell | args]), do: {:completion, shell, args}
  defp parse_command(["login" | _]), do: {:login, []}
  defp parse_command(["logout"]), do: :logout
  defp parse_command(["whoami"]), do: :whoami

  # Secret commands
  defp parse_command(["secret", "list" | args]), do: {:secret, :list, args}
  defp parse_command(["secret", "get", path | args]), do: {:secret, :get, path, args}
  defp parse_command(["secret", "create", path | args]), do: {:secret, :create, path, args}
  defp parse_command(["secret", "update", path | args]), do: {:secret, :update, path, args}
  defp parse_command(["secret", "delete", path | args]), do: {:secret, :delete, path, args}

  defp parse_command(["secret", "versions", path | args]),
    do: {:secret, :versions, path, args}

  defp parse_command(["secret", "rollback", path, version | args]),
    do: {:secret, :rollback, path, version, args}

  # Policy commands
  defp parse_command(["policy", "list" | args]), do: {:policy, :list, args}
  defp parse_command(["policy", "get", name | args]), do: {:policy, :get, name, args}
  defp parse_command(["policy", "create" | args]), do: {:policy, :create, args}
  defp parse_command(["policy", "update", name | args]), do: {:policy, :update, name, args}
  defp parse_command(["policy", "delete", name | args]), do: {:policy, :delete, name, args}
  defp parse_command(["policy", "simulate", name | args]), do: {:policy, :simulate, name, args}
  defp parse_command(["policy", "templates" | args]), do: {:policy, :templates, args}

  # Agent commands
  defp parse_command(["agent", "list" | args]), do: {:agent, :list, args}
  defp parse_command(["agent", "status", id | args]), do: {:agent, :status, id, args}
  defp parse_command(["agent", "logs", id | args]), do: {:agent, :logs, id, args}

  # Config commands
  defp parse_command(["config", "list" | args]), do: {:config, :list, args}
  defp parse_command(["config", "get", key | args]), do: {:config, :get, key, args}
  defp parse_command(["config", "set", key, value | args]), do: {:config, :set, key, value, args}

  defp parse_command(unknown), do: {:unknown, unknown}

  defp execute({:ok, :help, _opts}), do: {:ok, help_text()}
  defp execute({:ok, :version, _opts}), do: {:ok, "SecretHub CLI v#{@version}"}
  defp execute({:ok, {:completion, shell, _args}, _opts}), do: execute_completion(shell)
  defp execute({:ok, {:login, _}, opts}), do: LoginCommand.execute(opts)
  defp execute({:ok, :logout, _opts}), do: Auth.logout()
  defp execute({:ok, :whoami, opts}), do: LoginCommand.whoami(opts)

  # Secret commands
  defp execute({:ok, {:secret, action, path}, opts}),
    do: SecretCommands.execute(action, path, opts)

  defp execute({:ok, {:secret, action, path, args}, opts}),
    do: SecretCommands.execute(action, path, args, opts)

  # Policy commands
  defp execute({:ok, {:policy, action, args}, opts}),
    do: PolicyCommands.execute(action, args, opts)

  defp execute({:ok, {:policy, action, name, args}, opts}),
    do: PolicyCommands.execute(action, name, args, opts)

  # Agent commands
  defp execute({:ok, {:agent, action, args}, opts}),
    do: AgentCommands.execute(action, args, opts)

  defp execute({:ok, {:agent, action, id, args}, opts}),
    do: AgentCommands.execute(action, id, args, opts)

  # Config commands
  defp execute({:ok, {:config, :list, _}, opts}), do: ConfigCommands.list(opts)
  defp execute({:ok, {:config, :get, key, _}, opts}), do: ConfigCommands.get(key, opts)
  defp execute({:ok, {:config, :set, key, value, _}, opts}), do: ConfigCommands.set(key, value, opts)

  defp execute({:ok, {:unknown, args}, _opts}) do
    {:error, "Unknown command: #{Enum.join(args, " ")}\n\nRun 'secrethub help' for usage."}
  end

  defp execute({:error, reason}), do: {:error, reason}

  defp execute_completion("bash"), do: Completion.generate(:bash)
  defp execute_completion("zsh"), do: Completion.generate(:zsh)

  defp execute_completion(shell) do
    {:error, "Unsupported shell: #{shell}\n\nSupported shells: bash, zsh"}
  end

  defp handle_result({:ok, output}) do
    IO.puts(output)
    halt(0)
  end

  defp handle_result({:error, reason}) do
    IO.puts(:stderr, "Error: #{reason}")
    halt(1)
  end

  defp halt(code) do
    if Application.get_env(:secrethub_cli, :test_mode, false) do
      exit({:shutdown, code})
    else
      System.halt(code)
    end
  end

  defp help_text do
    """
    SecretHub CLI v#{@version}

    USAGE:
        secrethub [command] [options]

    COMMANDS:
        Authentication:
          login                    Authenticate with SecretHub
          logout                   Clear credentials
          whoami                   Show authentication status

        Secrets:
          secret list              List all secrets
          secret get <path>        Get a secret value
          secret create <path>     Create a new secret
          secret update <path>     Update a secret
          secret delete <path>     Delete a secret
          secret versions <path>   Show version history
          secret rollback <path>   Rollback to a version

        Policies:
          policy list              List all policies
          policy get <name>        Get policy details
          policy create            Create a policy
          policy update <name>     Update a policy
          policy delete <name>     Delete a policy
          policy simulate <name>   Simulate policy
          policy templates         List templates

        Agents:
          agent list               List connected agents
          agent status <id>        Get agent status
          agent logs <id>          Stream agent logs

        Configuration:
          config list              List configuration
          config get <key>         Get config value
          config set <key> <val>   Set config value

        Completion:
          completion bash          Generate Bash completion script
          completion zsh           Generate Zsh completion script

    GLOBAL OPTIONS:
        -h, --help               Show this help message
        -v, --version            Show version
        -s, --server <url>       Server URL
        -f, --format <format>    Output format (json|table|yaml)
        -q, --quiet              Suppress output
        --verbose                Detailed output

    EXAMPLES:
        secrethub login --role-id <id> --secret-id <secret>
        secrethub secret get prod.db.password
        secrethub policy create --from-template business_hours
        secrethub agent list

    For more information, visit: https://docs.secrethub.example.com
    """
  end
end
