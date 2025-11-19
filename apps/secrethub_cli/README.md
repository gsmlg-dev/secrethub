# SecretHub CLI

Command-line interface for SecretHub secrets management platform.

## Installation

### From Release Binary

```bash
# Download the latest release
curl -LO https://github.com/secrethub/secrethub/releases/latest/download/secrethub

# Make it executable
chmod +x secrethub

# Move to PATH
sudo mv secrethub /usr/local/bin/
```

### From Source

```bash
# Clone the repository
git clone https://github.com/secrethub/secrethub.git
cd secrethub

# Build the CLI
mix deps.get
mix escript.build

# Install to PATH
sudo cp secrethub /usr/local/bin/
```

## Quick Start

### Authentication

```bash
# Login with AppRole credentials
secrethub login --role-id <your-role-id> --secret-id <your-secret-id>

# Check authentication status
secrethub whoami
```

### Managing Secrets

```bash
# List all secrets
secrethub secret list

# Get a secret value
secrethub secret get prod.db.password

# Create a new secret
secrethub secret create dev.api.key --value "sk-1234567890"

# Update an existing secret
secrethub secret update prod.db.password --value "new-password"

# Delete a secret
secrethub secret delete dev.api.key

# View secret version history
secrethub secret versions prod.db.password

# Rollback to a previous version
secrethub secret rollback prod.db.password 2
```

### Managing Policies

```bash
# List all policies
secrethub policy list

# Get policy details
secrethub policy get developers

# Create a policy from template
secrethub policy create --from-template read_only --name "Developers"

# Delete a policy
secrethub policy delete old-policy

# List available policy templates
secrethub policy templates
```

### Managing Agents

```bash
# List connected agents
secrethub agent list

# Get agent status
secrethub agent status agent-123

# Stream agent logs
secrethub agent logs agent-123
```

### Configuration

```bash
# List all configuration
secrethub config list

# Get a configuration value
secrethub config get server_url

# Set a configuration value
secrethub config set server_url https://secrethub.example.com
```

## Shell Completion

SecretHub CLI provides powerful shell completion for both Bash and Zsh, including:

- Command and subcommand completion
- Option completion with descriptions (Zsh)
- Dynamic completion for secret paths, policy names, and agent IDs
- Context-aware suggestions
- Format option completion (json, table, yaml)

### Bash Completion

#### Installation

**Option 1: System-wide (requires sudo)**

```bash
sudo secrethub completion bash > /etc/bash_completion.d/secrethub
source ~/.bashrc
```

**Option 2: User-local**

```bash
mkdir -p ~/.bash_completion.d
secrethub completion bash > ~/.bash_completion.d/secrethub

# Add to ~/.bashrc:
echo 'if [ -f ~/.bash_completion.d/secrethub ]; then
    . ~/.bash_completion.d/secrethub
fi' >> ~/.bashrc

source ~/.bashrc
```

**Option 3: macOS with Homebrew**

```bash
# Install bash-completion if not already installed
brew install bash-completion

# Install secrethub completion
secrethub completion bash > $(brew --prefix)/etc/bash_completion.d/secrethub
source ~/.bash_profile
```

#### Testing

After installation, test by typing:

```bash
secrethub sec<TAB>
# Should complete to: secrethub secret

secrethub secret <TAB>
# Should show: list get create update delete versions rollback

secrethub --format <TAB>
# Should show: json table yaml
```

#### Troubleshooting

If completion doesn't work:

1. **Ensure bash-completion is installed:**
   - Debian/Ubuntu: `sudo apt install bash-completion`
   - RHEL/CentOS: `sudo yum install bash-completion`
   - macOS: `brew install bash-completion`

2. **Restart your shell** or source your rc file

3. **Check that secrethub is in your PATH:**
   ```bash
   which secrethub
   ```

### Zsh Completion

#### Installation

**Option 1: User-local (recommended)**

```bash
# Create completion directory
mkdir -p ~/.zsh/completion

# Generate completion file
secrethub completion zsh > ~/.zsh/completion/_secrethub

# Add to ~/.zshrc (BEFORE compinit):
echo 'fpath=(~/.zsh/completion $fpath)
autoload -Uz compinit
compinit' >> ~/.zshrc

# Reload configuration
source ~/.zshrc
```

**Option 2: System-wide (requires sudo)**

```bash
sudo secrethub completion zsh > /usr/local/share/zsh/site-functions/_secrethub

# Restart your shell
exec zsh
```

**Option 3: oh-my-zsh**

```bash
# Create plugin directory
mkdir -p ~/.oh-my-zsh/custom/plugins/secrethub

# Generate completion file
secrethub completion zsh > ~/.oh-my-zsh/custom/plugins/secrethub/_secrethub

# Add to plugins in ~/.zshrc:
# plugins=(... secrethub)

source ~/.zshrc
```

#### Testing

After installation, test by typing:

```bash
secrethub sec<TAB>
# Should show: secret -- Manage secrets

secrethub secret <TAB>
# Should show all subcommands with descriptions

secrethub --format <TAB>
# Should show: json table yaml
```

#### Troubleshooting

If completion doesn't work:

1. **Check that fpath includes your completion directory:**
   ```zsh
   echo $fpath
   ```

2. **Clear completion cache:**
   ```zsh
   rm -f ~/.zcompdump*
   compinit
   ```

3. **Ensure compinit is called AFTER adding to fpath** in your ~/.zshrc

4. **Check that secrethub is in your PATH:**
   ```zsh
   which secrethub
   ```

## Global Options

All commands support these global options:

- `-h, --help` - Show help message
- `-v, --version` - Show version information
- `-s, --server <url>` - SecretHub server URL (default: http://localhost:4000)
- `-f, --format <format>` - Output format: json, table, or yaml (default: table)
- `-q, --quiet` - Suppress non-error output
- `--verbose` - Show detailed output

## Output Formats

### Table (default)

Human-readable table format:

```bash
secrethub secret list
```

```
PATH                          VERSION  UPDATED
prod.db.password              3        2024-01-15 10:30:45
dev.api.key                   1        2024-01-14 09:15:20
```

### JSON

Machine-readable JSON format:

```bash
secrethub secret list --format json
```

```json
[
  {
    "path": "prod.db.password",
    "version": 3,
    "updated_at": "2024-01-15T10:30:45Z"
  },
  {
    "path": "dev.api.key",
    "version": 1,
    "updated_at": "2024-01-14T09:15:20Z"
  }
]
```

### YAML

YAML format for configuration files:

```bash
secrethub secret list --format yaml
```

```yaml
- path: prod.db.password
  version: 3
  updated_at: '2024-01-15T10:30:45Z'
- path: dev.api.key
  version: 1
  updated_at: '2024-01-14T09:15:20Z'
```

## Configuration File

The CLI stores configuration in `~/.secrethub/config.toml`:

```toml
server_url = "https://secrethub.example.com"
default_format = "table"

[auth]
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
expires_at = "2024-12-31T23:59:59Z"
```

You can edit this file directly or use the `config` commands.

## Environment Variables

- `SECRETHUB_SERVER` - Override server URL
- `SECRETHUB_TOKEN` - Provide authentication token
- `SECRETHUB_FORMAT` - Set default output format

Example:

```bash
export SECRETHUB_SERVER=https://secrethub.example.com
export SECRETHUB_FORMAT=json
secrethub secret list
```

## Examples

### Complete Workflow

```bash
# Login
secrethub login --role-id abc123 --secret-id xyz789

# Create a secret
secrethub secret create prod.db.password --value "secure-password-123"

# Get the secret
secrethub secret get prod.db.password

# Update the secret
secrethub secret update prod.db.password --value "new-password-456"

# View version history
secrethub secret versions prod.db.password

# Rollback to previous version
secrethub secret rollback prod.db.password 1

# Create a policy
secrethub policy create --from-template read_only --name "Developers"

# List agents
secrethub agent list

# Logout
secrethub logout
```

### Using with Scripts

```bash
#!/bin/bash

# Get database password for automation
DB_PASSWORD=$(secrethub secret get prod.db.password --format json | jq -r '.value')

# Use in connection string
psql "postgresql://user:${DB_PASSWORD}@localhost/mydb"
```

### Pipeline Integration

```bash
# In CI/CD pipeline
export SECRETHUB_TOKEN="${CI_SECRETHUB_TOKEN}"
API_KEY=$(secrethub secret get prod.api.key --quiet --format json | jq -r '.value')
echo "::set-output name=api_key::${API_KEY}"
```

## Development

### Building from Source

```bash
# Get dependencies
mix deps.get

# Build escript
mix escript.build

# Test the CLI
./secrethub --help
```

### Running Tests

```bash
mix test
```

### Generating Completions

During development, you can generate completion scripts using the Mix task:

```bash
# Generate both Bash and Zsh completions
mix cli.gen.completion all

# Generate only Bash completion
mix cli.gen.completion bash

# Generate only Zsh completion
mix cli.gen.completion zsh
```

Completion scripts are generated in `apps/secrethub_cli/priv/completion/`.

## Support

- Documentation: https://docs.secrethub.example.com
- Issues: https://github.com/secrethub/secrethub/issues
- Community: https://community.secrethub.example.com

## License

Copyright © 2024 SecretHub. All rights reserved.
