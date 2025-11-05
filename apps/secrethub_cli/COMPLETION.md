# Shell Completion Installation Guide

This guide provides detailed instructions for installing shell completion for the SecretHub CLI.

## Overview

SecretHub CLI provides intelligent shell completion for both Bash and Zsh, featuring:

- **Command completion**: Main commands and subcommands
- **Option completion**: All flags with descriptions (Zsh)
- **Dynamic completion**: Secret paths, policy names, and agent IDs from the server
- **Context-aware**: Knows which subcommand you're working with
- **Format values**: json, table, yaml
- **Policy templates**: Pre-configured policy template names

## Quick Start

### Bash

```bash
# Generate and install completion
secrethub completion bash | sudo tee /etc/bash_completion.d/secrethub
source ~/.bashrc
```

### Zsh

```bash
# Generate and install completion
mkdir -p ~/.zsh/completion
secrethub completion zsh > ~/.zsh/completion/_secrethub

# Add to ~/.zshrc (before compinit)
echo 'fpath=(~/.zsh/completion $fpath)' >> ~/.zshrc

# Reload
source ~/.zshrc
```

## Bash Completion

### Prerequisites

Bash completion must be installed on your system:

**Debian/Ubuntu:**
```bash
sudo apt install bash-completion
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum install bash-completion
# or
sudo dnf install bash-completion
```

**macOS:**
```bash
brew install bash-completion@2
```

### Installation Options

#### Option 1: System-wide Installation (Recommended for multi-user systems)

```bash
# Install completion script
sudo secrethub completion bash > /etc/bash_completion.d/secrethub

# Reload bash
source ~/.bashrc
```

**Pros:**
- Available to all users
- Automatically loaded by bash-completion

**Cons:**
- Requires sudo/root access

#### Option 2: User-local Installation

```bash
# Create completion directory
mkdir -p ~/.bash_completion.d

# Generate completion script
secrethub completion bash > ~/.bash_completion.d/secrethub

# Add to ~/.bashrc
cat >> ~/.bashrc << 'EOF'
# Load SecretHub completion
if [ -f ~/.bash_completion.d/secrethub ]; then
    . ~/.bash_completion.d/secrethub
fi
EOF

# Reload bash
source ~/.bashrc
```

**Pros:**
- No sudo required
- User-specific customization

**Cons:**
- Need to configure manually in .bashrc

#### Option 3: macOS with Homebrew

```bash
# Ensure bash-completion is installed
brew install bash-completion@2

# Install secrethub completion
secrethub completion bash > $(brew --prefix)/etc/bash_completion.d/secrethub

# Reload
source ~/.bash_profile
```

### Verification

Test that completion is working:

```bash
# Should complete to "secret"
secrethub sec<TAB>

# Should list: list get create update delete versions rollback
secrethub secret <TAB>

# Should complete to available format options
secrethub --format <TAB>
```

### Troubleshooting

**Completion not working:**

1. **Check bash-completion is loaded:**
   ```bash
   type _init_completion
   # Should output: _init_completion is a function
   ```

2. **Manually source the completion:**
   ```bash
   source /etc/bash_completion.d/secrethub
   # or
   source ~/.bash_completion.d/secrethub
   ```

3. **Check secrethub is in PATH:**
   ```bash
   which secrethub
   ```

4. **Enable bash-completion in .bashrc:**
   ```bash
   # Add to ~/.bashrc
   if [ -f /etc/bash_completion ]; then
       . /etc/bash_completion
   fi
   ```

**Dynamic completion not working:**

Dynamic completion (secret paths, policies, agents) requires:
- Active authentication (`secrethub login`)
- Network access to SecretHub server
- Config file at `~/.secrethub/config.toml`

Static completion (commands, options) will still work without authentication.

## Zsh Completion

### Prerequisites

Zsh completion system should be enabled (usually enabled by default).

### Installation Options

#### Option 1: User-local Installation (Recommended)

```bash
# Create completion directory
mkdir -p ~/.zsh/completion

# Generate completion file
secrethub completion zsh > ~/.zsh/completion/_secrethub

# Add to ~/.zshrc (BEFORE compinit)
cat >> ~/.zshrc << 'EOF'
# Add completion directory to fpath
fpath=(~/.zsh/completion $fpath)

# Initialize completion
autoload -Uz compinit
compinit
EOF

# Reload zsh
source ~/.zshrc
```

**Pros:**
- No sudo required
- Easy to update
- User-specific customization

**Cons:**
- Need to modify .zshrc

#### Option 2: System-wide Installation

```bash
# Install completion (requires sudo)
sudo secrethub completion zsh > /usr/local/share/zsh/site-functions/_secrethub

# Reload zsh
exec zsh
```

**Pros:**
- Available to all users
- Automatically found by zsh

**Cons:**
- Requires sudo/root access

#### Option 3: oh-my-zsh

```bash
# Create custom plugin directory
mkdir -p ~/.oh-my-zsh/custom/plugins/secrethub

# Generate completion
secrethub completion zsh > ~/.oh-my-zsh/custom/plugins/secrethub/_secrethub

# Edit ~/.zshrc and add 'secrethub' to plugins
# Before: plugins=(git docker ...)
# After:  plugins=(git docker ... secrethub)

# Reload zsh
source ~/.zshrc
```

**Pros:**
- Integrates with oh-my-zsh plugin system
- Easy to enable/disable

**Cons:**
- Requires oh-my-zsh

### Verification

Test that completion is working:

```bash
# Should show: secret -- Manage secrets
secrethub sec<TAB>

# Should list all subcommands with descriptions
secrethub secret <TAB>

# Should show format options
secrethub --format <TAB>
```

### Troubleshooting

**Completion not working:**

1. **Check completion is loaded:**
   ```zsh
   which _secrethub
   # Should output: _secrethub is a shell function
   ```

2. **Verify fpath includes completion directory:**
   ```zsh
   echo $fpath
   # Should include ~/.zsh/completion or /usr/local/share/zsh/site-functions
   ```

3. **Clear completion cache:**
   ```zsh
   rm -f ~/.zcompdump*
   compinit
   ```

4. **Check load order in .zshrc:**
   - `fpath` modification must come BEFORE `compinit`
   - Example:
     ```zsh
     # Correct order:
     fpath=(~/.zsh/completion $fpath)  # First
     autoload -Uz compinit              # Then
     compinit                           # Finally
     ```

5. **Debug completion:**
   ```zsh
   # Enable completion debugging
   zstyle ':completion:*' verbose yes
   zstyle ':completion:*' format 'Completing %d'
   ```

**Dynamic completion not working:**

Same requirements as Bash:
- Active authentication
- Network access to server
- Config file exists

## Advanced Usage

### Completion Features

**1. Command Completion**
```bash
secrethub <TAB>
# Shows: login logout whoami secret policy agent config completion help version
```

**2. Subcommand Completion**
```bash
secrethub secret <TAB>
# Shows: list get create update delete versions rollback
```

**3. Option Completion**
```bash
secrethub secret list --<TAB>
# Shows: --format --quiet --verbose --help --server
```

**4. Format Completion**
```bash
secrethub --format <TAB>
# Shows: json table yaml
```

**5. Dynamic Secret Paths** (requires authentication)
```bash
secrethub secret get <TAB>
# Shows: prod.db.password dev.api.key staging.redis.password ...
```

**6. Dynamic Policy Names** (requires authentication)
```bash
secrethub policy get <TAB>
# Shows: developers admins read-only business-hours ...
```

**7. Policy Templates**
```bash
secrethub policy create --from-template <TAB>
# Shows: admin read_only business_hours time_limited emergency_access
```

**8. Config Keys**
```bash
secrethub config get <TAB>
# Shows: server_url default_format log_level
```

**9. Config Values**
```bash
secrethub config set default_format <TAB>
# Shows: json table yaml
```

### Performance Considerations

Dynamic completion queries the SecretHub API for current data. To optimize:

1. **Caching**: Completion scripts don't implement caching to ensure fresh data
2. **Timeout**: API calls use shell's default timeout
3. **Fallback**: If API is unreachable, completion falls back to options only

If you need faster completion, consider:
- Using local server
- Adjusting shell timeout settings
- Using static completion (commands/options) only

### Customization

You can customize completion behavior by editing the generated scripts:

**Bash**: `~/.bash_completion.d/secrethub` or `/etc/bash_completion.d/secrethub`

**Zsh**: `~/.zsh/completion/_secrethub` or `/usr/local/share/zsh/site-functions/_secrethub`

Example customizations:
- Modify `_secrethub_get_policy_templates` to add custom templates
- Adjust timeout in dynamic completion functions
- Add custom completion for specific use cases

### Updating Completion

When SecretHub CLI is updated with new commands or options:

```bash
# Regenerate completion
secrethub completion bash > ~/.bash_completion.d/secrethub
# or
secrethub completion zsh > ~/.zsh/completion/_secrethub

# Reload shell
source ~/.bashrc  # Bash
source ~/.zshrc   # Zsh
```

## Examples

### Example Session (Bash)

```bash
$ secrethub log<TAB>
login  logout

$ secrethub login --<TAB>
--help      --role-id    --server   --verbose
--quiet     --secret-id  --version

$ secrethub secret <TAB>
create   delete   get      list     rollback update   versions

$ secrethub secret get prod.db.<TAB>
prod.db.password  prod.db.username  prod.db.host

$ secrethub --format <TAB>
json   table   yaml
```

### Example Session (Zsh)

```bash
$ secrethub <TAB>
login      -- Authenticate with SecretHub server
logout     -- Clear authentication credentials
whoami     -- Show current authentication status
secret     -- Manage secrets
policy     -- Manage access policies
agent      -- Manage SecretHub agents
config     -- Manage CLI configuration
completion -- Generate shell completion scripts
help       -- Show help message
version    -- Show version information

$ secrethub policy create --from-template <TAB>
admin            -- Full administrative access
read_only        -- Read-only access to secrets
business_hours   -- Access restricted to business hours
time_limited     -- Time-limited access policy
emergency_access -- Emergency break-glass access
```

## Support

If you encounter issues with completion:

1. Check this troubleshooting guide
2. Verify SecretHub CLI version: `secrethub --version`
3. Check shell version: `bash --version` or `zsh --version`
4. Report issues: https://github.com/secrethub/secrethub/issues

## Resources

- [Bash Completion Documentation](https://github.com/scop/bash-completion)
- [Zsh Completion System](http://zsh.sourceforge.net/Doc/Release/Completion-System.html)
- [SecretHub CLI Documentation](../README.md)
