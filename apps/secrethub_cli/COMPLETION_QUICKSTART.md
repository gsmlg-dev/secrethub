# Shell Completion Quick Start

One-page guide to installing and using SecretHub CLI shell completion.

## 30-Second Install

### Bash

```bash
secrethub completion bash | sudo tee /etc/bash_completion.d/secrethub > /dev/null
source ~/.bashrc
```

### Zsh

```bash
mkdir -p ~/.zsh/completion && \
secrethub completion zsh > ~/.zsh/completion/_secrethub && \
echo 'fpath=(~/.zsh/completion $fpath)' >> ~/.zshrc && \
source ~/.zshrc
```

## Quick Test

```bash
# Should complete to "secret"
secrethub sec<TAB>

# Should show subcommands
secrethub secret <TAB>

# Should show formats
secrethub --format <TAB>
```

## What You Get

✅ Complete all commands and subcommands
✅ Complete all options and flags
✅ Complete format values (json/table/yaml)
✅ Complete secret paths from server (when logged in)
✅ Complete policy names from server (when logged in)
✅ Complete agent IDs from server (when logged in)
✅ Complete policy templates
✅ Context-aware suggestions

## No Sudo? Use Local Install

### Bash (local)

```bash
mkdir -p ~/.bash_completion.d
secrethub completion bash > ~/.bash_completion.d/secrethub
echo 'source ~/.bash_completion.d/secrethub' >> ~/.bashrc
source ~/.bashrc
```

### Zsh (local - same as above)

```bash
mkdir -p ~/.zsh/completion
secrethub completion zsh > ~/.zsh/completion/_secrethub
echo 'fpath=(~/.zsh/completion $fpath)' >> ~/.zshrc
source ~/.zshrc
```

## Troubleshooting

### Bash not working?

```bash
# Install bash-completion
sudo apt install bash-completion  # Debian/Ubuntu
sudo yum install bash-completion  # RHEL/CentOS
brew install bash-completion@2    # macOS

# Reload
source ~/.bashrc
```

### Zsh not working?

```bash
# Clear cache
rm -f ~/.zcompdump*
compinit

# Verify fpath order in ~/.zshrc (fpath BEFORE compinit)
```

## Examples

```bash
# Complete command
secrethub <TAB>
→ login logout whoami secret policy agent config completion

# Complete subcommand
secrethub secret <TAB>
→ list get create update delete versions rollback

# Complete format
secrethub --format <TAB>
→ json table yaml

# Complete secret path (after login)
secrethub secret get <TAB>
→ prod.db.password dev.api.key staging.redis.url

# Complete policy template
secrethub policy create --from-template <TAB>
→ admin read_only business_hours time_limited emergency_access

# Complete config key
secrethub config get <TAB>
→ server_url default_format log_level
```

## More Info

- Full guide: `COMPLETION.md`
- CLI docs: `README.md`
- Summary: `COMPLETION_SUMMARY.md`

## Update Completion

When you update SecretHub CLI:

```bash
# Reinstall completion
secrethub completion bash > ~/.bash_completion.d/secrethub  # Bash
secrethub completion zsh > ~/.zsh/completion/_secrethub     # Zsh

# Reload
source ~/.bashrc  # Bash
source ~/.zshrc   # Zsh
```
