# SecretHub Development Environment Setup with devenv

This guide will help you set up the SecretHub development environment using **devenv** and **direnv**.

---

## 📋 Prerequisites

### 1. Install Nix

**macOS / Linux:**
```bash
sh <(curl -L https://nixos.org/nix/install) --daemon
```

**Verify installation:**
```bash
nix --version
# Should show: nix (Nix) 2.x.x
```

---

### 2. Install devenv

```bash
nix-env -if https://github.com/cachix/devenv/tarball/latest
```

**Verify installation:**
```bash
devenv --version
# Should show: devenv x.x.x
```

---

### 3. Install direnv (Optional but Recommended)

**macOS:**
```bash
brew install direnv
```

**Linux:**
```bash
# Debian/Ubuntu
sudo apt install direnv

# Fedora
sudo dnf install direnv

# Or using Nix
nix-env -iA nixpkgs.direnv
```

**Set up shell hook:**

Add to your shell config file:

**Bash** (`~/.bashrc`):
```bash
eval "$(direnv hook bash)"
```

**Zsh** (`~/.zshrc`):
```bash
eval "$(direnv hook zsh)"
```

**Fish** (`~/.config/fish/config.fish`):
```fish
direnv hook fish | source
```

---

## 🚀 Project Setup

### 1. After Running Initialization Script

After running the initialization script, you should have:
```
secrethub/
├── apps/
├── config/
├── docs/
├── infrastructure/
└── mix.exs
```

---

### 2. Add Devenv Configuration Files

Copy the following files to your project root:

**a. devenv.nix**
```bash
# Copy from artifacts
# This file defines your development environment
```

**b. .envrc**
```bash
# Copy from artifacts
# This file enables automatic environment activation with direnv
```

**c. devenv.yaml**
```bash
# Copy from artifacts
# This file configures devenv settings
```

**d. .gitignore**
```bash
# Copy from artifacts
# This includes devenv-specific ignores
```

---

### 3. Set Up Prometheus Configuration

```bash
# Create the Prometheus config
# Copy prometheus.yml to infrastructure/prometheus/prometheus.yml
```

---

### 4. Activate the Environment

**If using direnv (recommended):**
```bash
cd secrethub
direnv allow
# Environment will activate automatically
```

**If not using direnv:**
```bash
cd secrethub
devenv shell
# You're now in the devenv shell
```

---

### 5. Initialize the Database

```bash
# Set up database (create, migrate, seed)
db-setup

# Verify it worked
psql -U secrethub -d secrethub_dev -c "SELECT 1"
```

---

### 6. Install Elixir Dependencies

```bash
mix deps.get
```

---

### 7. Install Frontend Assets (when Web UI is ready)

```bash
assets-install
```

---

### 8. Verify Everything Works

```bash
# Compile the project
mix compile

# Run tests
mix test

# Start the server (when ready)
# server
```

---

## 🛠️ Daily Usage

### Starting Your Work Session

**With direnv:**
```bash
cd secrethub
# Environment activates automatically!
```

**Without direnv:**
```bash
cd secrethub
devenv shell
```

---

### Common Commands

```bash
# Database
db-setup        # Initial setup: create + migrate + seed
db-reset        # Reset database (drop, create, migrate, seed)
db-migrate      # Run pending migrations

# Assets (Frontend)
assets-install  # Install frontend dependencies with Bun
assets-build    # Build frontend assets

# Development
server          # Start Phoenix server (when web is ready)
console         # Interactive Elixir shell (iex -S mix)

# Testing
test-all        # Run all tests
test-watch      # Run tests in watch mode

# Code Quality
format          # Format all code (mix format)
lint            # Run Credo linter
quality         # Run all quality checks

# Utilities
gen-secret      # Generate Phoenix secret key
```

---

### Accessing Services

When devenv shell is active:

- **PostgreSQL:** `localhost:5432`
  - Database: `secrethub_dev`
  - User: `secrethub`
  - Password: `secrethub_dev_password`
  
- **Redis:** `localhost:6379`

- **Prometheus:** `http://localhost:9090`

---

## 🐛 Troubleshooting

### Issue: "devenv: command not found"

**Solution:**
```bash
# Add to PATH (if using non-standard installation)
export PATH="$HOME/.nix-profile/bin:$PATH"

# Or reinstall devenv
nix-env -if https://github.com/cachix/devenv/tarball/latest
```

---

### Issue: "direnv: error .envrc is blocked"

**Solution:**
```bash
direnv allow
```

---

### Issue: PostgreSQL won't start

**Solution:**
```bash
# Check if port 5432 is already in use
lsof -i :5432

# If another PostgreSQL is running, stop it first
# macOS (if installed via Homebrew)
brew services stop postgresql

# Or change the port in devenv.nix
```

---

### Issue: "Database secrethub_dev already exists"

**Solution:**
```bash
# This is fine! The database persists between sessions
# To reset:
db-reset
```

---

### Issue: Mix dependencies fail to compile

**Solution:**
```bash
# Clean and reinstall
rm -rf deps _build
mix deps.get
mix deps.compile
```

---

### Issue: devenv services not starting

**Solution:**
```bash
# Exit and re-enter the shell
exit
devenv shell

# Or restart devenv processes
devenv processes restart
```

---

## 🔧 Customizing Your Environment

### Adding New Packages

Edit `devenv.nix`:
```nix
packages = with pkgs; [
  git
  postgresql_16
  # Add your package here
  ripgrep  # Example: add ripgrep
];
```

Then reload:
```bash
# With direnv
direnv reload

# Without direnv
exit
devenv shell
```

---

### Adding Environment Variables

Edit `devenv.nix`:
```nix
env = {
  DATABASE_URL = "postgresql://...";
  # Add your variable here
  MY_CUSTOM_VAR = "value";
};
```

---

### Adding Custom Scripts

Edit `devenv.nix`:
```nix
scripts = {
  my-script.exec = ''
    echo "Hello from my script!"
  '';
};
```

Then use:
```bash
my-script
```

---

## 📚 Learn More

- **devenv documentation:** https://devenv.sh
- **direnv documentation:** https://direnv.net
- **Nix documentation:** https://nixos.org/manual/nix/stable/

---

## ✅ Checklist

After setup, you should have:

- [ ] Nix installed
- [ ] devenv installed
- [ ] direnv installed and configured (optional)
- [ ] devenv.nix in project root
- [ ] .envrc in project root
- [ ] devenv.yaml in project root
- [ ] Prometheus config in infrastructure/prometheus/
- [ ] Can run `devenv shell` successfully
- [ ] Database created (`db-setup` runs successfully)
- [ ] Can run `mix test` successfully
- [ ] All services accessible (PostgreSQL, Redis)

---

**You're all set! Welcome to SecretHub development! 🎉**
