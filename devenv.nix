{ pkgs, lib, config, inputs, ... }:

let
  pkgs-stable = import inputs.nixpkgs-stable { system = pkgs.stdenv.system; };
in
{
  # Project metadata
  name = "secrethub";

  # Development tools
  packages = with pkgs-stable; [
    git

    # Database tools
    postgresql_16

    # Additional tools
    openssl

    # For testing AWS integrations locally
    awscli2

    # Monitoring tools
    prometheus
    grafana

    # Frontend build tools (NixOS-compatible binaries)
    tailwindcss_4
  ] ++ lib.optionals pkgs.stdenv.isLinux [
    inotify-tools
  ];

  # Language configuration
  languages.elixir.enable = true;

  # JavaScript / Bun
  languages.javascript.enable = true;
  languages.javascript.bun.enable = true;
  languages.javascript.bun.package = pkgs-stable.bun;

  # Development services
  services = {
    # PostgreSQL - Main database
    postgres = {
      enable = true;
      package = pkgs-stable.postgresql_16;
      initialDatabases = [
        { name = "secrethub_dev"; }
        { name = "secrethub_test"; }
      ];
      initialScript = ''
        CREATE USER secrethub WITH PASSWORD 'secrethub_dev_password' SUPERUSER;
        GRANT ALL PRIVILEGES ON DATABASE secrethub_dev TO secrethub;
        GRANT ALL PRIVILEGES ON DATABASE secrethub_test TO secrethub;

        -- Connect to secrethub_dev and set up extensions
        \c secrethub_dev
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
        CREATE EXTENSION IF NOT EXISTS "pgcrypto";
        CREATE SCHEMA IF NOT EXISTS audit;

        -- Connect to secrethub_test and set up extensions
        \c secrethub_test
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
        CREATE EXTENSION IF NOT EXISTS "pgcrypto";
        CREATE SCHEMA IF NOT EXISTS audit;
      '';
      # Use Unix domain socket only (more secure and faster than TCP)
      listen_addresses = "";
      settings = {
        max_connections = 100;
        shared_buffers = "128MB";
        log_statement = "all";
        log_duration = true;
        # Unix socket permissions
        unix_socket_permissions = "0777";
        # Socket in project directory to avoid conflicts
        unix_socket_directories = "${config.devenv.root}/.devenv/state/postgres";
      };
    };

    # Test PostgreSQL - For testing dynamic secret engines
    # Note: devenv doesn't support multiple postgres instances directly
    # We'll document manual setup or use Docker for this specific case
  };

  # Process management
  processes = {
    # Phoenix server (will add when ready)
    # phoenix = {
    #   exec = "mix phx.server";
    #   process-compose = {
    #     depends_on = {
    #       postgres = {
    #         condition = "process_healthy";
    #       };
    #     };
    #   };
    # };

    # Prometheus (for metrics)
    prometheus = {
      exec = "prometheus --config.file=$DEVENV_ROOT/infrastructure/prometheus/prometheus.yml --storage.tsdb.path=$DEVENV_STATE/prometheus";
      process-compose = {
        availability = {
          restart = "on_failure";
          max_restarts = 3;
        };
      };
    };
  };

  # Environment variables
  env = {
    # PostgreSQL environment variables for Unix socket connection
    # Note: PGUSER/PGPASSWORD are NOT set here because they interfere with
    # devenv's postgres service (readiness probe and initialScript both need
    # to connect as the OS user during setup). Credentials are in DATABASE_URL.
    PGHOST = "${config.devenv.root}/.devenv/state/postgres";
    PGDATABASE = "secrethub_dev";

    # Database URLs (using Unix domain socket for security and performance)
    DATABASE_URL = "postgresql://secrethub:secrethub_dev_password@/secrethub_dev?host=${config.devenv.root}/.devenv/state/postgres";
    DATABASE_TEST_URL = "postgresql://secrethub:secrethub_dev_password@/secrethub_test?host=${config.devenv.root}/.devenv/state/postgres";

    # Asset tooling — tells Mix hex packages to use Nix-managed binaries
    MIX_BUN_PATH = lib.getExe pkgs-stable.bun;
    MIX_TAILWIND_PATH = lib.getExe pkgs-stable.tailwindcss_4;

    # Application
    MIX_ENV = "dev";
    SECRET_KEY_BASE = lib.mkDefault "dev-secret-key-base-change-in-production";

    # Phoenix
    PHX_HOST = "localhost";
    PHX_PORT = "4664";

    # Development flags
    ELIXIR_ERL_OPTIONS = "+sbwt none +sbwtdcpu none +sbwtdio none";
  };

  # Scripts for common tasks
  scripts = {
    # Clean up stale postgres lock files (useful after unclean shutdown)
    db-clean.exec = ''
      rm -f "$DEVENV_STATE/postgres/postmaster.pid" 2>/dev/null || true
      echo "✅ Cleaned stale postgres lock files"
    '';

    # Database initialization (run after devenv up to ensure user/databases exist)
    db-init.exec = ''
      # The socket is in PGHOST (set by devenv env block to .devenv/state/postgres)
      SOCKET_DIR="$PGHOST"

      # Check if postgres is accepting connections
      if ! pg_isready -h "$SOCKET_DIR" -q 2>/dev/null; then
        echo "❌ PostgreSQL is not running. Start it with: devenv up"
        exit 1
      fi

      # Check if secrethub user exists (connect as OS user who is the initdb superuser)
      if ! psql -h "$SOCKET_DIR" -U "$USER" -d postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='secrethub'" | grep -q 1; then
        echo "📦 Creating secrethub user..."
        psql -h "$SOCKET_DIR" -U "$USER" -d postgres -c "CREATE USER secrethub WITH PASSWORD 'secrethub_dev_password' SUPERUSER;"
      fi

      # Create databases if they don't exist
      if ! psql -h "$SOCKET_DIR" -U "$USER" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='secrethub_dev'" | grep -q 1; then
        echo "📦 Creating secrethub_dev database..."
        psql -h "$SOCKET_DIR" -U "$USER" -d postgres -c "CREATE DATABASE secrethub_dev OWNER secrethub;"
        psql -h "$SOCKET_DIR" -U "$USER" -d secrethub_dev -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"; CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"; CREATE SCHEMA IF NOT EXISTS audit; GRANT ALL ON SCHEMA audit TO secrethub;"
      fi

      if ! psql -h "$SOCKET_DIR" -U "$USER" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='secrethub_test'" | grep -q 1; then
        echo "📦 Creating secrethub_test database..."
        psql -h "$SOCKET_DIR" -U "$USER" -d postgres -c "CREATE DATABASE secrethub_test OWNER secrethub;"
        psql -h "$SOCKET_DIR" -U "$USER" -d secrethub_test -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"; CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"; CREATE SCHEMA IF NOT EXISTS audit; GRANT ALL ON SCHEMA audit TO secrethub;"
      fi

      echo "✅ Database initialized successfully!"
    '';

    # Database management
    db-setup.exec = ''
      db-init
      cd apps/secrethub_core
      mix ecto.create 2>/dev/null || true
      mix ecto.migrate
      mix run priv/repo/seeds.exs
    '';
    
    db-reset.exec = ''
      cd apps/secrethub_core
      mix ecto.drop
      mix ecto.create
      mix ecto.migrate
      mix run priv/repo/seeds.exs
    '';
    
    db-migrate.exec = ''
      cd apps/secrethub_core
      mix ecto.migrate
    '';
    
    # Asset management (using Bun workspaces)
    assets-install.exec = ''
      bun install
    '';

    assets-build.exec = ''
      mix bun secrethub_web
    '';
    
    # Development server
    server.exec = ''
      mix phx.server
    '';
    
    # Testing (MIX_ENV must be overridden since devenv sets it to "dev")
    test-all.exec = ''
      MIX_ENV=test mix test "$@"
    '';

    test-watch.exec = ''
      MIX_ENV=test mix test.watch "$@"
    '';
    
    # Code quality
    format.exec = ''
      mix format
    '';
    
    lint.exec = ''
      mix credo --strict
    '';
    
    quality.exec = ''
      mix format --check-formatted
      mix credo --strict
      mix dialyzer
    '';
    
    # Generate secrets
    gen-secret.exec = ''
      mix phx.gen.secret
    '';
    
    # Interactive shell
    console.exec = ''
      iex -S mix
    '';
  };

  # Enter shell hooks
  enterShell = ''
    # Welcome message
    cat << 'EOF'
    
    🔐 Welcome to SecretHub Development Environment
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    📦 Tools available:
       • Elixir 1.18
       • Erlang/OTP 28
       • PostgreSQL 16
       • Bun (JavaScript runtime)

    🚀 Quick commands:
       • db-setup         → Create and migrate database
       • db-reset         → Reset database
       • assets-install   → Install frontend dependencies (Bun)
       • assets-build     → Build frontend assets
       • server           → Start Phoenix server
       • test-all         → Run all tests
       • console          → Start IEx shell
       • quality          → Run all quality checks
    
    📝 Services running:
       • PostgreSQL:  Unix socket ($DEVENV_STATE/postgres)
       • Prometheus:  localhost:9090

    EOF

    # Initialize database (creates user/databases if needed)
    db-init 2>/dev/null || true

    # Check if dependencies are installed
    if [ ! -d "deps" ]; then
      echo "📦 Installing Elixir dependencies..."
      mix deps.get
      echo ""
    fi
    
    # Check if assets dependencies are installed
    if [ ! -d "apps/secrethub_web/node_modules" ]; then
      echo "📦 Frontend dependencies not installed. Run: assets-install"
      echo ""
    fi
    
    # Set up git hooks if not already set up
    if [ ! -f ".git/hooks/pre-commit" ]; then
      echo "🔧 Setting up git hooks..."
      echo ""
    fi
  '';

}
