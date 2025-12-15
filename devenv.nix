{ pkgs, lib, config, inputs, ... }:

let
  pkgs-stable = import inputs.nixpkgs-stable { system = pkgs.stdenv.system; };
in
{
  # Project metadata
  name = "secrethub";

  # Development tools
  packages = with pkgs; [
    # Elixir & Erlang (managed by languages.elixir)
    git
    
    # JavaScript runtime for Phoenix assets
    bun
    
    # Database tools
    postgresql_16
    
    # Additional tools
    openssl
    
    # For testing AWS integrations locally
    awscli2
    
    # Monitoring tools
    prometheus
    grafana
  ];

  # Language configuration
  languages = {
    elixir = {
      enable = true;
    };
  };

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
    # Database (using Unix domain socket for security and performance)
    # Socket is located at $DEVENV_STATE/postgres
    DATABASE_URL = "postgresql://secrethub:secrethub_dev_password@/secrethub_dev?host=$DEVENV_STATE/postgres";
    DATABASE_TEST_URL = "postgresql://secrethub:secrethub_dev_password@/secrethub_test?host=$DEVENV_STATE/postgres";

    # Application
    MIX_ENV = "dev";
    SECRET_KEY_BASE = lib.mkDefault "dev-secret-key-base-change-in-production";
    
    # Phoenix
    PHX_HOST = "localhost";
    PHX_PORT = "4000";

    # Development flags
    ELIXIR_ERL_OPTIONS = "+sbwt none +sbwtdcpu none +sbwtdio none";
  };

  # Scripts for common tasks
  scripts = {
    # Database management
    db-setup.exec = ''
      cd apps/secrethub_core
      mix ecto.create
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
    
    # Asset management (using Bun)
    assets-install.exec = ''
      cd apps/secrethub_web/assets
      bun install
    '';
    
    assets-build.exec = ''
      cd apps/secrethub_web/assets
      bun run build
    '';
    
    # Development server
    server.exec = ''
      mix phx.server
    '';
    
    # Testing
    test-all.exec = ''
      mix test
    '';
    
    test-watch.exec = ''
      mix test.watch
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
        
    # Check if dependencies are installed
    if [ ! -d "deps" ]; then
      echo "📦 Installing Elixir dependencies..."
      mix deps.get
      echo ""
    fi
    
    # Check if assets dependencies are installed
    if [ -d "apps/secrethub_web/assets" ] && [ ! -d "apps/secrethub_web/assets/node_modules" ]; then
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
