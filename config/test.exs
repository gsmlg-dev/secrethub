import Config

# Set test environment flag
config :secrethub_core, env: :test

# Disable SealState in test mode (it tries to write to DB during init, before Sandbox is set up)
config :secrethub_core, start_seal_state: false

# Configure the database
config :secrethub_core, SecretHub.Core.Repo,
  username: "secrethub",
  password: System.get_env("DATABASE_PASSWORD", "secrethub_test_password"),
  hostname: System.get_env("DATABASE_HOST", "localhost"),
  database: "secrethub_test#{System.get_env("MIX_TEST_PARTITION")}",
  port: String.to_integer(System.get_env("DATABASE_PORT", "5432")),
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :secrethub_web, SecretHub.WebWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "2ZOJa2EtaKKkdOjsRG7Ph4JsrwXMy1A1zDkWadar3rKTkRmfTMnO0nSVfIUjaiA7",
  server: false

# In test we don't send emails
config :secrethub_web, SecretHub.Web.Mailer, adapter: Swoosh.Adapters.Test

# Disable swoosh api client as it is only required for production adapters
config :swoosh, :api_client, false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Configure agent to use temp directory for Unix Domain Socket in test
config :secrethub_agent,
  socket_path: "/tmp/secrethub_test_agent.sock"
