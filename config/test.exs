import Config

# Configure the database
config :secrethub_core, SecretHub.Core.Repo,
  username: "secrethub",
  password: "secrethub_dev_password",
  hostname: "localhost",
  database: "secrethub_test#{System.get_env("MIX_TEST_PARTITION")}",
  port: 5432,
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
