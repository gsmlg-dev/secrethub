# This file is responsible for configuring your umbrella
# and **all applications** and their dependencies with the
# help of the Config module.
#
# Note that all applications in your umbrella share the
# same configuration and dependencies, which is why they
# all use the same configuration file. If you want different
# configurations or dependencies per app, it is best to
# move said applications out of the umbrella.
# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

# Configure Ecto repositories
config :secrethub_core,
  ecto_repos: [SecretHub.Core.Repo]

config :secrethub_web,
  namespace: SecretHub.Web,
  generators: [timestamp_type: :utc_datetime],
  ecto_repos: [SecretHub.Core.Repo]

# Configures the endpoint
config :secrethub_web, SecretHub.WebWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: SecretHub.WebWeb.ErrorHTML, json: SecretHub.WebWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: SecretHub.Web.PubSub,
  live_view: [signing_salt: "0PScoGoh"],
  # Secure session configuration
  session_options: [
    store: :cookie,
    key: "_secrethub_session",
    signing_salt: "secrethub_signing_salt",
    # Security hardening
    # Prevent JavaScript access (XSS protection)
    http_only: true,
    # Set to true in production (HTTPS only)
    secure: false,
    # CSRF protection
    same_site: "Lax",
    # 30 minutes session timeout
    max_age: 1800,
    encryption_salt: "secrethub_encryption_salt"
  ]

# Configures the mailer
#
# By default it uses the "Local" adapter which stores the emails
# locally. You can see the emails in your browser, at "/dev/mailbox".
#
# For production it's recommended to configure a different adapter
# at the `config/runtime.exs`.
config :secrethub_web, SecretHub.Web.Mailer, adapter: Swoosh.Adapters.Local

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.25.4",
  secrethub_web: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../apps/secrethub_web/assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "4.1.7",
  secrethub_web: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),
    cd: Path.expand("../apps/secrethub_web", __DIR__)
  ]

# Configures Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [
    :request_id,
    :agent_id,
    :serial,
    :reason,
    :event,
    :lease_id,
    :role,
    :ttl,
    :secret_path,
    :requested_topic,
    :topic,
    :peer,
    :payload,
    :ref,
    :common_name,
    :delay_ms,
    :channel,
    :core_url,
    :cert,
    :url,
    :new_version,
    :count,
    :ttl_seconds,
    :max_size,
    :fallback_enabled,
    :expires_at,
    :expired_at
  ]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"

# Sample configuration:
#
#     config :logger, :console,
#       level: :info,
#       format: "$date $time [$level] $metadata$message\n",
#       metadata: [:user_id]
#
