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
config :secrethub_web, SecretHub.Web.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: SecretHub.Web.ErrorHTML, json: SecretHub.Web.ErrorJSON],
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
    :action,
    :active_connections,
    :agent_id,
    :app_id,
    :backoff_ms,
    :ca_cert_path,
    :cert,
    :channel,
    :common_name,
    :core_url,
    :count,
    :current,
    :delay_ms,
    :error,
    :event,
    :exit_code,
    :expired_at,
    :expires_at,
    :fallback_enabled,
    :group,
    :lease_id,
    :max,
    :max_connections,
    :max_size,
    :new_expiry,
    :new_ttl,
    :new_version,
    :output,
    :owner,
    :path,
    :payload,
    :peer,
    :reason,
    :ref,
    :remaining,
    :request_id,
    :requested_topic,
    :retries,
    :retry,
    :role,
    :script,
    :secret_path,
    :serial,
    :signal,
    :size,
    :socket,
    :socket_path,
    :stacktrace,
    :target,
    :template_excerpt,
    :topic,
    :ttl,
    :ttl_seconds,
    :type,
    :url,
    :variable
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
