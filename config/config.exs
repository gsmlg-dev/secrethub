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
  live_view: [signing_salt: "V8xDL3qRkJhNm5wZ"],
  # Secure session configuration
  session_options: [
    store: :cookie,
    key: "_secrethub_session",
    signing_salt: "W9yFM4rSkKiOn6xA",
    # Security hardening
    # Prevent JavaScript access (XSS protection)
    http_only: true,
    # Set to true in production (HTTPS only)
    secure: false,
    # CSRF protection
    same_site: "Lax",
    # 30 minutes session timeout
    max_age: 1800,
    encryption_salt: "X0zGN5sTlLjPo7yB"
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
    :account_name,
    :action,
    :active_connections,
    :agent_id,
    :alert_id,
    :api_key,
    :app_id,
    :app_name,
    :args,
    :backoff_ms,
    :batch_size,
    :blob_name,
    :bucket,
    :ca_cert_path,
    :cert,
    :certificate_id,
    :channel,
    :channels,
    :common_name,
    :computed_hash,
    :config_id,
    :config_name,
    :container,
    :core_url,
    :count,
    :current,
    :default_ttl,
    :delay_ms,
    :deleted,
    :deleted_count,
    :description,
    :dry_run,
    :duration_ms,
    :engine_type,
    :entity_id,
    :error,
    :errors,
    :event,
    :event_type,
    :evicted,
    :exit_code,
    :expected_hash,
    :expired_at,
    :expires_at,
    :failed,
    :fallback_enabled,
    :group,
    :history_id,
    :integration_key,
    :invalid,
    :invalid_count,
    :invalid_log_ids,
    :ip,
    :kept_count,
    :key,
    :lease_id,
    :location,
    :log_id,
    :max,
    :max_connections,
    :max_entries,
    :max_size,
    :method,
    :name,
    :new_expiry,
    :new_ttl,
    :new_version,
    :operation,
    :output,
    :owner,
    :path,
    :payload,
    :peer,
    :policies,
    :policies_count,
    :policy,
    :policy_id,
    :policy_name,
    :project_id,
    :reason,
    :recipients,
    :records,
    :ref,
    :region,
    :remaining,
    :request_id,
    :requested_topic,
    :retries,
    :retry,
    :retry_after,
    :retry_count,
    :role,
    :role_arn,
    :rule,
    :scheduled,
    :schedule_id,
    :schedule_name,
    :scope,
    :script,
    :seconds,
    :secret_id,
    :secret_path,
    :sequence,
    :serial,
    :session_name,
    :severity,
    :signal,
    :size,
    :socket,
    :socket_path,
    :stacktrace,
    :subject,
    :successful,
    :table,
    :tables,
    :target,
    :template,
    :template_excerpt,
    :timestamp,
    :topic,
    :total,
    :total_channels,
    :total_logs,
    :ttl,
    :ttl_seconds,
    :type,
    :url,
    :username,
    :valid,
    :variable,
    :verification_results,
    :webhook_url
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
