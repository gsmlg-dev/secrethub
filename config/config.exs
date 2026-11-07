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

import_config "build_info.exs"

# Configure Ecto repositories
config :secrethub_core,
  env: config_env(),
  ecto_repos: [SecretHub.Core.Repo],
  cluster_node_freshness_timeout_seconds: 30

config :secrethub_core, SecretHub.Core.Styx,
  name: SecretHub.Core.Styx,
  repo: SecretHub.Core.Repo,
  queues: [acme: 4, acme_cleanup: 2],
  shutdown_grace_period: 15_000,
  plugins: [
    {Styx.Plugins.Pruner, max_age: 604_800},
    {Styx.Plugins.Cron, crontab: [{"* * * * *", SecretHub.Core.PKI.ACME.Reconciler}]}
  ]

config :secrethub_human,
  env: config_env(),
  enabled: true,
  ecto_repos: [SecretHub.Human.Repo]

# Database query arguments contain vault envelopes and credential verifiers.
config :secrethub_human, SecretHub.Human.Repo, log: false

config :secrethub_human, SecretHub.HumanWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [formats: [json: SecretHub.HumanWeb.ErrorJSON], layout: false],
  pubsub_server: SecretHub.Human.PubSub

config :secrethub_human, Styx,
  name: SecretHub.Human.Styx,
  repo: SecretHub.Human.Repo,
  queues: [human_audit: 5],
  plugins: [
    {Styx.Plugins.Pruner, max_age: 604_800},
    {Styx.Plugins.Cron,
     crontab: [
       {"* * * * *", SecretHub.Human.LeaseMonitor},
       {"0 * * * *", SecretHub.Human.Attachments.Cleanup}
     ]}
  ]

config :secrethub_web,
  namespace: SecretHub.Web,
  generators: [timestamp_type: :utc_datetime],
  ecto_repos: [SecretHub.Core.Repo],
  dev_mode: false

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

config :secrethub_web, SecretHub.Web.AgentEndpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  server: false,
  pubsub_server: SecretHub.Web.PubSub

config :secrethub_web, SecretHub.Web.MachineEndpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  server: false,
  render_errors: [formats: [json: SecretHub.Web.ErrorJSON], layout: false],
  pubsub_server: SecretHub.Web.PubSub

config :secrethub_web,
  agent_trusted_endpoint: "wss://localhost:4665/agent/socket/websocket"

# Configures the mailer
#
# By default it uses the "Local" adapter which stores the emails
# locally. You can see the emails in your browser, at "/dev/mailbox".
#
# For production it's recommended to configure a different adapter
# at the `config/runtime.exs`.
config :secrethub_web, SecretHub.Web.Mailer, adapter: Swoosh.Adapters.Local

# Build paths work from both the umbrella and the web Mix project.
web_assets = Path.expand("../apps/secrethub_web/assets", __DIR__)
web_lib = Path.expand("../apps/secrethub_web/lib", __DIR__)

config :duskmoon_bundler, :secrethub_web,
  root: web_assets,
  entry: Path.join(web_assets, "js/app.js"),
  outdir: Path.expand("../apps/secrethub_web/priv/static/assets", __DIR__),
  sourcemap: false,
  format: :esm,
  resolve_dirs: [Path.expand("../deps", __DIR__)],
  tailwind: [
    css: Path.join(web_assets, "css/app.css"),
    sources: [
      %{base: web_lib, pattern: "**/*.{ex,heex}"},
      %{base: web_assets, pattern: "**/*.{css,js}"},
      %{
        base: Path.expand("../deps/phoenix_duskmoon/lib", __DIR__),
        pattern: "**/*.{ex,heex}"
      }
    ]
  ],
  server: [prefix: "/assets", watch_dirs: [web_lib, web_assets]]

# Resolve manifests within the installed OTP app, independent of the build host.
config :duskmoon_bundler_runtime, :secrethub_web, outdir: "priv/static/assets"

# Redact sensitive request, channel, and LiveView event parameters in logs.
config :phoenix, :filter_parameters, [
  "password",
  "secret",
  "secret_data",
  "value",
  "token",
  "api_key",
  "apikey",
  "key",
  "share",
  "shares",
  "private_key",
  "private_key_pem",
  "wrapping_key",
  "master_key",
  "access_token",
  "refresh_token",
  "masterPasswordHash",
  "encrypted_key",
  "encryptedPrivateKey",
  "ciphertext"
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
    :rotator_id,
    :rotator_name,
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
