import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

secrethub_role =
  SecretHub.Human.RuntimeRole.resolve!(System.get_env("SECRETHUB_ROLE"), config_env())

human_enabled = SecretHub.Human.RuntimeRole.human_enabled?(secrethub_role)

config :secrethub_human, enabled: human_enabled

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/secrethub_web start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :secrethub_web, SecretHub.Web.Endpoint, server: true

  if human_enabled do
    config :secrethub_human, SecretHub.HumanWeb.Endpoint, server: true
  end
end

if System.get_env("SECRET_HUB_AGENT_ENDPOINT_SERVER") in ~w(true 1) do
  agent_host = System.get_env("SECRET_HUB_AGENT_ENDPOINT_HOST") || "localhost"
  agent_port = String.to_integer(System.get_env("SECRET_HUB_AGENT_ENDPOINT_PORT") || "4665")

  agent_certfile =
    System.get_env("SECRET_HUB_AGENT_ENDPOINT_CERT_PATH") ||
      raise "SECRET_HUB_AGENT_ENDPOINT_CERT_PATH is required when the trusted Agent endpoint is enabled"

  agent_keyfile =
    System.get_env("SECRET_HUB_AGENT_ENDPOINT_KEY_PATH") ||
      raise "SECRET_HUB_AGENT_ENDPOINT_KEY_PATH is required when the trusted Agent endpoint is enabled"

  agent_cacertfile =
    System.get_env("SECRET_HUB_AGENT_ENDPOINT_CA_CERT_PATH") ||
      raise "SECRET_HUB_AGENT_ENDPOINT_CA_CERT_PATH is required when the trusted Agent endpoint is enabled"

  config :secrethub_web, SecretHub.Web.AgentEndpoint,
    server: true,
    pubsub_server: SecretHub.Web.PubSub,
    url: [host: agent_host, port: agent_port],
    https: [
      ip: {0, 0, 0, 0, 0, 0, 0, 0},
      port: agent_port,
      cipher_suite: :strong,
      certfile: agent_certfile,
      keyfile: agent_keyfile,
      thousand_island_options: [
        transport_options: [
          cacertfile: String.to_charlist(agent_cacertfile),
          verify: :verify_peer,
          fail_if_no_peer_cert: true,
          versions: [:"tlsv1.2", :"tlsv1.3"],
          # Dual-stack so IPv4-resolving agents can reach the IPv6 wildcard bind
          ipv6_v6only: false
        ]
      ]
    ]

  config :secrethub_web,
    agent_trusted_endpoint: "wss://#{agent_host}:#{agent_port}/agent/socket/websocket"
end

# Asset tool paths (MIX_BUN_PATH, MIX_TAILWIND_PATH) are configured
# in config.exs via System.get_env so they apply at compile time
# when mix bun/tailwind tasks run.

if config_env() == :prod do
  alias SecretHub.Shared.{RuntimeConfig, RuntimeSecrets}

  if secrethub_role != :core or human_enabled do
    raise ArgumentError, "SECRETHUB_ROLE: single_operator_requires_core"
  end

  if System.get_env("SECRET_HUB_ADMIN_ENDPOINT_SERVER") in ~w(true 1) do
    raise ArgumentError, "SECRET_HUB_ADMIN_ENDPOINT_SERVER: unsupported_duplicate_authentication"
  end

  RuntimeConfig.distribution!()
  cluster_node_id = RuntimeSecrets.read!("SECRET_HUB_CLUSTER_NODE_ID")
  database_url = RuntimeConfig.database_url!(RuntimeSecrets.read!("DATABASE_URL"))
  secret_key_base = RuntimeSecrets.read!("SECRET_KEY_BASE")

  if byte_size(secret_key_base) < 64 or String.starts_with?(secret_key_base, "build-only") do
    raise ArgumentError, "SECRET_KEY_BASE: invalid_key"
  end

  audit_key = RuntimeConfig.decode_key!("AUDIT_HMAC_KEY", RuntimeSecrets.read!("AUDIT_HMAC_KEY"))
  audit_key_id = RuntimeSecrets.read!("AUDIT_HMAC_KEY_ID")

  verification_keys =
    RuntimeConfig.verification_keys!(
      RuntimeSecrets.read!("AUDIT_HMAC_VERIFICATION_KEYS", required: false)
    )

  config :secrethub_core,
    cluster_node_id: cluster_node_id,
    launch_profile: :single_operator,
    enabled_features: [:static_secrets, :client_auth_pki],
    audit_hmac_secret: audit_key,
    audit_hmac_key_id: audit_key_id,
    audit_hmac_verification_keys: verification_keys

  config :secrethub_human, enabled: false

  config :secrethub_core, SecretHub.Core.Repo,
    url: database_url,
    pool_size: RuntimeConfig.port!("POOL_SIZE", 10),
    socket_options: if(System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: [])

  # The public origin is independent of the private transport address and Host headers.
  origin =
    RuntimeConfig.https_url!(
      "SECRET_HUB_MANAGEMENT_ORIGIN",
      RuntimeSecrets.read!("SECRET_HUB_MANAGEMENT_ORIGIN")
    )

  if origin.path not in [nil, "", "/"],
    do: raise(ArgumentError, "SECRET_HUB_MANAGEMENT_ORIGIN: invalid_origin")

  port = RuntimeConfig.port!("PORT", 4664)
  management_ip = RuntimeConfig.private_ip!("SECRET_HUB_MANAGEMENT_BIND_IP", "127.0.0.1")
  proxy_ip = RuntimeConfig.private_ip!("SECRET_HUB_TRUSTED_PROXY_IP", "127.0.0.1")
  machine_port = RuntimeConfig.port!("SECRET_HUB_MACHINE_PORT", 4668)
  agent_port = RuntimeConfig.port!("SECRET_HUB_AGENT_ENDPOINT_PORT", 4665)

  if length(Enum.uniq([port, machine_port, agent_port])) != 3 do
    raise ArgumentError, "listeners: conflicting_ports"
  end

  config :secrethub_web, SecretHub.Web.Endpoint,
    url: [scheme: "https", host: origin.host, port: origin.port, path: ""],
    http: [ip: management_ip, port: port],
    https: nil,
    trusted_proxy_ips: [proxy_ip],
    secret_key_base: secret_key_base,
    check_origin: [URI.to_string(%{origin | path: nil})]

  # Machine enrollment and application-token APIs use an explicit separate route set.
  config :secrethub_web, SecretHub.Web.MachineEndpoint,
    server: System.get_env("SECRET_HUB_MACHINE_ENDPOINT_SERVER") in ~w(true 1),
    url: [host: System.get_env("SECRET_HUB_MACHINE_HOST") || "localhost", port: machine_port],
    http: [
      ip: RuntimeConfig.private_ip!("SECRET_HUB_MACHINE_BIND_IP", "127.0.0.1"),
      port: machine_port
    ],
    secret_key_base: secret_key_base,
    check_origin: false
end
