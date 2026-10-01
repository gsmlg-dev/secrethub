import Config

# Dedicated runtime config for standalone Agent releases. Packaged Core uses
# config/core_runtime.exs for DB/Phoenix secrets; config/runtime.exs is the source-execution compatibility entrypoint.
alias SecretHub.Shared.{RuntimeConfig, RuntimeSecrets}

core_url = RuntimeSecrets.read!("SECRET_HUB_AGENT_CORE_URL")
RuntimeConfig.https_url!("SECRET_HUB_AGENT_CORE_URL", core_url)
RuntimeConfig.distribution!()
host_key_path = RuntimeSecrets.read!("SECRET_HUB_AGENT_HOST_KEY_PATH")
state_dir = RuntimeSecrets.read!("SECRET_HUB_AGENT_STATE_DIR")
socket_path = RuntimeSecrets.read!("SECRET_HUB_AGENT_SOCKET_PATH")
bundle_dir = RuntimeSecrets.read!("SECRET_HUB_CLIENT_AUTH_BUNDLE_DIR")

config :secrethub_agent,
  enabled: true,
  launch_profile: :single_operator,
  enabled_features: [:static_secrets, :client_auth_pki],
  client_auth_pki_enabled: true,
  core_url: core_url,
  state_dir: state_dir,
  socket_path: socket_path,
  client_auth_bundle_dir: bundle_dir,
  enrollment_opts: [paths: [ecdsa: host_key_path, rsa: host_key_path]]
