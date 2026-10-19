import Config

# Dedicated runtime config for standalone Agent releases. Packaged Core uses
# config/core_runtime.exs for DB/Phoenix secrets; config/runtime.exs is the source-execution compatibility entrypoint.
alias SecretHub.Shared.RuntimeConfig

settings = SecretHub.Agent.Config.load!()
RuntimeConfig.distribution!()
host_key_path = settings[:host_key_path]
enrollment_ca = settings[:enrollment_ca_path]

enrollment_req_options =
  if enrollment_ca do
    [connect_options: [transport_opts: [cacertfile: enrollment_ca, verify: :verify_peer]]]
  else
    []
  end

config :secrethub_agent,
  enabled: true,
  ssh_lookup_enabled: settings[:ssh_lookup_enabled],
  ssh_signing_enabled: settings[:ssh_signing_enabled],
  ssh_lookup_socket_path: settings[:ssh_lookup_socket_path],
  ssh_signing_socket_path: settings[:ssh_signing_socket_path],
  ssh_lookup_socket_group: settings[:ssh_lookup_socket_group],
  ssh_signing_socket_group: settings[:ssh_signing_socket_group],
  launch_profile: :single_operator,
  enabled_features: [:static_secrets, :client_auth_pki],
  client_auth_pki_enabled: true,
  core_url: settings[:core_url],
  state_dir: settings[:state_dir],
  socket_path: settings[:socket_path],
  client_auth_bundle_dir: settings[:client_auth_bundle_dir],
  enrollment_req_options: enrollment_req_options,
  enrollment_opts: [paths: [ecdsa: host_key_path, rsa: host_key_path]]
