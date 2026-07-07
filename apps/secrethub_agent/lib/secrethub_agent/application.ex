defmodule SecretHub.Agent.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    # Check if agent is enabled (default: true)
    # Set `config :secrethub_agent, enabled: false` in dev.exs to disable
    if Application.get_env(:secrethub_agent, :enabled, true) do
      start_agent()
    else
      # Return empty supervisor when disabled
      Supervisor.start_link([], strategy: :one_for_one, name: SecretHub.Agent.Supervisor)
    end
  end

  defp start_agent do
    core_url = configured_value(:core_url, "SECRET_HUB_AGENT_CORE_URL")
    core_endpoints = [core_url]

    children = [
      # Cache for secrets
      SecretHub.Agent.Cache,

      # Endpoint manager for multi-endpoint failover
      {SecretHub.Agent.EndpointManager,
       [
         core_endpoints: core_endpoints,
         health_check_interval:
           Application.get_env(:secrethub_agent, :endpoint_health_check_interval, 30_000),
         failover_threshold:
           Application.get_env(:secrethub_agent, :endpoint_failover_threshold, 3)
       ]},

      # Bootstrap trusted runtime connection from local identity or enrollment
      {SecretHub.Agent.RuntimeBootstrapper,
       [
         core_url: core_url,
         core_endpoints: core_endpoints,
         enrollment_opts: Application.get_env(:secrethub_agent, :enrollment_opts, [])
       ]},

      # Lease renewer for dynamic secrets
      {SecretHub.Agent.LeaseRenewer,
       [
         core_url: core_url,
         callbacks: %{
           on_renewed: &handle_renewed/1,
           on_failed: &handle_failed/1,
           on_expiring_soon: &handle_expiring_soon/1,
           on_expired: &handle_expired/1
         }
       ]},

      # Unix Domain Socket server for application connections
      {SecretHub.Agent.UDSServer,
       [
         socket_path:
           Application.get_env(:secrethub_agent, :socket_path, "/var/run/secrethub/agent.sock"),
         max_connections: Application.get_env(:secrethub_agent, :max_connections, 100)
       ]}
    ]

    # :rest_for_one ensures downstream children restart when an upstream
    # dependency crashes (e.g., if RuntimeBootstrapper dies, LeaseRenewer
    # and UDSServer restart since they depend on the Core connection).
    opts = [strategy: :rest_for_one, name: SecretHub.Agent.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp configured_value(key, env_name) do
    value = System.get_env(env_name) || Application.get_env(:secrethub_agent, key)

    if is_binary(value) and value != "" do
      value
    else
      raise """
      #{env_name} is required to start the SecretHub Agent.
      For example: https://secrethub.example.com
      """
    end
  end

  # Lease renewal callbacks

  defp handle_renewed(lease) do
    # Update cache with renewed lease information
    require Logger

    Logger.info("Lease renewed successfully",
      lease_id: lease.id,
      secret_path: lease.secret_path,
      new_expiry: lease.expires_at
    )

    # TODO: Update cache expiry time for this secret
  end

  defp handle_failed(lease) do
    # Lease renewal failed permanently
    require Logger

    Logger.error("Lease renewal failed permanently",
      lease_id: lease.id,
      secret_path: lease.secret_path,
      retries: lease.retry_count
    )

    # TODO: Remove from cache and notify application
    # TODO: Maybe trigger alarm or send metric
  end

  defp handle_expiring_soon(lease) do
    # Lease is expiring soon (< 5 minutes)
    require Logger

    Logger.warning("Lease expiring soon",
      lease_id: lease.id,
      secret_path: lease.secret_path,
      expires_at: lease.expires_at
    )

    # TODO: Trigger warning metric
  end

  defp handle_expired(lease) do
    # Lease has expired
    require Logger

    Logger.error("Lease expired",
      lease_id: lease.id,
      secret_path: lease.secret_path
    )

    # TODO: Remove from cache
    # TODO: Trigger alarm
  end
end
