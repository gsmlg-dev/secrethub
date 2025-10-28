defmodule SecretHub.Agent.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Cache for secrets
      SecretHub.Agent.Cache,
      # Lease renewer for dynamic secrets
      {SecretHub.Agent.LeaseRenewer,
       [
         core_url: Application.get_env(:secrethub_agent, :core_url, "http://localhost:4000"),
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

    opts = [strategy: :one_for_one, name: SecretHub.Agent.Supervisor]
    Supervisor.start_link(children, opts)
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
