defmodule SecretHub.Web.AgentChannel do
  @moduledoc """
  Phoenix Channel for Agent communication.

  Handles all Agent requests including:
  - Static secret retrieval
  - Dynamic secret generation
  - Lease renewal
  - Server-side push notifications (secret rotation, policy updates)

  ## Message Format

  All messages follow JSON-RPC style:

      %{
        "event" => "event_name",
        "payload" => %{...},
        "ref" => 123
      }

  ## Supported Events

  ### Client → Server (handle_in)
  - `secrets:get_static` - Retrieve static secret
  - `secrets:get_dynamic` - Generate dynamic credentials
  - `lease:renew` - Renew an active lease

  ### Server → Client (push notifications)
  - `secret:rotated` - Secret has been rotated
  - `policy:updated` - Policy has changed
  - `cert:expiring` - Certificate expiring soon
  - `lease:revoked` - Lease has been revoked

  ## Authorization

  All requests are authorized based on the agent_id from socket assigns
  and policies bound to that agent (will be implemented in Week 8-9).
  """

  use Phoenix.Channel

  require Logger

  @impl true
  def join("agent:" <> topic_agent_id, _payload, socket) do
    agent_id = socket.assigns.agent_id

    if topic_agent_id == agent_id do
      Logger.info("Agent joined channel",
        agent_id: agent_id,
        topic: "agent:#{topic_agent_id}"
      )

      # Send welcome message after join completes
      send(self(), :after_join)

      {:ok, socket}
    else
      Logger.warning("Agent authorization failed: topic mismatch",
        agent_id: agent_id,
        requested_topic: topic_agent_id
      )

      {:error, %{reason: "unauthorized"}}
    end
  end

  @impl true
  def handle_info(:after_join, socket) do
    agent_id = socket.assigns.agent_id

    # Send welcome message after socket has joined
    push(socket, "connected", %{
      agent_id: agent_id,
      connected_at: DateTime.utc_now() |> DateTime.to_iso8601(),
      server_version: "0.1.0"
    })

    {:noreply, socket}
  end

  @impl true
  def handle_in("secrets:get_static", %{"path" => path}, socket) do
    agent_id = socket.assigns.agent_id

    Logger.info("Agent requesting static secret",
      agent_id: agent_id,
      secret_path: path
    )

    # TODO: Week 8-9 - Implement real secret retrieval
    # 1. Validate secret path format
    # 2. Check agent policies allow access to this secret
    # 3. Retrieve encrypted secret from database
    # 4. Log audit event
    # 5. Return secret

    # Mock response for now
    response = %{
      value: "mock_secret_#{path}",
      version: 1,
      metadata: %{
        created_at: DateTime.utc_now() |> DateTime.to_iso8601(),
        rotation_enabled: false
      }
    }

    {:reply, {:ok, response}, socket}
  end

  @impl true
  def handle_in("secrets:get_dynamic", %{"role" => role, "ttl" => ttl}, socket) do
    agent_id = socket.assigns.agent_id

    Logger.info("Agent requesting dynamic secret",
      agent_id: agent_id,
      role: role,
      ttl: ttl
    )

    # TODO: Week 13-14 - Implement dynamic secret generation
    # 1. Validate role exists
    # 2. Check agent policies allow this role
    # 3. Generate credentials via secret engine
    # 4. Create lease in database
    # 5. Schedule lease expiry
    # 6. Log audit event
    # 7. Return credentials + lease_id

    # Mock response
    lease_id = Ecto.UUID.generate()
    expires_at = DateTime.utc_now() |> DateTime.add(ttl, :second)

    response = %{
      username: "v-#{agent_id}-#{extract_role_suffix(role)}-#{random_suffix()}",
      password: "mock_password_#{random_suffix()}",
      lease_id: lease_id,
      lease_duration: ttl,
      expires_at: DateTime.to_iso8601(expires_at)
    }

    {:reply, {:ok, response}, socket}
  end

  @impl true
  def handle_in("lease:renew", %{"lease_id" => lease_id}, socket) do
    agent_id = socket.assigns.agent_id

    Logger.info("Agent renewing lease",
      agent_id: agent_id,
      lease_id: lease_id
    )

    # TODO: Week 13-14 - Implement lease renewal
    # 1. Look up lease in database
    # 2. Verify agent owns this lease
    # 3. Check lease is not expired or revoked
    # 4. Extend expiry time
    # 5. Increment renewal counter
    # 6. Log audit event
    # 7. Return new expiry

    # Mock response
    renewed_ttl = 3600
    new_expires_at = DateTime.utc_now() |> DateTime.add(renewed_ttl, :second)

    response = %{
      lease_id: lease_id,
      renewed_ttl: renewed_ttl,
      new_expires_at: DateTime.to_iso8601(new_expires_at)
    }

    {:reply, {:ok, response}, socket}
  end

  @doc """
  Handle unknown events.

  Returns an error for any unrecognized message types.
  """
  @impl true
  def handle_in(event, _payload, socket) do
    Logger.warning("Unknown event received",
      agent_id: socket.assigns.agent_id,
      event: event
    )

    {:reply, {:error, %{reason: "unknown_event", event: event}}, socket}
  end

  ## Server Push Notifications

  @doc """
  Notify agent that a secret has been rotated.

  Broadcast to a specific agent or all agents subscribed to a secret.

  ## Example

      notify_secret_rotated(socket, %{
        secret_path: "prod.db.postgres.password",
        new_version: 2,
        rotation_time: DateTime.utc_now()
      })
  """
  def notify_secret_rotated(socket, payload) do
    push(socket, "secret:rotated", payload)
    socket
  end

  @doc """
  Notify agent that a policy has been updated.
  """
  def notify_policy_updated(socket, payload) do
    push(socket, "policy:updated", payload)
    socket
  end

  @doc """
  Notify agent that their certificate is expiring soon.
  """
  def notify_cert_expiring(socket, payload) do
    push(socket, "cert:expiring", payload)
    socket
  end

  @doc """
  Notify agent that a lease has been revoked.
  """
  def notify_lease_revoked(socket, payload) do
    push(socket, "lease:revoked", payload)
    socket
  end

  # Private helpers

  defp extract_role_suffix(role) do
    role
    |> String.split(".")
    |> List.last()
  end

  defp random_suffix do
    6
    |> :crypto.strong_rand_bytes()
    |> Base.encode16(case: :lower)
  end
end
