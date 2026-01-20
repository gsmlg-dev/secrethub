defmodule SecretHub.Web.AgentController do
  @moduledoc """
  REST API controller for agent management operations.
  """

  use SecretHub.Web, :controller
  require Logger

  def disconnect(conn, %{"id" => agent_id}) do
    Logger.info("Disconnecting agent: #{agent_id}")

    # FIXME: Call SecretHub.Core.Connections.disconnect_agent(agent_id)

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", message: "Agent disconnected successfully"})
  end

  def reconnect(conn, %{"id" => agent_id}) do
    Logger.info("Reconnecting agent: #{agent_id}")

    # FIXME: Call SecretHub.Core.Connections.reconnect_agent(agent_id)

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", message: "Reconnect signal sent to agent"})
  end

  def restart(conn, %{"id" => agent_id}) do
    Logger.info("Restarting agent: #{agent_id}")

    # FIXME: Call SecretHub.Core.Connections.restart_agent(agent_id)

    conn
    |> put_resp_content_type("application/json")
    |> json(%{status: "ok", message: "Restart signal sent to agent"})
  end
end
