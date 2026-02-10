defmodule SecretHub.Web.Plugs.VaultTokenAuth do
  @moduledoc """
  Authentication plug that verifies X-Vault-Token header.

  Validates the token and assigns the authenticated agent to the connection.
  """

  import Plug.Conn
  require Logger

  def init(opts), do: opts

  def call(conn, _opts) do
    case get_req_header(conn, "x-vault-token") do
      [token] when token != "" ->
        verify_token(conn, token)

      _ ->
        conn
        |> put_status(:unauthorized)
        |> Phoenix.Controller.json(%{error: "Missing or empty X-Vault-Token header"})
        |> halt()
    end
  end

  defp verify_token(conn, token) do
    # Verify the Phoenix.Token
    case Phoenix.Token.verify(SecretHub.Web.Endpoint, "agent_auth", token, max_age: 86_400) do
      {:ok, payload} ->
        agent_db_id = payload.agent_db_id
        agent_id = payload.agent_id

        # Load the agent and its policies
        case SecretHub.Core.Repo.get(SecretHub.Shared.Schemas.Agent, agent_db_id) do
          nil ->
            unauthorized(conn, "Agent not found")

          %{status: :revoked} ->
            unauthorized(conn, "Agent has been revoked")

          %{status: :suspended} ->
            unauthorized(conn, "Agent has been suspended")

          agent ->
            agent = SecretHub.Core.Repo.preload(agent, [:policies, :certificate])

            conn
            |> assign(:current_agent, agent)
            |> assign(:agent_id, agent_id)
        end

      {:error, :expired} ->
        unauthorized(conn, "Token has expired")

      {:error, _reason} ->
        unauthorized(conn, "Invalid token")
    end
  end

  defp unauthorized(conn, message) do
    conn
    |> put_status(:unauthorized)
    |> Phoenix.Controller.json(%{error: message})
    |> halt()
  end
end
