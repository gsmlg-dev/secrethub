defmodule SecretHub.Web.Plugs.VaultTokenAuth do
  @moduledoc """
  Authentication plug that verifies X-Vault-Token header.

  Validates the token and assigns the authenticated agent to the connection.
  """

  import Plug.Conn
  import Ecto.Query
  require Logger

  alias SecretHub.Core.Auth.AppRole
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Agent, Policy}

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
        verify_agent_token(conn, payload)

      {:error, :expired} ->
        unauthorized(conn, "Token has expired")

      {:error, _reason} ->
        verify_approle_token(conn, token)
    end
  end

  defp verify_agent_token(conn, payload) do
    agent_db_id = payload.agent_db_id
    agent_id = payload.agent_id

    # Load the agent and its policies
    case Repo.get(Agent, agent_db_id) do
      nil ->
        unauthorized(conn, "Agent not found")

      %{status: :revoked} ->
        unauthorized(conn, "Agent has been revoked")

      %{status: :suspended} ->
        unauthorized(conn, "Agent has been suspended")

      agent ->
        agent = Repo.preload(agent, [:policies, :certificate])

        conn
        |> assign(:current_agent, agent)
        |> assign(:current_policies, agent.policies || [])
        |> assign(:current_actor, %{type: "agent", id: agent.id, external_id: agent_id})
        |> assign(:agent_id, agent_id)
    end
  end

  defp verify_approle_token(conn, token) do
    case AppRole.verify_token(token) do
      {:ok, payload} ->
        policies = load_approle_policies(Map.get(payload, :policies, []))

        conn
        |> assign(:current_policies, policies)
        |> assign(:current_approle, payload)
        |> assign(:current_actor, %{
          type: "approle",
          id: Map.get(payload, :role_id),
          external_id: Map.get(payload, :role_name)
        })

      {:error, "Token has expired"} ->
        unauthorized(conn, "Token has expired")

      {:error, "CLI access has been revoked"} ->
        unauthorized(conn, "CLI access has been revoked")

      {:error, _reason} ->
        unauthorized(conn, "Invalid token")
    end
  end

  defp load_approle_policies([]), do: []

  defp load_approle_policies(policy_refs) when is_list(policy_refs) do
    policy_ids = Enum.filter(policy_refs, &(Ecto.UUID.cast(&1) != :error))

    from(p in Policy, where: p.name in ^policy_refs or p.id in ^policy_ids)
    |> Repo.all()
  end

  defp load_approle_policies(_policy_refs), do: []

  defp unauthorized(conn, message) do
    conn
    |> put_status(:unauthorized)
    |> Phoenix.Controller.json(%{error: message})
    |> halt()
  end
end
