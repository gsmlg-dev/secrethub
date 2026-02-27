defmodule SecretHub.Web.Plugs.VaultTokenAuthTest do
  use SecretHub.Web.ConnCase, async: false

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.Agent
  alias SecretHub.Web.Plugs.VaultTokenAuth

  describe "VaultTokenAuth plug" do
    setup do
      # Create a test agent in active state
      {:ok, agent} =
        %Agent{}
        |> Agent.changeset(%{
          agent_id: "vault-token-test-agent",
          name: "Vault Token Test Agent",
          status: :active,
          ip_address: "127.0.0.1",
          metadata: %{}
        })
        |> Repo.insert()

      opts = VaultTokenAuth.init([])

      %{agent: agent, opts: opts}
    end

    test "returns 401 when no X-Vault-Token header", %{conn: conn, opts: opts} do
      conn = VaultTokenAuth.call(conn, opts)

      assert conn.halted
      assert conn.status == 401
      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "Missing or empty X-Vault-Token header"
    end

    test "returns 401 when empty X-Vault-Token header", %{conn: conn, opts: opts} do
      conn =
        conn
        |> put_req_header("x-vault-token", "")
        |> VaultTokenAuth.call(opts)

      assert conn.halted
      assert conn.status == 401
      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "Missing or empty X-Vault-Token header"
    end

    test "returns 401 with invalid/malformed token", %{conn: conn, opts: opts} do
      conn =
        conn
        |> put_req_header("x-vault-token", "totally-invalid-token-value")
        |> VaultTokenAuth.call(opts)

      assert conn.halted
      assert conn.status == 401
      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "Invalid token"
    end

    test "returns 401 with expired token", %{conn: conn, agent: agent, opts: opts} do
      # Sign a token with signed_at far enough in the past that it exceeds max_age: 86_400
      payload = %{agent_db_id: agent.id, agent_id: agent.agent_id}

      expired_token =
        Phoenix.Token.sign(SecretHub.Web.Endpoint, "agent_auth", payload,
          signed_at: System.system_time(:second) - 90_000
        )

      conn =
        conn
        |> put_req_header("x-vault-token", expired_token)
        |> VaultTokenAuth.call(opts)

      assert conn.halted
      assert conn.status == 401
      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "Token has expired"
    end

    test "returns 401 when agent not found in DB", %{conn: conn, opts: opts} do
      # Sign a valid token referencing a non-existent agent DB ID
      payload = %{
        agent_db_id: Ecto.UUID.generate(),
        agent_id: "nonexistent-agent"
      }

      token = Phoenix.Token.sign(SecretHub.Web.Endpoint, "agent_auth", payload)

      conn =
        conn
        |> put_req_header("x-vault-token", token)
        |> VaultTokenAuth.call(opts)

      assert conn.halted
      assert conn.status == 401
      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "Agent not found"
    end

    test "returns 401 when agent is revoked", %{conn: conn, opts: opts} do
      # Create an active agent first, then revoke it (direct :revoked insert is
      # rejected by validate_status_transition)
      {:ok, revoked_agent} =
        %Agent{}
        |> Agent.changeset(%{
          agent_id: "revoked-agent-test",
          name: "Revoked Agent",
          status: :active,
          ip_address: "127.0.0.1",
          metadata: %{}
        })
        |> Repo.insert()

      {:ok, revoked_agent} =
        revoked_agent
        |> Agent.revoke_changeset("test revocation")
        |> Repo.update()

      payload = %{agent_db_id: revoked_agent.id, agent_id: revoked_agent.agent_id}
      token = Phoenix.Token.sign(SecretHub.Web.Endpoint, "agent_auth", payload)

      conn =
        conn
        |> put_req_header("x-vault-token", token)
        |> VaultTokenAuth.call(opts)

      assert conn.halted
      assert conn.status == 401
      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "Agent has been revoked"
    end

    test "returns 401 when agent is suspended", %{conn: conn, opts: opts} do
      # Create an active agent first, then suspend it
      {:ok, suspended_agent} =
        %Agent{}
        |> Agent.changeset(%{
          agent_id: "suspended-agent-test",
          name: "Suspended Agent",
          status: :active,
          ip_address: "127.0.0.1",
          metadata: %{}
        })
        |> Repo.insert()

      {:ok, suspended_agent} =
        suspended_agent
        |> Agent.suspend_changeset("test suspension")
        |> Repo.update()

      payload = %{agent_db_id: suspended_agent.id, agent_id: suspended_agent.agent_id}
      token = Phoenix.Token.sign(SecretHub.Web.Endpoint, "agent_auth", payload)

      conn =
        conn
        |> put_req_header("x-vault-token", token)
        |> VaultTokenAuth.call(opts)

      assert conn.halted
      assert conn.status == 401
      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "Agent has been suspended"
    end

    test "passes through and assigns agent when valid token provided", %{
      conn: conn,
      agent: agent,
      opts: opts
    } do
      payload = %{agent_db_id: agent.id, agent_id: agent.agent_id}
      token = Phoenix.Token.sign(SecretHub.Web.Endpoint, "agent_auth", payload)

      conn =
        conn
        |> put_req_header("x-vault-token", token)
        |> VaultTokenAuth.call(opts)

      refute conn.halted
      assert conn.assigns[:current_agent].id == agent.id
      assert conn.assigns[:current_agent].agent_id == agent.agent_id
      assert conn.assigns[:agent_id] == agent.agent_id
    end
  end
end
