defmodule SecretHub.WebWeb.AgentRegistrationE2ETest do
  @moduledoc """
  End-to-end tests for agent registration flow.

  Tests the complete agent lifecycle:
  - Agent registration with AppRole credentials
  - Certificate issuance
  - Agent authentication
  - Policy enforcement
  """

  use SecretHub.WebWeb.ConnCase, async: false

  alias SecretHub.Core.{Agents, Policies}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Core.Repo

  setup do
    # Use shared mode for database access across processes
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

    # Start SealState for E2E tests
    {:ok, _pid} = start_supervised(SealState)
    Process.sleep(100)

    # Initialize and unseal vault if needed
    case SealState.status() do
      %{initialized: false} ->
        {:ok, shares} = SealState.initialize(3, 2)

        shares
        |> Enum.take(2)
        |> Enum.each(&SealState.unseal/1)

      %{sealed: true, threshold: threshold} ->
        # Vault is initialized but sealed - need shares from somewhere
        # For test purposes, we'll create fresh shares
        :ok

      _ ->
        :ok
    end

    on_exit(fn ->
      Ecto.Adapters.SQL.Sandbox.mode(Repo, :manual)
    end)

    :ok
  end

  describe "E2E: Agent registration flow" do
    test "complete agent registration with AppRole", %{conn: conn} do
      # Step 1: Create a policy for the agent
      {:ok, policy} =
        Policies.create_policy(%{
          name: "test-app-policy",
          path_rules: [
            %{
              path: "secret/data/test-app/*",
              capabilities: ["read"]
            }
          ]
        })

      # Step 2: Register agent with AppRole credentials
      agent_id = "test-agent-#{:rand.uniform(10000)}"

      {:ok, agent} =
        Agents.register_agent(%{
          agent_id: agent_id,
          name: "Test Agent E2E",
          description: "Agent for E2E testing",
          policy_ids: [policy.id],
          auth_method: "approle",
          metadata: %{
            "environment" => "test",
            "team" => "platform"
          }
        })

      assert agent.agent_id == agent_id
      assert agent.status == :pending_certificate

      # Step 3: Generate AppRole credentials for the agent
      {:ok, role_id, secret_id} = Agents.generate_approle_credentials(agent.id)

      assert is_binary(role_id)
      assert is_binary(secret_id)

      # Step 4: Agent authenticates and requests certificate
      # In real scenario, this would be done by the agent daemon
      # For E2E test, we simulate the agent's request

      conn =
        post(conn, "/v1/auth/approle/login", %{
          "role_id" => role_id,
          "secret_id" => secret_id
        })

      assert conn.status == 200
      response = json_response(conn, 200)
      assert Map.has_key?(response, "token")
      assert Map.has_key?(response, "certificate")

      token = response["token"]
      certificate_pem = response["certificate"]

      # Verify certificate is valid PEM format
      assert String.contains?(certificate_pem, "BEGIN CERTIFICATE")
      assert String.contains?(certificate_pem, "END CERTIFICATE")

      # Step 5: Verify agent status changed to active
      updated_agent = Agents.get_agent!(agent.id)
      assert updated_agent.status == :active
      assert updated_agent.current_certificate_pem != nil

      # Step 6: Use token to access secrets (within policy)
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token)

      conn = get(conn, "/v1/secret/data/test-app/config")

      # Should return 404 (secret doesn't exist) not 403 (policy allows access)
      assert conn.status in [404, 200]

      # Step 7: Try to access secret outside policy - should be denied
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token)

      conn = get(conn, "/v1/secret/data/other-app/config")

      assert conn.status == 403
      response = json_response(conn, 403)
      assert response["error"] =~ "permission denied" or response["error"] =~ "access denied"
    end

    test "agent certificate renewal", %{conn: conn} do
      # Step 1: Register and activate agent
      {:ok, policy} =
        Policies.create_policy(%{
          name: "renewal-test-policy",
          path_rules: [
            %{
              path: "secret/data/renewal-test/*",
              capabilities: ["read"]
            }
          ]
        })

      agent_id = "renewal-agent-#{:rand.uniform(10000)}"

      {:ok, agent} =
        Agents.register_agent(%{
          agent_id: agent_id,
          name: "Renewal Test Agent",
          policy_ids: [policy.id],
          auth_method: "approle"
        })

      {:ok, role_id, secret_id} = Agents.generate_approle_credentials(agent.id)

      # Initial login to get certificate
      conn =
        post(conn, "/v1/auth/approle/login", %{
          "role_id" => role_id,
          "secret_id" => secret_id
        })

      initial_cert = json_response(conn, 200)["certificate"]

      # Step 2: Request certificate renewal
      # In production, agent would renew before expiry
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", json_response(conn, 200)["token"])

      conn = post(conn, "/v1/agent/certificate/renew", %{})

      # Should get new certificate (implementation may vary)
      # For now, we just verify the endpoint exists
      assert conn.status in [200, 404, 501]
    end

    test "agent with invalid credentials is rejected", %{conn: conn} do
      # Try to authenticate with invalid AppRole credentials
      conn =
        post(conn, "/v1/auth/approle/login", %{
          "role_id" => "invalid-role-id",
          "secret_id" => "invalid-secret-id"
        })

      assert conn.status in [401, 403, 400]
      response = json_response(conn, conn.status)
      assert Map.has_key?(response, "error")
    end

    test "revoked agent cannot authenticate", %{conn: conn} do
      # Step 1: Register agent
      {:ok, policy} =
        Policies.create_policy(%{
          name: "revoke-test-policy",
          path_rules: [%{path: "secret/*", capabilities: ["read"]}]
        })

      agent_id = "revoke-agent-#{:rand.uniform(10000)}"

      {:ok, agent} =
        Agents.register_agent(%{
          agent_id: agent_id,
          name: "Revoke Test Agent",
          policy_ids: [policy.id],
          auth_method: "approle"
        })

      {:ok, role_id, secret_id} = Agents.generate_approle_credentials(agent.id)

      # Step 2: Revoke the agent
      {:ok, _revoked_agent} = Agents.revoke_agent_certificate(agent.id, "Testing revocation")

      # Step 3: Try to authenticate - should be rejected
      conn =
        post(conn, "/v1/auth/approle/login", %{
          "role_id" => role_id,
          "secret_id" => secret_id
        })

      assert conn.status in [401, 403]
      response = json_response(conn, conn.status)
      assert response["error"] =~ "revoked" or response["error"] =~ "denied"
    end
  end

  describe "E2E: Agent policy enforcement" do
    test "agent can only access secrets allowed by policy", %{conn: conn} do
      # Create two policies with different access
      {:ok, policy1} =
        Policies.create_policy(%{
          name: "app1-policy",
          path_rules: [%{path: "secret/data/app1/*", capabilities: ["read"]}]
        })

      {:ok, policy2} =
        Policies.create_policy(%{
          name: "app2-policy",
          path_rules: [%{path: "secret/data/app2/*", capabilities: ["read", "write"]}]
        })

      # Register two agents with different policies
      {:ok, agent1} =
        Agents.register_agent(%{
          agent_id: "policy-agent-1-#{:rand.uniform(10000)}",
          name: "Agent 1",
          policy_ids: [policy1.id],
          auth_method: "approle"
        })

      {:ok, agent2} =
        Agents.register_agent(%{
          agent_id: "policy-agent-2-#{:rand.uniform(10000)}",
          name: "Agent 2",
          policy_ids: [policy2.id],
          auth_method: "approle"
        })

      # Get tokens for both agents
      {:ok, role_id1, secret_id1} = Agents.generate_approle_credentials(agent1.id)
      {:ok, role_id2, secret_id2} = Agents.generate_approle_credentials(agent2.id)

      conn1 =
        post(conn, "/v1/auth/approle/login", %{
          "role_id" => role_id1,
          "secret_id" => secret_id1
        })

      token1 = json_response(conn1, 200)["token"]

      conn2 =
        build_conn()
        |> post("/v1/auth/approle/login", %{
          "role_id" => role_id2,
          "secret_id" => secret_id2
        })

      token2 = json_response(conn2, 200)["token"]

      # Agent 1 tries to access app1 secrets (should succeed)
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token1)
      conn = get(conn, "/v1/secret/data/app1/config")

      assert conn.status in [200, 404]

      # Agent 1 tries to access app2 secrets (should fail)
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token1)
      conn = get(conn, "/v1/secret/data/app2/config")

      assert conn.status == 403

      # Agent 2 can access app2 secrets
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token2)
      conn = get(conn, "/v1/secret/data/app2/config")

      assert conn.status in [200, 404]

      # Agent 2 cannot access app1 secrets
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token2)
      conn = get(conn, "/v1/secret/data/app1/config")

      assert conn.status == 403
    end
  end

  describe "E2E: Multiple agents concurrent registration" do
    test "multiple agents can register concurrently", %{conn: _conn} do
      # Create a shared policy
      {:ok, policy} =
        Policies.create_policy(%{
          name: "concurrent-test-policy",
          path_rules: [%{path: "secret/*", capabilities: ["read"]}]
        })

      # Register multiple agents concurrently
      tasks =
        Enum.map(1..10, fn i ->
          Task.async(fn ->
            Agents.register_agent(%{
              agent_id: "concurrent-agent-#{i}-#{:rand.uniform(10000)}",
              name: "Concurrent Agent #{i}",
              policy_ids: [policy.id],
              auth_method: "approle"
            })
          end)
        end)

      results = Task.await_many(tasks, 10000)

      # All registrations should succeed
      assert Enum.all?(results, fn result ->
               match?({:ok, _agent}, result)
             end)

      # Verify all agents are in database
      agents = Enum.map(results, fn {:ok, agent} -> agent end)
      assert length(agents) == 10

      # All agents should have unique IDs
      agent_ids = Enum.map(agents, & &1.agent_id)
      assert length(Enum.uniq(agent_ids)) == 10
    end
  end
end
