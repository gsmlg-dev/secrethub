defmodule SecretHub.Web.AccessControlE2ETest do
  @moduledoc """
  End-to-end tests for access control and policy enforcement.

  Tests:
  - Cross-agent secret isolation
  - Policy wildcard matching
  - Operation-level permissions (read-only vs read-write)
  - Token expiry and rejection
  - Rate limiting on auth endpoints
  - Unauthorized access patterns
  """

  use SecretHub.Web.ConnCase, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias SecretHub.Core.{Agents, Policies}
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState

  @moduletag :e2e

  setup do
    Sandbox.mode(Repo, {:shared, self()})
    {:ok, _pid} = start_supervised(SealState)
    Process.sleep(100)

    case SealState.status() do
      %{initialized: false} ->
        {:ok, shares} = SealState.initialize(3, 2)
        shares |> Enum.take(2) |> Enum.each(&SealState.unseal/1)

      _ ->
        :ok
    end

    on_exit(fn -> Sandbox.mode(Repo, :manual) end)
    :ok
  end

  # Helper to register an agent with a policy and return a vault token
  defp create_agent_with_token(policy_doc, opts \\ []) do
    suffix = :rand.uniform(100_000)
    policy_name = Keyword.get(opts, :policy_name, "acl-policy-#{suffix}")
    agent_name = Keyword.get(opts, :agent_name, "acl-agent-#{suffix}")

    {:ok, policy} =
      Policies.create_policy(%{
        name: policy_name,
        policy_document: policy_doc
      })

    {:ok, agent} =
      Agents.register_agent(%{
        agent_id: "acl-#{suffix}",
        name: agent_name,
        policy_ids: [policy.id],
        auth_method: "approle"
      })

    {:ok, role_id, secret_id} = Agents.generate_approle_credentials(agent.id)

    conn =
      build_conn()
      |> post("/v1/auth/approle/login", %{
        "role_id" => role_id,
        "secret_id" => secret_id
      })

    token = json_response(conn, 200)["token"]
    %{token: token, agent: agent, policy: policy}
  end

  # Helper to create a secret via API
  defp create_secret(token, path, data) do
    build_conn()
    |> put_req_header("x-vault-token", token)
    |> post("/v1/secret/data/#{path}", %{"data" => data})
  end

  describe "E2E: Cross-agent secret isolation" do
    test "agents with different policies cannot read each other's secrets" do
      # Agent A: access to team-alpha/*
      %{token: token_a} =
        create_agent_with_token(%{
          "version" => "1.0",
          "allowed_secrets" => ["secret/data/team-alpha/*"],
          "allowed_operations" => ["create", "read", "update", "delete"]
        })

      # Agent B: access to team-beta/*
      %{token: token_b} =
        create_agent_with_token(%{
          "version" => "1.0",
          "allowed_secrets" => ["secret/data/team-beta/*"],
          "allowed_operations" => ["create", "read", "update", "delete"]
        })

      # Agent A creates a secret in its namespace
      conn = create_secret(token_a, "team-alpha/db-creds", %{"password" => "alpha-secret"})
      assert conn.status == 200

      # Agent B creates a secret in its namespace
      conn = create_secret(token_b, "team-beta/db-creds", %{"password" => "beta-secret"})
      assert conn.status == 200

      # Agent A can read its own secret
      conn =
        build_conn()
        |> put_req_header("x-vault-token", token_a)
        |> get("/v1/secret/data/team-alpha/db-creds")

      assert conn.status == 200
      assert json_response(conn, 200)["data"]["password"] == "alpha-secret"

      # Agent A CANNOT read Agent B's secret
      conn =
        build_conn()
        |> put_req_header("x-vault-token", token_a)
        |> get("/v1/secret/data/team-beta/db-creds")

      assert conn.status == 403

      # Agent B CANNOT read Agent A's secret
      conn =
        build_conn()
        |> put_req_header("x-vault-token", token_b)
        |> get("/v1/secret/data/team-alpha/db-creds")

      assert conn.status == 403
    end

    test "agent with wildcard policy can access multiple paths" do
      %{token: token} =
        create_agent_with_token(%{
          "version" => "1.0",
          "allowed_secrets" => ["secret/data/shared/*", "secret/data/infra/*"],
          "allowed_operations" => ["create", "read"]
        })

      # Create secrets in both allowed paths
      conn = create_secret(token, "shared/config", %{"key" => "value1"})
      assert conn.status == 200

      conn = create_secret(token, "infra/monitoring", %{"key" => "value2"})
      assert conn.status == 200

      # Read from both paths
      conn =
        build_conn()
        |> put_req_header("x-vault-token", token)
        |> get("/v1/secret/data/shared/config")

      assert conn.status == 200

      conn =
        build_conn()
        |> put_req_header("x-vault-token", token)
        |> get("/v1/secret/data/infra/monitoring")

      assert conn.status == 200

      # Cannot read from an unallowed path
      conn =
        build_conn()
        |> put_req_header("x-vault-token", token)
        |> get("/v1/secret/data/private/admin-creds")

      assert conn.status == 403
    end
  end

  describe "E2E: Operation-level permissions" do
    test "read-only agent cannot create secrets" do
      %{token: token} =
        create_agent_with_token(%{
          "version" => "1.0",
          "allowed_secrets" => ["secret/data/readonly-test/*"],
          "allowed_operations" => ["read"]
        })

      # Try to create a secret — should be denied
      conn = create_secret(token, "readonly-test/attempt", %{"data" => "should-fail"})
      assert conn.status == 403
    end

    test "read-only agent cannot delete secrets" do
      # Create agent with write access to seed the secret
      %{token: writer_token} =
        create_agent_with_token(%{
          "version" => "1.0",
          "allowed_secrets" => ["secret/data/delete-test/*"],
          "allowed_operations" => ["create", "read", "update", "delete"]
        })

      # Create a secret
      conn = create_secret(writer_token, "delete-test/target", %{"val" => "exists"})
      assert conn.status == 200

      # Create read-only agent
      %{token: reader_token} =
        create_agent_with_token(%{
          "version" => "1.0",
          "allowed_secrets" => ["secret/data/delete-test/*"],
          "allowed_operations" => ["read"]
        })

      # Read-only agent can read
      conn =
        build_conn()
        |> put_req_header("x-vault-token", reader_token)
        |> get("/v1/secret/data/delete-test/target")

      assert conn.status == 200

      # Read-only agent cannot delete
      conn =
        build_conn()
        |> put_req_header("x-vault-token", reader_token)
        |> delete("/v1/secret/data/delete-test/target")

      assert conn.status == 403
    end
  end

  describe "E2E: Token validation edge cases" do
    test "request without X-Vault-Token header returns 401" do
      conn = get(build_conn(), "/v1/secret/data/any/path")
      assert conn.status == 401
    end

    test "request with empty X-Vault-Token returns 401" do
      conn =
        build_conn()
        |> put_req_header("x-vault-token", "")
        |> get("/v1/secret/data/any/path")

      assert conn.status == 401
    end

    test "request with malformed token returns 401" do
      conn =
        build_conn()
        |> put_req_header("x-vault-token", "not-a-valid-token-at-all")
        |> get("/v1/secret/data/any/path")

      assert conn.status == 401
    end

    test "request with tampered base64 token returns 401" do
      # Create a valid-looking but tampered token
      fake_payload =
        Jason.encode!(%{
          role_id: "fake-role",
          policies: ["admin"],
          issued_at: DateTime.utc_now() |> DateTime.to_unix(),
          expires_at: DateTime.utc_now() |> DateTime.add(3600) |> DateTime.to_unix()
        })

      tampered_token = Base.url_encode64(fake_payload, padding: false)

      conn =
        build_conn()
        |> put_req_header("x-vault-token", tampered_token)
        |> get("/v1/secret/data/any/path")

      assert conn.status == 401
    end
  end

  describe "E2E: Rate limiting on auth endpoints" do
    test "excessive login attempts are rate-limited" do
      # The auth pipeline has rate limiting: 5 requests per 60 seconds
      results =
        Enum.map(1..8, fn _i ->
          conn =
            build_conn()
            |> post("/v1/auth/approle/login", %{
              "role_id" => "nonexistent-role",
              "secret_id" => "nonexistent-secret"
            })

          conn.status
        end)

      # First several should get normal error responses (400/401/403)
      # After the limit, should get 429 (Too Many Requests)
      has_rate_limit = Enum.any?(results, &(&1 == 429))
      has_normal_errors = Enum.any?(results, &(&1 in [400, 401, 403]))

      assert has_normal_errors, "Expected normal error responses before rate limit"
      assert has_rate_limit, "Expected 429 after exceeding rate limit"
    end
  end

  describe "E2E: Sealed vault denies secret operations" do
    test "secret operations fail when vault is sealed" do
      # Get a valid token while vault is unsealed
      %{token: token} =
        create_agent_with_token(%{
          "version" => "1.0",
          "allowed_secrets" => ["secret/data/seal-test/*"],
          "allowed_operations" => ["create", "read"]
        })

      # Seal the vault
      build_conn() |> post("/v1/sys/seal", %{})

      # Try to create a secret while sealed
      conn = create_secret(token, "seal-test/locked", %{"val" => "should-fail"})

      # Should fail — either 503 (service unavailable) or 500
      assert conn.status in [401, 403, 500, 503]
    end
  end
end
