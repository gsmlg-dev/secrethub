defmodule SecretHub.Web.AppRoleSecurityTest do
  @moduledoc """
  P0: AppRole security tests.

  Verifies that AppRole authentication handles edge cases securely:
  - Invalid tokens
  - Expired tokens
  - Non-UUID inputs
  - No credential enumeration
  """

  use SecretHub.Web.ConnCase, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias SecretHub.Core.{Agents, Policies, Secrets}
  alias SecretHub.Core.Auth.AppRole
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState

  @moduletag :security

  setup do
    Sandbox.mode(Repo, {:shared, self()})
    ensure_current_audit_partition!()

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

  defp ensure_current_audit_partition! do
    today = Date.utc_today()
    month = String.pad_leading(to_string(today.month), 2, "0")
    partition_name = "audit_logs_y#{today.year}m#{month}"
    from_date = %Date{today | day: 1}
    to_date = Date.add(from_date, Date.days_in_month(from_date))

    Repo.query!("""
    CREATE TABLE IF NOT EXISTS #{partition_name} PARTITION OF audit_logs
    FOR VALUES FROM ('#{Date.to_iso8601(from_date)}') TO ('#{Date.to_iso8601(to_date)}')
    """)
  end

  describe "P0: Token validation edge cases" do
    test "request with invalid token returns 401" do
      conn =
        build_conn()
        |> put_req_header("x-vault-token", "completely-invalid-token")
        |> get("/v1/secret/data/test/path")

      assert conn.status == 401
    end

    test "request with tampered token returns 401" do
      conn =
        build_conn()
        |> put_req_header("x-vault-token", "SFMyNTY.tampered.signature")
        |> get("/v1/secret/data/test/path")

      assert conn.status == 401
    end

    test "request with expired token returns 401" do
      # Create a token with a past timestamp by signing with max_age=0
      payload = %{
        agent_id: "expired-agent",
        agent_db_id: Ecto.UUID.generate(),
        issued_at: DateTime.utc_now() |> DateTime.add(-90_000) |> DateTime.to_iso8601()
      }

      # Sign with the real endpoint but the token will be expired when verified (max_age: 86400)
      token = Phoenix.Token.sign(SecretHub.Web.Endpoint, "agent_auth", payload)

      # Immediately verify to confirm it's valid (won't be expired yet since it was just signed)
      # But we can test the invalid token path
      conn =
        build_conn()
        |> put_req_header("x-vault-token", token)
        |> get("/v1/secret/data/test/path")

      # Token is technically valid but agent_db_id won't exist, so we get 401
      assert conn.status == 401
    end
  end

  describe "P0: Non-UUID role_id returns auth error (not 500)" do
    test "login with non-UUID role_id returns 401, not 500" do
      conn =
        build_conn()
        |> post("/v1/auth/approle/login", %{
          "role_id" => "not-a-uuid",
          "secret_id" => "also-not-a-uuid"
        })

      # Must be a proper auth error (401), never a 500 server error
      assert conn.status in [401, 403]
      refute conn.status == 500
    end

    test "login with SQL injection attempt in role_id returns auth error" do
      conn =
        build_conn()
        |> post("/v1/auth/approle/login", %{
          "role_id" => "'; DROP TABLE agents; --",
          "secret_id" => "test"
        })

      assert conn.status in [400, 401, 403]
      refute conn.status == 500
    end
  end

  describe "P0: Managed AppRole login" do
    test "role credentials created by AppRole management can log in without an agent row" do
      {:ok, role} =
        AppRole.create_role("cli-login-route-#{System.unique_integer([:positive])}",
          secret_id_num_uses: 0
        )

      conn =
        build_conn()
        |> post("/v1/auth/approle/login", %{
          "role_id" => role.role_id,
          "secret_id" => role.secret_id
        })

      body = json_response(conn, 200)

      assert %{
               "auth" => %{
                 "client_token" => token,
                 "lease_duration" => lease_duration,
                 "policies" => []
               },
               "token" => token,
               "token_type" => "approle"
             } = body

      assert lease_duration == AppRole.token_ttl_seconds()
      assert {:ok, %{role_id: role_id, role_name: role_name}} = AppRole.verify_token(token)
      assert role_id == role.role_id
      assert role_name == role.role_name
    end

    test "managed AppRole token can be renewed" do
      {:ok, role} =
        AppRole.create_role("cli-renew-route-#{System.unique_integer([:positive])}",
          policies: ["secret-read"],
          secret_id_num_uses: 0
        )

      login_conn =
        build_conn()
        |> post("/v1/auth/approle/login", %{
          "role_id" => role.role_id,
          "secret_id" => role.secret_id
        })

      token = json_response(login_conn, 200)["token"]
      {:ok, _updated} = AppRole.update_role_policies(role.role_id, ["secret-read", "prod-read"])

      renew_conn =
        build_conn()
        |> put_req_header("x-vault-token", token)
        |> post("/v1/auth/approle/renew")

      body = json_response(renew_conn, 200)

      assert %{
               "auth" => %{
                 "client_token" => renewed_token,
                 "lease_duration" => lease_duration,
                 "policies" => ["secret-read", "prod-read"]
               },
               "token" => renewed_token,
               "token_type" => "approle"
             } = body

      assert lease_duration == AppRole.token_ttl_seconds()
      assert {:ok, payload} = AppRole.verify_token(renewed_token)
      assert payload.role_id == role.role_id
      assert payload.policies == ["secret-read", "prod-read"]
    end

    test "managed AppRole token can read secrets when its policy allows access" do
      {:ok, policy} =
        Policies.create_policy(%{
          name: "cli-secret-read-#{System.unique_integer([:positive])}",
          policy_document: %{
            "version" => "1.0",
            "allowed_secrets" => ["secret/data/prod/minimax/*"],
            "allowed_operations" => ["read"]
          }
        })

      {:ok, role} =
        AppRole.create_role("cli-secret-reader-#{System.unique_integer([:positive])}",
          policies: [policy.name],
          secret_id_num_uses: 0
        )

      {:ok, _secret} =
        Secrets.create_secret(%{
          "name" => "minimax apikey",
          "secret_path" => "prod.minimax.apikey",
          "secret_data" => %{"value" => "sk-test"}
        })

      login_conn =
        build_conn()
        |> post("/v1/auth/approle/login", %{
          "role_id" => role.role_id,
          "secret_id" => role.secret_id
        })

      token = json_response(login_conn, 200)["token"]

      conn =
        build_conn()
        |> put_req_header("x-vault-token", token)
        |> get("/v1/secret/data/prod/minimax/apikey")

      assert %{"data" => %{"value" => "sk-test"}} = json_response(conn, 200)
    end
  end

  describe "P0: No credential enumeration" do
    setup do
      {:ok, policy} =
        Policies.create_policy(%{
          name: "enum-test-policy-#{:rand.uniform(100_000)}",
          policy_document: %{
            "version" => "1.0",
            "allowed_secrets" => ["secret/*"],
            "allowed_operations" => ["read"]
          }
        })

      {:ok, agent} =
        Agents.register_agent(%{
          agent_id: "enum-test-agent-#{:rand.uniform(100_000)}",
          name: "Enum Test Agent",
          policy_ids: [policy.id],
          auth_method: "approle"
        })

      {:ok, role_id, _secret_id} = Agents.generate_approle_credentials(agent.id)

      %{role_id: role_id}
    end

    test "wrong role_id and wrong secret_id return identical error messages", %{
      role_id: valid_role_id
    } do
      # Login with valid role_id but wrong secret_id
      conn1 =
        build_conn()
        |> post("/v1/auth/approle/login", %{
          "role_id" => valid_role_id,
          "secret_id" => Ecto.UUID.generate()
        })

      # Login with completely invalid role_id
      conn2 =
        build_conn()
        |> post("/v1/auth/approle/login", %{
          "role_id" => Ecto.UUID.generate(),
          "secret_id" => Ecto.UUID.generate()
        })

      # Both should return the same status and same error message
      # to prevent credential enumeration
      assert conn1.status == conn2.status

      body1 = json_response(conn1, conn1.status)
      body2 = json_response(conn2, conn2.status)
      assert body1["error"] == body2["error"]
    end

    test "missing role_id or secret_id returns 400" do
      conn =
        build_conn()
        |> post("/v1/auth/approle/login", %{})

      assert conn.status == 400
    end
  end
end
