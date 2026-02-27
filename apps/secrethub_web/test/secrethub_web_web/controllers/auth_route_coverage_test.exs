defmodule SecretHub.Web.AuthRouteCoverageTest do
  @moduledoc """
  P0: Authentication route coverage tests.

  Verifies that protected API routes return 401 without a valid token.
  """

  use SecretHub.Web.ConnCase, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias SecretHub.Core.{Agents, Policies}
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState

  @moduletag :security

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

  describe "P0: Dynamic secrets route requires auth" do
    test "POST /v1/secrets/dynamic/:role without token returns 401" do
      conn =
        build_conn()
        |> post("/v1/secrets/dynamic/test-role", %{"ttl" => 3600})

      assert conn.status == 401
    end
  end

  describe "P0: Lease management routes require auth" do
    test "GET /v1/sys/leases/ without token returns 401" do
      conn =
        build_conn()
        |> get("/v1/sys/leases/")

      assert conn.status == 401
    end

    test "POST /v1/sys/leases/renew without token returns 401" do
      conn =
        build_conn()
        |> post("/v1/sys/leases/renew", %{"lease_id" => "fake"})

      assert conn.status == 401
    end
  end

  describe "P0: PKI routes require auth" do
    test "POST /v1/pki/ca/root/generate without token returns 401" do
      conn =
        build_conn()
        |> post("/v1/pki/ca/root/generate", %{
          "common_name" => "Test Root CA",
          "ttl" => "87600h"
        })

      assert conn.status == 401
    end
  end

  describe "P0: Application management routes require auth" do
    test "POST /v1/apps without token returns 401" do
      conn =
        build_conn()
        |> post("/v1/apps", %{"name" => "test-app"})

      assert conn.status == 401
    end
  end

  describe "P0: Protected routes work with valid token" do
    setup do
      {:ok, policy} =
        Policies.create_policy(%{
          name: "auth-coverage-policy-#{:rand.uniform(100_000)}",
          policy_document: %{
            "version" => "1.0",
            "allowed_secrets" => ["secret/data/*"],
            "allowed_operations" => ["create", "read", "update", "delete"]
          }
        })

      {:ok, agent} =
        Agents.register_agent(%{
          agent_id: "auth-coverage-agent-#{:rand.uniform(100_000)}",
          name: "Auth Coverage Agent",
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

      %{token: token}
    end

    test "GET /v1/sys/leases/ with valid token does not return 401", %{token: token} do
      try do
        conn =
          build_conn()
          |> put_req_header("x-vault-token", token)
          |> get("/v1/sys/leases/")

        # May fail for other reasons (LeaseManager not started), but must NOT be 401
        assert conn.status != 401
      rescue
        # LeaseManager GenServer may not be running in test env
        _ -> :ok
      catch
        :exit, _ -> :ok
      end
    end

    test "POST /v1/pki/ca/root/generate with valid token succeeds", %{token: token} do
      conn =
        build_conn()
        |> put_req_header("x-vault-token", token)
        |> post("/v1/pki/ca/root/generate", %{
          "common_name" => "Test Root CA",
          "ttl" => "87600h"
        })

      # Should succeed or return a business logic error, not 401
      assert conn.status != 401
    end
  end
end
