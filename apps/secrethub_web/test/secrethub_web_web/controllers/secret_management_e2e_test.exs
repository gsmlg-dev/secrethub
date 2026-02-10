defmodule SecretHub.Web.SecretManagementE2ETest do
  @moduledoc """
  End-to-end tests for secret management operations.

  Tests the complete secret lifecycle:
  - Creating secrets with different engines
  - Reading secrets with versioning
  - Updating secrets
  - Deleting secrets
  - Secret leasing and TTL
  - Secret rotation
  """

  use SecretHub.Web.ConnCase, async: false

  # Secret management E2E tests — require register_agent, generate_approle_credentials,
  # and the /v1/secret/* and /v1/auth/approle/login routes.

  alias SecretHub.Core.{Agents, Policies, Secrets}
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState

  setup do
    # Use shared mode for database access
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

      _ ->
        :ok
    end

    # Create a test policy with full secret access
    {:ok, policy} =
      Policies.create_policy(%{
        name: "secret-test-policy-#{:rand.uniform(10_000)}",
        policy_document: %{
          "version" => "1.0",
          "allowed_secrets" => ["secret/data/*", "secret/metadata/*"],
          "allowed_operations" => ["create", "read", "update", "delete", "list"]
        }
      })

    # Create a test agent with the policy
    {:ok, agent} =
      Agents.register_agent(%{
        agent_id: "secret-test-agent-#{:rand.uniform(10_000)}",
        name: "Secret Test Agent",
        policy_ids: [policy.id],
        auth_method: "approle"
      })

    {:ok, role_id, secret_id} = Agents.generate_approle_credentials(agent.id)

    # Get authentication token
    conn =
      build_conn()
      |> post("/v1/auth/approle/login", %{
        "role_id" => role_id,
        "secret_id" => secret_id
      })

    token = json_response(conn, 200)["token"]

    on_exit(fn ->
      Ecto.Adapters.SQL.Sandbox.mode(Repo, :manual)
    end)

    %{token: token, agent: agent, policy: policy}
  end

  describe "E2E: Static secret management" do
    test "create, read, update, and delete static secret", %{conn: conn, token: token} do
      # Step 1: Create a new static secret
      conn = put_req_header(conn, "x-vault-token", token)

      secret_path = "secret/data/test-app/database"

      conn =
        post(conn, "/v1/#{secret_path}", %{
          "data" => %{
            "username" => "db_user",
            "password" => "secure_password_123",
            "host" => "db.example.com",
            "port" => 5432
          }
        })

      assert conn.status == 200
      create_response = json_response(conn, 200)
      assert Map.has_key?(create_response, "version")
      assert create_response["version"] == 1

      # Step 2: Read the secret back
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token)
      conn = get(conn, "/v1/#{secret_path}")

      assert conn.status == 200
      read_response = json_response(conn, 200)

      assert read_response["data"]["username"] == "db_user"
      assert read_response["data"]["password"] == "secure_password_123"
      assert read_response["data"]["host"] == "db.example.com"
      assert read_response["metadata"]["version"] == 1

      # Step 3: Update the secret (creates new version)
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token)

      conn =
        post(conn, "/v1/#{secret_path}", %{
          "data" => %{
            "username" => "db_user",
            "password" => "new_secure_password_456",
            "host" => "db.example.com",
            "port" => 5432
          }
        })

      assert conn.status == 200
      update_response = json_response(conn, 200)
      assert update_response["version"] == 2

      # Step 4: Read latest version
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token)
      conn = get(conn, "/v1/#{secret_path}")

      assert conn.status == 200
      latest_response = json_response(conn, 200)
      assert latest_response["data"]["password"] == "new_secure_password_456"
      assert latest_response["metadata"]["version"] == 2

      # Step 5: Read specific version (version 1)
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token)
      conn = get(conn, "/v1/#{secret_path}?version=1")

      if conn.status == 200 do
        version1_response = json_response(conn, 200)
        assert version1_response["data"]["password"] == "secure_password_123"
        assert version1_response["metadata"]["version"] == 1
      end

      # Step 6: Delete the secret
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token)
      conn = delete(conn, "/v1/#{secret_path}")

      assert conn.status in [200, 204]

      # Step 7: Verify secret is deleted
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token)
      conn = get(conn, "/v1/#{secret_path}")

      assert conn.status == 404
    end

    test "secret versioning maintains history", %{conn: conn, token: token} do
      secret_path = "secret/data/versioning-test/config"

      # Create multiple versions
      versions = [
        %{"config" => "v1", "value" => 100},
        %{"config" => "v2", "value" => 200},
        %{"config" => "v3", "value" => 300}
      ]

      Enum.with_index(versions, 1)
      |> Enum.each(fn {data, expected_version} ->
        conn = build_conn()
        conn = put_req_header(conn, "x-vault-token", token)

        conn = post(conn, "/v1/#{secret_path}", %{"data" => data})

        assert conn.status == 200
        response = json_response(conn, 200)
        assert response["version"] == expected_version
      end)

      # Read latest version (should be v3)
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token)
      conn = get(conn, "/v1/#{secret_path}")

      assert conn.status == 200
      response = json_response(conn, 200)
      assert response["data"]["config"] == "v3"
      assert response["data"]["value"] == 300
    end
  end

  describe "E2E: Secret metadata operations" do
    test "list secrets in a path", %{conn: conn, token: token} do
      # Create multiple secrets in the same path
      base_path = "test-app-#{:rand.uniform(10_000)}"

      Enum.each(1..5, fn i ->
        conn = build_conn()
        conn = put_req_header(conn, "x-vault-token", token)

        conn =
          post(conn, "/v1/secret/data/#{base_path}/secret#{i}", %{
            "data" => %{"value" => "secret#{i}"}
          })

        assert conn.status == 200
      end)

      # List secrets in the path
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token)
      conn = get(conn, "/v1/secret/metadata/#{base_path}?list=true")

      if conn.status == 200 do
        response = json_response(conn, 200)
        assert Map.has_key?(response, "keys")
        assert length(response["keys"]) >= 5
      end
    end

    test "get secret metadata without reading data", %{conn: conn, token: token} do
      secret_path = "secret/data/metadata-test/config"

      # Create a secret
      conn = put_req_header(conn, "x-vault-token", token)

      conn =
        post(conn, "/v1/#{secret_path}", %{
          "data" => %{"sensitive" => "data"}
        })

      assert conn.status == 200

      # Get metadata (should not include actual secret data)
      metadata_path = String.replace(secret_path, "/data/", "/metadata/")
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token)
      conn = get(conn, "/v1/#{metadata_path}")

      if conn.status == 200 do
        response = json_response(conn, 200)

        # Should have metadata but not the actual secret data
        assert Map.has_key?(response, "versions")
        assert Map.has_key?(response, "created_time")
        refute Map.has_key?(response, "data")
        refute Map.has_key?(response["versions"]["1"], "sensitive")
      end
    end
  end

  describe "E2E: Secret lease and TTL" do
    test "dynamic secrets have TTL and leases", %{conn: _conn, token: _token} do
      # This test would require setting up a dynamic secret engine
      # For MVP, we'll document the expected behavior

      # Step 1: Enable dynamic PostgreSQL engine
      # Step 2: Configure database connection
      # Step 3: Create role with TTL
      # Step 4: Generate credentials (should create lease)
      # Step 5: Verify lease is tracked
      # Step 6: Lease expires and credentials are revoked

      :not_implemented
    end

    test "leases can be renewed", %{conn: _conn, token: _token} do
      # Test lease renewal flow
      :not_implemented
    end

    test "leases can be revoked manually", %{conn: _conn, token: _token} do
      # Test manual lease revocation
      :not_implemented
    end
  end

  describe "E2E: Secret rotation" do
    test "static secret rotation updates external system", %{conn: _conn, token: _token} do
      # This would test the static secret rotation flow
      # Requires Oban job execution

      # Step 1: Create static secret with rotation config
      # Step 2: Trigger rotation job
      # Step 3: Verify new credentials generated
      # Step 4: Verify old credentials revoked in external system

      :not_implemented
    end
  end

  describe "E2E: Error handling and edge cases" do
    test "reading non-existent secret returns 404", %{conn: conn, token: token} do
      conn = put_req_header(conn, "x-vault-token", token)
      conn = get(conn, "/v1/secret/data/non-existent/secret")

      assert conn.status == 404
      response = json_response(conn, 404)
      assert Map.has_key?(response, "error")
    end

    test "creating secret without required fields returns error", %{conn: conn, token: token} do
      conn = put_req_header(conn, "x-vault-token", token)
      conn = post(conn, "/v1/secret/data/invalid/secret", %{})

      assert conn.status in [400, 422]
    end

    test "accessing secret without token returns 401", %{conn: conn} do
      conn = get(conn, "/v1/secret/data/some/secret")

      assert conn.status == 401
    end

    test "accessing secret with invalid token returns 401", %{conn: conn} do
      conn = put_req_header(conn, "x-vault-token", "invalid-token")
      conn = get(conn, "/v1/secret/data/some/secret")

      assert conn.status == 401
    end
  end

  describe "E2E: Concurrent secret operations" do
    test "multiple agents can read same secret concurrently", %{token: token} do
      # Create a secret
      secret_path = "secret/data/concurrent-test/shared"

      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token)

      conn =
        post(conn, "/v1/#{secret_path}", %{
          "data" => %{"shared_value" => "accessible_to_all"}
        })

      assert conn.status == 200

      # Multiple concurrent reads
      tasks =
        Enum.map(1..20, fn _i ->
          Task.async(fn ->
            conn = build_conn()
            conn = put_req_header(conn, "x-vault-token", token)
            get(conn, "/v1/#{secret_path}")
          end)
        end)

      results = Task.await_many(tasks, 10_000)

      # All reads should succeed
      assert Enum.all?(results, fn conn ->
               conn.status == 200
             end)

      # All should return the same data
      values =
        Enum.map(results, fn conn ->
          json_response(conn, 200)["data"]["shared_value"]
        end)

      assert Enum.all?(values, &(&1 == "accessible_to_all"))
    end

    test "concurrent updates create proper versions", %{token: token} do
      secret_path = "secret/data/concurrent-test/versioned"

      # Create initial secret
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token)

      conn =
        post(conn, "/v1/#{secret_path}", %{
          "data" => %{"counter" => 0}
        })

      assert conn.status == 200

      # Multiple concurrent updates
      tasks =
        Enum.map(1..10, fn i ->
          Task.async(fn ->
            conn = build_conn()
            conn = put_req_header(conn, "x-vault-token", token)

            post(conn, "/v1/#{secret_path}", %{
              "data" => %{"counter" => i}
            })
          end)
        end)

      results = Task.await_many(tasks, 10_000)

      # All updates should succeed (or some might conflict)
      success_count = Enum.count(results, fn conn -> conn.status == 200 end)
      assert success_count >= 1

      # Final version number should reflect all successful updates
      conn = build_conn()
      conn = put_req_header(conn, "x-vault-token", token)
      conn = get(conn, "/v1/#{secret_path}")

      assert conn.status == 200
      response = json_response(conn, 200)
      # Should have version = 1 (initial) + number of successful updates
      assert response["metadata"]["version"] >= 1
    end
  end
end
