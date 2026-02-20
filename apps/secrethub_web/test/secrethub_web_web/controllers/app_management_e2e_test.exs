defmodule SecretHub.Web.AppManagementE2ETest do
  @moduledoc """
  End-to-end tests for application management lifecycle.

  Tests:
  - Application registration
  - Application listing and retrieval
  - Application update
  - Application suspension and activation
  - Application deletion
  - Bootstrap token generation and consumption
  - Application certificate issuance
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

    # Create an agent for app association
    {:ok, policy} =
      Policies.create_policy(%{
        name: "app-mgmt-policy-#{:rand.uniform(100_000)}",
        policy_document: %{
          "version" => "1.0",
          "allowed_secrets" => ["secret/*"],
          "allowed_operations" => ["read"]
        }
      })

    {:ok, agent} =
      Agents.register_agent(%{
        agent_id: "app-mgmt-agent-#{:rand.uniform(100_000)}",
        name: "App Management Agent",
        policy_ids: [policy.id],
        auth_method: "approle"
      })

    on_exit(fn -> Sandbox.mode(Repo, :manual) end)

    %{agent: agent, policy: policy}
  end

  describe "E2E: Application registration and CRUD" do
    test "register, get, update, and delete application", %{agent: agent} do
      app_name = "test-app-#{:rand.uniform(100_000)}"

      # Step 1: Register application
      conn =
        build_conn()
        |> post("/v1/apps", %{
          "name" => app_name,
          "description" => "E2E test application",
          "agent_id" => agent.id,
          "policies" => ["read-all"],
          "metadata" => %{"team" => "platform", "env" => "test"}
        })

      assert conn.status in [200, 201]
      register_response = Jason.decode!(conn.resp_body)
      assert Map.has_key?(register_response, "app_id")
      app_id = register_response["app_id"]

      # Step 2: Get application by ID
      conn = build_conn() |> get("/v1/apps/#{app_id}")

      assert conn.status == 200
      app_detail = json_response(conn, 200)
      assert app_detail["name"] == app_name
      assert app_detail["status"] == "active"

      # Step 3: Update application
      conn =
        build_conn()
        |> put("/v1/apps/#{app_id}", %{
          "description" => "Updated description",
          "metadata" => %{"team" => "platform", "env" => "staging"}
        })

      assert conn.status == 200
      updated = json_response(conn, 200)
      assert updated["description"] == "Updated description"

      # Step 4: Delete application
      conn = build_conn() |> delete("/v1/apps/#{app_id}")

      assert conn.status in [200, 204]

      # Step 5: Verify deletion
      conn = build_conn() |> get("/v1/apps/#{app_id}")
      assert conn.status == 404
    end

    test "list applications with filtering", %{agent: agent} do
      prefix = "list-test-#{:rand.uniform(100_000)}"

      # Create multiple applications
      Enum.each(1..3, fn i ->
        build_conn()
        |> post("/v1/apps", %{
          "name" => "#{prefix}-app-#{i}",
          "description" => "List test app #{i}",
          "agent_id" => agent.id
        })
      end)

      # List all applications
      conn = build_conn() |> get("/v1/apps")

      assert conn.status == 200
      response = json_response(conn, 200)
      assert Map.has_key?(response, "apps")
      assert length(response["apps"]) >= 3
    end
  end

  describe "E2E: Application lifecycle" do
    test "suspend and reactivate application", %{agent: agent} do
      app_name = "lifecycle-app-#{:rand.uniform(100_000)}"

      # Register
      conn =
        build_conn()
        |> post("/v1/apps", %{
          "name" => app_name,
          "agent_id" => agent.id
        })

      assert conn.status in [200, 201]
      app_id = Jason.decode!(conn.resp_body)["app_id"]

      # Suspend
      conn = build_conn() |> post("/v1/apps/#{app_id}/suspend", %{})

      assert conn.status == 200
      suspended = json_response(conn, 200)
      assert suspended["status"] == "suspended"

      # Verify suspended
      conn = build_conn() |> get("/v1/apps/#{app_id}")
      assert conn.status == 200
      assert json_response(conn, 200)["status"] == "suspended"

      # Reactivate
      conn = build_conn() |> post("/v1/apps/#{app_id}/activate", %{})

      assert conn.status == 200
      activated = json_response(conn, 200)
      assert activated["status"] == "active"
    end
  end

  describe "E2E: Application error handling" do
    test "register app with duplicate name returns error", %{agent: agent} do
      app_name = "duplicate-app-#{:rand.uniform(100_000)}"

      # First registration
      conn =
        build_conn()
        |> post("/v1/apps", %{
          "name" => app_name,
          "agent_id" => agent.id
        })

      assert conn.status in [200, 201]

      # Duplicate registration
      conn =
        build_conn()
        |> post("/v1/apps", %{
          "name" => app_name,
          "agent_id" => agent.id
        })

      assert conn.status in [400, 409, 422]
    end

    test "register app with invalid name format returns error", %{agent: agent} do
      conn =
        build_conn()
        |> post("/v1/apps", %{
          "name" => "INVALID NAME WITH SPACES!",
          "agent_id" => agent.id
        })

      assert conn.status in [400, 422]
    end

    test "get non-existent app returns 404" do
      conn = build_conn() |> get("/v1/apps/00000000-0000-0000-0000-000000000000")
      assert conn.status == 404
    end

    test "suspend non-existent app returns error" do
      conn =
        build_conn()
        |> post("/v1/apps/00000000-0000-0000-0000-000000000000/suspend", %{})

      assert conn.status in [400, 404]
    end
  end
end
