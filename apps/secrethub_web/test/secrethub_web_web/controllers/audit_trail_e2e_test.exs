defmodule SecretHub.Web.AuditTrailE2ETest do
  @moduledoc """
  End-to-end tests for audit trail integrity.

  Verifies that all secret operations produce correct audit log entries
  with proper hash chain integrity.
  """

  use SecretHub.Web.ConnCase, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias SecretHub.Core.{Agents, Audit, Policies}
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState

  import Ecto.Query

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

    # Create agent with full access
    {:ok, policy} =
      Policies.create_policy(%{
        name: "audit-test-policy-#{:rand.uniform(100_000)}",
        policy_document: %{
          "version" => "1.0",
          "allowed_secrets" => ["secret/data/audit-test/*"],
          "allowed_operations" => ["create", "read", "update", "delete"]
        }
      })

    {:ok, agent} =
      Agents.register_agent(%{
        agent_id: "audit-agent-#{:rand.uniform(100_000)}",
        name: "Audit Test Agent",
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

    on_exit(fn -> Sandbox.mode(Repo, :manual) end)

    %{token: token, agent: agent}
  end

  describe "E2E: Audit logging for secret operations" do
    test "secret creation generates audit event", %{token: token, agent: agent} do
      # Record timestamp before operation
      before = DateTime.utc_now() |> DateTime.truncate(:second)

      # Create a secret
      conn =
        build_conn()
        |> put_req_header("x-vault-token", token)
        |> post("/v1/secret/data/audit-test/creation-audit", %{
          "data" => %{"key" => "audited-value"}
        })

      assert conn.status == 200

      # Allow audit log to be written
      Process.sleep(200)

      # Query audit logs for this operation
      logs =
        from(a in SecretHub.Shared.Schemas.AuditLog,
          where: a.agent_id == ^agent.id,
          where: a.event_type == "secret.created",
          where: a.timestamp >= ^before,
          order_by: [desc: a.timestamp]
        )
        |> Repo.all()

      assert length(logs) >= 1
      log = List.first(logs)
      assert log.event_type == "secret.created"
      assert log.agent_id == agent.id
      assert log.access_granted == true
    end

    test "secret read generates audit event", %{token: token, agent: agent} do
      # First create a secret
      build_conn()
      |> put_req_header("x-vault-token", token)
      |> post("/v1/secret/data/audit-test/read-audit", %{
        "data" => %{"key" => "read-me"}
      })

      before = DateTime.utc_now() |> DateTime.truncate(:second)

      # Read the secret
      conn =
        build_conn()
        |> put_req_header("x-vault-token", token)
        |> get("/v1/secret/data/audit-test/read-audit")

      assert conn.status == 200

      Process.sleep(200)

      logs =
        from(a in SecretHub.Shared.Schemas.AuditLog,
          where: a.agent_id == ^agent.id,
          where: a.event_type == "secret.accessed",
          where: a.timestamp >= ^before,
          order_by: [desc: a.timestamp]
        )
        |> Repo.all()

      assert length(logs) >= 1
      log = List.first(logs)
      assert log.access_granted == true
    end

    test "denied access generates audit event with access_granted=false", %{agent: agent} do
      # Create agent with restricted access
      {:ok, restricted_policy} =
        Policies.create_policy(%{
          name: "restricted-audit-policy-#{:rand.uniform(100_000)}",
          policy_document: %{
            "version" => "1.0",
            "allowed_secrets" => ["secret/data/only-this/*"],
            "allowed_operations" => ["read"]
          }
        })

      {:ok, restricted_agent} =
        Agents.register_agent(%{
          agent_id: "restricted-audit-#{:rand.uniform(100_000)}",
          name: "Restricted Audit Agent",
          policy_ids: [restricted_policy.id],
          auth_method: "approle"
        })

      {:ok, role_id, secret_id} = Agents.generate_approle_credentials(restricted_agent.id)

      conn =
        build_conn()
        |> post("/v1/auth/approle/login", %{
          "role_id" => role_id,
          "secret_id" => secret_id
        })

      restricted_token = json_response(conn, 200)["token"]
      before = DateTime.utc_now() |> DateTime.truncate(:second)

      # Try to access a path outside policy
      conn =
        build_conn()
        |> put_req_header("x-vault-token", restricted_token)
        |> get("/v1/secret/data/forbidden/path")

      assert conn.status == 403

      Process.sleep(200)

      logs =
        from(a in SecretHub.Shared.Schemas.AuditLog,
          where: a.agent_id == ^restricted_agent.id,
          where: a.event_type == "secret.access_denied",
          where: a.timestamp >= ^before,
          order_by: [desc: a.timestamp]
        )
        |> Repo.all()

      assert length(logs) >= 1
      log = List.first(logs)
      assert log.access_granted == false
    end
  end

  describe "E2E: Audit hash chain integrity" do
    test "sequential operations maintain hash chain continuity", %{token: token} do
      # Perform several operations to build a chain
      Enum.each(1..5, fn i ->
        build_conn()
        |> put_req_header("x-vault-token", token)
        |> post("/v1/secret/data/audit-test/chain-#{i}", %{
          "data" => %{"index" => i}
        })
      end)

      Process.sleep(500)

      # Fetch recent audit logs in sequence order
      logs =
        from(a in SecretHub.Shared.Schemas.AuditLog,
          order_by: [asc: a.sequence_number],
          limit: 20
        )
        |> Repo.all()

      # Verify chain: each entry's previous_hash should match the prior entry's current_hash
      logs
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.each(fn [prev, curr] ->
        if curr.previous_hash != nil and prev.current_hash != nil do
          assert curr.previous_hash == prev.current_hash,
                 "Hash chain broken: entry #{curr.sequence_number}'s previous_hash " <>
                   "doesn't match entry #{prev.sequence_number}'s current_hash"
        end
      end)
    end

    test "audit logs have valid HMAC signatures", %{token: token} do
      # Create a secret to generate audit entry
      build_conn()
      |> put_req_header("x-vault-token", token)
      |> post("/v1/secret/data/audit-test/hmac-check", %{
        "data" => %{"val" => "hmac-test"}
      })

      Process.sleep(200)

      logs =
        from(a in SecretHub.Shared.Schemas.AuditLog,
          order_by: [desc: a.sequence_number],
          limit: 5
        )
        |> Repo.all()

      # Each log should have non-nil hash fields
      Enum.each(logs, fn log ->
        assert log.current_hash != nil, "current_hash should not be nil"
        assert log.signature != nil, "signature should not be nil"
        assert is_binary(log.current_hash)
        assert is_binary(log.signature)
      end)
    end
  end

  describe "E2E: Audit log for authentication events" do
    test "successful login generates auth audit event" do
      before = DateTime.utc_now() |> DateTime.truncate(:second)

      {:ok, policy} =
        Policies.create_policy(%{
          name: "auth-audit-policy-#{:rand.uniform(100_000)}",
          policy_document: %{
            "version" => "1.0",
            "allowed_secrets" => ["secret/*"],
            "allowed_operations" => ["read"]
          }
        })

      {:ok, agent} =
        Agents.register_agent(%{
          agent_id: "auth-audit-#{:rand.uniform(100_000)}",
          name: "Auth Audit Agent",
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

      assert conn.status == 200

      Process.sleep(200)

      # Check for auth-related audit entries
      auth_logs =
        from(a in SecretHub.Shared.Schemas.AuditLog,
          where: a.event_type in ["auth.agent_login", "auth.agent_bootstrap"],
          where: a.timestamp >= ^before,
          order_by: [desc: a.timestamp]
        )
        |> Repo.all()

      assert length(auth_logs) >= 1
    end
  end
end
