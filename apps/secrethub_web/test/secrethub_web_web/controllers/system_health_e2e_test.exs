defmodule SecretHub.Web.SystemHealthE2ETest do
  @moduledoc """
  End-to-end tests for system health, readiness, and liveness endpoints.

  Tests Kubernetes-style probe endpoints and system status reporting.
  """

  use SecretHub.Web.ConnCase, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Shamir

  @moduletag :e2e

  setup do
    Sandbox.mode(Repo, {:shared, self()})
    {:ok, _pid} = start_supervised(SealState)
    Process.sleep(100)

    on_exit(fn -> Sandbox.mode(Repo, :manual) end)
    :ok
  end

  describe "E2E: Health check endpoints" do
    test "health endpoint returns structured response", %{conn: conn} do
      conn = get(conn, "/v1/sys/health")

      response = Jason.decode!(conn.resp_body)
      assert Map.has_key?(response, "initialized")
      assert Map.has_key?(response, "sealed")
      assert is_boolean(response["initialized"])
      assert is_boolean(response["sealed"])
    end

    test "health endpoint reflects seal state transitions" do
      # Check initial state
      conn = build_conn() |> get("/v1/sys/health")
      _initial = Jason.decode!(conn.resp_body)

      # Initialize if needed
      case SealState.status() do
        %{initialized: false} ->
          {:ok, shares} = SealState.initialize(3, 2)

          # Health should show initialized=true, sealed=true
          conn = build_conn() |> get("/v1/sys/health")
          after_init = Jason.decode!(conn.resp_body)
          assert after_init["initialized"] == true
          assert after_init["sealed"] == true

          # Unseal
          shares |> Enum.take(2) |> Enum.each(&SealState.unseal/1)

          # Health should show sealed=false
          conn = build_conn() |> get("/v1/sys/health")
          after_unseal = Jason.decode!(conn.resp_body)
          assert after_unseal["initialized"] == true
          assert after_unseal["sealed"] == false

        _ ->
          :ok
      end
    end

    test "liveness probe always returns 200", %{conn: conn} do
      conn = get(conn, "/v1/sys/health/live")
      assert conn.status == 200
    end

    test "readiness probe reflects system state", %{conn: conn} do
      conn = get(conn, "/v1/sys/health/ready")
      # Should be 200 if unsealed and healthy, 503 otherwise
      assert conn.status in [200, 503]

      response = Jason.decode!(conn.resp_body)
      assert Map.has_key?(response, "ready") or Map.has_key?(response, "status")
    end
  end

  describe "E2E: Seal status endpoint" do
    test "seal-status returns complete state information", %{conn: conn} do
      conn = get(conn, "/v1/sys/seal-status")

      assert conn.status == 200
      status = json_response(conn, 200)

      assert Map.has_key?(status, "initialized")
      assert Map.has_key?(status, "sealed")
      assert Map.has_key?(status, "progress")
      assert is_integer(status["progress"])
    end

    test "seal and unseal cycle preserves state correctly" do
      # Initialize
      case SealState.status() do
        %{initialized: false} ->
          {:ok, shares} = SealState.initialize(3, 2)
          shares |> Enum.take(2) |> Enum.each(&SealState.unseal/1)

          # Verify unsealed
          conn = build_conn() |> get("/v1/sys/seal-status")
          assert json_response(conn, 200)["sealed"] == false

          # Seal
          build_conn() |> post("/v1/sys/seal", %{})

          # Verify sealed
          conn = build_conn() |> get("/v1/sys/seal-status")
          status = json_response(conn, 200)
          assert status["sealed"] == true
          assert status["progress"] == 0

          # Unseal again with different shares (encode for API)
          shares
          |> Enum.drop(1)
          |> Enum.take(2)
          |> Enum.each(fn share ->
            encoded = Shamir.encode_share(share)
            build_conn() |> post("/v1/sys/unseal", %{"share" => encoded})
          end)

          # Verify unsealed again
          conn = build_conn() |> get("/v1/sys/seal-status")
          assert json_response(conn, 200)["sealed"] == false

        _ ->
          :ok
      end
    end
  end
end
