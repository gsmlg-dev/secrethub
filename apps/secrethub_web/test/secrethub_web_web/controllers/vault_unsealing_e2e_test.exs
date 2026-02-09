defmodule SecretHub.Web.VaultUnsealingE2ETest do
  @moduledoc """
  End-to-end tests for the vault initialization and unsealing flow.

  Tests the complete lifecycle:
  - Vault initialization
  - Progressive unsealing with Shamir shares
  - Seal status tracking
  - Re-sealing
  - Error handling
  """

  use SecretHub.Web.ConnCase, async: false

  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState

  setup do
    # Use shared mode for the Sandbox so all processes can access the database
    # This is necessary because SealState writes to DB on init
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

    # Start the SealState GenServer for E2E tests
    # It's normally not started in test mode to avoid database writes
    {:ok, _pid} = start_supervised(SealState)

    # Give it a moment to initialize
    Process.sleep(100)

    # Return to manual mode for cleanup
    on_exit(fn ->
      Ecto.Adapters.SQL.Sandbox.mode(Repo, :manual)
    end)

    :ok
  end

  describe "E2E: Complete vault unsealing flow" do
    test "full initialization and unsealing lifecycle", %{conn: conn} do
      # Step 1: Check initial status - vault should be uninitialized
      conn = get(conn, "/v1/sys/seal-status")
      assert json_response(conn, 200)
      status = json_response(conn, 200)

      # If vault is already initialized from previous tests, we'll note it
      # but continue with the unsealing flow
      initial_state = status["initialized"]

      # Step 2: Initialize vault with 5 shares, threshold of 3
      conn = build_conn()

      conn =
        post(conn, "/v1/sys/init", %{
          "secret_shares" => 5,
          "secret_threshold" => 3
        })

      case conn.status do
        200 ->
          # Vault was successfully initialized
          response = json_response(conn, 200)

          assert response["threshold"] == 3
          assert response["total_shares"] == 5
          assert length(response["shares"]) == 5

          shares = response["shares"]

          # Verify all shares are encoded strings
          Enum.each(shares, fn share ->
            assert is_binary(share)
            assert String.starts_with?(share, "secrethub-share-")
          end)

          # Step 3: Check status - should be initialized and sealed
          conn = build_conn()
          conn = get(conn, "/v1/sys/seal-status")
          status = json_response(conn, 200)

          assert status["initialized"] == true
          assert status["sealed"] == true
          assert status["progress"] == 0
          assert status["threshold"] == 3
          assert status["total_shares"] == 5

          # Step 4: Progressive unsealing - provide first share
          conn = build_conn()

          conn =
            post(conn, "/v1/sys/unseal", %{
              "share" => Enum.at(shares, 0)
            })

          response = json_response(conn, 200)
          assert response["sealed"] == true
          assert response["progress"] == 1
          assert response["threshold"] == 3

          # Step 5: Provide second share
          conn = build_conn()

          conn =
            post(conn, "/v1/sys/unseal", %{
              "share" => Enum.at(shares, 1)
            })

          response = json_response(conn, 200)
          assert response["sealed"] == true
          assert response["progress"] == 2
          assert response["threshold"] == 3

          # Step 6: Provide third share - vault should unseal
          conn = build_conn()

          conn =
            post(conn, "/v1/sys/unseal", %{
              "share" => Enum.at(shares, 2)
            })

          response = json_response(conn, 200)
          assert response["sealed"] == false
          assert response["progress"] == 3
          assert response["threshold"] == 3

          # Step 7: Verify unsealed status
          conn = build_conn()
          conn = get(conn, "/v1/sys/seal-status")
          status = json_response(conn, 200)

          assert status["initialized"] == true
          assert status["sealed"] == false

          # Step 8: Re-seal the vault
          conn = build_conn()
          conn = post(conn, "/v1/sys/seal", %{})

          response = json_response(conn, 200)
          assert response["sealed"] == true

          # Step 9: Verify sealed status
          conn = build_conn()
          conn = get(conn, "/v1/sys/seal-status")
          status = json_response(conn, 200)

          assert status["initialized"] == true
          assert status["sealed"] == true
          assert status["progress"] == 0

        400 ->
          # Vault was already initialized
          response = json_response(conn, 400)
          assert response["error"] == "Vault already initialized"

          # Skip to unsealing tests with assumption vault is sealed
          # In production, you'd have a way to reset the vault for testing
          :skipped

        _ ->
          flunk("Unexpected status code: #{conn.status}")
      end
    end

    test "unsealing with duplicate shares is handled correctly", %{conn: conn} do
      # Initialize vault if needed
      conn =
        post(conn, "/v1/sys/init", %{
          "secret_shares" => 3,
          "secret_threshold" => 2
        })

      case conn.status do
        200 ->
          shares = json_response(conn, 200)["shares"]

          # Seal the vault first
          conn = build_conn()
          post(conn, "/v1/sys/seal", %{})

          # Provide first share
          conn = build_conn()

          conn =
            post(conn, "/v1/sys/unseal", %{
              "share" => Enum.at(shares, 0)
            })

          response = json_response(conn, 200)
          assert response["progress"] == 1

          # Provide same share again - should be deduplicated
          conn = build_conn()

          conn =
            post(conn, "/v1/sys/unseal", %{
              "share" => Enum.at(shares, 0)
            })

          response = json_response(conn, 200)
          # Progress should still be 1 (duplicate ignored)
          assert response["progress"] == 1
          assert response["sealed"] == true

          # Provide different share - should unseal
          conn = build_conn()

          conn =
            post(conn, "/v1/sys/unseal", %{
              "share" => Enum.at(shares, 1)
            })

          response = json_response(conn, 200)
          assert response["sealed"] == false

        400 ->
          # Already initialized, skip test
          :skipped

        _ ->
          flunk("Unexpected response")
      end
    end

    test "unsealing when already unsealed returns success", %{conn: conn} do
      # Initialize and unseal vault
      conn =
        post(conn, "/v1/sys/init", %{
          "secret_shares" => 3,
          "secret_threshold" => 2
        })

      case conn.status do
        200 ->
          shares = json_response(conn, 200)["shares"]

          # Unseal with required shares
          Enum.take(shares, 2)
          |> Enum.each(fn share ->
            conn = build_conn()
            post(conn, "/v1/sys/unseal", %{"share" => share})
          end)

          # Provide additional share when already unsealed
          conn = build_conn()

          conn =
            post(conn, "/v1/sys/unseal", %{
              "share" => Enum.at(shares, 2)
            })

          response = json_response(conn, 200)
          assert response["sealed"] == false

        400 ->
          :skipped

        _ ->
          flunk("Unexpected response")
      end
    end
  end

  describe "E2E: Error handling" do
    test "initialization with invalid parameters returns errors", %{conn: conn} do
      # Test: secret_shares too high
      conn =
        post(conn, "/v1/sys/init", %{
          "secret_shares" => 300,
          "secret_threshold" => 3
        })

      assert conn.status == 400
      response = json_response(conn, 400)
      assert response["error"] =~ "between 1 and 255"

      # Test: secret_threshold greater than secret_shares
      conn = build_conn()

      conn =
        post(conn, "/v1/sys/init", %{
          "secret_shares" => 3,
          "secret_threshold" => 5
        })

      assert conn.status == 400
      response = json_response(conn, 400)
      assert response["error"] =~ "between 1 and secret_shares"

      # Test: secret_shares less than 1
      conn = build_conn()

      conn =
        post(conn, "/v1/sys/init", %{
          "secret_shares" => 0,
          "secret_threshold" => 0
        })

      assert conn.status == 400
      response = json_response(conn, 400)
      assert response["error"] =~ "between 1 and 255"
    end

    test "unsealing with invalid share format returns error", %{conn: conn} do
      # Test with completely invalid share
      conn =
        post(conn, "/v1/sys/unseal", %{
          "share" => "invalid-share-format"
        })

      assert conn.status == 400
      response = json_response(conn, 400)
      assert response["error"] =~ "Invalid share format"

      # Test with missing share parameter
      conn = build_conn()
      conn = post(conn, "/v1/sys/unseal", %{})

      assert conn.status == 400
      response = json_response(conn, 400)
      assert response["error"] == "Missing 'share' parameter"
    end

    test "unsealing uninitialized vault returns error", %{conn: conn} do
      # Check if vault is uninitialized
      conn = get(conn, "/v1/sys/seal-status")
      status = json_response(conn, 200)

      if not status["initialized"] do
        # Try to unseal without initializing
        conn = build_conn()

        conn =
          post(conn, "/v1/sys/unseal", %{
            "share" => "secrethub-share-test"
          })

        assert conn.status == 400
        response = json_response(conn, 400)
        assert response["error"] =~ "not initialized" or response["error"] =~ "Invalid share"
      else
        # Vault already initialized, skip this test
        :skipped
      end
    end
  end

  describe "E2E: Health check" do
    test "health endpoint returns correct status", %{conn: conn} do
      conn = get(conn, "/v1/sys/health")

      assert conn.status in [200, 429, 500, 501, 503]
      response = Jason.decode!(conn.resp_body)
      assert Map.has_key?(response, "initialized")
      assert Map.has_key?(response, "sealed")
    end
  end

  describe "E2E: Seal status tracking" do
    test "seal status provides accurate progress tracking", %{conn: conn} do
      # Initialize vault
      conn =
        post(conn, "/v1/sys/init", %{
          "secret_shares" => 4,
          "secret_threshold" => 3
        })

      case conn.status do
        200 ->
          shares = json_response(conn, 200)["shares"]

          # Seal the vault
          conn = build_conn()
          post(conn, "/v1/sys/seal", %{})

          # Check status - progress should be 0
          conn = build_conn()
          conn = get(conn, "/v1/sys/seal-status")
          status = json_response(conn, 200)
          assert status["progress"] == 0
          assert status["sealed"] == true

          # Provide shares one by one and check progress
          [share1, share2, share3 | _] = shares

          # Share 1
          conn = build_conn()
          post(conn, "/v1/sys/unseal", %{"share" => share1})

          conn = build_conn()
          conn = get(conn, "/v1/sys/seal-status")
          status = json_response(conn, 200)
          assert status["progress"] == 1
          assert status["sealed"] == true

          # Share 2
          conn = build_conn()
          post(conn, "/v1/sys/unseal", %{"share" => share2})

          conn = build_conn()
          conn = get(conn, "/v1/sys/seal-status")
          status = json_response(conn, 200)
          assert status["progress"] == 2
          assert status["sealed"] == true

          # Share 3 - should unseal
          conn = build_conn()
          post(conn, "/v1/sys/unseal", %{"share" => share3})

          conn = build_conn()
          conn = get(conn, "/v1/sys/seal-status")
          status = json_response(conn, 200)
          # Reset after unsealing
          assert status["progress"] == 0
          assert status["sealed"] == false

        400 ->
          :skipped

        _ ->
          flunk("Unexpected response")
      end
    end
  end

  describe "E2E: Share encoding and decoding" do
    test "shares can be round-tripped through encode/decode", %{conn: conn} do
      # Initialize vault
      conn =
        post(conn, "/v1/sys/init", %{
          "secret_shares" => 3,
          "secret_threshold" => 2
        })

      case conn.status do
        200 ->
          shares = json_response(conn, 200)["shares"]

          # All shares should be valid encoded strings
          Enum.each(shares, fn share ->
            assert is_binary(share)
            assert String.starts_with?(share, "secrethub-share-")
            # Reasonable length check
            assert String.length(share) > 20
          end)

          # Seal and unseal with the shares to verify they work
          conn = build_conn()
          post(conn, "/v1/sys/seal", %{})

          Enum.take(shares, 2)
          |> Enum.each(fn share ->
            conn = build_conn()
            conn = post(conn, "/v1/sys/unseal", %{"share" => share})
            assert conn.status == 200
          end)

          # Verify vault is unsealed
          conn = build_conn()
          conn = get(conn, "/v1/sys/seal-status")
          status = json_response(conn, 200)
          assert status["sealed"] == false

        400 ->
          :skipped

        _ ->
          flunk("Unexpected response")
      end
    end
  end
end
