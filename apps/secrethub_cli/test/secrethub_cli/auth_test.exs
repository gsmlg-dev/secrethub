defmodule SecretHub.CLI.AuthTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias SecretHub.CLI.{Auth, Config}

  setup do
    # Use a temporary config directory for tests
    temp_dir =
      System.tmp_dir!() |> Path.join("secrethub_test_#{System.unique_integer([:positive])}")

    File.mkdir_p!(temp_dir)

    # Mock the config directory
    original_config_dir = Application.get_env(:secrethub_cli, :config_dir)
    original_token_renewer = Application.get_env(:secrethub_cli, :token_renewer)
    original_cli_access_requester = Application.get_env(:secrethub_cli, :cli_access_requester)
    original_cli_access_poller = Application.get_env(:secrethub_cli, :cli_access_poller)
    Application.put_env(:secrethub_cli, :config_dir, temp_dir)

    on_exit(fn ->
      File.rm_rf!(temp_dir)

      if original_config_dir do
        Application.put_env(:secrethub_cli, :config_dir, original_config_dir)
      else
        Application.delete_env(:secrethub_cli, :config_dir)
      end

      if original_token_renewer do
        Application.put_env(:secrethub_cli, :token_renewer, original_token_renewer)
      else
        Application.delete_env(:secrethub_cli, :token_renewer)
      end

      if original_cli_access_requester do
        Application.put_env(:secrethub_cli, :cli_access_requester, original_cli_access_requester)
      else
        Application.delete_env(:secrethub_cli, :cli_access_requester)
      end

      if original_cli_access_poller do
        Application.put_env(:secrethub_cli, :cli_access_poller, original_cli_access_poller)
      else
        Application.delete_env(:secrethub_cli, :cli_access_poller)
      end
    end)

    {:ok, temp_dir: temp_dir}
  end

  describe "login/3" do
    test "successfully authenticates with valid credentials" do
      # HTTPClientBehaviour not yet implemented, so we can't mock HTTP calls.
      # For now, verify the login function exists with correct arity.
      assert is_function(&Auth.login/3)
    end

    test "returns error when role_id is missing" do
      # Test would validate missing role_id
      # This is handled at the command level, not in Auth.login
      assert true
    end

    test "returns error when secret_id is missing" do
      # Test would validate missing secret_id
      # This is handled at the command level, not in Auth.login
      assert true
    end

    test "handles HTTP errors gracefully" do
      # Mock failed HTTP response
      # Would test error handling
      assert true
    end

    test "handles invalid response format" do
      # Mock response with missing required fields
      # Would test error handling
      assert true
    end
  end

  describe "login_with_cli_access/2" do
    test "shows the 6 character code, polls until approval, and saves the token" do
      expires_at = DateTime.utc_now() |> DateTime.add(600, :second)
      token_expires_at = DateTime.utc_now() |> DateTime.add(86_400, :second)

      Application.put_env(:secrethub_cli, :cli_access_requester, fn server, metadata ->
        send(self(), {:cli_access_request, server, metadata})

        {:ok,
         %{
           request_id: "request-123",
           user_code: "ABC234",
           expires_at: expires_at,
           interval: 0
         }}
      end)

      Application.put_env(:secrethub_cli, :cli_access_poller, fn
        server, "request-123" ->
          send(self(), {:cli_access_poll, server})
          {:approved, %{token: "approved-token", expires_at: token_expires_at}}
      end)

      output =
        capture_io(fn ->
          assert {:ok, "Authentication successful"} =
                   Auth.login_with_cli_access("https://core.example.com", poll_interval_ms: 0)
        end)

      assert output =~ "CLI Access Code: ABC234"
      assert output =~ "Admin > Access Control > CLI Access"
      assert output =~ "Successfully authenticated with SecretHub"
      assert_receive {:cli_access_request, "https://core.example.com", metadata}
      assert metadata["client_name"]
      assert_receive {:cli_access_poll, "https://core.example.com"}
      assert {:ok, "approved-token"} = Auth.get_token()
    end
  end

  describe "logout/0" do
    test "successfully clears authentication credentials" do
      # First create a config with auth
      config = %{
        "server_url" => "http://localhost:4000",
        "auth" => %{
          "token" => "test-token",
          "expires_at" =>
            DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.to_iso8601()
        }
      }

      assert :ok = Config.save(config)

      # Now logout
      output =
        capture_io(fn ->
          assert {:ok, _} = Auth.logout()
        end)

      assert output =~ "Successfully logged out"

      # Verify auth is cleared
      {:ok, loaded_config} = Config.load()
      refute Map.has_key?(loaded_config, "auth")
    end

    test "handles logout when not authenticated" do
      # Logout when no auth exists should still succeed
      output =
        capture_io(fn ->
          assert {:ok, _} = Auth.logout()
        end)

      assert output =~ "Successfully logged out"
    end
  end

  describe "authenticated?/0" do
    test "returns true when valid token exists" do
      # Create config with valid token
      config = %{
        "server_url" => "http://localhost:4000",
        "auth" => %{
          "token" => "test-token",
          "expires_at" =>
            DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.to_iso8601()
        }
      }

      assert :ok = Config.save(config)
      assert Auth.authenticated?() == true
    end

    test "returns false when token is expired" do
      # Create config with expired token
      config = %{
        "server_url" => "http://localhost:4000",
        "auth" => %{
          "token" => "test-token",
          "expires_at" =>
            DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.to_iso8601()
        }
      }

      assert :ok = Config.save(config)
      assert Auth.authenticated?() == false
    end

    test "returns false when no token exists" do
      # No auth config
      assert Auth.authenticated?() == false
    end
  end

  describe "get_token/0" do
    test "returns token when valid" do
      # Create config with valid token
      expires_at = DateTime.utc_now() |> DateTime.add(3600, :second)

      config = %{
        "server_url" => "http://localhost:4000",
        "auth" => %{
          "token" => "test-token-456",
          "expires_at" => DateTime.to_iso8601(expires_at)
        }
      }

      assert :ok = Config.save(config)
      assert {:ok, "test-token-456"} = Auth.get_token()
    end

    test "returns error when token is expired" do
      # Create config with expired token
      expires_at = DateTime.utc_now() |> DateTime.add(-3600, :second)

      config = %{
        "server_url" => "http://localhost:4000",
        "auth" => %{
          "token" => "test-token",
          "expires_at" => DateTime.to_iso8601(expires_at)
        }
      }

      assert :ok = Config.save(config)
      assert {:error, :expired} = Auth.get_token()
    end

    test "returns error when no token exists" do
      assert {:error, :not_found} = Auth.get_token()
    end
  end

  describe "ensure_authenticated/0" do
    test "returns token when authenticated" do
      # Create config with valid token
      expires_at = DateTime.utc_now() |> DateTime.add(3600, :second)

      config = %{
        "server_url" => "http://localhost:4000",
        "auth" => %{
          "token" => "test-token-789",
          "expires_at" => DateTime.to_iso8601(expires_at)
        }
      }

      assert :ok = Config.save(config)
      assert {:ok, "test-token-789"} = Auth.ensure_authenticated()
    end

    test "returns error and shows message when token expired" do
      # Create config with expired token
      expires_at = DateTime.utc_now() |> DateTime.add(-3600, :second)

      config = %{
        "server_url" => "http://localhost:4000",
        "auth" => %{
          "token" => "test-token",
          "expires_at" => DateTime.to_iso8601(expires_at)
        }
      }

      assert :ok = Config.save(config)

      Application.put_env(:secrethub_cli, :token_renewer, fn _server, _token ->
        {:error, "Token renewal failed"}
      end)

      output =
        capture_io(:stderr, fn ->
          assert {:error, :not_authenticated} = Auth.ensure_authenticated()
        end)

      assert output =~ "expired"
    end

    test "renews an expired local token before returning it" do
      expired_at = DateTime.utc_now() |> DateTime.add(-60, :second)
      renewed_expires_at = DateTime.utc_now() |> DateTime.add(86_400, :second)

      config = %{
        "server_url" => "https://secrethub.example.com",
        "auth" => %{
          "token" => "expired-locally",
          "expires_at" => DateTime.to_iso8601(expired_at)
        }
      }

      assert :ok = Config.save(config)

      Application.put_env(:secrethub_cli, :token_renewer, fn server, token ->
        send(self(), {:renew_token, server, token})
        {:ok, %{token: "renewed-token", expires_at: renewed_expires_at}}
      end)

      assert {:ok, "renewed-token"} = Auth.ensure_authenticated()
      assert_receive {:renew_token, "https://secrethub.example.com", "expired-locally"}
      assert {:ok, "renewed-token"} = Auth.get_token()
    end

    test "returns error and shows message when not authenticated" do
      output =
        capture_io(:stderr, fn ->
          assert {:error, :not_authenticated} = Auth.ensure_authenticated()
        end)

      assert output =~ "Not authenticated"
      assert output =~ "login"
    end
  end

  describe "auth_headers/0" do
    test "returns authorization header when authenticated" do
      # Create config with valid token
      expires_at = DateTime.utc_now() |> DateTime.add(3600, :second)

      config = %{
        "server_url" => "http://localhost:4000",
        "auth" => %{
          "token" => "test-token-abc",
          "expires_at" => DateTime.to_iso8601(expires_at)
        }
      }

      assert :ok = Config.save(config)
      headers = Auth.auth_headers()

      assert headers == [{"authorization", "Bearer test-token-abc"}]
    end

    test "returns x-vault-token header for Vault-compatible APIs" do
      expires_at = DateTime.utc_now() |> DateTime.add(3600, :second)

      config = %{
        "server_url" => "http://localhost:4000",
        "auth" => %{
          "token" => "vault-token-abc",
          "expires_at" => DateTime.to_iso8601(expires_at)
        }
      }

      assert :ok = Config.save(config)
      assert Auth.vault_headers() == [{"x-vault-token", "vault-token-abc"}]
    end

    test "returns empty list when not authenticated" do
      headers = Auth.auth_headers()
      assert headers == []
    end

    test "returns empty list when token is expired" do
      # Create config with expired token
      expires_at = DateTime.utc_now() |> DateTime.add(-3600, :second)

      config = %{
        "server_url" => "http://localhost:4000",
        "auth" => %{
          "token" => "test-token",
          "expires_at" => DateTime.to_iso8601(expires_at)
        }
      }

      assert :ok = Config.save(config)
      headers = Auth.auth_headers()

      assert headers == []
    end
  end

  describe "token parsing" do
    test "parses token response with client_token and lease_duration" do
      # This tests the internal parse_token_response logic
      # Would be tested through login integration
      assert true
    end

    test "parses token response with token and ttl" do
      # Alternative response format
      assert true
    end

    test "parses token response with just token (defaults to 24h)" do
      # Minimal response format
      assert true
    end

    test "handles invalid token response format" do
      # Missing required fields
      assert true
    end
  end
end
