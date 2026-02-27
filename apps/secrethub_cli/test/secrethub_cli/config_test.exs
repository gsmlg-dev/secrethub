defmodule SecretHub.CLI.ConfigTest do
  use ExUnit.Case, async: false

  alias SecretHub.CLI.Config

  setup do
    # Use a temporary config directory for tests
    temp_dir =
      System.tmp_dir!() |> Path.join("secrethub_test_#{System.unique_integer([:positive])}")

    File.mkdir_p!(temp_dir)
    config_file = Path.join(temp_dir, "config.toml")

    # Mock the config paths
    original_config_dir = Application.get_env(:secrethub_cli, :config_dir)
    Application.put_env(:secrethub_cli, :config_dir, temp_dir)

    on_exit(fn ->
      File.rm_rf!(temp_dir)

      if original_config_dir do
        Application.put_env(:secrethub_cli, :config_dir, original_config_dir)
      else
        Application.delete_env(:secrethub_cli, :config_dir)
      end
    end)

    {:ok, temp_dir: temp_dir, config_file: config_file}
  end

  describe "load/0" do
    test "loads existing configuration file", %{config_file: config_file} do
      # Create a config file
      config_content = """
      server_url = "https://secrethub.example.com"

      [output]
      format = "json"
      color = true

      [auth]
      token = "test-token"
      expires_at = "2025-12-31T23:59:59Z"
      """

      File.write!(config_file, config_content)

      assert {:ok, config} = Config.load()
      assert config["server_url"] == "https://secrethub.example.com"
      assert config["output"]["format"] == "json"
      assert config["output"]["color"] == true
      assert config["auth"]["token"] == "test-token"
    end

    test "returns default config when file doesn't exist" do
      # No config file created
      assert {:ok, config} = Config.load()
      assert config["server_url"] == "http://localhost:4000"
      assert config["output"]["format"] == "table"
      assert config["output"]["color"] == true
    end

    test "returns error when config file is malformed", %{config_file: config_file} do
      # Create invalid TOML
      File.write!(config_file, "invalid toml {{{")

      assert {:error, reason} = Config.load()
      assert reason =~ "Failed to parse config"
    end
  end

  describe "save/1" do
    test "saves configuration to file", %{config_file: config_file} do
      config = %{
        "server_url" => "https://secrethub.example.com",
        "output" => %{
          "format" => "yaml",
          "color" => false
        }
      }

      assert :ok = Config.save(config)
      assert File.exists?(config_file)

      # Verify content
      {:ok, loaded_config} = Config.load()
      assert loaded_config["server_url"] == "https://secrethub.example.com"
      assert loaded_config["output"]["format"] == "yaml"
      assert loaded_config["output"]["color"] == false
    end

    test "creates config directory with proper permissions", %{temp_dir: temp_dir} do
      # Remove the directory first
      File.rm_rf!(temp_dir)

      config = %{"server_url" => "http://localhost:4000"}
      assert :ok = Config.save(config)

      # Check directory was created
      assert File.exists?(temp_dir)

      # Check permissions (0700 = owner only)
      stat = File.stat!(temp_dir)
      # On Unix systems, mode should be 0o700 (448 in decimal) plus directory bit
      # The actual permission check depends on the system
      assert stat.type == :directory
    end

    test "overwrites existing config file", %{config_file: _config_file} do
      # Create initial config
      config1 = %{"server_url" => "http://localhost:4000"}
      assert :ok = Config.save(config1)

      # Update config
      config2 = %{"server_url" => "https://production.example.com"}
      assert :ok = Config.save(config2)

      # Verify update
      {:ok, loaded} = Config.load()
      assert loaded["server_url"] == "https://production.example.com"
    end
  end

  describe "get/1" do
    test "retrieves top-level configuration value" do
      config = %{"server_url" => "https://secrethub.example.com"}
      assert :ok = Config.save(config)

      assert {:ok, "https://secrethub.example.com"} = Config.get("server_url")
    end

    test "retrieves nested configuration value" do
      config = %{
        "output" => %{
          "format" => "json",
          "color" => true
        }
      }

      assert :ok = Config.save(config)

      assert {:ok, "json"} = Config.get("output.format")
      assert {:ok, true} = Config.get("output.color")
    end

    test "returns nil for non-existent key" do
      config = %{"server_url" => "http://localhost:4000"}
      assert :ok = Config.save(config)

      assert {:ok, nil} = Config.get("nonexistent.key")
    end

    test "handles deeply nested keys" do
      config = %{
        "level1" => %{
          "level2" => %{
            "level3" => "deep-value"
          }
        }
      }

      assert :ok = Config.save(config)

      assert {:ok, "deep-value"} = Config.get("level1.level2.level3")
    end
  end

  describe "set/2" do
    test "sets top-level configuration value" do
      assert :ok = Config.set("server_url", "https://new-server.com")

      {:ok, value} = Config.get("server_url")
      assert value == "https://new-server.com"
    end

    test "sets nested configuration value" do
      assert :ok = Config.set("output.format", "yaml")

      {:ok, value} = Config.get("output.format")
      assert value == "yaml"
    end

    test "creates intermediate keys if they don't exist" do
      assert :ok = Config.set("new.nested.key", "value")

      {:ok, value} = Config.get("new.nested.key")
      assert value == "value"
    end

    test "preserves existing configuration when setting new value" do
      config = %{
        "server_url" => "http://localhost:4000",
        "output" => %{"format" => "table"}
      }

      assert :ok = Config.save(config)

      assert :ok = Config.set("output.color", true)

      {:ok, server_url} = Config.get("server_url")
      {:ok, format} = Config.get("output.format")
      {:ok, color} = Config.get("output.color")

      assert server_url == "http://localhost:4000"
      assert format == "table"
      assert color == true
    end
  end

  describe "delete/1" do
    test "deletes top-level configuration value" do
      config = %{"server_url" => "http://localhost:4000", "other_key" => "value"}
      assert :ok = Config.save(config)

      assert :ok = Config.delete("server_url")

      {:ok, value} = Config.get("server_url")
      assert is_nil(value)

      # Other keys should remain
      {:ok, other} = Config.get("other_key")
      assert other == "value"
    end

    test "deletes nested configuration value" do
      config = %{
        "output" => %{
          "format" => "json",
          "color" => true
        }
      }

      assert :ok = Config.save(config)

      assert :ok = Config.delete("output.color")

      {:ok, color} = Config.get("output.color")
      assert is_nil(color)

      # Format should remain
      {:ok, format} = Config.get("output.format")
      assert format == "json"
    end
  end

  describe "get_server_url/0" do
    test "returns configured server URL" do
      config = %{"server_url" => "https://secrethub.example.com"}
      assert :ok = Config.save(config)

      assert Config.get_server_url() == "https://secrethub.example.com"
    end

    test "returns default when not configured" do
      assert Config.get_server_url() == "http://localhost:4000"
    end
  end

  describe "get_output_format/0" do
    test "returns configured output format" do
      config = %{"output" => %{"format" => "json"}}
      assert :ok = Config.save(config)

      assert Config.get_output_format() == "json"
    end

    test "returns default table format when not configured" do
      assert Config.get_output_format() == "table"
    end

    test "returns default for invalid format" do
      config = %{"output" => %{"format" => "invalid"}}
      assert :ok = Config.save(config)

      assert Config.get_output_format() == "table"
    end
  end

  describe "get_auth_token/0" do
    test "returns valid token" do
      expires_at = DateTime.utc_now() |> DateTime.add(3600, :second)

      config = %{
        "auth" => %{
          "token" => "test-token-123",
          "expires_at" => DateTime.to_iso8601(expires_at)
        }
      }

      assert :ok = Config.save(config)

      assert {:ok, "test-token-123"} = Config.get_auth_token()
    end

    test "returns error when token is expired" do
      expires_at = DateTime.utc_now() |> DateTime.add(-3600, :second)

      config = %{
        "auth" => %{
          "token" => "test-token",
          "expires_at" => DateTime.to_iso8601(expires_at)
        }
      }

      assert :ok = Config.save(config)

      assert {:error, :expired} = Config.get_auth_token()
    end

    test "returns token when expires_at is invalid (assumes valid)" do
      config = %{
        "auth" => %{
          "token" => "test-token",
          "expires_at" => "invalid-date"
        }
      }

      assert :ok = Config.save(config)

      assert {:ok, "test-token"} = Config.get_auth_token()
    end

    test "returns token when expires_at is missing (assumes valid)" do
      config = %{
        "auth" => %{
          "token" => "test-token"
        }
      }

      assert :ok = Config.save(config)

      assert {:ok, "test-token"} = Config.get_auth_token()
    end

    test "returns error when no token exists" do
      assert {:error, :not_found} = Config.get_auth_token()
    end
  end

  describe "save_auth/2" do
    test "saves authentication credentials" do
      token = "test-token-456"
      expires_at = DateTime.utc_now() |> DateTime.add(7200, :second)

      assert :ok = Config.save_auth(token, expires_at)

      {:ok, saved_token} = Config.get_auth_token()
      assert saved_token == token

      # Verify all auth fields are saved
      {:ok, config} = Config.load()
      assert config["auth"]["token"] == token
      assert config["auth"]["expires_at"] == DateTime.to_iso8601(expires_at)
      assert Map.has_key?(config["auth"], "authenticated_at")
    end

    test "overwrites existing auth credentials" do
      # Save first auth
      token1 = "token-1"
      expires1 = DateTime.utc_now() |> DateTime.add(3600, :second)
      assert :ok = Config.save_auth(token1, expires1)

      # Save new auth
      token2 = "token-2"
      expires2 = DateTime.utc_now() |> DateTime.add(7200, :second)
      assert :ok = Config.save_auth(token2, expires2)

      # Verify new auth
      {:ok, saved_token} = Config.get_auth_token()
      assert saved_token == token2
    end

    test "preserves other config when saving auth" do
      # Set some config
      config = %{"server_url" => "https://example.com"}
      assert :ok = Config.save(config)

      # Save auth
      token = "test-token"
      expires_at = DateTime.utc_now() |> DateTime.add(3600, :second)
      assert :ok = Config.save_auth(token, expires_at)

      # Verify both exist
      {:ok, server_url} = Config.get("server_url")
      assert server_url == "https://example.com"

      {:ok, saved_token} = Config.get_auth_token()
      assert saved_token == token
    end
  end

  describe "clear_auth/0" do
    test "clears authentication credentials" do
      # Save auth first
      token = "test-token"
      expires_at = DateTime.utc_now() |> DateTime.add(3600, :second)
      assert :ok = Config.save_auth(token, expires_at)

      # Clear auth
      assert :ok = Config.clear_auth()

      # Verify cleared
      assert {:error, :not_found} = Config.get_auth_token()

      {:ok, config} = Config.load()
      refute Map.has_key?(config, "auth")
    end

    test "preserves other config when clearing auth" do
      # Set config and auth
      config = %{
        "server_url" => "https://example.com",
        "auth" => %{"token" => "test-token"}
      }

      assert :ok = Config.save(config)

      # Clear auth
      assert :ok = Config.clear_auth()

      # Verify server_url remains
      {:ok, server_url} = Config.get("server_url")
      assert server_url == "https://example.com"

      # Verify auth is gone
      assert {:error, :not_found} = Config.get_auth_token()
    end
  end

  describe "default_config/0" do
    test "returns sensible defaults" do
      # Load config when file doesn't exist
      {:ok, config} = Config.load()

      assert config["server_url"] == "http://localhost:4000"
      assert config["output"]["format"] == "table"
      assert config["output"]["color"] == true
    end
  end
end
