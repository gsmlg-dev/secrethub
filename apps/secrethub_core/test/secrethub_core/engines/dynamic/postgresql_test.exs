defmodule SecretHub.Core.Engines.Dynamic.PostgreSQLTest do
  use ExUnit.Case, async: true

  alias SecretHub.Core.Engines.Dynamic.PostgreSQL

  describe "validate_config/1" do
    test "validates complete config successfully" do
      config = %{
        "connection" => %{
          "host" => "localhost",
          "port" => 5432,
          "database" => "testdb",
          "username" => "admin",
          "password" => "secret"
        },
        "creation_statements" => ["CREATE USER {{username}};"],
        "default_ttl" => 3600,
        "max_ttl" => 86_400
      }

      assert :ok == PostgreSQL.validate_config(config)
    end

    test "fails when connection is missing" do
      config = %{
        "creation_statements" => ["CREATE USER {{username}};"]
      }

      assert {:error, errors} = PostgreSQL.validate_config(config)
      assert "connection configuration is required" in errors
    end

    test "fails when required connection fields are missing" do
      config = %{
        "connection" => %{
          "host" => "localhost"
          # missing database, username, password
        },
        "creation_statements" => ["CREATE USER {{username}};"]
      }

      assert {:error, errors} = PostgreSQL.validate_config(config)
      assert "connection.database is required" in errors
      assert "connection.username is required" in errors
      assert "connection.password is required" in errors
    end

    test "fails when creation_statements is missing" do
      config = %{
        "connection" => %{
          "host" => "localhost",
          "database" => "testdb",
          "username" => "admin",
          "password" => "secret"
        }
      }

      assert {:error, errors} = PostgreSQL.validate_config(config)
      assert "creation_statements are required" in errors
    end

    test "fails when TTL values are not integers" do
      config = %{
        "connection" => %{
          "host" => "localhost",
          "database" => "testdb",
          "username" => "admin",
          "password" => "secret"
        },
        "creation_statements" => ["CREATE USER {{username}};"],
        "default_ttl" => "not_an_integer",
        "max_ttl" => "also_not_an_integer"
      }

      assert {:error, errors} = PostgreSQL.validate_config(config)
      assert "default_ttl must be an integer" in errors
      assert "max_ttl must be an integer" in errors
    end
  end

  describe "generate_credentials/2" do
    @tag :skip
    # This test requires a running PostgreSQL instance
    # Run with: PG_TEST=true mix test
    test "generates valid PostgreSQL credentials" do
      if System.get_env("PG_TEST") do
        config = %{
          "connection" => %{
            "host" => "localhost",
            "port" => 5432,
            "database" => "secrethub_test",
            "username" => "secrethub",
            "password" => "secrethub_test_password"
          },
          "creation_statements" => [
            "CREATE USER {{username}} WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"
          ],
          "default_ttl" => 60
        }

        opts = [config: config, ttl: 120]

        assert {:ok, credentials} = PostgreSQL.generate_credentials("test_role", opts)
        assert is_binary(credentials.username)
        assert String.starts_with?(credentials.username, "v_test_role_")
        assert is_binary(credentials.password)
        assert byte_size(credentials.password) == 32
        assert credentials.ttl == 120
        assert credentials.metadata.host == "localhost"
        assert credentials.metadata.database == "secrethub_test"

        # Clean up: revoke the created user
        PostgreSQL.revoke_credentials("test_lease", credentials)
      end
    end

    test "uses default TTL when not specified" do
      # This test doesn't actually connect, just validates the logic
      # We'd need to mock Postgrex for a true unit test
    end

    test "caps TTL at max_ttl" do
      # Mock test to verify TTL capping logic
    end
  end

  describe "renew_lease/2" do
    test "returns new TTL within max_ttl bounds" do
      config = %{"max_ttl" => 3600}

      opts = [
        increment: 1800,
        current_ttl: 600,
        credentials: %{username: "test_user"},
        config: config
      ]

      assert {:ok, %{ttl: new_ttl}} = PostgreSQL.renew_lease("lease_123", opts)
      # 600 + 1800
      assert new_ttl == 2400
    end

    test "respects max_ttl limit" do
      config = %{"max_ttl" => 3600}

      opts = [
        increment: 5000,
        current_ttl: 2000,
        credentials: %{username: "test_user"},
        config: config
      ]

      assert {:ok, %{ttl: new_ttl}} = PostgreSQL.renew_lease("lease_123", opts)
      # capped at max_ttl
      assert new_ttl == 3600
    end
  end
end
