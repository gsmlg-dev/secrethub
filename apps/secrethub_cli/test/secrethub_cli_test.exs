defmodule SecretHub.CLITest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias SecretHub.CLI

  describe "main/1 - help and version" do
    test "shows help when no arguments provided" do
      output = capture_io(fn ->
        catch_exit(CLI.main([]))
      end)

      assert output =~ "SecretHub CLI"
      assert output =~ "USAGE:"
      assert output =~ "COMMANDS:"
    end

    test "shows help with --help flag" do
      output = capture_io(fn ->
        catch_exit(CLI.main(["--help"]))
      end)

      assert output =~ "SecretHub CLI"
      assert output =~ "USAGE:"
    end

    test "shows help with help command" do
      output = capture_io(fn ->
        catch_exit(CLI.main(["help"]))
      end)

      assert output =~ "SecretHub CLI"
    end

    test "shows version with --version flag" do
      output = capture_io(fn ->
        catch_exit(CLI.main(["--version"]))
      end)

      assert output =~ "SecretHub CLI v0.1.0"
    end

    test "shows version with version command" do
      output = capture_io(fn ->
        catch_exit(CLI.main(["version"]))
      end)

      assert output =~ "SecretHub CLI v0.1.0"
    end
  end

  describe "main/1 - invalid options" do
    test "shows error for invalid options" do
      output = capture_io(:stderr, fn ->
        catch_exit(CLI.main(["--invalid-option"]))
      end)

      assert output =~ "Error:"
      assert output =~ "Invalid options"
    end
  end

  describe "main/1 - unknown commands" do
    test "shows error for unknown command" do
      output = capture_io(:stderr, fn ->
        catch_exit(CLI.main(["unknown", "command"]))
      end)

      assert output =~ "Error:"
      assert output =~ "Unknown command"
      assert output =~ "secrethub help"
    end
  end

  describe "parse_args/1 - command parsing" do
    test "parses login command" do
      args = ["login", "--role-id", "test-role", "--secret-id", "test-secret"]
      assert {:ok, {:login, []}, opts} = CLI.parse_args(args)
      assert Keyword.get(opts, :role_id) == "test-role"
      assert Keyword.get(opts, :secret_id) == "test-secret"
    end

    test "parses logout command" do
      args = ["logout"]
      assert {:ok, :logout, _opts} = CLI.parse_args(args)
    end

    test "parses whoami command" do
      args = ["whoami"]
      assert {:ok, :whoami, _opts} = CLI.parse_args(args)
    end

    test "parses secret list command" do
      args = ["secret", "list"]
      assert {:ok, {:secret, :list, []}, _opts} = CLI.parse_args(args)
    end

    test "parses secret get command" do
      args = ["secret", "get", "prod.db.password"]
      assert {:ok, {:secret, :get, "prod.db.password", []}, _opts} = CLI.parse_args(args)
    end

    test "parses secret create command" do
      args = ["secret", "create", "test.secret", "--value", "secret123"]
      assert {:ok, {:secret, :create, "test.secret", []}, opts} = CLI.parse_args(args)
      assert Keyword.get(opts, :value) == "secret123"
    end

    test "parses secret update command" do
      args = ["secret", "update", "test.secret", "--value", "newsecret"]
      assert {:ok, {:secret, :update, "test.secret", []}, opts} = CLI.parse_args(args)
      assert Keyword.get(opts, :value) == "newsecret"
    end

    test "parses secret delete command" do
      args = ["secret", "delete", "test.secret"]
      assert {:ok, {:secret, :delete, "test.secret", []}, _opts} = CLI.parse_args(args)
    end

    test "parses secret versions command" do
      args = ["secret", "versions", "test.secret"]
      assert {:ok, {:secret, :versions, "test.secret", []}, _opts} = CLI.parse_args(args)
    end

    test "parses secret rollback command" do
      args = ["secret", "rollback", "test.secret", "2"]
      assert {:ok, {:secret, :rollback, "test.secret", "2", []}, _opts} = CLI.parse_args(args)
    end

    test "parses policy list command" do
      args = ["policy", "list"]
      assert {:ok, {:policy, :list, []}, _opts} = CLI.parse_args(args)
    end

    test "parses policy get command" do
      args = ["policy", "get", "test-policy"]
      assert {:ok, {:policy, :get, "test-policy", []}, _opts} = CLI.parse_args(args)
    end

    test "parses policy create command" do
      args = ["policy", "create", "--from-template", "business_hours", "--name", "Dev Access"]
      assert {:ok, {:policy, :create, []}, opts} = CLI.parse_args(args)
      assert Keyword.get(opts, :from_template) == "business_hours"
      assert Keyword.get(opts, :name) == "Dev Access"
    end

    test "parses policy simulate command" do
      args = ["policy", "simulate", "test-policy"]
      assert {:ok, {:policy, :simulate, "test-policy", []}, _opts} = CLI.parse_args(args)
    end

    test "parses policy templates command" do
      args = ["policy", "templates"]
      assert {:ok, {:policy, :templates, []}, _opts} = CLI.parse_args(args)
    end

    test "parses agent list command" do
      args = ["agent", "list"]
      assert {:ok, {:agent, :list, []}, _opts} = CLI.parse_args(args)
    end

    test "parses agent status command" do
      args = ["agent", "status", "agent-123"]
      assert {:ok, {:agent, :status, "agent-123", []}, _opts} = CLI.parse_args(args)
    end

    test "parses agent logs command" do
      args = ["agent", "logs", "agent-123"]
      assert {:ok, {:agent, :logs, "agent-123", []}, _opts} = CLI.parse_args(args)
    end

    test "parses config list command" do
      args = ["config", "list"]
      assert {:ok, {:config, :list, []}, _opts} = CLI.parse_args(args)
    end

    test "parses config get command" do
      args = ["config", "get", "server_url"]
      assert {:ok, {:config, :get, "server_url", []}, _opts} = CLI.parse_args(args)
    end

    test "parses config set command" do
      args = ["config", "set", "server_url", "http://localhost:4000"]
      assert {:ok, {:config, :set, "server_url", "http://localhost:4000", []}, _opts} = CLI.parse_args(args)
    end
  end

  describe "parse_args/1 - global options" do
    test "parses server option" do
      args = ["--server", "https://secrethub.example.com", "secret", "list"]
      assert {:ok, {:secret, :list, []}, opts} = CLI.parse_args(args)
      assert Keyword.get(opts, :server) == "https://secrethub.example.com"
    end

    test "parses format option" do
      args = ["--format", "json", "secret", "list"]
      assert {:ok, {:secret, :list, []}, opts} = CLI.parse_args(args)
      assert Keyword.get(opts, :format) == "json"
    end

    test "parses quiet flag" do
      args = ["--quiet", "secret", "list"]
      assert {:ok, {:secret, :list, []}, opts} = CLI.parse_args(args)
      assert Keyword.get(opts, :quiet) == true
    end

    test "parses verbose flag" do
      args = ["--verbose", "config", "list"]
      assert {:ok, {:config, :list, []}, opts} = CLI.parse_args(args)
      assert Keyword.get(opts, :verbose) == true
    end

    test "parses short aliases" do
      args = ["-s", "http://localhost:5000", "-f", "yaml", "-q", "secret", "list"]
      assert {:ok, {:secret, :list, []}, opts} = CLI.parse_args(args)
      assert Keyword.get(opts, :server) == "http://localhost:5000"
      assert Keyword.get(opts, :format) == "yaml"
      assert Keyword.get(opts, :quiet) == true
    end
  end

end
