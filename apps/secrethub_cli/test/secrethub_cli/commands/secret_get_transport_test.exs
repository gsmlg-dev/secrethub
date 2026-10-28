defmodule SecretHub.CLI.Commands.SecretGetTransportTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias SecretHub.CLI
  alias SecretHub.CLI.{AgentClient, AgentSocketFixture, Config}
  alias SecretHub.CLI.Commands.SecretCommands

  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    original_config = Application.get_env(:secrethub_cli, :config_dir)
    original_socket = System.get_env("SECRET_HUB_AGENT_SOCKET_PATH")
    Application.put_env(:secrethub_cli, :config_dir, dir)
    System.delete_env("SECRET_HUB_AGENT_SOCKET_PATH")

    on_exit(fn ->
      if original_config do
        Application.put_env(:secrethub_cli, :config_dir, original_config)
      else
        Application.delete_env(:secrethub_cli, :config_dir)
      end

      if original_socket do
        System.put_env("SECRET_HUB_AGENT_SOCKET_PATH", original_socket)
      else
        System.delete_env("SECRET_HUB_AGENT_SOCKET_PATH")
      end
    end)

    :ok
  end

  test "uses the documented default socket when no environment override is set" do
    assert AgentClient.default_socket_path() == "/var/run/secrethub/agent.sock"
  end

  test "plain CLI secret get uses the default socket without login or application credentials" do
    path = socket_path()
    System.put_env("SECRET_HUB_AGENT_SOCKET_PATH", path)
    server = AgentSocketFixture.start_local(path, self())
    assert_receive :agent_socket_ready

    output =
      capture_io(fn ->
        assert catch_exit(CLI.main(["secret", "get", "prod.db.password", "--format", "json"])) ==
                 {:shutdown, 0}
      end)

    assert Jason.decode!(output) == %{"value" => "from-agent"}
    assert_receive {:local_request, %{"action" => "get_secret"}}
    assert {:error, :not_found} = Config.get_auth_token()
    Task.await(server, 5000)
  end

  test "explicit agent socket overrides the environment default" do
    System.put_env("SECRET_HUB_AGENT_SOCKET_PATH", socket_path())
    path = socket_path()
    server = AgentSocketFixture.start_local(path, self())
    assert_receive :agent_socket_ready

    assert {:ok, json} =
             SecretCommands.execute(:get, "prod.db.password", [],
               agent_socket: path,
               format: "json"
             )

    assert Jason.decode!(json) == %{"value" => "from-agent"}
    assert_receive {:local_request, %{"action" => "get_secret"}}
    Task.await(server, 5000)
  end

  test "rejects an empty explicit socket instead of using the environment default" do
    System.put_env("SECRET_HUB_AGENT_SOCKET_PATH", socket_path())

    assert {:error, "Missing required agent socket path"} =
             SecretCommands.execute(:get, "prod.db.password", [], agent_socket: "")
  end

  test "credential options without a socket still require a complete application pair" do
    System.put_env("SECRET_HUB_AGENT_SOCKET_PATH", socket_path())

    assert {:error, "Missing required agent private key"} =
             SecretCommands.execute(:get, "prod.db.password", [], agent_cert: "/tmp/no-cert")

    assert {:error, "Missing required agent certificate"} =
             SecretCommands.execute(:get, "prod.db.password", [], agent_key: "/tmp/no-key")

    assert {:error, "Missing required agent certificate"} =
             SecretCommands.execute(:get, "prod.db.password", [], agent_cert: "", agent_key: "")
  end

  test "explicit Core URL receives the read and stored token instead of the configured server" do
    Application.ensure_all_started(:req)
    :ok = Config.set("server_url", "http://127.0.0.1:1")
    :ok = Config.save_auth("core-read-token", DateTime.add(DateTime.utc_now(), 3600))
    {listener, url} = http_listener()
    owner = self()

    server =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 15_000)

        try do
          headers = receive_headers(socket)
          send(owner, {:http_request, headers})
          body = Jason.encode!(%{data: %{value: "from-core"}})

          :gen_tcp.send(socket, [
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ",
            Integer.to_string(byte_size(body)),
            "\r\nconnection: close\r\n\r\n",
            body
          ])
        after
          :gen_tcp.close(socket)
        end
      end)

    assert {:ok, json} =
             SecretCommands.execute(:get, "prod.db.password", [], server: url, format: "json")

    assert Jason.decode!(json) == %{"value" => "from-core"}
    assert_receive {:http_request, headers}
    assert headers =~ "GET /v1/secret/data/prod/db/password HTTP/1.1"
    assert String.downcase(headers) =~ "x-vault-token: core-read-token"
    Task.await(server, 5000)
  end

  test "explicit server conflicts with each Agent selector before authentication" do
    for option <- [:agent_socket, :agent_cert, :agent_key] do
      assert {:error, "Cannot combine --server with Agent options"} =
               SecretCommands.execute(:get, "prod.db.password", [], [
                 {:server, "http://127.0.0.1:1"},
                 {option, "/tmp/material"}
               ])
    end
  end

  test "an unavailable default socket never falls back to configured HTTP or login" do
    {listener, url} = http_listener()
    :ok = Config.set("server_url", url)
    System.put_env("SECRET_HUB_AGENT_SOCKET_PATH", socket_path())

    assert {:error, "Agent connection or key material unavailable"} =
             SecretCommands.execute(:get, "prod.db.password", [], [])

    assert {:error, :timeout} = :gen_tcp.accept(listener, 100)
    assert {:error, :not_found} = Config.get_auth_token()
  end

  test "an Agent denial remains an error without falling back to HTTP" do
    {listener, url} = http_listener()
    :ok = Config.set("server_url", url)
    :ok = Config.save_auth("core-read-token", DateTime.add(DateTime.utc_now(), 3600))
    path = socket_path()
    server = AgentSocketFixture.start_local(path, self(), {:error, "ACCESS_DENIED"})
    assert_receive :agent_socket_ready

    assert {:error, "ACCESS_DENIED"} =
             SecretCommands.execute(:get, "prod.db.password", [], agent_socket: path)

    assert {:error, :timeout} = :gen_tcp.accept(listener, 100)
    Task.await(server, 5000)
  end

  defp socket_path do
    path = Path.join(System.tmp_dir!(), "sh-route-#{System.unique_integer([:positive])}.sock")
    on_exit(fn -> File.rm(path) end)
    path
  end

  defp http_listener do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false, packet: :http_bin])

    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)
    {listener, "http://127.0.0.1:#{port}"}
  end

  defp receive_headers(socket, acc \\ []) do
    case :gen_tcp.recv(socket, 0, 5000) do
      {:ok, {:http_request, method, {:abs_path, path}, {major, minor}}} ->
        receive_headers(socket, ["#{method} #{path} HTTP/#{major}.#{minor}\r\n" | acc])

      {:ok, {:http_header, _, key, _, value}} ->
        receive_headers(socket, ["#{key}: #{value}\r\n" | acc])

      {:ok, :http_eoh} ->
        acc |> Enum.reverse() |> IO.iodata_to_binary()
    end
  end
end
