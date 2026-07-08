defmodule SecretHub.CLI.AgentClientTest do
  use ExUnit.Case, async: false

  alias SecretHub.CLI.AgentClient

  @tag :tmp_dir
  test "authenticates and retrieves a secret over the agent Unix socket", %{tmp_dir: tmp_dir} do
    socket_path =
      Path.join(System.tmp_dir!(), "sh_cli_#{System.unique_integer([:positive])}.sock")

    cert_path = Path.join(tmp_dir, "app.crt")
    cert_pem = "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----\n"
    File.write!(cert_path, cert_pem)

    on_exit(fn -> File.rm(socket_path) end)

    server = start_agent_socket_server(socket_path, self())

    assert {:ok, %{"value" => "from-agent"}} =
             AgentClient.get_secret("prod.db.password",
               socket_path: socket_path,
               certificate_path: cert_path
             )

    assert_receive {:auth_request,
                    %{
                      "action" => "authenticate",
                      "params" => %{"certificate" => ^cert_pem}
                    }}

    assert_receive {:secret_request,
                    %{
                      "action" => "get_secret",
                      "params" => %{"path" => "prod.db.password"}
                    }}

    Task.await(server, 5_000)
  end

  defp start_agent_socket_server(socket_path, test_pid) do
    Task.async(fn ->
      {:ok, listener} =
        :gen_tcp.listen(0, [
          {:ifaddr, {:local, String.to_charlist(socket_path)}},
          :binary,
          packet: :line,
          active: false,
          reuseaddr: true
        ])

      send(test_pid, :agent_socket_ready)

      {:ok, socket} = :gen_tcp.accept(listener, 5_000)

      auth_request = recv_json!(socket)
      send(test_pid, {:auth_request, auth_request})

      send_json!(socket, %{
        request_id: auth_request["request_id"],
        status: "ok",
        data: %{"authenticated" => true, "app_id" => "app-1"}
      })

      secret_request = recv_json!(socket)
      send(test_pid, {:secret_request, secret_request})

      send_json!(socket, %{
        request_id: secret_request["request_id"],
        status: "ok",
        data: %{"value" => "from-agent", "version" => 1}
      })

      :gen_tcp.close(socket)
      :gen_tcp.close(listener)
    end)
    |> tap(fn _task -> assert_receive :agent_socket_ready, 5_000 end)
  end

  defp recv_json!(socket) do
    {:ok, line} = :gen_tcp.recv(socket, 0, 5_000)
    Jason.decode!(line)
  end

  defp send_json!(socket, payload) do
    :ok = :gen_tcp.send(socket, Jason.encode!(payload) <> "\n")
  end
end
