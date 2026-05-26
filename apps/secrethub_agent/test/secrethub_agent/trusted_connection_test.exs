defmodule SecretHub.Agent.TrustedConnectionTest do
  use ExUnit.Case, async: false

  alias SecretHub.Agent.{Connection, TrustedConnection}

  setup do
    stop_registered_process(Connection)

    on_exit(fn ->
      stop_registered_process(Connection)
    end)

    :ok
  end

  test "starts connection from loaded private key PEM without requiring a host key" do
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    private_key_pem = X509.PrivateKey.to_pem(private_key, wrap: true)

    certificate_pem =
      private_key |> X509.Certificate.self_signed("/CN=agent-1") |> X509.Certificate.to_pem()

    callback = fn _payload -> :ok end

    assert {:ok, pid} =
             TrustedConnection.start_link(
               agent_id: "agent-1",
               connect_info: %{
                 "trusted_websocket_endpoint" => "wss://127.0.0.1:1",
                 "expected_core_server_name" => "localhost"
               },
               certificate_pem: certificate_pem,
               private_key_pem: private_key_pem,
               ca_pem: certificate_pem,
               on_runtime_accepted: callback
             )

    state = :sys.get_state(pid)

    assert state.private_key == private_key
    assert state.on_runtime_accepted == callback
  end

  test "returns a controlled error for invalid stored private key PEM" do
    assert {:error, {:invalid_private_key, _reason}} =
             TrustedConnection.start_link(
               agent_id: "agent-1",
               connect_info: %{
                 "trusted_websocket_endpoint" => "wss://127.0.0.1:1",
                 "expected_core_server_name" => "localhost"
               },
               certificate_pem:
                 "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
               private_key_pem: "not a private key",
               ca_pem: "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"
             )
  end

  test "returns a controlled error for malformed private key PEM" do
    assert {:error, {:invalid_private_key, _reason}} =
             TrustedConnection.start_link(
               agent_id: "agent-1",
               connect_info: %{
                 "trusted_websocket_endpoint" => "wss://127.0.0.1:1",
                 "expected_core_server_name" => "localhost"
               },
               certificate_pem:
                 "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
               private_key_pem: "-----BEGIN PRIVATE KEY-----\n@@@@\n-----END PRIVATE KEY-----\n",
               ca_pem: "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"
             )
  end

  defp stop_registered_process(name) do
    try do
      case Process.whereis(name) do
        nil -> :ok
        pid -> GenServer.stop(pid, :normal, 1000)
      end
    catch
      :exit, _reason -> :ok
    end
  end
end
