defmodule SecretHub.Agent.IdentityStoreTest do
  use ExUnit.Case, async: true

  alias SecretHub.Agent.IdentityStore

  @moduletag :tmp_dir

  test "write and load round trips trusted runtime material", %{tmp_dir: tmp_dir} do
    state_dir = Path.join(tmp_dir, "agent-state")

    material = %{
      agent_id: "agent-1",
      certificate_pem: "-----BEGIN CERTIFICATE-----\nagent\n-----END CERTIFICATE-----\n",
      private_key_pem: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
      ca_chain_pem: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n",
      connect_info: %{
        "trusted_websocket_endpoint" => "wss://core.example/agent/socket/websocket"
      },
      identity: %{
        "agent_id" => "agent-1",
        "enrollment_id" => "enrollment-1",
        "certificate_fingerprint" => "SHA256:certificate"
      }
    }

    assert :ok = IdentityStore.write(state_dir, material)

    assert {:ok,
            %IdentityStore{
              agent_id: "agent-1",
              certificate_pem: material.certificate_pem,
              private_key_pem: material.private_key_pem,
              ca_chain_pem: material.ca_chain_pem,
              connect_info: material.connect_info,
              identity: material.identity
            }} == IdentityStore.load(state_dir)

    assert mode(state_dir) == 0o700
    assert mode(Path.join(state_dir, "agent-cert.pem")) == 0o644
    assert mode(Path.join(state_dir, "agent-key.pem")) == 0o600
    assert mode(Path.join(state_dir, "ca-chain.pem")) == 0o644
    assert mode(Path.join(state_dir, "connect-info.json")) == 0o644
    assert mode(Path.join(state_dir, "identity.json")) == 0o644
  end

  test "load returns missing trusted material for an empty directory", %{tmp_dir: tmp_dir} do
    assert :ok = File.mkdir_p(tmp_dir)

    assert {:error, :missing_trusted_material} = IdentityStore.load(tmp_dir)
  end

  test "write rejects wrong trusted material field types before filesystem writes", %{
    tmp_dir: tmp_dir
  } do
    for invalid_material <- [
          Map.put(valid_material(), :agent_id, %{}),
          Map.put(valid_material(), :certificate_pem, %{})
        ] do
      state_dir = Path.join(tmp_dir, System.unique_integer([:positive]) |> Integer.to_string())

      assert {:error, :invalid_trusted_material} =
               IdentityStore.write(state_dir, invalid_material)

      refute_trusted_files_created(state_dir)
    end
  end

  test "write rejects non-encodable JSON material before filesystem writes", %{
    tmp_dir: tmp_dir
  } do
    state_dir = Path.join(tmp_dir, "invalid-json")

    material =
      Map.put(valid_material(), :identity, %{"agent_id" => "agent-1", "bad" => fn -> :ok end})

    assert {:error, {:invalid_json, :identity}} = IdentityStore.write(state_dir, material)

    refute_trusted_files_created(state_dir)
  end

  defp valid_material do
    %{
      agent_id: "agent-1",
      certificate_pem: "-----BEGIN CERTIFICATE-----\nagent\n-----END CERTIFICATE-----\n",
      private_key_pem: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
      ca_chain_pem: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n",
      connect_info: %{
        "trusted_websocket_endpoint" => "wss://core.example/agent/socket/websocket"
      },
      identity: %{
        "agent_id" => "agent-1",
        "enrollment_id" => "enrollment-1",
        "certificate_fingerprint" => "SHA256:certificate"
      }
    }
  end

  defp refute_trusted_files_created(state_dir) do
    trusted_files = [
      "agent-cert.pem",
      "agent-key.pem",
      "ca-chain.pem",
      "connect-info.json",
      "identity.json"
    ]

    refute File.exists?(state_dir)

    for file <- trusted_files do
      refute File.exists?(Path.join(state_dir, file))
    end
  end

  defp mode(path) do
    {:ok, stat} = File.stat(path)
    Bitwise.band(stat.mode, 0o777)
  end
end
