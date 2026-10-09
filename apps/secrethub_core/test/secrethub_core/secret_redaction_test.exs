defmodule SecretHub.Core.SecretRedactionTest do
  use SecretHub.Core.DataCase, async: false
  import ExUnit.CaptureLog
  alias SecretHub.Core.{Secrets, Vault.SealState}
  alias SecretHub.Shared.Crypto.Encryption
  alias SecretHub.Shared.Schemas.Secret

  setup do
    if pid = Process.whereis(SealState), do: GenServer.stop(pid)
    start_supervised!({SealState, []}, restart: :temporary)
    await_empty(100)
    {:ok, shares} = SealState.initialize(3, 2)
    Enum.each(Enum.take(shares, 2), &SealState.unseal/1)
    :ok
  end

  test "unsupported JSON values never appear in errors or logs" do
    marker = "disposable-private-json-marker"

    output =
      capture_log(fn ->
        result =
          Secrets.create_secret(%{
            name: "Redaction",
            secret_path: "test.redaction",
            secret_data: %{"private" => {marker, 1}}
          })

        assert match?({:error, "Encryption failed"}, result)
      end)

    refute output =~ marker
  end

  test "authenticated malformed JSON is not exposed by decode errors" do
    {:ok, key} = SealState.get_master_key()
    {:ok, blob} = Encryption.encrypt_to_blob("disposable-private-json-marker", key)

    Repo.insert!(
      Secret.changeset(%Secret{}, %{
        name: "Malformed JSON",
        secret_path: "test.redaction",
        encrypted_data: blob
      })
    )

    result = Secrets.read_decrypted("test.redaction")
    assert match?({:error, "Decryption failed"}, result)
  end

  defp await_empty(0), do: flunk("Vault loading timed out")

  defp await_empty(attempts) do
    if SealState.status().state == :not_initialized do
      :ok
    else
      Process.sleep(10)
      await_empty(attempts - 1)
    end
  end
end
