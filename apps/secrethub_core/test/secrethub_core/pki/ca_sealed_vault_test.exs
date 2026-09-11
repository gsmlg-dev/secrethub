defmodule SecretHub.Core.PKI.CASealedVaultTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.PKI.CA
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.{Certificate, VaultConfig}

  setup do
    if pid = Process.whereis(SealState) do
      GenServer.stop(pid)
    end

    Repo.delete_all(SecretHub.Shared.Schemas.ClientAuthBundleReceipt)
    Repo.delete_all(SecretHub.Shared.Schemas.ClientAuthIssuanceRequest)
    _ = Repo.query("UPDATE client_auth_authorities SET current_crl_id = NULL", [])
    Repo.delete_all(SecretHub.Shared.Schemas.ClientAuthCrl)
    Repo.delete_all(Certificate)
    Repo.delete_all(SecretHub.Shared.Schemas.ClientAuthIdentity)
    Repo.delete_all(SecretHub.Shared.Schemas.ClientAuthAuthority)
    Repo.delete_all(VaultConfig)

    start_supervised!(SealState)
    {:ok, _shares} = SealState.initialize(3, 2)

    on_exit(fn ->
      if pid = Process.whereis(SealState) do
        GenServer.stop(pid)
      end
    end)

    :ok
  end

  test "generate_root_ca returns an error instead of crashing when vault is sealed" do
    assert {:error, "Vault is sealed"} =
             CA.generate_root_ca("Sealed Root CA", "SecretHub", key_size: 2048)

    assert Repo.aggregate(Certificate, :count) == 0
  end
end
