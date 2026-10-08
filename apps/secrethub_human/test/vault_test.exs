defmodule SecretHub.Human.VaultTest do
  use SecretHub.Human.DataCase, async: true
  alias SecretHub.Human.Accounts
  alias SecretHub.Human.RateLimiter
  alias SecretHub.Human.Vault

  defp encrypted do
    "2." <> Enum.map_join([16, 16, 32], "|", &Base.encode64(:crypto.strong_rand_bytes(&1)))
  end

  defp actor do
    input = %{
      email: "vault-#{System.unique_integer([:positive])}@example.test",
      name: "Owner",
      password_hash: Base.encode64(:crypto.strong_rand_bytes(32)),
      encrypted_key: encrypted()
    }

    {:ok, _} = Accounts.provision(input, server_iterations: 1000)
    limiter = start_supervised!({RateLimiter, name: nil}, id: make_ref())

    {:ok, session} =
      Accounts.authenticate(input.email, input.password_hash, %{identifier: "browser"},
        rate_limiter: limiter
      )

    session.actor
  end

  test "ciphertext CRUD retains history and deletion tombstones with monotonic sync" do
    actor = actor()

    first_payload = %{
      "name" => encrypted(),
      "login" => %{"username" => encrypted(), "password" => encrypted()}
    }

    assert {:ok, item} = Vault.create_item(actor, %{type: "login", ciphertext: first_payload})
    assert {:ok, %{items: [%{id: id}], cursor: cursor}} = Vault.sync(actor, 0)
    assert id == item.id
    second_payload = %{first_payload | "name" => encrypted()}

    assert {:ok, updated} =
             Vault.update_item(actor, item.id, %{
               ciphertext: second_payload,
               expected_revision: item.revision
             })

    assert updated.revision > cursor
    assert {:ok, [version]} = Vault.item_history(actor, item.id)
    assert version.ciphertext == first_payload

    assert {:error, :conflict} =
             Vault.update_item(actor, item.id, %{
               ciphertext: first_payload,
               expected_revision: item.revision
             })

    assert {:ok, deleted} = Vault.delete_item(actor, item.id)
    assert deleted.deleted_at

    assert {:ok, %{items: [%{id: ^id, deleted_at: at}], cursor: next}} =
             Vault.sync(actor, updated.revision)

    assert at
    assert next == deleted.revision
    assert {:error, :not_found} = Vault.get_item(actor, item.id)
  end

  test "commands revalidate sessions and cannot read or mutate another owner's identifiers" do
    owner = actor()
    outsider = actor()

    assert {:ok, item} =
             Vault.create_item(owner, %{
               type: "secure_note",
               ciphertext: %{"name" => encrypted(), "notes" => encrypted()}
             })

    assert {:error, :not_found} = Vault.get_item(outsider, item.id)
    assert {:error, :not_found} = Vault.update_item(outsider, item.id, %{favorite: true})
    assert {:error, :not_found} = Vault.item_history(outsider, item.id)
    assert {:error, :not_found} = Vault.delete_item(outsider, item.id)
    assert {:ok, %{items: [], cursor: 0}} = Vault.sync(outsider, 0)
    assert :ok = Accounts.revoke_session(owner, owner.session_id)
    assert {:error, :unauthenticated} = Vault.get_item(owner, item.id)
  end

  test "folders are encrypted and ownership-scoped; deleting folders detaches items" do
    owner = actor()
    other = actor()
    assert {:ok, folder} = Vault.create_folder(owner, %{name: encrypted()})

    assert {:ok, item} =
             Vault.create_item(owner, %{
               type: "login",
               ciphertext: %{"name" => encrypted()},
               folder_id: folder.id
             })

    assert {:error, :not_found} =
             Vault.create_item(other, %{
               type: "login",
               ciphertext: %{"name" => encrypted()},
               folder_id: folder.id
             })

    assert {:error, :not_found} = Vault.update_folder(other, folder.id, %{name: encrypted()})
    assert {:ok, _} = Vault.delete_folder(owner, folder.id)
    assert {:ok, %{folder_id: nil}} = Vault.get_item(owner, item.id)
  end

  test "bounded sync pages preserve mixed folder and item changes including tombstones" do
    owner = actor()
    {:ok, first_folder} = Vault.create_folder(owner, %{name: encrypted()})

    {:ok, first_item} =
      Vault.create_item(owner, %{type: "login", ciphertext: %{"name" => encrypted()}})

    {:ok, second_folder} = Vault.create_folder(owner, %{name: encrypted()})

    {:ok, second_item} =
      Vault.create_item(owner, %{type: "secure_note", ciphertext: %{"name" => encrypted()}})

    {:ok, deleted} = Vault.delete_item(owner, first_item.id)
    {:ok, deleted_folder} = Vault.delete_folder(owner, first_folder.id)

    assert {:ok, %{folders: [folder], items: [item], cursor: cursor}} =
             Vault.sync(owner, 0, limit: 2)

    assert folder.id == second_folder.id
    assert item.id == second_item.id
    assert cursor == second_item.revision

    assert {:ok, %{folders: [folder], items: [item], cursor: next}} =
             Vault.sync(owner, cursor, limit: 2)

    assert item.id == deleted.id
    assert item.deleted_at
    assert folder.id == deleted_folder.id
    assert folder.deleted_at
    assert next == deleted_folder.revision
    assert {:ok, %{folders: [], items: [], cursor: ^next}} = Vault.sync(owner, next, limit: 2)
  end

  test "retained history is bounded and exports contain only current owned ciphertext" do
    owner = actor()
    outsider = actor()

    {:ok, initial} =
      Vault.create_item(owner, %{type: "login", ciphertext: %{"name" => encrypted()}})

    current =
      Enum.reduce(1..23, initial, fn _, item ->
        assert {:ok, updated} =
                 Vault.update_item(owner, item.id, %{
                   ciphertext: %{"name" => encrypted()},
                   expected_revision: item.revision
                 })

        updated
      end)

    assert {:ok, history} = Vault.item_history(owner, current.id)
    assert Enum.count(history) == 20
    assert Enum.map(history, & &1.revision) == Enum.to_list(23..4//-1)

    {:ok, deleted} =
      Vault.create_item(owner, %{type: "api_credential", ciphertext: %{"name" => encrypted()}})

    {:ok, _} = Vault.delete_item(owner, deleted.id)
    {:ok, _} = Vault.create_item(outsider, %{type: "card", ciphertext: %{"name" => encrypted()}})
    assert {:error, :confirmation_required} = Vault.export(owner, %{})
    assert {:ok, %{items: [exported]}} = Vault.export(owner, %{confirm: true})
    assert exported.id == current.id
    assert exported.ciphertext == current.ciphertext
    assert :ok = Accounts.revoke_session(owner, owner.session_id)
    assert {:error, :unauthenticated} = Vault.export(owner, %{confirm: true})
  end

  test "plaintext and malformed envelopes are rejected without leaking them in errors" do
    owner = actor()

    for payload <- [
          %{"name" => "plaintext password"},
          %{"name" => "2.invalid|cipher|mac"},
          %{"unknown" => encrypted()},
          %{"login" => %{"password" => "unencrypted"}}
        ] do
      assert {:error, :invalid_ciphertext} =
               Vault.create_item(owner, %{type: "login", ciphertext: payload})
    end

    assert {:error, :invalid_ciphertext} = Vault.create_folder(owner, %{name: "plaintext"})
    assert {:error, :invalid_input} = Vault.sync(owner, -1)
    assert {:error, :invalid_input} = Vault.sync(owner, 0, limit: 1001)
  end
end
