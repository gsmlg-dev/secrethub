defmodule SecretHub.Core.SecretValueFormatsTest do
  use ExUnit.Case, async: false
  import SecretHub.Core.VaultTestHelpers
  alias SecretHub.Core.{Repo, RuntimeDatabaseFixture, Secrets}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.Secret

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    if pid = Process.whereis(SealState), do: GenServer.stop(pid, :normal)
    RuntimeDatabaseFixture.setup(tags)
    start_supervised!({SealState, repo: RuntimeDatabaseFixture.VaultRepo}, restart: :temporary)
    await_vault_state(:not_initialized)
    {:ok, [first, second | _]} = SealState.initialize(3, 2)
    {:ok, _} = SealState.unseal(first)
    {:ok, _} = SealState.unseal(second)
    :ok
  end

  test "explicit text round trips exact bytes and replacement can be empty" do
    for value <- ["token", "{\"value\":1}", "密钥\nPEM", " \t\n", ""] do
      secret = create(%{"value_format" => "text", "value" => value})
      assert secret.value_format == "text"
      assert {:ok, %{"value" => ^value}, _} = Secrets.read_decrypted(secret.secret_path)

      assert {:ok, replaced} =
               Secrets.update_secret(secret.id, %{"secret_data" => %{"value" => ""}})

      assert replaced.value_format == "text"
      assert {:ok, %{"value" => ""}, _} = Secrets.read_decrypted(secret.secret_path)
    end
  end

  test "metadata-only preserves ciphertext and format, and explicit value allows whitespace" do
    secret = create(%{"value_format" => "text", "value" => "saved"})

    assert {:ok, updated} =
             Secrets.update_secret(secret.id, %{"description" => "new description"})

    assert updated.encrypted_data == secret.encrypted_data
    assert updated.value_format == "text"

    assert {:ok, _} =
             Secrets.update_secret(secret.id, %{"value_format" => "text", "value" => " \n"})

    assert {:ok, %{"value" => " \n"}, _} = Secrets.read_decrypted(secret.secret_path)
  end

  test "explicit formats validate replacements and switches require complete payload" do
    assert {:error, :invalid_text_value} =
             Secrets.create_secret(
               attrs(%{"value_format" => "text", "secret_data" => %{"other" => "x"}})
             )

    assert {:error, :invalid_value_format} =
             Secrets.create_secret(attrs(%{"value_format" => "other"}))

    text = create(%{"value_format" => "text", "value" => "old"})

    assert {:error, :format_change_requires_replacement} =
             Secrets.update_secret(text.id, %{"value_format" => "structured"})

    assert {:error, :invalid_text_value} =
             Secrets.update_secret(text.id, %{"secret_data" => %{"a" => 1}})

    assert {:error, :invalid_value_format} =
             Secrets.update_secret(text.id, %{"value_format" => nil})

    assert {:ok, structured} =
             Secrets.update_secret(text.id, %{
               "value_format" => "structured",
               "secret_data" => %{}
             })

    assert structured.value_format == "structured"
  end

  test "legacy classification validates the current shape and versions unchanged ciphertext" do
    legacy = create(%{"secret_data" => %{"value" => "saved", "data" => [false, nil]}})
    assert legacy.value_format == nil

    assert {:error, :invalid_text_value} =
             Secrets.update_secret(legacy.id, %{"value_format" => "text"})

    assert {:ok, structured} = Secrets.update_secret(legacy.id, %{"value_format" => "structured"})
    assert structured.encrypted_data == legacy.encrypted_data
    assert {:ok, %{value_format: nil}} = Secrets.get_secret_version(legacy.id, 1)

    assert {:ok, %{"value" => "saved", "data" => [false, nil]}, nil} =
             Secrets.read_exact_material_with_format(legacy.id, 1)

    assert {:ok, _, "structured"} = Secrets.read_exact_material_with_format(legacy.id, 2)
    assert {:ok, restored} = Secrets.rollback_secret(legacy.id, 1)
    assert restored.value_format == nil
    assert {:ok, comparison} = Secrets.compare_versions(legacy.id, 1, 2)
    assert comparison.value_format == {nil, "structured"}
    wrapper = create(%{"secret_data" => %{"value" => "saved"}})

    assert {:ok, %{value_format: "text"}} =
             Secrets.update_secret(wrapper.id, %{"value_format" => "text"})
  end

  test "field descriptors contain kinds and field operations use expected version" do
    data = %{"value" => [1, false], "data" => %{"nested" => nil}, "" => 42, " " => true}
    secret = create(%{"value_format" => "structured", "secret_data" => data})
    assert {:ok, %{version: 1, fields: fields}} = Secrets.field_descriptors(secret.id)
    assert %{key: "value", kind: "array"} in fields
    assert Enum.all?(fields, &(Map.keys(&1) |> Enum.sort() == [:key, :kind]))

    operations = [
      %{"original_key" => "value", "name" => "data", "operation" => "keep"},
      %{"original_key" => "data", "name" => "value", "operation" => "keep"},
      %{"name" => "format", "value" => "", "operation" => "replace"},
      %{"name" => "value_format", "value" => "entered", "operation" => "replace"}
    ]

    assert {:error, :expected_version_required} =
             Secrets.update_secret(secret.id, %{"field_operations" => operations})

    assert {:error, :stale_version} =
             Secrets.update_secret(secret.id, %{"field_operations" => operations},
               expected_version: 9
             )

    assert {:ok, %{version: 2}} =
             Secrets.update_secret(secret.id, %{"field_operations" => operations},
               expected_version: 1
             )

    assert {:ok,
            %{
              "data" => [1, false],
              "value" => %{"nested" => nil},
              "" => 42,
              " " => true,
              "format" => "",
              "value_format" => "entered"
            }, _} = Secrets.read_decrypted(secret.secret_path)

    assert {:error, :stale_version} =
             Secrets.update_secret(secret.id, %{"field_operations" => operations},
               expected_version: 1
             )
  end

  test "rejected field edits make no archived version or ciphertext change" do
    secret =
      create(%{"value_format" => "structured", "secret_data" => %{"a" => "private", "b" => 1}})

    operations = [%{"original_key" => "a", "name" => "b", "operation" => "keep"}]

    assert {:error, :duplicate_field_name} =
             Secrets.update_secret(secret.id, %{"field_operations" => operations},
               expected_version: 1
             )

    assert [] = Secrets.list_secret_versions(secret.id)
    assert Repo.get!(Secret, secret.id).encrypted_data == secret.encrypted_data
  end

  test "database constraints reject unsupported format" do
    secret = create(%{"value_format" => "structured", "secret_data" => %{}})

    assert {:error, %Postgrex.Error{postgres: %{code: :check_violation}}} =
             Repo.query("UPDATE secrets SET value_format = 'json' WHERE id = $1", [
               Ecto.UUID.dump!(secret.id)
             ])
  end

  test "managed output publication sets structured on initial and replacement writes and guards format" do
    source =
      create(%{"value_format" => "structured", "secret_data" => %{"certificate" => "fixture"}})

    resource = %{slug: "format-test", output_secret_id: nil}

    assert {:ok, {:ok, initial}} =
             Repo.transaction(fn ->
               Secrets.write_managed_output_locked(resource, source.encrypted_data)
             end)

    assert initial.value_format == "structured"
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    account =
      Repo.insert!(%SecretHub.Shared.Schemas.AcmeAccount{
        name: "Format fixture",
        environment: "staging",
        directory_url: "https://acme.invalid/directory",
        terms_url: "https://acme.invalid/terms",
        terms_accepted_at: now,
        encrypted_key: <<1>>
      })

    Repo.insert!(%SecretHub.Shared.Schemas.ManagedCertificate{
      slug: "format-test",
      account_id: account.id,
      identifiers: ["example.invalid"],
      bindings: [],
      output_secret_id: initial.id
    })

    assert {:error, :managed_certificate_output} =
             Secrets.update_secret(initial.id, %{"value_format" => "text"})

    assert {:error,
            %Postgrex.Error{
              postgres: %{code: :check_violation, message: "managed_certificate_output"}
            }} =
             Repo.query("UPDATE secrets SET value_format = 'text' WHERE id = $1", [
               Ecto.UUID.dump!(initial.id)
             ])

    assert {:ok, {:ok, replacement}} =
             Repo.transaction(fn ->
               Secrets.write_managed_output_locked(
                 %{resource | output_secret_id: initial.id},
                 source.encrypted_data
               )
             end)

    assert replacement.value_format == "structured"
    assert {:ok, %{value_format: "structured"}} = Secrets.get_secret_version(initial.id, 1)
  end

  test "field-operation changeset failures never include saved plaintext" do
    secret =
      create(%{
        "value_format" => "structured",
        "secret_data" => %{"saved" => "saved-sensitive-marker"}
      })

    assert {:error, changeset} =
             Secrets.update_secret(
               secret.id,
               %{
                 "name" => "invalid!",
                 "field_operations" => [
                   %{"name" => "new", "operation" => "replace", "value" => "entered"}
                 ]
               },
               expected_version: 1
             )

    refute inspect(changeset) =~ "saved-sensitive-marker"
    refute inspect(changeset.params) =~ "saved-sensitive-marker"
    assert [] = Secrets.list_secret_versions(secret.id)
  end

  @tag :format_edge
  test "explicit text rejects nil through the simplified input" do
    assert {:error, :invalid_text_value} =
             Secrets.create_secret(attrs(%{"value_format" => "text", "value" => nil}))
  end

  @tag :format_edge
  test "explicit structured creation requires a supplied object" do
    for extra <- [
          %{"value_format" => "structured"},
          %{"value_format" => "structured", "secret_data" => nil},
          %{"value_format" => "structured", "secret_data" => false}
        ] do
      assert {:error, :invalid_structured_value} = Secrets.create_secret(attrs(extra))
    end
  end

  defp create(extra),
    do: Secrets.create_secret(attrs(extra)) |> then(fn {:ok, secret} -> secret end)

  defp attrs(extra) do
    Map.merge(
      %{
        "name" => "Format Test",
        "secret_path" => "test.format.s#{System.unique_integer([:positive])}"
      },
      extra
    )
  end
end
