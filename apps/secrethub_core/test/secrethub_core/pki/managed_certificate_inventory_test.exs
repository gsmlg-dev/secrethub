defmodule SecretHub.Core.PKI.ManagedCertificateInventoryTest do
  use ExUnit.Case, async: false

  alias Ecto.Changeset
  alias SecretHub.Core.PKI.ManagedCertificates, as: Managed
  alias SecretHub.Core.{Repo, RuntimeDatabaseFixture}

  alias SecretHub.Shared.Schemas.{
    AcmeAccount,
    AcmeOrder,
    ManagedCertificate,
    ManagedCertificateVersion,
    Secret
  }

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)

    account =
      Repo.insert!(%AcmeAccount{
        name: "Inventory fixture account",
        environment: "staging",
        directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory",
        terms_url: "https://example.com/terms",
        terms_accepted_at: Managed.now(),
        encrypted_key: "unreadable-account-ciphertext"
      })

    secret =
      Repo.insert!(%Secret{
        name: "Inventory fixture output",
        secret_path: "test.inventory.output",
        secret_type: :static,
        encrypted_data: "unreadable-private-bundle-ciphertext"
      })

    %{account: account, secret: secret}
  end

  test "all published generations remain visible across lifecycle states and disabled ACME", c do
    previous = Application.fetch_env(:secrethub_core, :acme_enabled)
    Application.put_env(:secrethub_core, :acme_enabled, false)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:secrethub_core, :acme_enabled, value)
        :error -> Application.delete_env(:secrethub_core, :acme_enabled)
      end
    end)

    resource = insert_resource(c.account, name: "gsmlg.net", enabled: false)
    unissued = insert_resource(c.account)
    now = Managed.now()

    versions = [
      insert_version(resource, c.secret, 1, not_after: DateTime.add(now, -1)),
      insert_version(resource, c.secret, 2, quarantined_at: now, revocation_state: "pending"),
      insert_version(resource, c.secret, 3, quarantined_at: now, revocation_state: "failed"),
      insert_version(resource, c.secret, 4, quarantined_at: now, revocation_state: "confirmed"),
      insert_version(resource, c.secret, 5, environment: "staging")
    ]

    current = List.last(versions)
    Repo.update!(Changeset.change(resource, current_version_id: current.id))
    inventory = Managed.list_published_certificates()

    assert Enum.sort(Enum.map(inventory, & &1.id)) == Enum.sort(Enum.map(versions, & &1.id))
    refute Enum.any?(inventory, &(&1.managed_certificate_id == unissued.id))

    for version <- versions do
      entry = Enum.find(inventory, &(&1.id == version.id))
      assert entry.publication_sequence == version.publication_sequence
      assert entry.environment == version.environment
      assert entry.not_after == version.not_after
      assert entry.quarantined_at == version.quarantined_at
      assert entry.revocation_state == version.revocation_state
      assert entry.current == (version.id == current.id)
    end
  end

  test "inventory returns only metadata and uses issued values rather than edited configuration",
       c do
    resource = insert_resource(c.account, name: "gsmlg.net")

    version =
      insert_version(resource, c.secret, 1,
        identifiers: ["gsmlg.net", "www.gsmlg.net"],
        environment: "production",
        key_policy: "ec_p256"
      )

    Repo.update!(
      Changeset.change(resource,
        identifiers: ["future.example.com"],
        key_policy: "rsa_2048",
        current_version_id: version.id
      )
    )

    assert Managed.list_published_certificates() == [
             %{
               id: version.id,
               managed_certificate_id: resource.id,
               name: "gsmlg.net",
               slug: resource.slug,
               publication_sequence: 1,
               environment: "production",
               fingerprint: version.fingerprint,
               identifiers: ["gsmlg.net", "www.gsmlg.net"],
               not_before: version.not_before,
               not_after: version.not_after,
               key_policy: "ec_p256",
               inserted_at: version.inserted_at,
               quarantined_at: nil,
               revocation_state: "none",
               current: true
             }
           ]
  end

  test "legacy names and an absent current pointer preserve nil name and false current", c do
    resource = insert_resource(c.account)
    version = insert_version(resource, c.secret, 1)

    assert [%{id: id, name: nil, slug: slug, current: false}] =
             Managed.list_published_certificates()

    assert id == version.id
    assert slug == resource.slug
  end

  test "configured resources without a published generation do not appear", c do
    insert_resource(c.account, name: "Not issued")
    assert Managed.list_published_certificates() == []
  end

  defp insert_resource(account, attrs \\ []) do
    %ManagedCertificate{
      slug: "inventory-#{Ecto.UUID.generate()}",
      account_id: account.id,
      identifiers: ["configured.example.com"],
      bindings: []
    }
    |> struct(attrs)
    |> Repo.insert!()
  end

  defp insert_version(resource, secret, sequence, attrs \\ []) do
    order =
      Repo.insert!(%AcmeOrder{
        managed_certificate_id: resource.id,
        request_id: Ecto.UUID.generate(),
        request_digest: "inventory-fixture",
        configuration_revision: 1,
        state: "published",
        phase: "published",
        identifiers: resource.identifiers,
        bindings: [],
        account_snapshot: %{"id" => resource.account_id, "environment" => "production"},
        deadline_at: DateTime.add(Managed.now(), 86_400)
      })

    %ManagedCertificateVersion{
      managed_certificate_id: resource.id,
      order_id: order.id,
      publication_sequence: sequence,
      environment: "production",
      fingerprint: "inventory-fingerprint-#{sequence}",
      certificate_pem: "public-certificate-fixture-must-not-be-selected",
      chain_pem: "public-chain-fixture-must-not-be-selected",
      fullchain_pem: "public-fullchain-fixture-must-not-be-selected",
      identifiers: ["issued.example.com"],
      not_before: DateTime.add(Managed.now(), -86_400),
      not_after: DateTime.add(Managed.now(), 86_400),
      key_policy: "ec_p256",
      output_secret_id: secret.id,
      secret_version_number: sequence
    }
    |> struct(attrs)
    |> Repo.insert!()
  end
end
