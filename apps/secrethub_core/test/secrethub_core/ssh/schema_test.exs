defmodule SecretHub.Core.SSH.SchemaTest do
  use ExUnit.Case, async: false
  alias SecretHub.Core.{Repo, RuntimeDatabaseFixture}
  alias SecretHub.Shared.Schemas.Agent
  alias SecretHub.Shared.Schemas.SSH.{Identity, IdentityKey}

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags)
  end

  test "identities hold public keys only and enforce origin shape" do
    Repo.insert!(%Agent{agent_id: "laptop", name: "laptop", status: :trusted_connected})
    refute :private_key_encrypted in Identity.__schema__(:fields)

    agent = %Identity{
      id: Ecto.UUID.generate(),
      name: "gao@laptop",
      origin: "agent",
      agent_id: "laptop",
      local_username: "gao",
      local_uid: 1000,
      status: "pending"
    }

    assert {:ok, stored} = Repo.insert(agent)

    assert {:ok, _} =
             Repo.insert(%IdentityKey{
               id: Ecto.UUID.generate(),
               identity_id: stored.id,
               generation: 1,
               public_key: "ssh-ed25519 AAAA",
               fingerprint: "SHA256:one"
             })

    assert [%IdentityKey{generation: 1}] =
             Repo.preload(Repo.get!(Identity, stored.id), :keys).keys

    invalid = %Identity{
      id: Ecto.UUID.generate(),
      name: "broken",
      origin: "external",
      agent_id: "laptop",
      status: "active"
    }

    assert_raise Ecto.ConstraintError, fn -> Repo.insert(invalid) end
  end

  test "legacy rules are cleared by the migration" do
    assert %{rules: []} = Repo.get!(SecretHub.Shared.Schemas.SSH.Inventory, 1)
  end
end
