defmodule SecretHub.Human.Organizations.FailingCore do
  def revoke_organization_membership(_, _), do: {:error, :backend_unavailable}
end

defmodule SecretHub.Human.OrganizationsTest do
  use SecretHub.Human.DataCase, async: true
  alias SecretHub.Human.{Accounts, Organizations, RateLimiter, Vault}

  defp encrypted do
    "2." <> Enum.map_join([16, 16, 32], "|", &Base.encode64(:crypto.strong_rand_bytes(&1)))
  end

  defp actor do
    input = %{
      email: "org-#{System.unique_integer([:positive])}@example.test",
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

  defp organization(owner) do
    assert {:ok, organization} =
             Organizations.create(owner, %{name: encrypted(), encrypted_key: encrypted()})

    organization
  end

  test "organization creation keeps encrypted owner key and session-derived memberships" do
    owner = actor()
    organization = organization(owner)
    assert {:ok, [id]} = Organizations.memberships(owner)
    assert id == organization.id
    assert {:ok, [dto]} = Organizations.list(owner)
    assert dto.role == "owner"
    assert dto.encrypted_key == organization.encrypted_key
    assert {:error, :unauthenticated} = Organizations.memberships(%{user_id: owner.user_id})
    assert :ok = Accounts.revoke_session(owner, owner.session_id)
    assert {:error, :unauthenticated} = Organizations.list(owner)
  end

  test "only organization administrators can add members with bounded encrypted envelopes" do
    owner = actor()
    member = actor()
    outsider = actor()
    organization = organization(owner)

    assert {:error, :not_found} =
             Organizations.add_member(outsider, organization.id, %{
               user_id: member.user_id,
               encrypted_key: encrypted(),
               role: "member"
             })

    assert {:error, :invalid_ciphertext} =
             Organizations.add_member(owner, organization.id, %{
               user_id: member.user_id,
               encrypted_key: "plaintext",
               role: "member"
             })

    rsa_key = "3." <> Base.encode64(:crypto.strong_rand_bytes(256))

    assert {:ok, membership} =
             Organizations.add_member(owner, organization.id, %{
               user_id: member.user_id,
               encrypted_key: rsa_key,
               role: "member"
             })

    assert membership.role == "member"
    assert {:ok, [id]} = Organizations.memberships(member)
    assert id == organization.id

    assert {:error, :unauthorized} =
             Organizations.add_member(member, organization.id, %{
               user_id: outsider.user_id,
               encrypted_key: encrypted(),
               role: "admin"
             })
  end

  test "collection access is permission-scoped and write permission requires read" do
    owner = actor()
    member = actor()
    organization = organization(owner)

    assert {:ok, _} =
             Organizations.add_member(owner, organization.id, %{
               user_id: member.user_id,
               encrypted_key: encrypted(),
               role: "member"
             })

    assert {:ok, collection} =
             Organizations.create_collection(owner, organization.id, %{name: encrypted()})

    assert {:ok, []} = Organizations.list_collections(member, organization.id)

    assert {:error, :invalid_input} =
             Organizations.set_collection_permission(owner, collection.id, %{
               user_id: member.user_id,
               can_read: false,
               can_write: true
             })

    assert {:ok, _} =
             Organizations.set_collection_permission(owner, collection.id, %{
               user_id: member.user_id,
               can_read: true,
               can_write: false
             })

    assert {:ok, [dto]} = Organizations.list_collections(member, organization.id)
    assert dto.id == collection.id

    assert {:error, :unauthorized} =
             Organizations.update_collection(member, collection.id, %{name: encrypted()})
  end

  test "sharing requires fresh organization-key ciphertext and never copies personal payload" do
    owner = actor()
    member = actor()
    organization = organization(owner)

    {:ok, _} =
      Organizations.add_member(owner, organization.id, %{
        user_id: member.user_id,
        encrypted_key: encrypted(),
        role: "member"
      })

    {:ok, collection} =
      Organizations.create_collection(owner, organization.id, %{name: encrypted()})

    {:ok, _} =
      Organizations.set_collection_permission(owner, collection.id, %{
        user_id: member.user_id,
        can_read: true,
        can_write: false
      })

    personal_payload = %{"name" => encrypted(), "login" => %{"password" => encrypted()}}
    {:ok, item} = Vault.create_item(owner, %{type: "login", ciphertext: personal_payload})

    assert {:error, :invalid_ciphertext} =
             Organizations.share_item(owner, collection.id, item.id, %{})

    organization_payload = %{"name" => encrypted(), "login" => %{"password" => encrypted()}}

    assert {:ok, shared} =
             Organizations.share_item(owner, collection.id, item.id, %{
               ciphertext: organization_payload
             })

    assert shared.ciphertext == organization_payload
    refute shared.ciphertext == personal_payload
    assert shared.organization_id == organization.id
    assert {:ok, fetched} = Organizations.get_item(member, shared.id)
    assert fetched.id == shared.id

    assert {:error, :unauthorized} =
             Organizations.update_item(member, shared.id, %{ciphertext: %{"name" => encrypted()}})
  end

  test "membership removal denies future reads and persists UUID-only revocation retry" do
    owner = actor()
    member = actor()
    organization = organization(owner)

    {:ok, _} =
      Organizations.add_member(owner, organization.id, %{
        user_id: member.user_id,
        encrypted_key: encrypted(),
        role: "member"
      })

    {:ok, collection} =
      Organizations.create_collection(owner, organization.id, %{name: encrypted()})

    {:ok, _} =
      Organizations.set_collection_permission(owner, collection.id, %{
        user_id: member.user_id,
        can_read: true,
        can_write: true
      })

    assert :ok =
             Organizations.remove_member(owner, organization.id, member.user_id,
               core_adapter: SecretHub.Human.Organizations.FailingCore
             )

    assert {:ok, []} = Organizations.memberships(member)
    assert {:error, :not_found} = Organizations.list_collections(member, organization.id)

    jobs =
      Repo.all(
        from(j in Oban.Job, where: j.worker == "SecretHub.Human.Organizations.RevokeMembership")
      )

    assert [%{args: %{"organization_id" => id, "subject_id" => subject}}] = jobs
    assert id == organization.id
    assert subject == member.user_id
  end

  test "last owner cannot be removed and admins cannot promote themselves to owner" do
    owner = actor()
    admin = actor()
    organization = organization(owner)

    assert {:error, :last_owner} =
             Organizations.remove_member(owner, organization.id, owner.user_id)

    {:ok, _} =
      Organizations.add_member(owner, organization.id, %{
        user_id: admin.user_id,
        encrypted_key: encrypted(),
        role: "admin"
      })

    assert {:error, :unauthorized} =
             Organizations.add_member(admin, organization.id, %{
               user_id: admin.user_id,
               encrypted_key: encrypted(),
               role: "owner"
             })

    assert {:error, :unauthorized} =
             Organizations.remove_member(admin, organization.id, owner.user_id)
  end

  test "shared dynamic references contain policy identifiers without issued credential values" do
    owner = actor()
    organization = organization(owner)

    {:ok, collection} =
      Organizations.create_collection(owner, organization.id, %{name: encrypted()})

    assert {:ok, reference} =
             Organizations.create_dynamic_reference(owner, collection.id, %{
               mount_id: "postgres-team",
               role_id: "reader",
               requested_ttl: 120
             })

    assert reference.organization_id == organization.id
    assert {:ok, [^reference]} = Organizations.list_dynamic_references(owner, collection.id)

    assert {:error, :invalid_input} =
             Organizations.create_dynamic_reference(owner, collection.id, %{
               mount_id: "postgres-team",
               role_id: "reader",
               requested_ttl: 120,
               password: "never-persist"
             })
  end

  test "removed and re-added members do not regain stale collection permissions" do
    owner = actor()
    member = actor()
    organization = organization(owner)
    member_attrs = %{user_id: member.user_id, encrypted_key: encrypted(), role: "member"}
    {:ok, _} = Organizations.add_member(owner, organization.id, member_attrs)

    {:ok, collection} =
      Organizations.create_collection(owner, organization.id, %{name: encrypted()})

    {:ok, _} =
      Organizations.set_collection_permission(owner, collection.id, %{
        user_id: member.user_id,
        can_read: true,
        can_write: true
      })

    assert :ok =
             Organizations.remove_member(owner, organization.id, member.user_id,
               core_adapter: SecretHub.Human.Organizations.FailingCore
             )

    {:ok, _} = Organizations.add_member(owner, organization.id, member_attrs)
    assert {:ok, []} = Organizations.list_collections(member, organization.id)
    assert {:error, :unauthorized} = Organizations.list_dynamic_references(member, collection.id)
  end

  test "write-authorized members update and delete shared items with revision conflicts" do
    owner = actor()
    member = actor()
    organization = organization(owner)

    {:ok, _} =
      Organizations.add_member(owner, organization.id, %{
        user_id: member.user_id,
        encrypted_key: encrypted(),
        role: "member"
      })

    {:ok, collection} =
      Organizations.create_collection(owner, organization.id, %{name: encrypted()})

    {:ok, _} =
      Organizations.set_collection_permission(owner, collection.id, %{
        user_id: member.user_id,
        can_read: true,
        can_write: true
      })

    payload = %{"name" => encrypted()}
    {:ok, personal} = Vault.create_item(owner, %{type: "secure_note", ciphertext: payload})

    assert {:error, :invalid_ciphertext} =
             Organizations.share_item(owner, collection.id, personal.id, %{ciphertext: payload})

    {:ok, shared} =
      Organizations.share_item(owner, collection.id, personal.id, %{
        ciphertext: %{"name" => encrypted()}
      })

    assert {:error, :conflict} =
             Organizations.update_item(member, shared.id, %{
               ciphertext: %{"name" => encrypted()},
               expected_revision: 0
             })

    assert {:ok, updated} =
             Organizations.update_item(member, shared.id, %{
               ciphertext: %{"name" => encrypted()},
               expected_revision: shared.revision
             })

    assert updated.revision == shared.revision + 1
    assert {:ok, [^updated]} = Organizations.list_items(member, collection.id)
    assert {:ok, deleted} = Organizations.delete_item(member, shared.id)
    assert deleted.deleted_at != nil
    assert {:error, :not_found} = Organizations.get_item(owner, shared.id)
    assert {:ok, []} = Organizations.list_items(owner, collection.id)
  end

  test "owner demotion and malformed RSA member envelopes are rejected" do
    owner = actor()
    member = actor()
    organization = organization(owner)

    assert {:error, :last_owner} =
             Organizations.add_member(owner, organization.id, %{
               user_id: owner.user_id,
               encrypted_key: encrypted(),
               role: "member"
             })

    for envelope <- [
          "3.bad",
          "4." <> Base.encode64(:crypto.strong_rand_bytes(128)),
          "5." <> Base.encode64(:crypto.strong_rand_bytes(256))
        ] do
      assert {:error, :invalid_ciphertext} =
               Organizations.add_member(owner, organization.id, %{
                 user_id: member.user_id,
                 encrypted_key: envelope,
                 role: "member"
               })
    end

    assert {:ok, [%{user_id: user_id, role: "owner"}]} =
             Organizations.list_members(owner, organization.id)

    assert user_id == owner.user_id
  end
end
