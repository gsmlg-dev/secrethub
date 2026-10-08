defmodule SecretHub.Human.Organizations do
  @moduledoc "Encrypted organization vaults. Membership removal denies access and queues Core lease revocation."
  import Ecto.Query
  alias Ecto.Changeset
  alias SecretHub.Human.{Accounts, Audit, Repo, Vault}

  alias SecretHub.Human.Organizations.{
    Collection,
    DynamicReference,
    Membership,
    Organization,
    Permission,
    RevokeMembership,
    SharedItem
  }

  alias SecretHub.Human.Schemas.User
  alias SecretHub.Human.Vault.Envelope

  def create(actor, attrs) do
    command(actor, fn ->
      name = encrypted!(value(attrs, :name))
      key = encrypted_key!(value(attrs, :encrypted_key))
      organization = Repo.insert!(%Organization{name: name})

      member =
        Repo.insert!(%Membership{
          organization_id: organization.id,
          user_id: actor.user_id,
          role: "owner",
          encrypted_key: key
        })

      audit!("human.organization.created", actor, %{organization_id: organization.id})
      organization_dto(organization, member)
    end)
  end

  def list(actor) do
    command(actor, fn ->
      Repo.all(
        from(o in Organization,
          join: m in Membership,
          on: m.organization_id == o.id,
          where: m.user_id == ^actor.user_id and is_nil(m.removed_at),
          order_by: o.id,
          select: {o, m}
        )
      )
      |> Enum.map(fn {o, m} -> organization_dto(o, m) end)
    end)
  end

  def memberships(actor) do
    command(actor, fn ->
      Repo.all(
        from(m in Membership,
          where: m.user_id == ^actor.user_id and is_nil(m.removed_at),
          order_by: m.organization_id,
          select: m.organization_id
        )
      )
    end)
  end

  def list_members(actor, organization_id) do
    command(actor, fn ->
      member = member!(actor, organization_id)
      administrator!(member)

      Repo.all(
        from(m in Membership,
          where: m.organization_id == ^member.organization_id and is_nil(m.removed_at),
          order_by: m.id
        )
      )
      |> Enum.map(&member_dto/1)
    end)
  end

  def add_member(actor, organization_id, attrs) do
    command(actor, fn ->
      acting = member!(actor, organization_id)
      administrator!(acting)
      user_id = uuid!(value(attrs, :user_id))
      role = value(attrs, :role, "member")
      unless role in ["owner", "admin", "member"], do: Repo.rollback(:invalid_input)
      key = encrypted_key!(value(attrs, :encrypted_key))

      unless Repo.exists?(from(u in User, where: u.id == ^user_id and is_nil(u.disabled_at))),
        do: Repo.rollback(:not_found)

      existing =
        Repo.get_by(Membership, organization_id: acting.organization_id, user_id: user_id)

      authorize_owner_change!(acting, existing, role)
      preserve_owner_change!(existing, role)
      membership = upsert_membership(existing, acting.organization_id, user_id, role, key)

      audit!("human.organization.member.added", actor, %{
        organization_id: acting.organization_id,
        user_id: user_id
      })

      member_dto(membership)
    end)
  end

  def remove_member(actor, organization_id, user_id, opts \\ []) do
    result =
      command(actor, fn ->
        acting = member!(actor, organization_id)
        administrator!(acting)
        subject = uuid!(user_id)

        target =
          Repo.one(
            from(m in Membership,
              where:
                m.organization_id == ^acting.organization_id and m.user_id == ^subject and
                  is_nil(m.removed_at)
            )
          )

        removable_member!(acting, target)
        Repo.update!(Changeset.change(target, removed_at: DateTime.utc_now()))

        collections =
          from(c in Collection, where: c.organization_id == ^acting.organization_id, select: c.id)

        Repo.delete_all(
          from(p in Permission,
            where: p.user_id == ^subject and p.collection_id in subquery(collections)
          )
        )

        job =
          RevokeMembership.new(%{
            "organization_id" => acting.organization_id,
            "subject_id" => subject
          })

        enqueue_revocation!(job)

        audit!("human.organization.member.removed", actor, %{
          organization_id: acting.organization_id,
          user_id: subject
        })

        {acting.organization_id, subject}
      end)

    case result do
      {:ok, {org, subject}} ->
        # Job was persisted in the Human transaction before this separate Core side effect.
        RevokeMembership.revoke(org, subject, Keyword.get(opts, :core_adapter, SecretHub.Access))
        :ok

      {:error, _} = error ->
        error
    end
  end

  def create_collection(actor, organization_id, attrs) do
    command(actor, fn ->
      member = member!(actor, organization_id)
      administrator!(member)

      collection =
        Repo.insert!(%Collection{
          organization_id: member.organization_id,
          name: encrypted!(value(attrs, :name))
        })

      audit!("human.collection.created", actor, %{
        organization_id: member.organization_id,
        collection_id: collection.id
      })

      collection_dto(collection)
    end)
  end

  def list_collections(actor, organization_id) do
    command(actor, fn ->
      member = member!(actor, organization_id)

      Repo.all(
        from(c in Collection, where: c.organization_id == ^member.organization_id, order_by: c.id)
      )
      |> Enum.filter(&permitted?(member, &1, :read))
      |> Enum.map(&collection_dto/1)
    end)
  end

  def update_collection(actor, id, attrs) do
    command(actor, fn ->
      {collection, member} = collection!(actor, id, :read)
      administrator!(member)
      updated = Repo.update!(Changeset.change(collection, name: encrypted!(value(attrs, :name))))

      audit!("human.collection.updated", actor, %{
        organization_id: member.organization_id,
        collection_id: id
      })

      collection_dto(updated)
    end)
  end

  def set_collection_permission(actor, id, attrs) do
    command(actor, fn ->
      {collection, member} = collection!(actor, id, :read)
      administrator!(member)
      user_id = uuid!(value(attrs, :user_id))
      can_read = value(attrs, :can_read, false)
      can_write = value(attrs, :can_write, false)

      unless is_boolean(can_read) and is_boolean(can_write) and (not can_write or can_read),
        do: Repo.rollback(:invalid_input)

      unless Repo.exists?(
               from(m in Membership,
                 where:
                   m.organization_id == ^member.organization_id and m.user_id == ^user_id and
                     is_nil(m.removed_at)
               )
             ),
             do: Repo.rollback(:not_found)

      existing = Repo.get_by(Permission, collection_id: collection.id, user_id: user_id)

      permission =
        if existing do
          Repo.update!(Changeset.change(existing, can_read: can_read, can_write: can_write))
        else
          Repo.insert!(%Permission{
            collection_id: collection.id,
            user_id: user_id,
            can_read: can_read,
            can_write: can_write
          })
        end

      audit!("human.collection.updated", actor, %{
        organization_id: member.organization_id,
        collection_id: id,
        user_id: user_id
      })

      Map.take(permission, [:id, :collection_id, :user_id, :can_read, :can_write])
    end)
  end

  def share_item(actor, collection_id, personal_item_id, attrs) do
    command(actor, fn ->
      {collection, _} = collection!(actor, collection_id, :write)

      personal =
        case Vault.get_item(actor, personal_item_id) do
          {:ok, item} -> item
          {:error, reason} -> Repo.rollback(reason)
        end

      ciphertext = payload!(value(attrs, :ciphertext))
      # Organization keys are client-owned. Explicit fresh ciphertext is mandatory.
      if ciphertext == personal.ciphertext, do: Repo.rollback(:invalid_ciphertext)

      item =
        Repo.insert!(%SharedItem{
          organization_id: collection.organization_id,
          collection_id: collection.id,
          type: personal.type,
          ciphertext: ciphertext,
          revision: 1
        })

      audit!("human.collection.item.shared", actor, %{
        organization_id: item.organization_id,
        collection_id: item.collection_id,
        item_id: item.id
      })

      item_dto(item)
    end)
  end

  def get_item(actor, id), do: command(actor, fn -> item!(actor, id, :read) |> item_dto() end)

  def list_items(actor, collection_id) do
    command(actor, fn ->
      {collection, _} = collection!(actor, collection_id, :read)

      Repo.all(
        from(i in SharedItem,
          where: i.collection_id == ^collection.id and is_nil(i.deleted_at),
          order_by: i.id
        )
      )
      |> Enum.map(&item_dto/1)
    end)
  end

  def update_item(actor, id, attrs) do
    command(actor, fn ->
      item = item!(actor, id, :write)
      expected = value(attrs, :expected_revision)
      unless is_nil(expected) or expected == item.revision, do: Repo.rollback(:conflict)

      updated =
        Repo.update!(
          Changeset.change(item,
            ciphertext: payload!(value(attrs, :ciphertext)),
            revision: item.revision + 1
          )
        )

      audit!("human.vault.item.updated", actor, %{
        organization_id: item.organization_id,
        collection_id: item.collection_id,
        item_id: id,
        revision: updated.revision
      })

      item_dto(updated)
    end)
  end

  def delete_item(actor, id) do
    command(actor, fn ->
      item = item!(actor, id, :write)

      deleted =
        Repo.update!(
          Changeset.change(item, deleted_at: DateTime.utc_now(), revision: item.revision + 1)
        )

      audit!("human.vault.item.deleted", actor, %{
        organization_id: item.organization_id,
        collection_id: item.collection_id,
        item_id: id,
        revision: deleted.revision
      })

      item_dto(deleted)
    end)
  end

  def create_dynamic_reference(actor, collection_id, attrs) do
    command(actor, fn ->
      {collection, _} = collection!(actor, collection_id, :write)

      unless is_map(attrs) and
               Enum.all?(
                 Map.keys(attrs),
                 &(&1 in [
                     :mount_id,
                     :role_id,
                     :requested_ttl,
                     "mount_id",
                     "role_id",
                     "requested_ttl"
                   ])
               ),
             do: Repo.rollback(:invalid_input)

      mount = value(attrs, :mount_id)
      role = value(attrs, :role_id)
      ttl = value(attrs, :requested_ttl)

      unless safe_id?(mount) and safe_id?(role) and is_integer(ttl) and ttl in 1..86_400,
        do: Repo.rollback(:invalid_input)

      reference =
        Repo.insert!(%DynamicReference{
          organization_id: collection.organization_id,
          collection_id: collection.id,
          mount_id: mount,
          role_id: role,
          requested_ttl: ttl
        })

      audit!("human.collection.updated", actor, %{
        organization_id: collection.organization_id,
        collection_id: collection.id,
        mount_id: mount,
        role_id: role
      })

      reference_dto(reference)
    end)
  end

  def list_dynamic_references(actor, collection_id) do
    command(actor, fn ->
      {collection, _} = collection!(actor, collection_id, :read)

      Repo.all(
        from(r in DynamicReference, where: r.collection_id == ^collection.id, order_by: r.id)
      )
      |> Enum.map(&reference_dto/1)
    end)
  end

  defp command(actor, fun) do
    Repo.transaction(fn ->
      case Accounts.authorize_actor(actor) do
        {:ok, _} -> fun.()
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  defp member!(actor, organization_id) do
    id = uuid!(organization_id)
    # One organization lock serializes membership removal with permission checks and writes.
    unless Repo.one(from(o in Organization, where: o.id == ^id, lock: "FOR UPDATE")),
      do: Repo.rollback(:not_found)

    case Repo.one(
           from(m in Membership,
             where:
               m.organization_id == ^id and m.user_id == ^actor.user_id and is_nil(m.removed_at)
           )
         ) do
      nil -> Repo.rollback(:not_found)
      member -> member
    end
  end

  defp administrator!(%Membership{role: role}) when role in ["owner", "admin"], do: :ok
  defp administrator!(_), do: Repo.rollback(:unauthorized)

  defp authorize_owner_change!(%Membership{role: "owner"}, _existing, _role), do: :ok

  defp authorize_owner_change!(_acting, %Membership{role: "owner"}, _role),
    do: Repo.rollback(:unauthorized)

  defp authorize_owner_change!(_acting, _existing, "owner"), do: Repo.rollback(:unauthorized)
  defp authorize_owner_change!(_acting, _existing, _role), do: :ok

  defp preserve_owner_change!(%Membership{role: "owner", removed_at: nil} = member, role)
       when role != "owner",
       do: preserve_owner!(member)

  defp preserve_owner_change!(_member, _role), do: :ok

  defp upsert_membership(nil, organization_id, user_id, role, key),
    do:
      Repo.insert!(%Membership{
        organization_id: organization_id,
        user_id: user_id,
        role: role,
        encrypted_key: key
      })

  defp upsert_membership(existing, _organization_id, _user_id, role, key),
    do: Repo.update!(Changeset.change(existing, role: role, encrypted_key: key, removed_at: nil))

  defp removable_member!(_acting, nil), do: Repo.rollback(:not_found)

  defp removable_member!(%Membership{role: role}, %Membership{role: "owner"})
       when role != "owner",
       do: Repo.rollback(:unauthorized)

  defp removable_member!(_acting, %Membership{role: "owner"} = member),
    do: preserve_owner!(member)

  defp removable_member!(_acting, _member), do: :ok

  defp enqueue_revocation!(job) do
    case Oban.insert(SecretHub.Human.Oban, job) do
      {:ok, _} -> :ok
      {:error, _} -> Repo.rollback(:revocation_unavailable)
    end
  end

  defp preserve_owner!(member) do
    count =
      Repo.aggregate(
        from(m in Membership,
          where:
            m.organization_id == ^member.organization_id and m.role == "owner" and
              is_nil(m.removed_at)
        ),
        :count
      )

    if count <= 1, do: Repo.rollback(:last_owner)
  end

  defp collection!(actor, id, operation) do
    id = uuid!(id)
    collection = Repo.get(Collection, id)
    if is_nil(collection), do: Repo.rollback(:not_found)
    member = member!(actor, collection.organization_id)
    unless permitted?(member, collection, operation), do: Repo.rollback(:unauthorized)
    {collection, member}
  end

  defp permitted?(%Membership{role: role}, _collection, _) when role in ["owner", "admin"],
    do: true

  defp permitted?(member, collection, operation) do
    permission = Repo.get_by(Permission, collection_id: collection.id, user_id: member.user_id)

    not is_nil(permission) and permission.can_read and
      (operation == :read or permission.can_write)
  end

  defp item!(actor, id, operation) do
    id = uuid!(id)
    item = Repo.get(SharedItem, id)
    if is_nil(item) or not is_nil(item.deleted_at), do: Repo.rollback(:not_found)
    collection!(actor, item.collection_id, operation)
    Repo.one!(from(i in SharedItem, where: i.id == ^id, lock: "FOR UPDATE"))
  end

  defp encrypted!(input),
    do: if(Envelope.valid?(input), do: input, else: Repo.rollback(:invalid_ciphertext))

  defp encrypted_key!(input) do
    valid = Envelope.valid?(input) or rsa_key?(input)
    if valid, do: input, else: Repo.rollback(:invalid_ciphertext)
  end

  defp rsa_key?(<<type, ?., encoded::binary>>)
       when type in [?3, ?4] and byte_size(encoded) <= 684 do
    case Base.decode64(encoded) do
      {:ok, bytes} -> byte_size(bytes) in [256, 512]
      :error -> false
    end
  end

  defp rsa_key?(_), do: false

  defp payload!(input),
    do: if(Envelope.valid_payload?(input), do: input, else: Repo.rollback(:invalid_ciphertext))

  defp uuid!(input) do
    case Ecto.UUID.cast(input) do
      {:ok, id} -> id
      :error -> Repo.rollback(:not_found)
    end
  end

  defp audit!(event, actor, data) do
    case Audit.record(event, actor, data) do
      {:ok, _} -> :ok
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp organization_dto(organization, member),
    do: %{
      id: organization.id,
      name: organization.name,
      role: member.role,
      encrypted_key: member.encrypted_key
    }

  defp member_dto(member),
    do: Map.take(member, [:id, :organization_id, :user_id, :role, :encrypted_key])

  defp collection_dto(collection), do: Map.take(collection, [:id, :organization_id, :name])

  defp item_dto(item),
    do:
      Map.take(item, [
        :id,
        :organization_id,
        :collection_id,
        :type,
        :ciphertext,
        :revision,
        :deleted_at,
        :inserted_at,
        :updated_at
      ])

  defp reference_dto(reference),
    do:
      Map.take(reference, [
        :id,
        :organization_id,
        :collection_id,
        :mount_id,
        :role_id,
        :requested_ttl
      ])

  defp value(attrs, key, default \\ nil),
    do: Map.get(attrs, key, Map.get(attrs, Atom.to_string(key), default))

  defp safe_id?(input),
    do: is_binary(input) and Regex.match?(~r/\A[a-zA-Z0-9_\/-]{1,128}\z/, input)
end
