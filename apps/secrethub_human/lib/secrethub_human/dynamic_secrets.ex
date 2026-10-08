defmodule SecretHub.Human.DynamicSecrets do
  @moduledoc "Human orchestration over the public Core boundary. Persists references and lease metadata only."
  import Ecto.Query
  alias SecretHub.Human.Accounts
  alias SecretHub.Human.Audit
  alias SecretHub.Human.DynamicSecrets.Lease
  alias SecretHub.Human.DynamicSecrets.Reference
  alias SecretHub.Human.Organizations
  alias SecretHub.Human.Repo
  alias SecretHub.Human.RevealStore
  alias SecretHub.HumanWeb.Bitwarden.Token

  def capabilities(token, opts \\ []), do: boundary(opts).list_capabilities(token)

  def create_reference(token, attrs, opts \\ []) do
    with {:ok, actor} <- Token.authenticate(token),
         {:ok, capabilities} <- capabilities(token, opts),
         mount when is_binary(mount) <- value(attrs, :mount_id),
         role when is_binary(role) <- value(attrs, :role_id),
         ttl when is_integer(ttl) <- value(attrs, :requested_ttl),
         true <-
           Enum.any?(
             capabilities,
             &(&1.mount_id == mount and &1.role_id == role and ttl in 1..&1.max_ttl)
           ),
         name <- value(attrs, :display_name),
         true <- is_nil(name) or (is_binary(name) and byte_size(name) <= 200) do
      %Reference{
        user_id: actor.user_id,
        mount_id: mount,
        role_id: role,
        requested_ttl: ttl,
        display_name: name
      }
      |> Repo.insert()
      |> public_result()
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_input}
    end
  end

  def references(token) do
    with {:ok, actor} <- Token.authenticate(token),
         do:
           {:ok,
            Repo.all(from(r in Reference, where: r.user_id == ^actor.user_id))
            |> Enum.map(&reference_dto/1)}
  end

  def request(token, id, attrs, opts \\ []) do
    with {:ok, actor} <- Token.authenticate(token),
         {:ok, ref} <- reference(actor, id),
         request = %{
           mount_id: ref.mount_id,
           role_id: ref.role_id,
           requested_ttl: value(attrs, :requested_ttl, ref.requested_ttl),
           request_id: value(attrs, :request_id),
           approval_id: value(attrs, :approval_id)
         },
         {:ok, _} <- boundary(opts).authorize(token, request),
         {:ok, issued} <- boundary(opts).issue_dynamic_secret(token, request) do
      handoff(actor, issued, opts)
    end
  end

  def request_shared(token, collection_id, reference_id, attrs, opts \\ []) do
    with {:ok, actor} <- Token.authenticate(token),
         {:ok, request} <- shared_request(actor, collection_id, reference_id, attrs),
         {:ok, _} <- boundary(opts).authorize(token, request),
         {:ok, issued} <- boundary(opts).issue_dynamic_secret(token, request) do
      handoff(actor, issued, opts)
    end
  end

  def request_shared_approval(token, collection_id, reference_id, attrs, opts \\ []) do
    with {:ok, actor} <- Token.authenticate(token),
         {:ok, request} <- shared_request(actor, collection_id, reference_id, attrs),
         do: boundary(opts).request_approval(token, request)
  end

  defp shared_request(actor, collection_id, reference_id, attrs) do
    with {:ok, references} <-
           Organizations.list_dynamic_references(actor, collection_id),
         reference when not is_nil(reference) <- Enum.find(references, &(&1.id == reference_id)) do
      {:ok,
       %{
         mount_id: reference.mount_id,
         role_id: reference.role_id,
         requested_ttl: value(attrs, :requested_ttl, reference.requested_ttl),
         organization_id: reference.organization_id,
         request_id: value(attrs, :request_id),
         approval_id: value(attrs, :approval_id)
       }}
    else
      {:error, _} = error -> error
      _ -> {:error, :not_found}
    end
  end

  def reveal(token, reveal_token, opts \\ []) do
    result =
      with {:ok, actor} <- Token.authenticate(token) do
        RevealStore.redeem_guarded(
          reveal_token,
          actor,
          fn id ->
            authorize_reveal(token, actor, id, opts)
          end,
          server: store(opts)
        )
      end

    if match?({:error, _}, result),
      do:
        Audit.record("human.dynamic_secret.reveal_failed", nil, %{
          result: "failure",
          reason: "invalid_reveal"
        })

    result
  end

  defp authorize_reveal(token, actor, id, opts) do
    with {:ok, %{status: "active", expires_at: expiry}} <-
           boundary(opts).read_lease(token, id),
         true <- DateTime.compare(expiry, DateTime.utc_now()) == :gt,
         {:ok, _} <-
           boundary(opts).record_human_event(
             "human.dynamic_secret.revealed",
             actor.user_id,
             %{lease_id: id, session_id: actor.session_id, device_id: actor.device_id},
             Ecto.UUID.generate()
           ),
         {:ok, ^actor} <- Token.authenticate(token),
         {:ok, %{status: "active", expires_at: fresh_expiry}} <-
           boundary(opts).read_lease(token, id),
         true <- DateTime.compare(fresh_expiry, DateTime.utc_now()) == :gt do
      :ok
    else
      _ -> {:error, :invalid_reveal}
    end
  end

  def stored_leases(actor) do
    with {:ok, _} <- Accounts.authorize_actor(actor) do
      now = DateTime.utc_now()

      rows =
        Repo.all(
          from(l in Lease,
            where:
              l.user_id == ^actor.user_id and l.session_id == ^actor.session_id and
                l.device_id == ^actor.device_id,
            order_by: [desc: l.inserted_at],
            limit: 200
          )
        )

      {:ok,
       Enum.map(rows, fn lease ->
         dto = lease_dto(lease)

         if dto.status == "active" and DateTime.compare(dto.expires_at, now) != :gt,
           do: %{dto | status: "expired"},
           else: dto
       end)}
    end
  end

  def leases(token, opts \\ []) do
    with {:ok, actor} <- Token.authenticate(token),
         {:ok, leases} <- boundary(opts).list_leases(token) do
      Enum.each(leases, &persist_lease(actor, &1))
      {:ok, leases}
    end
  end

  def renew(token, attrs, opts \\ []) do
    with {:ok, actor} <- Token.authenticate(token),
         {:ok, lease} <- boundary(opts).renew_lease(token, attrs),
         {:ok, _} <- persist_lease(actor, lease),
         do: {:ok, lease}
  end

  def revoke(token, id, opts \\ []) do
    with {:ok, actor} <- Token.authenticate(token),
         :ok <- boundary(opts).revoke_lease(token, id) do
      Repo.update_all(from(l in Lease, where: l.id == ^id and l.user_id == ^actor.user_id),
        set: [status: "revoked"]
      )

      :ok
    end
  end

  def request_approval(token, id, attrs, opts \\ []) do
    with {:ok, actor} <- Token.authenticate(token), {:ok, ref} <- reference(actor, id) do
      boundary(opts).request_approval(token, %{
        mount_id: ref.mount_id,
        role_id: ref.role_id,
        requested_ttl: value(attrs, :requested_ttl, ref.requested_ttl),
        request_id: value(attrs, :request_id)
      })
    end
  end

  def approvals(token, opts \\ []), do: boundary(opts).list_approvals(token)
  def approve(token, id, opts \\ []), do: boundary(opts).approve_request(token, id)
  def deny(token, id, opts \\ []), do: boundary(opts).deny_request(token, id)

  defp handoff(actor, %{lease: lease, credentials: credentials}, opts) do
    result =
      with {:ok, _} <- Accounts.authorize_actor(actor),
           {:ok, _} <- persist_lease(actor, lease),
           {:ok, reveal} <- RevealStore.put(actor, lease, credentials, server: store(opts)) do
        {:ok, %{lease: lease, reveal_token: reveal.token, expires_in: reveal.expires_in}}
      end

    if match?({:error, _}, result), do: boundary(opts).abandon_human_lease(lease.id)
    result
  end

  defp persist_lease(actor, lease) do
    params =
      Map.take(lease, [:id, :mount_id, :role_id, :status, :expires_at, :renewable])
      |> Map.merge(%{
        user_id: actor.user_id,
        session_id: actor.session_id,
        device_id: actor.device_id
      })

    Repo.insert(struct(Lease, params),
      on_conflict: {:replace, [:status, :expires_at, :renewable, :updated_at]},
      conflict_target: :id
    )
  end

  defp reference(actor, id) do
    with {:ok, id} <- Ecto.UUID.cast(id),
         %Reference{} = ref <- Repo.get_by(Reference, id: id, user_id: actor.user_id),
         do: {:ok, ref},
         else: (_ -> {:error, :not_found})
  end

  defp boundary(opts), do: Keyword.get(opts, :boundary, SecretHub.Access)
  defp store(opts), do: Keyword.get(opts, :reveal_store, RevealStore)

  defp value(attrs, key, default \\ nil),
    do: Map.get(attrs, key, Map.get(attrs, Atom.to_string(key), default))

  defp reference_dto(ref),
    do: Map.take(ref, [:id, :mount_id, :role_id, :display_name, :requested_ttl])

  defp lease_dto(lease),
    do: Map.take(lease, [:id, :mount_id, :role_id, :status, :expires_at, :renewable])

  defp public_result({:ok, ref}), do: {:ok, reference_dto(ref)}
  defp public_result({:error, _}), do: {:error, :invalid_input}
end
