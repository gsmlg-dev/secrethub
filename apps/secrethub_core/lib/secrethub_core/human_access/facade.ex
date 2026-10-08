defmodule SecretHub.Core.HumanAccess do
  @moduledoc "Core-owned, opt-in Human grants, approvals and metadata-only dynamic leases."
  import Ecto.Query
  alias Ecto.Changeset
  alias SecretHub.Core.HumanAccess.{Approval, Grant, Lease, PostgreSQLBackend}
  alias SecretHub.Core.Repo
  @operations ~w(issue read renew revoke request_approval)
  @unfinished_grace_seconds 30
  @grant_fields [
    :subject_id,
    :organization_id,
    :mount_id,
    :role_id,
    :allowed_operations,
    :max_ttl,
    :require_approval,
    :require_device,
    :require_mfa,
    :approver_subject_ids,
    :enabled
  ]

  def configure_mounts(mounts) when is_map(mounts) do
    with :ok <- validate_mounts(mounts) do
      Application.put_env(:secrethub_core, :human_mounts, mounts)
      :ok
    end
  end

  def configure_mounts(_), do: {:error, :invalid_backend_config}

  def provision_grant(attrs) when is_map(attrs) do
    changeset = grant_changeset(%Grant{}, attrs)

    case Repo.insert(changeset) do
      {:ok, grant} -> {:ok, grant_dto(grant)}
      {:error, _} -> {:error, :invalid_input}
    end
  end

  def provision_grant(_), do: {:error, :invalid_input}

  def update_grant(id, attrs) when is_map(attrs) do
    with {:ok, id} <- uuid(id) do
      Repo.transaction(fn -> update_grant_locked(id, attrs) end)
    end
  end

  def update_grant(_, _), do: {:error, :invalid_input}

  def revoke_grant(id) do
    case update_grant(id, %{enabled: false}) do
      {:ok, _} -> :ok
      {:error, _} = error -> error
    end
  end

  def list_capabilities(token, opts \\ []) do
    with {:ok, principal} <- identity(token, opts) do
      capabilities =
        Repo.all(
          from(g in Grant,
            where:
              (g.subject_id == ^principal.subject_id or g.organization_id in ^principal.groups) and
                g.enabled
          )
        )
        |> Enum.filter(
          &(constraints?(&1, principal) and match?({:ok, _}, mount(&1.mount_id, &1.role_id, opts)))
        )
        |> Enum.map(&capability/1)

      {:ok, capabilities}
    end
  end

  def authorize(token, attrs, opts \\ []) do
    with {:ok, principal} <- identity(token, opts),
         {:ok, request} <- request(attrs, false),
         {:ok, grant} <- allowed_request(principal, request, "issue", opts) do
      {:ok, capability(grant)}
    end
  end

  def issue_dynamic_secret(token, attrs, opts \\ []) do
    with {:ok, principal} <- identity(token, opts),
         {:ok, request} <- request(attrs, true),
         {:ok, grant} <- allowed_request(principal, request, "issue", opts),
         {:ok, backend} <- mount(request.mount_id, request.role_id, opts),
         {:ok, lease} <- reserve(principal, request, grant, opts) do
      issue_reserved(token, request, backend, lease, opts)
    end
  end

  def read_lease(token, id, opts \\ []) do
    with {:ok, principal} <- identity(token, opts),
         {:ok, lease} <- owned_lease(principal, id),
         :ok <- current_membership(principal, lease),
         {:ok, _grant} <- allowed(principal, lease_request(lease), "read", opts) do
      if lease.status == "active" and
           DateTime.compare(lease.expires_at, DateTime.utc_now()) != :gt,
         do: {:error, :lease_expired},
         else: {:ok, lease_dto(lease)}
    end
  end

  def list_leases(token, opts \\ []) do
    with {:ok, principal} <- identity(token, opts) do
      leases =
        Repo.all(
          from(l in Lease,
            where:
              l.subject_id == ^principal.subject_id and l.session_id == ^principal.session_id and
                l.device_id == ^principal.device_id,
            order_by: [desc: l.inserted_at],
            limit: 200
          )
        )

      {:ok,
       leases
       |> Enum.filter(&(current_membership(principal, &1) == :ok))
       |> Enum.map(&lease_dto/1)}
    end
  end

  def renew_lease(token, attrs, opts \\ [])

  def renew_lease(token, attrs, opts) when is_map(attrs) do
    with {:ok, principal} <- identity(token, opts),
         {:ok, lease} <- owned_lease(principal, get(attrs, :lease_id)),
         :ok <- current_membership(principal, lease),
         {:ok, request} <-
           request(
             %{
               mount_id: lease.mount_id,
               role_id: lease.role_id,
               organization_id: lease.organization_id,
               requested_ttl: get(attrs, :requested_ttl)
             },
             false
           ),
         {:ok, _grant} <- allowed(principal, request, "renew", opts),
         {:ok, backend} <- mount(lease.mount_id, lease.role_id, opts) do
      result =
        Repo.transaction(fn -> renew_lease_locked(token, lease, request, backend, opts) end)

      case result do
        {:ok, _} ->
          result

        {:error, reason} when reason in [:audit_unavailable, :unauthenticated, :unauthorized] ->
          compensate(lease, backend)
          result

        _ ->
          result
      end
    end
  end

  def renew_lease(_, _, _), do: {:error, :invalid_input}

  def revoke_lease(token, id, opts \\ []) do
    with {:ok, principal} <- identity(token, opts),
         {:ok, lease} <- owned_lease(principal, id),
         {:ok, backend} <- mount(lease.mount_id, lease.role_id, opts) do
      if lease.status in ["revoked", "expired", "failed"] do
        :ok
      else
        lease |> Changeset.change(status: "revoke_pending") |> Repo.update!()
        revoke_backend(lease, backend, principal, "revoked")
      end
    end
  end

  @doc "Trusted server operation; revoked sessions need no credential to abandon their lease."
  def abandon_lease(id) do
    with {:ok, id} <- uuid(id) do
      Repo.update_all(from(l in Lease, where: l.id == ^id and l.status in ["reserved", "active"]),
        set: [status: "revoke_pending"]
      )

      :ok
    end
  end

  @doc "Trusted Human membership projection change; durable cleanup owns backend revocation."
  def revoke_organization_membership(organization_id, subject_id) do
    with {:ok, org} <- uuid(organization_id), {:ok, subject} <- uuid(subject_id) do
      Repo.update_all(
        from(l in Lease,
          where:
            l.organization_id == ^org and l.subject_id == ^subject and
              l.status in ["reserved", "active"]
        ),
        set: [status: "revoke_pending"]
      )

      :ok
    end
  end

  @doc "Trusted scheduled cleanup; pending failures remain durable for retry."
  def cleanup(opts \\ []) do
    now = DateTime.utc_now()
    unfinished_cutoff = DateTime.add(now, -@unfinished_grace_seconds)

    candidates =
      Repo.all(
        from(l in Lease,
          where:
            (l.status == "revoke_pending" or
               (l.status in ["active", "reserved"] and l.expires_at <= ^now)) and
              (not is_nil(l.issued_at) or l.inserted_at <= ^unfinished_cutoff),
          limit: 200
        )
      )

    results =
      Enum.flat_map(candidates, &cleanup_candidate(&1, opts))

    {:ok, results}
  end

  defp claim_revocation(id) do
    Repo.transaction(fn ->
      current = Repo.one(from(l in Lease, where: l.id == ^id, lock: "FOR UPDATE"))
      now = DateTime.utc_now()

      # A missing role is not final while a bounded backend creation can still be in flight.
      settled =
        not is_nil(current) and
          (not is_nil(current.issued_at) or
             DateTime.compare(current.inserted_at, DateTime.add(now, -@unfinished_grace_seconds)) !=
               :gt)

      if settled and
           (current.status == "revoke_pending" or
              (current.status in ["active", "reserved"] and
                 DateTime.compare(current.expires_at, now) != :gt)) do
        current |> Changeset.change(status: "revoke_pending") |> update!()
      end
    end)
  end

  def request_approval(token, attrs, opts \\ []) do
    with {:ok, principal} <- identity(token, opts),
         {:ok, request} <- request(attrs, true),
         {:ok, grant} <- allowed_request(principal, request, "request_approval", opts) do
      Repo.transaction(fn -> request_approval_locked(principal, request, grant) end)
    end
  end

  def approve_request(token, id, opts \\ []), do: decide(token, id, "approved", opts)
  def deny_request(token, id, opts \\ []), do: decide(token, id, "denied", opts)

  def list_approvals(token, opts \\ []) do
    with {:ok, principal} <- identity(token, opts) do
      approvals =
        Repo.all(
          from(a in Approval,
            join: g in Grant,
            on: g.id == a.grant_id,
            where:
              a.subject_id == ^principal.subject_id or
                ^principal.subject_id in g.approver_subject_ids,
            order_by: [desc: a.inserted_at],
            limit: 200
          )
        )

      {:ok, Enum.map(approvals, &approval_dto/1)}
    end
  end

  defp decide(token, id, status, opts) do
    with {:ok, principal} <- identity(token, opts), {:ok, id} <- uuid(id) do
      Repo.transaction(fn -> decide_locked(principal, id, status) end)
    end
  end

  defp reserve(principal, request, grant, opts) do
    Repo.transaction(fn -> reserve_locked(principal, request, grant, opts) end)
  end

  defp finalize(token, lease, request, opts) do
    Repo.transaction(fn ->
      principal = unwrap!(identity(token, opts))
      grant = unwrap!(allowed_request(principal, request, "issue", opts))
      current = Repo.one(from(l in Lease, where: l.id == ^lease.id, lock: "FOR UPDATE"))

      if current.status != "reserved" or current.grant_id != grant.id or
           current.grant_revision != grant.revision or
           current_membership(principal, current) != :ok,
         do: Repo.rollback(:unauthorized)

      updated =
        current |> Changeset.change(status: "active", issued_at: DateTime.utc_now()) |> update!()

      audit!(
        "human.dynamic_secret.issued",
        principal,
        %{
          lease_id: lease.id,
          request_id: lease.request_id,
          mount_id: lease.mount_id,
          role_id: lease.role_id,
          ttl: request.requested_ttl
        },
        opts
      )

      updated
    end)
  rescue
    _error in [
      Postgrex.Error,
      DBConnection.ConnectionError,
      Ecto.ConstraintError,
      Ecto.InvalidChangesetError
    ] ->
      {:error, :metadata_unavailable}
  end

  defp consume_approval!(principal, request, grant) do
    approval_id = request.approval_id
    if grant.require_approval and is_nil(approval_id), do: Repo.rollback(:approval_required)

    if not is_nil(approval_id) do
      approval = Repo.one(from(a in Approval, where: a.id == ^approval_id, lock: "FOR UPDATE"))

      if not valid_approval?(approval, principal, request, grant),
        do: Repo.rollback(:approval_invalid)

      approval
      |> Changeset.change(status: "consumed", consumed_at: DateTime.utc_now())
      |> update!()
    end
  end

  defp compensate(lease, backend) do
    status =
      case PostgreSQLBackend.revoke(backend, lease.username) do
        :ok -> "failed"
        {:error, _} -> "revoke_pending"
      end

    Repo.update_all(from(l in Lease, where: l.id == ^lease.id), set: [status: status])
    :ok
  rescue
    _error in [Postgrex.Error, DBConnection.ConnectionError] ->
      # Reservation already durably owns this handle, so expiry cleanup can retry it.
      :ok
  end

  defp revoke_backend(lease, backend, principal, status) do
    case PostgreSQLBackend.revoke(backend, lease.username) do
      :ok ->
        commit_revocation(lease, principal, status)

      {:error, _} ->
        {:error, :backend_unavailable}
    end
  end

  defp commit_revocation(lease, principal, status) do
    case Repo.transaction(fn -> mark_revoked(lease, principal, status) end) do
      {:ok, :ok} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp identity(token, opts) do
    enabled =
      Keyword.get(
        opts,
        :feature_enabled,
        Application.get_env(:secrethub_core, :human_dynamic_enabled, false)
      )

    adapter =
      Keyword.get(
        opts,
        :identity_adapter,
        Application.get_env(:secrethub_core, :human_identity_adapter)
      )

    cond do
      enabled != true ->
        {:error, :feature_disabled}

      not (is_binary(token) and byte_size(token) in 1..4096) ->
        {:error, :unauthenticated}

      not identity_adapter?(adapter) ->
        {:error, :unauthenticated}

      true ->
        case adapter.verify(token) do
          {:ok, principal} -> validate_principal(principal)
          _ -> {:error, :unauthenticated}
        end
    end
  rescue
    _ -> {:error, :unauthenticated}
  catch
    :exit, _ -> {:error, :unauthenticated}
  end

  defp validate_principal(
         %{
           subject_id: subject,
           session_id: session,
           device_id: device,
           groups: groups,
           auth_strength: strength
         } = principal
       ) do
    if valid_uuid?(subject) and valid_uuid?(session) and (is_nil(device) or valid_uuid?(device)) and
         is_list(groups) and length(groups) <= 50 and
         Enum.all?(groups, &valid_uuid?/1) and
         strength in [:password, :mfa],
       do:
         {:ok,
          Map.take(principal, [:subject_id, :session_id, :device_id, :groups, :auth_strength])},
       else: {:error, :unauthenticated}
  end

  defp validate_principal(_), do: {:error, :unauthenticated}

  defp allowed_request(principal, request, operation, opts) do
    case allowed(principal, request, operation, opts) do
      {:error, :unauthorized} = denied ->
        metadata =
          request
          |> Map.take([:request_id, :organization_id, :mount_id, :role_id, :requested_ttl])
          |> Map.reject(fn {_key, value} -> is_nil(value) end)
          |> Map.merge(%{
            session_id: principal.session_id,
            result: "denied",
            reason: "unauthorized"
          })

        adapter = Keyword.get(opts, :audit_adapter, SecretHub.Access)

        case adapter.record_human_event(
               "human.dynamic_secret.denied",
               principal.subject_id,
               metadata,
               Ecto.UUID.generate()
             ) do
          {:ok, _} -> denied
          _ -> {:error, :audit_unavailable}
        end

      result ->
        result
    end
  end

  defp allowed(principal, request, operation, opts) do
    organization_id = Map.get(request, :organization_id)

    grant =
      Repo.all(
        from(g in Grant,
          where:
            g.mount_id == ^request.mount_id and g.role_id == ^request.role_id and g.enabled and
              (g.subject_id == ^principal.subject_id or g.organization_id in ^principal.groups),
          order_by: [asc_nulls_last: g.subject_id, asc: g.id]
        )
      )
      |> Enum.find(fn g ->
        (is_nil(organization_id) or g.organization_id == organization_id) and
          operation in g.allowed_operations and constraints?(g, principal) and
          request.requested_ttl <= g.max_ttl
      end)

    with %Grant{} <- grant,
         {:ok, _} <- mount(request.mount_id, request.role_id, opts) do
      {:ok, grant}
    else
      _ -> {:error, :unauthorized}
    end
  end

  defp constraints?(grant, principal),
    do:
      (not grant.require_device or not is_nil(principal.device_id)) and
        (not grant.require_mfa or principal.auth_strength == :mfa)

  defp mount(id, role, opts) do
    mounts = Keyword.get(opts, :mounts, Application.get_env(:secrethub_core, :human_mounts, %{}))

    case Map.get(mounts, id) do
      %{engine: PostgreSQLBackend, roles: roles} = backend when is_map(roles) ->
        if Map.has_key?(roles, role) and PostgreSQLBackend.validate_config(backend) == :ok,
          do: {:ok, backend},
          else: {:error, :unsupported_engine}

      _ ->
        {:error, :unsupported_engine}
    end
  end

  defp validate_mounts(mounts) do
    Enum.reduce_while(mounts, :ok, fn
      {id, %{engine: PostgreSQLBackend} = mount}, :ok ->
        if safe_id?(id) and PostgreSQLBackend.validate_config(mount) == :ok,
          do: {:cont, :ok},
          else: {:halt, {:error, :invalid_backend_config}}

      _, :ok ->
        {:halt, {:error, :unsupported_engine}}
    end)
  end

  defp owned_lease(principal, id) do
    with {:ok, id} <- uuid(id),
         %Lease{} = lease <-
           Repo.get_by(Lease,
             id: id,
             subject_id: principal.subject_id,
             session_id: principal.session_id,
             device_id: principal.device_id
           ) do
      {:ok, lease}
    else
      _ -> {:error, :not_found}
    end
  end

  defp request(attrs, require_id) when is_map(attrs) do
    mount = get(attrs, :mount_id)
    role = get(attrs, :role_id)
    ttl = get(attrs, :requested_ttl)
    id = get(attrs, :request_id)
    approval = get(attrs, :approval_id)
    organization_id = get(attrs, :organization_id)

    if safe_id?(mount) and safe_id?(role) and is_integer(ttl) and ttl in 1..86_400 and
         valid_request_ids?(require_id, id, approval, organization_id),
       do:
         {:ok,
          %{
            mount_id: mount,
            role_id: role,
            requested_ttl: ttl,
            request_id: id,
            approval_id: approval,
            organization_id: organization_id
          }},
       else: {:error, :invalid_input}
  end

  defp request(_, _), do: {:error, :invalid_input}

  defp lease_request(lease),
    do: %{
      mount_id: lease.mount_id,
      role_id: lease.role_id,
      requested_ttl: 1,
      organization_id: lease.organization_id
    }

  defp same_request?(record, principal, request),
    do:
      record.subject_id == principal.subject_id and record.session_id == principal.session_id and
        record.device_id == principal.device_id and record.mount_id == request.mount_id and
        record.role_id == request.role_id and record.request_id == request.request_id

  defp grant_changeset(grant, attrs) do
    params = Map.new(@grant_fields, fn key -> {key, get(attrs, key, Map.get(grant, key))} end)

    grant
    |> Changeset.cast(params, @grant_fields)
    |> Changeset.validate_required([
      :mount_id,
      :role_id,
      :allowed_operations,
      :max_ttl
    ])
    |> Changeset.validate_format(:mount_id, ~r/\A[a-zA-Z0-9_\/-]{1,128}\z/)
    |> Changeset.validate_format(:role_id, ~r/\A[a-zA-Z0-9_\/-]{1,128}\z/)
    |> Changeset.validate_number(:max_ttl, greater_than: 0, less_than_or_equal_to: 86_400)
    |> Changeset.validate_subset(:allowed_operations, @operations)
    |> Changeset.validate_length(:allowed_operations, min: 1, max: 5)
    |> Changeset.validate_length(:approver_subject_ids, max: 50)
    |> validate_grant_scope()
    |> Changeset.unique_constraint([:subject_id, :mount_id, :role_id])
    |> Changeset.unique_constraint([:organization_id, :mount_id, :role_id])
  end

  defp validate_grant_scope(changeset) do
    if is_nil(Changeset.get_field(changeset, :subject_id)) !=
         is_nil(Changeset.get_field(changeset, :organization_id)),
       do: changeset,
       else:
         Changeset.add_error(
           changeset,
           :subject_id,
           "requires exactly one subject or organization"
         )
  end

  defp current_membership(_principal, %Lease{organization_id: nil}), do: :ok

  defp current_membership(principal, lease),
    do: if(lease.organization_id in principal.groups, do: :ok, else: {:error, :unauthorized})

  defp unwrap_membership!(principal, lease) do
    case current_membership(principal, lease) do
      :ok -> :ok
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp grant_dto(grant), do: Map.take(grant, [:id | @grant_fields] ++ [:revision])

  defp capability(grant),
    do:
      Map.take(grant, [
        :organization_id,
        :mount_id,
        :role_id,
        :max_ttl,
        :require_approval,
        :require_device,
        :require_mfa,
        :allowed_operations
      ])

  defp lease_dto(lease) do
    status =
      if lease.status == "active" and
           DateTime.compare(lease.expires_at, DateTime.utc_now()) != :gt,
         do: "expired",
         else: lease.status

    Map.take(lease, [
      :id,
      :organization_id,
      :mount_id,
      :role_id,
      :username,
      :status,
      :issued_at,
      :expires_at,
      :renewable,
      :subject_id,
      :session_id,
      :device_id,
      :request_id
    ])
    |> Map.put(:status, status)
  end

  defp approval_dto(approval),
    do:
      Map.take(approval, [
        :id,
        :subject_id,
        :session_id,
        :device_id,
        :request_id,
        :mount_id,
        :role_id,
        :requested_ttl,
        :max_ttl,
        :status,
        :expires_at,
        :decided_by
      ])

  defp approval_evidence(approval),
    do:
      Map.take(approval, [:request_id, :mount_id, :role_id, :requested_ttl])
      |> Map.put(:approval_id, approval.id)

  defp request_lock(subject, request_id),
    do:
      Repo.query!(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
        ["human-request:" <> subject <> ":" <> request_id],
        log: false
      )

  defp audit!(event, principal, metadata, opts \\ []) do
    adapter = Keyword.get(opts, :audit_adapter, SecretHub.Access)

    case adapter.record_human_event(
           event,
           principal.subject_id,
           metadata,
           Ecto.UUID.generate()
         ) do
      {:ok, _} -> :ok
      {:error, _} -> Repo.rollback(:audit_unavailable)
    end
  end

  defp insert!(changeset) do
    case Repo.insert(changeset) do
      {:ok, value} -> value
      {:error, _} -> Repo.rollback(:invalid_input)
    end
  end

  defp update!(changeset) do
    case Repo.update(changeset) do
      {:ok, value} -> value
      {:error, _} -> Repo.rollback(:invalid_input)
    end
  end

  defp unwrap!({:ok, value}), do: value
  defp unwrap!({:error, reason}), do: Repo.rollback(reason)

  defp get(attrs, key, default \\ nil),
    do: Map.get(attrs, key, Map.get(attrs, Atom.to_string(key), default))

  defp safe_id?(value),
    do: is_binary(value) and Regex.match?(~r/\A[a-zA-Z0-9_\/-]{1,128}\z/, value)

  defp valid_uuid?(value), do: match?({:ok, _}, Ecto.UUID.cast(value))
  defp uuid(value), do: if(valid_uuid?(value), do: {:ok, value}, else: {:error, :invalid_input})

  defp update_grant_locked(id, attrs) do
    case Repo.one(from(g in Grant, where: g.id == ^id, lock: "FOR UPDATE")) do
      nil ->
        Repo.rollback(:not_found)

      grant ->
        update =
          attrs
          |> Map.drop([
            :subject_id,
            :organization_id,
            :mount_id,
            :role_id,
            "subject_id",
            "organization_id",
            "mount_id",
            "role_id"
          ])

        updated =
          grant
          |> grant_changeset(update)
          |> Changeset.put_change(:revision, grant.revision + 1)
          |> update!()

        if not updated.enabled do
          Repo.update_all(
            from(l in Lease,
              where: l.grant_id == ^grant.id and l.status in ["active", "reserved"]
            ),
            set: [status: "revoke_pending"]
          )
        end

        grant_dto(updated)
    end
  end

  defp renew_lease_locked(token, lease, request, backend, opts) do
    locked = Repo.one(from(l in Lease, where: l.id == ^lease.id, lock: "FOR UPDATE"))

    if locked.status != "active" or not locked.renewable or
         DateTime.compare(locked.expires_at, DateTime.utc_now()) != :gt,
       do: Repo.rollback(:lease_expired)

    principal = unwrap!(identity(token, opts))
    unwrap_membership!(principal, locked)
    grant = unwrap!(allowed(principal, request, "renew", opts))
    expires_at = DateTime.add(DateTime.utc_now(), request.requested_ttl)

    case PostgreSQLBackend.renew(backend, locked.username, expires_at) do
      :ok -> :ok
      {:error, _} -> Repo.rollback(:backend_unavailable)
    end

    updated =
      locked
      |> Changeset.change(expires_at: expires_at, grant_revision: grant.revision)
      |> update!()

    audit!("human.dynamic_secret.renewed", principal, %{
      lease_id: locked.id,
      ttl: request.requested_ttl
    })

    lease_dto(updated)
  end

  defp request_approval_locked(principal, request, grant) do
    request_lock(principal.subject_id, request.request_id)

    case Repo.get_by(Approval,
           subject_id: principal.subject_id,
           request_id: request.request_id
         ) do
      nil ->
        approval =
          %Approval{}
          |> Changeset.change(
            Map.merge(Map.drop(request, [:approval_id, :organization_id]), %{
              grant_id: grant.id,
              grant_revision: grant.revision,
              subject_id: principal.subject_id,
              session_id: principal.session_id,
              device_id: principal.device_id,
              max_ttl: grant.max_ttl,
              expires_at: DateTime.add(DateTime.utc_now(), 300)
            })
          )
          |> insert!()

        audit!("human.dynamic_secret.requested", principal, approval_evidence(approval))
        approval_dto(approval)

      existing ->
        if same_request?(existing, principal, request),
          do: approval_dto(existing),
          else: Repo.rollback(:request_conflict)
    end
  end

  defp decide_locked(principal, id, status) do
    approval = Repo.one(from(a in Approval, where: a.id == ^id, lock: "FOR UPDATE"))
    if is_nil(approval), do: Repo.rollback(:not_found)
    grant = Repo.get!(Grant, approval.grant_id)

    if not grant.enabled or principal.subject_id not in grant.approver_subject_ids or
         principal.subject_id == approval.subject_id,
       do: Repo.rollback(:unauthorized)

    if approval.status != "pending" or approval.grant_revision != grant.revision or
         DateTime.compare(approval.expires_at, DateTime.utc_now()) != :gt,
       do: Repo.rollback(:approval_invalid)

    updated =
      approval
      |> Changeset.change(
        status: status,
        decided_by: principal.subject_id,
        decided_at: DateTime.utc_now()
      )
      |> update!()

    event =
      if status == "approved",
        do: "human.dynamic_secret.approved",
        else: "human.dynamic_secret.denied"

    audit!(event, principal, approval_evidence(approval))
    approval_dto(updated)
  end

  defp reserve_locked(principal, request, grant, opts) do
    request_lock(principal.subject_id, request.request_id)

    case Repo.get_by(Lease, subject_id: principal.subject_id, request_id: request.request_id) do
      nil ->
        :ok

      existing ->
        if not same_request?(existing, principal, request), do: Repo.rollback(:request_conflict)

        reason =
          case existing.status do
            "active" -> :already_issued
            "reserved" -> :issuance_pending
            _ -> :issuance_failed
          end

        Repo.rollback(reason)
    end

    consume_approval!(principal, request, grant)
    id = Ecto.UUID.generate()

    lease =
      %Lease{id: id}
      |> Changeset.change(%{
        grant_id: grant.id,
        grant_revision: grant.revision,
        organization_id: grant.organization_id,
        subject_id: principal.subject_id,
        session_id: principal.session_id,
        device_id: principal.device_id,
        request_id: request.request_id,
        mount_id: request.mount_id,
        role_id: request.role_id,
        username: "human_" <> String.replace(id, "-", ""),
        expires_at: DateTime.add(DateTime.utc_now(), request.requested_ttl)
      })
      |> insert!()

    audit!(
      "human.dynamic_secret.requested",
      principal,
      %{
        lease_id: lease.id,
        request_id: lease.request_id,
        mount_id: lease.mount_id,
        role_id: lease.role_id,
        requested_ttl: request.requested_ttl
      },
      opts
    )

    lease
  end

  defp issue_reserved(token, request, backend, lease, opts) do
    case PostgreSQLBackend.create(backend, request.role_id, lease.username, lease.expires_at) do
      {:ok, credentials} ->
        case finalize(token, lease, request, opts) do
          {:ok, active} ->
            {:ok, %{lease: lease_dto(active), credentials: credentials}}

          {:error, reason} ->
            compensate(lease, backend)
            {:error, reason}
        end

      {:error, _} ->
        compensate(lease, backend)
        {:error, :backend_unavailable}
    end
  end

  defp cleanup_candidate(candidate, opts) do
    case claim_revocation(candidate.id) do
      {:ok, nil} -> []
      {:ok, lease} -> [{lease.id, cleanup_backend(lease, opts)}]
      {:error, reason} -> [{candidate.id, {:error, reason}}]
    end
  end

  defp cleanup_backend(lease, opts) do
    case mount(lease.mount_id, lease.role_id, opts) do
      {:ok, backend} ->
        principal = Map.take(lease, [:subject_id, :session_id, :device_id])

        status =
          if DateTime.compare(lease.expires_at, DateTime.utc_now()) != :gt,
            do: "expired",
            else: "revoked"

        revoke_backend(lease, backend, principal, status)

      {:error, _} ->
        {:error, :backend_unavailable}
    end
  end

  defp mark_revoked(lease, principal, status) do
    current = Repo.get!(Lease, lease.id)
    current |> Changeset.change(status: status) |> update!()

    event =
      if status == "expired",
        do: "human.dynamic_secret.expired",
        else: "human.dynamic_secret.revoked"

    audit!(event, principal, %{
      lease_id: lease.id,
      mount_id: lease.mount_id,
      role_id: lease.role_id
    })

    :ok
  end

  defp valid_approval?(%Approval{} = approval, principal, request, grant) do
    approval.status == "approved" and is_nil(approval.consumed_at) and
      approval.grant_id == grant.id and approval.grant_revision == grant.revision and
      approval.decided_by in grant.approver_subject_ids and
      fresh_approval_request?(approval, principal, request)
  end

  defp valid_approval?(_, _, _, _), do: false

  defp fresh_approval_request?(approval, principal, request) do
    DateTime.compare(approval.expires_at, DateTime.utc_now()) == :gt and
      same_request?(approval, principal, request) and
      approval.requested_ttl == request.requested_ttl
  end

  defp valid_request_ids?(require_id, id, approval, organization_id) do
    (not require_id or valid_uuid?(id)) and (is_nil(approval) or valid_uuid?(approval)) and
      (is_nil(organization_id) or valid_uuid?(organization_id))
  end

  defp identity_adapter?(adapter) do
    is_atom(adapter) and not is_nil(adapter) and Code.ensure_loaded?(adapter) and
      function_exported?(adapter, :verify, 1)
  end
end
