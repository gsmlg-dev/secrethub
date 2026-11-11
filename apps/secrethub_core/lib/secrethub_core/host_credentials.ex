defmodule SecretHub.Core.HostCredentials do
  @moduledoc """
  Typed facade for Agent-scoped host credentials.

  Every runtime operation receives a principal resolved from the trusted mTLS
  socket and a request validated by `SecretHub.Shared.HostCredentials`. Inside
  one transaction it revalidates the Agent, selects only that Agent's entries,
  evaluates explicit `credential_*` grants, records the Core decision, performs
  the effect, and commits checked audit evidence. Decisions are made before any
  mutation: a failed mutation aborts the whole transaction and is recorded as
  separate error evidence afterwards.

  Owned entries keep their value in dedicated encrypted Secret storage.
  Reference entries point at an operator-selected source Secret by its stable
  ID; erasing a reference only disables its binding.
  """
  import Ecto.Query

  alias SecretHub.Core.PKI.ManagedCertificates
  alias SecretHub.Core.Vault.SealState

  alias SecretHub.Core.{
    AccessAudit,
    Agents,
    Audit,
    AuthorizationVersions,
    Repo,
    RuntimeAuthorization,
    RuntimePrincipal,
    Secrets
  }

  alias SecretHub.Shared.AccessAudit.Event
  alias SecretHub.Shared.HostCredentials, as: Contract

  alias SecretHub.Shared.Schemas.{
    Agent,
    Certificate,
    HostCredentialBinding,
    Secret,
    SecretPathRevision,
    UpgradeGate
  }

  @chain_events %{
    "credential_read" => "host_credential.read",
    "credential_write" => "host_credential.written",
    "credential_delete" => "host_credential.deleted",
    "credential_list" => "host_credential.listed"
  }

  @denied ~w(permission_denied invalid_agent invalid_principal invalid_request revoked disabled
    expired incompatible_version read_only)a

  ## Runtime facade

  @doc """
  Executes one credential action (`credential_get`, `credential_put`,
  `credential_delete`, `credential_list`) for an Agent-only principal.
  Returns `{:ok, result}` with string keys or `{:error, reason}`.
  """
  def execute(principal, action, params, correlation \\ %{})

  def execute(
        %RuntimePrincipal{application_id: nil, agent_id: agent_id, agent_certificate_id: cert_id} =
          principal,
        action,
        params,
        correlation
      )
      when is_binary(agent_id) and is_binary(cert_id) do
    context = audit_context(correlation)

    case Contract.operation(action) do
      {:ok, operation} ->
        case Contract.validate(action, params) do
          {:ok, request} -> run(principal, operation, request, context)
          {:error, reason} -> rejected(principal, operation, reason, context)
        end

      :error ->
        rejected(principal, "credential_read", :invalid_request, context)
    end
  rescue
    _ in [DBConnection.ConnectionError, Postgrex.Error] -> {:error, :audit_unavailable}
  catch
    :exit, _ -> {:error, :audit_unavailable}
  end

  def execute(_, _, _, _), do: {:error, :invalid_principal}

  defp run(principal, operation, request, context) do
    Repo.transaction(fn ->
      lock!(principal, operation)

      decision =
        with :ok <- current_principal(principal) do
          policies = RuntimeAuthorization.subject_policies("agent:" <> principal.agent_id)
          decide(%{principal: principal, policies: policies}, operation, request)
        end

      decision_event = observe!(principal, operation, evidence(decision), context)

      case decision do
        {:ok, plan} ->
          result = perform!(principal, plan)
          observe!(principal, operation, access_evidence(plan, decision_event), context)
          chain!(principal, operation, {:ok, result}, plan)
          {:ok, Map.put(result, "audit_event_id", decision_event.event_id)}

        {:error, reason} ->
          chain!(principal, operation, {:error, reason}, nil)
          {:error, reason}
      end
    end)
    |> case do
      {:ok, result} -> result
      {:error, reason} -> failed(principal, operation, reason, context)
    end
  end

  # Writers serialize through the global epoch; readers share it. Entity rows
  # follow in the existing order used by Agent-scoped static reads.
  defp lock!(principal, operation) when operation in ~w(credential_write credential_delete) do
    AuthorizationVersions.lock_global()
    lock_identity!(principal)
  end

  defp lock!(principal, _operation) do
    AuthorizationVersions.lock_agent_for_share(Repo, principal.agent_id)
    lock_identity!(principal)
  end

  @doc false
  # Shared with `SecretHub.Core.AgentSecretWrites`: same lock order and Agent checks.
  def lock_identity!(principal) do
    Repo.one(from(a in Agent, where: a.id == ^principal.agent_id, lock: "FOR SHARE"))

    Repo.one(
      from(c in Certificate, where: c.id == ^principal.agent_certificate_id, lock: "FOR SHARE")
    )
  end

  @doc false
  def current_principal(principal) do
    with %UpgradeGate{} <- Repo.get_by(UpgradeGate, name: "typed_runtime_authorization"),
         :ok <-
           Agents.authorize_runtime(principal.agent_public_id, principal.agent_certificate_id),
         %Agent{id: id} when id == principal.agent_id <-
           Repo.get_by(Agent, agent_id: principal.agent_public_id),
         %Certificate{entity_type: "agent"} = certificate <-
           Repo.get(Certificate, principal.agent_certificate_id),
         true <- live?(certificate) do
      :ok
    else
      nil -> {:error, :authorization_unavailable}
      {:error, :certificate_revoked} -> {:error, :revoked}
      {:error, :certificate_expired} -> {:error, :expired}
      _ -> {:error, :invalid_agent}
    end
  end

  defp live?(%Certificate{valid_from: from, valid_until: until}) do
    now = DateTime.utc_now()
    DateTime.compare(from, now) != :gt and DateTime.compare(until, now) == :gt
  end

  ## Decisions (no mutation)

  defp decide(ctx, "credential_read", request) do
    case lookup(ctx.principal, request, :active) do
      [] ->
        with :ok <- collection_grant(ctx, request, "credential_read"),
             do: {:error, :not_found}

      [_, _ | _] ->
        with :ok <- collection_grant(ctx, request, "credential_read"),
             do: {:error, :ambiguous}

      [binding] ->
        with :ok <- grant(ctx, resource(ctx, binding), "credential_read"),
             :ok <- vault_ready(),
             {:ok, source} <- source(ctx, binding),
             :ok <- ManagedCertificates.check_delivery(source.secret.id) do
          {:ok, %{op: :read, binding: binding, source: source, known: request["known"]}}
        end
    end
  end

  defp decide(ctx, "credential_write", request) do
    identity = Map.update!(request, "account", &(&1 || ""))

    case Repo.one(identity_query(ctx.principal, identity) |> lock("FOR UPDATE")) do
      nil ->
        with :ok <- grant(ctx, collection(ctx, identity), "credential_write"),
             :ok <- vault_ready(),
             do: {:ok, %{op: :create, request: identity}}

      %HostCredentialBinding{} = binding ->
        with :ok <- grant(ctx, resource(ctx, binding), "credential_write"),
             :ok <- vault_ready(),
             do: decide_store(ctx, binding, identity)
    end
  end

  defp decide(ctx, "credential_delete", request) do
    case lookup(ctx.principal, request, :any) do
      [] ->
        with :ok <- collection_grant(ctx, request, "credential_delete"),
             do: {:ok, %{op: :absent, resource: request["namespace"] && collection(ctx, request)}}

      [_, _ | _] ->
        with :ok <- collection_grant(ctx, request, "credential_delete"),
             do: {:error, :ambiguous}

      [binding] ->
        with :ok <- grant(ctx, resource(ctx, binding), "credential_delete"),
             do: decide_erase(ctx, binding, request["expected_value"])
    end
  end

  defp decide(ctx, "credential_list", request) do
    with :ok <- collection_grant(ctx, request, "credential_list") do
      rows =
        Repo.all(
          from(b in HostCredentialBinding,
            where:
              b.owner_agent_id == ^ctx.principal.agent_id and b.namespace == ^request["namespace"] and
                b.state == "active",
            order_by: b.id,
            limit: ^(request["limit"] + 1)
          )
          |> after_cursor(request["cursor"])
        )

      {page, more} = Enum.split(rows, request["limit"])

      entries =
        page
        |> Enum.filter(&(grant(ctx, resource(ctx, &1), "credential_list") == :ok))
        |> Enum.map(&HostCredentialBinding.metadata/1)

      next = if more != [], do: List.last(page).id

      {:ok, %{op: :list, resource: collection(ctx, request), entries: entries, next_cursor: next}}
    end
  end

  # An identical store on an active binding is an audited no-op. A reference is
  # never replaced or reactivated by an ordinary store.
  defp decide_store(_ctx, %{source_kind: "reference", state: "disabled"}, _request),
    do: {:error, :read_only}

  defp decide_store(ctx, binding, request) do
    with {:ok, source} <- source(ctx, binding),
         {:ok, current} <- extract(binding, source) do
      same? = current.value == request["value"] and current.username == request["username"]

      cond do
        same? -> {:ok, %{op: :unchanged, binding: binding, source: source}}
        binding.source_kind == "reference" -> {:error, :read_only}
        true -> {:ok, %{op: :update, binding: binding, source: source, request: request}}
      end
    end
  end

  defp decide_erase(_ctx, %{source_kind: "reference", state: "disabled"} = binding, _expected),
    do: {:ok, %{op: :already_disabled, binding: binding}}

  defp decide_erase(_ctx, binding, nil), do: {:ok, erase_plan(binding, nil)}

  # A stale value supplied by the client must not erase a newer replacement.
  defp decide_erase(ctx, binding, expected) do
    with :ok <- vault_ready(),
         {:ok, source} <- source(ctx, binding),
         {:ok, current} <- extract(binding, source) do
      if current.value == expected,
        do: {:ok, erase_plan(binding, source)},
        else: {:ok, %{op: :value_mismatch, binding: binding, source: source}}
    end
  end

  defp erase_plan(%{source_kind: "owned"} = binding, source),
    do: %{op: :delete_owned, binding: binding, source: source}

  defp erase_plan(binding, source), do: %{op: :disable, binding: binding, source: source}

  defp lookup(principal, %{"entry_id" => id}, states) do
    from(b in HostCredentialBinding,
      where: b.owner_agent_id == ^principal.agent_id and b.id == ^id
    )
    |> with_state(states)
    |> lock("FOR SHARE")
    |> Repo.all()
  end

  defp lookup(principal, request, states) do
    query =
      from(b in HostCredentialBinding,
        where:
          b.owner_agent_id == ^principal.agent_id and b.namespace == ^request["namespace"] and
            b.service == ^request["service"] and b.authority == ^request["authority"] and
            b.context == ^request["context"],
        order_by: b.id,
        limit: 2
      )

    # Docker identity is the registry alone; Git and generic match the account
    # exactly when supplied. A missing Git account must resolve uniquely.
    query =
      case {request["namespace"], request["account"]} do
        {"docker", _} -> where(query, [b], b.account == "")
        {_, nil} -> query
        {_, account} -> where(query, [b], b.account == ^account)
      end

    query |> with_state(states) |> lock("FOR SHARE") |> Repo.all()
  end

  defp with_state(query, :active), do: where(query, [b], b.state == "active")
  defp with_state(query, :any), do: query

  defp identity_query(principal, request) do
    from(b in HostCredentialBinding,
      where:
        b.owner_agent_id == ^principal.agent_id and b.namespace == ^request["namespace"] and
          b.service == ^request["service"] and b.authority == ^request["authority"] and
          b.account == ^request["account"] and b.context == ^request["context"]
    )
  end

  defp after_cursor(query, nil), do: query
  defp after_cursor(query, cursor), do: where(query, [b], b.id > ^cursor)

  # The source must be the original Secret by stable ID; a deleted or recreated
  # path never satisfies it. References also need the Agent's static read grant.
  defp source(ctx, binding) do
    with id when is_binary(id) <- binding.secret_id,
         true <- id == binding.source_secret_id,
         %Secret{secret_type: :static} = secret <-
           Repo.one(from(s in Secret, where: s.id == ^id, lock: "FOR SHARE")),
         :ok <- source_grant(ctx, binding, secret),
         %SecretPathRevision{revision: revision} <-
           Repo.one(
             from(r in SecretPathRevision,
               where: r.secret_path == ^secret.secret_path,
               lock: "FOR SHARE"
             )
           ) do
      {:ok, %{secret: secret, revision: revision}}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :secret_not_found}
    end
  end

  defp source_grant(_ctx, %{source_kind: "owned"}, _secret), do: :ok
  defp source_grant(ctx, _binding, secret), do: grant(ctx, secret.secret_path, "read")

  defp grant(ctx, resource, operation) do
    RuntimeAuthorization.authorize_with_policies(
      ctx.policies,
      "agent:" <> ctx.principal.agent_id,
      resource,
      operation
    )
  end

  defp vault_ready do
    case SealState.get_master_key() do
      {:ok, _} -> :ok
      _ -> {:error, :sealed}
    end
  end

  # An entry ID lookup carries no namespace; any collection grant for this
  # operation distinguishes a genuine miss from a denial.
  defp collection_grant(ctx, %{"namespace" => _} = request, operation),
    do: grant(ctx, collection(ctx, request), operation)

  defp collection_grant(ctx, _request, operation) do
    if Enum.any?(
         Contract.namespaces(),
         &(grant(ctx, collection(ctx, %{"namespace" => &1}), operation) == :ok)
       ),
       do: :ok,
       else: {:error, :permission_denied}
  end

  defp collection(ctx, request),
    do: Contract.collection_resource(ctx.principal.agent_id, request["namespace"])

  defp resource(ctx, binding),
    do: Contract.entry_resource(ctx.principal.agent_id, binding.namespace, binding.id)

  ## Effects (run only after a recorded grant)

  defp perform!(principal, %{op: :read, binding: binding, source: source, known: known}) do
    base = read_metadata(principal, binding, source)

    if known == %{
         "entry_id" => binding.id,
         "binding_revision" => binding.revision,
         "source_revision" => source.revision
       } do
      Map.put(base, "not_modified", true)
    else
      case extract(binding, source) do
        {:ok, %{username: username, value: value}} ->
          Map.merge(base, %{"username" => username, "value" => value})

        {:error, reason} ->
          Repo.rollback(reason)
      end
    end
  end

  defp perform!(principal, %{op: :create, request: request}) do
    id = Ecto.UUID.generate()
    path = Contract.entry_resource(principal.agent_id, request["namespace"], id)

    secret =
      ok!(
        Secrets.create_secret(%{
          name: "Host credential " <> id,
          secret_path: path,
          value_format: "structured",
          secret_data: %{"username" => request["username"], "value" => request["value"]},
          description: "Agent-owned host credential",
          metadata: %{"host_credential_binding_id" => id},
          created_by: principal.agent_public_id
        })
      )

    binding =
      %HostCredentialBinding{}
      |> HostCredentialBinding.changeset(%{
        id: id,
        owner_agent_id: principal.agent_id,
        namespace: request["namespace"],
        service: request["service"],
        authority: request["authority"],
        account: request["account"],
        context: request["context"],
        username: request["username"],
        source_kind: "owned",
        secret_id: secret.id,
        source_secret_id: secret.id,
        username_field: "username",
        value_field: "value",
        state: "active",
        revision: 1
      })
      |> Repo.insert()
      |> ok!()

    store_result("created", binding, secret)
  end

  defp perform!(principal, %{op: :update, binding: binding, source: source, request: request}) do
    secret =
      ok!(
        Secrets.update_secret(
          source.secret.id,
          %{
            "secret_data" => %{"username" => request["username"], "value" => request["value"]},
            "value_format" => "structured"
          },
          created_by: principal.agent_public_id,
          change_description: "Host credential updated by its Agent"
        )
      )

    binding =
      if binding.username == request["username"],
        do: binding,
        else:
          binding
          |> HostCredentialBinding.changeset(%{
            username: request["username"],
            revision: binding.revision + 1
          })
          |> Repo.update()
          |> ok!()

    store_result("updated", binding, secret)
  end

  defp perform!(_principal, %{op: :unchanged, binding: binding, source: source}),
    do: store_result("unchanged", binding, source.secret)

  defp perform!(_principal, %{op: :absent}), do: %{"status" => "absent"}

  defp perform!(_principal, %{op: :already_disabled, binding: binding}),
    do: erase_result("disabled", binding)

  defp perform!(_principal, %{op: :value_mismatch, binding: binding}),
    do: erase_result("unchanged", binding)

  defp perform!(_principal, %{op: :delete_owned, binding: binding}) do
    ok!(Repo.delete(binding))

    if binding.secret_id && exclusively_owned?(binding) do
      ok!(Secrets.delete_secret(binding.secret_id))
    end

    erase_result("deleted", binding)
  end

  defp perform!(_principal, %{op: :disable, binding: binding}) do
    binding
    |> HostCredentialBinding.changeset(%{state: "disabled", revision: binding.revision + 1})
    |> Repo.update()
    |> ok!()
    |> then(&erase_result("disabled", &1))
  end

  defp perform!(_principal, %{op: :list, entries: entries, next_cursor: next}),
    do: %{"entries" => entries, "next_cursor" => next}

  defp exclusively_owned?(binding) do
    case Repo.get(Secret, binding.secret_id) do
      %Secret{metadata: %{"host_credential_binding_id" => id}} = secret when id == binding.id ->
        not Repo.exists?(
          from(b in HostCredentialBinding,
            where: b.secret_id == ^secret.id or b.source_secret_id == ^secret.id
          )
        )

      _ ->
        false
    end
  end

  defp read_metadata(principal, binding, source) do
    %{
      "entry_id" => binding.id,
      "namespace" => binding.namespace,
      "source_kind" => binding.source_kind,
      "resource" => Contract.entry_resource(principal.agent_id, binding.namespace, binding.id),
      "binding_revision" => binding.revision,
      "source_revision" => source.revision,
      "secret_version" => source.secret.version
    }
  end

  defp store_result(status, binding, secret) do
    revision =
      Repo.one(
        from(r in SecretPathRevision,
          where: r.secret_path == ^secret.secret_path,
          select: r.revision
        )
      )

    %{
      "status" => status,
      "entry_id" => binding.id,
      "source_kind" => binding.source_kind,
      "binding_revision" => binding.revision,
      "source_revision" => revision
    }
  end

  defp erase_result(status, binding),
    do: %{"status" => status, "entry_id" => binding.id, "source_kind" => binding.source_kind}

  # Decrypted values never leave this module except in a granted read result.
  defp extract(binding, %{secret: secret}) do
    with :ok <- ManagedCertificates.check_delivery(secret.id),
         {:ok, data, %Secret{id: id}} when id == secret.id <-
           Secrets.read_decrypted(secret.secret_path),
         value when is_binary(value) <- Map.get(data, binding.value_field),
         {:ok, username} <- username(binding, data) do
      {:ok, %{username: username, value: value}}
    else
      {:error, reason} when reason in [:sealed, :initializing] -> {:error, :sealed}
      {:error, :invalid_value} -> {:error, :invalid_value}
      {:error, _} -> {:error, :secret_not_found}
      _ -> {:error, :invalid_value}
    end
  end

  defp username(%{username_field: nil} = binding, _data),
    do: {:ok, binding.username || binding.account}

  defp username(%{username_field: field}, data) do
    case Map.get(data, field) do
      value when is_binary(value) -> {:ok, value}
      _ -> {:error, :invalid_value}
    end
  end

  defp ok!({:ok, value}), do: value
  defp ok!({:error, %Ecto.Changeset{}}), do: Repo.rollback(:conflict)
  defp ok!({:error, :sealed}), do: Repo.rollback(:sealed)
  defp ok!({:error, _}), do: Repo.rollback(:authorization_unavailable)

  ## Evidence

  defp evidence({:ok, plan}) do
    %{
      phase: "core_decision",
      outcome: "success",
      reason_code: "allowed",
      secret_path: plan_resource(plan),
      secret_id: plan_secret_id(plan),
      cache_status: cache_status(plan)
    }
  end

  defp evidence({:error, reason}) do
    %{
      phase: "core_decision",
      outcome: outcome(reason),
      reason_code: Event.reason(reason, 2),
      cache_status: "none"
    }
  end

  defp access_evidence(plan, decision) do
    plan
    |> then(&evidence({:ok, &1}))
    |> Map.merge(%{phase: "core_access", core_event_id: decision.event_id})
  end

  defp plan_resource(%{resource: resource}), do: resource

  defp plan_resource(%{binding: binding}),
    do: Contract.entry_resource(binding.owner_agent_id, binding.namespace, binding.id)

  defp plan_resource(_), do: nil

  defp plan_secret_id(%{source: %{secret: secret}}), do: secret.id
  defp plan_secret_id(_), do: nil

  defp cache_status(%{op: :read, known: known, binding: binding, source: source}) do
    if known == %{
         "entry_id" => binding.id,
         "binding_revision" => binding.revision,
         "source_revision" => source.revision
       },
       do: "hit",
       else: "miss"
  end

  defp cache_status(_), do: "none"

  defp outcome(reason) when reason in @denied, do: "denied"
  defp outcome(_), do: "error"

  defp observe!(principal, operation, attrs, context) do
    %{
      schema_version: 2,
      request_id: context.request_id,
      attempt_id: context.attempt_id,
      agent_id: principal.agent_public_id,
      application_id: nil,
      identity_status: "unverified",
      attribution: "none",
      operation: operation,
      duration_us: max(System.monotonic_time(:microsecond) - context.started, 0)
    }
    |> Map.merge(attrs)
    |> AccessAudit.record_core()
    |> case do
      {:ok, observation} -> observation
      {:error, _} -> Repo.rollback(:audit_unavailable)
    end
  end

  defp chain!(principal, operation, outcome, plan) do
    {granted, status} =
      case outcome do
        {:ok, result} -> {true, result["status"]}
        {:error, reason} -> {false, Event.reason(reason, 2)}
      end

    attrs = %{
      event_type: Map.fetch!(@chain_events, operation),
      actor_type: "agent",
      actor_id: principal.agent_public_id,
      agent_id: principal.agent_public_id,
      access_granted: granted,
      secret_id: plan && plan_secret_id(plan),
      event_data: %{
        operation: operation,
        resource: plan && plan_resource(plan),
        result: status
      }
    }

    case Audit.log_event(attrs) do
      {:ok, _} -> :ok
      _ -> Repo.rollback(:audit_unavailable)
    end
  end

  # Invalid requests and aborted effects still leave committed evidence.
  defp rejected(principal, operation, reason, context) do
    Repo.transaction(fn ->
      observe!(principal, operation, evidence({:error, reason}), context)
      chain!(principal, operation, {:error, reason}, nil)
      reason
    end)
    |> case do
      {:ok, reason} -> {:error, reason}
      {:error, _} -> {:error, :audit_unavailable}
    end
  end

  defp failed(_principal, _operation, :audit_unavailable, _context),
    do: {:error, :audit_unavailable}

  defp failed(principal, operation, reason, context),
    do: rejected(principal, operation, reason, context)

  defp audit_context(correlation) do
    %{
      request_id: valid_uuid(correlation[:request_id]),
      attempt_id: valid_uuid(correlation[:attempt_id]),
      started: System.monotonic_time(:microsecond)
    }
  end

  defp valid_uuid(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> uuid
      :error -> Ecto.UUID.generate()
    end
  end
end
