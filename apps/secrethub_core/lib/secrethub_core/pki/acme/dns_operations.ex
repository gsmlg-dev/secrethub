defmodule SecretHub.Core.PKI.ACME.DNSOperations do
  @moduledoc """
  Durable DNS intent, provider evidence and independent cleanup obligations.

  `advance/2` performs one bounded step. The only pinned connection spans a short
  provider mutation/reconciliation critical section. Authoritative propagation
  queries run after database checkout has ended. Provider receipts survive an
  order cancellation or a superseded order claim.
  """
  import Ecto.Query
  alias Ecto.Changeset
  alias SecretHub.Core.PKI.{DNS, ManagedCertificates}
  alias SecretHub.Core.PKI.DNS.Names
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{AcmeOrder, DNSChallengeOperation, ManagedCertificate}
  @terminal ["published", "failed", "cancelled"]
  @claim_seconds 90

  def create_intent(order, authorization, value, opts \\ []) do
    case Repo.get_by(DNSChallengeOperation, authorization_id: authorization.id) do
      %DNSChallengeOperation{} = existing ->
        if existing.order_id == order.id and existing.value == value,
          do: {:ok, existing},
          else: {:error, :intent_conflict}

      nil ->
        create_new_intent(order, authorization, value, opts)
    end
  end

  def advance(operation, opts \\ []) do
    with {:ok, operation} <- claim(operation) do
      case operation.state do
        "intent" -> prepare(operation, opts)
        "prepared" -> present(operation, opts)
        state when state in ["presenting", "ambiguous"] -> reconcile(operation, opts)
        "presented" -> propagation(operation, opts)
        "propagated" -> finish(operation, %{}, nil)
        _ -> fail(operation, :invalid_dns_state)
      end
    end
  end

  def cleanup(operation, opts \\ []) do
    with {:ok, operation} <- claim(operation) do
      order = Repo.get!(AcmeOrder, operation.order_id)

      cond do
        operation.cleanup_status == "cleaned" -> finish(operation, %{}, nil)
        order.state not in @terminal -> fail(operation, :order_active)
        operation.state in ["intent", "prepared"] -> mark_cleaned(operation)
        true -> cleanup_owned(operation, opts)
      end
    end
  end

  defp create_new_intent(order, authorization, value, opts) do
    identifier =
      if authorization.wildcard,
        do: "*." <> String.trim_leading(authorization.identifier, "*."),
        else: authorization.identifier

    with :ok <- new_effect_allowed(order.id, opts),
         true <- authorization.order_id == order.id,
         {:ok, binding} <- Names.bind(identifier, order.bindings),
         {:ok, original} <- Names.challenge_owner(identifier),
         {:ok, owner} <- DNS.effective_owner(original, binding, opts) do
      id = Ecto.UUID.generate()
      binding = normalize_binding(binding)

      attrs = %{
        id: id,
        order_id: order.id,
        authorization_id: authorization.id,
        provider_id: binding["provider_id"],
        provider_snapshot: binding,
        original_owner: original,
        owner: owner,
        value: value,
        intent: %{"id" => id, "owner" => owner, "value" => value}
      }

      persist_intent(attrs, id, order)
    else
      false -> {:error, :authorization_order_mismatch}
      error -> error
    end
  end

  defp persist_intent(attrs, id, order) do
    Repo.transaction(fn ->
      # This insert and its stable effect ID commit before any provider mutation.
      changeset =
        DNSChallengeOperation.changeset(%DNSChallengeOperation{id: id}, Map.delete(attrs, :id))

      case Repo.insert(changeset, on_conflict: :nothing, conflict_target: [:authorization_id]) do
        {:ok, _} -> :ok
        {:error, reason} -> Repo.rollback(reason)
      end

      operation = Repo.get_by!(DNSChallengeOperation, authorization_id: attrs.authorization_id)

      if operation.order_id != order.id or operation.value != attrs.value,
        do: Repo.rollback(:intent_conflict)

      if operation.id == id,
        do: ManagedCertificates.audit!("acme.dns.intent", id, %{order_id: order.id})

      operation
    end)
  end

  defp prepare(operation, opts) do
    with :ok <- new_effect_allowed(operation.order_id, opts),
         {:ok, credentials} <- credentials(operation, opts),
         {:ok, _} <- DNS.validate_zone(operation.provider_snapshot, credentials, opts),
         {:ok, intent} <-
           DNS.prepare(operation.provider_snapshot, credentials, operation.intent, opts) do
      finish(operation, %{intent: intent, state: "prepared"}, "acme.dns.prepared")
    else
      {:error, reason} -> fail(operation, reason)
    end
  end

  defp present(operation, opts) do
    with_owner_lock(operation, fn ->
      with :ok <- new_effect_allowed(operation.order_id, opts),
           {:ok, credentials} <- credentials(operation, opts),
           :ok <- new_effect_allowed(operation.order_id, opts),
           {:ok, presenting} <- begin_effect(operation, %{state: "presenting"}) do
        result = DNS.present(presenting.provider_snapshot, credentials, presenting.intent, opts)
        after_effect(result, opts)
        record_presentation(presenting, result)
      else
        {:error, reason} -> fail(operation, reason)
      end
    end)
    |> locked_result(operation)
  end

  defp reconcile(operation, opts) do
    with_owner_lock(operation, fn ->
      case credentials(operation, opts) do
        {:ok, credentials} ->
          result = DNS.reconcile(operation.provider_snapshot, credentials, operation.intent, opts)
          record_presentation(operation, result)

        {:error, reason} ->
          fail(operation, reason)
      end
    end)
    |> locked_result(operation)
  end

  defp record_presentation(operation, {:ok, receipt}) do
    finish(operation, %{receipt: receipt, state: "presented"}, "acme.dns.presented")
  end

  defp record_presentation(operation, {:error, %{reason: :ambiguous_mutation, receipt: receipt}}) do
    fail(operation, :ambiguous_mutation, %{receipt: receipt, state: "ambiguous"})
  end

  # A rejected exact-preimage batch performed no mutation; reprepare against the
  # new RRset on the next step. Uncertain responses remain reconcile-only.
  defp record_presentation(operation, {:error, :record_conflict}),
    do: fail(operation, :record_conflict, %{state: "intent"})

  defp record_presentation(operation, {:error, reason}), do: fail(operation, reason)

  defp propagation(operation, opts) do
    with {:ok, credentials} <- credentials(operation, opts),
         {:ok, receipt} <-
           DNS.poll_change(operation.provider_snapshot, credentials, operation.receipt, opts) do
      if receipt["change_status"] == "PENDING" do
        finish(
          operation,
          %{receipt: receipt, next_attempt_at: DateTime.add(ManagedCertificates.now(), 10)},
          nil
        )
      else
        observe_propagation(operation, receipt, opts)
      end
    else
      {:error, reason} -> fail(operation, reason)
    end
  end

  defp observe_propagation(operation, receipt, opts) do
    # Repo calls have returned their connections before the authoritative query.
    values = required_values(operation)

    case DNS.propagated?(operation.owner, values, opts) do
      {:ok, :propagated} ->
        finish(operation, %{receipt: receipt, state: "propagated"}, "acme.dns.propagated")

      {:error, reason} ->
        fail(operation, reason, %{receipt: receipt})
    end
  end

  defp cleanup_owned(operation, opts) do
    with_owner_lock(operation, fn ->
      if shared_value_in_use?(operation),
        do: fail(operation, :value_in_use),
        else: run_cleanup(operation, opts)
    end)
    |> locked_result(operation)
  end

  defp run_cleanup(operation, opts) do
    with {:ok, credentials} <- credentials(operation, opts),
         {:ok, receipt} <- cleanup_receipt(operation, credentials, opts),
         {:ok, _} <- begin_effect(operation, %{}),
         {:ok, result} <- DNS.cleanup(operation.provider_snapshot, credentials, receipt, opts) do
      finish(
        operation,
        %{receipt: result, cleanup_status: result["cleanup_status"] || "pending"},
        "acme.dns.cleanup"
      )
    else
      {:error, reason} -> fail(operation, reason, %{cleanup_status: "blocked"})
    end
  end

  defp cleanup_receipt(%{state: state} = operation, credentials, opts)
       when state in ["presenting", "ambiguous"] do
    DNS.reconcile(operation.provider_snapshot, credentials, operation.intent, opts)
  end

  defp cleanup_receipt(operation, _, _), do: {:ok, operation.receipt}

  defp mark_cleaned(operation),
    do: finish(operation, %{cleanup_status: "cleaned"}, "acme.dns.cleanup")

  defp required_values(operation) do
    siblings(operation)
    |> where(
      [d, o],
      o.state not in ^@terminal and d.state in ["presented", "propagated"] and
        d.cleanup_status != "cleaned"
    )
    |> select([d], d.value)
    |> Repo.all()
    |> then(&Enum.uniq([operation.value | &1]))
  end

  defp shared_value_in_use?(operation) do
    siblings(operation)
    |> where(
      [d, o],
      d.id != ^operation.id and d.value == ^operation.value and d.cleanup_status != "cleaned" and
        o.state not in ^@terminal
    )
    |> Repo.exists?()
  end

  defp siblings(operation) do
    zone = operation.provider_snapshot["zone_id"]
    provider = operation.provider_snapshot["provider"]

    from(d in DNSChallengeOperation,
      join: o in AcmeOrder,
      on: o.id == d.order_id,
      where:
        d.owner == ^operation.owner and fragment("?->>'zone_id'", d.provider_snapshot) == ^zone and
          fragment("?->>'provider'", d.provider_snapshot) == ^provider
    )
  end

  defp claim(operation) do
    id = if is_binary(operation), do: operation, else: operation.id

    Repo.transaction(fn ->
      operation =
        Repo.one(from(d in DNSChallengeOperation, where: d.id == ^id, lock: "FOR UPDATE")) ||
          Repo.rollback(:not_found)

      now = ManagedCertificates.now()

      if operation.claim_token && operation.claim_expires_at &&
           DateTime.compare(operation.claim_expires_at, now) == :gt,
         do: Repo.rollback(:operation_busy)

      ManagedCertificates.update!(
        Changeset.change(operation,
          claim_token: Ecto.UUID.generate(),
          claim_expires_at: DateTime.add(now, @claim_seconds)
        )
      )
    end)
  end

  defp begin_effect(operation, attrs) do
    Repo.transaction(fn ->
      current = ManagedCertificates.locked!(DNSChallengeOperation, operation.id)

      if current.claim_token != operation.claim_token or is_nil(current.claim_expires_at) or
           DateTime.compare(current.claim_expires_at, ManagedCertificates.now()) != :gt,
         do: Repo.rollback(:stale_dns_claim)

      ManagedCertificates.update!(Changeset.change(current, attrs))
    end)
  end

  defp new_effect_allowed(order_id, opts) do
    order = Repo.get!(AcmeOrder, order_id)
    resource = Repo.get!(ManagedCertificate, order.managed_certificate_id)
    expected_claim = opts[:order_claim] || opts[:claim_token]

    cond do
      stale_order_claim?(order, expected_claim) ->
        {:error, :stale_order_claim}

      order.state in @terminal ->
        {:error, :order_terminal}

      resource.configuration_revision != order.configuration_revision ->
        {:error, :configuration_superseded}

      not ManagedCertificates.enabled?(resource) ->
        {:error, :disabled}

      true ->
        :ok
    end
  end

  defp stale_order_claim?(_, nil), do: false

  defp stale_order_claim?(order, expected_claim) do
    order.claim_token != expected_claim or is_nil(order.claim_expires_at) or
      DateTime.compare(order.claim_expires_at, ManagedCertificates.now()) != :gt
  end

  defp credentials(operation, opts),
    do:
      Keyword.get(opts, :credentials_resolver, &ManagedCertificates.credentials/1).(
        operation.provider_snapshot
      )

  defp with_owner_lock(operation, fun) do
    scope =
      {operation.provider_snapshot["provider"], operation.provider_snapshot["zone_id"],
       operation.owner}

    <<key::signed-64, _::binary>> = :crypto.hash(:sha256, :erlang.term_to_binary(scope))

    Repo.checkout(fn ->
      case Repo.query!("SELECT pg_try_advisory_lock($1)", [key]).rows do
        [[true]] ->
          try do
            fun.()
          after
            Repo.query!("SELECT pg_advisory_unlock($1)", [key])
          end

        [[false]] ->
          {:error, :owner_busy}
      end
    end)
  end

  defp locked_result({:error, :owner_busy}, operation), do: fail(operation, :owner_busy)
  defp locked_result(result, _), do: result

  defp finish(operation, attrs, event) do
    persist(operation, Map.merge(%{last_error: %{}, next_attempt_at: nil}, attrs), event, true)
  end

  defp fail(operation, reason, attrs \\ %{}) do
    reason = sanitize(reason)

    case persist(
           operation,
           Map.merge(
             %{
               last_error: %{"reason" => to_string(reason)},
               next_attempt_at: DateTime.add(ManagedCertificates.now(), 30)
             },
             attrs
           ),
           nil,
           true
         ) do
      {:ok, _} -> {:error, reason}
      error -> error
    end
  end

  defp persist(operation, attrs, event, release_claim?) do
    Repo.transaction(fn ->
      current = ManagedCertificates.locked!(DNSChallengeOperation, operation.id)
      # Keep receipts even when cancellation/revision changes revoke the order's
      # publication claim. A stale claim never authorizes a second provider effect.
      attrs =
        if release_claim? and current.claim_token == operation.claim_token,
          do: Map.merge(attrs, %{claim_token: nil, claim_expires_at: nil}),
          else: attrs

      updated = ManagedCertificates.update!(Changeset.change(current, attrs))
      if event, do: ManagedCertificates.audit!(event, current.id, %{order_id: current.order_id})
      updated
    end)
  end

  defp after_effect(result, opts) do
    if hook = opts[:after_effect], do: hook.(result)
  end

  defp sanitize(%{reason: reason}) when is_atom(reason), do: reason
  defp sanitize(reason) when is_atom(reason), do: reason
  defp sanitize(_), do: :dns_operation_failed

  defp normalize_binding(%{"provider" => "route53"} = binding),
    do: Map.update!(binding, "zone_id", &String.trim_leading(&1, "/hostedzone/"))

  defp normalize_binding(binding), do: binding
end
