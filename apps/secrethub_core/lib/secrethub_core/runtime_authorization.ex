defmodule SecretHub.Core.RuntimeAuthorization do
  @moduledoc "Linearizable static reads with independent Agent and application policy gates."
  import Ecto.Query

  alias SecretHub.Core.{
    AccessAudit,
    Audit,
    AuthorizationVersions,
    PolicyEvaluator,
    Repo,
    RuntimePrincipal,
    Secrets
  }

  alias SecretHub.Shared.AccessAudit.{Event, Telemetry}

  alias SecretHub.Shared.Schemas.{
    Agent,
    AppCertificate,
    AuthorizationEpoch,
    Certificate,
    Policy,
    Secret,
    SecretPathRevision
  }

  alias SecretHub.Shared.Schemas.Application, as: App

  def authorize_static_read(principal, path, known_revision \\ nil, correlation \\ %{})

  def authorize_static_read(%RuntimePrincipal{} = principal, path, known_revision, correlation) do
    context = audit_context(correlation)

    with {:ok, normalized} <- PolicyEvaluator.normalize_runtime_path(path),
         true <- is_nil(known_revision) or (is_integer(known_revision) and known_revision > 0),
         true <- is_binary(principal.agent_id) and is_binary(principal.application_id) do
      Repo.transaction(fn ->
        AuthorizationVersions.lock_for_share(Repo, principal.agent_id, principal.application_id)
        floor = Repo.get!(AuthorizationEpoch, 1).minimum_uds_auth_version

        gate =
          cond do
            floor == 2 and principal.local_auth_version != 2 ->
              {:error, :incompatible_version}

            is_nil(
              Repo.get_by(SecretHub.Shared.Schemas.UpgradeGate,
                name: "typed_runtime_authorization"
              )
            ) ->
              {:error, :authorization_unavailable}

            true ->
              :ok
          end

        # Hold entity/certificate locks until commit. Writers acquire epoch first.
        lock_identity_rows(principal)

        identity = %{
          agent_id: principal.agent_public_id,
          certificate_id: principal.agent_certificate_id
        }

        outcome =
          with :ok <- gate,
               {:ok, current} <-
                 RuntimePrincipal.resolve_runtime_principal(
                   identity,
                   principal.application_id,
                   principal.fingerprint,
                   Map.take(context, [:request_id, :attempt_id])
                 ),
               true <-
                 current.agent_id == principal.agent_id and
                   current.certificate_id == principal.certificate_id,
               :ok <- authorize_subject("agent:" <> current.agent_id, normalized),
               :ok <- authorize_subject("application:" <> current.application_id, normalized),
               {:ok, _key} <- SecretHub.Core.Vault.SealState.get_master_key(),
               %SecretPathRevision{} = revision <-
                 Repo.one(
                   from(r in SecretPathRevision,
                     where: r.secret_path == ^normalized,
                     lock: "FOR SHARE"
                   )
                 ),
               %Secret{secret_type: :static} = secret <-
                 Repo.one(
                   from(s in Secret, where: s.secret_path == ^normalized, lock: "FOR SHARE")
                 ) do
            if revision.revision == known_revision do
              {:ok, %{not_modified: true, revision: revision.revision, version: secret.version}}
            else
              case Secrets.read_decrypted(normalized) do
                {:ok, value, _} ->
                  {:ok, %{value: value, revision: revision.revision, version: secret.version}}

                {:error, reason} ->
                  {:error, normalize_read_error(reason)}
              end
            end
          else
            nil -> {:error, :not_found}
            false -> {:error, :invalid_principal}
            {:error, reason} -> {:error, reason}
            _ -> {:error, :not_found}
          end

        # Commit denied audit events, then return the denial without rolling back evidence.
        event_id =
          audit!(
            principal,
            normalized,
            outcome,
            Map.put(context, :identity_verified, verified_identity?(gate, outcome))
          )

        with {:ok, result} <- outcome, do: {:ok, Map.put(result, :audit_event_id, event_id)}
      end)
      |> case do
        {:ok, result} -> result
        {:error, reason} -> {:error, reason}
      end
    else
      false -> audit_rejected_read(principal, :invalid_revision, context)
      {:error, reason} -> audit_rejected_read(principal, reason, context)
    end
  rescue
    _ in [DBConnection.ConnectionError, Postgrex.Error] -> {:error, :audit_unavailable}
  catch
    :exit, _ -> {:error, :audit_unavailable}
  end

  def authorize_static_read(_, _, _, _), do: {:error, :invalid_principal}

  defp audit_rejected_read(principal, reason, context) do
    Repo.transaction(fn ->
      audit!(principal, nil, {:error, reason}, context)
      {:error, reason}
    end)
    |> case do
      {:ok, result} -> result
      {:error, failure} -> {:error, failure}
    end
  end

  defp lock_identity_rows(p) do
    Repo.one(from(a in Agent, where: a.id == ^p.agent_id, lock: "FOR SHARE"))
    Repo.one(from(a in App, where: a.id == ^p.application_id, lock: "FOR SHARE"))
    ids = Enum.sort([p.agent_certificate_id, p.certificate_id])
    Repo.all(from(c in Certificate, where: c.id in ^ids, order_by: c.id, lock: "FOR SHARE"))

    Repo.all(
      from(ac in AppCertificate, where: ac.certificate_id == ^p.certificate_id, lock: "FOR SHARE")
    )

    :ok
  end

  defp authorize_subject(subject, path) do
    policies =
      Repo.all(from(p in Policy, where: ^subject in p.entity_bindings or p.entity_bindings == []))

    context = %{
      entity_id: subject,
      secret_path: path,
      operation: "read",
      timestamp: DateTime.utc_now()
    }

    evaluations = Enum.map(policies, &{&1, PolicyEvaluator.evaluate_runtime(&1, context)})

    cond do
      Enum.any?(evaluations, fn {policy, decision} ->
        (policy.deny_policy and decision == {:deny, :explicit_deny}) or
            decision == {:deny, :malformed_policy}
      end) ->
        {:error, :permission_denied}

      Enum.any?(evaluations, fn {_policy, decision} -> match?({:allow, _}, decision) end) ->
        :ok

      true ->
        {:error, :permission_denied}
    end
  end

  defp audit!(principal, path, outcome, context) do
    granted = match?({:ok, _}, outcome)

    result =
      case outcome do
        {:ok, result} -> result
        {:error, _} -> %{}
      end

    reason =
      case outcome do
        {:ok, _} -> "allowed"
        {:error, reason} -> Event.reason(reason)
      end

    cache = if result[:not_modified], do: "hit", else: "miss"

    evidence =
      %{
        request_id: context.request_id,
        attempt_id: context.attempt_id,
        agent_id: principal.agent_public_id,
        operation: "read",
        secret_id: audit_secret_id(path),
        secret_path: path,
        secret_version: result[:version],
        phase: "core_decision",
        outcome: outcome_category(outcome),
        reason_code: reason,
        duration_us: System.monotonic_time(:microsecond) - context.started,
        cache_status: cache
      }
      |> Map.merge(identity_evidence(principal, context.identity_verified))

    decision = checked_observation!(evidence)

    Telemetry.emit(
      :authorization_result,
      %{count: 1, duration_us: evidence.duration_us},
      Map.take(Map.put(evidence, :source, "core"), [
        :source,
        :operation,
        :outcome,
        :reason_code,
        :cache_status
      ])
    )

    if granted do
      checked_observation!(
        %{evidence | phase: "core_access"}
        |> Map.put(:core_event_id, decision.event_id)
      )
    end

    attrs = %{
      event_type: "secret.accessed",
      actor_type: "application",
      actor_id: principal.application_id,
      agent_id: principal.agent_public_id,
      access_granted: granted,
      event_data: %{
        agent_id: principal.agent_public_id,
        certificate_fingerprint: principal.fingerprint,
        secret_path: path
      }
    }

    case Audit.log_event(attrs) do
      {:ok, _} -> decision.event_id
      _ -> Repo.rollback(:audit_unavailable)
    end
  end

  defp identity_evidence(principal, true),
    do: %{
      application_id: principal.application_id,
      identity_status: "verified",
      attribution: "core_certificate"
    }

  defp identity_evidence(_, false),
    do: %{application_id: nil, identity_status: "unverified", attribution: "none"}

  defp audit_secret_id(nil), do: nil

  defp audit_secret_id(path) do
    case Repo.get_by(Secret, secret_path: path) do
      nil -> nil
      secret -> secret.id
    end
  end

  defp checked_observation!(attrs) do
    case AccessAudit.record_core(attrs) do
      {:ok, observation} -> observation
      {:error, _} -> Repo.rollback(:audit_unavailable)
    end
  end

  defp verified_identity?(gate, outcome), do: gate == :ok and verified_outcome?(outcome)

  defp outcome_category({:ok, _}), do: "success"

  defp outcome_category({:error, reason})
       when reason in [
              :permission_denied,
              :invalid_principal,
              :invalid_application,
              :invalid_agent,
              :invalid_certificate,
              :invalid_fingerprint,
              :invalid_revision,
              :invalid_path,
              :incompatible_version,
              :unauthorized,
              :revoked,
              :disabled,
              :expired
            ],
       do: "denied"

  defp outcome_category({:error, _}), do: "error"

  defp verified_outcome?({:error, reason})
       when reason in [
              :invalid_principal,
              :invalid_application,
              :invalid_agent,
              :invalid_certificate,
              :invalid_fingerprint,
              :revoked,
              :disabled,
              :expired
            ],
       do: false

  defp verified_outcome?(_), do: true

  defp audit_context(correlation) do
    %{
      request_id: valid_uuid(correlation[:request_id]),
      attempt_id: valid_uuid(correlation[:attempt_id]),
      identity_verified: false,
      started: System.monotonic_time(:microsecond)
    }
  end

  defp valid_uuid(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> uuid
      :error -> Ecto.UUID.generate()
    end
  end

  defp normalize_read_error(:sealed), do: :sealed
  defp normalize_read_error(:initializing), do: :sealed
  defp normalize_read_error(_), do: :authorization_unavailable
end
