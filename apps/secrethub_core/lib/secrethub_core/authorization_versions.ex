defmodule SecretHub.Core.AuthorizationVersions do
  @moduledoc """
  Fixed-order locks for runtime reads and authorization mutations.

  Readers never create missing state. Database mutation triggers acquire the
  global write lock before entity rows and maintain subject versions atomically.
  This deliberately serializes writers while allowing concurrent runtime reads.
  """
  import Ecto.Query
  alias SecretHub.Core.Repo

  alias SecretHub.Shared.Schemas.{
    Agent,
    Application,
    AuthorizationEpoch,
    AuthorizationSubjectVersion,
    Policy
  }

  def lock_for_share(repo, agent_id, app_id) do
    epoch = repo.one(from(e in AuthorizationEpoch, where: e.id == 1, lock: "FOR SHARE"))
    agent = lock_subject(repo, "agent:" <> agent_id, "FOR SHARE")
    app = lock_subject(repo, "application:" <> app_id, "FOR SHARE")

    if epoch && agent && app,
      do: %{global: epoch.version, agent: agent.version, application: app.version},
      else: repo.rollback(:authorization_unavailable)
  end

  def bump_subjects(repo, subjects) do
    lock_global(repo)

    subjects
    |> Enum.uniq()
    |> Enum.sort_by(&subject_order/1)
    |> Enum.each(fn subject ->
      if lock_subject(repo, subject, "FOR UPDATE") do
        repo.update_all(from(s in AuthorizationSubjectVersion, where: s.subject == ^subject),
          inc: [version: 1]
        )
      else
        repo.rollback(:authorization_unavailable)
      end
    end)

    :ok
  end

  def lock_global(repo \\ Repo) do
    repo.one(from(e in AuthorizationEpoch, where: e.id == 1, lock: "FOR UPDATE")) ||
      repo.rollback(:authorization_unavailable)
  end

  def resolve_binding("agent:" <> id) do
    if valid_uuid?(id) && Repo.get(Agent, id),
      do: {:ok, "agent:" <> id},
      else: {:error, :missing_subject}
  end

  def resolve_binding("application:" <> id) do
    if valid_uuid?(id) && Repo.get(Application, id),
      do: {:ok, "application:" <> id},
      else: {:error, :missing_subject}
  end

  def resolve_binding(value) when is_binary(value) do
    agents = Repo.all(from(a in Agent, where: a.agent_id == ^value, select: a.id))

    agents =
      if valid_uuid?(value) && Repo.get(Agent, value),
        do: Enum.uniq([value | agents]),
        else: agents

    apps = if valid_uuid?(value) && Repo.get(Application, value), do: [value], else: []

    case Enum.map(agents, &("agent:" <> &1)) ++ Enum.map(apps, &("application:" <> &1)) do
      [subject] -> {:ok, subject}
      [] -> {:error, :missing_subject}
      _ -> {:error, :ambiguous_subject}
    end
  end

  def resolve_binding(_), do: {:error, :missing_subject}

  def report do
    subjects =
      Enum.map(Repo.all(Agent), &("agent:" <> &1.id)) ++
        Enum.map(Repo.all(Application), &("application:" <> &1.id))

    missing =
      Enum.reject(subjects, &Repo.get(AuthorizationSubjectVersion, &1))
      |> Enum.map(&%{kind: "missing_subject_version", identifier: &1})

    binding_findings =
      Enum.flat_map(Repo.all(Policy), fn policy ->
        Enum.flat_map(policy.entity_bindings, fn binding ->
          case resolve_binding(binding) do
            {:ok, ^binding} -> []
            {:ok, _} -> [%{kind: "legacy_binding", identifier: policy.id}]
            {:error, reason} -> [%{kind: Atom.to_string(reason), identifier: policy.id}]
          end
        end)
      end)

    orphans =
      Repo.all(
        from(a in Application,
          left_join: g in Agent,
          on: a.agent_id == g.id,
          where: is_nil(g.id),
          select: a.id
        )
      )
      |> Enum.map(&%{kind: "orphan_assignment", identifier: &1})

    compatibility =
      Enum.flat_map(Repo.all(Application), fn app ->
        Enum.flat_map(app.policies, fn name ->
          case Repo.get_by(Policy, name: name) do
            nil ->
              [%{kind: "missing_compatibility_policy", identifier: app.id}]

            policy ->
              if ("application:" <> app.id) in policy.entity_bindings,
                do: [],
                else: [%{kind: "untyped_compatibility_policy", identifier: app.id}]
          end
        end)
      end)

    agent_links = Repo.query!("SELECT agent_id::text, policy_id::text FROM agents_policies").rows

    compatibility =
      compatibility ++
        Enum.flat_map(agent_links, fn [agent_id, policy_id] ->
          policy = Repo.get!(Policy, policy_id)

          if ("agent:" <> agent_id) in policy.entity_bindings,
            do: [],
            else: [%{kind: "untyped_agent_policy", identifier: agent_id}]
        end)

    fk =
      Repo.query!(
        "SELECT count(*) FROM pg_constraint WHERE conrelid = 'applications'::regclass AND contype = 'f' AND confrelid = 'agents'::regclass AND convalidated"
      ).rows

    fk_findings =
      if fk == [[1]],
        do: [],
        else: [%{kind: "unvalidated_application_agent_fk", identifier: "applications"}]

    epoch =
      if Repo.get(AuthorizationEpoch, 1),
        do: [],
        else: [%{kind: "missing_epoch", identifier: "1"}]

    %{
      format: "secrethub.upgrade-gate-report.v1",
      gate: "typed_runtime_authorization",
      preflight_version: "1",
      findings:
        Enum.sort_by(
          epoch ++ missing ++ binding_findings ++ orphans ++ compatibility ++ fk_findings,
          &{&1.kind, &1.identifier}
        )
    }
  end

  def backfill_bindings do
    Repo.transaction(fn ->
      lock_global()
      # Expand compatibility lists/joins into typed authoritative bindings first.
      Enum.each(Repo.all(Application), fn app ->
        Enum.each(app.policies, fn name ->
          policy = Repo.get_by(Policy, name: name) || Repo.rollback(:missing_policy)

          Repo.update!(
            Ecto.Changeset.change(policy,
              entity_bindings: Enum.uniq(["application:" <> app.id | policy.entity_bindings])
            )
          )
        end)
      end)

      Enum.each(
        Repo.query!("SELECT agent_id::text, policy_id::text FROM agents_policies").rows,
        fn [agent_id, policy_id] ->
          policy = Repo.get!(Policy, policy_id)

          Repo.update!(
            Ecto.Changeset.change(policy,
              entity_bindings: Enum.uniq(["agent:" <> agent_id | policy.entity_bindings])
            )
          )
        end
      )

      Enum.each(Repo.all(Policy), fn policy ->
        bindings =
          Enum.map(policy.entity_bindings, fn binding ->
            case resolve_binding(binding) do
              {:ok, typed} -> typed
              {:error, reason} -> Repo.rollback(reason)
            end
          end)

        Repo.update!(Ecto.Changeset.change(policy, entity_bindings: Enum.uniq(bindings)))
      end)

      :ok
    end)
  end

  defp lock_subject(repo, subject, "FOR SHARE"),
    do:
      repo.one(
        from(s in AuthorizationSubjectVersion, where: s.subject == ^subject, lock: "FOR SHARE")
      )

  defp lock_subject(repo, subject, "FOR UPDATE"),
    do:
      repo.one(
        from(s in AuthorizationSubjectVersion, where: s.subject == ^subject, lock: "FOR UPDATE")
      )

  defp subject_order("agent:" <> id), do: {0, id}
  defp subject_order("application:" <> id), do: {1, id}

  defp valid_uuid?(id),
    do:
      is_binary(id) and
        Regex.match?(~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/, id)
end
