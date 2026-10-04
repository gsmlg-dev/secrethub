defmodule SecretHub.Core.AuthorizationVersionsTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.{Agents, Apps, AuthorizationVersions}
  alias SecretHub.Shared.Schemas.{AuthorizationEpoch, AuthorizationSubjectVersion}

  test "creation installs typed subjects and status changes bump in the same transaction" do
    {:ok, agent} = Agents.register_agent(%{agent_id: "auth-version-agent", name: "Version Agent"})
    {:ok, %{app: app}} = Apps.register_app(%{name: "auth-version-app", agent_id: agent.id})
    assert Repo.aggregate(AuthorizationEpoch, :count) == 1
    a = Repo.get!(AuthorizationSubjectVersion, "agent:" <> agent.id)
    p = Repo.get!(AuthorizationSubjectVersion, "application:" <> app.id)
    assert {:ok, _} = Apps.suspend_app(app.id)
    assert Repo.get!(AuthorizationSubjectVersion, p.subject).version > p.version
    assert Repo.get!(AuthorizationSubjectVersion, a.subject).version >= a.version
  end

  test "readers fail closed without installing missing subjects" do
    missing = Ecto.UUID.generate()

    assert {:error, :authorization_unavailable} =
             Repo.transaction(fn ->
               AuthorizationVersions.lock_for_share(Repo, missing, missing)
             end)

    refute Repo.get(AuthorizationSubjectVersion, "agent:" <> missing)
  end

  test "typed binding preflight reports missing and ambiguous identities" do
    assert {:error, :missing_subject} = AuthorizationVersions.resolve_binding("unknown")
    {:ok, agent} = Agents.register_agent(%{agent_id: "binding-identity", name: "Binding Agent"})
    assert AuthorizationVersions.resolve_binding(agent.agent_id) == {:ok, "agent:" <> agent.id}

    assert {:error, :missing_subject} =
             AuthorizationVersions.resolve_binding("application:" <> Ecto.UUID.generate())
  end

  test "bump locks and rollback do not retain subject changes" do
    {:ok, agent} = Agents.register_agent(%{agent_id: "rollback-agent", name: "Rollback Agent"})
    subject = "agent:" <> agent.id
    before = Repo.get!(AuthorizationSubjectVersion, subject).version

    assert {:error, :abort} =
             Repo.transaction(fn ->
               AuthorizationVersions.bump_subjects(Repo, [subject])
               Repo.rollback(:abort)
             end)

    assert Repo.get!(AuthorizationSubjectVersion, subject).version == before
  end
end
