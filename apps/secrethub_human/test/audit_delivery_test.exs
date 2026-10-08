defmodule SecretHub.Human.AuditDeliveryTest do
  use SecretHub.Human.DataCase, async: false
  alias Ecto.Adapters.SQL.Sandbox
  alias SecretHub.Core.Audit, as: CoreAudit
  alias SecretHub.Core.Repo, as: CoreRepo
  alias SecretHub.Human.Audit
  alias SecretHub.Human.Audit.Event
  alias SecretHub.Human.Repo
  alias SecretHub.Shared.Schemas.AuditLog

  setup_all do
    if is_nil(Process.whereis(CoreRepo)), do: start_supervised!(CoreRepo)
    Sandbox.mode(CoreRepo, :manual)
    :ok
  end

  setup do
    owner = Sandbox.start_owner!(CoreRepo, shared: true)
    on_exit(fn -> Sandbox.stop_owner(owner) end)
    :ok
  end

  test "outbox delivery commits canonical Core evidence once despite retries" do
    subject = Ecto.UUID.generate()

    assert {:ok, id} =
             Audit.record("human.login.failed", %{id: subject}, %{reason: "invalid_credentials"})

    assert [%{args: %{"event_id" => ^id}}] =
             Oban.Testing.all_enqueued(repo: Repo) |> Enum.filter(&(&1.args["event_id"] == id))

    assert :ok = Audit.deliver(id)
    assert :ok = Audit.deliver(id)

    assert [
             %{
               hash_version: 2,
               actor_id: ^subject,
               event_data: %{"reason" => "invalid_credentials"}
             }
           ] =
             CoreRepo.all(from(a in AuditLog, where: a.correlation_id == ^id))

    assert Repo.get!(Event, id).delivered_at
    assert {:ok, :valid} = CoreAudit.verify_chain()

    assert {:error, :event_conflict} =
             SecretHub.Access.record_human_event(
               "human.login.failed",
               subject,
               %{reason: "expired"},
               id
             )
  end

  test "secret-shaped data is rejected before an outbox or job is inserted" do
    before_events = Repo.aggregate(Event, :count)
    before_jobs = Oban.Testing.all_enqueued(repo: Repo) |> Enum.map(& &1.id) |> Enum.sort()

    assert {:error, :invalid_evidence} =
             Audit.record("human.login.failed", nil, %{password: "secret"})

    assert Repo.aggregate(Event, :count) == before_events

    assert Oban.Testing.all_enqueued(repo: Repo) |> Enum.map(& &1.id) |> Enum.sort() ==
             before_jobs
  end
end
