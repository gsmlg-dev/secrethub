defmodule SecretHub.Core.PKI.ACME.CoreRuntimeTest do
  use ExUnit.Case, async: false
  alias SecretHub.Core.PKI.ACME.Reconciler
  alias SecretHub.Core.Repo
  alias SecretHub.Core.RuntimeDatabaseFixture

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags, default_repo: true)
    :ok
  end

  test "the named Core Oban executes durable queued work after its instance restarts" do
    configured = Application.fetch_env!(:secrethub_core, SecretHub.Core.Oban)
    assert configured[:name] == SecretHub.Core.Oban
    assert configured[:repo] == Repo

    opts =
      configured
      |> Keyword.merge(
        testing: :disabled,
        plugins: false,
        notifier: Oban.Notifiers.PG,
        peer: false,
        queues: [acme: [limit: 1, paused: true]]
      )

    {:ok, first} = Oban.start_link(opts)
    Process.unlink(first)
    {:ok, job} = Oban.insert(SecretHub.Core.Oban, Reconciler.new(%{}))
    assert Repo.get!(Oban.Job, job.id).state == "available"
    Supervisor.stop(first)
    {:ok, second} = Oban.start_link(Keyword.put(opts, :queues, acme: 1))
    Process.unlink(second)
    on_exit(fn -> if Process.alive?(second), do: Supervisor.stop(second) end)
    assert eventually(fn -> Repo.get!(Oban.Job, job.id).state == "completed" end)
    refute Process.whereis(SecretHub.Human.Oban)
  end

  defp eventually(fun, attempts \\ 100)
  defp eventually(_, 0), do: false

  defp eventually(fun, attempts) do
    if fun.(),
      do: true,
      else:
        (
          Process.sleep(100)
          eventually(fun, attempts - 1)
        )
  end
end
