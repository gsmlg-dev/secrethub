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

  test "the named Core Styx executes durable queued work after its instance restarts" do
    configured = Application.fetch_env!(:secrethub_core, SecretHub.Core.Styx)
    assert configured[:name] == SecretHub.Core.Styx
    assert configured[:repo] == Repo

    opts =
      configured
      |> Keyword.merge(
        testing: :disabled,
        plugins: false,
        peer: false,
        queues: [acme: [limit: 1, paused: true]]
      )

    {:ok, first} = Styx.start_link(opts)
    Process.unlink(first)
    {:ok, job} = Styx.insert(SecretHub.Core.Styx, Reconciler.new(%{}))
    assert Repo.get!(Styx.Job, job.id).state == "available"
    Supervisor.stop(first)
    {:ok, second} = Styx.start_link(Keyword.put(opts, :queues, acme: 1))
    Process.unlink(second)
    on_exit(fn -> if Process.alive?(second), do: Supervisor.stop(second) end)
    assert eventually(fn -> Repo.get!(Styx.Job, job.id).state == "completed" end)
    refute Process.whereis(SecretHub.Human.Styx)
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
