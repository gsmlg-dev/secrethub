defmodule SecretHub.Core.Vault.AvailabilityTest do
  use ExUnit.Case, async: false
  alias SecretHub.Core.Vault.SealState

  defmodule FailingRepo do
    def all(_, _opts \\ []),
      do: raise(DBConnection.ConnectionError, message: "private database diagnostic")
  end

  defmodule DelayedRepo do
    def all(_, _opts \\ []) do
      case Agent.get(__MODULE__, & &1) do
        :unavailable -> raise DBConnection.ConnectionError, message: "not yet ready"
        :empty -> []
      end
    end
  end

  defmodule InsertFailureRepo do
    def all(_, _opts \\ []), do: []
    def transaction(_), do: {:error, :insert_failed}
  end

  defmodule SlowRepo do
    def all(_, _opts \\ []) do
      Process.sleep(200)
      []
    end
  end

  setup do
    if pid = Process.whereis(SealState), do: GenServer.stop(pid)
    on_exit(fn -> if pid = Process.whereis(SealState), do: GenServer.stop(pid) end)
    :ok
  end

  test "startup database failure is unavailable and refuses initialization" do
    {:ok, _} = SealState.start_link(repo: FailingRepo, retry_interval: 10)
    await_state(:unavailable)
    assert %{state: :unavailable, initialized: false, sealed: true} = SealState.status()
    assert {:error, "Vault durable state unavailable"} = SealState.initialize(5, 3)
    assert {:error, :unavailable} = SealState.get_master_key()
  end

  test "delayed database availability recovers only after a successful empty read" do
    start_supervised!(%{
      id: DelayedRepo,
      start: {Agent, :start_link, [fn -> :unavailable end, [name: DelayedRepo]]}
    })

    {:ok, _} = SealState.start_link(repo: DelayedRepo, retry_interval: 5)
    await_state(:unavailable)
    assert SealState.status().state == :unavailable
    Agent.update(DelayedRepo, fn _ -> :empty end)
    await_empty(50)
    assert %{state: :not_initialized, sealed: true} = SealState.status()
  end

  test "failed persistence returns no shares and leaves no initialized state" do
    {:ok, _} = SealState.start_link(repo: InsertFailureRepo)
    await_state(:not_initialized)

    assert {:error, "Vault initialization failed; durable state unavailable"} =
             SealState.initialize(5, 3)

    assert SealState.status().state == :unavailable
    assert {:error, :unavailable} = SealState.get_master_key()
  end

  test "loading status remains responsive during a delayed database read" do
    {:ok, _} = SealState.start_link(repo: SlowRepo)
    started = System.monotonic_time(:millisecond)
    assert %{state: :loading, sealed: true, initialized: false} = SealState.status()
    assert System.monotonic_time(:millisecond) - started < 100
    assert {:error, "Vault durable state unavailable"} = SealState.initialize(5, 3)
    assert {:error, :unavailable} = SealState.get_master_key()
    await_empty(100)
  end

  test "load timeout cancels its task and remains unavailable" do
    {:ok, _} = SealState.start_link(repo: SlowRepo, load_timeout: 20)
    await_state(:unavailable)
    assert %{state: :unavailable, initialized: false, sealed: true} = SealState.status()
    assert [] = Task.Supervisor.children(:sys.get_state(SealState).task_supervisor)
  end

  defp await_state(expected, remaining \\ 100)
  defp await_state(_, 0), do: flunk("Vault state did not recover")

  defp await_state(expected, remaining) do
    if SealState.status().state != expected do
      Process.sleep(5)
      await_state(expected, remaining - 1)
    end
  end

  defp await_empty(0), do: flunk("Vault did not recover after database became available")

  defp await_empty(attempts) do
    if SealState.status().state != :not_initialized do
      Process.sleep(5)
      await_empty(attempts - 1)
    end
  end
end
