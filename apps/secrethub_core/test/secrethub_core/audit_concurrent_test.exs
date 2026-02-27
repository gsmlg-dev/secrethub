defmodule SecretHub.Core.AuditConcurrentTest do
  @moduledoc """
  P1: Audit log concurrent insert tests.

  Verifies that the audit logging system handles concurrent writes correctly
  with proper sequence numbers and hash chain integrity.
  """

  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.Audit
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.AuditLog

  import Ecto.Query

  @moduletag :audit

  setup do
    # Clear any existing audit logs for a clean chain
    Repo.delete_all(AuditLog)
    :ok
  end

  describe "P1: Concurrent audit log inserts" do
    test "10 concurrent log_event calls all succeed" do
      tasks =
        Enum.map(1..10, fn i ->
          Task.async(fn ->
            Audit.log_event(%{
              event_type: "secret.accessed",
              actor_type: "agent",
              actor_id: "concurrent-agent-#{i}",
              agent_id: "concurrent-agent-#{i}",
              access_granted: true,
              event_data: %{test_index: i}
            })
          end)
        end)

      results = Task.await_many(tasks, 10_000)

      # All should succeed (no lost writes)
      success_count = Enum.count(results, fn result -> match?({:ok, _}, result) end)
      assert success_count == 10, "Expected 10 successful inserts, got #{success_count}"
    end

    test "after concurrent inserts, sequence numbers have no gaps" do
      tasks =
        Enum.map(1..10, fn i ->
          Task.async(fn ->
            Audit.log_event(%{
              event_type: "secret.accessed",
              actor_type: "agent",
              actor_id: "seq-agent-#{i}",
              agent_id: "seq-agent-#{i}",
              access_granted: true,
              event_data: %{test_index: i}
            })
          end)
        end)

      Task.await_many(tasks, 10_000)

      # Fetch all logs ordered by sequence number
      logs =
        from(a in AuditLog, order_by: [asc: a.sequence_number])
        |> Repo.all()

      assert length(logs) == 10

      # Verify sequence numbers are consecutive (no gaps)
      sequence_numbers = Enum.map(logs, & &1.sequence_number)

      Enum.chunk_every(sequence_numbers, 2, 1, :discard)
      |> Enum.each(fn [a, b] ->
        assert b == a + 1,
               "Sequence gap detected: #{a} -> #{b}"
      end)
    end

    test "after concurrent inserts, verify_chain returns {:ok, :valid}" do
      tasks =
        Enum.map(1..10, fn i ->
          Task.async(fn ->
            Audit.log_event(%{
              event_type: "secret.created",
              actor_type: "agent",
              actor_id: "chain-agent-#{i}",
              agent_id: "chain-agent-#{i}",
              access_granted: true,
              event_data: %{test_index: i}
            })
          end)
        end)

      Task.await_many(tasks, 10_000)

      assert {:ok, :valid} = Audit.verify_chain()
    end

    test "retry logic handles constraint errors correctly" do
      # Insert a sequence of events that may cause collisions
      results =
        Enum.map(1..5, fn i ->
          Audit.log_event(%{
            event_type: "secret.updated",
            actor_type: "agent",
            actor_id: "retry-agent",
            agent_id: "retry-agent",
            access_granted: true,
            event_data: %{step: i}
          })
        end)

      # All sequential inserts should succeed
      assert Enum.all?(results, fn result -> match?({:ok, _}, result) end)

      # Verify chain is intact
      assert {:ok, :valid} = Audit.verify_chain()
    end
  end
end
