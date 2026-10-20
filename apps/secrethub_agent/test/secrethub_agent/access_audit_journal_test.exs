defmodule SecretHub.Agent.AccessAudit.JournalTest do
  use ExUnit.Case, async: true
  alias SecretHub.Agent.AccessAudit.Journal
  @moduletag :tmp_dir

  defp attrs,
    do: %{
      operation: "read",
      identity_status: "unverified",
      attribution: "none",
      outcome: "unknown",
      reason_code: "none",
      cache_status: "none",
      secret_path: "prod.db.password"
    }

  defp journal(dir, opts \\ []),
    do: start_supervised!({Journal, [state_dir: dir, name: nil] ++ opts})

  defp wal(dir), do: Path.join(dir, "access-audit/observations.wal")

  test "first startup fails before creating a WAL when a new ancestor cannot be durably linked",
       %{
         tmp_dir: dir
       } do
    parent = Path.join(dir, "write-and-traverse-only")
    File.mkdir!(parent)
    File.chmod!(parent, 0o300)
    on_exit(fn -> File.chmod!(parent, 0o700) end)
    state_dir = Path.join(parent, "new-ancestor/state")

    assert {:error, _} = start_supervised({Journal, [state_dir: state_dir, name: nil]})
    refute File.exists?(wal(state_dir))
    assert File.dir?(Path.join(parent, "new-ancestor"))
    File.chmod!(parent, 0o700)
    pid = journal(state_dir)
    assert {:ok, _} = Journal.admit(attrs(), pid)
  end

  test "synced admission survives process loss before upload and before transport observation", %{
    tmp_dir: dir
  } do
    pid = journal(dir)
    assert {:ok, request} = Journal.admit(attrs(), pid)

    assert {:ok, _} =
             Journal.append(request.reservation, Map.put(attrs(), :phase, "attempt"), pid)

    assert {:ok, _} =
             Journal.append(request.reservation, Map.put(attrs(), :phase, "release_intent"), pid)

    assert :ok = stop_supervised(Journal)
    pid = journal(dir)
    assert {:ok, [admitted, attempt, intent]} = Journal.batch(pid)
    assert admitted["request_id"] == request.request_id
    assert attempt["attempt_id"] == request.attempt_id
    assert intent["phase"] == "release_intent"
    # Nothing invents a sent result or retries delivery after a crash.
    assert {:error, :invalid_reservation} = Journal.finish(request.reservation, attrs(), pid)
  end

  test "acknowledged empty compaction retains producer and monotonically increasing sequence", %{
    tmp_dir: dir
  } do
    pid = journal(dir)
    assert {:ok, _} = Journal.admit(attrs(), pid)
    assert {:ok, [event]} = Journal.batch(pid)
    assert :ok = Journal.acknowledge([event["event_id"]], pid)
    assert {:ok, []} = Journal.batch(pid)
    assert :ok = stop_supervised(Journal)
    pid = journal(dir)
    assert {:ok, _} = Journal.admit(attrs(), pid)
    assert {:ok, [next]} = Journal.batch(pid)
    assert next["producer_id"] == event["producer_id"]
    assert next["producer_sequence"] == event["producer_sequence"] + 1
  end

  test "admission reserves all terminal records when event capacity is exhausted", %{tmp_dir: dir} do
    pid = journal(dir, max_events: 4, max_admissions: 1)
    assert {:ok, request} = Journal.admit(attrs(), pid)
    assert {:error, :journal_full} = Journal.admit(attrs(), pid)

    for phase <- ~w(attempt release_intent) do
      assert {:ok, _} = Journal.append(request.reservation, Map.put(attrs(), :phase, phase), pid)
    end

    terminal =
      Map.merge(attrs(), %{phase: "response_sent", outcome: "success", reason_code: "allowed"})

    assert {:ok, _} = Journal.finish(request.reservation, terminal, pid)
    assert {:ok, [_, _, _, %{"phase" => "response_sent"}]} = Journal.batch(pid)
    assert {:error, :journal_full} = Journal.admit(attrs(), pid)
  end

  test "byte admission fails without writing partial evidence and never evicts unacked events", %{
    tmp_dir: dir
  } do
    pid = journal(dir, max_bytes: 20_000)
    assert {:ok, _} = Journal.admit(attrs(), pid)
    before = File.read!(wal(dir))
    assert {:error, :journal_full} = Journal.admit(attrs(), pid)
    assert {:ok, [_]} = Journal.batch(pid)
    # Capacity reclamation may compact, but the original accepted event survives.
    assert byte_size(File.read!(wal(dir))) <= byte_size(before)
  end

  test "partial tail, checksum damage, and interrupted compaction preserve evidence and fail closed",
       %{tmp_dir: dir} do
    for damage <- [:tail, :checksum, :compaction] do
      subdir = Path.join(dir, Atom.to_string(damage))
      pid = journal(subdir)
      assert {:ok, _} = Journal.admit(attrs(), pid)
      assert :ok = stop_supervised(Journal)

      case damage do
        :tail ->
          File.write!(wal(subdir), <<0, 0, 0>>, [:append])

        :checksum ->
          <<prefix::binary-size(40), byte, rest::binary>> = File.read!(wal(subdir))
          File.write!(wal(subdir), <<prefix::binary, Bitwise.bxor(byte, 1), rest::binary>>)

        :compaction ->
          File.write!(wal(subdir) <> ".compact", "retained evidence")
      end

      damaged = File.read!(wal(subdir))
      assert {:error, _} = start_supervised({Journal, [state_dir: subdir, name: nil]})
      assert File.read!(wal(subdir)) == damaged
    end
  end

  test "write and sync failures refuse new observations and delivery while preserving prior evidence",
       %{tmp_dir: dir} do
    pid = journal(dir)
    assert {:ok, request} = Journal.admit(attrs(), pid)
    # Execute close in the raw file owner's process, producing a real closed-fd I/O failure.
    :sys.replace_state(pid, fn state ->
      :file.close(state.file)
      state
    end)

    assert {:error, :audit_unavailable} =
             Journal.append(request.reservation, Map.put(attrs(), :phase, "attempt"), pid)

    assert {:error, :audit_unavailable} = Journal.admit(attrs(), pid)
    assert {:ok, %{"journal_status" => "audit_unavailable"}} = Journal.health(pid)
    assert :ok = stop_supervised(Journal)
    pid = journal(dir)
    assert {:ok, [%{"phase" => "admitted"}]} = Journal.batch(pid)
  end

  test "real kernel ENOSPC refuses delivery and preserves accepted WAL evidence", %{tmp_dir: dir} do
    pid = journal(dir)
    assert {:ok, request} = Journal.admit(attrs(), pid)
    accepted = File.read!(wal(dir))

    :sys.replace_state(pid, fn state ->
      :ok = :file.close(state.file)
      {:ok, full} = :file.open(~c"/dev/full", [:raw, :binary, :write])
      assert {:error, :enospc} = :file.write(full, "disposable capacity probe")
      %{state | file: full}
    end)

    assert {:error, :audit_unavailable} =
             Journal.append(request.reservation, Map.put(attrs(), :phase, "attempt"), pid)

    assert {:error, :audit_unavailable} = Journal.admit(attrs(), pid)
    assert File.read!(wal(dir)) == accepted
    assert :ok = stop_supervised(Journal)
    pid = journal(dir)
    assert {:ok, [%{"phase" => "admitted"}]} = Journal.batch(pid)
  end

  test "directory-sync failure after atomic rename enters unavailable state and replay retains committed sequence",
       %{tmp_dir: dir} do
    pid = journal(dir)
    assert {:ok, _} = Journal.admit(attrs(), pid)
    assert {:ok, [event]} = Journal.batch(pid)
    # Preserve the real WAL path and replacement write, fail only directory sync.
    :sys.replace_state(pid, &%{&1 | dir: Path.join(dir, "missing-sync-directory")})
    assert {:error, :audit_unavailable} = Journal.acknowledge([event["event_id"]], pid)
    assert {:error, :audit_unavailable} = Journal.admit(attrs(), pid)
    assert :ok = stop_supervised(Journal)
    pid = journal(dir)
    assert {:ok, []} = Journal.batch(pid)
    assert {:ok, %{"producer_id" => producer, "producer_sequence" => 1}} = Journal.health(pid)
    assert producer == event["producer_id"]
  end

  test "quarantine is persistent bounded evidence and stops new admission when full", %{
    tmp_dir: dir
  } do
    pid = journal(dir, max_quarantine: 1)
    assert {:ok, _} = Journal.admit(attrs(), pid)
    assert {:ok, [event]} = Journal.batch(pid)
    assert :ok = Journal.quarantine([event["event_id"]], "unsupported_schema", pid)
    assert {:ok, []} = Journal.batch(pid)
    assert {:error, :journal_full} = Journal.admit(attrs(), pid)
    assert :ok = stop_supervised(Journal)
    pid = journal(dir, max_quarantine: 1)

    assert {:ok, %{"quarantined_events" => 1, "journal_status" => "quarantined"}} =
             Journal.health(pid)

    assert File.read!(wal(dir)) =~ event["event_id"]
  end

  @tag :quarantine_replay
  test "operator replay durably restores identical quarantined observations without resetting identity or sequence",
       %{tmp_dir: dir} do
    pid = journal(dir)
    assert {:ok, _} = Journal.admit(attrs(), pid)
    assert {:ok, [original]} = Journal.batch(pid)
    id = original["event_id"]
    assert :ok = Journal.quarantine([id], "unsupported_schema", pid)
    assert :ok = stop_supervised(Journal)
    pid = journal(dir)
    assert {:ok, [entry]} = Journal.quarantined(pid)

    assert entry ==
             Map.take(original, ~w(event_id request_id producer_sequence))
             |> Map.put("reason", "unsupported_schema")

    assert :ok = Journal.replay_quarantined([id], pid)
    assert {:ok, []} = Journal.quarantined(pid)
    assert {:ok, [^original]} = Journal.batch(pid)
    assert {:ok, %{"quarantined_events" => 0}} = Journal.health(pid)
    assert :ok = stop_supervised(Journal)
    pid = journal(dir)
    assert {:ok, [^original]} = Journal.batch(pid)
    assert :ok = Journal.acknowledge([id], pid)
    assert {:ok, _} = Journal.admit(attrs(), pid)
    assert {:ok, [next]} = Journal.batch(pid)
    assert next["producer_id"] == original["producer_id"]
    assert next["producer_sequence"] == original["producer_sequence"] + 1
  end

  @tag :quarantine_replay
  test "operator replay rejects unknown, repeated, or oversized IDs atomically", %{tmp_dir: dir} do
    pid = journal(dir)
    assert {:ok, _} = Journal.admit(attrs(), pid)
    assert {:ok, [event]} = Journal.batch(pid)
    id = event["event_id"]
    assert :ok = Journal.quarantine([id], "invalid_event", pid)
    retained = File.read!(wal(dir))

    for ids <- [[Ecto.UUID.generate()], [id, id], List.duplicate(id, 101)] do
      assert {:error, :invalid_replay} = Journal.replay_quarantined(ids, pid)
      assert File.read!(wal(dir)) == retained
      assert {:ok, []} = Journal.batch(pid)
    end
  end

  test "unknown fields and secret/token canaries never enter WAL", %{tmp_dir: dir} do
    pid = journal(dir)
    canary = "disposable-secret-token-canary-48296"
    assert {:error, :invalid_event} = Journal.admit(Map.put(attrs(), :value, canary), pid)
    assert {:error, :invalid_event} = Journal.admit(Map.put(attrs(), :token, canary), pid)
    refute File.read!(wal(dir)) =~ canary
    assert {:ok, []} = Journal.batch(pid)
  end

  test "consumer crash releases reservation and retains incomplete accepted evidence", %{
    tmp_dir: dir
  } do
    pid = journal(dir, max_events: 8, max_admissions: 1)
    owner = self()

    consumer =
      spawn(fn ->
        result = Journal.admit(attrs(), pid)
        send(owner, {:admitted, result})

        receive do
          :never -> :ok
        end
      end)

    assert_receive {:admitted, {:ok, _}}, 2_000
    assert {:error, :journal_full} = Journal.admit(attrs(), pid)
    Process.exit(consumer, :kill)
    # :DOWN is sent by the runtime; a subsequent call observes the released slot.
    assert eventually(fn ->
             case Journal.admit(attrs(), pid) do
               {:ok, _} -> true
               _ -> false
             end
           end)

    assert {:ok, [%{"phase" => "admitted"}, %{"phase" => "admitted"}]} = Journal.batch(pid)
  end

  test "batch selection respects both finite record and encoded byte limits", %{tmp_dir: dir} do
    pid = journal(dir, max_events: 1_000, max_admissions: 200)
    for _ <- 1..120, do: assert({:ok, _} = Journal.admit(attrs(), pid))
    assert {:ok, events} = Journal.batch(pid)
    assert length(events) == 100
    assert byte_size(Jason.encode!(events)) <= 131_072
  end

  defp eventually(fun, attempts \\ 100)
  defp eventually(_fun, 0), do: false

  defp eventually(fun, attempts) do
    if fun.(),
      do: true,
      else:
        (
          Process.sleep(10)
          eventually(fun, attempts - 1)
        )
  end

  test "acknowledgements cannot remove events not named in committed reply", %{tmp_dir: dir} do
    pid = journal(dir)
    assert {:ok, _} = Journal.admit(attrs(), pid)
    assert {:ok, [event]} = Journal.batch(pid)
    assert {:error, :invalid_acknowledgement} = Journal.acknowledge([Ecto.UUID.generate()], pid)
    assert {:ok, [^event]} = Journal.batch(pid)
  end
end

defmodule SecretHub.Agent.AccessAudit.JournalDirectoryDurabilityTest do
  use ExUnit.Case, async: false
  alias SecretHub.Agent.AccessAudit.Journal
  @moduletag :tmp_dir

  for failed_startup <- [false, true] do
    test "directory links are durable before acknowledgement after failed startup: #{failed_startup}",
         %{
           tmp_dir: dir
         } do
      ancestor = Path.join(dir, "new-ancestor")
      state_dir = Path.join(ancestor, "state")
      wal = Path.join(state_dir, "access-audit/observations.wal")
      owner = self()

      if unquote(failed_startup) do
        File.chmod!(dir, 0o300)
        on_exit(fn -> File.chmod!(dir, 0o700) end)
        assert {:error, _} = start_supervised({Journal, [state_dir: state_dir, name: nil]})
        assert File.dir?(ancestor)
        File.chmod!(dir, 0o700)
      end

      starter =
        spawn(fn ->
          receive do
            :start ->
              result = Journal.start_link(state_dir: state_dir, name: nil)
              send(owner, {:started, self(), result})

              receive do
                :stop ->
                  case result do
                    {:ok, pid} -> GenServer.stop(pid)
                    _ -> :ok
                  end
              end
          end
        end)

      for {function, arity} <- [open: 2, sync: 1] do
        :erlang.trace_pattern({:file, function, arity}, [{:_, [], [{:return_trace}]}], [:local])
      end

      :erlang.trace(starter, true, [:call, :set_on_spawn, {:tracer, owner}])

      on_exit(fn ->
        for {function, arity} <- [open: 2, sync: 1] do
          :erlang.trace_pattern({:file, function, arity}, false, [:local])
        end

        monitor = Process.monitor(starter)
        send(starter, :stop)
        assert_receive {:DOWN, ^monitor, :process, ^starter, _}, 2_000
      end)

      send(starter, :start)
      assert_receive {:started, ^starter, {:ok, pid}}, 2_000

      assert {:ok, _} =
               Journal.admit(
                 %{
                   operation: "read",
                   identity_status: "unverified",
                   attribution: "none",
                   outcome: "unknown",
                   reason_code: "none",
                   cache_status: "none"
                 },
                 pid
               )

      delivered = :erlang.trace_delivered(pid)

      operations =
        pid |> collect_trace(delivered, []) |> Enum.chunk_every(2) |> Enum.map(&operation/1)

      first_wal_open = Enum.find_index(operations, &match?({:open, ^wal, _}, &1))
      assert is_integer(first_wal_open)

      for parent <- [dir, ancestor, state_dir] do
        assert {:open, ^parent, descriptor} =
                 Enum.find(operations, &match?({:open, ^parent, _}, &1))

        sync = Enum.find_index(operations, &(&1 == {:sync, descriptor}))
        assert is_integer(sync) and sync < first_wal_open
      end
    end
  end

  defp collect_trace(pid, delivered, events) do
    receive do
      {:trace_delivered, ^pid, ^delivered} -> Enum.reverse(events)
      {:trace, ^pid, _, _} = event -> collect_trace(pid, delivered, [event | events])
      {:trace, ^pid, _, _, _} = event -> collect_trace(pid, delivered, [event | events])
    after
      2_000 -> flunk("journal file-operation traces were not delivered")
    end
  end

  defp operation([
         {:trace, _, :call, {:file, :open, [path, _options]}},
         {:trace, _, :return_from, {:file, :open, 2}, {:ok, descriptor}}
       ]),
       do: {:open, to_string(path), descriptor}

  defp operation([
         {:trace, _, :call, {:file, :sync, [descriptor]}},
         {:trace, _, :return_from, {:file, :sync, 1}, :ok}
       ]),
       do: {:sync, descriptor}
end
