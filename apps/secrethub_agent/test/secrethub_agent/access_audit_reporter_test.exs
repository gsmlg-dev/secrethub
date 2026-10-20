defmodule SecretHub.Agent.AccessAudit.ReporterTest do
  use ExUnit.Case, async: true
  alias SecretHub.Agent.AccessAudit.{Journal, Reporter}
  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    journal = start_supervised!({Journal, state_dir: dir, name: nil})

    {:ok, _} =
      Journal.admit(
        %{
          operation: "read",
          outcome: "unknown",
          reason_code: "none",
          cache_status: "none",
          identity_status: "unverified",
          attribution: "none"
        },
        journal
      )

    %{journal: journal}
  end

  test "a lost acknowledgement after Core commit replays the identical event after reporter restart",
       %{journal: journal} do
    owner = self()

    reporter =
      start_supervised!(
        {Reporter,
         name: nil,
         journal: journal,
         submit: fn events ->
           send(owner, {:committed, events, self()})

           receive do
             :never -> {:ok, %{}}
           end
         end}
      )

    assert_receive {:committed, [event], ^reporter}
    assert {:ok, [^event]} = Journal.batch(journal)
    assert :ok = stop_supervised(Reporter)

    start_supervised!(
      {Reporter,
       name: nil,
       journal: journal,
       interval: 60_000,
       submit: fn events ->
         send(owner, {:replayed, events})
         {:ok, %{"accepted" => [], "duplicates" => Enum.map(events, & &1["event_id"])}}
       end}
    )

    assert_receive {:replayed, [^event]}
    assert eventually(fn -> Journal.batch(journal) == {:ok, []} end)
  end

  test "success replies acknowledge only explicitly returned submitted IDs", %{journal: journal} do
    owner = self()

    start_supervised!(
      {Reporter,
       name: nil,
       journal: journal,
       submit: fn events ->
         send(owner, {:submitted, events})
         {:ok, %{"accepted" => [], "duplicates" => []}}
       end}
    )

    assert_receive {:submitted, [event]}
    assert {:ok, [^event]} = Journal.batch(journal)
  end

  test "forged acknowledgements and transient failures preserve pending evidence", %{
    journal: journal
  } do
    owner = self()

    for reply <- [
          {:ok, %{"accepted" => [Ecto.UUID.generate()], "duplicates" => []}},
          {:error, :timeout},
          {:error, :unsupported}
        ] do
      start_supervised!(
        {Reporter,
         name: nil,
         journal: journal,
         submit: fn events ->
           send(owner, {:submitted, events})
           reply
         end}
      )

      assert_receive {:submitted, [event]}
      assert eventually(fn -> Journal.batch(journal) == {:ok, [event]} end)
      assert :ok = stop_supervised(Reporter)
    end
  end

  test "permanent schema rejection preserves original envelope in visible quarantine", %{
    journal: journal
  } do
    start_supervised!(
      {Reporter,
       name: nil,
       journal: journal,
       submit: fn _ ->
         {:error, %{"reason" => "unsupported_schema"}}
       end}
    )

    assert eventually(fn ->
             case Journal.health(journal) do
               {:ok, %{"quarantined_events" => 1}} -> true
               _ -> false
             end
           end)

    assert {:ok, []} = Journal.batch(journal)
  end

  test "events beyond retained Core history are preserved for explicit recovery", %{
    journal: journal
  } do
    start_supervised!(
      {Reporter,
       name: nil,
       journal: journal,
       submit: fn _ ->
         {:error, %{"reason" => "outside_retention"}}
       end}
    )

    assert eventually(fn ->
             case Journal.health(journal) do
               {:ok, %{"quarantined_events" => 1}} -> true
               _ -> false
             end
           end)

    assert {:ok, []} = Journal.batch(journal)
  end

  test "one bounded upload is in flight and reporter loss never loses the journal", %{
    journal: journal
  } do
    owner = self()

    pid =
      start_supervised!(
        {Reporter,
         name: nil,
         journal: journal,
         submit: fn events ->
           send(owner, {:in_flight, events})

           receive do
             :never -> {:error, :timeout}
           end
         end}
      )

    assert_receive {:in_flight, [_]}
    refute_receive {:in_flight, _}
    assert :ok = stop_supervised(Reporter)
    refute Process.alive?(pid)
    assert {:ok, [_]} = Journal.batch(journal)
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
end
