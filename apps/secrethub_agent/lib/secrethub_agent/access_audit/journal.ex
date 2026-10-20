defmodule SecretHub.Agent.AccessAudit.Journal do
  @moduledoc """
  Serialized, synced access-observation WAL. No successful admission or append is
  returned before fsync. Corrupt/partial evidence requires explicit operator
  recovery; startup never truncates it. Reservations cover the attempt, intent,
  and transport observation of one operation (there are no automatic read retries).
  """
  use GenServer
  alias SecretHub.Shared.AccessAudit.{Event, Telemetry}

  @frame_bytes 4_608
  @max_record_bytes 8_192
  @max_replay_records 100_000

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  def admit(attrs, server \\ __MODULE__), do: call(server, {:admit, attrs})

  def append(reservation, attrs, server \\ __MODULE__),
    do: call(server, {:append, reservation, attrs, false})

  def finish(reservation, attrs, server \\ __MODULE__),
    do: call(server, {:append, reservation, attrs, true})

  def batch(server \\ __MODULE__), do: call(server, :batch)
  def acknowledge(ids, server \\ __MODULE__), do: call(server, {:acknowledge, ids})
  def quarantine(ids, reason, server \\ __MODULE__), do: call(server, {:quarantine, ids, reason})

  @doc "Explicit operator replay after compatibility repair; preserves original envelopes and identities."
  def replay_quarantined(ids, server \\ __MODULE__), do: call(server, {:replay_quarantined, ids})
  def health(server \\ __MODULE__), do: call(server, :health)
  def quarantined(server \\ __MODULE__), do: call(server, :quarantined)
  def compact(server \\ __MODULE__), do: call(server, :compact)

  def reporting_status(status, server \\ __MODULE__),
    do: call(server, {:reporting_status, status})

  defp call(server, message) do
    GenServer.call(server, message, 15_000)
  catch
    :exit, _ -> {:error, :audit_unavailable}
  end

  @impl true
  def init(opts) do
    :ok = Telemetry.install_handler_monitor()
    dir = Path.join(Keyword.fetch!(opts, :state_dir), "access-audit")
    path = Path.join(dir, "observations.wal")

    state = %{
      dir: dir,
      path: path,
      file: nil,
      bytes: 0,
      sequence: 0,
      producer_id: nil,
      pending: %{},
      pending_since: %{},
      quarantine: %{},
      reservations: %{},
      status: :healthy,
      reporting_status: :healthy,
      max_bytes: Keyword.get(opts, :max_bytes, 16_777_216),
      max_events: Keyword.get(opts, :max_events, 2_000),
      max_admissions: Keyword.get(opts, :max_admissions, 256),
      max_quarantine: min(Keyword.get(opts, :max_quarantine, 100), 100)
    }

    case open(state) do
      {:ok, state} -> {:ok, state}
      {:error, reason} -> {:stop, {:audit_journal_unavailable, reason}}
    end
  end

  @impl true
  def handle_call(:health, _from, state) do
    oldest =
      state.pending |> Map.values() |> Enum.map(& &1["observed_at"]) |> Enum.min(fn -> nil end)

    health = %{
      "producer_id" => state.producer_id,
      "producer_sequence" => state.sequence,
      "pending_events" => map_size(state.pending),
      "pending_bytes" => pending_bytes(state.pending),
      "quarantined_events" => map_size(state.quarantine),
      "oldest_pending_at" => oldest,
      "journal_status" =>
        cond do
          state.status != :healthy -> "audit_unavailable"
          map_size(state.quarantine) > 0 -> "quarantined"
          true -> Atom.to_string(state.reporting_status)
        end
    }

    health =
      case Map.values(state.pending_since) do
        [] ->
          health

        times ->
          Map.put(
            health,
            "oldest_pending_age_ms",
            max(System.monotonic_time(:millisecond) - Enum.min(times), 0)
          )
      end

    Telemetry.emit(
      :backlog,
      %{
        pending_events: map_size(state.pending),
        pending_bytes: pending_bytes(state.pending),
        quarantined_events: map_size(state.quarantine),
        oldest_pending_age_ms: Map.get(health, "oldest_pending_age_ms", 0)
      },
      %{source: "agent"}
    )

    {:reply, {:ok, health}, state}
  end

  def handle_call(:quarantined, _from, state) do
    entries =
      state.quarantine
      |> Map.values()
      |> Enum.sort_by(& &1["event"]["producer_sequence"])
      |> Enum.take(100)
      |> Enum.map(fn entry ->
        entry["event"]
        |> Map.take(~w(event_id request_id producer_sequence))
        |> Map.put("reason", entry["reason"])
      end)

    {:reply, {:ok, entries}, state}
  end

  def handle_call({:reporting_status, status}, _from, state)
      when status in [:healthy, :unsupported, :audit_unavailable],
      do: {:reply, :ok, %{state | reporting_status: status}}

  def handle_call(_message, _from, %{status: status} = state) when status != :healthy,
    do: {:reply, {:error, :audit_unavailable}, state}

  def handle_call({:admit, attrs}, {owner, _tag}, state) do
    reserved = reserved_events(state)

    if map_size(state.reservations) >= state.max_admissions or
         map_size(state.pending) + map_size(state.quarantine) + reserved + 4 > state.max_events or
         map_size(state.quarantine) >= state.max_quarantine do
      {:reply, {:error, :journal_full}, state}
    else
      token = Ecto.UUID.generate()

      context = %{
        request_id: Ecto.UUID.generate(),
        attempt_id: Ecto.UUID.generate(),
        reservation: token
      }

      attrs =
        Map.merge(attrs, %{request_id: context.request_id, attempt_id: nil, phase: "admitted"})

      with {:ok, state} <- ensure_space(state, (reserved + 4) * @frame_bytes),
           {:ok, _event, state} <- write_event(state, attrs) do
        reservation = %{
          remaining: 3,
          request_id: context.request_id,
          attempt_id: context.attempt_id,
          monitor: Process.monitor(owner)
        }

        state = put_in(state.reservations[token], reservation)
        {:reply, {:ok, context}, state}
      else
        {:error, reason, state} -> {:reply, {:error, reason}, state}
        {:error, reason} -> {:reply, {:error, reason}, state}
      end
    end
  end

  def handle_call({:append, token, attrs, finish?}, _from, state) do
    case state.reservations[token] do
      %{remaining: remaining} = reservation when remaining > 0 ->
        attrs =
          Map.merge(attrs, %{
            request_id: reservation.request_id,
            attempt_id: reservation.attempt_id
          })

        case write_event(state, attrs) do
          {:ok, event, state} ->
            state = complete_reservation(state, token, reservation, finish?)
            {:reply, {:ok, event}, state}

          {:error, reason, state} ->
            {:reply, {:error, reason}, state}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end

      _ ->
        {:reply, {:error, :invalid_reservation}, state}
    end
  end

  def handle_call(:batch, _from, state) do
    events = state.pending |> Map.values() |> Enum.sort_by(& &1["producer_sequence"])

    {batch, _bytes} =
      Enum.reduce_while(events, {[], 2}, fn event, {batch, bytes} ->
        size = byte_size(Event.canonical(event)) + 1

        if length(batch) == 100 or bytes + size > 131_072,
          do: {:halt, {batch, bytes}},
          else: {:cont, {[event | batch], bytes + size}}
      end)

    {:reply, {:ok, Enum.reverse(batch)}, state}
  end

  def handle_call({:acknowledge, []}, _from, state), do: {:reply, :ok, state}

  def handle_call({:acknowledge, ids}, _from, state) do
    if valid_ids?(ids, state.pending) do
      mutate(state, %{"type" => "ack", "ids" => ids}, fn state ->
        %{
          state
          | pending: Map.drop(state.pending, ids),
            pending_since: Map.drop(state.pending_since, ids)
        }
      end)
    else
      {:reply, {:error, :invalid_acknowledgement}, state}
    end
  end

  def handle_call({:quarantine, ids, reason}, _from, state) do
    if valid_ids?(ids, state.pending) and
         reason in ~w(invalid_event unsupported_schema event_conflict outside_retention) and
         map_size(state.quarantine) + length(ids) <= state.max_quarantine do
      mutate(
        state,
        %{"type" => "quarantine", "ids" => ids, "reason" => reason},
        &move_to_quarantine(&1, ids, reason)
      )
    else
      {:reply, {:error, :quarantine_unavailable}, state}
    end
  end

  def handle_call({:replay_quarantined, ids}, _from, state) do
    if valid_replay?(ids, state) do
      mutate(state, %{"type" => "replay", "ids" => ids}, &restore_quarantined(&1, ids))
    else
      {:reply, {:error, :invalid_replay}, state}
    end
  end

  def handle_call(:compact, _from, state) do
    case compact_file(state) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
  end

  defp complete_reservation(state, token, reservation, true) do
    Process.demonitor(reservation.monitor, [:flush])
    %{state | reservations: Map.delete(state.reservations, token)}
  end

  defp complete_reservation(state, token, reservation, false) do
    reservations =
      Map.put(state.reservations, token, %{reservation | remaining: reservation.remaining - 1})

    %{state | reservations: reservations}
  end

  defp move_to_quarantine(state, ids, reason) do
    quarantine =
      Enum.reduce(ids, state.quarantine, fn id, acc ->
        Map.put(acc, id, %{"event" => state.pending[id], "reason" => reason})
      end)

    %{
      state
      | pending: Map.drop(state.pending, ids),
        pending_since: Map.drop(state.pending_since, ids),
        quarantine: quarantine
    }
  end

  @impl true
  def handle_info({:DOWN, monitor, :process, _owner, _reason}, state) do
    # Consumer death releases only its capacity reservation. Accepted phases
    # remain durable and incomplete; no code replays a plaintext response.
    reservations = Map.reject(state.reservations, fn {_, r} -> r.monitor == monitor end)
    {:noreply, %{state | reservations: reservations}}
  end

  @impl true
  def terminate(_reason, %{file: nil}), do: :ok
  def terminate(_reason, state), do: :file.close(state.file)

  @impl true
  def format_status(status),
    do: status |> Map.put(:state, :redacted) |> Map.put(:message, :redacted)

  defp write_event(state, attrs) do
    attrs =
      Map.merge(attrs, %{
        event_id: Ecto.UUID.generate(),
        producer_id: state.producer_id,
        producer_sequence: state.sequence + 1,
        schema_version: 1,
        source: "agent",
        observed_at: DateTime.utc_now() |> DateTime.to_iso8601()
      })

    with {:ok, event} <- Event.validate(attrs, source: "agent"),
         {:ok, state} <- write_record(state, %{"type" => "event", "event" => event}) do
      {:ok, event,
       %{
         state
         | sequence: state.sequence + 1,
           pending: Map.put(state.pending, event["event_id"], event),
           pending_since:
             Map.put(state.pending_since, event["event_id"], System.monotonic_time(:millisecond))
       }}
    end
  end

  defp mutate(state, record, fun) do
    with {:ok, state} <- ensure_space(state, byte_size(frame(record))),
         {:ok, state} <- write_record(state, record),
         {:ok, state} <- compact_file(fun.(state)) do
      {:reply, :ok, state}
    else
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
  end

  defp valid_ids?(ids, pending),
    do:
      is_list(ids) and length(ids) <= 100 and
        length(Enum.uniq(ids)) == length(ids) and Enum.all?(ids, &Map.has_key?(pending, &1))

  defp valid_replay?(ids, state) do
    valid_ids?(ids, state.quarantine) and
      Enum.all?(ids, fn id ->
        match?({:ok, _}, Event.validate(state.quarantine[id]["event"], source: "agent"))
      end)
  end

  defp restore_quarantined(state, ids) do
    Enum.reduce(ids, state, fn id, acc ->
      event = acc.quarantine[id]["event"]

      %{
        acc
        | quarantine: Map.delete(acc.quarantine, id),
          pending: Map.put(acc.pending, id, event),
          pending_since: Map.put(acc.pending_since, id, replay_enqueue_time(event))
      }
    end)
  end

  defp reserved_events(state),
    do: Enum.reduce(state.reservations, 0, fn {_, r}, n -> n + r.remaining end)

  defp pending_bytes(pending),
    do: Enum.reduce(pending, 0, fn {_, e}, n -> n + byte_size(Event.canonical(e)) end)

  defp ensure_space(state, needed) do
    if state.bytes + needed <= state.max_bytes do
      {:ok, state}
    else
      case compact_file(state) do
        {:ok, compacted} when compacted.bytes + needed <= compacted.max_bytes -> {:ok, compacted}
        {:ok, compacted} -> {:error, :journal_full, compacted}
        error -> error
      end
    end
  end

  defp write_record(state, record) do
    data = frame(record)

    if state.bytes + byte_size(data) > state.max_bytes do
      {:error, :journal_full, state}
    else
      case synced_write(state.file, data) do
        :ok ->
          {:ok, %{state | bytes: state.bytes + byte_size(data)}}

        {:error, _} ->
          Telemetry.emit(:journal_append_failure, %{count: 1}, %{
            source: "agent",
            reason_code: "audit_unavailable"
          })

          {:error, :audit_unavailable, %{state | status: :io_failure}}
      end
    end
  end

  defp frame(record) do
    data = Jason.encode!(record)
    <<byte_size(data)::unsigned-big-32, :crypto.hash(:sha256, data)::binary, data::binary>>
  end

  defp synced_write(file, data) do
    with :ok <- :file.write(file, data), do: :file.sync(file)
  rescue
    _ -> {:error, :io_failure}
  catch
    _, _ -> {:error, :io_failure}
  end

  defp open(state) do
    with :ok <- durable_mkdir(state.dir),
         :ok <- File.chmod(state.dir, 0o700),
         false <- File.exists?(state.path <> ".compact"),
         {:ok, state} <- replay_or_create(state),
         {:ok, file} <- :file.open(String.to_charlist(state.path), [:raw, :binary, :append]),
         :ok <- File.chmod(state.path, 0o600) do
      {:ok, %{state | file: file}}
    else
      true -> {:error, :interrupted_compaction}
      error -> error
    end
  end

  defp durable_mkdir(dir) do
    parent = Path.dirname(dir)

    # An existing ancestor may survive a prior startup that failed its parent sync.
    with :ok <- if(parent == dir, do: :ok, else: durable_mkdir(parent)),
         result when result in [:ok, {:error, :eexist}] <- File.mkdir(dir),
         true <- File.dir?(dir) do
      sync_dir(parent)
    else
      false -> {:error, :enotdir}
      error -> error
    end
  end

  defp replay_or_create(state) do
    case File.stat(state.path) do
      {:ok, %{size: size}} when size <= state.max_bytes ->
        with {:ok, bytes} <- File.read(state.path),
             {:ok, state} <- replay(bytes, state, 0),
             true <- is_binary(state.producer_id) do
          {:ok, %{state | bytes: size}}
        else
          _ -> {:error, :journal_corrupt}
        end

      {:ok, _} ->
        {:error, :journal_limit}

      {:error, :enoent} ->
        create_file(%{state | producer_id: Ecto.UUID.generate()})

      error ->
        error
    end
  end

  defp create_file(state) do
    with {:ok, file} <-
           :file.open(String.to_charlist(state.path), [:raw, :binary, :write, :exclusive]) do
      result = synced_write(file, frame(metadata(state)))
      :file.close(file)

      with :ok <- result,
           :ok <- sync_dir(state.dir),
           do: {:ok, %{state | bytes: byte_size(frame(metadata(state)))}}
    end
  end

  defp replay(<<>>, state, _count), do: {:ok, state}

  defp replay(_bytes, _state, count) when count >= @max_replay_records,
    do: {:error, :journal_limit}

  defp replay(<<size::unsigned-big-32, checksum::binary-size(32), rest::binary>>, state, count)
       when size <= @max_record_bytes and byte_size(rest) >= size do
    <<data::binary-size(size), tail::binary>> = rest

    with true <- :crypto.hash(:sha256, data) == checksum,
         {:ok, record} <- Jason.decode(data),
         {:ok, state} <- apply_record(record, state) do
      replay(tail, state, count + 1)
    else
      _ -> {:error, :journal_corrupt}
    end
  end

  defp replay(_, _, _), do: {:error, :journal_corrupt}

  defp apply_record(
         %{"type" => "meta", "producer_id" => id, "sequence" => seq},
         %{producer_id: nil} = state
       )
       when is_integer(seq) and seq >= 0 do
    case Ecto.UUID.cast(id) do
      {:ok, _} -> {:ok, %{state | producer_id: id, sequence: seq}}
      _ -> {:error, :journal_corrupt}
    end
  end

  defp apply_record(%{"type" => "event", "event" => event}, state) do
    with {:ok, event} <- Event.validate(event, source: "agent"),
         true <- event["producer_id"] == state.producer_id,
         false <- Map.has_key?(state.pending, event["event_id"]),
         false <-
           Enum.any?(state.pending, fn {_, e} ->
             e["producer_sequence"] == event["producer_sequence"]
           end),
         false <-
           Enum.any?(state.quarantine, fn {_, q} ->
             q["event"]["producer_sequence"] == event["producer_sequence"]
           end),
         true <- map_size(state.pending) + map_size(state.quarantine) < state.max_events do
      {:ok,
       %{
         state
         | sequence: max(state.sequence, event["producer_sequence"]),
           pending: Map.put(state.pending, event["event_id"], event),
           pending_since:
             Map.put(state.pending_since, event["event_id"], replay_enqueue_time(event))
       }}
    else
      _ -> {:error, :journal_corrupt}
    end
  end

  defp apply_record(%{"type" => "ack", "ids" => ids}, state) do
    if valid_ids?(ids, state.pending),
      do:
        {:ok,
         %{
           state
           | pending: Map.drop(state.pending, ids),
             pending_since: Map.drop(state.pending_since, ids)
         }},
      else: {:error, :journal_corrupt}
  end

  defp apply_record(%{"type" => "quarantine", "ids" => ids, "reason" => reason}, state) do
    if valid_ids?(ids, state.pending) and
         reason in ~w(invalid_event unsupported_schema event_conflict outside_retention) and
         map_size(state.quarantine) + length(ids) <= state.max_quarantine do
      quarantine =
        Enum.reduce(ids, state.quarantine, fn id, acc ->
          Map.put(acc, id, %{"event" => state.pending[id], "reason" => reason})
        end)

      {:ok,
       %{
         state
         | pending: Map.drop(state.pending, ids),
           pending_since: Map.drop(state.pending_since, ids),
           quarantine: quarantine
       }}
    else
      {:error, :journal_corrupt}
    end
  end

  defp apply_record(
         %{"type" => "quarantined", "entry" => %{"event" => event, "reason" => reason}},
         state
       ) do
    with true <- reason in ~w(invalid_event unsupported_schema event_conflict outside_retention),
         {:ok, state} <- apply_record(%{"type" => "event", "event" => event}, state) do
      apply_record(
        %{"type" => "quarantine", "ids" => [event["event_id"]], "reason" => reason},
        state
      )
    else
      _ -> {:error, :journal_corrupt}
    end
  end

  defp apply_record(%{"type" => "replay", "ids" => ids}, state) do
    if valid_replay?(ids, state),
      do: {:ok, restore_quarantined(state, ids)},
      else: {:error, :journal_corrupt}
  end

  defp apply_record(_, _), do: {:error, :journal_corrupt}

  defp replay_enqueue_time(event) do
    {:ok, observed, _} = DateTime.from_iso8601(event["observed_at"])
    local_age = max(DateTime.diff(DateTime.utc_now(), observed, :millisecond), 0)
    System.monotonic_time(:millisecond) - local_age
  end

  defp metadata(state),
    do: %{"type" => "meta", "producer_id" => state.producer_id, "sequence" => state.sequence}

  defp compact_file(state) do
    path = state.path <> ".compact"

    records =
      [metadata(state)] ++
        (state.pending
         |> Map.values()
         |> Enum.sort_by(& &1["producer_sequence"])
         |> Enum.map(&%{"type" => "event", "event" => &1})) ++
        Enum.map(state.quarantine, fn {_, entry} ->
          %{"type" => "quarantined", "entry" => entry}
        end)

    data = Enum.map(records, &frame/1)

    case :file.open(String.to_charlist(path), [:raw, :binary, :write, :exclusive]) do
      {:ok, temp} ->
        result = with :ok <- File.chmod(path, 0o600), do: synced_write(temp, data)
        :file.close(temp)

        with :ok <- result,
             :ok <- File.rename(path, state.path),
             :ok <- sync_dir(state.dir),
             {:ok, file} <- :file.open(String.to_charlist(state.path), [:raw, :binary, :append]) do
          :file.close(state.file)
          {:ok, %{state | file: file, bytes: IO.iodata_length(data)}}
        else
          _ -> {:error, :audit_unavailable, %{state | status: :io_failure}}
        end

      _ ->
        {:error, :audit_unavailable, %{state | status: :io_failure}}
    end
  end

  defp sync_dir(dir) do
    with {:ok, file} <- :file.open(String.to_charlist(dir), [:raw, :read, :directory]) do
      result = :file.sync(file)
      :file.close(file)
      result
    end
  end
end
