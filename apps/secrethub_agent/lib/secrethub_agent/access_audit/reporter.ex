defmodule SecretHub.Agent.AccessAudit.Reporter do
  @moduledoc "One bounded authenticated batch at a time; only explicit committed IDs are acknowledged."
  use GenServer
  alias SecretHub.Agent.AccessAudit.Journal
  alias SecretHub.Agent.Connection
  alias SecretHub.Shared.AccessAudit.Telemetry

  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @impl true
  def init(opts) do
    send(self(), :upload)

    {:ok,
     %{
       journal: Keyword.get(opts, :journal, Journal),
       submit: Keyword.get(opts, :submit, &Connection.submit_audit_batch/1),
       interval: Keyword.get(opts, :interval, 5_000),
       retries: 0
     }}
  end

  @impl true
  def handle_info(:upload, state) do
    started = System.monotonic_time(:microsecond)

    result =
      with {:ok, events} <- Journal.batch(state.journal),
           reply <- submit(state.submit, events) do
        result = handle_reply(reply, events, state.journal)

        status =
          case {reply, result} do
            {_, :ok} -> :healthy
            {{:error, :unsupported}, _} -> :unsupported
            _ -> :audit_unavailable
          end

        Journal.reporting_status(status, state.journal)
        result
      end

    Telemetry.emit(
      :upload_result,
      %{count: 1, duration_us: max(System.monotonic_time(:microsecond) - started, 0)},
      %{source: "agent", outcome: if(result == :ok, do: "success", else: "error")}
    )

    retries = if result == :ok, do: 0, else: min(state.retries + 1, 10)
    delay = if result == :ok, do: state.interval, else: backoff(retries)
    Process.send_after(self(), :upload, delay)
    {:noreply, %{state | retries: retries}}
  end

  @impl true
  def format_status(status),
    do: status |> Map.put(:state, :redacted) |> Map.put(:message, :redacted)

  defp submit(fun, events) do
    fun.(events)
  rescue
    _ -> {:error, :audit_unavailable}
  catch
    _, _ -> {:error, :audit_unavailable}
  end

  defp handle_reply({:ok, %{"accepted" => accepted, "duplicates" => duplicates}}, events, journal)
       when is_list(accepted) and is_list(duplicates) do
    ids = accepted ++ duplicates
    submitted = MapSet.new(events, & &1["event_id"])

    if length(ids) == length(Enum.uniq(ids)) and Enum.all?(ids, &MapSet.member?(submitted, &1)) do
      Journal.acknowledge(ids, journal)
    else
      {:error, :invalid_acknowledgement}
    end
  end

  defp handle_reply({:error, %{"reason" => reason}}, events, journal)
       when reason in ~w(invalid_event unsupported_schema event_conflict outside_retention) and
              events != [] do
    # Core rejects a batch atomically. Preserve every unaccepted original envelope.
    Journal.quarantine(Enum.map(events, & &1["event_id"]), reason, journal)
  end

  defp handle_reply(_, _, _), do: {:error, :audit_unavailable}

  defp backoff(retries) do
    cap = min(1_000 * Integer.pow(2, retries), 60_000)
    max(100, round(cap * (0.75 + :rand.uniform() * 0.25)))
  end
end
