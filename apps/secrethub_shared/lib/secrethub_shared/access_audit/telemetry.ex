defmodule SecretHub.Shared.AccessAudit.Telemetry do
  @moduledoc """
  Lightweight access pipeline signals. Explicit journal and Audit writes enforce
  durability; no telemetry handler is responsible for storing required evidence.
  Measurements use native monotonic units for `duration`, microseconds for
  `duration_us`, and milliseconds for `oldest_pending_age_ms`.
  """
  alias SecretHub.Shared.AccessAudit.Event

  @events %{
    request_start: [:request, :start],
    request_stop: [:request, :stop],
    request_exception: [:request, :exception],
    authorization_result: [:authorization, :result],
    response_observation: [:response, :observation],
    journal_append_failure: [:journal, :append_failure],
    upload_result: [:upload, :result],
    ingestion_result: [:ingestion, :result],
    backlog: [:backlog],
    handler_failure: [:handler, :failure]
  }
  @measurements ~w(count duration duration_us pending_events pending_bytes quarantined_events
    oldest_pending_age_ms duplicates conflicts)a

  def catalog, do: @events

  def emit(name, measurements, metadata) when is_map(measurements) and is_map(metadata) do
    case @events[name] do
      nil ->
        :ok

      suffix ->
        values =
          measurements
          |> Map.take(@measurements)
          |> Map.filter(fn {_, v} -> is_number(v) and v >= 0 end)

        labels =
          metadata
          |> Map.take([:operation, :outcome, :reason_code, :cache_status, :source])
          |> Map.filter(&valid_label?/1)

        :telemetry.execute([:secrethub, :access_audit] ++ suffix, values, labels)
    end
  end

  def install_handler_monitor do
    case :telemetry.attach(
           "secrethub-access-audit-handler-monitor",
           [:telemetry, :handler, :failure],
           &__MODULE__.handler_failure/4,
           nil
         ) do
      :ok -> :ok
      {:error, :already_exists} -> :ok
    end
  end

  def handler_failure(_, _, _, _), do: emit(:handler_failure, %{count: 1}, %{})

  defp valid_label?({:source, v}), do: v in ~w(agent core)
  defp valid_label?({:operation, v}), do: v in ~w(read invalid authenticate)
  defp valid_label?({:outcome, v}), do: v in ~w(success denied error unknown)
  defp valid_label?({:cache_status, v}), do: v in ~w(none miss hit validated invalidated)
  defp valid_label?({:reason_code, v}), do: v in Event.reasons()
end
