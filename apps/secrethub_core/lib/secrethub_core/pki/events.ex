defmodule SecretHub.Core.PKI.Events do
  @moduledoc """
  Append-only event store for PKI lifecycle operations.

  This is the SecretHub adaptation of the GSMLG PKI event interface. It keeps
  PostgreSQL as the storage backend and returns event maps compatible with the
  original PKI event shape.
  """

  import Ecto.Query

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.PKIEvent

  @type event_type ::
          :ca_initialized
          | :certificate_issued
          | :certificate_revoked
          | :certificate_renewed
          | :crl_generated
          | :certificate_validated

  @type event :: %{
          required(:id) => String.t(),
          required(:type) => :pki_event,
          required(:event_type) => event_type(),
          required(:timestamp) => DateTime.t(),
          required(:sequence) => pos_integer(),
          required(:ca_id) => String.t(),
          required(:metadata) => map(),
          optional(:actor) => String.t() | nil,
          optional(:correlation_id) => String.t() | nil
        }

  @revocation_reasons [
    :unspecified,
    :keyCompromise,
    :cACompromise,
    :affiliationChanged,
    :superseded,
    :cessationOfOperation,
    :certificateHold,
    :removeFromCRL,
    :privilegeWithdrawn,
    :aACompromise
  ]

  @doc """
  Append a PKI event and assign the next sequence number within the CA stream.
  """
  @spec append(event_type(), map(), keyword()) :: {:ok, event()} | {:error, term()}
  def append(event_type, metadata, opts \\ []) do
    ca_id = Keyword.fetch!(opts, :ca_id)

    timestamp =
      opts |> Keyword.get(:timestamp, DateTime.utc_now()) |> DateTime.truncate(:microsecond)

    Repo.transaction(fn ->
      attrs = %{
        id: generate_event_id(),
        event_type: event_type,
        timestamp: timestamp,
        sequence: next_sequence(ca_id),
        ca_id: ca_id,
        metadata: metadata || %{},
        actor: Keyword.get(opts, :actor),
        correlation_id: Keyword.get(opts, :correlation_id)
      }

      case Repo.insert(PKIEvent.changeset(%PKIEvent{}, attrs)) do
        {:ok, event} -> PKIEvent.to_pki_event(event)
        {:error, changeset} -> Repo.rollback(changeset)
      end
    end)
  end

  @doc """
  Query all events for a CA stream ordered by sequence.
  """
  @spec query_by_ca(String.t(), keyword()) :: {:ok, [event()]} | {:error, term()}
  def query_by_ca(ca_id, opts \\ []) do
    query =
      PKIEvent
      |> where([event], event.ca_id == ^ca_id)
      |> maybe_sequence_range(opts)
      |> maybe_order_by_sequence(Keyword.get(opts, :descending, false))
      |> maybe_limit(Keyword.get(opts, :limit))

    {:ok, Repo.all(query) |> Enum.map(&PKIEvent.to_pki_event/1)}
  rescue
    error -> {:error, error}
  end

  @doc """
  Query events by event type, ordered by timestamp.
  """
  @spec query_by_type(event_type(), keyword()) :: {:ok, [event()]} | {:error, term()}
  def query_by_type(event_type, opts \\ []) do
    query =
      PKIEvent
      |> where([event], event.event_type == ^event_type)
      |> maybe_time_range(opts)
      |> order_by([event], asc: event.timestamp)
      |> maybe_limit(Keyword.get(opts, :limit))

    {:ok, Repo.all(query) |> Enum.map(&PKIEvent.to_pki_event/1)}
  rescue
    error -> {:error, error}
  end

  @doc """
  Query events related to a certificate serial number.
  """
  @spec query_by_serial(String.t() | non_neg_integer()) :: {:ok, [event()]} | {:error, term()}
  def query_by_serial(serial) do
    serial = to_string(serial)

    query =
      from(event in PKIEvent,
        where: fragment("?->>'serial' = ?", event.metadata, ^serial),
        order_by: [asc: event.timestamp]
      )

    {:ok, Repo.all(query) |> Enum.map(&PKIEvent.to_pki_event/1)}
  rescue
    error -> {:error, error}
  end

  @doc """
  Get current certificate state by replaying all events for a serial.
  """
  @spec get_certificate_state(String.t() | non_neg_integer()) :: {:ok, map()} | {:error, term()}
  def get_certificate_state(serial) do
    with {:ok, events} <- query_by_serial(serial) do
      {:ok, replay_certificate_events(events)}
    end
  end

  @doc """
  Get revocation entries for CRL construction.
  """
  @spec get_revocations(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_revocations(ca_id, opts \\ []) do
    since = Keyword.get(opts, :since)

    with {:ok, events} <- query_by_ca(ca_id) do
      revocations =
        events
        |> Enum.filter(&(&1.event_type == :certificate_revoked))
        |> Enum.filter(fn event ->
          is_nil(since) or DateTime.compare(event.timestamp, since) == :gt
        end)
        |> Enum.map(fn event ->
          %{
            serial: metadata(event, :serial),
            revocation_date: parse_datetime(metadata(event, :revocation_date)) || event.timestamp,
            reason: normalize_reason(metadata(event, :reason))
          }
        end)

      {:ok, revocations}
    end
  end

  @doc """
  Get active certificate states for a CA.
  """
  @spec get_active_certificates(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_active_certificates(ca_id, opts \\ []) do
    at_time = Keyword.get(opts, :at_time, DateTime.utc_now())

    with {:ok, events} <- query_by_ca(ca_id) do
      certificates =
        events
        |> Enum.group_by(&metadata(&1, :serial))
        |> Enum.reject(fn {serial, _events} -> is_nil(serial) end)
        |> Enum.map(fn {_serial, events} -> replay_certificate_events(events, at_time) end)
        |> Enum.filter(&(&1.status == :active))

      {:ok, certificates}
    end
  end

  @doc """
  Get active certificates expiring within a number of days.
  """
  @spec get_expiring_certificates(String.t(), non_neg_integer()) ::
          {:ok, [map()]} | {:error, term()}
  def get_expiring_certificates(ca_id, days \\ 30) do
    now = DateTime.utc_now()
    threshold = DateTime.add(now, days, :day)

    with {:ok, active} <- get_active_certificates(ca_id, at_time: now) do
      expiring =
        active
        |> Enum.filter(&(&1.not_after && DateTime.compare(&1.not_after, threshold) == :lt))
        |> Enum.map(&Map.put(&1, :days_remaining, DateTime.diff(&1.not_after, now, :day)))
        |> Enum.sort_by(& &1.not_after, DateTime)

      {:ok, expiring}
    end
  end

  @doc """
  Return aggregate event-store statistics.
  """
  @spec get_stats() :: {:ok, map()} | {:error, term()}
  def get_stats do
    total_events = Repo.one(from(event in PKIEvent, select: count(event.id)))

    events_by_type =
      PKIEvent
      |> group_by([event], event.event_type)
      |> select([event], {event.event_type, count(event.id)})
      |> Repo.all()
      |> Map.new()

    {:ok,
     %{total_events: total_events, events_by_type: events_by_type, storage_backend: :postgres}}
  rescue
    error -> {:error, error}
  end

  defp maybe_sequence_range(query, opts) do
    query
    |> maybe_start_sequence(Keyword.get(opts, :start_sequence))
    |> maybe_end_sequence(Keyword.get(opts, :end_sequence))
  end

  defp maybe_start_sequence(query, nil), do: query

  defp maybe_start_sequence(query, sequence),
    do: where(query, [event], event.sequence >= ^sequence)

  defp maybe_end_sequence(query, nil), do: query
  defp maybe_end_sequence(query, sequence), do: where(query, [event], event.sequence <= ^sequence)

  defp maybe_time_range(query, opts) do
    query
    |> maybe_start_time(Keyword.get(opts, :start_time))
    |> maybe_end_time(Keyword.get(opts, :end_time))
  end

  defp maybe_start_time(query, nil), do: query

  defp maybe_start_time(query, timestamp),
    do: where(query, [event], event.timestamp >= ^timestamp)

  defp maybe_end_time(query, nil), do: query
  defp maybe_end_time(query, timestamp), do: where(query, [event], event.timestamp <= ^timestamp)

  defp maybe_order_by_sequence(query, true), do: order_by(query, [event], desc: event.sequence)
  defp maybe_order_by_sequence(query, false), do: order_by(query, [event], asc: event.sequence)

  defp maybe_limit(query, nil), do: query
  defp maybe_limit(query, limit), do: limit(query, ^limit)

  defp next_sequence(ca_id) do
    max_sequence =
      Repo.one(
        from(event in PKIEvent,
          where: event.ca_id == ^ca_id,
          select: max(event.sequence)
        )
      )

    (max_sequence || 0) + 1
  end

  defp generate_event_id do
    "event:" <> Ecto.UUID.generate()
  end

  defp replay_certificate_events(events, at_time \\ nil) do
    check_time = at_time || DateTime.utc_now()

    final_state =
      Enum.reduce(events, initial_certificate_state(), fn event, state ->
        state = Map.update!(state, :events, &(&1 ++ [event]))

        case event.event_type do
          :certificate_issued ->
            %{
              state
              | status: :active,
                serial: metadata(event, :serial),
                subject: metadata(event, :subject),
                not_before: parse_datetime(metadata(event, :not_before)),
                not_after: parse_datetime(metadata(event, :not_after)),
                certificate_pem: metadata(event, :certificate_pem),
                certificate_der: metadata(event, :certificate_der),
                cert_id: metadata(event, :cert_id),
                fingerprint: metadata(event, :fingerprint)
            }

          :certificate_revoked ->
            %{
              state
              | status: :revoked,
                revoked_at: parse_datetime(metadata(event, :revocation_date)) || event.timestamp,
                revocation_reason: normalize_reason(metadata(event, :reason))
            }

          :certificate_renewed ->
            Map.put(state, :renewed_from, metadata(event, :old_serial))

          _other ->
            state
        end
      end)

    cond do
      final_state.status == :revoked ->
        final_state

      final_state.not_after && DateTime.compare(check_time, final_state.not_after) == :gt ->
        %{final_state | status: :expired}

      final_state.not_before && DateTime.compare(check_time, final_state.not_before) == :lt ->
        %{final_state | status: :not_yet_valid}

      true ->
        final_state
    end
  end

  defp initial_certificate_state do
    %{
      status: :unknown,
      serial: nil,
      subject: nil,
      not_before: nil,
      not_after: nil,
      certificate_pem: nil,
      certificate_der: nil,
      cert_id: nil,
      fingerprint: nil,
      revoked_at: nil,
      revocation_reason: nil,
      events: []
    }
  end

  defp metadata(%{metadata: metadata}, key) when is_map(metadata) do
    Map.get(metadata, key) || Map.get(metadata, Atom.to_string(key))
  end

  defp metadata(_event, _key), do: nil

  defp parse_datetime(nil), do: nil
  defp parse_datetime(%DateTime{} = datetime), do: datetime

  defp parse_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} -> datetime
      {:error, _reason} -> nil
    end
  end

  defp parse_datetime(_value), do: nil

  defp normalize_reason(nil), do: nil
  defp normalize_reason(reason) when is_atom(reason), do: reason

  defp normalize_reason(reason) when is_binary(reason) do
    Enum.find(@revocation_reasons, &(Atom.to_string(&1) == reason)) || :unspecified
  end
end
