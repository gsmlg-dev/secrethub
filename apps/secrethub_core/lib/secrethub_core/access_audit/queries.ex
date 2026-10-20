defmodule SecretHub.Core.AccessAudit.Queries do
  @moduledoc false
  import Ecto.Query
  alias SecretHub.Core.AccessAudit.{Observation, Producer, Request, Retention}
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.Agent
  @filters ~w(application_id agent_id secret_path outcome reason_code from to cursor limit)
  @outcomes ~w(success denied error unknown incomplete)

  def requests(filters \\ %{}) do
    with {:ok, query, parsed} <- query(filters),
         {:ok, query} <- cursor(query, parsed["cursor"]) do
      entries =
        Repo.all(
          from(r in query,
            order_by: [desc: r.started_at, desc: r.id],
            limit: ^(parsed["limit"] + 1)
          )
        )

      {page, more} = Enum.split(entries, parsed["limit"])
      next = if more != [], do: encode_cursor(List.last(page)), else: nil
      {:ok, %{entries: page, next_cursor: next}}
    end
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError] -> {:error, :storage_unavailable}
  catch
    :exit, _ -> {:error, :storage_unavailable}
  end

  def summary(filters \\ %{}) do
    with {:ok, query, _} <- query(filters), do: {:ok, aggregate(query)}
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError] -> {:error, :storage_unavailable}
  catch
    :exit, _ -> {:error, :storage_unavailable}
  end

  def applications(filters \\ %{}) do
    with {:ok, query, _} <- query(filters) do
      query =
        from(r in query, where: not is_nil(r.application_id) and r.identity_status == "verified")

      {:ok, grouped(query, [:application_id, :attribution])}
    end
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError] -> {:error, :storage_unavailable}
  catch
    :exit, _ -> {:error, :storage_unavailable}
  end

  def secrets(filters \\ %{}) do
    with {:ok, query, _} <- query(filters), do: {:ok, grouped(query, [:secret_path])}
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError] -> {:error, :storage_unavailable}
  catch
    :exit, _ -> {:error, :storage_unavailable}
  end

  def reasons(filters \\ %{}) do
    with {:ok, query, _} <- query(filters) do
      {:ok,
       Repo.all(
         from(r in query,
           group_by: r.reason_code,
           order_by: [desc: count(r.id)],
           select: %{reason_code: r.reason_code, count: count(r.id)},
           limit: 100
         )
       )}
    end
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError] -> {:error, :storage_unavailable}
  catch
    :exit, _ -> {:error, :storage_unavailable}
  end

  def time_buckets(filters \\ %{}) do
    with {:ok, query, _} <- query(filters) do
      query = from(r in query, group_by: fragment("date_trunc('hour', ?)", r.started_at))

      result =
        Repo.all(
          from(r in query,
            order_by: [asc: fragment("date_trunc('hour', ?)", r.started_at)],
            select: %{
              at: fragment("date_trunc('hour', ?)", r.started_at),
              requests: count(r.id),
              success: filter(count(r.id), r.outcome == "success"),
              denied: filter(count(r.id), r.outcome == "denied"),
              error: filter(count(r.id), r.outcome == "error"),
              incomplete: filter(count(r.id), r.incomplete),
              attempts: coalesce(sum(r.attempts), 0),
              unverified: filter(count(r.id), r.identity_status == "unverified")
            }
          )
        )

      {:ok, result}
    end
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError] -> {:error, :storage_unavailable}
  catch
    :exit, _ -> {:error, :storage_unavailable}
  end

  def timeline(namespace, request_id) when is_binary(namespace) and byte_size(namespace) <= 300 do
    case Ecto.UUID.cast(request_id) do
      {:ok, id} ->
        {:ok,
         Repo.all(
           from(e in Observation,
             where: e.namespace == ^namespace and e.request_id == ^id,
             order_by: [asc: e.observed_at, asc: e.id],
             limit: 1000
           )
         )}

      :error ->
        {:error, :invalid_filter}
    end
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError] -> {:error, :storage_unavailable}
  catch
    :exit, _ -> {:error, :storage_unavailable}
  end

  def timeline(_, _), do: {:error, :invalid_filter}

  def health do
    producers = Repo.all(from(p in Producer, order_by: [desc: p.last_received_at], limit: 101))
    now = DateTime.utc_now()

    reports =
      Repo.all(
        from(h in "access_audit_agent_health",
          order_by: [desc: h.received_at],
          left_join: a in Agent,
          on: a.agent_id == h.agent_id,
          limit: 101,
          select: %{
            agent_id: h.agent_id,
            agent_status: a.status,
            status: h.status,
            received_at: type(h.received_at, :utc_datetime_usec)
          }
        )
      )

    # Query missing reporters independently: one healthy reporter must not hide
    # another enrolled Agent, including Agents outside the bounded report page.
    unknown_agents =
      Repo.all(
        from(a in Agent,
          left_join: h in "access_audit_agent_health",
          on: h.agent_id == a.agent_id,
          where: not is_nil(a.certificate_id) and is_nil(h.agent_id),
          where:
            a.status in [
              :certificate_issued,
              :connect_info_delivered,
              :trusted_connecting,
              :trusted_connected,
              :active,
              :disconnected
            ],
          order_by: a.agent_id,
          limit: 101,
          select: a.agent_id
        )
      )

    reports =
      Enum.map(reports, fn report ->
        Map.merge(report, %{
          stale: DateTime.diff(now, report.received_at) > 300,
          oldest_pending_age_ms: report.status["oldest_pending_age_ms"]
        })
      end)

    coverage_limited =
      length(reports) > 100 or length(producers) > 100 or length(unknown_agents) > 100

    with {:ok, retention_policy} <- Retention.policy() do
      {:ok,
       %{
         reports: Enum.take(reports, 100),
         unknown_agents: Enum.take(unknown_agents, 100),
         coverage_limited: coverage_limited,
         producers:
           Enum.map(Enum.take(producers, 100), fn p ->
             %{
               namespace: p.namespace,
               producer_id: p.producer_id,
               last_sequence: p.last_sequence,
               event_count: p.event_count,
               gaps: p.last_sequence - p.event_count,
               last_received_at: p.last_received_at,
               last_observed_at: p.last_observed_at,
               stale: DateTime.diff(DateTime.utc_now(), p.last_received_at) > 300
             }
           end),
         pending_unknown:
           reports == [] or unknown_agents != [] or coverage_limited or
             Enum.any?(reports, &(&1.stale or &1.agent_status == :disconnected)),
         retention_enabled: retention_policy.enabled,
         retention_policy: retention_policy
       }}
    end
  rescue
    _ in [Postgrex.Error, DBConnection.ConnectionError] -> {:error, :storage_unavailable}
  catch
    :exit, _ -> {:error, :storage_unavailable}
  end

  # Public only to support EXPLAIN qualification of exactly the production query.
  @doc false
  def query(filters) when is_map(filters) do
    with {:ok, parsed} <- parse(filters) do
      query =
        from(r in Request,
          where: r.started_at >= ^parsed["from"] and r.started_at < ^parsed["to"]
        )

      query =
        ~w(application_id agent_id secret_path outcome reason_code)
        |> Enum.map(&{&1, parsed[&1]})
        |> Enum.reject(fn {_, value} -> is_nil(value) end)
        |> Enum.reduce(query, &filter_request/2)

      {:ok, query, parsed}
    end
  end

  def query(_), do: {:error, :invalid_filter}

  defp filter_request({key, value}, query),
    do: where(query, [r], field(r, ^String.to_existing_atom(key)) == ^value)

  defp aggregate(query) do
    Repo.one(
      from(r in query,
        select: %{
          requests: count(r.id),
          last_activity: max(r.last_observed_at),
          success: filter(count(r.id), r.outcome == "success"),
          denied: filter(count(r.id), r.outcome == "denied"),
          error: filter(count(r.id), r.outcome == "error"),
          incomplete: filter(count(r.id), r.incomplete),
          attempts: coalesce(sum(r.attempts), 0),
          unverified: filter(count(r.id), r.identity_status == "unverified")
        }
      )
    )
  end

  defp grouped(query, fields) do
    # Grouping runs in PostgreSQL; the finite result cap does not truncate totals in each group.
    query = from(r in query, group_by: ^fields)

    counts =
      from(r in query,
        select: %{
          requests: count(r.id),
          last_activity: max(r.last_observed_at),
          success: filter(count(r.id), r.outcome == "success"),
          denied: filter(count(r.id), r.outcome == "denied"),
          error: filter(count(r.id), r.outcome == "error"),
          incomplete: filter(count(r.id), r.incomplete),
          attempts: coalesce(sum(r.attempts), 0),
          unverified: filter(count(r.id), r.identity_status == "unverified")
        }
      )

    Repo.all(
      from(r in counts, select_merge: map(r, ^fields), order_by: [desc: count(r.id)], limit: 100)
    )
  end

  defp parse(filters) do
    parsed =
      Map.new(filters, fn {key, value} ->
        {if(is_atom(key), do: Atom.to_string(key), else: key), value}
      end)

    now = DateTime.utc_now()

    with true <-
           map_size(parsed) == map_size(filters) and
             Enum.all?(Map.keys(parsed), &(&1 in @filters)),
         {:ok, to} <- datetime(parsed["to"], now),
         {:ok, from} <- datetime(parsed["from"], DateTime.add(to, -86_400)),
         true <- DateTime.compare(from, to) == :lt and DateTime.diff(to, from) <= 31 * 86_400,
         {:ok, limit} <- limit(parsed["limit"]),
         true <- Enum.all?(~w(agent_id secret_path reason_code), &valid_text?(parsed[&1])),
         true <- is_nil(parsed["outcome"]) or parsed["outcome"] in @outcomes,
         {:ok, app_id} <- uuid(parsed["application_id"]) do
      {:ok,
       parsed
       |> Map.put("from", from)
       |> Map.put("to", to)
       |> Map.put("limit", limit)
       |> Map.put("application_id", app_id)}
    else
      _ -> {:error, :invalid_filter}
    end
  end

  defp datetime(nil, default), do: {:ok, default}
  defp datetime(%DateTime{} = value, _), do: {:ok, value}

  defp datetime(value, _) when is_binary(value) and byte_size(value) <= 40 do
    case DateTime.from_iso8601(value) do
      {:ok, dt, _} -> {:ok, dt}
      _ -> :error
    end
  end

  defp datetime(_, _), do: :error
  defp limit(nil), do: {:ok, 50}
  defp limit(value) when is_integer(value) and value in 1..100, do: {:ok, value}

  defp limit(value) when is_binary(value) and byte_size(value) <= 3 do
    case Integer.parse(value) do
      {n, ""} -> limit(n)
      _ -> :error
    end
  end

  defp limit(_), do: :error
  defp uuid(nil), do: {:ok, nil}
  defp uuid(value), do: Ecto.UUID.cast(value)
  defp valid_text?(nil), do: true

  defp valid_text?(value) when is_binary(value),
    do: byte_size(value) in 1..512 and String.valid?(value) and not String.contains?(value, <<0>>)

  defp valid_text?(_), do: false

  defp encode_cursor(r),
    do:
      Base.url_encode64(Jason.encode!([DateTime.to_iso8601(r.started_at), r.id]), padding: false)

  defp cursor(query, nil), do: {:ok, query}

  defp cursor(query, value) when is_binary(value) and byte_size(value) <= 200 do
    with {:ok, json} <- Base.url_decode64(value, padding: false),
         {:ok, [timestamp, id]} <- Jason.decode(json),
         true <- is_integer(id) and id > 0,
         {:ok, %DateTime{} = at} <- datetime(timestamp, nil) do
      {:ok, where(query, [r], r.started_at < ^at or (r.started_at == ^at and r.id < ^id))}
    else
      _ -> {:error, :invalid_cursor}
    end
  end

  defp cursor(_, _), do: {:error, :invalid_cursor}
end
