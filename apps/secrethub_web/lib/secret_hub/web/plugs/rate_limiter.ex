defmodule SecretHub.Web.Plugs.RateLimiter do
  @moduledoc """
  Rate limiting plug using ETS for in-memory storage.

  Prevents brute force attacks by limiting requests per IP address.

  Configuration:
  - max_requests: Maximum requests allowed in the time window
  - window_ms: Time window in milliseconds
  - scope: Identifier for this rate limiter (e.g., :login, :api)
  """

  use GenServer

  import Plug.Conn
  require Logger

  alias SecretHub.Core.Audit

  @table_name :rate_limiter_table

  def start_link(:server) do
    GenServer.start_link(__MODULE__, :server, name: __MODULE__)
  end

  @impl GenServer
  def init(:server) do
    table =
      :ets.new(@table_name, [
        :set,
        :public,
        :named_table,
        read_concurrency: true
      ])

    {:ok, table}
  end

  def init(opts) when is_list(opts) do
    %{
      max_requests: Keyword.get(opts, :max_requests, 10),
      window_ms: Keyword.get(opts, :window_ms, 60_000),
      scope: Keyword.get(opts, :scope, :default)
    }
  end

  def call(conn, opts) do
    client_ip = get_client_ip(conn)
    key = {opts.scope, client_ip}
    now = System.monotonic_time(:millisecond)

    case check_rate_limit(key, now, opts) do
      :ok ->
        conn

      {:error, :rate_limited, retry_after} ->
        Logger.warning("Rate limit exceeded",
          scope: opts.scope,
          ip: client_ip,
          path: conn.request_path,
          retry_after: retry_after
        )

        # Log rate limit event
        Audit.log_event(%{
          event_type: "rate_limit.exceeded",
          actor_type: "unknown",
          actor_id: client_ip,
          access_granted: false,
          denial_reason: "Rate limit exceeded",
          source_ip: client_ip,
          event_data: %{
            scope: opts.scope,
            path: conn.request_path,
            retry_after: retry_after
          }
        })

        conn
        |> put_status(:too_many_requests)
        |> put_resp_header("retry-after", to_string(retry_after))
        |> Phoenix.Controller.json(%{
          error: "Too many requests",
          retry_after: retry_after
        })
        |> halt()
    end
  end

  defp check_rate_limit(key, now, opts) do
    GenServer.call(__MODULE__, {:check_rate_limit, key, now, opts})
  end

  @impl GenServer
  def handle_call({:check_rate_limit, key, now, opts}, _from, table) do
    result =
      case :ets.lookup(table, key) do
        [] ->
          :ets.insert(table, {key, now, 1})
          :ok

        [{^key, first_request_time, count}] ->
          window_start = now - opts.window_ms

          cond do
            first_request_time < window_start ->
              :ets.insert(table, {key, now, 1})
              :ok

            count < opts.max_requests ->
              :ets.update_counter(table, key, {3, 1})
              :ok

            true ->
              time_until_reset = opts.window_ms - (now - first_request_time)
              retry_after = div(time_until_reset, 1000) + 1

              {:error, :rate_limited, retry_after}
          end
      end

    {:reply, result, table}
  end

  @impl GenServer
  def handle_call({:cleanup_old_entries, cutoff}, _from, table) do
    match_spec = [
      {
        {:"$1", :"$2", :"$3"},
        [{:<, :"$2", cutoff}],
        [true]
      }
    ]

    {:reply, :ets.select_delete(table, match_spec), table}
  end

  defp get_client_ip(conn) do
    # Get real IP, considering X-Forwarded-For
    case get_req_header(conn, "x-forwarded-for") do
      [ip | _] ->
        ip |> String.split(",") |> List.first() |> String.trim()

      _ ->
        case conn.remote_ip do
          {a, b, c, d} -> "#{a}.#{b}.#{c}.#{d}"
          {a, b, c, d, e, f, g, h} -> Enum.join([a, b, c, d, e, f, g, h], ":")
          _ -> "unknown"
        end
    end
  end

  @doc """
  Cleanup function to remove old entries from ETS table.

  Should be called periodically (e.g., every 5 minutes) to prevent memory growth.
  """
  def cleanup_old_entries(max_age_ms \\ 3_600_000) do
    now = System.monotonic_time(:millisecond)
    cutoff = now - max_age_ms
    deleted = GenServer.call(__MODULE__, {:cleanup_old_entries, cutoff})

    Logger.debug("Cleaned up rate limiter entries", deleted: deleted)

    {:ok, deleted}
  end
end
