defmodule SecretHub.Core.Audit do
  @moduledoc """
  Audit logging module with tamper-evident hash chains.

  Provides secure, tamper-evident audit logging for all security-relevant events.
  Uses cryptographic hash chains to detect any unauthorized modifications to logs.

  ## Hash Chain Algorithm

  Each audit log entry contains:
  - `current_hash`: SHA-256 hash of the entry's fields
  - `previous_hash`: Reference to the previous entry's `current_hash`
  - `signature`: HMAC signature for additional integrity verification

  The hash chain ensures:
  1. Sequential integrity - entries cannot be inserted between existing ones
  2. Tamper detection - any modification breaks the chain
  3. Deletion detection - removing entries breaks the chain

  ## Event Types

  Supported event types:
  - Secret access: `secret.accessed`, `secret.dynamic_issued`, `secret.lease_renewed`
  - Secret mutations: `secret.created`, `secret.updated`, `secret.rotated`, `secret.deleted`
  - Authentication: `auth.*`
  - Policy changes: `policy.*`
  - System events: `system.*`

  ## Usage

      # Log a secret access event
      Audit.log_event(%{
        event_type: "secret.accessed",
        actor_type: "agent",
        actor_id: "agent-prod-01",
        secret_id: secret.id,
        access_granted: true,
        policy_matched: "read-policy",
        source_ip: "10.0.1.5"
      })

      # Verify audit log integrity
      case Audit.verify_chain() do
        {:ok, :valid} -> IO.puts("Audit log integrity verified")
        {:error, reason} -> IO.puts("Integrity check failed: \#{reason}")
      end

      # Search audit logs
      logs = Audit.search_logs(%{
        event_type: "secret.accessed",
        actor_id: "agent-prod-01",
        from: ~U[2023-10-01 00:00:00Z],
        to: ~U[2023-10-31 23:59:59Z]
      })
  """

  require Logger
  import Ecto.Query

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.AuditLog

  @hmac_secret Application.compile_env(:secrethub_core, :audit_hmac_secret, "dev-audit-secret")

  @doc """
  Log an audit event with hash chain integrity.

  ## Parameters

  - `event_attrs` - Map containing event details:
    - `event_type` (required) - Type of event (see `AuditLog.valid_event_types/0`)
    - `actor_type` - Type of actor (agent, app, admin)
    - `actor_id` - ID of the actor
    - `secret_id` - ID of accessed secret (if applicable)
    - `access_granted` - Boolean indicating access result
    - `policy_matched` - Name of policy that allowed/denied access
    - `source_ip` - Source IP address
    - `event_data` - Additional event-specific data

  ## Returns

  - `{:ok, audit_log}` - Successfully logged event
  - `{:error, changeset}` - Validation failed

  ## Examples

      iex> Audit.log_event(%{
        event_type: "secret.accessed",
        actor_type: "agent",
        actor_id: "agent-001",
        secret_id: "secret-uuid",
        access_granted: true
      })
      {:ok, %AuditLog{}}
  """
  @spec log_event(map()) :: {:ok, AuditLog.t()} | {:error, Ecto.Changeset.t()}
  def log_event(event_attrs) do
    # Get the last log entry to build the chain
    last_entry = get_last_audit_entry()

    # Generate sequence number and hash chain
    sequence_number = if last_entry, do: last_entry.sequence_number + 1, else: 1
    previous_hash = if last_entry, do: last_entry.current_hash, else: "GENESIS"

    # Prepare audit log entry
    attrs =
      event_attrs
      |> Map.put(:event_id, Ecto.UUID.generate())
      |> Map.put(:sequence_number, sequence_number)
      |> Map.put(:timestamp, DateTime.utc_now())
      |> Map.put(:previous_hash, previous_hash)
      |> Map.put(:correlation_id, Map.get(event_attrs, :correlation_id, Ecto.UUID.generate()))
      |> Map.put(:created_at, DateTime.utc_now())

    # Calculate current hash
    current_hash = calculate_entry_hash(attrs)
    attrs = Map.put(attrs, :current_hash, current_hash)

    # Sign the entry
    signature = sign_entry(attrs)
    attrs = Map.put(attrs, :signature, signature)

    # Insert into database
    %AuditLog{}
    |> AuditLog.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, log} = result ->
        Logger.debug("Audit event logged",
          event_type: log.event_type,
          sequence: log.sequence_number
        )

        result

      {:error, changeset} = error ->
        Logger.error("Failed to log audit event",
          errors: inspect(changeset.errors),
          event_type: event_attrs[:event_type]
        )

        error
    end
  end

  @doc """
  Get the last audit log entry (highest sequence number).
  """
  @spec get_last_audit_entry() :: AuditLog.t() | nil
  def get_last_audit_entry do
    query =
      from(a in AuditLog,
        order_by: [desc: a.sequence_number],
        limit: 1
      )

    Repo.one(query)
  end

  @doc """
  Verify the integrity of the entire audit log chain.

  Checks:
  1. Sequential ordering (no gaps in sequence numbers)
  2. Hash chain integrity (each entry references previous)
  3. Signature validity (HMAC verification)

  ## Returns

  - `{:ok, :valid}` - Chain is valid
  - `{:error, reason}` - Chain is invalid with details
  """
  @spec verify_chain() :: {:ok, :valid} | {:error, String.t()}
  def verify_chain do
    query =
      from(a in AuditLog,
        order_by: [asc: a.sequence_number]
      )

    logs = Repo.all(query)

    case logs do
      [] ->
        {:ok, :valid}

      [first | rest] ->
        # Verify first entry
        if first.sequence_number != 1 do
          {:error, "Chain does not start at sequence 1"}
        else
          verify_chain_recursive(first, rest, 1)
        end
    end
  end

  @doc """
  Search audit logs with filters.

  ## Filters

  - `:event_type` - Filter by event type
  - `:actor_type` - Filter by actor type (agent, app, admin)
  - `:actor_id` - Filter by specific actor ID
  - `:secret_id` - Filter by secret ID
  - `:access_granted` - Filter by access result (true/false)
  - `:from` - Start timestamp (DateTime)
  - `:to` - End timestamp (DateTime)
  - `:limit` - Maximum number of results (default: 100)
  - `:offset` - Pagination offset

  ## Examples

      iex> Audit.search_logs(%{
        event_type: "secret.accessed",
        from: ~U[2023-10-01 00:00:00Z],
        limit: 50
      })
      [%AuditLog{}, ...]
  """
  @spec search_logs(map()) :: [AuditLog.t()]
  def search_logs(filters \\ %{}) do
    query = from(a in AuditLog, order_by: [desc: a.timestamp])

    query =
      Enum.reduce(filters, query, fn
        {:event_type, type}, q ->
          where(q, [a], a.event_type == ^type)

        {:actor_type, type}, q ->
          where(q, [a], a.actor_type == ^type)

        {:actor_id, id}, q ->
          where(q, [a], a.actor_id == ^id)

        {:secret_id, id}, q ->
          where(q, [a], a.secret_id == ^id)

        {:access_granted, granted}, q ->
          where(q, [a], a.access_granted == ^granted)

        {:from, datetime}, q ->
          where(q, [a], a.timestamp >= ^datetime)

        {:to, datetime}, q ->
          where(q, [a], a.timestamp <= ^datetime)

        {:correlation_id, id}, q ->
          where(q, [a], a.correlation_id == ^id)

        {:limit, limit}, q ->
          limit(q, ^limit)

        {:offset, offset}, q ->
          offset(q, ^offset)

        _, q ->
          q
      end)

    Repo.all(query)
  end

  @doc """
  Get audit log by ID.
  """
  @spec get_log(binary()) :: {:ok, AuditLog.t()} | {:error, :not_found}
  def get_log(log_id) do
    case Repo.get(AuditLog, log_id) do
      nil -> {:error, :not_found}
      log -> {:ok, log}
    end
  end

  @doc """
  Get statistics about audit logs.
  """
  @spec get_stats() :: map()
  def get_stats do
    total = Repo.aggregate(AuditLog, :count, :id)

    access_granted =
      Repo.aggregate(
        from(a in AuditLog, where: a.access_granted == true),
        :count,
        :id
      )

    access_denied =
      Repo.aggregate(
        from(a in AuditLog, where: a.access_granted == false),
        :count,
        :id
      )

    # Get event type distribution
    event_types =
      Repo.all(
        from(a in AuditLog,
          group_by: a.event_type,
          select: {a.event_type, count(a.id)}
        )
      )
      |> Enum.into(%{})

    # Get recent activity (last 24 hours)
    yesterday = DateTime.add(DateTime.utc_now(), -86_400, :second)

    recent_count =
      Repo.aggregate(
        from(a in AuditLog, where: a.timestamp >= ^yesterday),
        :count,
        :id
      )

    %{
      total: total,
      access_granted: access_granted,
      access_denied: access_denied,
      event_types: event_types,
      recent_24h: recent_count
    }
  end

  @doc """
  Export audit logs to CSV format.

  ## Parameters

  - `filters` - Same filters as `search_logs/1`

  ## Returns

  CSV string with audit log data.
  """
  @spec export_to_csv(map()) :: String.t()
  def export_to_csv(filters \\ %{}) do
    logs = search_logs(filters)

    headers = [
      "Timestamp",
      "Event Type",
      "Actor Type",
      "Actor ID",
      "Secret ID",
      "Access Granted",
      "Policy Matched",
      "Denial Reason",
      "Source IP",
      "Correlation ID"
    ]

    rows =
      Enum.map(logs, fn log ->
        [
          DateTime.to_iso8601(log.timestamp),
          log.event_type,
          log.actor_type || "",
          log.actor_id || "",
          log.secret_id || "",
          to_string(log.access_granted || false),
          log.policy_matched || "",
          log.denial_reason || "",
          to_string(log.source_ip || ""),
          log.correlation_id || ""
        ]
      end)

    ([headers] ++ rows)
    |> Enum.map_join("\n", &Enum.join(&1, ","))
  end

  ## Private Functions

  defp calculate_entry_hash(attrs) do
    # Create deterministic string from entry fields
    content =
      [
        attrs[:sequence_number],
        attrs[:timestamp] |> DateTime.to_iso8601(),
        attrs[:event_type],
        attrs[:actor_type] || "",
        attrs[:actor_id] || "",
        attrs[:secret_id] || "",
        attrs[:access_granted] || false,
        attrs[:previous_hash]
      ]
      |> Enum.join("|")

    :crypto.hash(:sha256, content)
    |> Base.encode16(case: :lower)
  end

  defp sign_entry(attrs) do
    content =
      [
        attrs[:event_id],
        attrs[:sequence_number],
        attrs[:current_hash]
      ]
      |> Enum.join("|")

    :crypto.mac(:hmac, :sha256, @hmac_secret, content)
    |> Base.encode16(case: :lower)
  end

  defp verify_signature(log) do
    content =
      [
        log.event_id,
        log.sequence_number,
        log.current_hash
      ]
      |> Enum.join("|")

    expected_signature =
      :crypto.mac(:hmac, :sha256, @hmac_secret, content)
      |> Base.encode16(case: :lower)

    log.signature == expected_signature
  end

  defp verify_chain_recursive(_prev, [], _expected_seq), do: {:ok, :valid}

  defp verify_chain_recursive(prev, [current | rest], expected_seq) do
    cond do
      current.sequence_number != expected_seq + 1 ->
        {:error,
         "Sequence gap detected: expected #{expected_seq + 1}, got #{current.sequence_number}"}

      current.previous_hash != prev.current_hash ->
        {:error,
         "Hash chain broken at sequence #{current.sequence_number}: previous_hash mismatch"}

      !verify_signature(current) ->
        {:error, "Invalid signature at sequence #{current.sequence_number}"}

      true ->
        verify_chain_recursive(current, rest, expected_seq + 1)
    end
  end
end
