defmodule SecretHub.Core.UpgradeGates do
  @moduledoc """
  Persists mechanical upgrade preflight evidence and validates cluster support.

  A gate records only the canonical hash of a zero-finding report. Stale-node
  acknowledgements are bound to an exact node-incarnation snapshot and the
  gate's current verification generation.
  """

  import Ecto.Query

  alias Ecto.UUID
  alias SecretHub.Core.{Audit, CanonicalJSON, ClusterState, Repo}

  alias SecretHub.Shared.Schemas.{
    ClusterNode,
    UpgradeGate,
    UpgradeGateStaleNodeAcknowledgement
  }

  @report_format "secrethub.upgrade-gate-report.v1"
  @preflight_version "1"
  @gates [
    "app_certificate_v2",
    "typed_runtime_authorization",
    "dynamic_secure_storage",
    "agent_certificate_bindings"
  ]
  @report_keys ~w(findings format gate preflight_version)
  @acknowledgement_keys [
    "capabilities_hash",
    "incarnation_id",
    "node_id",
    "observed_last_seen_at",
    "observed_status",
    "observed_version",
    "reason"
  ]
  @control_characters ~r/[\x00-\x1F\x7F]/u
  @sha256_hex ~r/\A[0-9a-f]{64}\z/

  defmodule RequirementError do
    @moduledoc """
    Raised when a cutover or contract requirement is not proven.
    """

    defexception [:message, :reason]
  end

  @type gate_name ::
          :app_certificate_v2
          | :typed_runtime_authorization
          | :dynamic_secure_storage
          | :agent_certificate_bindings
          | String.t()
  @type capability :: {String.t() | atom(), pos_integer()} | String.t() | atom()

  @doc """
  Returns the fixed gate allowlist.
  """
  @spec gates() :: [String.t()]
  def gates, do: @gates

  @doc """
  Canonicalizes and hashes a structurally valid upgrade report.

  Reports with findings can be hashed for diagnostic comparison, but `verify/3`
  will persist only a zero-finding report.
  """
  @spec report_hash(map()) :: {:ok, String.t()} | {:error, :invalid_report}
  def report_hash(report) do
    with {:ok, normalized_report} <- normalize_report(report) do
      {:ok, canonical_hash(normalized_report)}
    end
  end

  @doc """
  Persists a zero-finding report and optional exact stale-node acknowledgements.

  `report` may be a map or a zero-arity callback. Callbacks are executed only
  after the transaction-scoped gate lock is held, which lets the Mix task rerun
  its registered preflight inside the authoritative transaction.

  Required option:

    * `:actor_id` - nonempty public operator identity

  Optional options:

    * `:stale_node_acknowledgements` - snapshots returned by
      `cluster_capability/2`, each extended with a nonempty `:reason`
    * `:capability` - public capability evidence string or `{name, revision}`;
      defaults to `preflight@1`
  """
  @spec verify(gate_name(), map() | (-> map()), keyword()) ::
          {:ok, UpgradeGate.t()}
          | {:error,
             :unknown_gate
             | :invalid_actor
             | :invalid_report
             | :nonzero_findings
             | :invalid_acknowledgement
             | term()}
  def verify(gate, report, opts) do
    with {:ok, gate_name} <- normalize_gate(gate),
         {:ok, actor_id} <- normalize_actor(opts),
         {:ok, capability} <- normalize_audit_capability(opts) do
      Repo.transaction(fn ->
        verify_locked(gate_name, report, opts, actor_id, capability)
      end)
    end
  end

  @doc """
  Requires a durable verified marker for the fixed gate.
  """
  @spec require_verified!(gate_name()) :: :ok
  def require_verified!(gate) do
    case normalize_gate(gate) do
      {:ok, gate_name} ->
        if Repo.get_by(UpgradeGate, name: gate_name) do
          :ok
        else
          raise RequirementError,
            reason: :gate_not_verified,
            message: "upgrade gate #{gate_name} is not verified"
        end

      {:error, :unknown_gate} ->
        raise RequirementError,
          reason: :unknown_gate,
          message: "unknown upgrade gate #{inspect(gate)}"
    end
  end

  @doc """
  Checks fresh active Core nodes and exact stale-node acknowledgement evidence.

  Returns structured, sanitized failures so operator tooling can report public
  node identifiers without exposing node metadata.
  """
  @spec cluster_capability(gate_name(), capability()) ::
          :ok
          | {:error, :unknown_gate | :invalid_capability | :no_fresh_active_nodes}
          | {:error, {:incompatible_nodes, [map()]}}
          | {:error, {:stale_nodes, [map()]}}
  def cluster_capability(gate, capability) do
    with {:ok, gate_name} <- normalize_gate(gate),
         {:ok, capability_name, required_revision} <- normalize_capability(capability) do
      active_nodes =
        ClusterNode
        |> where([node], node.status != "shutdown")
        |> order_by([node], asc: node.node_id)
        |> Repo.all()

      cutoff =
        DateTime.add(
          DateTime.utc_now() |> DateTime.truncate(:second),
          -ClusterState.freshness_timeout_seconds(),
          :second
        )

      {fresh_nodes, stale_nodes} =
        Enum.split_with(active_nodes, &fresh?(&1, cutoff))

      incompatible_nodes =
        fresh_nodes
        |> Enum.reject(&supports_capability?(&1, capability_name, required_revision))
        |> Enum.map(&incompatible_node_evidence(&1, capability_name))

      unacknowledged_stale_nodes =
        stale_nodes
        |> unresolved_stale_snapshots(gate_name)

      cond do
        fresh_nodes == [] ->
          {:error, :no_fresh_active_nodes}

        incompatible_nodes != [] ->
          {:error, {:incompatible_nodes, incompatible_nodes}}

        unacknowledged_stale_nodes != [] ->
          {:error, {:stale_nodes, unacknowledged_stale_nodes}}

        true ->
          :ok
      end
    end
  end

  @doc """
  Raises `RequirementError` unless `cluster_capability/2` succeeds.
  """
  @spec require_cluster_capability!(gate_name(), capability()) :: :ok
  def require_cluster_capability!(gate, capability) do
    case cluster_capability(gate, capability) do
      :ok ->
        :ok

      {:error, reason} ->
        raise RequirementError,
          reason: reason,
          message: capability_error_message(gate, capability, reason)
    end
  end

  defp verify_locked(gate_name, report, opts, actor_id, capability) do
    acquire_gate_lock!(gate_name)
    current_gate = lock_current_gate(gate_name)
    generation = next_generation(current_gate)

    with {:ok, resolved_report} <- resolve_report(report),
         {:ok, normalized_report} <- normalize_report(resolved_report),
         :ok <- validate_report_for_gate(normalized_report, gate_name),
         {:ok, acknowledgements} <-
           validate_acknowledgements(
             Keyword.get(opts, :stale_node_acknowledgements, []),
             actor_id
           ),
         {:ok, persisted_gate} <-
           persist_gate(
             current_gate,
             gate_name,
             normalized_report,
             actor_id,
             generation
           ),
         :ok <-
           persist_acknowledgements(
             persisted_gate,
             generation,
             acknowledgements,
             actor_id
           ),
         :ok <-
           audit_acknowledgements(
             gate_name,
             persisted_gate.report_hash,
             capability,
             acknowledgements,
             actor_id
           ),
         :ok <-
           audit_gate(
             gate_name,
             persisted_gate.report_hash,
             capability,
             acknowledgements,
             actor_id
           ) do
      persisted_gate
    else
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp lock_current_gate(gate_name) do
    Repo.one(
      from(g in UpgradeGate,
        where: g.name == ^gate_name,
        lock: "FOR UPDATE"
      )
    )
  end

  defp next_generation(nil), do: 1

  defp next_generation(%UpgradeGate{verification_generation: current}) do
    current + 1
  end

  defp acquire_gate_lock!(gate_name) do
    Repo.query!(
      "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))",
      ["secrethub:upgrade-gate:#{gate_name}"]
    )

    :ok
  end

  defp resolve_report(report) when is_function(report, 0) do
    case report.() do
      {:ok, resolved_report} when is_map(resolved_report) -> {:ok, resolved_report}
      resolved_report when is_map(resolved_report) -> {:ok, resolved_report}
      _other -> {:error, :invalid_report}
    end
  end

  defp resolve_report(report) when is_map(report), do: {:ok, report}
  defp resolve_report(_report), do: {:error, :invalid_report}

  defp normalize_report(report) when is_map(report) do
    with {:ok, normalized_report} <- normalize_exact_map(report, @report_keys),
         true <- normalized_report["format"] == @report_format,
         true <- normalized_report["preflight_version"] == @preflight_version,
         {:ok, gate_name} <- normalize_gate(normalized_report["gate"]),
         true <- is_list(normalized_report["findings"]) do
      normalized_report = Map.put(normalized_report, "gate", gate_name)

      try do
        CanonicalJSON.encode!(normalized_report)
        {:ok, normalized_report}
      rescue
        ArgumentError -> {:error, :invalid_report}
        Jason.EncodeError -> {:error, :invalid_report}
      end
    else
      _other -> {:error, :invalid_report}
    end
  end

  defp normalize_report(_report), do: {:error, :invalid_report}

  defp validate_report_for_gate(report, gate_name) do
    cond do
      report["gate"] != gate_name -> {:error, :invalid_report}
      report["findings"] != [] -> {:error, :nonzero_findings}
      true -> :ok
    end
  end

  defp persist_gate(current_gate, gate_name, report, actor_id, generation) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    attrs = %{
      name: gate_name,
      report_format: report["format"],
      report_hash: canonical_hash(report),
      preflight_version: report["preflight_version"],
      verified_at: now,
      verified_by: actor_id,
      verification_generation: generation
    }

    (current_gate || %UpgradeGate{})
    |> UpgradeGate.changeset(attrs)
    |> then(fn changeset ->
      if current_gate, do: Repo.update(changeset), else: Repo.insert(changeset)
    end)
  end

  defp validate_acknowledgements(acknowledgements, actor_id)
       when is_list(acknowledgements) do
    stale_nodes =
      ClusterNode
      |> where([node], node.status != "shutdown")
      |> Repo.all()
      |> Enum.reject(&fresh?(&1, freshness_cutoff()))

    stale_snapshots =
      Map.new(stale_nodes, fn node ->
        snapshot = stale_node_snapshot(node)
        {snapshot_key(snapshot), snapshot}
      end)

    acknowledgements
    |> Enum.reduce_while({:ok, [], MapSet.new()}, fn acknowledgement, {:ok, normalized, seen} ->
      with {:ok, normalized_acknowledgement} <-
             normalize_acknowledgement(acknowledgement, actor_id),
           key <- snapshot_key(normalized_acknowledgement),
           false <- MapSet.member?(seen, key),
           ^normalized_acknowledgement <-
             stale_snapshots
             |> Map.get(key)
             |> merge_reason(normalized_acknowledgement.reason) do
        {:cont, {:ok, [normalized_acknowledgement | normalized], MapSet.put(seen, key)}}
      else
        _other -> {:halt, {:error, :invalid_acknowledgement}}
      end
    end)
    |> case do
      {:ok, normalized, _seen} -> {:ok, Enum.reverse(normalized)}
      {:error, :invalid_acknowledgement} = error -> error
    end
  end

  defp validate_acknowledgements(_acknowledgements, _actor_id) do
    {:error, :invalid_acknowledgement}
  end

  defp normalize_acknowledgement(acknowledgement, _actor_id)
       when is_map(acknowledgement) do
    with {:ok, normalized} <-
           normalize_exact_map(acknowledgement, @acknowledgement_keys),
         {:ok, incarnation_id} <- UUID.cast(normalized["incarnation_id"]),
         %DateTime{} = observed_last_seen_at <- normalized["observed_last_seen_at"],
         true <- normalized["observed_status"] in ~w(starting initializing sealed unsealed),
         true <- public_string?(normalized["node_id"]),
         true <-
           is_nil(normalized["observed_version"]) or
             public_string?(normalized["observed_version"]),
         true <- valid_sha256?(normalized["capabilities_hash"]),
         true <- public_string?(normalized["reason"], 1_024) do
      {:ok,
       %{
         node_id: normalized["node_id"],
         incarnation_id: incarnation_id,
         observed_last_seen_at: observed_last_seen_at,
         observed_status: normalized["observed_status"],
         observed_version: normalized["observed_version"],
         capabilities_hash: normalized["capabilities_hash"],
         reason: normalized["reason"]
       }}
    else
      _other -> {:error, :invalid_acknowledgement}
    end
  end

  defp normalize_acknowledgement(_acknowledgement, _actor_id) do
    {:error, :invalid_acknowledgement}
  end

  defp merge_reason(nil, _reason), do: nil
  defp merge_reason(snapshot, reason), do: Map.put(snapshot, :reason, reason)

  defp persist_acknowledgements(gate, generation, acknowledgements, actor_id) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Enum.reduce_while(acknowledgements, :ok, fn acknowledgement, :ok ->
      attrs =
        acknowledgement
        |> Map.put(:upgrade_gate_id, gate.id)
        |> Map.put(:verification_generation, generation)
        |> Map.put(:acknowledged_by, actor_id)
        |> Map.put(:acknowledged_at, now)

      case %UpgradeGateStaleNodeAcknowledgement{}
           |> UpgradeGateStaleNodeAcknowledgement.changeset(attrs)
           |> Repo.insert() do
        {:ok, _persisted} -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp audit_acknowledgements(
         gate_name,
         report_hash,
         capability,
         acknowledgements,
         actor_id
       ) do
    Enum.reduce_while(acknowledgements, :ok, fn acknowledgement, :ok ->
      case audit_event(
             "system.upgrade_stale_node_acknowledged",
             gate_name,
             report_hash,
             capability,
             snapshot_hash(acknowledgement),
             actor_id
           ) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp audit_gate(gate_name, report_hash, capability, acknowledgements, actor_id) do
    acknowledgement_snapshot_hash =
      acknowledgements
      |> Enum.map(&snapshot_payload/1)
      |> Enum.sort_by(fn snapshot ->
        {
          snapshot["node_id"],
          snapshot["incarnation_id"],
          snapshot["observed_last_seen_at"]
        }
      end)
      |> canonical_hash()

    audit_event(
      "system.upgrade_gate_verified",
      gate_name,
      report_hash,
      capability,
      acknowledgement_snapshot_hash,
      actor_id
    )
  end

  defp audit_event(
         event_type,
         gate_name,
         report_hash,
         capability,
         acknowledgement_snapshot_hash,
         actor_id
       ) do
    attrs = %{
      event_type: event_type,
      hash_version: 2,
      actor_type: "admin",
      actor_id: actor_id,
      access_granted: true,
      event_data: %{
        "upgrade_gate" => %{
          "gate" => gate_name,
          "report_hash" => report_hash,
          "capability" => capability,
          "acknowledgement_snapshot_hash" => acknowledgement_snapshot_hash
        }
      }
    }

    case audit_module().log_event(attrs) do
      {:ok, _audit_log} -> :ok
      {:error, reason} -> {:error, reason}
      other -> {:error, {:invalid_audit_result, other}}
    end
  end

  if Application.compile_env(:secrethub_core, :env) == :test do
    defp audit_module do
      Application.get_env(:secrethub_core, :upgrade_gate_audit_module, Audit)
    end
  else
    defp audit_module, do: Audit
  end

  defp unresolved_stale_snapshots(stale_nodes, gate_name) do
    acknowledgements = current_acknowledgement_snapshots(gate_name)

    stale_nodes
    |> Enum.map(&stale_node_snapshot/1)
    |> Enum.reject(&MapSet.member?(acknowledgements, &1))
  end

  defp current_acknowledgement_snapshots(gate_name) do
    UpgradeGateStaleNodeAcknowledgement
    |> join(:inner, [ack], gate in UpgradeGate,
      on:
        gate.id == ack.upgrade_gate_id and
          gate.verification_generation == ack.verification_generation
    )
    |> where([_ack, gate], gate.name == ^gate_name)
    |> lock("FOR SHARE")
    |> Repo.all()
    |> Enum.map(&acknowledgement_snapshot/1)
    |> MapSet.new()
  end

  defp stale_node_snapshot(node) do
    %{
      node_id: node.node_id,
      incarnation_id: node.incarnation_id,
      observed_last_seen_at: node.last_seen_at,
      observed_status: node.status,
      observed_version: node.version,
      capabilities_hash: capabilities_hash(node)
    }
  end

  defp acknowledgement_snapshot(acknowledgement) do
    %{
      node_id: acknowledgement.node_id,
      incarnation_id: acknowledgement.incarnation_id,
      observed_last_seen_at: acknowledgement.observed_last_seen_at,
      observed_status: acknowledgement.observed_status,
      observed_version: acknowledgement.observed_version,
      capabilities_hash: acknowledgement.capabilities_hash
    }
  end

  defp snapshot_payload(snapshot) do
    %{
      "node_id" => snapshot.node_id,
      "incarnation_id" => snapshot.incarnation_id,
      "observed_last_seen_at" => snapshot.observed_last_seen_at,
      "observed_status" => snapshot.observed_status,
      "observed_version" => snapshot.observed_version,
      "capabilities_hash" => snapshot.capabilities_hash
    }
  end

  defp snapshot_hash(snapshot) do
    snapshot
    |> snapshot_payload()
    |> canonical_hash()
  end

  defp snapshot_key(snapshot) do
    {
      snapshot.node_id,
      snapshot.incarnation_id,
      snapshot.observed_last_seen_at
    }
  end

  defp capabilities_hash(node) do
    node
    |> capabilities()
    |> canonical_hash()
  end

  defp capabilities(node) do
    metadata = node.metadata || %{}
    Map.get(metadata, "capabilities") || Map.get(metadata, :capabilities) || %{}
  end

  defp supports_capability?(node, capability_name, required_revision) do
    case capabilities(node) do
      capability_map when is_map(capability_map) ->
        revision =
          Map.get(capability_map, capability_name) ||
            safe_existing_atom_value(capability_map, capability_name)

        is_integer(revision) and revision >= required_revision

      _other ->
        false
    end
  end

  defp incompatible_node_evidence(node, capability_name) do
    capability_revision =
      case capabilities(node) do
        capability_map when is_map(capability_map) ->
          Map.get(capability_map, capability_name) ||
            safe_existing_atom_value(capability_map, capability_name)

        _other ->
          nil
      end

    %{
      node_id: node.node_id,
      incarnation_id: node.incarnation_id,
      status: node.status,
      version: node.version,
      capability_revision: capability_revision
    }
  end

  defp safe_existing_atom_value(map, key) do
    Map.get(map, String.to_existing_atom(key))
  rescue
    ArgumentError -> nil
  end

  defp freshness_cutoff do
    DateTime.add(
      DateTime.utc_now() |> DateTime.truncate(:second),
      -ClusterState.freshness_timeout_seconds(),
      :second
    )
  end

  defp fresh?(%ClusterNode{last_seen_at: nil}, _cutoff), do: false

  defp fresh?(%ClusterNode{last_seen_at: last_seen_at}, cutoff) do
    DateTime.compare(last_seen_at, cutoff) in [:gt, :eq]
  end

  defp normalize_gate(gate) when is_atom(gate), do: gate |> Atom.to_string() |> normalize_gate()

  defp normalize_gate(gate) when is_binary(gate) do
    if gate in @gates, do: {:ok, gate}, else: {:error, :unknown_gate}
  end

  defp normalize_gate(_gate), do: {:error, :unknown_gate}

  defp normalize_actor(opts) when is_list(opts) do
    if Keyword.keyword?(opts) and public_string?(Keyword.get(opts, :actor_id)) do
      {:ok, Keyword.fetch!(opts, :actor_id)}
    else
      {:error, :invalid_actor}
    end
  end

  defp normalize_actor(_opts), do: {:error, :invalid_actor}

  defp normalize_audit_capability(opts) do
    case Keyword.get(opts, :capability, "preflight@1") do
      {name, revision} ->
        with {:ok, capability_name, required_revision} <-
               normalize_capability({name, revision}) do
          {:ok, "#{capability_name}@#{required_revision}"}
        end

      capability when is_binary(capability) ->
        if public_string?(capability), do: {:ok, capability}, else: {:error, :invalid_capability}

      capability when is_atom(capability) ->
        normalize_audit_capability(Keyword.put(opts, :capability, Atom.to_string(capability)))

      _other ->
        {:error, :invalid_capability}
    end
  end

  defp normalize_capability({name, revision}) when is_integer(revision) and revision > 0 do
    case normalize_capability_name(name) do
      {:ok, capability_name} -> {:ok, capability_name, revision}
      {:error, :invalid_capability} = error -> error
    end
  end

  defp normalize_capability(name) do
    case normalize_capability_name(name) do
      {:ok, capability_name} -> {:ok, capability_name, 1}
      {:error, :invalid_capability} = error -> error
    end
  end

  defp normalize_capability_name(name) when is_atom(name) do
    name |> Atom.to_string() |> normalize_capability_name()
  end

  defp normalize_capability_name(name) when is_binary(name) do
    if public_string?(name), do: {:ok, name}, else: {:error, :invalid_capability}
  end

  defp normalize_capability_name(_name), do: {:error, :invalid_capability}

  defp normalize_exact_map(value, expected_keys) when is_map(value) do
    pairs =
      Enum.map(value, fn {key, nested_value} ->
        {normalize_key(key), nested_value}
      end)

    keys = Enum.map(pairs, &elem(&1, 0))

    cond do
      Enum.any?(keys, &(&1 == :error)) ->
        {:error, :invalid_map}

      Enum.uniq(keys) != keys ->
        {:error, :invalid_map}

      Enum.sort(keys) != Enum.sort(expected_keys) ->
        {:error, :invalid_map}

      true ->
        {:ok, Map.new(pairs)}
    end
  end

  defp normalize_exact_map(_value, _expected_keys), do: {:error, :invalid_map}

  defp normalize_key(key) when is_binary(key), do: key
  defp normalize_key(key) when is_atom(key), do: Atom.to_string(key)
  defp normalize_key(_key), do: :error

  defp public_string?(value, max_length \\ 255)

  defp public_string?(value, max_length)
       when is_binary(value) and byte_size(value) > 0 and byte_size(value) <= max_length do
    String.valid?(value) and String.trim(value) != "" and
      not Regex.match?(@control_characters, value)
  end

  defp public_string?(_value, _max_length), do: false

  defp valid_sha256?(value) when is_binary(value), do: Regex.match?(@sha256_hex, value)
  defp valid_sha256?(_value), do: false

  defp canonical_hash(value) do
    value
    |> CanonicalJSON.encode!()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp capability_error_message(gate, capability, :no_fresh_active_nodes) do
    "upgrade gate #{inspect(gate)} capability #{inspect(capability)} has no fresh active nodes"
  end

  defp capability_error_message(gate, capability, {:incompatible_nodes, nodes}) do
    "upgrade gate #{inspect(gate)} capability #{inspect(capability)} is missing on " <>
      "#{length(nodes)} fresh active node(s)"
  end

  defp capability_error_message(gate, capability, {:stale_nodes, nodes}) do
    "upgrade gate #{inspect(gate)} capability #{inspect(capability)} has " <>
      "#{length(nodes)} unacknowledged stale node(s)"
  end

  defp capability_error_message(gate, capability, reason) do
    "upgrade gate #{inspect(gate)} capability #{inspect(capability)} failed: #{inspect(reason)}"
  end
end
