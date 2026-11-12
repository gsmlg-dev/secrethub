defmodule SecretHub.Core.SSH do
  @moduledoc "Revisioned SSH management and freshly authorized machine runtime views."
  import Ecto.Query
  alias SecretHub.Core.{Agents, Audit, Repo}
  alias SecretHub.Core.SSH.{Evaluator, Identities}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.{Agent, Certificate}
  alias SecretHub.Shared.Schemas.SSH.{Identity, IdentityKey, Inventory}
  alias SecretHub.Shared.SSH.Key

  @identity_fields [
    :id,
    :name,
    :origin,
    :agent_id,
    :local_username,
    :local_uid,
    :status,
    :rotation_days,
    :next_rotation_at,
    :requested_generation,
    :rotation_overdue
  ]
  @key_fields [:id, :generation, :public_key, :fingerprint, :not_after, :inserted_at]
  @inventory_fields [:groups, :endpoints, :rules, :reports]
  @mutating_ops ["inventory", "identity_report"]
  # identity_report rejections are audited with their reason but replied to as :denied.
  @report_rejections [
    :invalid_request,
    :invalid_public_key,
    :account_changed,
    :retired,
    :duplicate_key,
    :name_taken,
    :unexpected_generation
  ]
  @record_keys ~w(id name kind agent_ids identity_ids agent_id aliases port host_keys approved enabled effect source_kind source_id destination_kind destination_id destination_user candidate_host_keys)

  def snapshot do
    case Repo.transaction(fn -> public_snapshot(load_inventory(lock_inventory("FOR SHARE"))) end) do
      {:ok, value} -> value
      {:error, reason} -> {:error, reason}
    end
  end

  def preview(changes, expected_revision) do
    with {:ok, _master_key} <- master_key() do
      Repo.transaction(fn ->
        row = lock_inventory("FOR UPDATE")
        check_revision!(row, expected_revision)
        before = load_inventory(row)
        after_inventory = change_batch!(before, changes, now())
        diff = Evaluator.diff(before, after_inventory)

        Map.merge(diff, %{
          revision: row.revision,
          changes: scrub_changes(changes),
          identity_names: Map.new(after_inventory.identities, &{&1.id, &1.name})
        })
      end)
    end
  end

  def apply_changes(changes, expected_revision) do
    with {:ok, master_key} <- master_key() do
      result =
        Repo.transaction(fn ->
          row = lock_inventory("FOR UPDATE")
          check_revision!(row, expected_revision)
          inventory = change_batch!(load_inventory(row), changes, now())
          revision = row.revision + 1

          audit!("configuration", "operator", "management", revision, true, %{
            changes: scrub_changes(changes),
            identities:
              Enum.map(inventory.identities, fn identity ->
                identity
                |> Map.take([:id, :name, :origin, :agent_id, :status, :requested_generation])
                |> Map.put(:fingerprints, Enum.map(identity.keys, & &1.fingerprint))
              end)
          })

          ensure_master_key!(master_key)
          persist!(row, inventory, revision)
          public_snapshot(%{inventory | revision: revision})
        end)

      case result do
        {:ok, snapshot} ->
          broadcast(snapshot.revision)
          {:ok, snapshot}

        error ->
          error
      end
    end
  end

  @doc "Applies due rotations, overdue flags and key pruning. Returns {:ok, events}."
  def rotate_due(now \\ DateTime.utc_now()) do
    now = DateTime.truncate(now, :second)

    with {:ok, master_key} <- master_key() do
      Repo.transaction(fn ->
        row = lock_inventory("FOR UPDATE")
        inventory = load_inventory(row)

        case Identities.schedule(inventory.identities, now) do
          {_, []} ->
            []

          {identities, events} ->
            revision = row.revision + 1

            for event <- events do
              {name, data} = rotation_audit(event)
              audit!(name, "system", "ssh_identity_rotation", revision, true, data)
            end

            ensure_master_key!(master_key)
            persist!(row, %{inventory | identities: identities}, revision)
            {revision, events}
        end
      end)
      |> case do
        {:ok, []} ->
          {:ok, []}

        {:ok, {revision, events}} ->
          broadcast(revision)
          {:ok, events}

        error ->
          error
      end
    end
  end

  defp rotation_audit({:rotation_requested, id, generation}),
    do: {"identity_rotation_requested", %{"identity_id" => id, "generation" => generation}}

  defp rotation_audit({:rotation_overdue, id}),
    do: {"identity_rotation_overdue", %{"identity_id" => id}}

  defp rotation_audit({:keys_pruned, id, count}),
    do: {"identity_keys_pruned", %{"identity_id" => id, "count" => count}}

  def runtime_operation(%{agent_id: agent_id, certificate_id: certificate_id}, operation, payload)
      when is_binary(agent_id) and is_binary(operation) and is_map(payload) do
    with {:ok, master_key} <- master_key() do
      Repo.transaction(fn ->
        now = now()

        inventory =
          load_inventory(
            lock_inventory(if(operation in @mutating_ops, do: "FOR UPDATE", else: "FOR SHARE"))
          )

        lock_machine(agent_id)

        result =
          with :ok <- Agents.authorize_runtime(agent_id, certificate_id),
               :ok <- current_certificate_start(certificate_id),
               :ok <- capability(agent_id, operation) do
            runtime_view(inventory, agent_id, operation, payload, now)
          end

        granted = decision_granted?(result)

        metadata =
          audit_metadata(inventory, agent_id, operation, payload, result)
          |> Map.put("outcome", if(granted, do: "allowed", else: "denied"))

        revision =
          case result do
            {:ok, %{revision: revision}} -> revision
            _ -> inventory.revision
          end

        audit!(operation, "agent", agent_id, revision, granted, metadata)

        final =
          with :ok <- fresh_master_key(master_key),
               :ok <- Agents.authorize_runtime(agent_id, certificate_id),
               :ok <- current_certificate_start(certificate_id),
               :ok <- capability(agent_id, operation) do
            if operation in @mutating_ops,
              do: result,
              else:
                runtime_view(
                  load_inventory(lock_inventory("FOR SHARE")),
                  agent_id,
                  operation,
                  payload,
                  now
                )
          end

        final = if final != result and match?({:ok, _}, final), do: {:error, :denied}, else: final

        if final != result,
          do:
            audit!(
              operation,
              "agent",
              agent_id,
              revision,
              false,
              Map.put(metadata, "outcome", "changed_before_release")
            )

        persist_runtime(operation, inventory, agent_id, final)
      end)
      |> case do
        {:ok, {:ok, %{unchanged: true} = reply}} when operation in @mutating_ops ->
          {:ok, Map.delete(reply, :unchanged)}

        {:ok, {:ok, %{revision: revision} = reply}} when operation in @mutating_ops ->
          broadcast(revision)
          {:ok, reply}

        {:ok, {:error, reason}}
        when operation == "identity_report" and reason in @report_rejections ->
          {:error, :denied}

        {:ok, result} ->
          result

        error ->
          error
      end
    end
  end

  def runtime_operation(_, _, _), do: {:error, :invalid_identity}

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)

  defp broadcast(revision) do
    if Process.whereis(SecretHub.Web.PubSub),
      do:
        Phoenix.PubSub.broadcast(
          SecretHub.Web.PubSub,
          "ssh:policy",
          {:ssh_policy_changed, revision}
        )
  end

  defp runtime_view(inventory, agent_id, "identities", payload, now) do
    with true <- local_account?(payload) do
      keys =
        case agent_identity(inventory, agent_id, payload) do
          nil ->
            []

          identity ->
            if Identities.usable?(identity, now) and outgoing?(inventory, identity),
              do:
                for(
                  key <- Identities.valid_keys(identity, now),
                  do: %{public_key: key.public_key, generation: key.generation}
                ),
              else: []
        end

      {:ok, %{identities: keys, revision: inventory.revision}}
    else
      _ -> {:error, :invalid_request}
    end
  end

  defp runtime_view(inventory, agent_id, "authorize_sign", payload, now) do
    with true <- local_account?(payload),
         {:ok, public} <- Key.decode_public(payload["public_key"]),
         %{} = identity <- agent_identity(inventory, agent_id, payload),
         true <- Identities.usable?(identity, now),
         %{} = key <-
           Enum.find(
             Identities.valid_keys(identity, now),
             &(&1.public_key == public.public_line)
           ),
         true <- outgoing?(inventory, identity) do
      {:ok,
       %{
         allowed: true,
         public_key: key.public_key,
         generation: key.generation,
         revision: inventory.revision
       }}
    else
      _ -> {:error, :denied}
    end
  end

  defp runtime_view(inventory, agent_id, "authorized_keys", payload, now) do
    with true <- valid_user?(payload["username"]),
         {:ok, public} <- Key.decode_public(payload["key"]) do
      lines =
        for identity <- inventory.identities,
            Identities.usable?(identity, now),
            key <- Identities.valid_keys(identity, now),
            key.public_key == public.public_line,
            trusted_source?(identity),
            approved_endpoint?(inventory, agent_id),
            Evaluator.decision(inventory, identity.id, agent_id, payload["username"]).allowed,
            do: "no-agent-forwarding " <> key.public_key

      {:ok, %{lines: Enum.uniq(lines), revision: inventory.revision}}
    else
      _ -> {:error, :invalid_request}
    end
  end

  defp runtime_view(inventory, agent_id, "known_hosts", payload, now) do
    with true <- local_account?(payload),
         true <- payload["reason"] in ["ORDER", "HOSTNAME", "ADDRESS"],
         true <- is_integer(payload["port"]) and payload["port"] in 1..65_535,
         {:ok, host} <- lookup_alias(payload["host"], payload["port"]) do
      lines =
        for identity <- List.wrap(agent_identity(inventory, agent_id, payload)),
            Identities.usable?(identity, now),
            endpoint <- inventory.endpoints,
            endpoint.approved and endpoint.host_keys != [],
            endpoint.port == payload["port"] and host in endpoint.aliases,
            live_agent?(endpoint.agent_id, "ssh_lookup_v1"),
            outgoing_to?(inventory, identity, endpoint.agent_id),
            key <- endpoint.host_keys,
            do: known_host_name(host, endpoint.port) <> " " <> key

      {:ok, %{lines: Enum.uniq(lines), revision: inventory.revision}}
    else
      _ -> {:error, :invalid_request}
    end
  end

  defp runtime_view(inventory, agent_id, "inventory", payload, now) do
    with {:ok, keys} <- public_keys(Map.get(payload, "host_keys", [])),
         {:ok, users} <- reported_users(Map.get(payload, "users", [])) do
      endpoint = Enum.find(inventory.endpoints, &(&1.agent_id == agent_id))
      report = Map.get(inventory.reports, agent_id)

      unchanged =
        endpoint != nil and report != nil and Map.get(endpoint, :candidate_host_keys, []) == keys and
          report["users"] == users

      {:ok,
       %{
         revision: inventory.revision + if(unchanged, do: 0, else: 1),
         candidate_host_keys: keys,
         users: users,
         unchanged: unchanged,
         identity_generations: identity_generations(inventory, agent_id, now)
       }}
    else
      _ -> {:error, :invalid_request}
    end
  end

  defp runtime_view(inventory, agent_id, "identity_report", payload, now) do
    with true <-
           (local_account?(payload) and is_integer(payload["generation"]) and
              payload["generation"] >= 1) || {:error, :invalid_request},
         %Agent{} = agent <- Repo.get_by(Agent, agent_id: agent_id) || {:error, :invalid_request},
         {:ok, identities, event} <-
           Identities.report(
             inventory.identities,
             %{
               agent_id: agent_id,
               agent_name: agent.name || agent_id,
               uid: payload["uid"],
               username: payload["username"],
               generation: payload["generation"],
               public_key: payload["public_key"]
             },
             now
           ) do
      unchanged = event == :unchanged

      {:ok,
       %{
         revision: inventory.revision + if(unchanged, do: 0, else: 1),
         unchanged: unchanged,
         identities: identities,
         event: event
       }}
    end
  end

  defp runtime_view(_, _, _, _, _), do: {:error, :unsupported_operation}

  defp persist_runtime("inventory", inventory, agent_id, result),
    do: persist_candidates(inventory, agent_id, result)

  defp persist_runtime(
         "identity_report",
         _inventory,
         _agent_id,
         {:ok, %{unchanged: true} = reply}
       ),
       do: {:ok, Map.drop(reply, [:identities, :event])}

  defp persist_runtime(
         "identity_report",
         inventory,
         _agent_id,
         {:ok, %{revision: revision, identities: identities}}
       ) do
    persist!(Repo.get!(Inventory, 1), %{inventory | identities: identities}, revision)
    {:ok, %{revision: revision, accepted: true}}
  end

  defp persist_runtime(_, _, _, result), do: result

  defp persist_candidates(_, _, {:ok, %{unchanged: true} = reply}),
    do: {:ok, Map.take(reply, [:unchanged, :revision, :identity_generations])}

  defp persist_candidates(
         inventory,
         agent_id,
         {:ok, %{candidate_host_keys: keys, users: users, revision: revision} = reply}
       ) do
    endpoint =
      Enum.find(inventory.endpoints, &(&1.agent_id == agent_id)) ||
        %{agent_id: agent_id, aliases: [], port: 22, host_keys: [], approved: false}

    updated =
      put_record(inventory, :endpoints, Map.put(endpoint, :candidate_host_keys, keys), :agent_id)

    report = %{"users" => users, "seen_at" => DateTime.to_iso8601(DateTime.utc_now())}
    updated = %{updated | reports: Map.put(updated.reports, agent_id, report)}
    # Inventory heartbeats change endpoints and reports only, never identities.
    persist_inventory!(Repo.get!(Inventory, 1), updated, revision)
    {:ok, %{revision: revision, identity_generations: reply.identity_generations}}
  end

  defp persist_candidates(_, _, result), do: result

  defp local_account?(payload),
    do:
      is_integer(payload["uid"]) and payload["uid"] in 0..4_294_967_295 and
        valid_user?(payload["username"])

  defp agent_identity(inventory, agent_id, payload) do
    username = payload["username"]

    case Identities.find_agent_identity(inventory.identities, agent_id, payload["uid"]) do
      %{local_username: ^username} = identity -> identity
      _ -> nil
    end
  end

  defp identity_generations(inventory, agent_id, now) do
    for identity <- inventory.identities,
        identity.origin == "agent" and identity.agent_id == agent_id,
        do: %{
          uid: identity.local_uid,
          status: identity.status,
          requested_generation: identity.requested_generation,
          generations:
            if(identity.status == "retired",
              do: [],
              else: Enum.map(Identities.valid_keys(identity, now), & &1.generation)
            )
        }
  end

  defp outgoing?(inventory, identity),
    do:
      Enum.any?(
        inventory.endpoints,
        &(approved_endpoint?(inventory, &1.agent_id) and
            outgoing_to?(inventory, identity, &1.agent_id))
      )

  defp outgoing_to?(inventory, identity, destination),
    do:
      Enum.any?(inventory.rules, fn rule ->
        Evaluator.decision(inventory, identity.id, destination, rule.destination_user).allowed
      end)

  defp approved_endpoint?(inventory, agent_id),
    do:
      Enum.any?(
        inventory.endpoints,
        &(&1.agent_id == agent_id and &1.approved and &1.host_keys != [])
      ) and live_agent?(agent_id, "ssh_lookup_v1")

  defp live_agent?(agent_id, capability) do
    case lock_machine(agent_id) do
      %Agent{runtime_capabilities: capabilities} = agent ->
        capability in capabilities and trusted_agent?(agent)

      _ ->
        false
    end
  end

  # A device-held private key stays usable on a revoked device, so an Agent
  # identity is served only while its source Agent is still trusted. It need
  # not be online or advertise ssh_signing_v1.
  defp trusted_source?(%{origin: "external"}), do: true

  defp trusted_source?(%{origin: "agent", agent_id: agent_id}) do
    case lock_machine(agent_id) do
      %Agent{certificate_id: certificate_id} ->
        Agents.trusted_identity_source?(agent_id, certificate_id) and
          current_certificate_start(certificate_id) == :ok

      _ ->
        false
    end
  end

  defp trusted_source?(_), do: false

  defp trusted_agent?(%Agent{agent_id: agent_id, certificate_id: certificate_id}),
    do:
      Agents.authorize_runtime(agent_id, certificate_id) == :ok and
        current_certificate_start(certificate_id) == :ok

  defp lock_machine(agent_id) do
    agent = Repo.one(from(agent in Agent, where: agent.agent_id == ^agent_id, lock: "FOR SHARE"))

    if agent && agent.certificate_id,
      do:
        Repo.one(
          from(certificate in Certificate,
            where: certificate.id == ^agent.certificate_id,
            lock: "FOR SHARE"
          )
        )

    agent
  end

  defp current_certificate_start(id) do
    case Repo.one(
           from(certificate in Certificate, where: certificate.id == ^id, lock: "FOR SHARE")
         ) do
      %Certificate{valid_from: from} when not is_nil(from) ->
        if DateTime.compare(from, DateTime.utc_now()) == :gt,
          do: {:error, :certificate_not_yet_valid},
          else: :ok

      _ ->
        {:error, :invalid_certificate}
    end
  end

  defp capability(agent_id, operation) do
    required =
      case operation do
        "inventory" ->
          ["ssh_signing_v1", "ssh_lookup_v1"]

        operation when operation in ["identities", "authorize_sign", "identity_report"] ->
          ["ssh_signing_v1"]

        _ ->
          ["ssh_lookup_v1"]
      end

    case Repo.get_by(Agent, agent_id: agent_id) do
      %Agent{runtime_capabilities: capabilities} ->
        if Enum.any?(required, &(&1 in capabilities)),
          do: :ok,
          else: {:error, :capability_unavailable}

      _ ->
        {:error, :agent_not_found}
    end
  end

  defp lock_inventory("FOR SHARE"),
    do: Repo.one!(from(inventory in Inventory, where: inventory.id == 1, lock: "FOR SHARE"))

  defp lock_inventory("FOR UPDATE"),
    do: Repo.one!(from(inventory in Inventory, where: inventory.id == 1, lock: "FOR UPDATE"))

  defp check_revision!(%{revision: revision}, revision), do: :ok
  defp check_revision!(_, _), do: Repo.rollback(:stale_revision)

  defp load_inventory(row) do
    %{
      revision: row.revision,
      groups: Enum.map(records(row.groups), &normalize_group/1),
      endpoints: records(row.endpoints),
      rules: records(row.rules),
      reports: row.reports,
      identities:
        Repo.all(from(i in Identity, order_by: i.id, preload: :keys))
        |> Enum.map(fn identity ->
          identity
          |> Map.take(@identity_fields)
          |> Map.put(:keys, Enum.map(identity.keys, &Map.take(&1, @key_fields)))
        end)
    }
  end

  # Groups stored before identity groups existed are host groups.
  defp normalize_group(group) do
    case Map.get(group, :kind, "host") do
      "identity" -> group |> Map.put(:kind, "identity") |> Map.put_new(:identity_ids, [])
      _ -> group |> Map.put(:kind, "host") |> Map.put_new(:agent_ids, [])
    end
  end

  defp records(records),
    do:
      Enum.map(records, fn record ->
        Map.new(record, fn {key, value} -> {record_key(key), value} end)
      end)

  defp record_key(key) when is_atom(key), do: key
  defp record_key(key) when key in @record_keys, do: String.to_existing_atom(key)

  defp public_snapshot(inventory) do
    agents =
      Repo.all(from(agent in Agent, order_by: agent.agent_id))
      |> Enum.map(fn agent ->
        report = Map.get(inventory.reports, agent.agent_id, %{})

        users =
          Enum.map(Map.get(report, "users", []), fn user ->
            %{
              username: user["username"],
              uid: user["uid"],
              signing_access: user["signing_access"],
              lookup_access: user["lookup_access"],
              unambiguous: user["unambiguous"]
            }
          end)

        agent
        |> Map.take([:agent_id, :name, :status, :runtime_capabilities])
        |> Map.put(:ssh_users, users)
        |> Map.put(:ssh_inventory_seen_at, report["seen_at"])
      end)

    inventory
    |> Map.delete(:reports)
    |> Map.put(:identities, inventory.identities)
    |> Map.put(:agents, agents)
    |> Map.put(:edges, Evaluator.edges(inventory))
  end

  defp change_batch!(inventory, changes, now)
       when is_list(changes) and length(changes) <= 500 do
    Enum.reduce(changes, inventory, fn change, current ->
      case change(current, change, now) do
        {:ok, next} -> next
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  defp change_batch!(_, _, _), do: Repo.rollback(:invalid_change)

  defp change(inventory, %{"op" => "group_upsert", "name" => name} = attrs, _)
       when is_binary(name) and byte_size(name) in 1..100 do
    id = attrs["id"] || Ecto.UUID.generate()
    existing = Enum.find(inventory.groups, &(&1.id == id))
    kind = if existing, do: existing.kind, else: attrs["kind"]

    if valid_id?(id) and kind in ["host", "identity"] and not String.contains?(name, <<0>>) do
      group = existing || normalize_group(%{id: id, kind: kind})
      {:ok, put_record(inventory, :groups, Map.put(group, :name, name))}
    else
      {:error, :invalid_change}
    end
  end

  defp change(inventory, %{"op" => "group_members", "group_id" => id, "member_ids" => ids}, _)
       when is_list(ids) and length(ids) <= 10_000 do
    ids = ids |> Enum.uniq() |> Enum.sort()

    case Enum.find(inventory.groups, &(&1.id == id)) do
      %{kind: "host"} = group ->
        if Enum.all?(ids, &agent_exists?/1),
          do: {:ok, put_record(inventory, :groups, %{group | agent_ids: ids})},
          else: {:error, :invalid_change}

      %{kind: "identity"} = group ->
        known = MapSet.new(inventory.identities, & &1.id)

        if Enum.all?(ids, &MapSet.member?(known, &1)),
          do: {:ok, put_record(inventory, :groups, %{group | identity_ids: ids})},
          else: {:error, :invalid_change}

      _ ->
        {:error, :invalid_change}
    end
  end

  defp change(inventory, %{"op" => "group_delete", "id" => id}, _) do
    used =
      Enum.any?(
        inventory.rules,
        &((&1.source_kind == "identity_group" and &1.source_id == id) or
            (&1.destination_kind == "host_group" and &1.destination_id == id))
      )

    if used,
      do: {:error, :group_in_use},
      else: {:ok, %{inventory | groups: Enum.reject(inventory.groups, &(&1.id == id))}}
  end

  defp change(
         inventory,
         %{
           "op" => "endpoint_upsert",
           "agent_id" => agent_id,
           "aliases" => aliases,
           "host_keys" => keys
         } = attrs,
         _
       ) do
    with true <- agent_exists?(agent_id),
         true <- is_integer(attrs["port"]) and attrs["port"] in 1..65_535,
         true <- is_boolean(attrs["approved"]),
         {:ok, aliases} <- aliases(aliases),
         {:ok, keys} <- public_keys(keys),
         false <-
           Enum.any?(inventory.endpoints, fn endpoint ->
             endpoint.agent_id != agent_id and endpoint.port == attrs["port"] and
               Enum.any?(aliases, &(&1 in endpoint.aliases))
           end) do
      endpoint = %{
        agent_id: agent_id,
        aliases: aliases,
        port: attrs["port"],
        host_keys: keys,
        approved: attrs["approved"],
        candidate_host_keys: []
      }

      {:ok, put_record(inventory, :endpoints, endpoint, :agent_id)}
    else
      true -> {:error, :endpoint_conflict}
      _ -> {:error, :invalid_change}
    end
  end

  defp change(inventory, %{"op" => "endpoint_delete"} = attrs, _) do
    id = attrs["agent_id"] || attrs["id"]
    {:ok, %{inventory | endpoints: Enum.reject(inventory.endpoints, &(&1.agent_id == id))}}
  end

  defp change(inventory, %{"op" => "identity_approve", "id" => id}, now),
    do: identities(inventory, Identities.approve(inventory.identities, id, now))

  # Deleting an identity also removes its access rules and group memberships;
  # the UI hides retired identities, so they could not be removed there.
  defp change(inventory, %{"op" => "identity_delete", "id" => id}, _now) do
    rules = Enum.reject(inventory.rules, &(&1.source_kind == "identity" and &1.source_id == id))

    groups =
      Enum.map(inventory.groups, fn
        %{kind: "identity"} = group ->
          %{group | identity_ids: Enum.reject(group.identity_ids, &(&1 == id))}

        group ->
          group
      end)

    identities(
      %{inventory | rules: rules, groups: groups},
      Identities.delete(inventory.identities, id)
    )
  end

  defp change(inventory, %{"op" => "identity_revoke", "id" => id}, now),
    do: identities(inventory, Identities.revoke(inventory.identities, id, now))

  defp change(inventory, %{"op" => "identity_rotate", "id" => id}, now),
    do: identities(inventory, Identities.request_rotation(inventory.identities, id, now))

  defp change(inventory, %{"op" => "identity_rotation", "id" => id} = attrs, now)
       when is_map_key(attrs, "rotation_days"),
       do:
         identities(
           inventory,
           Identities.set_rotation(inventory.identities, id, attrs["rotation_days"], now)
         )

  defp change(
         inventory,
         %{"op" => "identity_external_add", "name" => name, "public_key" => key} = attrs,
         now
       ),
       do:
         identities(
           inventory,
           Identities.add_external(
             inventory.identities,
             name,
             key,
             Map.get(attrs, "rotation_days", Identities.default_rotation_days()),
             now
           )
         )

  defp change(
         inventory,
         %{"op" => "identity_external_replace", "id" => id, "public_key" => key},
         now
       ),
       do: identities(inventory, Identities.replace_external(inventory.identities, id, key, now))

  defp change(inventory, %{"op" => "rule_upsert"} = attrs, _) do
    rule = %{
      id: attrs["id"] || Ecto.UUID.generate(),
      effect: attrs["effect"],
      enabled: Map.get(attrs, "enabled", true),
      source_kind: attrs["source_kind"],
      source_id: attrs["source_id"],
      destination_kind: attrs["destination_kind"],
      destination_id: attrs["destination_id"],
      destination_user: attrs["destination_user"]
    }

    if valid_id?(rule.id) and rule.effect in ["allow", "deny"] and is_boolean(rule.enabled) and
         valid_user?(rule.destination_user) and
         rule.source_kind in ["identity", "identity_group"] and
         rule.destination_kind in ["endpoint", "host_group"] and
         selector_exists?(inventory, rule.source_kind, rule.source_id) and
         selector_exists?(inventory, rule.destination_kind, rule.destination_id) do
      {:ok, put_record(inventory, :rules, rule)}
    else
      {:error, :invalid_change}
    end
  end

  defp change(inventory, %{"op" => "rule_delete", "id" => id}, _),
    do: {:ok, %{inventory | rules: Enum.reject(inventory.rules, &(&1.id == id))}}

  defp change(_, _, _), do: {:error, :invalid_change}

  defp identities(inventory, {:ok, identities}), do: {:ok, %{inventory | identities: identities}}
  defp identities(_, {:error, reason}), do: {:error, reason}

  defp persist!(row, inventory, revision) do
    persist_inventory!(row, inventory, revision)
    persist_identities!(inventory.identities)
  end

  defp persist_inventory!(row, inventory, revision) do
    row
    |> Ecto.Changeset.change(
      Map.take(inventory, @inventory_fields)
      |> Map.put(:revision, revision)
    )
    |> Repo.update!(log: false)
  end

  defp persist_identities!(identities) do
    now = now()
    replace = (@identity_fields -- [:id]) ++ [:updated_at]
    ids = Enum.map(identities, & &1.id)
    # identity_delete removes pending/retired identities; their keys cascade.
    Repo.delete_all(from(i in Identity, where: i.id not in ^ids), log: false)

    for identity <- identities do
      row =
        identity
        |> Map.take(@identity_fields)
        |> Map.merge(%{inserted_at: now, updated_at: now})

      Repo.insert_all(Identity, [row],
        on_conflict: {:replace, replace},
        conflict_target: :id,
        log: false
      )

      key_ids = Enum.map(identity.keys, & &1.id)

      Repo.delete_all(
        from(k in IdentityKey, where: k.identity_id == ^identity.id and k.id not in ^key_ids),
        log: false
      )

      keys =
        for key <- identity.keys,
            do:
              key
              |> Map.take(@key_fields)
              |> Map.update!(:inserted_at, &DateTime.truncate(&1, :second))
              |> Map.put(:identity_id, identity.id)

      Repo.insert_all(IdentityKey, keys,
        on_conflict: {:replace, [:not_after]},
        conflict_target: :id,
        log: false
      )
    end

    :ok
  end

  defp put_record(inventory, field, record, key \\ :id),
    do:
      Map.update!(inventory, field, fn records ->
        records
        |> Enum.reject(&(Map.fetch!(&1, key) == Map.fetch!(record, key)))
        |> Kernel.++([record])
        |> Enum.sort_by(&Map.fetch!(&1, key))
      end)

  defp valid_user?(user),
    do: is_binary(user) and Regex.match?(~r/\A[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?\z/, user)

  defp valid_id?(id), do: is_binary(id) and Regex.match?(~r/\A[a-zA-Z0-9_-]{1,100}\z/, id)

  defp agent_exists?(id),
    do: is_binary(id) and Repo.exists?(from(a in Agent, where: a.agent_id == ^id))

  defp selector_exists?(inventory, "identity", id),
    do: Enum.any?(inventory.identities, &(&1.id == id))

  defp selector_exists?(inventory, "identity_group", id),
    do: Enum.any?(inventory.groups, &(&1.id == id and &1.kind == "identity"))

  defp selector_exists?(_, "endpoint", id), do: agent_exists?(id)

  defp selector_exists?(inventory, "host_group", id),
    do: Enum.any?(inventory.groups, &(&1.id == id and &1.kind == "host"))

  defp selector_exists?(_, _, _), do: false

  defp reported_users(users) when is_list(users) and length(users) <= 1024 do
    valid =
      Enum.all?(users, fn
        %{
          "username" => user,
          "uid" => uid,
          "signing_access" => signing,
          "lookup_access" => lookup,
          "unambiguous" => unambiguous
        } ->
          valid_user?(user) and is_integer(uid) and uid in 0..4_294_967_295 and
            is_boolean(signing) and is_boolean(lookup) and is_boolean(unambiguous)

        _ ->
          false
      end)

    names = for user <- users, do: user["username"]

    if valid and length(Enum.uniq(names)) == length(names),
      do:
        {:ok,
         Enum.map(users, &Map.take(&1, ~w(username uid signing_access lookup_access unambiguous)))
         |> Enum.sort_by(& &1["username"])},
      else: {:error, :invalid_users}
  end

  defp reported_users(_), do: {:error, :invalid_users}

  defp aliases(values) when is_list(values) and length(values) in 1..128 do
    Enum.reduce_while(values, {:ok, []}, fn value, {:ok, acc} ->
      case normalize_alias(value) do
        {:ok, host} -> {:cont, {:ok, [host | acc]}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, values} -> {:ok, Enum.uniq(values) |> Enum.sort()}
      error -> error
    end
  end

  defp aliases(_), do: {:error, :invalid_alias}

  defp normalize_alias(host) when is_binary(host) and byte_size(host) in 1..253 do
    host = host |> String.downcase() |> String.trim_trailing(".")

    if String.contains?(host, ":") do
      case :inet.parse_address(String.to_charlist(host)) do
        {:ok, address} -> {:ok, address |> :inet.ntoa() |> to_string()}
        _ -> {:error, :invalid_alias}
      end
    else
      if Regex.match?(~r/\A[a-z0-9][a-z0-9.-]*\z/, host) and not String.contains?(host, ".."),
        do: {:ok, host},
        else: {:error, :invalid_alias}
    end
  end

  defp normalize_alias(_), do: {:error, :invalid_alias}

  # OpenSSH's %H includes [host]:port for a nondefault port, including ORDER.
  # The embedded port must agree with %p before matching approved inventory.
  defp lookup_alias("[" <> rest, port) when byte_size(rest) <= 264 do
    with [host, token_port] <- String.split(rest, "]:", parts: 2),
         {^port, ""} <- Integer.parse(token_port) do
      normalize_alias(host)
    else
      _ -> {:error, :invalid_alias}
    end
  end

  defp lookup_alias(host, _port), do: normalize_alias(host)

  defp public_keys(keys) when is_list(keys) and length(keys) <= 32 do
    Enum.reduce_while(keys, {:ok, []}, fn line, {:ok, acc} ->
      case Key.decode_public(line) do
        {:ok, public} -> {:cont, {:ok, [public.public_line | acc]}}
        _ -> {:halt, {:error, :invalid_public_key}}
      end
    end)
    |> case do
      {:ok, keys} -> {:ok, Enum.uniq(keys) |> Enum.sort()}
      error -> error
    end
  end

  defp public_keys(_), do: {:error, :invalid_public_key}
  defp known_host_name(host, 22), do: host
  defp known_host_name(host, port), do: "[#{host}]:#{port}"

  defp scrub_changes(changes),
    do:
      Enum.map(
        changes,
        &Map.take(&1, @record_keys ++ ~w(op group_id member_ids public_key rotation_days))
      )

  defp decision_granted?({:ok, %{lines: lines}}), do: lines != []
  # An accepted or unchanged identity_report; rejections are {:error, reason}.
  defp decision_granted?({:ok, %{event: _}}), do: true

  defp decision_granted?({:ok, %{identities: identities}}) when is_list(identities),
    do: identities != []

  defp decision_granted?({:ok, _}), do: true
  defp decision_granted?(_), do: false

  defp audit_metadata(inventory, agent_id, operation, payload, result) do
    identity =
      if is_integer(payload["uid"]),
        do: Identities.find_agent_identity(inventory.identities, agent_id, payload["uid"])

    presented =
      case Key.decode_public(payload["public_key"] || payload["key"]) do
        {:ok, public} -> public
        _ -> nil
      end

    identity =
      identity ||
        (presented &&
           Enum.find(inventory.identities, fn i ->
             Enum.any?(i.keys, &(&1.public_key == presented.public_line))
           end))

    host =
      case lookup_alias(payload["host"], payload["port"]) do
        {:ok, host} -> host
        _ -> nil
      end

    port = is_integer(payload["port"]) and payload["port"] in 1..65_535 and payload["port"]

    endpoint =
      Enum.find(inventory.endpoints, fn endpoint ->
        operation == "known_hosts" and endpoint.port == port and host in endpoint.aliases
      end)

    %{}
    |> put_present(
      identity,
      &%{
        "source_identity_id" => &1.id,
        "source_identity_name" => &1.name,
        "source_origin" => &1.origin
      }
    )
    |> put_present(presented, &%{"key_fingerprint" => &1.fingerprint})
    |> put_present(valid_user?(payload["username"]) && payload["username"], &%{"username" => &1})
    |> put_present(
      is_integer(payload["uid"]) && payload["uid"] in 0..4_294_967_295 && payload["uid"],
      &%{"uid" => &1}
    )
    |> put_present(
      is_integer(payload["generation"]) && payload["generation"],
      &%{"generation" => &1}
    )
    |> put_present(
      payload["reason"] in ["ORDER", "HOSTNAME", "ADDRESS"] && payload["reason"],
      &%{"reason" => &1}
    )
    |> put_present(host, &%{"host" => &1})
    |> put_present(port, &%{"port" => &1})
    |> put_present(
      endpoint,
      &%{
        "destination_agent_id" => &1.agent_id,
        "destination_port" => &1.port,
        "destination_alias" => host
      }
    )
    |> put_present(
      (operation == "authorized_keys" and valid_user?(payload["username"])) &&
        payload["username"],
      &%{"destination_agent_id" => agent_id, "destination_user" => &1}
    )
    |> put_present(report_event(result), & &1)
    |> put_present(match?({:error, _}, result) && elem(result, 1), &%{"error" => to_string(&1)})
  end

  defp report_event({:ok, %{event: :unchanged}}), do: %{"event" => "unchanged"}

  defp report_event({:ok, %{event: {event, id}}}),
    do: %{"event" => Atom.to_string(event), "source_identity_id" => id}

  defp report_event(_), do: nil

  defp put_present(metadata, value, _) when value in [nil, false], do: metadata
  defp put_present(metadata, value, fun), do: Map.merge(metadata, fun.(value))

  defp master_key do
    case SealState.get_master_key() do
      {:ok, key} -> {:ok, key}
      _ -> {:error, :sealed}
    end
  catch
    :exit, _ -> {:error, :sealed}
  end

  defp fresh_master_key(expected) do
    case master_key() do
      {:ok, ^expected} -> :ok
      _ -> {:error, :sealed}
    end
  end

  defp ensure_master_key!(expected) do
    case master_key() do
      {:ok, ^expected} -> :ok
      _ -> Repo.rollback(:sealed)
    end
  end

  defp audit!(operation, actor_type, actor_id, revision, granted, data) do
    case Audit.log_event(%{
           event_type: "ssh." <> operation,
           actor_type: actor_type,
           actor_id: actor_id,
           event_data: Map.put(data, :policy_revision, revision),
           access_granted: granted,
           response_time_ms: 0
         }) do
      {:ok, _} -> :ok
      _ -> Repo.rollback(:audit_unavailable)
    end
  rescue
    _ -> Repo.rollback(:audit_unavailable)
  catch
    :exit, _ -> Repo.rollback(:audit_unavailable)
  end
end
