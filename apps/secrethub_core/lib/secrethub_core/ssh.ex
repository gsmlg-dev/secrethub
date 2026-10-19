defmodule SecretHub.Core.SSH do
  @moduledoc "Revisioned SSH management and freshly authorized machine runtime views."
  import Ecto.Query
  alias SecretHub.Core.{Agents, Audit, Repo}
  alias SecretHub.Core.SSH.Evaluator
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Encryption
  alias SecretHub.Shared.Schemas.{Agent, Certificate}
  alias SecretHub.Shared.Schemas.SSH.{Identity, Inventory}
  alias SecretHub.Shared.SSH.Key

  @identity_fields [
    :id,
    :agent_id,
    :username,
    :uid,
    :public_key,
    :fingerprint,
    :key_revision,
    :active
  ]
  @inventory_fields [:groups, :endpoints, :rules, :reports]
  @record_keys ~w(id name agent_ids agent_id aliases port host_keys approved enabled effect source_kind source_id source_user destination_kind destination_id destination_user candidate_host_keys)

  def snapshot do
    case Repo.transaction(fn -> public_snapshot(load_inventory(lock_inventory("FOR SHARE"))) end) do
      {:ok, value} -> value
      {:error, reason} -> {:error, reason}
    end
  end

  def preview(changes, expected_revision) do
    with {:ok, master_key} <- master_key() do
      Repo.transaction(fn ->
        row = lock_inventory("FOR UPDATE")
        check_revision!(row, expected_revision)
        before = load_inventory(row)
        after_inventory = change_batch!(before, changes, master_key)
        diff = Evaluator.diff(before, after_inventory)
        Map.merge(diff, %{revision: row.revision, changes: scrub_changes(changes)})
      end)
    end
  end

  def apply_changes(changes, expected_revision) do
    with {:ok, master_key} <- master_key() do
      result =
        Repo.transaction(fn ->
          row = lock_inventory("FOR UPDATE")
          check_revision!(row, expected_revision)
          inventory = change_batch!(load_inventory(row), changes, master_key)
          revision = row.revision + 1

          audit!("configuration", "operator", "management", revision, true, %{
            changes: scrub_changes(changes),
            identities:
              Enum.map(
                inventory.identities,
                &Map.take(&1, [
                  :id,
                  :agent_id,
                  :username,
                  :uid,
                  :fingerprint,
                  :key_revision,
                  :active
                ])
              )
          })

          ensure_master_key!(master_key)
          persist!(row, inventory, revision)
          public_snapshot(%{inventory | revision: revision})
        end)

      case result do
        {:ok, snapshot} ->
          if Process.whereis(SecretHub.Web.PubSub),
            do:
              Phoenix.PubSub.broadcast(
                SecretHub.Web.PubSub,
                "ssh:policy",
                {:ssh_policy_changed, snapshot.revision}
              )

          {:ok, snapshot}

        error ->
          error
      end
    end
  end

  def runtime_operation(%{agent_id: agent_id, certificate_id: certificate_id}, operation, payload)
      when is_binary(agent_id) and is_binary(operation) and is_map(payload) do
    with {:ok, master_key} <- master_key() do
      Repo.transaction(fn ->
        inventory =
          load_inventory(
            lock_inventory(if(operation == "inventory", do: "FOR UPDATE", else: "FOR SHARE"))
          )

        lock_machine(agent_id)

        result =
          with :ok <- Agents.authorize_runtime(agent_id, certificate_id),
               :ok <- current_certificate_start(certificate_id),
               :ok <- capability(agent_id, operation) do
            runtime_view(inventory, agent_id, operation, payload, master_key)
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
            if operation == "inventory",
              do: result,
              else:
                runtime_view(
                  load_inventory(lock_inventory("FOR SHARE")),
                  agent_id,
                  operation,
                  payload,
                  master_key
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

        if operation == "inventory",
          do: persist_candidates(inventory, agent_id, final),
          else: final
      end)
      |> case do
        {:ok, {:ok, %{unchanged: true, revision: revision}}} when operation == "inventory" ->
          {:ok, %{revision: revision}}

        {:ok, {:ok, %{revision: revision}} = result} when operation == "inventory" ->
          if Process.whereis(SecretHub.Web.PubSub),
            do:
              Phoenix.PubSub.broadcast(
                SecretHub.Web.PubSub,
                "ssh:policy",
                {:ssh_policy_changed, revision}
              )

          result

        {:ok, result} ->
          result

        error ->
          error
      end
    end
  end

  def runtime_operation(_, _, _), do: {:error, :invalid_identity}

  defp runtime_view(inventory, agent_id, "identities", payload, _) do
    identities =
      source_identities(inventory, agent_id, payload)
      |> Enum.filter(&outgoing?(inventory, &1))
      |> Enum.map(&Map.take(&1, [:public_key, :key_revision]))

    {:ok, %{identities: identities, revision: inventory.revision}}
  end

  defp runtime_view(inventory, agent_id, "authorize_sign", payload, master_key) do
    with {:ok, public} <- Key.decode_public(payload["public_key"]),
         %Identity{} = identity <-
           Enum.find(
             source_identities(inventory, agent_id, payload),
             &(&1.public_key == public.public_line)
           ),
         true <- outgoing?(inventory, identity),
         {:ok, pem} <-
           Encryption.decrypt_from_blob(
             identity.private_key_encrypted,
             identity_encryption_key(master_key, identity)
           ) do
      {:ok,
       %{
         private_key: pem,
         public_key: identity.public_key,
         key_revision: identity.key_revision,
         revision: inventory.revision
       }}
    else
      _ -> {:error, :denied}
    end
  end

  defp runtime_view(inventory, agent_id, "authorized_keys", payload, _) do
    with true <- valid_user?(payload["username"]),
         {:ok, public} <- Key.decode_public(payload["key"]) do
      lines =
        for identity <- inventory.identities,
            identity.active and identity.public_key == public.public_line,
            live_agent?(identity.agent_id, "ssh_signing_v1"),
            approved_endpoint?(inventory, agent_id),
            Evaluator.decision(
              inventory,
              identity.agent_id,
              identity.username,
              agent_id,
              payload["username"]
            ).allowed,
            do: "no-agent-forwarding " <> identity.public_key

      {:ok, %{lines: Enum.uniq(lines), revision: inventory.revision}}
    else
      _ -> {:error, :invalid_request}
    end
  end

  defp runtime_view(inventory, agent_id, "known_hosts", payload, _) do
    with true <- payload["reason"] in ["ORDER", "HOSTNAME", "ADDRESS"],
         true <- is_integer(payload["port"]) and payload["port"] in 1..65_535,
         {:ok, host} <- lookup_alias(payload["host"], payload["port"]) do
      lines =
        for identity <- source_identities(inventory, agent_id, payload),
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

  defp runtime_view(inventory, agent_id, "inventory", payload, _) do
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
         unchanged: unchanged
       }}
    else
      _ -> {:error, :invalid_request}
    end
  end

  defp runtime_view(_, _, _, _, _), do: {:error, :unsupported_operation}

  defp persist_candidates(_, _, {:ok, %{unchanged: true, revision: revision}}),
    do: {:ok, %{unchanged: true, revision: revision}}

  defp persist_candidates(
         inventory,
         agent_id,
         {:ok, %{candidate_host_keys: keys, users: users, revision: revision}}
       ) do
    endpoint =
      Enum.find(inventory.endpoints, &(&1.agent_id == agent_id)) ||
        %{agent_id: agent_id, aliases: [], port: 22, host_keys: [], approved: false}

    updated =
      put_record(inventory, :endpoints, Map.put(endpoint, :candidate_host_keys, keys), :agent_id)

    report = %{"users" => users, "seen_at" => DateTime.to_iso8601(DateTime.utc_now())}
    updated = %{updated | reports: Map.put(updated.reports, agent_id, report)}
    persist!(Repo.get!(Inventory, 1), updated, revision)
    {:ok, %{revision: revision}}
  end

  defp persist_candidates(_, _, result), do: result

  defp source_identities(inventory, agent_id, payload) do
    Enum.filter(inventory.identities, fn identity ->
      is_integer(payload["uid"]) and valid_user?(payload["username"]) and
        identity.active and identity.agent_id == agent_id and
        identity.username == payload["username"] and identity.uid == payload["uid"]
    end)
  end

  defp outgoing?(inventory, identity),
    do:
      Enum.any?(
        inventory.endpoints,
        &(approved_endpoint?(inventory, &1.agent_id) and
            outgoing_to?(inventory, identity, &1.agent_id))
      )

  defp outgoing_to?(inventory, identity, destination) do
    Enum.any?(inventory.rules, fn rule ->
      Evaluator.decision(
        inventory,
        identity.agent_id,
        identity.username,
        destination,
        rule.destination_user
      ).allowed
    end)
  end

  defp approved_endpoint?(inventory, agent_id),
    do:
      Enum.any?(
        inventory.endpoints,
        &(&1.agent_id == agent_id and &1.approved and &1.host_keys != [])
      ) and live_agent?(agent_id, "ssh_lookup_v1")

  defp live_agent?(agent_id, capability) do
    case lock_machine(agent_id) do
      %Agent{certificate_id: certificate_id, runtime_capabilities: capabilities} ->
        capability in capabilities and Agents.authorize_runtime(agent_id, certificate_id) == :ok and
          current_certificate_start(certificate_id) == :ok

      _ ->
        false
    end
  end

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
        "inventory" -> ["ssh_signing_v1", "ssh_lookup_v1"]
        operation when operation in ["identities", "authorize_sign"] -> ["ssh_signing_v1"]
        _ -> ["ssh_lookup_v1"]
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
      groups: records(row.groups),
      endpoints: records(row.endpoints),
      rules: records(row.rules),
      reports: row.reports,
      identities: Repo.all(from(i in Identity, order_by: i.id))
    }
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
    |> Map.put(:identities, Enum.map(inventory.identities, &Map.take(&1, @identity_fields)))
    |> Map.put(:agents, agents)
    |> Map.put(:edges, Evaluator.edges(inventory))
  end

  defp change_batch!(inventory, changes, master_key)
       when is_list(changes) and length(changes) <= 500 do
    Enum.reduce(changes, inventory, fn change, current ->
      case change(current, change, master_key) do
        {:ok, next} -> next
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  defp change_batch!(_, _, _), do: Repo.rollback(:invalid_change)

  defp change(inventory, %{"op" => "group_upsert", "name" => name} = attrs, _)
       when is_binary(name) and byte_size(name) in 1..100 do
    id = attrs["id"] || Ecto.UUID.generate()

    if valid_id?(id) and not String.contains?(name, <<0>>) do
      group = Enum.find(inventory.groups, &(&1.id == id)) || %{id: id, agent_ids: []}
      {:ok, put_record(inventory, :groups, Map.put(group, :name, name))}
    else
      {:error, :invalid_change}
    end
  end

  defp change(inventory, %{"op" => "group_members", "group_id" => id, "agent_ids" => ids}, _)
       when is_list(ids) and length(ids) <= 10_000 do
    with %{id: ^id} = group <- Enum.find(inventory.groups, &(&1.id == id)),
         true <- Enum.all?(ids, &agent_exists?/1) do
      {:ok, put_record(inventory, :groups, %{group | agent_ids: Enum.uniq(ids) |> Enum.sort()})}
    else
      _ -> {:error, :invalid_change}
    end
  end

  defp change(inventory, %{"op" => "group_delete", "id" => id}, _) do
    used =
      Enum.any?(
        inventory.rules,
        &((&1.source_kind == "group" and &1.source_id == id) or
            (&1.destination_kind == "group" and &1.destination_id == id))
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

  defp change(
         inventory,
         %{
           "op" => "identity_upsert",
           "agent_id" => agent_id,
           "username" => username,
           "uid" => uid
         } = attrs,
         master_key
       ) do
    with true <-
           agent_exists?(agent_id) and valid_user?(username) and is_integer(uid) and
             uid in 0..4_294_967_295,
         {:ok, key} <- provisioning_key(attrs) do
      old =
        Enum.find(inventory.identities, &(&1.agent_id == agent_id and &1.username == username))

      identity =
        old || %Identity{id: Ecto.UUID.generate(), agent_id: agent_id, username: username}

      duplicate =
        Enum.any?(
          inventory.identities,
          &(&1.id != identity.id and
              ((&1.agent_id == agent_id and &1.uid == uid) or
                 &1.fingerprint == key.public.fingerprint))
        )

      if duplicate do
        {:error, :duplicate_identity}
      else
        identity = %{
          identity
          | uid: uid,
            public_key: key.public.public_line,
            fingerprint: key.public.fingerprint,
            active: true,
            key_revision: if(old, do: old.key_revision + 1, else: 1)
        }

        with {:ok, ciphertext} <-
               Encryption.encrypt_to_blob(
                 key.private_pem,
                 identity_encryption_key(master_key, identity)
               ) do
          {:ok,
           put_record(inventory, :identities, %{identity | private_key_encrypted: ciphertext})}
        end
      end
    else
      _ -> {:error, :invalid_change}
    end
  end

  defp change(inventory, %{"op" => "identity_revoke", "id" => id}, _) do
    case Enum.find(inventory.identities, &(&1.id == id)) do
      nil ->
        {:error, :invalid_change}

      identity ->
        {:ok,
         put_record(inventory, :identities, %{
           identity
           | active: false,
             key_revision: identity.key_revision + 1
         })}
    end
  end

  defp change(inventory, %{"op" => "rule_upsert"} = attrs, _) do
    rule = %{
      id: attrs["id"] || Ecto.UUID.generate(),
      effect: attrs["effect"],
      enabled: Map.get(attrs, "enabled", true),
      source_kind: attrs["source_kind"],
      source_id: attrs["source_id"],
      source_user: attrs["source_user"],
      destination_kind: attrs["destination_kind"],
      destination_id: attrs["destination_id"],
      destination_user: attrs["destination_user"]
    }

    if valid_id?(rule.id) and rule.effect in ["allow", "deny"] and is_boolean(rule.enabled) and
         valid_user?(rule.source_user) and valid_user?(rule.destination_user) and
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

  defp persist!(row, inventory, revision) do
    row
    |> Ecto.Changeset.change(
      Map.take(inventory, @inventory_fields)
      |> Map.put(:revision, revision)
    )
    |> Repo.update!(log: false)

    for identity <- inventory.identities do
      attrs = Map.take(identity, @identity_fields ++ [:private_key_encrypted])
      existing = Repo.get(Identity, identity.id) || %Identity{id: identity.id}

      case existing |> Ecto.Changeset.change(attrs) |> Repo.insert_or_update(log: false) do
        {:ok, _} -> :ok
        {:error, _} -> Repo.rollback(:invalid_change)
      end
    end
  end

  defp put_record(inventory, field, record, key \\ :id),
    do:
      Map.update!(inventory, field, fn records ->
        records
        |> Enum.reject(&(Map.fetch!(&1, key) == Map.fetch!(record, key)))
        |> Kernel.++([record])
        |> Enum.sort_by(&Map.fetch!(&1, key))
      end)

  defp provisioning_key(%{"private_key" => pem}), do: Key.import_private(pem)
  defp provisioning_key(attrs), do: Key.generate(Map.get(attrs, "algorithm", "ed25519"))

  defp identity_encryption_key(master_key, identity),
    do:
      :crypto.mac(
        :hmac,
        :sha256,
        master_key,
        "secrethub:ssh:identity:" <>
          identity.id <> ":" <> Integer.to_string(identity.key_revision)
      )

  defp valid_user?(user),
    do: is_binary(user) and Regex.match?(~r/\A[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?\z/, user)

  defp valid_id?(id), do: is_binary(id) and Regex.match?(~r/\A[a-zA-Z0-9_-]{1,100}\z/, id)

  defp agent_exists?(id),
    do: is_binary(id) and Repo.exists?(from(a in Agent, where: a.agent_id == ^id))

  defp selector_exists?(_, "agent", id), do: agent_exists?(id)
  defp selector_exists?(inventory, "group", id), do: Enum.any?(inventory.groups, &(&1.id == id))
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
    do: Enum.map(changes, &Map.take(&1, @record_keys ++ ~w(op group_id username uid algorithm)))

  defp decision_granted?({:ok, %{lines: lines}}), do: lines != []
  defp decision_granted?({:ok, %{identities: identities}}), do: identities != []
  defp decision_granted?({:ok, _}), do: true
  defp decision_granted?(_), do: false

  defp audit_metadata(inventory, agent_id, operation, payload, result) do
    identity =
      Enum.find(
        inventory.identities,
        &(&1.agent_id == agent_id and &1.username == payload["username"] and
            &1.uid == payload["uid"])
      )

    metadata =
      if identity,
        do: %{
          "source_identity_id" => identity.id,
          "source_agent_id" => identity.agent_id,
          "source_user" => identity.username,
          "source_uid" => identity.uid,
          "key_fingerprint" => identity.fingerprint
        },
        else: %{}

    metadata =
      if operation == "authorized_keys" and valid_user?(payload["username"]),
        do:
          Map.merge(metadata, %{
            "destination_agent_id" => agent_id,
            "destination_user" => payload["username"]
          }),
        else: metadata

    metadata =
      if valid_user?(payload["username"]),
        do: Map.put(metadata, "username", payload["username"]),
        else: metadata

    metadata =
      if is_integer(payload["uid"]) and payload["uid"] in 0..4_294_967_295,
        do: Map.put(metadata, "uid", payload["uid"]),
        else: metadata

    metadata =
      if payload["reason"] in ["ORDER", "HOSTNAME", "ADDRESS"],
        do: Map.put(metadata, "reason", payload["reason"]),
        else: metadata

    metadata =
      case lookup_alias(payload["host"], payload["port"]) do
        {:ok, host} -> Map.put(metadata, "host", host)
        _ -> metadata
      end

    metadata =
      if is_integer(payload["port"]) and payload["port"] in 1..65_535,
        do: Map.put(metadata, "port", payload["port"]),
        else: metadata

    metadata =
      case Enum.find(inventory.endpoints, fn endpoint ->
             operation == "known_hosts" and endpoint.port == metadata["port"] and
               metadata["host"] in endpoint.aliases
           end) do
        nil ->
          metadata

        endpoint ->
          Map.merge(metadata, %{
            "destination_agent_id" => endpoint.agent_id,
            "destination_port" => endpoint.port,
            "destination_alias" => metadata["host"]
          })
      end

    public =
      case result do
        {:ok, %{public_key: public}} -> public
        _ -> payload["public_key"] || payload["key"]
      end

    case Key.decode_public(public) do
      {:ok, public} ->
        metadata = Map.put(metadata, "key_fingerprint", public.fingerprint)

        case Enum.find(inventory.identities, &(&1.public_key == public.public_line)) do
          nil ->
            metadata

          identity ->
            Map.merge(metadata, %{
              "source_identity_id" => identity.id,
              "source_agent_id" => identity.agent_id,
              "source_user" => identity.username,
              "source_uid" => identity.uid
            })
        end

      _ ->
        metadata
    end
  end

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
