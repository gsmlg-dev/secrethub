defmodule SecretHub.Core.SSH.Identities do
  @moduledoc """
  Pure SSH identity lifecycle over in-memory maps. Core never sees private keys:
  Agents report public keys per generation; operators add external public keys.

  Callers must pass `now` truncated to whole seconds: the `:utc_datetime`
  columns reject microseconds.
  """
  alias SecretHub.Shared.SSH.Key

  @grace_seconds 3 * 86_400
  @retain_expired_seconds 30 * 86_400
  @default_rotation_days 90

  def default_rotation_days, do: @default_rotation_days

  def valid_keys(identity, now), do: Enum.filter(identity.keys, &key_valid?(&1, now))

  def usable?(identity, now),
    do: identity.status == "active" and valid_keys(identity, now) != []

  def current_generation(identity),
    do: identity.keys |> Enum.map(& &1.generation) |> Enum.max(fn -> 0 end)

  def find_agent_identity(identities, agent_id, uid),
    do:
      Enum.find(
        identities,
        &(&1.origin == "agent" and &1.agent_id == agent_id and &1.local_uid == uid)
      )

  def report(identities, report, now) do
    with {:ok, public} <- Key.decode_public(report.public_key) do
      existing = find_agent_identity(identities, report.agent_id, report.uid)

      cond do
        existing && existing.local_username != report.username ->
          {:error, :account_changed}

        existing && existing.status == "retired" ->
          {:error, :retired}

        existing && same_key?(existing, report.generation, public) ->
          {:ok, identities, :unchanged}

        fingerprint_taken?(identities, public.fingerprint) ->
          {:error, :duplicate_key}

        is_nil(existing) and report.generation == 1 and is_nil(agent_name(identities, report)) ->
          {:error, :name_taken}

        is_nil(existing) and report.generation == 1 ->
          identity = %{
            id: Ecto.UUID.generate(),
            name: agent_name(identities, report),
            origin: "agent",
            agent_id: report.agent_id,
            local_username: report.username,
            local_uid: report.uid,
            status: "pending",
            rotation_days: @default_rotation_days,
            next_rotation_at: nil,
            requested_generation: 1,
            rotation_overdue: false,
            keys: [new_key(public, 1, now)]
          }

          {:ok, put(identities, identity), {:reported, identity.id}}

        is_nil(existing) ->
          {:error, :unexpected_generation}

        report.generation == existing.requested_generation and
            report.generation == current_generation(existing) + 1 ->
          rotated = supersede(existing, new_key(public, report.generation, now), now)
          {:ok, put(identities, rotated), {:rotated, rotated.id}}

        true ->
          {:error, :unexpected_generation}
      end
    else
      _ -> {:error, :invalid_public_key}
    end
  end

  defp agent_name(identities, report) do
    [report.agent_name, report.agent_id]
    |> Enum.map(&(report.username <> "@" <> &1))
    |> Enum.find(fn name -> not Enum.any?(identities, &(&1.name == name)) end)
  end

  def approve(identities, id, now) do
    update(identities, id, fn
      %{status: "pending"} = identity ->
        {:ok,
         %{
           identity
           | status: "active",
             next_rotation_at: next_rotation(identity.rotation_days, now)
         }}

      _ ->
        {:error, :invalid_change}
    end)
  end

  def revoke(identities, id, now) do
    update(identities, id, fn
      %{status: "retired"} ->
        {:error, :invalid_change}

      identity ->
        keys = Enum.map(identity.keys, &expire_by(&1, now))
        {:ok, %{identity | status: "retired", keys: keys, next_rotation_at: nil}}
    end)
  end

  @doc "Removes a pending or retired identity so the next generation-1 report starts fresh."
  def delete(identities, id) do
    case Enum.find(identities, &(&1.id == id)) do
      %{status: status} when status in ["pending", "retired"] ->
        {:ok, Enum.reject(identities, &(&1.id == id))}

      _ ->
        {:error, :invalid_change}
    end
  end

  def add_external(identities, name, public_key, rotation_days, now) do
    with true <-
           (valid_name?(name) and not Enum.any?(identities, &(&1.name == name))) ||
             {:error, :invalid_name},
         true <- valid_rotation?(rotation_days) || {:error, :invalid_rotation},
         {:ok, public} <- decode(public_key),
         false <- fingerprint_taken?(identities, public.fingerprint) && {:error, :duplicate_key} do
      identity = %{
        id: Ecto.UUID.generate(),
        name: name,
        origin: "external",
        agent_id: nil,
        local_username: nil,
        local_uid: nil,
        status: "active",
        rotation_days: rotation_days,
        next_rotation_at: next_rotation(rotation_days, now),
        requested_generation: 1,
        rotation_overdue: false,
        keys: [new_key(public, 1, now)]
      }

      {:ok, put(identities, identity)}
    end
  end

  def replace_external(identities, id, public_key, now) do
    with {:ok, public} <- decode(public_key),
         false <- fingerprint_taken?(identities, public.fingerprint) && {:error, :duplicate_key} do
      update(identities, id, fn
        %{origin: "external", status: "active"} = identity ->
          generation = current_generation(identity) + 1
          rotated = supersede(identity, new_key(public, generation, now), now)
          {:ok, %{rotated | requested_generation: generation, rotation_overdue: false}}

        _ ->
          {:error, :invalid_change}
      end)
    end
  end

  def set_rotation(identities, id, days, now) do
    if valid_rotation?(days) do
      update(identities, id, fn identity ->
        next = if identity.status == "active", do: next_rotation(days, now), else: nil

        overdue =
          identity.rotation_overdue and is_struct(next, DateTime) and
            DateTime.compare(next, now) != :gt

        {:ok,
         %{identity | rotation_days: days, next_rotation_at: next, rotation_overdue: overdue}}
      end)
    else
      {:error, :invalid_rotation}
    end
  end

  def request_rotation(identities, id, now) do
    update(identities, id, fn
      %{origin: "agent", status: "active"} = identity ->
        {:ok, request(identity, now)}

      _ ->
        {:error, :invalid_change}
    end)
  end

  @doc "Due rotations and pruning. Returns {identities, events}; events are empty when nothing changed."
  def schedule(identities, now) do
    {updated, events} =
      Enum.map_reduce(identities, [], fn identity, events ->
        {identity, events} = due(identity, now, events)
        prune(identity, now, events)
      end)

    {updated, Enum.reverse(events)}
  end

  defp due(%{status: "active", next_rotation_at: %DateTime{} = at} = identity, now, events) do
    cond do
      DateTime.compare(at, now) == :gt ->
        {identity, events}

      identity.origin == "agent" ->
        requested = request(identity, now)
        {requested, [{:rotation_requested, identity.id, requested.requested_generation} | events]}

      identity.rotation_overdue ->
        {identity, events}

      true ->
        {%{identity | rotation_overdue: true}, [{:rotation_overdue, identity.id} | events]}
    end
  end

  defp due(identity, _, events), do: {identity, events}

  defp prune(identity, now, events) do
    cutoff = DateTime.add(now, -@retain_expired_seconds)

    {expired, kept} =
      Enum.split_with(
        identity.keys,
        &(&1.not_after && DateTime.compare(&1.not_after, cutoff) == :lt)
      )

    if expired == [],
      do: {identity, events},
      else: {%{identity | keys: kept}, [{:keys_pruned, identity.id, length(expired)} | events]}
  end

  defp request(identity, now) do
    pending = identity.requested_generation > current_generation(identity)

    %{
      identity
      | requested_generation:
          if(pending, do: identity.requested_generation, else: current_generation(identity) + 1),
        next_rotation_at: next_rotation(identity.rotation_days, now)
    }
  end

  defp supersede(identity, key, now) do
    grace = now |> DateTime.add(@grace_seconds) |> DateTime.truncate(:second)

    keys =
      Enum.map(identity.keys, fn
        %{not_after: nil} = old -> %{old | not_after: grace}
        old -> old
      end)

    %{
      identity
      | keys: keys ++ [key],
        next_rotation_at: next_rotation(identity.rotation_days, now)
    }
  end

  defp same_key?(identity, generation, public),
    do:
      Enum.any?(
        identity.keys,
        &(&1.generation == generation and &1.fingerprint == public.fingerprint)
      )

  defp fingerprint_taken?(identities, fingerprint),
    do:
      Enum.any?(identities, fn identity ->
        Enum.any?(identity.keys, &(&1.fingerprint == fingerprint))
      end)

  defp new_key(public, generation, now),
    do: %{
      id: Ecto.UUID.generate(),
      generation: generation,
      public_key: public.public_line,
      fingerprint: public.fingerprint,
      not_after: nil,
      inserted_at: DateTime.truncate(now, :second)
    }

  defp expire_by(key, now) do
    now = DateTime.truncate(now, :second)

    if is_nil(key.not_after) or DateTime.compare(key.not_after, now) == :gt,
      do: %{key | not_after: now},
      else: key
  end

  defp key_valid?(%{not_after: nil}, _), do: true
  defp key_valid?(%{not_after: at}, now), do: DateTime.compare(at, now) == :gt

  defp next_rotation(nil, _), do: nil

  defp next_rotation(days, now),
    do: now |> DateTime.add(days * 86_400) |> DateTime.truncate(:second)

  defp valid_rotation?(nil), do: true
  defp valid_rotation?(days), do: is_integer(days) and days in 1..3650

  defp valid_name?(name),
    do: is_binary(name) and Regex.match?(~r/\A[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,99}\z/, name)

  defp decode(public_key) do
    case Key.decode_public(public_key) do
      {:ok, public} -> {:ok, public}
      _ -> {:error, :invalid_public_key}
    end
  end

  defp update(identities, id, fun) do
    case Enum.find(identities, &(&1.id == id)) do
      nil ->
        {:error, :invalid_change}

      identity ->
        with {:ok, updated} <- fun.(identity), do: {:ok, put(identities, updated)}
    end
  end

  defp put(identities, identity),
    do:
      identities
      |> Enum.reject(&(&1.id == identity.id))
      |> Kernel.++([identity])
      |> Enum.sort_by(& &1.id)
end
