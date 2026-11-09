defmodule SecretHub.CLI.ExecResolver do
  @moduledoc """
  Resolver half of `secrethub exec` (`secrethub __exec-resolve`).

  The native `secrethub-exec` launcher runs this resolver with a private pipe
  as stdout. The resolver fetches every mapped credential through the local
  Agent before anything is written, validates names and values, and emits
  `NAME=VALUE\\0` records. Any failure writes nothing to stdout and exits
  non-zero; the launcher then never starts the target. Values never appear in
  diagnostics.

  Map file:

      {"env": {"DB_PASSWORD": {"entry_id": "<uuid>", "field": "value"},
               "DB_USER": {"entry_id": "<uuid>", "field": "username", "allow_empty": false}}}
  """
  alias SecretHub.CLI.AgentClient

  @name ~r/\A[A-Za-z_][A-Za-z0-9_]{0,254}\z/
  @uuid ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/
  @max_bytes 1_048_576
  @max_entries 128

  @doc "Returns `{:ok, records_binary}` or `{:error, message}`."
  def resolve(map_json, opts \\ []) do
    client = Keyword.get(opts, :client, &AgentClient.credential/3)

    with {:ok, mapping} <- decode(map_json),
         {:ok, values} <- fetch_all(mapping, client, opts) do
      records = Enum.map_join(values, fn {name, value} -> name <> "=" <> value <> <<0>> end)

      if byte_size(records) <= @max_bytes,
        do: {:ok, records},
        else: {:error, "resolved environment exceeds #{@max_bytes} bytes"}
    end
  end

  defp decode(json) do
    case Jason.decode(json) do
      {:ok, %{"env" => env} = map} when is_map(env) and map_size(map) == 1 ->
        validate_mapping(env)

      _ ->
        {:error, "map must be a JSON object of the form {\"env\": {...}}"}
    end
  end

  defp validate_mapping(env) when map_size(env) > @max_entries,
    do: {:error, "map has more than #{@max_entries} entries"}

  defp validate_mapping(env) do
    env
    |> Enum.sort()
    |> Enum.reduce_while({:ok, []}, fn {name, spec}, {:ok, acc} ->
      case entry(name, spec) do
        {:ok, entry} -> {:cont, {:ok, [entry | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, entries} -> {:ok, Enum.reverse(entries)}
      error -> error
    end
  end

  defp entry(name, %{"entry_id" => id, "field" => field} = spec)
       when is_binary(name) and is_binary(id) and field in ["value", "username"] do
    allowed = Map.keys(spec) -- ["entry_id", "field", "allow_empty"]
    allow_empty = Map.get(spec, "allow_empty", false)

    cond do
      not Regex.match?(@name, name) ->
        {:error, "invalid environment name #{inspect(name)}"}

      not Regex.match?(@uuid, id) ->
        {:error, "#{name}: entry_id must be a credential binding UUID"}

      allowed != [] or not is_boolean(allow_empty) ->
        {:error, "#{name}: unsupported mapping keys"}

      true ->
        {:ok, %{name: name, entry_id: id, field: field, allow_empty: allow_empty}}
    end
  end

  # Non-scalar or embedded production values are not accepted in the map.
  defp entry(name, _spec), do: {:error, "#{inspect(name)}: mapping requires entry_id and field"}

  defp fetch_all(entries, client, opts) do
    Enum.reduce_while(entries, {:ok, []}, fn entry, {:ok, acc} ->
      case fetch(entry, client, opts) do
        {:ok, value} -> {:cont, {:ok, [{entry.name, value} | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, values} -> {:ok, Enum.reverse(values)}
      error -> error
    end
  end

  defp fetch(entry, client, opts) do
    case client.("credential_get", %{"entry_id" => entry.entry_id}, opts) do
      {:ok, data} -> field(entry, Map.get(data, entry.field))
      {:error, code} -> {:error, "#{entry.name}: credential unavailable (#{code})"}
    end
  end

  defp field(entry, value) when is_binary(value) do
    cond do
      String.contains?(value, <<0>>) -> {:error, "#{entry.name}: value contains NUL"}
      value == "" and not entry.allow_empty -> {:error, "#{entry.name}: empty value not allowed"}
      true -> {:ok, value}
    end
  end

  defp field(entry, _), do: {:error, "#{entry.name}: field #{entry.field} is missing"}
end
