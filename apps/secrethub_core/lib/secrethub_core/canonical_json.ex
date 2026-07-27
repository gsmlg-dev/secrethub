defmodule SecretHub.Core.CanonicalJSON do
  @moduledoc """
  Encodes JSON values with recursively sorted, string-normalized object keys.

  Object key collisions introduced by string normalization are rejected.
  """

  @spec encode!(term()) :: String.t()
  def encode!(value) do
    value
    |> canonicalize()
    |> Jason.encode!()
  end

  defp canonicalize(%DateTime{} = datetime), do: DateTime.to_iso8601(datetime)

  defp canonicalize(value) when is_map(value) do
    pairs =
      Enum.map(value, fn {key, nested_value} ->
        {normalize_key!(key), nested_value}
      end)

    reject_duplicate_keys!(pairs)

    pairs
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.map(fn {key, nested_value} -> {key, canonicalize(nested_value)} end)
    |> Jason.OrderedObject.new()
  end

  defp canonicalize(value) when is_list(value), do: Enum.map(value, &canonicalize/1)

  defp canonicalize(value)
       when is_binary(value) or is_integer(value) or is_float(value) or is_boolean(value) or
              is_nil(value),
       do: value

  defp canonicalize(value) do
    raise ArgumentError, "unsupported canonical JSON value: #{inspect(value)}"
  end

  defp normalize_key!(key) when is_binary(key), do: key
  defp normalize_key!(key) when is_atom(key), do: Atom.to_string(key)

  defp normalize_key!(key) do
    raise ArgumentError,
          "canonical JSON object keys must be atoms or strings, got: #{inspect(key)}"
  end

  defp reject_duplicate_keys!(pairs) do
    pairs
    |> Enum.group_by(&elem(&1, 0))
    |> Enum.find(fn {_key, entries} -> length(entries) > 1 end)
    |> case do
      nil -> :ok
      {key, _entries} -> raise ArgumentError, ~s(duplicate canonical JSON key "#{key}")
    end
  end
end
