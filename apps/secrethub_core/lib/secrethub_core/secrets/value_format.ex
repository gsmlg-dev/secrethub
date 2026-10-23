defmodule SecretHub.Core.Secrets.ValueFormat do
  @moduledoc false

  def validate(%{"value" => value} = data, "text")
      when map_size(data) == 1 and is_binary(value),
      do: :ok

  def validate(_data, "text"), do: {:error, :invalid_text_value}
  def validate(data, "structured") when is_map(data), do: :ok
  def validate(_data, "structured"), do: {:error, :invalid_structured_value}
  def validate(data, nil) when is_map(data), do: :ok
  def validate(_data, nil), do: {:error, :invalid_structured_value}
  def validate(_data, _format), do: {:error, :invalid_value_format}

  def descriptors(data) do
    data
    |> Enum.sort_by(fn {key, _value} -> key end)
    |> Enum.map(fn {key, value} -> %{key: key, kind: kind(value)} end)
  end

  def apply_field_operations(data, operations) when is_map(data) and is_list(operations) do
    with {:ok, edits} <- validate_operations(data, operations),
         sources = for({source, _target} <- edits, not is_nil(source), do: source),
         :ok <- unique(sources, :duplicate_field_source) do
      retained = Map.drop(data, sources) |> Map.to_list()
      replacements = for {_source, {name, value}} <- edits, do: {name, value}
      fields = retained ++ replacements

      with :ok <- unique(Enum.map(fields, &elem(&1, 0)), :duplicate_field_name) do
        {:ok, Map.new(fields)}
      end
    end
  end

  def apply_field_operations(_data, _operations), do: {:error, :invalid_field_operations}

  defp validate_operations(data, operations) do
    operations
    |> Enum.with_index(1)
    |> Enum.reduce_while({:ok, []}, fn {operation, index}, {:ok, edits} ->
      case validate_operation(data, operation) do
        {:ok, edit} -> {:cont, {:ok, [edit | edits]}}
        :error -> {:halt, {:error, {:invalid_field_operation, index}}}
      end
    end)
  end

  defp validate_operation(data, %{"original_key" => source, "operation" => "remove"}) do
    if Map.has_key?(data, source), do: {:ok, {source, nil}}, else: :error
  end

  defp validate_operation(data, %{"original_key" => source, "name" => name, "operation" => "keep"}) do
    if Map.has_key?(data, source) and valid_name?(source, name),
      do: {:ok, {source, {name, Map.fetch!(data, source)}}},
      else: :error
  end

  defp validate_operation(
         data,
         %{"name" => name, "operation" => "replace", "value" => value} = operation
       )
       when is_binary(value) do
    source = Map.get(operation, "original_key")
    valid_source = not Map.has_key?(operation, "original_key") or Map.has_key?(data, source)

    if valid_source and valid_name?(source, name),
      do: {:ok, {source, {name, value}}},
      else: :error
  end

  defp validate_operation(_data, _operation), do: :error

  defp valid_name?(source, name) when is_binary(name),
    do: source == name or String.trim(name) != ""

  defp valid_name?(_source, _name), do: false

  defp unique(names, reason) do
    if length(names) == MapSet.size(MapSet.new(names)), do: :ok, else: {:error, reason}
  end

  defp kind(nil), do: "null"
  defp kind(value) when is_binary(value), do: "string"
  defp kind(value) when is_boolean(value), do: "boolean"
  defp kind(value) when is_number(value), do: "number"
  defp kind(value) when is_list(value), do: "array"
  defp kind(value) when is_map(value), do: "object"
end
