defmodule SecretHub.CLI.Output do
  @moduledoc """
  Output formatting utilities for the CLI.

  Supports multiple output formats:
  - table (default) - ASCII table format
  - json - JSON output
  - yaml - YAML output
  """

  @doc """
  Formats data for output based on the specified format.
  """
  def format(data, opts \\ []) do
    format = Keyword.get(opts, :format, "table")

    case format do
      "json" -> format_json(data)
      "yaml" -> format_yaml(data)
      "table" -> format_table(data)
      _ -> {:error, "Unknown format: #{format}"}
    end
  end

  @doc """
  Formats data as JSON.
  """
  def format_json(data) do
    case Jason.encode(data, pretty: true) do
      {:ok, json} -> {:ok, json}
      {:error, reason} -> {:error, "JSON encoding failed: #{inspect(reason)}"}
    end
  end

  @doc """
  Formats data as YAML.
  """
  def format_yaml(data) do
    # Simple YAML-like format (basic implementation)
    yaml = to_yaml(data, 0)
    {:ok, yaml}
  end

  @doc """
  Formats data as an ASCII table.
  """
  def format_table(data) when is_list(data) and data != [] do
    # Extract headers from first item
    headers =
      data
      |> List.first()
      |> Map.keys()
      |> Enum.map(&to_string/1)

    # Extract rows
    rows =
      Enum.map(data, fn item ->
        Enum.map(headers, fn header ->
          value = Map.get(item, String.to_atom(header)) || Map.get(item, header)
          format_value(value)
        end)
      end)

    # Calculate column widths
    col_widths =
      Enum.zip(headers, List.duplicate([], length(headers)))
      |> Enum.map(fn {header, _} ->
        header_width = String.length(header)

        value_widths =
          Enum.map(rows, fn row ->
            col_index = Enum.find_index(headers, &(&1 == header))
            Enum.at(row, col_index) |> String.length()
          end)

        Enum.max([header_width | value_widths])
      end)

    # Build table
    separator = build_separator(col_widths)
    header_row = build_row(headers, col_widths)
    data_rows = Enum.map(rows, &build_row(&1, col_widths))

    table =
      [separator, header_row, separator] ++
        data_rows ++
        [separator]

    {:ok, Enum.join(table, "\n")}
  end

  def format_table(data) when is_map(data) do
    rows =
      Enum.map(data, fn {key, value} ->
        [to_string(key), format_value(value)]
      end)

    col_widths = [
      rows |> Enum.map(&String.length(Enum.at(&1, 0))) |> Enum.max(),
      rows |> Enum.map(&String.length(Enum.at(&1, 1))) |> Enum.max()
    ]

    separator = build_separator(col_widths)
    header_row = build_row(["Key", "Value"], col_widths)
    data_rows = Enum.map(rows, &build_row(&1, col_widths))

    table =
      [separator, header_row, separator] ++
        data_rows ++
        [separator]

    {:ok, Enum.join(table, "\n")}
  end

  def format_table(_data) do
    {:error, "Table format requires a list or map"}
  end

  @doc """
  Prints success message in green.
  """
  def success(message) do
    tagged = Owl.Data.tag(message, :green)
    IO.puts(Owl.Data.to_chardata(tagged))
  end

  @doc """
  Prints error message in red.
  """
  def error(message) do
    tagged = Owl.Data.tag("Error: #{message}", :red)
    IO.puts(:stderr, Owl.Data.to_chardata(tagged))
  end

  @doc """
  Prints warning message in yellow.
  """
  def warning(message) do
    tagged = Owl.Data.tag("Warning: #{message}", :yellow)
    IO.puts(Owl.Data.to_chardata(tagged))
  end

  @doc """
  Prints info message.
  """
  def info(message) do
    IO.puts(message)
  end

  ## Private Functions

  defp format_value(nil), do: ""
  defp format_value(value) when is_binary(value), do: value
  defp format_value(value) when is_atom(value), do: to_string(value)
  defp format_value(value) when is_number(value), do: to_string(value)
  defp format_value(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_value(value) when is_list(value), do: Enum.join(value, ", ")
  defp format_value(value) when is_map(value), do: inspect(value, limit: 50)
  defp format_value(value), do: inspect(value)

  defp build_separator(col_widths) do
    "+" <>
      Enum.map_join(col_widths, "+", &String.duplicate("-", &1 + 2)) <>
      "+"
  end

  defp build_row(values, col_widths) do
    "| " <>
      Enum.map_join(Enum.zip(values, col_widths), " | ", fn {value, width} ->
        String.pad_trailing(value, width)
      end) <>
      " |"
  end

  defp to_yaml(data, indent) when is_map(data) do
    spacing = String.duplicate("  ", indent)

    Enum.map_join(data, "\n", fn {key, value} ->
      "#{spacing}#{key}:\n#{to_yaml(value, indent + 1)}"
    end)
  end

  defp to_yaml(data, indent) when is_list(data) do
    spacing = String.duplicate("  ", indent)

    Enum.map_join(data, "\n", fn item ->
      "#{spacing}- #{to_yaml(item, indent + 1)}"
    end)
  end

  defp to_yaml(data, indent) do
    spacing = String.duplicate("  ", indent)
    "#{spacing}#{format_value(data)}"
  end
end
