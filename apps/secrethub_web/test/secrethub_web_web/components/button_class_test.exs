defmodule SecretHub.Web.ButtonClassTest do
  use ExUnit.Case, async: true

  @source_root Path.expand("../../../lib/secret_hub/web", __DIR__)
  @button_like_tag ~r/<(?:button\b|\.link\b)(?:(?!>).)*>/s
  @form_control_tag ~r/<(input|select)\b(?:(?!>).)*>/s
  @input_exempt_types ~w(hidden checkbox radio file)

  test "button variant classes include the base btn class" do
    failures =
      for path <- source_files(),
          source = File.read!(path),
          {tag, offset} <- button_like_tags(source),
          class = class_value(tag),
          missing_base_btn?(class) do
        "#{Path.relative_to_cwd(path)}:#{line_number(source, offset)} has class=#{inspect(class)}"
      end

    assert failures == [],
           "button-like elements with btn-* variants must include the base btn class:\n" <>
             Enum.join(failures, "\n")
  end

  test "form control elements include their base component class" do
    failures =
      for path <- source_files(),
          source = File.read!(path),
          {tag_name, tag, offset} <- form_control_tags(source),
          class_attribute_source(tag),
          missing_form_control_base?(tag_name, tag) do
        class = class_attribute_source(tag) || "<missing>"

        "#{Path.relative_to_cwd(path)}:#{line_number(source, offset)} <#{tag_name}> has class=#{inspect(class)}"
      end

    assert failures == [],
           "form controls must include their base component class:\n" <>
             Enum.join(failures, "\n")
  end

  defp source_files do
    for extension <- ~w(ex heex),
        path <- Path.wildcard(Path.join(@source_root, "**/*.#{extension}")) do
      path
    end
  end

  defp button_like_tags(source) do
    for [{offset, length}] <- Regex.scan(@button_like_tag, source, return: :index) do
      {binary_part(source, offset, length), offset}
    end
  end

  defp form_control_tags(source) do
    for [{offset, length}, {tag_offset, tag_length}] <-
          Regex.scan(@form_control_tag, source, return: :index) do
      tag = binary_part(source, offset, length)
      tag_name = binary_part(source, tag_offset, tag_length)

      {tag_name, tag, offset}
    end
  end

  defp class_value(tag) do
    case Regex.run(~r/\bclass\s*=\s*"([^"]*)"/s, tag, capture: :all_but_first) do
      [class] ->
        class

      nil ->
        case Regex.run(~r/\bclass\s*=\s*\{\s*"([^"]*)"/s, tag, capture: :all_but_first) do
          [class] -> class
          nil -> nil
        end
    end
  end

  defp class_attribute_source(tag) do
    case Regex.run(~r/\bclass\s*=\s*"([^"]*)"/s, tag, capture: :all_but_first) do
      [class] ->
        class

      nil ->
        case Regex.run(~r/\bclass\s*=\s*\{(.+?)\}/s, tag, capture: :all_but_first) do
          [class] -> class
          nil -> nil
        end
    end
  end

  defp missing_base_btn?(class) do
    tokens = String.split(class, ~r/\s+/, trim: true)

    "btn" not in tokens and Enum.any?(tokens, &String.starts_with?(&1, "btn-"))
  end

  defp missing_form_control_base?("input", tag) do
    input_type = attribute_value(tag, "type") || "text"

    input_type not in @input_exempt_types and
      not class_attribute_contains_token?(tag, "input")
  end

  defp missing_form_control_base?("select", tag) do
    not class_attribute_contains_token?(tag, "select")
  end

  defp attribute_value(tag, attribute) do
    case Regex.run(~r/\b#{attribute}\s*=\s*"([^"]*)"/s, tag, capture: :all_but_first) do
      [value] -> value
      nil -> nil
    end
  end

  defp class_attribute_contains_token?(tag, token) do
    tag
    |> class_attribute_source()
    |> class_tokens()
    |> Enum.member?(token)
  end

  defp class_tokens(nil), do: []

  defp class_tokens(class) do
    class
    |> string_literal_values()
    |> Enum.flat_map(&String.split(&1, ~r/\s+/, trim: true))
  end

  defp string_literal_values(class) do
    case Regex.scan(~r/"([^"]*)"/, class, capture: :all_but_first) do
      [] -> [class]
      matches -> List.flatten(matches)
    end
  end

  defp line_number(source, offset) do
    source
    |> binary_part(0, offset)
    |> String.split("\n")
    |> length()
  end
end
