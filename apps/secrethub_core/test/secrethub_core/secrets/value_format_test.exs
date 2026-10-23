ExUnit.start()

defmodule SecretHub.Core.Secrets.ValueFormatTest do
  use ExUnit.Case, async: true
  alias SecretHub.Core.Secrets.ValueFormat

  test "text accepts only an exact string wrapper and preserves bytes" do
    for value <- ["", " \n\t ", "{\"region\":\"x\"}", "密钥\nPEM"] do
      assert :ok = ValueFormat.validate(%{"value" => value}, "text")
    end

    for data <- [%{}, %{"value" => 1}, %{"value" => "x", "region" => "y"}] do
      assert {:error, :invalid_text_value} = ValueFormat.validate(data, "text")
    end
  end

  test "structured accepts arbitrary JSON objects without reserving names" do
    assert :ok = ValueFormat.validate(%{}, "structured")
    assert :ok = ValueFormat.validate(%{"value" => [nil, 1, true], "" => %{}}, "structured")
    assert {:error, :invalid_structured_value} = ValueFormat.validate("text", "structured")
    assert {:error, :invalid_value_format} = ValueFormat.validate(%{}, "json")
  end

  test "field operations rename simultaneously and preserve unmentioned JSON values" do
    original = %{"a" => [1, false], "b" => %{"nested" => nil}, "" => 42, " " => true}

    operations = [
      %{"original_key" => "a", "name" => "b", "operation" => "keep"},
      %{"original_key" => "b", "name" => "a", "operation" => "keep"},
      %{"name" => "value_format", "operation" => "replace", "value" => ""}
    ]

    assert {:ok,
            %{
              "a" => %{"nested" => nil},
              "b" => [1, false],
              "" => 42,
              " " => true,
              "value_format" => ""
            }} = ValueFormat.apply_field_operations(original, operations)
  end

  test "field operations remove and explicitly replace existing values" do
    assert {:ok, %{"data" => "new"}} =
             ValueFormat.apply_field_operations(
               %{"old" => "hidden", "data" => false},
               [
                 %{"original_key" => "old", "operation" => "remove"},
                 %{
                   "original_key" => "data",
                   "name" => "data",
                   "operation" => "replace",
                   "value" => "new"
                 }
               ]
             )
  end

  test "invalid operations reject duplicate sources and final names without secret values" do
    original = %{"a" => "hidden-secret", "b" => 1}

    assert {:error, :duplicate_field_source} =
             ValueFormat.apply_field_operations(original, [
               %{"original_key" => "a", "operation" => "remove"},
               %{"original_key" => "a", "operation" => "remove"}
             ])

    assert {:error, :duplicate_field_name} =
             ValueFormat.apply_field_operations(original, [
               %{"original_key" => "a", "name" => "b", "operation" => "keep"}
             ])

    for name <- ["", " \t"] do
      assert {:error, {:invalid_field_operation, 1}} =
               ValueFormat.apply_field_operations(original, [
                 %{"name" => name, "operation" => "replace", "value" => "entered"}
               ])
    end

    assert {:error, {:invalid_field_operation, 1}} =
             ValueFormat.apply_field_operations(original, [
               %{"original_key" => "missing", "name" => "new", "operation" => "keep"}
             ])
  end

  test "descriptors expose only key and JSON kind" do
    assert [
             %{key: "array", kind: "array"},
             %{key: "bool", kind: "boolean"},
             %{key: "null", kind: "null"},
             %{key: "number", kind: "number"},
             %{key: "object", kind: "object"},
             %{key: "text", kind: "string"}
           ] =
             ValueFormat.descriptors(%{
               "text" => "hidden-secret",
               "array" => [],
               "object" => %{},
               "number" => 1,
               "null" => nil,
               "bool" => false
             })
  end
end
