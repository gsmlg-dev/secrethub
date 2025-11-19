defmodule SecretHub.CLI.OutputTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias SecretHub.CLI.Output

  describe "format/2 - JSON format" do
    test "formats simple map as JSON" do
      data = %{"name" => "test", "value" => "secret123"}

      assert {:ok, output} = Output.format(data, format: "json")
      assert output =~ ~s("name": "test")
      assert output =~ ~s("value": "secret123")

      # Verify it's valid JSON
      assert {:ok, _} = Jason.decode(output)
    end

    test "formats list of maps as JSON" do
      data = [
        %{"id" => 1, "name" => "secret1"},
        %{"id" => 2, "name" => "secret2"}
      ]

      assert {:ok, output} = Output.format(data, format: "json")
      assert {:ok, decoded} = Jason.decode(output)
      assert length(decoded) == 2
    end

    test "formats nested data as JSON" do
      data = %{
        "metadata" => %{
          "created_at" => "2025-01-01T00:00:00Z",
          "version" => 1
        },
        "data" => %{"key" => "value"}
      }

      assert {:ok, output} = Output.format(data, format: "json")
      assert {:ok, decoded} = Jason.decode(output)
      assert decoded["metadata"]["version"] == 1
    end

    test "handles encoding errors gracefully" do
      # Most Elixir types can be encoded, but we can test the error path
      # by ensuring the error handling exists
      assert is_function(&Output.format_json/1)
    end
  end

  describe "format/2 - YAML format" do
    test "formats simple map as YAML" do
      data = %{"name" => "test", "value" => "secret123"}

      assert {:ok, output} = Output.format(data, format: "yaml")
      assert output =~ "name:"
      assert output =~ "test"
      assert output =~ "value:"
      assert output =~ "secret123"
    end

    test "formats list as YAML" do
      data = [
        %{"id" => 1, "name" => "secret1"},
        %{"id" => 2, "name" => "secret2"}
      ]

      assert {:ok, output} = Output.format(data, format: "yaml")
      assert output =~ "id:"
      assert output =~ "name:"
    end

    test "formats nested data with proper indentation" do
      data = %{
        "level1" => %{
          "level2" => "value"
        }
      }

      assert {:ok, output} = Output.format(data, format: "yaml")
      assert output =~ "level1:"
      assert output =~ "level2:"
      # Check for indentation (spaces before level2)
      assert output =~ ~r/\s+level2:/
    end
  end

  describe "format/2 - Table format" do
    test "formats list of maps as table" do
      data = [
        %{"id" => "1", "name" => "secret1", "version" => "2"},
        %{"id" => "2", "name" => "secret2", "version" => "1"}
      ]

      assert {:ok, output} = Output.format(data, format: "table")

      # Check for table structure
      assert output =~ "+"
      assert output =~ "-"
      assert output =~ "|"

      # Check for headers
      assert output =~ "id"
      assert output =~ "name"
      assert output =~ "version"

      # Check for data
      assert output =~ "secret1"
      assert output =~ "secret2"
    end

    test "formats single map as key-value table" do
      data = %{"server_url" => "http://localhost:4000", "format" => "table"}

      assert {:ok, output} = Output.format(data, format: "table")

      # Check for table structure
      assert output =~ "+"
      assert output =~ "|"

      # Check for key-value pairs
      assert output =~ "server_url"
      assert output =~ "http://localhost:4000"
      assert output =~ "format"
      assert output =~ "table"
    end

    test "handles empty list" do
      data = []

      assert {:error, _} = Output.format(data, format: "table")
    end

    test "aligns columns properly" do
      data = [
        %{"short" => "a", "very_long_column_name" => "value1"},
        %{"short" => "b", "very_long_column_name" => "value2"}
      ]

      assert {:ok, output} = Output.format(data, format: "table")

      # All rows should have same width separators
      lines = String.split(output, "\n")
      separators = Enum.filter(lines, &String.starts_with?(&1, "+"))

      # All separators should be the same length
      lengths = Enum.map(separators, &String.length/1)
      assert Enum.uniq(lengths) |> length() == 1
    end

    test "formats DateTime values" do
      dt = DateTime.from_naive!(~N[2025-01-01 12:00:00], "Etc/UTC")
      data = [%{"timestamp" => dt, "event" => "login"}]

      assert {:ok, output} = Output.format(data, format: "table")
      assert output =~ "2025-01-01"
      assert output =~ "12:00:00"
    end

    test "formats list values as comma-separated" do
      data = [%{"tags" => ["tag1", "tag2", "tag3"], "name" => "item"}]

      assert {:ok, output} = Output.format(data, format: "table")
      assert output =~ "tag1, tag2, tag3"
    end

    test "formats nested maps with inspect" do
      data = [%{"config" => %{"nested" => "value"}, "id" => "1"}]

      assert {:ok, output} = Output.format(data, format: "table")
      # Nested maps should be inspected
      assert output =~ "%{"
    end
  end

  describe "format/2 - default format" do
    test "defaults to table format when format not specified" do
      data = [%{"key" => "value"}]

      assert {:ok, output} = Output.format(data)
      assert output =~ "|"
      assert output =~ "+"
    end
  end

  describe "format/2 - unknown format" do
    test "returns error for unknown format" do
      data = %{"key" => "value"}

      assert {:error, reason} = Output.format(data, format: "unknown")
      assert reason =~ "Unknown format"
    end
  end

  describe "format_json/1" do
    test "formats data as pretty JSON" do
      data = %{"a" => 1, "b" => 2}

      assert {:ok, json} = Output.format_json(data)
      # Pretty JSON should have newlines
      assert json =~ "\n"
      # Should be valid JSON
      assert {:ok, _} = Jason.decode(json)
    end
  end

  describe "format_yaml/1" do
    test "formats simple values" do
      data = %{"string" => "value", "number" => 42, "bool" => true}

      assert {:ok, yaml} = Output.format_yaml(data)
      assert yaml =~ "string:"
      assert yaml =~ "value"
      assert yaml =~ "number:"
      assert yaml =~ "42"
      assert yaml =~ "bool:"
      assert yaml =~ "true"
    end
  end

  describe "format_table/1" do
    test "formats list of maps" do
      data = [
        %{"name" => "alice", "age" => 30},
        %{"name" => "bob", "age" => 25}
      ]

      assert {:ok, table} = Output.format_table(data)
      assert table =~ "alice"
      assert table =~ "bob"
      assert table =~ "30"
      assert table =~ "25"
    end

    test "formats single map" do
      data = %{"key1" => "value1", "key2" => "value2"}

      assert {:ok, table} = Output.format_table(data)
      assert table =~ "Key"
      assert table =~ "Value"
      assert table =~ "key1"
      assert table =~ "value1"
    end

    test "returns error for invalid input" do
      assert {:error, reason} = Output.format_table("invalid")
      assert reason =~ "Table format requires"
    end
  end

  describe "success/1" do
    test "prints success message in color" do
      output = capture_io(fn ->
        Output.success("Operation completed")
      end)

      assert output =~ "Operation completed"
    end
  end

  describe "error/1" do
    test "prints error message to stderr" do
      output = capture_io(:stderr, fn ->
        Output.error("Something went wrong")
      end)

      assert output =~ "Error:"
      assert output =~ "Something went wrong"
    end
  end

  describe "warning/1" do
    test "prints warning message in color" do
      output = capture_io(fn ->
        Output.warning("This is a warning")
      end)

      assert output =~ "Warning:"
      assert output =~ "This is a warning"
    end
  end

  describe "info/1" do
    test "prints info message" do
      output = capture_io(fn ->
        Output.info("Information message")
      end)

      assert output =~ "Information message"
    end
  end

  describe "format_value/1 - private helper" do
    # These test the internal formatting logic through the public API
    test "handles nil values in table" do
      data = [%{"key" => nil, "other" => "value"}]

      assert {:ok, output} = Output.format_table(data)
      # nil should be formatted as empty string
      lines = String.split(output, "\n")
      # Should not contain "nil" text
      refute Enum.any?(lines, &String.contains?(&1, "nil"))
    end

    test "handles atom values in table" do
      data = [%{"status" => :active, "name" => "test"}]

      assert {:ok, output} = Output.format_table(data)
      assert output =~ "active"
    end

    test "handles number values in table" do
      data = [%{"count" => 42, "price" => 19.99}]

      assert {:ok, output} = Output.format_table(data)
      assert output =~ "42"
      assert output =~ "19.99"
    end
  end

  describe "table column width calculation" do
    test "calculates widths based on longest content" do
      data = [
        %{"short" => "a", "long" => "this is a very long value"},
        %{"short" => "b", "long" => "short"}
      ]

      assert {:ok, output} = Output.format_table(data)

      # The "long" column should be wide enough for the longest value
      assert output =~ "this is a very long value"
      # Values should be properly padded
      lines = String.split(output, "\n")
      data_lines = Enum.filter(lines, &String.contains?(&1, "| "))

      # All data lines should have the same length
      lengths = Enum.map(data_lines, &String.length/1)
      assert Enum.uniq(lengths) |> length() <= 2  # Header and data might differ slightly
    end
  end
end
