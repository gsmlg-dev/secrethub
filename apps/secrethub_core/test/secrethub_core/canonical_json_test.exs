defmodule SecretHub.Core.CanonicalJSONTest do
  use ExUnit.Case, async: true

  alias SecretHub.Core.CanonicalJSON

  test "map insertion order and atom or string keys produce identical canonical bytes" do
    string_keyed =
      Map.new([
        {"report_hash", String.duplicate("a", 64)},
        {"capability", "secret-lifecycle"},
        {"gate", "agent-security"}
      ])

    atom_keyed =
      Map.new([
        {:gate, "agent-security"},
        {:report_hash, String.duplicate("a", 64)},
        {:capability, "secret-lifecycle"}
      ])

    assert CanonicalJSON.encode!(string_keyed) == CanonicalJSON.encode!(atom_keyed)

    assert sha256(CanonicalJSON.encode!(string_keyed)) ==
             sha256(CanonicalJSON.encode!(atom_keyed))
  end

  test "normalizes nested object ordering recursively and encodes DateTimes as ISO8601" do
    datetime = ~U[2026-07-16 12:34:56Z]

    left = %{
      "z" => %{"second" => 2, "first" => %{"b" => false, "a" => datetime}},
      "a" => "value"
    }

    right = %{
      a: "value",
      z: %{first: %{a: datetime, b: false}, second: 2}
    }

    expected =
      ~s({"a":"value","z":{"first":{"a":"2026-07-16T12:34:56Z","b":false},"second":2}})

    assert CanonicalJSON.encode!(left) == expected
    assert CanonicalJSON.encode!(right) == expected
  end

  test "preserves list order" do
    first = CanonicalJSON.encode!(%{items: [1, 2, 3]})
    second = CanonicalJSON.encode!(%{items: [3, 2, 1]})

    assert first == ~s({"items":[1,2,3]})
    assert second == ~s({"items":[3,2,1]})
    refute first == second
    refute sha256(first) == sha256(second)
  end

  test "rejects map keys that collide after string normalization" do
    assert_raise ArgumentError, ~r/duplicate canonical JSON key "gate"/, fn ->
      CanonicalJSON.encode!(%{:gate => "first", "gate" => "second"})
    end

    assert_raise ArgumentError, ~r/duplicate canonical JSON key "hash"/, fn ->
      CanonicalJSON.encode!(%{outer: %{:hash => "first", "hash" => "second"}})
    end
  end

  defp sha256(bytes) do
    :crypto.hash(:sha256, bytes)
    |> Base.encode16(case: :lower)
  end
end
