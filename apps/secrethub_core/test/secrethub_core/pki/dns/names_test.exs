defmodule SecretHub.Core.PKI.DNS.NamesTest do
  use ExUnit.Case, async: true
  alias SecretHub.Core.PKI.DNS.Names

  test "canonicalizes IDNA, case and trailing dots and deduplicates a SAN set" do
    assert {:ok, ["*.example.com", "example.com", "xn--bcher-kva.example"]} =
             Names.normalize_identifiers([
               "Example.COM.",
               "*.EXAMPLE.com",
               "bücher.example",
               "example.com"
             ])
  end

  test "rejects IPs, internal names, invalid wildcards and invalid labels" do
    for value <- [
          "127.0.0.1",
          "::1",
          "localhost",
          "app.local",
          "a.*.example.com",
          "*.*.example.com",
          "-app.example.com",
          "a..example.com"
        ] do
      assert {:error, :invalid_identifier} = Names.normalize_identifier(value)
    end
  end

  test "wildcard and apex share a DNS challenge owner" do
    assert {:ok, "_acme-challenge.example.com"} = Names.challenge_owner("*.example.com")
    assert {:ok, "_acme-challenge.example.com"} = Names.challenge_owner("example.com")
  end

  test "bindings use label boundaries and longest suffix across providers" do
    bindings = [
      %{
        "suffix" => "example.com",
        "provider_id" => "cf",
        "zone_id" => "one",
        "zone_name" => "example.com"
      },
      %{
        "suffix" => "sub.example.com",
        "provider_id" => "aws",
        "zone_id" => "two",
        "zone_name" => "sub.example.com"
      }
    ]

    assert {:ok, %{"provider_id" => "aws"}} = Names.bind("app.sub.example.com", bindings)
    assert {:ok, %{"provider_id" => "cf"}} = Names.bind("*.example.com", bindings)
    assert {:error, :unbound_identifier} = Names.bind("badexample.com", bindings)
    assert {:error, :ambiguous_binding} = Names.bind("example.com", bindings ++ [hd(bindings)])
  end

  test "delegation is explicit, bounded and rejects loops" do
    resolver = fn
      "_acme-challenge.example.com", :cname -> {:ok, ["validation.example.net."]}
      "validation.example.net", :cname -> {:ok, []}
    end

    binding = %{"zone_name" => "example.net", "delegated_owner" => "validation.example.net"}

    assert {:ok, "validation.example.net"} =
             Names.effective_owner("_acme-challenge.example.com", binding, resolver: resolver)

    assert {:error, :unconfigured_delegation} =
             Names.effective_owner("_acme-challenge.example.com", %{"zone_name" => "example.com"},
               resolver: resolver
             )

    loop = fn _, :cname -> {:ok, ["_acme-challenge.example.com"]} end

    assert {:error, :delegation_loop} =
             Names.effective_owner("_acme-challenge.example.com", binding, resolver: loop)
  end
end
