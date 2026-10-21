defmodule SecretHub.Core.PKI.DNS.PropagationTest do
  use ExUnit.Case, async: true
  alias SecretHub.Core.PKI.DNS.{Propagation, Resolver}

  test "requires all apex/wildcard values from every authoritative server" do
    resolver = fn "_acme-challenge.example.com" ->
      {:ok,
       [
         %{server: "ns1", authoritative: true, values: ["apex", "wildcard", "unrelated"]},
         %{server: "ns2", authoritative: true, values: ["apex", "wildcard"]}
       ]}
    end

    assert {:ok, :propagated} =
             Propagation.check("_acme-challenge.example.com", ["apex", "wildcard"],
               authoritative_resolver: resolver
             )

    assert {:error, :not_propagated} =
             Propagation.check("_acme-challenge.example.com", ["missing"],
               authoritative_resolver: resolver
             )

    assert {:error, :not_authoritative} =
             Propagation.check("_acme-challenge.example.com", ["apex"],
               authoritative_resolver: fn _ ->
                 {:ok, [%{server: "recursive", authoritative: false, values: ["apex"]}]}
               end
             )

    assert {:error, :no_authoritative_servers} =
             Propagation.check("_acme-challenge.example.com", ["apex"],
               authoritative_resolver: fn _ -> {:ok, []} end
             )
  end

  test "discovers authority and queries its public address without recursion" do
    parent = self()

    query = fn name, type, opts ->
      send(parent, {name, type, opts})

      case {name, type} do
        {"_acme-challenge.example.com", :ns} ->
          {:ok, %{authoritative: false, answers: []}}

        {"example.com", :ns} ->
          {:ok, %{authoritative: false, answers: [%{type: :ns, data: "ns1.example.com"}]}}

        {"ns1.example.com", :a} ->
          {:ok, %{authoritative: false, answers: [%{type: :a, data: {8, 8, 8, 8}}]}}

        {"_acme-challenge.example.com", :txt} ->
          assert opts[:nameservers] == [{{8, 8, 8, 8}, 53}]
          assert opts[:recurse] == false
          {:ok, %{authoritative: true, answers: [%{type: :txt, data: ["ab", "cd"]}]}}
      end
    end

    assert {:ok, [%{authoritative: true, server: "ns1.example.com", values: ["abcd"]}]} =
             Resolver.authoritative_txt("_acme-challenge.example.com", dns_query: query)

    assert_received {"_acme-challenge.example.com", :txt, _}
  end

  test "refuses private authoritative addresses" do
    query = fn _, type, _ ->
      case type do
        :ns -> {:ok, %{authoritative: false, answers: [%{type: :ns, data: "ns.example.com"}]}}
        :a -> {:ok, %{authoritative: false, answers: [%{type: :a, data: {127, 0, 0, 1}}]}}
        :aaaa -> {:ok, %{authoritative: false, answers: []}}
      end
    end

    assert {:error, :no_public_nameserver_address} =
             Resolver.authoritative_txt("_acme-challenge.example.com", dns_query: query)
  end
end
