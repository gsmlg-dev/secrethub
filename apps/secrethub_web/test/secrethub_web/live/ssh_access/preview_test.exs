defmodule SecretHub.Web.SSHAccess.PreviewTest do
  use ExUnit.Case, async: true
  alias SecretHub.Web.SSHAccess.Preview

  @inventory %{
    agents: [%{agent_id: "a1", name: "vultr-01"}, %{agent_id: "a2", name: "vultr-02"}],
    identities: [%{id: "i1", name: "gao@laptop"}],
    groups: [%{id: "servers", name: "Servers", kind: "host"}]
  }

  test "groups edges by identity and user into readable sentences" do
    preview = %{
      gained: [
        %{identity_id: "i1", destination_agent_id: "a1", destination_user: "gao"},
        %{identity_id: "i1", destination_agent_id: "a2", destination_user: "gao"}
      ],
      lost: [%{identity_id: "i9", destination_agent_id: "a1", destination_user: "deploy"}],
      changes: [],
      identity_names: %{"i9" => "gh-deploy"}
    }

    assert Preview.edges(preview, @inventory) == [
             {:gained, "gao@laptop can log in as gao on vultr-01, vultr-02"},
             {:lost, "gh-deploy can no longer log in as deploy on vultr-01"}
           ]
  end

  test "describes configuration operations without key material" do
    changes = [
      %{"op" => "identity_approve", "id" => "i1"},
      %{"op" => "identity_external_add", "name" => "ci", "public_key" => "ssh-ed25519 AAAA"},
      %{"op" => "endpoint_upsert", "agent_id" => "a1", "host_keys" => ["k"], "approved" => true},
      %{"op" => "rule_delete", "id" => "r"}
    ]

    assert Preview.changes(changes, @inventory) == [
             "Approve identity gao@laptop",
             "Add external identity ci",
             "Trust 1 host key for vultr-01",
             "Remove 1 access rule"
           ]
  end

  describe "endpoint_upsert" do
    @endpoint_inventory Map.put(@inventory, :endpoints, [
                          %{agent_id: "a1", host_keys: ["k1"], approved: true}
                        ])

    test "trusts changed keys" do
      change = %{
        "op" => "endpoint_upsert",
        "agent_id" => "a1",
        "aliases" => ["a.example"],
        "port" => 22,
        "host_keys" => ["k2", "k3"],
        "approved" => true
      }

      assert Preview.changes([change], @endpoint_inventory) == [
               "Trust 2 host keys for vultr-01"
             ]
    end

    test "saves aliases and port when keys are unchanged" do
      change = %{
        "op" => "endpoint_upsert",
        "agent_id" => "a1",
        "aliases" => ["a.example", "a"],
        "port" => 2222,
        "host_keys" => ["k1"],
        "approved" => true
      }

      assert Preview.changes([change], @endpoint_inventory) == [
               "Save endpoint vultr-01 (aliases a.example, a, port 2222); host keys unchanged"
             ]
    end

    test "saves an endpoint without trusted keys" do
      change = %{
        "op" => "endpoint_upsert",
        "agent_id" => "a2",
        "aliases" => [],
        "port" => 22,
        "host_keys" => [],
        "approved" => false
      }

      assert Preview.changes([change], @endpoint_inventory) == [
               "Save endpoint vultr-02 without trusted host keys"
             ]
    end
  end
end
