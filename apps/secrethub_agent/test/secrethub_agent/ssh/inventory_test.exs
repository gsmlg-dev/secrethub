defmodule SecretHub.Agent.SSH.InventoryTest do
  use ExUnit.Case, async: true
  alias SecretHub.Agent.SSH.Inventory

  test "public OS observations separate group access and reject UID aliases" do
    passwd =
      "deploy:x:1000:100:Deploy:/home/deploy:/bin/sh\nnobody:x:65534:65534::/:/bin/false\nalias:x:1000:100::/:/bin/sh\n"

    groups = "lookup:x:1000:deploy,nobody\nsigning:x:1001:deploy\n"

    settings = [
      ssh_lookup_enabled: true,
      ssh_signing_enabled: true,
      ssh_lookup_socket_group: "lookup",
      ssh_signing_socket_group: "signing"
    ]

    assert [
             %{
               "username" => "deploy",
               "uid" => 1000,
               "signing_access" => true,
               "lookup_access" => true,
               "unambiguous" => false
             },
             %{
               "username" => "nobody",
               "uid" => 65534,
               "signing_access" => false,
               "lookup_access" => true,
               "unambiguous" => true
             },
             %{
               "username" => "alias",
               "uid" => 1000,
               "signing_access" => false,
               "lookup_access" => false,
               "unambiguous" => false
             }
           ] = Inventory.users(passwd, groups, settings, %{lookup: true, signing: true})

    assert Enum.all?(
             Inventory.users(passwd, groups, settings, %{lookup: false, signing: false}),
             fn row -> !row["lookup_access"] and !row["signing_access"] end
           )
  end
end
