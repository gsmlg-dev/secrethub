defmodule SecretHub.Agent.SSH.ProtocolTest do
  use ExUnit.Case, async: true
  alias SecretHub.Agent.SSH.{Identity, Protocol}

  test "only identity and sign requests are accepted and framing is strict" do
    assert {:ok, :identities} = Protocol.decode(<<11>>)

    assert {:ok, {:sign, "key", "data", 2}} =
             Protocol.decode(<<13, 3::32, "key", 4::32, "data", 2::32>>)

    for input <- [<<11, 0>>, <<13, 999_999::32>>, <<17>>, <<>>, <<13, 0::32, 0::32, 8::32>>] do
      assert {:error, _} = Protocol.decode(input)
    end

    assert <<12, 1::32, 3::32, "key", 0::32>> = Protocol.identities(["key"])
    assert <<14, 3::32, "sig">> = Protocol.signature("sig")
  end

  test "UID aliases and changed UID/name bindings fail closed" do
    entries = "alice:x:1000:100:Alice:/home/alice:/bin/sh\nbob:x:1001:100:Bob:/home/bob:/bin/sh\n"
    assert {:ok, %{uid: 1000, username: "alice"}} = Identity.resolve(1000, entries)
    assert {:error, _} = Identity.resolve(1000, entries <> "alias:x:1000:100::/:/bin/sh\n")
    assert {:error, _} = Identity.resolve(9, entries)
    assert {:error, _} = Identity.resolve(1000, "alice:x:bad:100::/:/bin/sh\n")
  end
end
