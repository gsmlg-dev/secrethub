defmodule SecretHub.Core.Vault.LegacyRecoveryTest do
  use ExUnit.Case, async: true
  alias SecretHub.Core.Vault.LegacyRecovery

  test "strictly reconstructs supported historical wire versions only in recovery" do
    config = %{threshold: 2, total_shares: 3}

    for version <- 1..3 do
      key = :binary.copy(<<if(version == 3, do: 254, else: 42)>>, 32)

      shares =
        for id <- 1..2 do
          value = :binary.copy(<<rem(rem(:binary.at(key, 0), 251) + 7 * id, 251)>>, 32)

          blob =
            case version do
              1 -> <<1, id, 2, 3, value::binary>>
              2 -> <<2, id, 2, 3, 32, value::binary>>
              3 -> <<3, id, 2, 3, 32, 32, :binary.copy(<<1>>, 32)::binary, value::binary>>
            end

          "secrethub-share-" <> Base.url_encode64(blob, padding: false)
        end

      assert {:ok, ^key} = LegacyRecovery.reconstruct(shares, config)
      assert {:error, _} = LegacyRecovery.reconstruct([hd(shares), hd(shares)], config)
    end
  end

  test "rejects malformed, oversized, zero coordinate, extra bytes, mismatches and arbitrary maps" do
    encode = fn blob -> "secrethub-share-" <> Base.url_encode64(blob, padding: false) end
    valid = encode.(<<2, 1, 1, 2, 32, 0::256>>)

    for invalid <- [
          nil,
          %{},
          "secrethub-share-" <> String.duplicate("A", 1000),
          valid <> "=",
          encode.(<<2, 0, 1, 2, 32, 0::256>>),
          encode.(<<2, 1, 1, 2, 32, 0::264>>),
          encode.(<<3, 1, 1, 2, 32, 32, 0::16>>),
          encode.(<<2, 251, 1, 251, 32, 0::256>>)
        ] do
      assert {:error, _} = LegacyRecovery.reconstruct([invalid], %{threshold: 1, total_shares: 2})
    end
  end

  test "rejects historical adjustment metadata that would overflow a recovered byte" do
    encoded =
      "secrethub-share-" <>
        Base.url_encode64(
          <<3, 1, 1, 1, 32, 32, :binary.copy(<<1>>, 32)::binary,
            :binary.copy(<<249>>, 32)::binary>>,
          padding: false
        )

    assert {:error, :invalid_legacy_shares} =
             LegacyRecovery.reconstruct([encoded], %{threshold: 1, total_shares: 1})
  end
end
