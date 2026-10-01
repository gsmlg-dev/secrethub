defmodule SecretHub.Core.Vault.KeyEnvelopeTest do
  use ExUnit.Case, async: true
  alias SecretHub.Core.Vault.KeyEnvelope

  test "authenticates wrapping key and every durable binding" do
    wrapping = :crypto.strong_rand_bytes(32)
    data = :crypto.strong_rand_bytes(32)

    config = %{
      id: "5c14bfa1-3b24-4b79-a1af-322ed35c380d",
      share_set_id: <<9::128>>,
      threshold: 3,
      total_shares: 5
    }

    blob = KeyEnvelope.wrap(data, wrapping, config)
    assert {:ok, ^data} = KeyEnvelope.unwrap(blob, wrapping, config)
    assert {:error, :invalid_key_envelope} = KeyEnvelope.unwrap(blob, <<0::256>>, config)

    for {field, value} <- [
          id: "5c14bfa1-3b24-4b79-a1af-322ed35c380e",
          share_set_id: <<10::128>>,
          threshold: 2,
          total_shares: 6
        ] do
      assert {:error, :invalid_key_envelope} =
               KeyEnvelope.unwrap(blob, wrapping, Map.put(config, field, value))
    end
  end

  test "rejects malformed, unsupported and tampered envelopes without material in errors" do
    wrapping = :crypto.strong_rand_bytes(32)

    config = %{
      id: "5c14bfa1-3b24-4b79-a1af-322ed35c380d",
      share_set_id: <<9::128>>,
      threshold: 3,
      total_shares: 5
    }

    blob = KeyEnvelope.wrap(<<4::256>>, wrapping, config)
    <<head, rest::binary>> = blob

    for invalid <- [
          nil,
          <<>>,
          <<2, rest::binary>>,
          <<head, rest::binary, 0>>,
          binary_part(blob, 0, 20)
        ] do
      assert {:error, :invalid_key_envelope} = KeyEnvelope.unwrap(invalid, wrapping, config)
    end
  end
end
