defmodule SecretHub.Agent.SSH.Protocol do
  @moduledoc "Bounded SSH agent protocol, supporting only list and sign."
  @max_frame 1_048_576
  def max_frame, do: @max_frame
  def decode(<<11>>), do: {:ok, :identities}

  def decode(<<13, size::32, key::binary-size(size), rest::binary>>) when size in 1..16_384 do
    case rest do
      <<length::32, data::binary-size(length), flags::32>>
      when length <= @max_frame - 16_400 and flags in [0, 2, 4] ->
        {:ok, {:sign, key, data, flags}}

      _ ->
        {:error, :invalid_request}
    end
  end

  def decode(_), do: {:error, :unsupported_request}
  def string(value), do: <<byte_size(value)::32, value::binary>>

  def identities(keys),
    do: IO.iodata_to_binary([<<12, length(keys)::32>>, Enum.map(keys, &[string(&1), <<0::32>>])])

  def signature(signature), do: <<14, string(signature)::binary>>
  def failure, do: <<5>>
end
