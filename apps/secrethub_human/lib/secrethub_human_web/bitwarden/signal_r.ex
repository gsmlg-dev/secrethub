defmodule SecretHub.HumanWeb.Bitwarden.SignalR do
  @moduledoc "Small server-only SignalR framing for personal vault synchronization."
  import Bitwise

  def handshake(data) when is_binary(data) and byte_size(data) <= 1024 do
    with [json, ""] <- String.split(data, <<30>>),
         {:ok, %{"protocol" => protocol, "version" => 1}} <- Jason.decode(json) do
      case protocol do
        "messagepack" -> {:ok, :messagepack}
        "json" -> {:ok, :json}
        _ -> {:error, :invalid_protocol}
      end
    else
      _ -> {:error, :invalid_protocol}
    end
  end

  def handshake(_), do: {:error, :invalid_protocol}
  def heartbeat(:messagepack), do: {:binary, <<2, 0x91, 6>>}
  def heartbeat(:json), do: {:text, "{\"type\":6}\x1e"}

  def vault_changed(:json, user_id) do
    data = %{type: 1, target: "ReceiveMessage", arguments: [notification(user_id)]}
    {:text, Jason.encode!(data) <> <<30>>}
  end

  def vault_changed(:messagepack, user_id) do
    body =
      pack([1, %{}, nil, "ReceiveMessage", [notification(user_id)], []]) |> IO.iodata_to_binary()

    {:binary, varint(byte_size(body)) <> body}
  end

  defp notification(user_id),
    do: %{"ContextId" => Ecto.UUID.generate(), "Type" => 5, "Payload" => %{"UserId" => user_id}}

  defp varint(n) when n < 128, do: <<n>>
  defp varint(n), do: <<bor(band(n, 127), 128)>> <> varint(n >>> 7)
  defp pack(nil), do: <<0xC0>>
  defp pack(n) when is_integer(n) and n in 0..127, do: <<n>>

  defp pack(text) when is_binary(text) and byte_size(text) < 32,
    do: [<<0xA0 + byte_size(text)>>, text]

  defp pack(text) when is_binary(text) and byte_size(text) <= 255,
    do: [<<0xD9, byte_size(text)>>, text]

  defp pack(list) when is_list(list) and length(list) < 16,
    do: [<<0x90 + length(list)>>, Enum.map(list, &pack/1)]

  defp pack(map) when is_map(map) and map_size(map) < 16 do
    [
      <<0x80 + map_size(map)>>,
      map |> Enum.sort() |> Enum.map(fn {key, value} -> [pack(key), pack(value)] end)
    ]
  end
end
