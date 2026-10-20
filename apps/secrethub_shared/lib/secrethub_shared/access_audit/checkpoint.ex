defmodule SecretHub.Shared.AccessAudit.Checkpoint do
  @moduledoc "Strict, value-free retention checkpoint and marker contracts."
  @keys ~w(schema_version prune_id audit_log_id event_id sequence_number timestamp previous_hash current_hash hash_version original_signature original_signature_version original_signing_key_id signature_version signing_key_id signature namespace producer_id producer_sequence observation_event_id request_id canonical_digest)
  @marker_keys ~w(schema_version prune_id raw_before aggregate_before observations requests checkpoint_digest)
  @hash ~r/\A[0-9a-f]{64}\z/
  @key ~r/\A[a-zA-Z0-9_.-]{1,64}\z/

  def validate(checkpoint) when is_map(checkpoint) do
    if Enum.sort(Map.keys(checkpoint)) == Enum.sort(@keys) and
         valid_ledger_identity?(checkpoint) and valid_source_identity?(checkpoint) and
         valid_hashes?(checkpoint) and valid_signatures?(checkpoint),
       do: {:ok, checkpoint},
       else: {:error, :invalid_checkpoint}
  end

  def validate(_), do: {:error, :invalid_checkpoint}

  def validate_marker(%{"access_retention" => marker} = data)
      when map_size(data) == 1 and is_map(marker) do
    if Enum.sort(Map.keys(marker)) == Enum.sort(@marker_keys) and
         valid_marker?(marker),
       do: {:ok, data},
       else: {:error, :invalid_checkpoint}
  end

  def validate_marker(_), do: {:error, :invalid_checkpoint}

  defp valid_marker?(marker) do
    marker["schema_version"] == 1 and uuid?(marker["prune_id"]) and
      time?(marker["raw_before"]) and time?(marker["aggregate_before"]) and
      bounded?(marker["observations"], 0..10_000) and bounded?(marker["requests"], 0..10) and
      hash?(marker["checkpoint_digest"])
  end

  def canonical(data), do: data |> Enum.sort() |> Jason.OrderedObject.new() |> Jason.encode!()
  def signature_payload(checkpoint), do: checkpoint |> Map.delete("signature") |> canonical()

  defp valid_ledger_identity?(checkpoint) do
    checkpoint["schema_version"] == 1 and checkpoint["hash_version"] == 2 and
      uuid?(checkpoint["prune_id"]) and uuid?(checkpoint["event_id"]) and
      positive?(checkpoint["audit_log_id"]) and positive?(checkpoint["sequence_number"]) and
      time?(checkpoint["timestamp"])
  end

  defp valid_source_identity?(checkpoint) do
    is_binary(checkpoint["namespace"]) and byte_size(checkpoint["namespace"]) in 1..300 and
      uuid?(checkpoint["producer_id"]) and positive?(checkpoint["producer_sequence"]) and
      uuid?(checkpoint["observation_event_id"]) and uuid?(checkpoint["request_id"])
  end

  defp valid_hashes?(checkpoint) do
    hash?(checkpoint["canonical_digest"]) and hash?(checkpoint["current_hash"]) and
      (hash?(checkpoint["previous_hash"]) or checkpoint["previous_hash"] == "GENESIS")
  end

  defp valid_signatures?(checkpoint) do
    hash?(checkpoint["original_signature"]) and hash?(checkpoint["signature"]) and
      key?(checkpoint["original_signature_version"], checkpoint["original_signing_key_id"]) and
      key?(checkpoint["signature_version"], checkpoint["signing_key_id"])
  end

  defp bounded?(value, range), do: is_integer(value) and value in range
  defp uuid?(value) when is_binary(value), do: match?({:ok, ^value}, Ecto.UUID.cast(value))
  defp uuid?(_), do: false
  defp positive?(value), do: is_integer(value) and value in 1..9_007_199_254_740_991
  defp hash?(value) when is_binary(value), do: Regex.match?(@hash, value)
  defp hash?(_), do: false

  defp time?(value) when is_binary(value) and byte_size(value) <= 40,
    do: match?({:ok, _, _}, DateTime.from_iso8601(value))

  defp time?(_), do: false
  defp key?(1, nil), do: true
  defp key?(2, value) when is_binary(value), do: Regex.match?(@key, value)
  defp key?(_, _), do: false
end
