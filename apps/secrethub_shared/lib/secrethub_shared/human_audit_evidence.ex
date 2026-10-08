defmodule SecretHub.Shared.HumanAuditEvidence do
  @moduledoc "Strict, secret-free evidence shared by the Human outbox and Core audit sink."
  @events ~w(human.user.provisioned human.user.registered human.user.key_id.updated human.login.succeeded human.login.failed
    human.session.refreshed human.session.revoked human.device.registered human.device.removed
    human.vault.item.created human.vault.item.updated human.vault.item.deleted
    human.vault.folder.created human.vault.folder.updated human.vault.folder.deleted
    human.vault.exported human.attachment.created human.attachment.deleted
    human.organization.created human.organization.member.added human.organization.member.removed
    human.collection.created human.collection.updated human.collection.item.shared
    human.dynamic_secret.requested human.dynamic_secret.approved human.dynamic_secret.denied
    human.dynamic_secret.issued human.dynamic_secret.revealed human.dynamic_secret.reveal_failed human.dynamic_secret.renewed
    human.dynamic_secret.revoked human.dynamic_secret.expired)
  @uuid_keys ~w(user_id actor_id subject_id session_id device_id item_id folder_id lease_id
    request_id organization_id collection_id attachment_id approval_id event_id)
  @count_keys ~w(ttl requested_ttl revision item_count byte_size)
  @reasons ~w(invalid_credentials rate_limited revoked expired device_mismatch unauthorized
    invalid_reveal signup_disabled approval_required approval_expired denied policy_changed backend_unavailable)

  def events, do: @events

  def validate(event, metadata) when event in @events and is_map(metadata) do
    Enum.reduce_while(metadata, {:ok, %{}}, fn {key, value}, {:ok, acc} ->
      key = if is_atom(key), do: Atom.to_string(key), else: key

      if valid_value?(key, value) and not Map.has_key?(acc, key) do
        {:cont, {:ok, Map.put(acc, key, value)}}
      else
        {:halt, {:error, :invalid_evidence}}
      end
    end)
  end

  def validate(_, _), do: {:error, :invalid_evidence}

  defp valid_value?(key, value) when key in @uuid_keys,
    do: is_binary(value) and match?({:ok, _}, Ecto.UUID.cast(value))

  defp valid_value?(key, value) when key in @count_keys,
    do: is_integer(value) and value >= 0 and value <= 1_000_000_000

  defp valid_value?("reason", value), do: value in @reasons
  defp valid_value?("result", value), do: value in ~w(success failure allowed denied pending)

  defp valid_value?("email_digest", value),
    do: is_binary(value) and Regex.match?(~r/\A[0-9a-f]{64}\z/, value)

  defp valid_value?(key, value) when key in ["mount_id", "role_id"],
    do: is_binary(value) and Regex.match?(~r/\A[a-zA-Z0-9_\/-]{1,128}\z/, value)

  defp valid_value?(_, _), do: false
end
