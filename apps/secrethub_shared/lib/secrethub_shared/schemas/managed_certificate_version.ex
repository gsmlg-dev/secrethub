defmodule SecretHub.Shared.Schemas.ManagedCertificateVersion do
  @moduledoc "Dedicated public certificate lifecycle state; separate from internal identities."
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "managed_certificate_versions" do
    field(:managed_certificate_id, :binary_id)
    field(:order_id, :binary_id)
    field(:publication_sequence, :integer)
    field(:environment, :string)
    field(:fingerprint, :string)
    field(:certificate_pem, :string)
    field(:chain_pem, :string, default: "")
    field(:fullchain_pem, :string)
    field(:identifiers, {:array, :string})
    field(:not_before, :utc_datetime)
    field(:not_after, :utc_datetime)
    field(:key_policy, :string)
    field(:output_secret_id, :binary_id)
    field(:secret_version_number, :integer)
    field(:ari, :map, default: %{})
    field(:renewal_due_at, :utc_datetime)
    field(:ari_refresh_at, :utc_datetime)
    field(:quarantined_at, :utc_datetime)
    field(:revocation_state, :string, default: "none")
    field(:revocation_reason, :integer, default: 0)
    field(:revocation_next_attempt_at, :utc_datetime)
    field(:revocation_error, :map, default: %{})
    timestamps(type: :utc_datetime)
  end

  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :managed_certificate_id,
      :order_id,
      :publication_sequence,
      :environment,
      :fingerprint,
      :certificate_pem,
      :chain_pem,
      :fullchain_pem,
      :identifiers,
      :not_before,
      :not_after,
      :key_policy,
      :output_secret_id,
      :secret_version_number,
      :ari,
      :renewal_due_at,
      :ari_refresh_at,
      :quarantined_at,
      :revocation_state,
      :revocation_reason,
      :revocation_next_attempt_at,
      :revocation_error
    ])
    |> validate_required([
      :managed_certificate_id,
      :order_id,
      :publication_sequence,
      :environment,
      :fingerprint,
      :certificate_pem,
      :fullchain_pem,
      :identifiers,
      :not_before,
      :not_after,
      :key_policy,
      :output_secret_id,
      :secret_version_number
    ])
    |> unique_constraint(:order_id)
    |> unique_constraint(:publication_sequence, name: :managed_versions_sequence)
  end
end
