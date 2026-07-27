defmodule SecretHub.Shared.Schemas.AppCertificateRenewal do
  @moduledoc """
  Persistent idempotency evidence for application certificate renewal.

  Each row binds one application-scoped request ID to the original certificate,
  normalized request digests, proof, and the certificate issued by that request.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @canonical_fingerprint_format ~r/\A[0-9a-f]{64}\z/
  @canonical_fingerprint_error "must be a 64-character lowercase hexadecimal SHA-256 fingerprint"
  @proof_algorithms ~w(rsa-pss-sha256 ecdsa-sha256)

  schema "app_certificate_renewals" do
    field(:request_id, :binary_id)
    field(:original_fingerprint, :string)
    field(:csr_sha256, :binary)
    field(:normalized_payload_sha256, :binary)
    field(:proof, :binary)
    field(:proof_algorithm, :string)

    belongs_to(:app, SecretHub.Shared.Schemas.Application, type: :binary_id)

    belongs_to(:current_certificate, SecretHub.Shared.Schemas.Certificate, type: :binary_id)

    belongs_to(:issued_certificate, SecretHub.Shared.Schemas.Certificate, type: :binary_id)

    timestamps(type: :utc_datetime)
  end

  @doc """
  Builds a renewal evidence changeset.
  """
  @spec changeset(t(), map()) :: Ecto.Changeset.t()
  def changeset(renewal, attrs) do
    renewal
    |> cast(attrs, [
      :app_id,
      :current_certificate_id,
      :issued_certificate_id,
      :request_id,
      :original_fingerprint,
      :csr_sha256,
      :normalized_payload_sha256,
      :proof,
      :proof_algorithm
    ])
    |> validate_required([
      :app_id,
      :current_certificate_id,
      :issued_certificate_id,
      :request_id,
      :original_fingerprint,
      :csr_sha256,
      :normalized_payload_sha256,
      :proof,
      :proof_algorithm
    ])
    |> validate_format(:original_fingerprint, @canonical_fingerprint_format,
      message: @canonical_fingerprint_error
    )
    |> validate_inclusion(:proof_algorithm, @proof_algorithms)
    |> validate_binary_size(:csr_sha256, 32)
    |> validate_binary_size(:normalized_payload_sha256, 32)
    |> validate_nonempty_binary(:proof)
    |> validate_distinct_certificates()
    |> unique_constraint([:app_id, :request_id])
    |> foreign_key_constraint(:app_id)
    |> foreign_key_constraint(:current_certificate_id)
    |> foreign_key_constraint(:issued_certificate_id)
    |> check_constraint(:original_fingerprint,
      name: :app_certificate_renewals_original_fingerprint_format
    )
    |> check_constraint(:issued_certificate_id,
      name: :app_certificate_renewals_distinct_certificates
    )
    |> check_constraint(:csr_sha256, name: :app_certificate_renewals_csr_sha256_size)
    |> check_constraint(:normalized_payload_sha256,
      name: :app_certificate_renewals_normalized_payload_sha256_size
    )
    |> check_constraint(:proof, name: :app_certificate_renewals_proof_nonempty)
    |> check_constraint(:proof_algorithm,
      name: :app_certificate_renewals_proof_algorithm
    )
  end

  defp validate_binary_size(changeset, field, size) do
    validate_change(changeset, field, fn
      ^field, value when is_binary(value) and byte_size(value) == size -> []
      ^field, _value -> [{field, "must be exactly #{size} bytes"}]
    end)
  end

  defp validate_nonempty_binary(changeset, field) do
    validate_change(changeset, field, fn
      ^field, value when is_binary(value) and byte_size(value) > 0 -> []
      ^field, _value -> [{field, "must not be empty"}]
    end)
  end

  defp validate_distinct_certificates(changeset) do
    current_certificate_id = get_field(changeset, :current_certificate_id)
    issued_certificate_id = get_field(changeset, :issued_certificate_id)

    if current_certificate_id && current_certificate_id == issued_certificate_id do
      add_error(
        changeset,
        :issued_certificate_id,
        "must differ from current_certificate_id"
      )
    else
      changeset
    end
  end

  @type t :: %__MODULE__{}
end
