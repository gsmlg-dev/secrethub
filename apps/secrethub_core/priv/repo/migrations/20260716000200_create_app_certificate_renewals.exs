defmodule SecretHub.Core.Repo.Migrations.CreateAppCertificateRenewals do
  use Ecto.Migration

  @proof_algorithms ~w(rsa-pss-sha256 ecdsa-sha256)

  def up do
    create table(:app_certificate_renewals, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :app_id,
        references(:applications, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(
        :current_certificate_id,
        references(:certificates, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(
        :issued_certificate_id,
        references(:certificates, type: :binary_id, on_delete: :restrict),
        null: false
      )

      add(:request_id, :uuid, null: false)
      add(:original_fingerprint, :string, null: false)
      add(:csr_sha256, :binary, null: false)
      add(:normalized_payload_sha256, :binary, null: false)
      add(:proof, :binary, null: false)
      add(:proof_algorithm, :string, null: false)

      timestamps(type: :utc_datetime)
    end

    create(unique_index(:app_certificate_renewals, [:app_id, :request_id]))
    create(index(:app_certificate_renewals, [:current_certificate_id]))
    create(index(:app_certificate_renewals, [:issued_certificate_id]))

    create(
      constraint(
        :app_certificate_renewals,
        :app_certificate_renewals_original_fingerprint_format,
        check: "original_fingerprint ~ '^[0-9a-f]{64}$'"
      )
    )

    create(
      constraint(
        :app_certificate_renewals,
        :app_certificate_renewals_distinct_certificates,
        check: "current_certificate_id <> issued_certificate_id"
      )
    )

    create(
      constraint(:app_certificate_renewals, :app_certificate_renewals_csr_sha256_size,
        check: "octet_length(csr_sha256) = 32"
      )
    )

    create(
      constraint(
        :app_certificate_renewals,
        :app_certificate_renewals_normalized_payload_sha256_size,
        check: "octet_length(normalized_payload_sha256) = 32"
      )
    )

    create(
      constraint(:app_certificate_renewals, :app_certificate_renewals_proof_nonempty,
        check: "octet_length(proof) > 0"
      )
    )

    create(
      constraint(:app_certificate_renewals, :app_certificate_renewals_proof_algorithm,
        check: "proof_algorithm IN (#{sql_values(@proof_algorithms)})"
      )
    )
  end

  def down do
    drop(table(:app_certificate_renewals))
  end

  defp sql_values(values) do
    Enum.map_join(values, ", ", &"'#{&1}'")
  end
end
