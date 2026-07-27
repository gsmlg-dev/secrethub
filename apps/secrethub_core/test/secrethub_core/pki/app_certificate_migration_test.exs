defmodule SecretHub.Core.PKI.AppCertificateMigrationTest do
  use SecretHub.Core.DataCase, async: true

  alias SecretHub.Shared.Schemas.{
    AppBootstrapToken,
    AppCertificateRenewal,
    Application,
    Certificate
  }

  @canonical_fingerprint String.duplicate("a", 64)

  test "canonical fingerprints are nullable and have a partial unique index" do
    assert %Postgrex.Result{rows: [["YES"]]} =
             Repo.query!("""
             SELECT is_nullable
             FROM information_schema.columns
             WHERE table_schema = 'public'
               AND table_name = 'certificates'
               AND column_name = 'canonical_fingerprint'
             """)

    assert %Postgrex.Result{rows: [[index_definition]]} =
             Repo.query!("""
             SELECT indexdef
             FROM pg_indexes
             WHERE schemaname = 'public'
               AND tablename = 'certificates'
               AND indexname = 'certificates_canonical_fingerprint_unique'
             """)

    assert index_definition =~ "CREATE UNIQUE INDEX"
    assert index_definition =~ "WHERE (canonical_fingerprint IS NOT NULL)"

    assert %Postgrex.Result{rows: [[constraint_definition]]} =
             Repo.query!("""
             SELECT pg_get_constraintdef(oid)
             FROM pg_constraint
             WHERE conname = 'certificates_canonical_fingerprint_format'
             """)

    assert constraint_definition =~ "canonical_fingerprint IS NULL"
    assert constraint_definition =~ "^[0-9a-f]{64}$"

    assert :ok = insert_certificate_with_canonical_fingerprint(nil)
    assert :ok = insert_certificate_with_canonical_fingerprint(@canonical_fingerprint)
  end

  test "canonical fingerprints are unique when present" do
    assert :ok = insert_certificate_with_canonical_fingerprint(@canonical_fingerprint)

    error =
      assert_raise Postgrex.Error, fn ->
        insert_certificate_with_canonical_fingerprint(@canonical_fingerprint)
      end

    assert error.postgres.code == :unique_violation
    assert error.postgres.constraint == "certificates_canonical_fingerprint_unique"
  end

  test "canonical fingerprints reject uppercase hexadecimal values" do
    error =
      assert_raise Postgrex.Error, fn ->
        insert_certificate_with_canonical_fingerprint(String.upcase(@canonical_fingerprint))
      end

    assert error.postgres.code == :check_violation
    assert error.postgres.constraint == "certificates_canonical_fingerprint_format"
  end

  test "certificate changesets reject noncanonical fingerprints before database access" do
    changeset =
      Certificate.changeset(%Certificate{}, certificate_attrs(%{canonical_fingerprint: "ABC"}))

    assert %{
             canonical_fingerprint: [
               "must be a 64-character lowercase hexadecimal SHA-256 fingerprint"
             ]
           } =
             errors_on(changeset)
  end

  test "bootstrap tokens carry issuance idempotency references" do
    request_id = Ecto.UUID.generate()
    certificate_id = Ecto.UUID.generate()

    changeset =
      AppBootstrapToken.changeset(%AppBootstrapToken{}, %{
        app_id: Ecto.UUID.generate(),
        token_hash: "token-hash",
        expires_at: ~U[2026-07-28 00:00:00Z],
        issuance_request_id: request_id,
        issued_certificate_id: certificate_id
      })

    assert %{issuance_request_id: ^request_id, issued_certificate_id: ^certificate_id} =
             changeset.changes

    assert %{field: :issued_certificate} =
             AppBootstrapToken.__schema__(:association, :issued_certificate)

    assert %Postgrex.Result{
             rows: [
               ["issuance_request_id", "uuid", "YES"],
               ["issued_certificate_id", "uuid", "YES"]
             ]
           } =
             Repo.query!("""
             SELECT column_name, data_type, is_nullable
             FROM information_schema.columns
             WHERE table_schema = 'public'
               AND table_name = 'app_bootstrap_tokens'
               AND column_name IN ('issuance_request_id', 'issued_certificate_id')
             ORDER BY column_name
             """)

    assert %Postgrex.Result{rows: [["certificates", "r", true]]} =
             Repo.query!("""
             SELECT target.relname, constraint_row.confdeltype, constraint_row.convalidated
             FROM pg_constraint AS constraint_row
             JOIN pg_class AS target ON target.oid = constraint_row.confrelid
             WHERE constraint_row.conname = 'app_bootstrap_tokens_issued_certificate_id_fkey'
             """)
  end

  test "application certificate renewals bind the request payload and reject unsupported proof algorithms" do
    renewal = struct(AppCertificateRenewal)

    valid_changeset = AppCertificateRenewal.changeset(renewal, renewal_attrs())

    assert valid_changeset.valid?

    invalid_changeset =
      AppCertificateRenewal.changeset(
        renewal,
        Map.put(renewal_attrs(), :proof_algorithm, "ed25519")
      )

    assert %{proof_algorithm: ["is invalid"]} = errors_on(invalid_changeset)

    invalid_fingerprint_changeset =
      AppCertificateRenewal.changeset(
        renewal,
        Map.put(renewal_attrs(), :original_fingerprint, "ABC")
      )

    assert %{
             original_fingerprint: [
               "must be a 64-character lowercase hexadecimal SHA-256 fingerprint"
             ]
           } = errors_on(invalid_fingerprint_changeset)

    same_certificate_id = Ecto.UUID.generate()

    same_certificate_changeset =
      AppCertificateRenewal.changeset(
        renewal,
        renewal_attrs()
        |> Map.put(:current_certificate_id, same_certificate_id)
        |> Map.put(:issued_certificate_id, same_certificate_id)
      )

    assert %{issued_certificate_id: ["must differ from current_certificate_id"]} =
             errors_on(same_certificate_changeset)

    assert %{field: :certificate_renewals} =
             Application.__schema__(:association, :certificate_renewals)
  end

  test "renewal storage is request-idempotent and applications have a validated agent foreign key" do
    assert %Postgrex.Result{rows: [[true, "agents", "a"]]} =
             Repo.query!("""
             SELECT constraint_row.convalidated, target.relname, constraint_row.confdeltype
             FROM pg_constraint AS constraint_row
             JOIN pg_class AS target ON target.oid = constraint_row.confrelid
             WHERE constraint_row.conname = 'applications_agent_id_fkey'
             """)

    assert %Postgrex.Result{rows: [[true, ["app_id", "request_id"]]]} =
             Repo.query!("""
             SELECT pg_index.indisunique,
                    array_agg(attribute.attname ORDER BY key_columns.ordinality)
             FROM pg_index
             JOIN pg_class ON pg_class.oid = pg_index.indexrelid
             JOIN unnest(pg_index.indkey) WITH ORDINALITY AS key_columns(attnum, ordinality)
               ON TRUE
             JOIN pg_attribute AS attribute
               ON attribute.attrelid = pg_index.indrelid
              AND attribute.attnum = key_columns.attnum
             WHERE pg_class.relname = 'app_certificate_renewals_app_id_request_id_index'
             GROUP BY pg_class.relname, pg_index.indisunique
             """)

    assert %Postgrex.Result{
             rows: [
               ["app_id", "uuid", "NO"],
               ["csr_sha256", "bytea", "NO"],
               ["current_certificate_id", "uuid", "NO"],
               ["issued_certificate_id", "uuid", "NO"],
               ["normalized_payload_sha256", "bytea", "NO"],
               ["original_fingerprint", "character varying", "NO"],
               ["proof", "bytea", "NO"],
               ["proof_algorithm", "character varying", "NO"],
               ["request_id", "uuid", "NO"]
             ]
           } =
             Repo.query!("""
             SELECT column_name, data_type, is_nullable
             FROM information_schema.columns
             WHERE table_schema = 'public'
               AND table_name = 'app_certificate_renewals'
               AND column_name IN (
                 'app_id',
                 'csr_sha256',
                 'current_certificate_id',
                 'issued_certificate_id',
                 'normalized_payload_sha256',
                 'original_fingerprint',
                 'proof',
                 'proof_algorithm',
                 'request_id'
               )
             ORDER BY column_name
             """)

    assert %Postgrex.Result{
             rows: [
               ["app_certificate_renewals_app_id_fkey", "applications", "r"],
               ["app_certificate_renewals_current_certificate_id_fkey", "certificates", "r"],
               ["app_certificate_renewals_issued_certificate_id_fkey", "certificates", "r"]
             ]
           } =
             Repo.query!("""
             SELECT constraint_row.conname, target.relname, constraint_row.confdeltype
             FROM pg_constraint AS constraint_row
             JOIN pg_class AS target ON target.oid = constraint_row.confrelid
             WHERE constraint_row.conrelid = 'app_certificate_renewals'::regclass
               AND constraint_row.contype = 'f'
             ORDER BY constraint_row.conname
             """)
  end

  defp insert_certificate_with_canonical_fingerprint(canonical_fingerprint) do
    suffix = System.unique_integer([:positive])

    Repo.query!(
      """
      INSERT INTO certificates (
        id, serial_number, fingerprint, certificate_pem, subject, issuer, common_name,
        valid_from, valid_until, cert_type, canonical_fingerprint, inserted_at, updated_at
      )
      VALUES (
        gen_random_uuid(), $1, $2, 'pem', 'subject', 'issuer', 'common-name',
        NOW(), NOW() + INTERVAL '1 day', 'app_client', $3, NOW(), NOW()
      )
      """,
      ["serial-#{suffix}", "legacy-#{suffix}", canonical_fingerprint]
    )

    :ok
  end

  defp certificate_attrs(overrides) do
    Map.merge(
      %{
        serial_number: "serial-#{System.unique_integer([:positive])}",
        fingerprint: "legacy-fingerprint-#{System.unique_integer([:positive])}",
        certificate_pem: "pem",
        subject: "subject",
        issuer: "issuer",
        common_name: "common-name",
        valid_from: ~U[2026-07-28 00:00:00Z],
        valid_until: ~U[2026-07-29 00:00:00Z],
        cert_type: :app_client
      },
      overrides
    )
  end

  defp renewal_attrs do
    %{
      app_id: Ecto.UUID.generate(),
      current_certificate_id: Ecto.UUID.generate(),
      issued_certificate_id: Ecto.UUID.generate(),
      request_id: Ecto.UUID.generate(),
      original_fingerprint: @canonical_fingerprint,
      csr_sha256: :crypto.strong_rand_bytes(32),
      normalized_payload_sha256: :crypto.strong_rand_bytes(32),
      proof: <<1, 2, 3>>,
      proof_algorithm: "rsa-pss-sha256"
    }
  end
end
