defmodule SecretHub.Core.PKI.ClientAuthMigrationTest do
  use ExUnit.Case, async: false

  alias SecretHub.Core.PKI.ClientAuth
  alias SecretHub.Core.Repo

  @migration_version 20_260_830_000_001
  Code.require_file(
    Path.join(
      Application.app_dir(:secrethub_core, "priv/repo/migrations"),
      "20260830000001_create_client_auth_pki.exs"
    )
  )

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})

    clean_client_auth_tables()

    on_exit(fn ->
      :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)

      try do
        clean_client_auth_tables()
      after
        Ecto.Adapters.SQL.Sandbox.checkin(Repo)
      end
    end)

    :ok
  end

  test "migration rollback (down) cleanly tears down client auth schema with populated data" do
    # 1. Initialize authority
    {:ok, initialized} = ClientAuth.initialize_authority()
    assert initialized.authority.slug == "client-auth"

    # 2. Create identity
    {:ok, identity} = ClientAuth.create_identity(%{"name" => "migration-test-agent"})

    # 3. Issue certificate
    key = X509.PrivateKey.new_ec(:secp256r1)
    csr_pem = key |> X509.CSR.new("/CN=migration-test") |> X509.CSR.to_pem()
    request_id = Ecto.UUID.generate()

    assert {:ok, _issued} = ClientAuth.issue_certificate(identity.id, csr_pem, request_id)

    # 4. Record bundle receipt
    {:ok, current_bundle} = ClientAuth.current_bundle()

    assert {:ok, _receipt} =
             ClientAuth.record_bundle_receipt(%{
               "authority_slug" => "client-auth",
               "agent_id" => "agent-migration-1",
               "generation" => current_bundle["generation"],
               "crl_number" => current_bundle["crl_number"],
               "bundle_sha256" => current_bundle["bundle_sha256"],
               "status" => "applied",
               "applied_at" => DateTime.utc_now()
             })

    # 5. Run migration down for Client Auth PKI
    _ =
      Ecto.Migration.Runner.run(
        Repo,
        Repo.config(),
        @migration_version,
        SecretHub.Core.Repo.Migrations.CreateClientAuthPki,
        :forward,
        :down,
        :down,
        log: false
      )

    # Verify tables are dropped without FK errors
    refute table_exists?("client_auth_bundle_receipts")
    refute table_exists?("client_auth_issuance_requests")
    refute table_exists?("client_auth_crls")
    refute table_exists?("client_auth_identities")
    refute table_exists?("client_auth_authorities")

    # 6. Run migration up again to verify clean re-application
    _ =
      Ecto.Migration.Runner.run(
        Repo,
        Repo.config(),
        @migration_version,
        SecretHub.Core.Repo.Migrations.CreateClientAuthPki,
        :forward,
        :up,
        :up,
        log: false
      )

    assert table_exists?("client_auth_authorities")
    assert table_exists?("client_auth_identities")
    assert table_exists?("client_auth_crls")
    assert table_exists?("client_auth_issuance_requests")
    assert table_exists?("client_auth_bundle_receipts")

    # Clean up created rows
    clean_client_auth_tables()
  end

  defp clean_client_auth_tables do
    if table_exists?("client_auth_authorities") do
      _ = Repo.query("DELETE FROM client_auth_bundle_receipts", [])
      _ = Repo.query("DELETE FROM client_auth_issuance_requests", [])
      _ = Repo.query("UPDATE client_auth_authorities SET current_crl_id = NULL", [])
      _ = Repo.query("DELETE FROM client_auth_crls", [])

      _ =
        Repo.query(
          "DELETE FROM certificates WHERE cert_type IN ('client_auth_client', 'client_auth_ca')",
          []
        )

      _ = Repo.query("DELETE FROM client_auth_identities", [])
      _ = Repo.query("DELETE FROM client_auth_authorities", [])
    end
  end

  defp table_exists?(table_name) do
    query =
      "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1"

    case Repo.query(query, [table_name]) do
      {:ok, %{num_rows: n}} -> n > 0
      _ -> false
    end
  end
end
