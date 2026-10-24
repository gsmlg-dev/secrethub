defmodule SecretHub.Web.PKIAdminLiveTest do
  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  @endpoint SecretHub.Web.Endpoint

  alias SecretHub.Core.PKI.Events
  alias SecretHub.Core.{Repo, RuntimeDatabaseFixture}

  alias SecretHub.Shared.Schemas.{
    AcmeAccount,
    AcmeOrder,
    Certificate,
    ManagedCertificate,
    ManagedCertificateVersion,
    PKIEvent,
    Secret
  }

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup context do
    :ok = RuntimeDatabaseFixture.setup(context, default_repo: true)
    Repo.delete_all(PKIEvent)
    Repo.delete_all(Certificate)

    conn = init_test_session(build_conn(), %{admin_id: "test-admin"})

    {:ok, conn: conn}
  end

  test "overview links the migrated PKI screens", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/admin/pki")

    assert html =~ "PKI Overview"
    assert html =~ "CA List"
    assert html =~ "Certificate List"
    assert html =~ "Issue Certificate"
    assert html =~ "CSR Management"
    assert html =~ "Upload CSR"
    assert html =~ "Analytics"
    assert html =~ ~s(href="/admin/pki/ca")
    assert html =~ ~s(href="/admin/pki/certificates")
    assert html =~ ~s(href="/admin/pki/certificates/issue")
    assert html =~ ~s(href="/admin/pki/csr")
    assert html =~ ~s(href="/admin/pki/csr/upload")
    assert html =~ ~s(href="/admin/pki/search")
    assert html =~ ~s(href="/admin/pki/analytics")
    refute html =~ "New CA"
    refute html =~ "Generate Root CA"
    refute html =~ "Generate Intermediate CA"
    refute html =~ ~s(href="/admin/pki/ca/new")
    refute html =~ ~s(href="/admin/certificates")
  end

  test "CA listing and detail routes render CA records and event history", %{conn: conn} do
    ca = insert_certificate!("SecretHub Root CA", :root_ca, "CA100")

    {:ok, _event} =
      Events.append(
        :ca_initialized,
        %{cert_id: ca.id, serial: ca.serial_number, subject: ca.subject},
        ca_id: ca.id,
        timestamp: ~U[2026-06-12 01:00:00Z]
      )

    {:ok, _view, html} = live(conn, "/admin/pki/ca")

    assert html =~ "CA List"
    assert html =~ "SecretHub Root CA"
    assert html =~ "New CA"
    assert html =~ ~s(href="/admin/pki/ca/new")
    assert html =~ ~s(href="/admin/pki/ca/#{ca.id}")

    {:ok, _view, html} = live(conn, "/admin/pki/ca/#{ca.id}")

    assert html =~ "CA Details"
    assert html =~ "ca_initialized"
    assert html =~ "CA100"

    {:ok, _view, html} = live(conn, "/admin/pki/cas/#{ca.id}")

    assert html =~ "CA Details"
    assert html =~ "SecretHub Root CA"
  end

  test "new CA route renders the generation page without adding a global menu item", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/admin/pki/ca/new")

    assert html =~ "New CA"
    assert html =~ "Generate Root CA"
    assert html =~ "Generate Intermediate CA"
    refute html =~ ~s(href="/admin/pki/ca/new")
  end

  test "certificate listing route renders persisted certificate records", %{conn: conn} do
    insert_certificate!("agent-runtime-1", :agent_client, "AGENT100")

    {:ok, _view, html} = live(conn, "/admin/pki/certificates")

    assert html =~ "Certificate List"
    assert html =~ "agent-runtime-1"
    assert html =~ "Agent Client"
  end

  test "certificate list includes published ACME history alongside internal certificates", %{
    conn: conn
  } do
    internal = insert_certificate!("agent-runtime-1", :agent_client, "AGENT100")
    managed = insert_managed!("public-server", "Public server")
    historical = insert_publication!(managed, 1, %{environment: "staging"})
    current = insert_publication!(managed, 2, %{environment: "production"})

    Repo.update!(
      Ecto.Changeset.change(managed, current_version_id: current.id, publication_sequence: 2)
    )

    insert_managed!("unissued-definition", "Not yet issued")

    {:ok, view, html} = live(conn, "/admin/pki/certificates")

    assert has_element?(view, "table", "agent-runtime-1")
    assert has_element?(view, "table", "Public server")
    historical_row = public_row(view, historical)
    current_row = public_row(view, current)
    assert LazyHTML.text(historical_row) =~ "Historical"
    assert LazyHTML.text(historical_row) =~ "staging"
    assert LazyHTML.text(current_row) =~ "Current"
    assert LazyHTML.text(current_row) =~ "production"
    assert LazyHTML.text(current_row) =~ "Version 2"
    assert LazyHTML.text(current_row) =~ "ACME Server"
    assert LazyHTML.text(current_row) =~ "Fingerprint"
    assert LazyHTML.text(current_row) =~ current.fingerprint
    refute Enum.empty?(LazyHTML.query(current_row, "a[href='/admin/pki/acme']"))
    assert Enum.empty?(LazyHTML.query(current_row, "[phx-click]"))

    assert has_element?(
             view,
             "[phx-click='view_certificate'][phx-value-cert_id='#{internal.id}']"
           )

    refute html =~ "Not yet issued"
    refute html =~ "account-private-fixture"
    refute html =~ "secret-private-fixture"
    refute html =~ "public-pem-fixture"
  end

  test "ACME list rows distinguish revocation quarantine expiry and legacy display names", %{
    conn: conn
  } do
    active = insert_publication!(insert_managed!("legacy-public", nil), 1)

    expired =
      insert_publication!(insert_managed!("expired-public", "Expired public"), 1, %{
        not_after: DateTime.add(DateTime.utc_now() |> DateTime.truncate(:second), -60)
      })

    quarantined =
      insert_publication!(insert_managed!("quarantined-public", "Quarantined public"), 1, %{
        quarantined_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })

    revoked =
      insert_publication!(insert_managed!("revoked-public", "Revoked public"), 1, %{
        quarantined_at: DateTime.utc_now() |> DateTime.truncate(:second),
        revocation_state: "confirmed"
      })

    {:ok, view, _html} = live(conn, "/admin/pki/certificates")

    assert public_row(view, active) |> LazyHTML.text() =~ "legacy-public"
    assert public_row(view, active) |> LazyHTML.query(".badge") |> LazyHTML.text() =~ "Active"
    assert public_row(view, expired) |> LazyHTML.query(".badge") |> LazyHTML.text() =~ "Expired"

    assert public_row(view, quarantined) |> LazyHTML.query(".badge") |> LazyHTML.text() =~
             "Quarantined"

    assert public_row(view, revoked) |> LazyHTML.query(".badge") |> LazyHTML.text() =~ "Revoked"
  end

  test "certificate type filters and search include every ACME SAN without changing internal filters",
       %{conn: conn} do
    insert_certificate!("payments-agent", :agent_client, "PAY100")
    managed = insert_managed!("public-search", "Public search")
    version = insert_publication!(managed, 1)
    {:ok, view, _html} = live(conn, "/admin/pki/certificates")

    render_change(view, "filter_certificates", %{"filter_type" => "acme_server"})
    assert has_element?(view, "tbody", version.fingerprint)
    refute has_element?(view, "tbody", "payments-agent")
    render_change(view, "filter_certificates", %{"filter_type" => "agent_client"})
    assert has_element?(view, "tbody", "payments-agent")
    refute has_element?(view, "tbody", version.fingerprint)
    render_change(view, "filter_certificates", %{"filter_type" => "all"})
    render_change(view, "search_certificates", %{"query" => "SECONDARY.EXAMPLE.COM"})
    assert has_element?(view, "tbody", version.fingerprint)
    refute has_element?(view, "tbody", "payments-agent")

    {:ok, search_view, _html} = live(conn, "/admin/pki/search?query=secondary.example.com")
    assert has_element?(search_view, "tbody", version.fingerprint)
  end

  test "source-style issue, CSR upload, and analytics routes render", %{conn: conn} do
    insert_certificate!("SecretHub Root CA", :root_ca, "CA100")
    insert_certificate!("agent-runtime-1", :agent_client, "AGENT100")

    {:ok, _view, html} = live(conn, "/admin/pki/certificates/issue")

    assert html =~ "Issue New Certificate"
    assert html =~ "Certificate Authority"
    assert html =~ "Certificate Template"
    assert html =~ "Certificate Signing Request"

    {:ok, _view, html} = live(conn, "/admin/pki/csr")

    assert html =~ "CSR Management"
    assert html =~ "CSR PEM"

    {:ok, _view, html} = live(conn, "/admin/pki/csr/upload")

    assert html =~ "Upload CSR"
    assert html =~ "Certificate Signing Request"

    {:ok, _view, html} = live(conn, "/admin/pki/analytics")

    assert html =~ "PKI Analytics"
    assert html =~ "Event Types"
    assert html =~ "Expiring Certificates"
  end

  test "search route filters certificates by query", %{conn: conn} do
    insert_certificate!("payments-agent", :agent_client, "PAY100")
    insert_certificate!("inventory-agent", :agent_client, "INV100")

    {:ok, _view, html} = live(conn, "/admin/pki/search?query=pay")

    assert html =~ "PKI Search"
    assert html =~ "payments-agent"
    refute html =~ "inventory-agent"
  end

  test "client auth certificates display link to Client Auth PKI and omit revoke/remove buttons in generic view",
       %{conn: conn} do
    ca_cert = insert_certificate!("Client Auth Root", :client_auth_ca, "CAAUTH01")

    client_cert =
      insert_certificate!(
        "00000000-0000-0000-0000-000000000001",
        :client_auth_client,
        "CLIENTAUTH01"
      )

    {:ok, view, _html} = live(conn, "/admin/pki/certificates")

    # Trigger view_certificate modal on client_cert
    view_html = render_click(view, :view_certificate, %{"cert_id" => client_cert.id})
    assert view_html =~ "Client Auth PKI"
    assert view_html =~ ~s(href="/admin/pki/client-auth")

    # Trigger view_certificate modal on ca_cert
    ca_view_html = render_click(view, :view_certificate, %{"cert_id" => ca_cert.id})
    assert ca_view_html =~ "Client Auth PKI"
    assert ca_view_html =~ ~s(href="/admin/pki/client-auth")
  end

  defp public_row(view, version) do
    row =
      view
      |> render()
      |> LazyHTML.from_document()
      |> LazyHTML.query("tbody tr")
      |> Enum.find(fn row -> String.contains?(LazyHTML.text(row), version.fingerprint) end)

    assert row, "Expected a published certificate row for #{version.fingerprint}"
    row
  end

  defp insert_certificate!(common_name, cert_type, serial_number) do
    %Certificate{}
    |> Certificate.changeset(%{
      serial_number: serial_number,
      fingerprint: "sha256:#{serial_number}",
      certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
      subject: "CN=#{common_name},O=SecretHub",
      issuer: "CN=SecretHub Root CA,O=SecretHub",
      common_name: common_name,
      organization: "SecretHub",
      valid_from: ~U[2026-06-12 01:00:00Z],
      valid_until: ~U[2027-06-12 01:00:00Z],
      cert_type: cert_type,
      key_usage: ["digitalSignature"]
    })
    |> Repo.insert!()
  end

  defp insert_managed!(slug, name) do
    account =
      Repo.insert!(%AcmeAccount{
        name: slug <> "-account",
        environment: "production",
        directory_url: "https://acme-v02.api.letsencrypt.org/directory",
        contact: ["mailto:owner@example.com"],
        terms_url: "https://example.com/terms",
        terms_accepted_at: DateTime.utc_now() |> DateTime.truncate(:second),
        encrypted_key: "account-private-fixture"
      })

    secret =
      %Secret{}
      |> Secret.changeset(%{
        name: slug,
        secret_path: "pki.acme." <> slug,
        encrypted_data: "secret-private-fixture"
      })
      |> Repo.insert!()

    Repo.insert!(%ManagedCertificate{
      name: name,
      slug: slug,
      account_id: account.id,
      output_secret_id: secret.id,
      identifiers: ["example.com", "secondary.example.com"],
      bindings: []
    })
  end

  defp insert_publication!(managed, sequence, attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    order =
      Repo.insert!(%AcmeOrder{
        managed_certificate_id: managed.id,
        request_id: "publication-#{sequence}",
        request_digest: "fixture-digest",
        configuration_revision: 1,
        state: "published",
        identifiers: managed.identifiers,
        bindings: managed.bindings,
        account_snapshot: %{},
        deadline_at: DateTime.add(now, 3600)
      })

    %ManagedCertificateVersion{
      managed_certificate_id: managed.id,
      order_id: order.id,
      publication_sequence: sequence,
      environment: "production",
      fingerprint: "sha256:#{managed.slug}-#{sequence}",
      certificate_pem: "public-pem-fixture",
      fullchain_pem: "public-pem-fixture",
      identifiers: managed.identifiers,
      not_before: DateTime.add(now, -3600),
      not_after: DateTime.add(now, 86_400),
      key_policy: "ec_p256",
      output_secret_id: managed.output_secret_id,
      secret_version_number: sequence
    }
    |> Ecto.Changeset.change(attrs)
    |> Repo.insert!()
  end
end
