defmodule SecretHub.Web.PKIAdminLiveTest do
  use SecretHub.Web.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias SecretHub.Core.PKI.Events
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Certificate, PKIEvent}

  setup %{conn: conn} do
    Repo.delete_all(PKIEvent)
    Repo.delete_all(Certificate)

    conn = init_test_session(conn, %{admin_id: "test-admin"})

    {:ok, conn: conn}
  end

  test "overview links the migrated PKI screens", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/admin/pki")

    assert html =~ "PKI Overview"
    assert html =~ ~s(href="/admin/pki/cas")
    assert html =~ ~s(href="/admin/pki/certificates")
    assert html =~ ~s(href="/admin/pki/csr")
    assert html =~ ~s(href="/admin/pki/search")
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

    {:ok, _view, html} = live(conn, "/admin/pki/cas")

    assert html =~ "Certificate Authorities"
    assert html =~ "SecretHub Root CA"
    assert html =~ ~s(href="/admin/pki/cas/#{ca.id}")

    {:ok, _view, html} = live(conn, "/admin/pki/cas/#{ca.id}")

    assert html =~ "CA Details"
    assert html =~ "ca_initialized"
    assert html =~ "CA100"
  end

  test "certificate listing route renders persisted certificate records", %{conn: conn} do
    insert_certificate!("agent-runtime-1", :agent_client, "AGENT100")

    {:ok, _view, html} = live(conn, "/admin/pki/certificates")

    assert html =~ "PKI Certificates"
    assert html =~ "agent-runtime-1"
    assert html =~ "Agent Client"
  end

  test "search route filters certificates by query", %{conn: conn} do
    insert_certificate!("payments-agent", :agent_client, "PAY100")
    insert_certificate!("inventory-agent", :agent_client, "INV100")

    {:ok, _view, html} = live(conn, "/admin/pki/search?query=pay")

    assert html =~ "PKI Search"
    assert html =~ "payments-agent"
    refute html =~ "inventory-agent"
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
end
