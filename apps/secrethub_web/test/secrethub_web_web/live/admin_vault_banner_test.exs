defmodule SecretHub.Web.AdminVaultBannerTest do
  use SecretHub.Web.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.Certificate
  alias SecretHub.Shared.Schemas.VaultConfig

  setup %{conn: conn} do
    if pid = Process.whereis(SealState) do
      GenServer.stop(pid)
    end

    Repo.delete_all(VaultConfig)
    Repo.delete_all(Certificate)

    start_supervised!(SealState)
    {:ok, _shares} = SealState.initialize(3, 2)

    conn = init_test_session(conn, %{admin_id: "test-admin"})

    on_exit(fn ->
      if pid = Process.whereis(SealState) do
        GenServer.stop(pid)
      end
    end)

    {:ok, conn: conn}
  end

  test "admin layout shows a vault sealed banner with unseal link", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/admin/pki")

    assert html =~ ~s(id="vault-sealed-banner")
    assert html =~ "Vault sealed"
    assert html =~ "Secret and PKI operations are unavailable until the vault is unsealed."
    assert html =~ ~s(href="/vault/unseal")
    assert html =~ "Unseal vault"
  end

  test "sealed root CA generation uses the app banner instead of form validation", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/admin/pki")

    view
    |> element("button", "Generate Root CA")
    |> render_click()

    html =
      view
      |> form("form[phx-submit='generate_ca']", %{
        "ca" => %{
          "common_name" => "SecretHub Root CA",
          "organization" => "SecretHub",
          "country" => "US",
          "key_type" => "rsa",
          "key_bits" => "2048",
          "ttl_days" => "3650"
        }
      })
      |> render_submit()

    assert html =~ ~s(id="vault-sealed-banner")
    assert html =~ "Vault sealed"
    refute html =~ "Unseal the vault before generating CA certificates."
  end

  test "pki page renders persisted certificates with schema validity fields", %{conn: conn} do
    certificate =
      %Certificate{}
      |> Certificate.changeset(%{
        serial_number: "ABC1234567890",
        fingerprint: "sha256:aa:bb:cc",
        certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        subject: "CN=SecretHub Root CA,O=SecretHub,C=US",
        issuer: "CN=SecretHub Root CA,O=SecretHub,C=US",
        common_name: "SecretHub Root CA",
        organization: "SecretHub",
        valid_from: ~U[2026-04-30 00:00:00Z],
        valid_until: ~U[2036-04-30 00:00:00Z],
        cert_type: :root_ca,
        key_usage: ["key_cert_sign", "crl_sign"]
      })
      |> Repo.insert!()

    {:ok, view, html} = live(conn, "/admin/pki")

    assert html =~ "SecretHub Root CA"
    assert html =~ "Expires: 2036-04-30"

    details_html =
      view
      |> element("button[phx-value-cert_id='#{certificate.id}']", "View Details")
      |> render_click()

    assert details_html =~ "sha256:aa:bb:cc"
    assert details_html =~ "2026-04-30 00:00:00Z"
    assert details_html =~ "2036-04-30 00:00:00Z"
    assert details_html =~ "Issuer:"
    assert details_html =~ "Subject:"
    assert details_html =~ "CN=SecretHub Root CA,O=SecretHub,C=US"
    assert details_html =~ "X509v3 extensions:"
  end

  test "intermediate CA generation requires an existing root CA", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/admin/pki")

    view
    |> element("button", "Generate Intermediate CA")
    |> render_click()

    html =
      view
      |> form("form[phx-submit='generate_ca']", %{
        "ca" => %{
          "common_name" => "SecretHub Intermediate CA",
          "organization" => "SecretHub",
          "country" => "US",
          "parent_ca_id" => "",
          "key_type" => "rsa",
          "key_bits" => "2048",
          "ttl_days" => "1825"
        }
      })
      |> render_submit()

    assert html =~ "Select a Parent CA before generating an Intermediate CA"
  end

  test "intermediate CA form includes parent CA selection", %{conn: conn} do
    certificate =
      %Certificate{}
      |> Certificate.changeset(%{
        serial_number: "PARENT1234567890",
        fingerprint: "sha256:dd:ee:ff",
        certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        subject: "CN=SecretHub Root CA,O=SecretHub,C=US",
        issuer: "CN=SecretHub Root CA,O=SecretHub,C=US",
        common_name: "SecretHub Root CA",
        organization: "SecretHub",
        valid_from: ~U[2026-04-30 00:00:00Z],
        valid_until: ~U[2036-04-30 00:00:00Z],
        cert_type: :root_ca,
        key_usage: ["key_cert_sign", "crl_sign"]
      })
      |> Repo.insert!()

    {:ok, view, _html} = live(conn, "/admin/pki")

    html =
      view
      |> element("button", "Generate Intermediate CA")
      |> render_click()

    assert html =~ "Parent CA"
    assert html =~ "SecretHub Root CA (Root CA)"
    assert html =~ ~s(name="ca[parent_ca_id]")
    assert html =~ ~s(value="#{certificate.id}")
  end

  test "certificate removal requires exact confirmation text", %{conn: conn} do
    certificate =
      %Certificate{}
      |> Certificate.changeset(%{
        serial_number: "REMOVE1234567890",
        fingerprint: "sha256:11:22:33",
        certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        subject: "CN=SecretHub Root CA,O=SecretHub,C=US",
        issuer: "CN=SecretHub Root CA,O=SecretHub,C=US",
        common_name: "SecretHub Root CA",
        organization: "SecretHub",
        valid_from: ~U[2026-04-30 00:00:00Z],
        valid_until: ~U[2036-04-30 00:00:00Z],
        cert_type: :root_ca,
        key_usage: ["key_cert_sign", "crl_sign"]
      })
      |> Repo.insert!()

    {:ok, view, _html} = live(conn, "/admin/pki")

    html =
      view
      |> element("button[phx-value-cert_id='#{certificate.id}']", "Remove")
      |> render_click()

    assert html =~ "Remove Certificate"

    assert html =~
             "I know remove certificate will break everything, I&#39;m sure I want remove it"

    html =
      view
      |> form("form[phx-submit='remove_certificate']", %{
        "remove" => %{"confirmation" => "remove"}
      })
      |> render_submit()

    assert html =~ "Confirmation text does not match"

    html =
      view
      |> form("form[phx-submit='remove_certificate']", %{
        "remove" => %{
          "confirmation" =>
            "I know remove certificate will break everything, I'm sure I want remove it"
        }
      })
      |> render_submit()

    refute html =~ "SecretHub Root CA"
    refute Repo.get(Certificate, certificate.id)
  end
end
