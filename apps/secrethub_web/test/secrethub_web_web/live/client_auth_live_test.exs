defmodule SecretHub.Web.ClientAuthLiveTest do
  use SecretHub.Web.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias SecretHub.Core.PKI.ClientAuth

  setup %{conn: conn} do
    conn = init_test_session(conn, %{admin_id: "test-admin"})
    {:ok, conn: conn}
  end

  test "renders uninitialized state and initializes authority", %{conn: conn} do
    {:ok, view, html} = live(conn, "/admin/pki/client-auth")

    assert html =~ "Client Auth PKI"
    assert html =~ "No Client Auth Authority Initialized"

    # Submit authority initialization form
    init_form_data = %{
      "init" => %{
        "name" => "SecretHub Client Authentication Root CA",
        "key_algorithm" => "ecdsa_p384",
        "default_ttl_days" => "30",
        "max_ttl_days" => "90"
      }
    }

    render_submit(view, :init_authority, init_form_data)

    rendered = render(view)
    assert rendered =~ "Client Auth Authority successfully initialized!"
    assert rendered =~ "Authority Details"
    assert rendered =~ "client-auth"
    assert rendered =~ "ecdsa_p384"
  end

  test "manages identities, certificate issuance, and revocation in LiveView", %{conn: conn} do
    # Ensure initialized
    {:ok, _auth} =
      ClientAuth.init_authority(%{"name" => "Client Auth CA", "key_algorithm" => "ecdsa_p384"})

    {:ok, view, _html} = live(conn, "/admin/pki/client-auth")

    # 1. Create Identity
    render_submit(view, :create_identity, %{
      "identity" => %{
        "name" => "api-worker-test",
        "description" => "Test client worker"
      }
    })

    # Switch to identities tab
    render_click(view, :switch_tab, %{"tab" => "identities"})
    identities_html = render(view)
    assert identities_html =~ "api-worker-test"

    identities = ClientAuth.list_identities()
    identity = Enum.find(identities, &(&1.name == "api-worker-test"))
    assert identity != nil

    # 2. Issue Certificate
    client_key = X509.PrivateKey.new_ec(:secp384r1)
    csr = X509.CSR.new(client_key, "/O=Custom/CN=custom")
    csr_pem = X509.CSR.to_pem(csr)

    render_submit(view, :issue_certificate, %{
      "issue" => %{
        "identity_id" => identity.id,
        "csr_pem" => csr_pem,
        "ttl_days" => "10"
      }
    })

    render_click(view, :switch_tab, %{"tab" => "certificates"})
    certs_html = render(view)
    assert certs_html =~ identity.id

    certs = ClientAuth.list_certificates()
    cert = Enum.find(certs, &(&1.client_auth_identity_id == identity.id))
    assert cert != nil
    refute cert.revoked

    # 3. Revoke Certificate
    render_click(view, :open_revoke_modal, %{"id" => cert.id})
    render_submit(view, :revoke_certificate, %{"revoke" => %{"reason" => "keyCompromise"}})

    certs_html2 = render(view)
    assert certs_html2 =~ "Revoked"

    # 4. Force CRL refresh
    render_click(view, :force_crl_refresh, %{})
    refreshed_html = render(view)
    assert refreshed_html =~ "CRL successfully refreshed"
  end
end
