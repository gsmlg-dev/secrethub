defmodule SecretHub.Web.AcmeManagementTest do
  use ExUnit.Case, async: false
  import Phoenix.ConnTest
  import Plug.Conn
  alias SecretHub.Core.RuntimeDatabaseFixture

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    if tags[:database], do: RuntimeDatabaseFixture.setup(tags)
    {:ok, conn: build_conn()}
  end

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{AcmeAccount, DNSProvider}
  alias SecretHub.Web.{AcmeController, AcmeLive, TrustStoresLive}
  import Phoenix.LiveViewTest, only: [render_component: 2]

  test "public trust export has exact digest and no vault dependency", %{conn: conn} do
    response = AcmeController.trust_bundle(conn, %{"id" => "mozilla_webpki"})
    assert response.status == 200
    assert response.resp_body =~ "-----BEGIN CERTIFICATE-----"
    assert get_resp_header(response, "content-type") == ["application/x-pem-file; charset=utf-8"]
    assert [digest] = get_resp_header(response, "x-content-sha256")
    assert digest == Base.encode16(:crypto.hash(:sha256, response.resp_body), case: :lower)
  end

  @tag :database
  test "management list allowlists public state and omits encrypted keys", %{conn: conn} do
    account =
      Repo.insert!(%AcmeAccount{
        name: "staging-account",
        environment: "staging",
        directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory",
        contact: [],
        terms_url: "https://letsencrypt.org/repository/",
        terms_accepted_at: DateTime.utc_now() |> DateTime.truncate(:second),
        encrypted_key: "must-never-serialize"
      })

    response = AcmeController.index(conn, %{})
    decoded = Jason.decode!(response.resp_body)
    assert [%{"id" => id, "name" => "staging-account"}] = decoded["data"]["accounts"]
    assert id == account.id
    refute response.resp_body =~ "encrypted_key"
    refute response.resp_body =~ "must-never-serialize"
  end

  @tag :database
  test "provider configuration accepts encrypted references without plaintext credentials", %{
    conn: conn
  } do
    response =
      AcmeController.create_provider(conn, %{
        "name" => "route53-test",
        "provider" => "route53",
        "credential_mode" => "aws_environment",
        "zones" => [%{"zone_id" => "ZPUBLIC", "zone_name" => "example.com"}]
      })

    assert response.status == 201

    assert %{"data" => %{"provider" => "route53", "credential_mode" => "aws_environment"}} =
             Jason.decode!(response.resp_body)

    assert [%DNSProvider{name: "route53-test"}] = Repo.all(DNSProvider)
  end

  @tag :database
  test "invalid IDs return an error without internal exception details", %{conn: conn} do
    response = AcmeController.show(conn, %{"id" => "invalid"})
    assert response.status in [400, 404]
    refute response.resp_body =~ "Ecto"
  end

  @tag :database
  test "existing account terms update requires explicit fresh acceptance", %{conn: conn} do
    account =
      Repo.insert!(%AcmeAccount{
        name: "terms-account",
        environment: "staging",
        directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory",
        contact: [],
        terms_url: "https://example.com/old-terms",
        terms_accepted_at: DateTime.utc_now() |> DateTime.truncate(:second),
        encrypted_key: "encrypted-fixture"
      })

    rejected =
      AcmeController.update_account(conn, %{
        "id" => account.id,
        "terms_url" => "https://example.com/new-terms",
        "terms_accepted" => false
      })

    assert rejected.status == 400
    assert Repo.get!(AcmeAccount, account.id).terms_url == "https://example.com/old-terms"

    accepted =
      AcmeController.update_account(conn, %{
        "id" => account.id,
        "terms_url" => "https://example.com/new-terms",
        "terms_accepted" => true
      })

    assert accepted.status == 200
    assert Repo.get!(AcmeAccount, account.id).terms_url == "https://example.com/new-terms"
    refute accepted.resp_body =~ "encrypted-fixture"
    socket = %Phoenix.LiveView.Socket{assigns: %{__changed__: %{}, flash: %{}}}
    {:ok, socket} = AcmeLive.mount(%{}, %{}, socket)
    {:noreply, socket} = AcmeLive.handle_event("edit_account", %{"id" => account.id}, socket)
    assert socket.assigns.account_edit_id == account.id
    assert socket.assigns.account_form["terms_accepted"] == "false"
  end

  test "public trust view supports root search without private material" do
    socket = %Phoenix.LiveView.Socket{assigns: %{__changed__: %{}, flash: %{}}}
    assert {:ok, socket} = TrustStoresLive.mount(%{}, %{}, socket)
    html = render_component(&TrustStoresLive.render/1, socket.assigns)
    assert html =~ "Mozilla-derived TLS root CA bundle"
    assert html =~ "SHA-256"
    refute html =~ "PRIVATE KEY"

    assert {:noreply, searched} =
             TrustStoresLive.handle_event("search", %{"query" => "not-an-existing-root"}, socket)

    assert searched.assigns.roots == []
  end

  @tag :database
  test "ACME view renders explicit provider/account/certificate configuration and cleanup" do
    socket = %Phoenix.LiveView.Socket{assigns: %{__changed__: %{}, flash: %{}}}
    assert {:ok, socket} = AcmeLive.mount(%{}, %{}, socket)
    html = render_component(&AcmeLive.render/1, socket.assigns)
    assert html =~ "Public server certificates"
    assert html =~ "Route 53"
    assert html =~ "Cloudflare"
    assert html =~ "Terms"
    assert html =~ "DNS cleanup"
    refute html =~ "PRIVATE KEY"
  end

  test "new operations belong only to private management routes" do
    management =
      Phoenix.Router.route_info(
        SecretHub.Web.Router,
        "POST",
        "/admin/api/pki/acme/certificates",
        "localhost"
      )

    assert :admin_api in management.pipe_through

    machine =
      Phoenix.Router.route_info(
        SecretHub.Web.MachineRouter,
        "POST",
        "/admin/api/pki/acme/certificates",
        "localhost"
      )

    assert machine.plug == SecretHub.Web.ErrorController
    assert machine.plug_opts == :not_found
  end

  test "issuance requires an explicit bounded idempotency request ID", %{conn: conn} do
    for params <- [
          %{"id" => "unused"},
          %{"id" => "unused", "request_id" => ""},
          %{"id" => "unused", "request_id" => String.duplicate("x", 161)}
        ] do
      response = AcmeController.issue(conn, params)
      assert response.status == 400
      assert Jason.decode!(response.resp_body)["error"] == "request_id_required"
    end
  end

  test "failed private export is never cacheable", %{conn: conn} do
    response = AcmeController.export(conn, %{"id" => "invalid"})
    assert response.status in [400, 404]
    assert get_resp_header(response, "cache-control") == ["no-store"]
    assert get_resp_header(response, "pragma") == ["no-cache"]
    refute response.resp_body =~ "PRIVATE KEY"
  end

  test "unsupported revocation reason is rejected before touching a version", %{conn: conn} do
    response = AcmeController.revoke(conn, %{"id" => "unused", "reason" => "2"})
    assert response.status == 400
    assert Jason.decode!(response.resp_body)["error"] == "unsupported_revocation_reason"
  end

  @tag :database
  test "adding DNS zones and SAN bindings preserves unsaved form values" do
    socket = %Phoenix.LiveView.Socket{assigns: %{__changed__: %{}, flash: %{}}}
    {:ok, socket} = AcmeLive.mount(%{}, %{}, socket)

    provider = %{
      "name" => "cloudflare",
      "zones" => %{"0" => %{"zone_id" => "owned", "zone_name" => "example.com"}}
    }

    {:noreply, socket} =
      AcmeLive.handle_event("provider_change", %{"provider" => provider}, socket)

    {:noreply, socket} = AcmeLive.handle_event("add_zone", %{}, socket)
    assert socket.assigns.provider_form["name"] == "cloudflare"
    assert [%{"zone_id" => "owned"}, %{}] = socket.assigns.zone_rows

    managed = %{
      "slug" => "web",
      "identifiers" => "example.com",
      "bindings" => %{"0" => %{"suffix" => "example.com", "provider_zone" => "provider|zone"}}
    }

    {:noreply, socket} = AcmeLive.handle_event("managed_change", %{"managed" => managed}, socket)
    {:noreply, socket} = AcmeLive.handle_event("add_binding", %{}, socket)
    assert socket.assigns.managed_form["identifiers"] == "example.com"
    assert [%{"suffix" => "example.com"}, %{}] = socket.assigns.binding_rows
  end

  test "disabling ACME blocks new work while preserving recovery and inspection routes" do
    previous = Application.fetch_env(:secrethub_core, :acme_enabled)
    Application.put_env(:secrethub_core, :acme_enabled, false)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:secrethub_core, :acme_enabled, value)
        :error -> Application.delete_env(:secrethub_core, :acme_enabled)
      end
    end)

    alias SecretHub.Web.Plugs.LaunchFeatures
    blocked = LaunchFeatures.call(build_conn(:post, "/admin/api/pki/acme/certificates"), [])
    assert blocked.status == 503
    assert blocked.halted

    for path <- [
          "/admin/api/pki/acme/orders/order/cancel",
          "/admin/api/pki/acme/versions/version/revoke",
          "/admin/api/pki/acme/cleanup/operation/retry"
        ] do
      refute LaunchFeatures.call(build_conn(:post, path), []).halted
    end

    refute LaunchFeatures.call(build_conn(:get, "/admin/pki/acme"), []).halted
    assert LaunchFeatures.allowed_view?(AcmeLive)
    socket = %Phoenix.LiveView.Socket{assigns: %{__changed__: %{}, flash: %{}}}
    {:noreply, socket} = AcmeLive.handle_event("save_provider", %{"provider" => %{}}, socket)
    assert socket.assigns.flash["error"] =~ "disabled"
  end

  test "private management mutations retain CSRF protection" do
    conn =
      build_conn(:post, "/admin/api/pki/acme/certificates", %{})
      |> init_test_session(%{})
      |> put_private(:plug_skip_csrf_protection, false)

    error =
      assert_raise Plug.Conn.WrapperError, fn ->
        SecretHub.Web.Router.call(conn, SecretHub.Web.Router.init([]))
      end

    assert %Plug.CSRFProtection.InvalidCSRFTokenError{} = error.reason
  end
end
