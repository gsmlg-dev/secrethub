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

    if tags[:account_registration] do
      {:ok, oban} =
        Oban.start_link(
          name: SecretHub.Core.Oban,
          repo: SecretHub.Core.Repo,
          get_dynamic_repo: fn -> :runtime_authorization_fixture end,
          testing: :disabled,
          queues: false,
          plugins: false
        )

      Process.unlink(oban)
      on_exit(fn -> if Process.alive?(oban), do: Supervisor.stop(oban) end)
    end

    {:ok, conn: build_conn()}
  end

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{AcmeAccount, DNSProvider, ManagedCertificate, Secret}
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
  @tag :account_registration
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
  test "ACME view links to dedicated DNS provider configuration" do
    socket = %Phoenix.LiveView.Socket{assigns: %{__changed__: %{}, flash: %{}}}
    assert {:ok, socket} = AcmeLive.mount(%{}, %{}, socket)
    html = render_component(&AcmeLive.render/1, socket.assigns)
    assert html =~ "Public server certificates"
    assert html =~ ~s(href="/admin/pki/acme/dns-providers")
    assert html =~ ~s(phx-click="new_account")
    assert html =~ ~s(phx-click="new_managed")
    refute html =~ ~s(id="account-form")
    refute html =~ ~s(id="managed-certificate-form")
    assert html =~ "DNS cleanup"
    refute html =~ ~s(id="provider-form")
    refute html =~ "PRIVATE KEY"

    provider_socket = %Phoenix.LiveView.Socket{
      assigns: %{__changed__: %{}, flash: %{}, live_action: :dns_providers}
    }

    assert {:ok, provider_socket} = AcmeLive.mount(%{}, %{}, provider_socket)
    provider_html = render_component(&AcmeLive.render/1, provider_socket.assigns)
    assert provider_html =~ ~s(phx-click="new_provider")
    assert provider_html =~ "Add DNS provider"
    refute provider_html =~ ~s(id="provider-form")
    assert provider_html =~ ~s(href="/admin/pki/acme")
    refute provider_html =~ ~s(id="account-form")
    refute provider_html =~ ~s(id="managed-certificate-form")
    refute provider_html =~ "PRIVATE KEY"

    route =
      Phoenix.Router.route_info(
        SecretHub.Web.Router,
        "GET",
        "/admin/pki/acme/dns-providers",
        "localhost"
      )

    assert :admin_browser in route.pipe_through
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
  test "DNS provider page lists saved providers and opens create and edit forms in a modal" do
    credential = credential_metadata("prod.cloudflare")

    saved =
      Repo.insert!(%DNSProvider{
        name: "Saved Cloudflare",
        provider: "cloudflare",
        credential_secret_id: credential.id,
        zones: [%{"zone_id" => "saved-zone", "zone_name" => "example.com"}]
      })

    socket = provider_socket()
    html = render_component(&AcmeLive.render/1, socket.assigns)
    assert html =~ "Saved Cloudflare"
    assert html =~ "example.com"
    assert html =~ "<table"
    refute html =~ ~s(id="provider-form")

    {:noreply, socket} = AcmeLive.handle_event("new_provider", %{}, socket)
    assert socket.assigns.provider_modal_open
    html = render_component(&AcmeLive.render/1, socket.assigns)
    assert html =~ ~s(phx-hook="FormModal")
    assert html =~ ~s(data-close-event="close_provider_modal")
    assert html =~ ~s(id="provider-form")
    assert html =~ "Credential secret path"
    assert html =~ "Route 53"
    assert html =~ "Cloudflare"
    refute html =~ "Public zone ID"
    refute html =~ "Zone DNS name"

    {:noreply, socket} = AcmeLive.handle_event("close_provider_modal", %{}, socket)
    refute socket.assigns.provider_modal_open
    refute render_component(&AcmeLive.render/1, socket.assigns) =~ ~s(id="provider-form")

    {:noreply, socket} = AcmeLive.handle_event("edit_provider", %{"id" => saved.id}, socket)
    assert socket.assigns.provider_modal_open
    assert socket.assigns.provider_edit_id == saved.id
    assert socket.assigns.provider_form["credential_secret_path"] == credential.secret_path
    assert socket.assigns.selected_zone_ids == ["saved-zone"]
    assert socket.assigns.zone_choices == saved.zones
  end

  @tag :database
  test "credential autocomplete contains only current usable static secret paths" do
    usable = credential_metadata("prod.cloudflare")
    dynamic = credential_metadata("prod.dynamic")
    inactive = credential_metadata("prod.inactive")
    Repo.update!(Ecto.Changeset.change(dynamic, secret_type: :dynamic))
    Repo.update!(Ecto.Changeset.change(inactive, status: "error"))

    {:noreply, socket} = AcmeLive.handle_event("new_provider", %{}, provider_socket())

    assert socket.assigns.credential_secrets == [
             %{id: usable.id, secret_path: usable.secret_path}
           ]

    html = render_component(&AcmeLive.render/1, socket.assigns)
    assert html =~ ~s(name="provider[credential_secret_path]")
    assert html =~ ~s(<datalist)
    assert html =~ ~s(value="prod.cloudflare")
    refute html =~ dynamic.secret_path
    refute html =~ inactive.secret_path
    refute html =~ usable.id
    refute html =~ "encrypted-credential-fixture"
    refute html =~ ~s(name="provider[credential_secret_id]")
  end

  @tag :database
  test "changing provider credentials invalidates choices while other form edits preserve selection" do
    original = credential_metadata("prod.original")
    replacement = credential_metadata("prod.replacement")
    form = provider_params(original.secret_path)
    key = {"cloudflare", "secret", original.secret_path}
    zone = %{"zone_id" => "owned", "zone_name" => "example.com"}
    {:noreply, socket} = AcmeLive.handle_event("new_provider", %{}, provider_socket())

    socket =
      Phoenix.Component.assign(socket,
        provider_form: form,
        zone_request_key: key,
        zone_choices: [zone],
        selected_zone_ids: ["owned"],
        zones_loading: false
      )

    edited = Map.merge(form, %{"name" => "Unsaved name", "zone_ids" => ["owned"]})
    {:noreply, socket} = AcmeLive.handle_event("provider_change", %{"provider" => edited}, socket)
    assert socket.assigns.provider_form["name"] == "Unsaved name"
    assert socket.assigns.zone_choices == [zone]
    assert socket.assigns.selected_zone_ids == ["owned"]

    changed = Map.put(edited, "credential_secret_path", replacement.secret_path)

    {:noreply, socket} =
      AcmeLive.handle_event("provider_change", %{"provider" => changed}, socket)

    assert socket.assigns.zone_choices == []
    assert socket.assigns.selected_zone_ids == []
    assert socket.assigns.zone_request_key == {"cloudflare", "secret", replacement.secret_path}
    assert socket.assigns.provider_form["name"] == "Unsaved name"

    changed = Map.put(changed, "provider", "route53")

    {:noreply, socket} =
      AcmeLive.handle_event("provider_change", %{"provider" => changed}, socket)

    assert socket.assigns.zone_request_key == {"route53", "secret", replacement.secret_path}
    assert socket.assigns.zone_choices == []

    changed = Map.put(changed, "credential_mode", "aws_environment")

    {:noreply, socket} =
      AcmeLive.handle_event("provider_change", %{"provider" => changed}, socket)

    assert socket.assigns.zone_request_key == {"route53", "aws_environment", ""}
    assert socket.assigns.zone_choices == []
    assert socket.assigns.selected_zone_ids == []
  end

  @tag :database
  test "zone discovery ignores stale results and results arriving after modal closure" do
    secret = credential_metadata("prod.cloudflare")
    key = {"cloudflare", "secret", secret.secret_path}
    zone = %{"zone_id" => "current", "zone_name" => "example.com"}
    {:noreply, socket} = AcmeLive.handle_event("new_provider", %{}, provider_socket())

    socket =
      Phoenix.Component.assign(socket,
        provider_form: provider_params(secret.secret_path),
        zone_request_key: key,
        zone_choices: [],
        zones_loading: true
      )

    stale = {"cloudflare", "secret", "prod.old"}

    {:noreply, socket} =
      AcmeLive.handle_async(:provider_zones, {:ok, {stale, {:ok, [zone]}}}, socket)

    assert socket.assigns.zone_choices == []
    assert socket.assigns.zones_loading

    {:noreply, socket} =
      AcmeLive.handle_async(:provider_zones, {:ok, {key, {:ok, [zone]}}}, socket)

    assert socket.assigns.zone_choices == [zone]
    refute socket.assigns.zones_loading
    assert socket.assigns.selected_zone_ids == []

    {:noreply, socket} = AcmeLive.handle_event("close_provider_modal", %{}, socket)

    {:noreply, socket} =
      AcmeLive.handle_async(:provider_zones, {:ok, {key, {:ok, [zone]}}}, socket)

    refute socket.assigns.provider_modal_open
    assert socket.assigns.zone_choices == []
  end

  @tag :database
  test "provider save rejects forged zone IDs and credentials without a matching discovery cache" do
    secret = credential_metadata("prod.cloudflare")
    replacement = credential_metadata("prod.replacement")
    form = provider_params(secret.secret_path)
    {:noreply, socket} = AcmeLive.handle_event("new_provider", %{}, provider_socket())

    socket =
      Phoenix.Component.assign(socket,
        provider_form: form,
        zone_request_key: {"cloudflare", "secret", secret.secret_path},
        zone_choices: [%{"zone_id" => "allowed", "zone_name" => "example.com"}],
        zones_loading: false
      )

    for params <- [
          Map.put(form, "zone_ids", ["forged"]),
          form
          |> Map.put("zone_ids", ["allowed"])
          |> Map.put("credential_secret_path", replacement.secret_path)
        ] do
      {:noreply, rejected} =
        AcmeLive.handle_event("save_provider", %{"provider" => params}, socket)

      assert Repo.all(DNSProvider) == []
      assert rejected.assigns.provider_modal_open
      assert rejected.assigns.flash["error"]
    end

    params =
      form
      |> Map.put("zone_ids", ["allowed"])
      |> Map.put("zones", %{"0" => %{"zone_id" => "forged", "zone_name" => "attacker.com"}})

    {:noreply, socket} = AcmeLive.handle_event("save_provider", %{"provider" => params}, socket)

    assert [
             %DNSProvider{
               credential_secret_id: credential_id,
               zones: [%{"zone_id" => "allowed", "zone_name" => "example.com"}]
             }
           ] = Repo.all(DNSProvider)

    assert credential_id == secret.id
    refute socket.assigns.provider_modal_open
  end

  @tag :database
  test "account forms open in a modal and cancel resets editing state" do
    account = modal_account()
    socket = acme_socket()
    {:noreply, socket} = AcmeLive.handle_event("edit_account", %{"id" => account.id}, socket)
    assert socket.assigns.account_modal_open
    assert socket.assigns.account_form["name"] == account.name
    html = render_component(&AcmeLive.render/1, socket.assigns)
    assert html =~ ~s(id="account-modal")
    assert html =~ ~s(phx-hook="FormModal")
    assert html =~ ~s(data-close-event="close_account_modal")
    assert html =~ ~s(phx-click="close_account_modal")
    assert html =~ ~s(id="account-form")
    assert html =~ ~r/<input(?=[^>]*name="account\[name\]")(?=[^>]*disabled)[^>]*>/
    assert html =~ ~s(value="modal-account")

    {:noreply, socket} =
      AcmeLive.handle_event(
        "account_change",
        %{"account" => %{"terms_url" => "https://example.com/updated"}},
        socket
      )

    assert socket.assigns.account_form["name"] == account.name
    assert socket.assigns.account_form["contact"] == "mailto:owner@example.com"

    {:noreply, socket} = AcmeLive.handle_event("close_account_modal", %{}, socket)
    refute socket.assigns.account_modal_open
    assert socket.assigns.account_edit_id == nil
    refute render_component(&AcmeLive.render/1, socket.assigns) =~ ~s(id="account-form")

    {:noreply, socket} = AcmeLive.handle_event("new_account", %{}, socket)
    assert socket.assigns.account_modal_open
    assert socket.assigns.account_form["name"] == ""
    assert socket.assigns.account_edit_id == nil
  end

  @tag :database
  @tag :account_registration
  test "account terms confirmation uses the loaded agreement and queues registration" do
    account = modal_account()

    {:noreply, socket} =
      AcmeLive.handle_event("edit_account", %{"id" => account.id}, acme_socket())

    current_terms = "https://letsencrypt.org/documents/current-test-agreement.pdf"
    key = socket.assigns.account_terms_request_key
    assert socket.assigns.account_form["terms_accepted"] == "false"
    assert socket.assigns.account_terms_loading
    assert socket.assigns.account_terms_url == nil

    {:noreply, socket} =
      AcmeLive.handle_async({:account_terms, key}, {:ok, {:ok, current_terms}}, socket)

    html = render_component(&AcmeLive.render/1, socket.assigns)
    assert html =~ ~s(href="#{current_terms}")
    refute html =~ ~s(name="account[terms_url]")
    assert socket.assigns.account_form["terms_accepted"] == "false"

    params = %{"terms_url" => "https://attacker.example/terms", "terms_accepted" => "false"}
    {:noreply, socket} = AcmeLive.handle_event("save_account", %{"account" => params}, socket)
    assert socket.assigns.account_modal_open
    assert socket.assigns.account_error =~ "terms acceptance required"
    assert Repo.get!(AcmeAccount, account.id).terms_url == account.terms_url

    {:noreply, socket} =
      AcmeLive.handle_event(
        "save_account",
        %{"account" => Map.put(params, "terms_accepted", "true")},
        socket
      )

    refute socket.assigns.account_modal_open
    assert socket.assigns.account_edit_id == nil
    assert socket.assigns.account_terms_url == nil
    assert Repo.get!(AcmeAccount, account.id).terms_url == current_terms
    assert [%Oban.Job{args: %{"account_id" => id}}] = Repo.all(Oban.Job)
    assert id == account.id

    {:noreply, socket} = AcmeLive.handle_event("new_account", %{}, socket)
    assert socket.assigns.account_form["terms_accepted"] == "false"
    assert socket.assigns.account_terms_url == nil
  end

  @tag :database
  test "account terms require current metadata and discard responses after environment changes or close" do
    {:noreply, socket} = AcmeLive.handle_event("new_account", %{}, acme_socket())
    staging_key = socket.assigns.account_terms_request_key
    assert socket.assigns.account_terms_loading

    {:noreply, rejected} =
      AcmeLive.handle_event("save_account", %{"account" => %{"terms_accepted" => "true"}}, socket)

    assert rejected.assigns.account_modal_open
    assert rejected.assigns.account_error =~ "Load the current"
    assert Repo.all(AcmeAccount) == []

    {:noreply, socket} =
      AcmeLive.handle_async(
        {:account_terms, staging_key},
        {:ok, {:ok, "https://example.com/staging-terms"}},
        socket
      )

    {:noreply, socket} =
      AcmeLive.handle_event(
        "account_change",
        %{"account" => %{"terms_accepted" => "true"}},
        socket
      )

    assert socket.assigns.account_form["terms_accepted"] == "true"

    {:noreply, socket} =
      AcmeLive.handle_event(
        "account_change",
        %{"account" => %{"environment" => "production", "terms_accepted" => "true"}},
        socket
      )

    production_key = socket.assigns.account_terms_request_key
    refute production_key == staging_key
    assert socket.assigns.account_form["terms_accepted"] == "false"
    assert socket.assigns.account_terms_url == nil
    assert socket.assigns.account_terms_loading

    {:noreply, socket} =
      AcmeLive.handle_async(
        {:account_terms, staging_key},
        {:ok, {:ok, "https://example.com/staging-terms"}},
        socket
      )

    assert socket.assigns.account_terms_url == nil
    assert socket.assigns.account_terms_loading

    {:noreply, socket} = AcmeLive.handle_event("close_account_modal", %{}, socket)

    {:noreply, socket} =
      AcmeLive.handle_async(
        {:account_terms, production_key},
        {:ok, {:ok, "https://example.com/production-terms"}},
        socket
      )

    refute socket.assigns.account_modal_open
    assert socket.assigns.account_terms_url == nil
  end

  @tag :database
  test "account terms failures are visible and retryable without stale task exits replacing fresh data" do
    {:noreply, socket} = AcmeLive.handle_event("new_account", %{}, acme_socket())
    failed_key = socket.assigns.account_terms_request_key

    {:noreply, socket} =
      AcmeLive.handle_async({:account_terms, failed_key}, {:ok, {:error, :timeout}}, socket)

    refute socket.assigns.account_terms_loading
    assert socket.assigns.account_terms_error

    assert render_component(&AcmeLive.render/1, socket.assigns) =~
             ~s(phx-click="load_account_terms")

    {:noreply, socket} = AcmeLive.handle_event("load_account_terms", %{}, socket)
    fresh_key = socket.assigns.account_terms_request_key
    refute fresh_key == failed_key
    assert socket.assigns.account_terms_loading
    assert socket.assigns.account_form["terms_accepted"] == "false"

    {:noreply, socket} =
      AcmeLive.handle_async(
        {:account_terms, fresh_key},
        {:ok, {:ok, "https://example.com/current-terms"}},
        socket
      )

    {:noreply, socket} =
      AcmeLive.handle_async({:account_terms, failed_key}, {:exit, :timeout}, socket)

    assert socket.assigns.account_terms_url == "https://example.com/current-terms"
    assert socket.assigns.account_terms_error == nil
    refute socket.assigns.account_terms_loading
  end

  @tag :database
  test "managed certificate modal exposes only five fields and resets between edit and create" do
    {certificate, provider} = modal_certificate()

    {:noreply, socket} =
      AcmeLive.handle_event("edit_managed", %{"id" => certificate.id}, acme_socket())

    assert socket.assigns.managed_modal_open
    assert socket.assigns.managed_form["name"] == certificate.slug
    choice = provider.id <> "|modal-zone"
    assert socket.assigns.managed_form["zone"] == choice
    html = render_component(&AcmeLive.render/1, socket.assigns)
    assert html =~ ~s(id="managed-certificate-modal")
    assert html =~ ~s(data-close-event="close_managed_modal")
    assert html =~ ~s(phx-click="close_managed_modal")
    fields = Regex.scan(~r/name="managed\[([^\]]+)\]"/, html, capture: :all_but_first)
    assert Enum.sort(List.flatten(fields)) == ~w(account_id identifiers key_policy name zone)
    refute html =~ "Stable slug"
    refute html =~ "Name suffix"
    refute html =~ "Delegated TXT owner"
    refute html =~ "Add provider binding"
    assert html =~ ~s(value="modal-cert")

    {:noreply, socket} =
      AcmeLive.handle_event(
        "managed_change",
        %{"managed" => %{"key_policy" => "rsa_2048"}},
        socket
      )

    assert socket.assigns.managed_form["name"] == certificate.slug
    assert socket.assigns.managed_form["account_id"] == certificate.account_id
    assert socket.assigns.managed_form["zone"] == choice

    {:noreply, socket} = AcmeLive.handle_event("close_managed_modal", %{}, socket)
    refute socket.assigns.managed_modal_open
    assert socket.assigns.managed_edit_id == nil
    {:noreply, socket} = AcmeLive.handle_event("new_managed", %{}, socket)
    assert socket.assigns.managed_modal_open
    assert socket.assigns.managed_form["name"] == ""
    assert socket.assigns.managed_form["zone"] == ""
  end

  @tag :database
  test "managed modal retains an invalid zone and closes after a corrected save" do
    {certificate, provider} = modal_certificate()

    {:noreply, socket} =
      AcmeLive.handle_event("edit_managed", %{"id" => certificate.id}, acme_socket())

    params =
      Map.merge(socket.assigns.managed_form, %{
        "identifiers" => "www.example.com",
        "zone" => "missing|zone"
      })

    {:noreply, socket} = AcmeLive.handle_event("save_managed", %{"managed" => params}, socket)
    assert socket.assigns.managed_modal_open
    assert socket.assigns.managed_form["identifiers"] == "www.example.com"
    assert socket.assigns.managed_form["zone"] == "missing|zone"
    assert socket.assigns.flash["error"]
    assert socket.assigns.managed_error =~ "Zone: select an allowed zone"
    {:noreply, socket} = AcmeLive.handle_event("close_managed_modal", %{}, socket)
    {:noreply, socket} = AcmeLive.handle_event("new_managed", %{}, socket)
    assert socket.assigns.managed_error == nil
    assert socket.assigns.managed_form["identifiers"] == ""
    {:noreply, socket} = AcmeLive.handle_event("edit_managed", %{"id" => certificate.id}, socket)
    params = Map.put(params, "zone", provider.id <> "|modal-zone")
    {:noreply, socket} = AcmeLive.handle_event("save_managed", %{"managed" => params}, socket)
    refute socket.assigns.managed_modal_open
    assert socket.assigns.managed_edit_id == nil
    assert socket.assigns.managed_form["zone"] == ""
    assert socket.assigns.managed_error == nil
    assert Repo.get!(ManagedCertificate, certificate.id).identifiers == ["www.example.com"]
    assert Repo.get!(ManagedCertificate, certificate.id).name == nil
  end

  @tag :database
  test "managed creation accepts a domain name and derives its binding from the selected zone" do
    {certificate, provider} = modal_certificate()
    {:noreply, socket} = AcmeLive.handle_event("new_managed", %{}, acme_socket())

    params = %{
      "name" => "gsmlg.net",
      "account_id" => certificate.account_id,
      "key_policy" => "rsa_2048",
      "identifiers" => "example.com\nwww.example.com",
      "zone" => provider.id <> "|modal-zone",
      "slug" => "forged-slug",
      "bindings" => %{"0" => %{"suffix" => "evil.test", "delegated_owner" => "evil.test"}}
    }

    {:noreply, socket} = AcmeLive.handle_event("save_managed", %{"managed" => params}, socket)

    refute socket.assigns.managed_modal_open
    assert socket.assigns.managed_error == nil
    created = Repo.get_by!(ManagedCertificate, name: "gsmlg.net")
    assert created.slug =~ ~r/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/
    refute created.slug == "forged-slug"
    assert created.identifiers == ["example.com", "www.example.com"]
    assert created.key_policy == "rsa_2048"

    assert created.bindings == [
             %{
               "provider_id" => provider.id,
               "zone_id" => "modal-zone",
               "zone_name" => "example.com",
               "suffix" => "example.com"
             }
           ]

    assert AcmeController.public_managed(created).name == "gsmlg.net"
    assert render_component(&AcmeLive.render/1, socket.assigns) =~ "gsmlg.net"
    {:noreply, socket} = AcmeLive.handle_event("select", %{"id" => created.id}, socket)
    assert render_component(&AcmeLive.render/1, socket.assigns) =~ "gsmlg.net: versions"
  end

  @tag :database
  test "managed creation reports blank and duplicate names without exposing account material" do
    {certificate, provider} = modal_certificate()
    {:noreply, socket} = AcmeLive.handle_event("new_managed", %{}, acme_socket())

    params = %{
      "name" => "",
      "account_id" => certificate.account_id,
      "key_policy" => "ec_p256",
      "identifiers" => "example.com",
      "zone" => provider.id <> "|modal-zone"
    }

    {:noreply, socket} = AcmeLive.handle_event("save_managed", %{"managed" => params}, socket)

    assert socket.assigns.managed_modal_open
    assert socket.assigns.managed_form["name"] == ""
    assert socket.assigns.managed_error =~ "Name: can't be blank"

    params = Map.put(params, "name", "gsmlg.net")
    {:noreply, socket} = AcmeLive.handle_event("save_managed", %{"managed" => params}, socket)
    refute socket.assigns.managed_modal_open
    {:noreply, socket} = AcmeLive.handle_event("new_managed", %{}, socket)
    {:noreply, socket} = AcmeLive.handle_event("save_managed", %{"managed" => params}, socket)
    assert socket.assigns.managed_modal_open
    assert socket.assigns.managed_form["name"] == "gsmlg.net"
    assert socket.assigns.managed_error =~ "Name: has already been taken"
    html = render_component(&AcmeLive.render/1, socket.assigns)
    refute html =~ "encrypted-modal-fixture"
    refute html =~ "Ecto.Changeset"
    assert Repo.aggregate(ManagedCertificate, :count) == 2
  end

  @tag :database
  test "managed names outside the selected zone fail without changing the certificate" do
    {certificate, provider} = modal_certificate()
    {:noreply, socket} = AcmeLive.handle_event("new_managed", %{}, acme_socket())

    params = %{
      "name" => "Wrong zone",
      "account_id" => certificate.account_id,
      "key_policy" => "ec_p256",
      "identifiers" => "unrelated.net",
      "zone" => provider.id <> "|modal-zone"
    }

    {:noreply, socket} = AcmeLive.handle_event("save_managed", %{"managed" => params}, socket)
    assert socket.assigns.managed_modal_open
    assert socket.assigns.managed_error =~ "DNS names must be covered by the selected Zone"
    assert socket.assigns.managed_form["name"] == "Wrong zone"
    assert Repo.aggregate(ManagedCertificate, :count) == 1
  end

  @tag :database
  test "editing an advanced certificate preserves bindings and immutable identity" do
    {certificate, provider} = modal_certificate()
    zones = provider.zones ++ [%{"zone_id" => "second-zone", "zone_name" => "example.net"}]
    provider |> Ecto.Changeset.change(zones: zones) |> Repo.update!()

    bindings = [
      %{
        "provider_id" => provider.id,
        "zone_id" => "modal-zone",
        "zone_name" => "example.com",
        "suffix" => "www.example.com",
        "delegated_owner" => "_acme-challenge.example.com"
      },
      %{
        "provider_id" => provider.id,
        "zone_id" => "second-zone",
        "zone_name" => "example.net",
        "suffix" => "example.net"
      }
    ]

    certificate =
      certificate
      |> Ecto.Changeset.change(
        identifiers: ["www.example.com", "example.net"],
        bindings: bindings
      )
      |> Repo.update!()

    {:noreply, socket} =
      AcmeLive.handle_event("edit_managed", %{"id" => certificate.id}, acme_socket())

    assert socket.assigns.managed_form["zone"] == ""
    assert render_component(&AcmeLive.render/1, socket.assigns) =~ "Keep current zones"

    params = %{
      "name" => "网站 certificate",
      "key_policy" => "rsa_2048",
      "zone" => "",
      "slug" => "forged-slug",
      "account_id" => Ecto.UUID.generate(),
      "bindings" => %{}
    }

    {:noreply, socket} = AcmeLive.handle_event("save_managed", %{"managed" => params}, socket)
    refute socket.assigns.managed_modal_open
    updated = Repo.get!(ManagedCertificate, certificate.id)
    assert Map.get(updated, :name) == "网站 certificate"
    assert updated.bindings == bindings
    assert updated.slug == certificate.slug
    assert updated.account_id == certificate.account_id
    assert updated.key_policy == "rsa_2048"
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

    for event <- ["new_account", "new_managed"] do
      {:noreply, blocked_socket} = AcmeLive.handle_event(event, %{}, socket)
      assert blocked_socket.assigns.flash["error"] =~ "disabled"
    end
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

  defp provider_socket do
    socket = %Phoenix.LiveView.Socket{
      assigns: %{__changed__: %{}, flash: %{}, live_action: :dns_providers}
    }

    {:ok, socket} = AcmeLive.mount(%{}, %{}, socket)
    socket
  end

  defp acme_socket do
    socket = %Phoenix.LiveView.Socket{assigns: %{__changed__: %{}, flash: %{}}}
    {:ok, socket} = AcmeLive.mount(%{}, %{}, socket)
    socket
  end

  defp modal_account do
    Repo.insert!(%AcmeAccount{
      name: "modal-account",
      environment: "staging",
      directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory",
      contact: ["mailto:owner@example.com"],
      terms_url: "https://example.com/terms",
      terms_accepted_at: DateTime.utc_now() |> DateTime.truncate(:second),
      encrypted_key: "encrypted-modal-fixture"
    })
  end

  defp modal_certificate do
    account = modal_account()

    provider =
      Repo.insert!(%DNSProvider{
        name: "Modal DNS",
        provider: "route53",
        credential_mode: "aws_environment",
        zones: [%{"zone_id" => "modal-zone", "zone_name" => "example.com"}]
      })

    certificate =
      Repo.insert!(%ManagedCertificate{
        slug: "modal-cert",
        account_id: account.id,
        identifiers: ["example.com"],
        bindings: [
          %{
            "provider_id" => provider.id,
            "zone_id" => "modal-zone",
            "zone_name" => "example.com",
            "suffix" => "example.com"
          }
        ]
      })

    {certificate, provider}
  end

  defp provider_params(path),
    do: %{
      "name" => "Cloudflare",
      "provider" => "cloudflare",
      "credential_mode" => "secret",
      "credential_secret_path" => path
    }

  defp credential_metadata(path),
    do:
      Repo.insert!(%Secret{
        name: "DNS credential",
        secret_path: path,
        secret_type: :static,
        engine_type: "static",
        status: "active",
        encrypted_data: "encrypted-credential-fixture"
      })
end
