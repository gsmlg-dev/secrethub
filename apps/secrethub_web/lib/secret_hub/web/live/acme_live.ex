defmodule SecretHub.Web.AcmeLive do
  @moduledoc "Focused operator management for ACME server certificates and cleanup obligations."
  use SecretHub.Web, :live_view
  alias SecretHub.Core.PKI.ManagedCertificates, as: Managed
  alias SecretHub.Shared.LaunchProfile
  alias SecretHub.Web.AcmeController

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Process.send_after(self(), :refresh, 5_000)

    socket =
      assign(socket,
        page_title: "Public certificates",
        selected_id: nil,
        selected: nil,
        versions: [],
        orders: [],
        account_edit_id: nil,
        provider_edit_id: nil,
        managed_edit_id: nil,
        provider_form: provider_defaults(),
        account_form: account_defaults(),
        managed_form: managed_defaults(),
        provider_modal_open: false,
        account_modal_open: false,
        managed_modal_open: false,
        account_error: nil,
        account_terms_url: nil,
        account_terms_loading: false,
        account_terms_error: nil,
        account_terms_request_key: nil,
        managed_error: nil,
        credential_secrets: [],
        zone_choices: [],
        selected_zone_ids: [],
        zones_loading: false,
        zones_error: nil,
        provider_error: nil,
        zone_request_key: nil,
        managed_original: nil
      )

    {:ok, load_data(socket)}
  end

  @impl true
  def handle_params(_params, _uri, socket) do
    title =
      if socket.assigns.live_action == :dns_providers,
        do: "DNS providers",
        else: "Public certificates"

    {:noreply, assign(socket, page_title: title)}
  end

  @impl true
  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, 5_000)
    {:noreply, load_data(socket)}
  end

  @impl true
  def handle_async(:provider_zones, {:ok, {key, result}}, socket) do
    if socket.assigns.provider_modal_open and key == socket.assigns.zone_request_key and
         key == provider_key(socket.assigns.provider_form) do
      case result do
        {:ok, zones} ->
          zone_ids = Enum.map(zones, & &1["zone_id"])

          selected =
            Enum.filter(socket.assigns.selected_zone_ids, &(&1 in zone_ids))

          {:noreply,
           assign(socket,
             zone_choices: zones,
             selected_zone_ids: selected,
             zones_loading: false,
             zones_error: nil
           )}

        {:error, reason} ->
          {:noreply,
           assign(socket,
             zone_choices: [],
             selected_zone_ids: [],
             zones_loading: false,
             zones_error: zone_error(reason)
           )}
      end
    else
      {:noreply, socket}
    end
  end

  def handle_async(:provider_zones, {:exit, _reason}, socket) do
    if socket.assigns.provider_modal_open and socket.assigns.zones_loading do
      {:noreply,
       assign(socket, zones_loading: false, zones_error: zone_error(:zone_discovery_failed))}
    else
      {:noreply, socket}
    end
  end

  def handle_async({:account_terms, key}, {:ok, result}, socket) do
    if current_account_terms_request?(socket, key) do
      case result do
        {:ok, url} ->
          {:noreply,
           assign(socket,
             account_terms_url: url,
             account_terms_loading: false,
             account_terms_error: nil,
             account_form: Map.put(socket.assigns.account_form, "terms_accepted", "false")
           )}

        {:error, _reason} ->
          {:noreply,
           assign(socket,
             account_terms_url: nil,
             account_terms_loading: false,
             account_terms_error:
               "Could not load the current Terms of Service. Retry to review and accept them."
           )}
      end
    else
      {:noreply, socket}
    end
  end

  def handle_async({:account_terms, key}, {:exit, _reason}, socket),
    do: handle_async({:account_terms, key}, {:ok, {:error, :terms_unavailable}}, socket)

  @issuance_events ~w(new_provider provider_change load_provider_zones save_provider edit_provider toggle_provider new_account load_account_terms save_account edit_account register_account toggle_account new_managed save_managed edit_managed toggle_managed issue)

  @impl true
  def handle_event(event, params, socket) do
    if event in @issuance_events and not LaunchProfile.enabled?(:acme) do
      {:noreply,
       put_flash(
         socket,
         :error,
         "New ACME work is disabled; existing cleanup and revocation remain available."
       )}
    else
      do_handle_event(event, params, socket)
    end
  end

  defp do_handle_event("new_provider", _, socket) do
    {:noreply,
     socket
     |> reset_provider_form()
     |> assign(provider_modal_open: true, credential_secrets: Managed.credential_secret_options())}
  end

  defp do_handle_event("close_provider_modal", _, socket),
    do: {:noreply, reset_provider_form(socket)}

  defp do_handle_event("provider_change", %{"provider" => params}, socket) do
    form = provider_form(socket, params)
    key_changed = provider_key(form) != provider_key(socket.assigns.provider_form)
    socket = assign(socket, provider_form: form, provider_error: nil)

    socket =
      if key_changed do
        load_provider_zones(socket)
      else
        assign(socket, selected_zone_ids: selected_zone_ids(params))
      end

    {:noreply, socket}
  end

  defp do_handle_event("load_provider_zones", _, socket),
    do: {:noreply, load_provider_zones(socket)}

  defp do_handle_event("new_account", _, socket),
    do:
      {:noreply,
       socket |> reset_account_form() |> assign(account_modal_open: true) |> load_account_terms()}

  defp do_handle_event("load_account_terms", _, socket) do
    {:noreply,
     if(socket.assigns.account_modal_open, do: load_account_terms(socket), else: socket)}
  end

  defp do_handle_event("close_account_modal", _, socket),
    do: {:noreply, reset_account_form(socket)}

  defp do_handle_event("new_managed", _, socket),
    do: {:noreply, socket |> reset_managed_form() |> assign(managed_modal_open: true)}

  defp do_handle_event("close_managed_modal", _, socket),
    do: {:noreply, reset_managed_form(socket)}

  defp do_handle_event("account_change", %{"account" => params}, socket),
    do: {:noreply, put_account_form(socket, params)}

  defp do_handle_event("managed_change", %{"managed" => params}, socket),
    do: {:noreply, put_managed_form(socket, params)}

  defp do_handle_event("refresh", _, socket), do: {:noreply, load_data(socket)}

  defp do_handle_event("select", %{"id" => id}, socket),
    do: {:noreply, socket |> assign(selected_id: id) |> load_data()}

  defp do_handle_event("save_provider", %{"provider" => params}, socket) do
    form = provider_form(socket, params)
    selected = selected_zone_ids(params)
    socket = assign(socket, provider_form: form, selected_zone_ids: selected)

    with true <- socket.assigns.provider_modal_open,
         true <- provider_key(form) == socket.assigns.zone_request_key,
         false <- socket.assigns.zones_loading,
         nil <- socket.assigns.zones_error,
         [_ | _] <- selected,
         true <-
           Enum.all?(selected, fn id ->
             Enum.any?(socket.assigns.zone_choices, &(&1["zone_id"] == id))
           end) do
      zones = Enum.filter(socket.assigns.zone_choices, &(&1["zone_id"] in selected))
      attrs = Map.put(form, "zones", zones)

      result =
        if socket.assigns.provider_edit_id,
          do:
            Managed.update_provider(
              socket.assigns.provider_edit_id,
              Map.delete(attrs, "provider")
            ),
          else: Managed.create_provider(attrs)

      case result do
        {:ok, _} ->
          respond(socket, result, "Provider configuration saved", &reset_provider_form/1)

        {:error, reason} ->
          {:noreply,
           socket
           |> assign(provider_error: error_text(reason))
           |> put_flash(:error, error_text(reason))}
      end
    else
      _ ->
        message = "Load zones for the selected credentials and select at least one allowed zone."
        {:noreply, socket |> assign(provider_error: message) |> put_flash(:error, message)}
    end
  end

  defp do_handle_event("edit_provider", %{"id" => id}, socket) do
    case Enum.find(socket.assigns.providers, &(&1.id == id)) do
      nil ->
        {:noreply, put_flash(socket, :error, "Provider not found")}

      provider ->
        secrets = Managed.credential_secret_options()

        form = %{
          "name" => provider.name,
          "provider" => provider.provider,
          "credential_mode" => provider.credential_mode,
          "credential_secret_path" => credential_path(provider, secrets)
        }

        {:noreply,
         socket
         |> reset_provider_form()
         |> assign(
           provider_modal_open: true,
           provider_edit_id: id,
           provider_form: form,
           credential_secrets: secrets,
           zone_request_key: provider_key(form),
           zone_choices: provider.zones,
           selected_zone_ids: Enum.map(provider.zones, & &1["zone_id"])
         )}
    end
  end

  defp do_handle_event("toggle_provider", %{"id" => id}, socket) do
    case Enum.find(socket.assigns.providers, &(&1.id == id)) do
      nil ->
        {:noreply, put_flash(socket, :error, "Provider not found")}

      provider ->
        respond(
          socket,
          Managed.update_provider(id, %{"enabled" => !provider.enabled}),
          "Provider availability updated"
        )
    end
  end

  defp do_handle_event("save_account", %{"account" => params}, socket) do
    socket = put_account_form(socket, params)
    attrs = account_attrs(socket.assigns.account_form, socket.assigns.account_terms_url)

    result =
      cond do
        not account_terms_ready?(socket) ->
          {:error, "Load the current Terms of Service before confirming acceptance."}

        not attrs["terms_accepted"] ->
          {:error, :terms_acceptance_required}

        socket.assigns.account_edit_id ->
          Managed.update_account(
            socket.assigns.account_edit_id,
            Map.take(attrs, ~w(terms_url terms_accepted))
          )

        true ->
          Managed.create_account(attrs)
      end

    message =
      if socket.assigns.account_edit_id,
        do: "Account terms accepted and registration queued for enabled accounts",
        else: "Account registration queued"

    case result do
      {:ok, _} ->
        respond(socket, result, message, &reset_account_form/1)

      {:error, reason} ->
        {:noreply,
         socket
         |> assign(account_error: error_text(reason))
         |> put_flash(:error, error_text(reason))}
    end
  end

  defp do_handle_event("edit_account", %{"id" => id}, socket) do
    case Enum.find(socket.assigns.accounts, &(&1.id == id)) do
      nil ->
        {:noreply, put_flash(socket, :error, "Account not found")}

      account ->
        form =
          stringify(AcmeController.public_account(account))
          |> Map.put("contact", Enum.join(account.contact, "\n"))
          |> Map.delete("terms_url")
          |> Map.put("terms_accepted", "false")

        {:noreply,
         socket
         |> assign(
           account_edit_id: id,
           account_form: form,
           account_modal_open: true,
           account_error: nil
         )
         |> load_account_terms()}
    end
  end

  defp do_handle_event("register_account", %{"id" => id}, socket),
    do: respond(socket, Managed.register_account(id), "Account registration queued")

  defp do_handle_event("toggle_account", %{"id" => id}, socket) do
    case Enum.find(socket.assigns.accounts, &(&1.id == id)) do
      nil ->
        {:noreply, put_flash(socket, :error, "Account not found")}

      account ->
        respond(
          socket,
          Managed.update_account(id, %{"enabled" => !account.enabled}),
          "Account availability updated"
        )
    end
  end

  defp do_handle_event("save_managed", %{"managed" => params}, socket) do
    socket = put_managed_form(socket, params)
    form = socket.assigns.managed_form

    case managed_bindings(socket) do
      {:ok, bindings} ->
        attrs =
          Map.take(form, ~w(name account_id key_policy))
          |> Map.put("identifiers", split_names(form["identifiers"]))
          |> Map.put("bindings", bindings)
          |> preserve_legacy_name(socket.assigns.managed_original)

        result =
          if socket.assigns.managed_edit_id,
            do:
              Managed.update_managed(
                socket.assigns.managed_edit_id,
                Map.take(attrs, ~w(name identifiers bindings key_policy))
              ),
            else: Managed.create_managed(attrs)

        case result do
          {:ok, _} ->
            respond(socket, result, "Certificate configuration saved", &reset_managed_form/1)

          {:error, reason} ->
            managed_form_error(socket, reason)
        end

      {:error, reason} ->
        managed_form_error(socket, reason)
    end
  end

  defp do_handle_event("edit_managed", %{"id" => id}, socket) do
    case Enum.find(socket.assigns.certificates, &(&1.id == id)) do
      nil ->
        {:noreply, put_flash(socket, :error, "Certificate not found")}

      certificate ->
        form =
          %{
            "name" => certificate_name(certificate),
            "account_id" => certificate.account_id,
            "key_policy" => certificate.key_policy,
            "identifiers" => Enum.join(certificate.identifiers, "\n"),
            "zone" => managed_zone(certificate.bindings)
          }

        {:noreply,
         assign(socket,
           managed_edit_id: id,
           managed_form: form,
           managed_original: certificate,
           managed_modal_open: true,
           managed_error: nil
         )}
    end
  end

  defp do_handle_event("toggle_managed", %{"id" => id}, socket) do
    case Enum.find(socket.assigns.certificates, &(&1.id == id)) do
      nil ->
        {:noreply, put_flash(socket, :error, "Certificate not found")}

      certificate ->
        respond(
          socket,
          Managed.update_managed(id, %{"enabled" => !certificate.enabled}),
          "Certificate availability updated"
        )
    end
  end

  defp do_handle_event("issue", %{"id" => id}, socket),
    do:
      respond(
        socket,
        Managed.request_issue(id, Ecto.UUID.generate()),
        "Issuance or renewal queued"
      )

  defp do_handle_event("cancel", %{"id" => id}, socket),
    do:
      respond(
        socket,
        Managed.cancel_order(id),
        "Order cancelled; owned DNS cleanup remains queued"
      )

  defp do_handle_event("revoke", %{"id" => id}, socket),
    do:
      respond(
        socket,
        Managed.request_revocation(id),
        "Version quarantined; remote revocation queued"
      )

  defp do_handle_event("retry_cleanup", %{"id" => id}, socket),
    do: respond(socket, Managed.retry_cleanup(id), "DNS cleanup retry queued")

  defp load_data(socket) do
    selected =
      if socket.assigns.selected_id do
        case Managed.get_managed(socket.assigns.selected_id) do
          {:ok, resource} -> resource
          _ -> nil
        end
      end

    assign(socket,
      acme_enabled: LaunchProfile.enabled?(:acme),
      accounts: Managed.list_accounts(),
      providers: Managed.list_providers(),
      credential_secrets: Managed.credential_secret_options(),
      certificates: Managed.list_managed(),
      cleanup: Managed.list_cleanup(),
      selected: selected,
      versions: if(selected, do: Managed.list_versions(selected.id), else: []),
      orders: if(selected, do: Managed.list_orders(selected.id), else: [])
    )
  end

  defp respond(socket, result, message, after_success \\ &Function.identity/1)

  defp respond(socket, {:ok, _}, message, after_success),
    do: {:noreply, socket |> after_success.() |> put_flash(:info, message) |> load_data()}

  defp respond(socket, {:error, reason}, _message, _after_success),
    do: {:noreply, put_flash(socket, :error, error_text(reason))}

  defp error_text(%Ecto.Changeset{}), do: "Check the required configuration fields."

  defp error_text(reason) when is_atom(reason),
    do: reason |> Atom.to_string() |> String.replace("_", " ")

  defp error_text(reason) when is_binary(reason),
    do: reason |> String.replace("_", " ") |> String.slice(0, 160)

  defp error_text(_), do: "The request could not be completed. Check lifecycle status and retry."
  defp stringify(map), do: Map.new(map, fn {key, value} -> {to_string(key), value} end)
  defp split_names(text), do: String.split(text, ~r/[\s,]+/, trim: true)

  defp account_status_variant("pending"), do: "warning"
  defp account_status_variant("valid"), do: "success"

  defp account_status_variant(status) when status in ["revoked", "invalid", "quarantined"],
    do: "error"

  defp account_status_variant(_status), do: "neutral"

  defp reset_provider_form(socket) do
    socket
    |> cancel_async(:provider_zones)
    |> assign(
      provider_modal_open: false,
      provider_edit_id: nil,
      provider_form: provider_defaults(),
      zone_choices: [],
      selected_zone_ids: [],
      zones_loading: false,
      zones_error: nil,
      provider_error: nil,
      zone_request_key: nil
    )
  end

  defp reset_account_form(socket),
    do:
      socket
      |> cancel_async({:account_terms, socket.assigns.account_terms_request_key})
      |> assign(
        account_modal_open: false,
        account_edit_id: nil,
        account_form: account_defaults(),
        account_error: nil,
        account_terms_url: nil,
        account_terms_loading: false,
        account_terms_error: nil,
        account_terms_request_key: nil
      )

  defp reset_managed_form(socket),
    do:
      assign(socket,
        managed_modal_open: false,
        managed_edit_id: nil,
        managed_form: managed_defaults(),
        managed_original: nil,
        managed_error: nil
      )

  defp account_attrs(form, terms_url) do
    contacts =
      split_names(form["contact"] || "")
      |> Enum.map(fn contact ->
        if String.starts_with?(contact, "mailto:"), do: contact, else: "mailto:" <> contact
      end)

    form
    |> Map.take(~w(name environment))
    |> Map.put("terms_url", terms_url)
    |> Map.put("contact", contacts)
    |> Map.put("terms_accepted", form["terms_accepted"] == "true")
  end

  defp put_account_form(socket, params) do
    params =
      if socket.assigns.account_edit_id,
        do: Map.take(params, ~w(terms_accepted)),
        else: Map.take(params, ~w(name environment contact terms_accepted))

    form = Map.merge(socket.assigns.account_form, params)
    environment_changed = form["environment"] != socket.assigns.account_form["environment"]
    socket = assign(socket, account_form: form, account_error: nil)
    if environment_changed, do: load_account_terms(socket), else: socket
  end

  defp load_account_terms(socket) do
    environment = socket.assigns.account_form["environment"]
    key = {environment, make_ref()}

    socket
    |> cancel_async({:account_terms, socket.assigns.account_terms_request_key})
    |> assign(
      account_terms_url: nil,
      account_terms_loading: true,
      account_terms_error: nil,
      account_terms_request_key: key,
      account_error: nil,
      account_form: Map.put(socket.assigns.account_form, "terms_accepted", "false")
    )
    |> start_async({:account_terms, key}, fn -> Managed.discover_account_terms(environment) end)
  end

  defp current_account_terms_request?(socket, {environment, _} = key) do
    socket.assigns.account_modal_open and key == socket.assigns.account_terms_request_key and
      environment == socket.assigns.account_form["environment"]
  end

  defp account_terms_ready?(socket) do
    key = socket.assigns.account_terms_request_key

    not is_nil(key) and current_account_terms_request?(socket, key) and
      not socket.assigns.account_terms_loading and is_nil(socket.assigns.account_terms_error) and
      is_binary(socket.assigns.account_terms_url)
  end

  defp put_managed_form(socket, params) do
    params = Map.take(params, ~w(name account_id key_policy identifiers zone))

    params =
      if socket.assigns.managed_edit_id, do: Map.delete(params, "account_id"), else: params

    assign(socket,
      managed_form: Map.merge(socket.assigns.managed_form, params),
      managed_error: nil
    )
  end

  defp managed_form_error(socket, reason),
    do:
      {:noreply,
       socket
       |> assign(managed_error: managed_error_text(reason))
       |> put_flash(:error, managed_error_text(reason))}

  defp managed_error_text(%Ecto.Changeset{} = changeset) do
    errors =
      Enum.flat_map(
        [
          name: "Name",
          account_id: "ACME account",
          key_policy: "Leaf key",
          identifiers: "DNS names",
          bindings: "Zone"
        ],
        fn {field, label} ->
          Enum.map(Keyword.get_values(changeset.errors, field), fn {message, opts} ->
            message =
              String.replace(message, "%{count}", to_string(Keyword.get(opts, :count, "")))

            label <> ": " <> message
          end)
        end
      )

    if errors == [], do: error_text(changeset), else: Enum.join(errors, "; ")
  end

  defp managed_error_text(:select_explicit_provider_zone), do: "Zone: select an allowed zone."

  defp managed_error_text(:invalid_bindings),
    do: "DNS names must be covered by the selected Zone. Check the names and Zone."

  defp managed_error_text(:invalid_identifiers), do: "DNS names: enter valid public DNS names."
  defp managed_error_text(reason), do: error_text(reason)

  defp provider_form(socket, params) do
    form =
      Map.merge(
        socket.assigns.provider_form,
        Map.take(params, ~w(name provider credential_mode credential_secret_path))
      )

    form =
      if socket.assigns.provider_edit_id,
        do: Map.put(form, "provider", socket.assigns.provider_form["provider"]),
        else: form

    if form["provider"] == "route53", do: form, else: Map.put(form, "credential_mode", "secret")
  end

  defp provider_key(form) do
    path = if form["credential_mode"] == "secret", do: form["credential_secret_path"], else: ""
    {form["provider"], form["credential_mode"], path}
  end

  defp selected_zone_ids(params),
    do:
      params
      |> Map.get("zone_ids", [])
      |> List.wrap()
      |> Enum.filter(&(is_binary(&1) and &1 != ""))
      |> Enum.uniq()

  defp credential_path(provider, secrets) do
    case Enum.find(secrets, &(&1.id == provider.credential_secret_id)) do
      nil -> ""
      secret -> secret.secret_path
    end
  end

  defp credentials_ready?(form, secrets) do
    case provider_key(form) do
      {"route53", "aws_environment", ""} ->
        true

      {provider, "secret", path} when provider in ["cloudflare", "route53"] ->
        Enum.any?(secrets, &(&1.secret_path == path))

      _ ->
        false
    end
  end

  defp load_provider_zones(socket) do
    form = socket.assigns.provider_form
    key = provider_key(form)

    selected =
      if key == socket.assigns.zone_request_key, do: socket.assigns.selected_zone_ids, else: []

    socket =
      socket
      |> cancel_async(:provider_zones)
      |> assign(
        zone_request_key: key,
        zone_choices: [],
        selected_zone_ids: selected,
        zones_loading: false,
        zones_error: nil,
        provider_error: nil
      )

    if socket.assigns.provider_modal_open and
         credentials_ready?(form, socket.assigns.credential_secrets) do
      attrs = Map.take(form, ~w(provider credential_mode credential_secret_path))

      socket
      |> assign(zones_loading: true)
      |> start_async(:provider_zones, fn -> {key, Managed.discover_provider_zones(attrs)} end)
    else
      assign(socket, zones_error: "Select an existing credential secret path to load zones.")
    end
  end

  defp zone_error(reason) when reason in [:sealed, :not_initialized, :vault_unavailable],
    do: "Unlock the vault before loading DNS zones."

  defp zone_error(:authentication),
    do:
      "The DNS service rejected these credentials. Check their validity and zone read permissions."

  defp zone_error(:credentials_unavailable),
    do:
      "Check the DNS credentials: Cloudflare accepts a Text API token; Route53 needs Structured data with access_key_id and secret_access_key, or AWS environment credentials."

  defp zone_error(:throttled), do: "The DNS service is rate limiting requests. Retry shortly."

  defp zone_error(_), do: "Unable to load DNS zones. Check the credentials and retry."

  defp provider_defaults,
    do: %{
      "name" => "",
      "provider" => "cloudflare",
      "credential_mode" => "secret",
      "credential_secret_path" => ""
    }

  defp account_defaults,
    do: %{
      "name" => "",
      "environment" => "staging",
      "contact" => "",
      "terms_accepted" => "false"
    }

  defp managed_defaults,
    do: %{
      "name" => "",
      "account_id" => "",
      "identifiers" => "",
      "key_policy" => "ec_p256",
      "zone" => ""
    }

  defp managed_bindings(socket) do
    original = socket.assigns.managed_original
    selected_zone = socket.assigns.managed_form["zone"]

    if original && selected_zone == managed_zone(original.bindings),
      do: {:ok, original.bindings},
      else: zone_binding(selected_zone, socket.assigns.providers)
  end

  defp zone_binding(selected_zone, providers) do
    with [provider_id, zone_id] <- String.split(selected_zone, "|", parts: 2),
         provider when not is_nil(provider) <- Enum.find(providers, &(&1.id == provider_id)),
         zone when not is_nil(zone) <- Enum.find(provider.zones, &(&1["zone_id"] == zone_id)) do
      {:ok,
       [
         %{
           "provider_id" => provider_id,
           "zone_id" => zone_id,
           "zone_name" => zone["zone_name"],
           "suffix" => zone["zone_name"]
         }
       ]}
    else
      _ -> {:error, :select_explicit_provider_zone}
    end
  end

  defp managed_zone(bindings) do
    case Enum.uniq(Enum.map(bindings, &(&1["provider_id"] <> "|" <> &1["zone_id"]))) do
      [zone] -> zone
      _ -> ""
    end
  end

  defp preserve_legacy_name(attrs, %{name: nil, slug: slug}) do
    if attrs["name"] == slug, do: Map.delete(attrs, "name"), else: attrs
  end

  defp preserve_legacy_name(attrs, _), do: attrs
  defp certificate_name(certificate), do: certificate.name || certificate.slug

  defp zone_options(providers) do
    Enum.flat_map(providers, fn provider ->
      Enum.map(provider.zones, fn zone ->
        {provider.id <> "|" <> zone["zone_id"],
         provider.name <> " · " <> zone["zone_name"] <> " (" <> zone["zone_id"] <> ")"}
      end)
    end)
  end

  defp timestamp(nil), do: "—"
  defp timestamp(datetime), do: Calendar.strftime(datetime, "%Y-%m-%d %H:%M UTC")

  @impl true
  def render(%{live_action: :dns_providers} = assigns) do
    ~H"""
    <div class="max-w-7xl mx-auto p-6 space-y-6" id="dns-provider-management">
      <header class="flex flex-wrap justify-between items-start gap-4">
        <div>
          <h1 class="text-3xl font-bold">DNS providers</h1>
          <p class="text-on-surface-variant">
            Configure DNS credentials and allowed public zones for ACME DNS-01 validation.
          </p>
        </div>
        <div class="flex flex-wrap gap-3">
          <.dm_btn navigate={~p"/admin/pki/acme"} variant="outline">Public certificates</.dm_btn>
          <.dm_btn phx-click="refresh" variant="ghost">Refresh</.dm_btn>
          <.dm_btn phx-click="new_provider" variant="primary" disabled={!@acme_enabled}>
            Add DNS provider
          </.dm_btn>
        </div>
      </header>
      <p :if={!@acme_enabled} role="status" class="text-warning">
        New ACME work is disabled. Existing material, cleanup and revocation remain available.
      </p>
      <.dm_card variant="bordered">
        <:title>Configured DNS providers</:title>
        <div class="overflow-x-auto">
          <.dm_table id="dns-providers-table" data={@providers}>
            <:col :let={provider} label="Name">{provider.name}</:col>
            <:col :let={provider} label="DNS service">
              {if provider.provider == "cloudflare", do: "Cloudflare", else: "Route 53"}
            </:col>
            <:col :let={provider} label="Credentials">
              <span :if={provider.credential_mode == "aws_environment"}>AWS environment</span>
              <span :if={provider.credential_mode == "secret"} class="font-mono text-sm break-all">
                {case credential_path(provider, @credential_secrets) do
                  "" -> "Secret unavailable"
                  path -> path
                end}
              </span>
            </:col>
            <:col :let={provider} label="Allowed zones">
              <div :for={zone <- provider.zones}>{zone["zone_name"]}</div>
            </:col>
            <:col :let={provider} label="Status">
              {if provider.enabled, do: "Enabled", else: "Disabled"}
            </:col>
            <:col :let={provider} label="Actions">
              <div class="flex gap-2">
                <.dm_btn
                  size="sm"
                  variant="ghost"
                  phx-click="edit_provider"
                  phx-value-id={provider.id}
                  disabled={!@acme_enabled}
                >
                  Edit
                </.dm_btn>
                <.dm_btn
                  size="sm"
                  variant="outline"
                  phx-click="toggle_provider"
                  phx-value-id={provider.id}
                  disabled={!@acme_enabled}
                >
                  {if provider.enabled, do: "Disable", else: "Enable"}
                </.dm_btn>
              </div>
            </:col>
          </.dm_table>
        </div>
        <p :if={@providers == []} class="py-8 text-center text-on-surface-variant">
          No DNS providers configured. Add a provider to select credentials and public zones.
        </p>
      </.dm_card>
      <.dm_modal
        :if={@provider_modal_open}
        id="dns-provider-modal"
        size="lg"
        phx-hook="FormModal"
        data-close-event="close_provider_modal"
      >
        <:title>{if @provider_edit_id, do: "Edit DNS provider", else: "Add DNS provider"}</:title>
        <:body>
          <.form
            for={%{}}
            phx-change="provider_change"
            phx-submit="save_provider"
            id="provider-form"
            class="space-y-5"
          >
            <p :if={@provider_error} role="alert" class="text-error">{@provider_error}</p>
            <.dm_input
              id="dns-provider-name"
              name="provider[name]"
              value={@provider_form["name"]}
              label="Provider name"
              required
            />
            <div class="grid gap-4 sm:grid-cols-2">
              <.dm_select
                id="dns-provider-service"
                name="provider[provider]"
                value={@provider_form["provider"]}
                label="DNS service"
                disabled={!is_nil(@provider_edit_id)}
                options={[{"cloudflare", "Cloudflare"}, {"route53", "Route 53"}]}
              />
              <.dm_select
                id="dns-provider-credential-mode"
                name="provider[credential_mode]"
                value={@provider_form["credential_mode"]}
                label="Credentials"
                options={
                  if @provider_form["provider"] == "route53",
                    do: [
                      {"secret", "Encrypted secret"},
                      {"aws_environment", "AWS environment credential chain"}
                    ],
                    else: [{"secret", "Encrypted secret"}]
                }
              />
            </div>
            <.dm_input
              :if={@provider_form["credential_mode"] == "secret"}
              id="dns-provider-secret-path"
              name="provider[credential_secret_path]"
              value={@provider_form["credential_secret_path"]}
              label="Credential secret path"
              list="dns-credential-secret-paths"
              autocomplete="off"
              phx-debounce="300"
              placeholder="Select an existing secret path"
              helper={
                if @provider_form["provider"] == "cloudflare",
                  do:
                    "Select a Text secret containing the API token, or Structured data with api_token.",
                  else:
                    "Select Structured data with access_key_id and secret_access_key; session_token is optional."
              }
              required
            />
            <datalist id="dns-credential-secret-paths">
              <option :for={secret <- @credential_secrets} value={secret.secret_path} />
            </datalist>
            <fieldset class="space-y-3">
              <legend class="font-semibold">Allowed public zones</legend>
              <div class="flex justify-end">
                <.dm_btn
                  type="button"
                  size="sm"
                  variant="outline"
                  phx-click="load_provider_zones"
                  disabled={
                    @zones_loading or !credentials_ready?(@provider_form, @credential_secrets)
                  }
                >
                  Reload zones
                </.dm_btn>
              </div>
              <p :if={@zones_loading} role="status" class="text-on-surface-variant">
                Loading public zones…
              </p>
              <p :if={@zones_error} role="alert" class="text-error">{@zones_error}</p>
              <p
                :if={!@zones_loading and is_nil(@zones_error) and @zone_choices == []}
                class="text-sm text-on-surface-variant"
              >
                {if @zone_request_key,
                  do: "No public zones were found for these credentials.",
                  else: "Choose credentials to load available zones."}
              </p>
              <input type="hidden" name="provider[zone_ids][]" value="" />
              <div :if={@zone_choices != []} class="max-h-64 overflow-y-auto space-y-3">
                <.dm_checkbox
                  :for={zone <- @zone_choices}
                  id={"dns-zone-" <> zone["zone_id"]}
                  name="provider[zone_ids][]"
                  value={zone["zone_id"]}
                  label={zone["zone_name"]}
                  helper={zone["zone_id"]}
                  hidden_input={false}
                  checked={zone["zone_id"] in @selected_zone_ids}
                />
              </div>
            </fieldset>
            <div class="flex justify-end gap-3">
              <.dm_btn type="button" variant="ghost" phx-click="close_provider_modal">Cancel</.dm_btn>
              <.dm_btn
                native_submit
                variant="primary"
                disabled={
                  !@acme_enabled or @zones_loading or @selected_zone_ids == [] or
                    !is_nil(@zones_error)
                }
              >
                {if @provider_edit_id, do: "Save changes", else: "Add provider"}
              </.dm_btn>
            </div>
          </.form>
        </:body>
      </.dm_modal>
    </div>
    """
  end

  def render(assigns) do
    ~H"""
    <div class="max-w-7xl mx-auto p-6 space-y-6" id="acme-management">
      <header class="flex flex-wrap justify-between items-start gap-4">
        <div>
          <h1 class="text-3xl font-bold">Public server certificates</h1><p class="text-on-surface-variant">
            Let's Encrypt DNS-01 · explicit staging or production accounts · durable renewal and cleanup
          </p>
        </div>
        <div class="flex flex-wrap gap-3">
          <.dm_btn navigate={~p"/admin/pki/acme/dns-providers"} variant="outline">
            DNS providers
          </.dm_btn>
          <.dm_btn navigate={~p"/admin/pki/trust-stores"} variant="outline">Public trust</.dm_btn><.dm_btn
            phx-click="refresh"
            variant="ghost"
          >
            Refresh
          </.dm_btn>
        </div>
      </header>
      <p :if={!@acme_enabled} role="status" class="text-warning">
        New ACME work is disabled. Existing material, cleanup and revocation remain available.
      </p>
      <p class="text-sm text-on-surface-variant">
        Published versions are encrypted static secrets at pki.acme.&lt;slug&gt;. Export or deliver one matching bundle. Application deployment and reload remain operator actions.
      </p>
      <.dm_card variant="bordered">
        <:title>Managed certificates</:title>
        <div class="flex justify-end mb-4">
          <.dm_btn phx-click="new_managed" variant="primary" disabled={!@acme_enabled}>
            Add managed certificate
          </.dm_btn>
        </div>
        <.dm_table data={@certificates} compact>
          <:col :let={cert} label="Certificate">
            <.dm_btn variant="link" phx-click="select" phx-value-id={cert.id}>
              {certificate_name(cert)}
            </.dm_btn><div class="text-xs">
              {Enum.join(cert.identifiers, ", ")}
            </div>
          </:col>
          <:col :let={cert} label="Serving version">
            {cert.publication_sequence} · {if cert.enabled, do: "enabled", else: "paused"}
            <div class="text-xs">Renew: {timestamp(cert.next_renewal_at)}</div>
          </:col>
          <:col :let={cert} label="Actions">
            <div class="flex flex-wrap gap-2">
              <.dm_btn
                size="sm"
                phx-click="issue"
                phx-value-id={cert.id}
                disabled={!cert.enabled or !@acme_enabled}
              >
                Issue / renew
              </.dm_btn><.dm_btn
                size="sm"
                variant="outline"
                phx-click="toggle_managed"
                phx-value-id={cert.id}
                disabled={!@acme_enabled}
              >
                {if cert.enabled, do: "Pause", else: "Resume"}
              </.dm_btn><.dm_btn
                size="sm"
                variant="ghost"
                phx-click="edit_managed"
                phx-value-id={cert.id}
                disabled={!@acme_enabled}
              >
                Edit
              </.dm_btn>
            </div>
          </:col>
        </.dm_table>
        <p :if={@certificates == []} class="text-on-surface-variant">
          Configure a DNS provider using the link above, add an account, then add a managed certificate.
        </p>
      </.dm_card>
      <.dm_card :if={@selected} variant="bordered">
        <:title>{certificate_name(@selected)}: versions and order progress</:title>
        <p class="font-mono text-sm">pki.acme.{@selected.slug}</p>
        <.dm_table data={@versions} compact>
          <:col :let={version} label="Version">
            {version.publication_sequence} · {version.environment}
            <div class="font-mono text-xs break-all">{version.fingerprint}</div>
          </:col>
          <:col :let={version} label="Validity">
            {timestamp(version.not_after)}
            <div>Revocation: {version.revocation_state}</div><div
              :if={version.quarantined_at}
              class="text-error"
            >
              Quarantined from new delivery
            </div>
          </:col>
          <:col :let={version} label="Actions">
            <div class="flex gap-2">
              <.dm_btn
                :if={is_nil(version.quarantined_at)}
                href={~p"/admin/pki/acme/versions/#{version.id}/export"}
                size="sm"
                variant="outline"
              >
                Export combined PEM
              </.dm_btn><.dm_btn
                :if={version.revocation_state != "confirmed"}
                size="sm"
                variant="error"
                phx-click="revoke"
                phx-value-id={version.id}
                confirm="Quarantine this version and request remote revocation? Already distributed files cannot be recalled."
              >
                Revoke
              </.dm_btn>
            </div>
          </:col>
        </.dm_table>
        <.dm_table data={@orders} compact>
          <:col :let={order} label="Order">
            <code class="text-xs">{order.id}</code><div>
              {order.state} · {order.phase} · CA: {order.remote_status || "pending"}
            </div>
          </:col>
          <:col :let={order} label="Retry / failure">
            {timestamp(order.next_attempt_at)}
            <div class="text-xs">
              {error_text(order.last_error["code"] || order.last_error[:code] || "")}
            </div>
          </:col>
          <:col :let={order} label="Action">
            <.dm_btn
              :if={order.state not in ["published", "failed", "cancelled"]}
              size="sm"
              variant="outline"
              phx-click="cancel"
              phx-value-id={order.id}
            >
              Cancel
            </.dm_btn>
          </:col>
        </.dm_table>
      </.dm_card>
      <div class="grid gap-6">
        <.dm_card variant="bordered">
          <:title>ACME accounts</:title>
          <div class="flex justify-end mb-4">
            <.dm_btn phx-click="new_account" variant="primary" disabled={!@acme_enabled}>
              Add ACME account
            </.dm_btn>
          </div>
          <div :for={account <- @accounts} class="border-b border-outline-variant py-3 space-y-2">
            <div class="flex flex-wrap items-center gap-2">
              <p class="font-semibold">{account.name} · {account.environment}</p>
              <.dm_badge variant={account_status_variant(account.status)} size="sm">
                {account.status}
              </.dm_badge>
            </div>
            <p class="text-xs break-all">Accepted terms: {account.terms_url}</p>
            <div class="flex gap-2">
              <.dm_btn
                size="sm"
                variant="outline"
                phx-click="register_account"
                phx-value-id={account.id}
                disabled={!account.enabled or !@acme_enabled}
              >
                Retry registration
              </.dm_btn><.dm_btn
                size="sm"
                variant="ghost"
                phx-click="toggle_account"
                phx-value-id={account.id}
              >
                {if account.enabled, do: "Disable", else: "Enable"}
              </.dm_btn>
              <.dm_btn
                size="sm"
                variant="ghost"
                phx-click="edit_account"
                phx-value-id={account.id}
                disabled={!@acme_enabled}
              >
                Update accepted terms
              </.dm_btn>
            </div>
          </div>
        </.dm_card>
      </div>
      <.dm_modal
        :if={@account_modal_open}
        id="account-modal"
        size="lg"
        phx-hook="FormModal"
        data-close-event="close_account_modal"
      >
        <:title>{if @account_edit_id, do: "Update accepted terms", else: "Add ACME account"}</:title>
        <:body>
          <.form
            for={%{}}
            phx-change="account_change"
            phx-submit="save_account"
            id="account-form"
            class="space-y-3"
          >
            <p :if={@account_error} role="alert" class="text-error">{@account_error}</p>
            <.dm_input
              name="account[name]"
              value={@account_form["name"]}
              label="Account name"
              disabled={!is_nil(@account_edit_id)}
              required
            />
            <.dm_select
              name="account[environment]"
              value={@account_form["environment"]}
              label="Environment"
              disabled={!is_nil(@account_edit_id)}
              options={[
                {"staging", "Staging — test certificates"},
                {"production", "Production — publicly trusted certificates"}
              ]}
            />
            <.dm_input
              name="account[contact]"
              value={@account_form["contact"]}
              label="Contact email addresses"
              disabled={!is_nil(@account_edit_id)}
              required
            />
            <div class="space-y-2">
              <p class="font-medium">Current Terms of Service</p>
              <p :if={@account_terms_loading} role="status">Loading the current agreement…</p>
              <a
                :if={@account_terms_url}
                href={@account_terms_url}
                target="_blank"
                rel="noopener noreferrer"
                class="link break-all"
              >
                {@account_terms_url}
              </a>
              <p :if={@account_terms_error} role="alert" class="text-error">{@account_terms_error}</p>
              <.dm_btn
                :if={@account_terms_error}
                type="button"
                variant="outline"
                phx-click="load_account_terms"
              >
                Retry loading agreement
              </.dm_btn>
            </div>
            <.dm_checkbox
              name="account[terms_accepted]"
              checked={@account_form["terms_accepted"] == "true"}
              label="I have reviewed and accept these Terms of Service"
              disabled={
                @account_terms_loading || is_nil(@account_terms_url) ||
                  not is_nil(@account_terms_error)
              }
            />
            <div class="flex justify-end gap-3">
              <.dm_btn type="button" variant="ghost" phx-click="close_account_modal">Cancel</.dm_btn>
              <.dm_btn
                native_submit
                variant="primary"
                disabled={
                  !@acme_enabled || @account_terms_loading || is_nil(@account_terms_url) ||
                    not is_nil(@account_terms_error) || @account_form["terms_accepted"] != "true"
                }
              >
                {if @account_edit_id,
                  do: "Update accepted terms",
                  else: "Create account and queue registration"}
              </.dm_btn>
            </div>
          </.form>
        </:body>
      </.dm_modal>
      <.dm_modal
        :if={@managed_modal_open}
        id="managed-certificate-modal"
        size="lg"
        phx-hook="FormModal"
        data-close-event="close_managed_modal"
      >
        <:title>
          {if @managed_edit_id, do: "Edit certificate configuration", else: "Add managed certificate"}
        </:title>
        <:body>
          <.form
            for={%{}}
            phx-change="managed_change"
            phx-submit="save_managed"
            id="managed-certificate-form"
            class="space-y-4"
          >
            <p :if={@managed_error} role="alert" class="text-error">{@managed_error}</p>
            <div class="grid gap-4 md:grid-cols-3">
              <.dm_select
                id="managed-account"
                name="managed[account_id]"
                value={@managed_form["account_id"]}
                label="ACME account"
                options={Enum.map(@accounts, &{&1.id, &1.name <> " · " <> &1.environment})}
                prompt="Select account"
                disabled={!is_nil(@managed_edit_id)}
              />
              <.dm_input
                id="managed-name"
                name="managed[name]"
                value={@managed_form["name"]}
                label="Name"
                placeholder="gsmlg.net"
                required
              />
              <.dm_select
                id="managed-leaf-key"
                name="managed[key_policy]"
                value={@managed_form["key_policy"]}
                label="Leaf key"
                options={[{"ec_p256", "ECDSA P-256"}, {"rsa_2048", "RSA 2048"}]}
              />
            </div>
            <.dm_textarea
              id="managed-dns-names"
              name="managed[identifiers]"
              value={@managed_form["identifiers"]}
              label="DNS names, one per line"
              placeholder="example.com\n*.example.com"
              required
            />
            <.dm_select
              id="managed-zone"
              name="managed[zone]"
              value={@managed_form["zone"]}
              label="Zone"
              options={zone_options(@providers)}
              prompt={
                if @managed_original && managed_zone(@managed_original.bindings) == "",
                  do: "Keep current zones",
                  else: "Select allowed zone"
              }
            />
            <div class="flex gap-3">
              <.dm_btn type="button" variant="ghost" phx-click="close_managed_modal">Cancel</.dm_btn>
              <.dm_btn native_submit variant="primary" disabled={!@acme_enabled}>
                Save certificate configuration
              </.dm_btn>
            </div>
          </.form>
        </:body>
      </.dm_modal>
      <.dm_card variant="bordered">
        <:title>DNS cleanup</:title>
        <p class="text-sm text-on-surface-variant">
          Outstanding owned records remain eligible for reconciliation after issuance, cancellation or disabling. Restore unavailable credentials to let retries finish.
        </p>
        <.dm_table data={@cleanup} compact>
          <:col :let={operation} label="Owner">
            <code>{operation.owner}</code><div class="text-xs">{operation.provider_id}</div>
          </:col>
          <:col :let={operation} label="State">{operation.state} · {operation.cleanup_status}</:col>
          <:col :let={operation} label="Next retry">{timestamp(operation.next_attempt_at)}</:col>
          <:col :let={operation} label="Action">
            <.dm_btn size="sm" variant="outline" phx-click="retry_cleanup" phx-value-id={operation.id}>
              Retry cleanup
            </.dm_btn>
          </:col>
        </.dm_table>
        <p :if={@cleanup == []} class="text-on-surface-variant">
          No outstanding cleanup obligations.
        </p>
      </.dm_card>
    </div>
    """
  end
end
