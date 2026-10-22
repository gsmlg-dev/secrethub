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
        zone_rows: [%{}],
        binding_rows: [%{}]
      )

    {:ok, load_data(socket)}
  end

  @impl true
  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, 5_000)
    {:noreply, load_data(socket)}
  end

  @issuance_events ~w(save_provider edit_provider toggle_provider save_account edit_account register_account toggle_account save_managed edit_managed toggle_managed issue)

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

  defp do_handle_event("provider_change", %{"provider" => params}, socket),
    do: {:noreply, assign(socket, provider_form: params, zone_rows: rows(params["zones"]))}

  defp do_handle_event("account_change", %{"account" => params}, socket),
    do: {:noreply, assign(socket, account_form: params)}

  defp do_handle_event("managed_change", %{"managed" => params}, socket),
    do: {:noreply, assign(socket, managed_form: params, binding_rows: rows(params["bindings"]))}

  defp do_handle_event("refresh", _, socket), do: {:noreply, load_data(socket)}

  defp do_handle_event("select", %{"id" => id}, socket),
    do: {:noreply, socket |> assign(selected_id: id) |> load_data()}

  defp do_handle_event("add_zone", _, socket),
    do: {:noreply, update(socket, :zone_rows, &(&1 ++ [%{}]))}

  defp do_handle_event("add_binding", _, socket),
    do: {:noreply, update(socket, :binding_rows, &(&1 ++ [%{}]))}

  defp do_handle_event("save_provider", %{"provider" => params}, socket) do
    attrs =
      params
      |> Map.take(~w(name provider credential_mode credential_secret_id))
      |> Map.put("zones", rows(params["zones"]))

    attrs =
      if attrs["credential_secret_id"] == "",
        do: Map.delete(attrs, "credential_secret_id"),
        else: attrs

    result =
      if socket.assigns.provider_edit_id,
        do:
          Managed.update_provider(socket.assigns.provider_edit_id, Map.delete(attrs, "provider")),
        else: Managed.create_provider(attrs)

    respond(socket, result, "Provider configuration saved", fn socket ->
      assign(socket, provider_edit_id: nil, provider_form: provider_defaults(), zone_rows: [%{}])
    end)
  end

  defp do_handle_event("edit_provider", %{"id" => id}, socket) do
    case Enum.find(socket.assigns.providers, &(&1.id == id)) do
      nil ->
        {:noreply, put_flash(socket, :error, "Provider not found")}

      provider ->
        {:noreply,
         assign(socket,
           provider_edit_id: id,
           provider_form: stringify(AcmeController.public_provider(provider)),
           zone_rows: provider.zones
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
    attrs =
      Map.take(params, ~w(name environment terms_url))
      |> Map.put(
        "contact",
        split_names(params["contact"] || "")
        |> Enum.map(fn contact ->
          if String.starts_with?(contact, "mailto:"), do: contact, else: "mailto:" <> contact
        end)
      )
      |> Map.put("terms_accepted", params["terms_accepted"] == "true")

    result =
      if socket.assigns.account_edit_id do
        if attrs["terms_accepted"],
          do:
            Managed.update_account(
              socket.assigns.account_edit_id,
              Map.take(attrs, ~w(terms_url terms_accepted))
            ),
          else: {:error, :terms_acceptance_required}
      else
        Managed.create_account(attrs)
      end

    message =
      if socket.assigns.account_edit_id,
        do: "Account terms acceptance updated",
        else: "Account registration queued"

    respond(
      socket,
      result,
      message,
      &assign(&1, account_edit_id: nil, account_form: account_defaults())
    )
  end

  defp do_handle_event("edit_account", %{"id" => id}, socket) do
    case Enum.find(socket.assigns.accounts, &(&1.id == id)) do
      nil ->
        {:noreply, put_flash(socket, :error, "Account not found")}

      account ->
        form =
          stringify(AcmeController.public_account(account))
          |> Map.put("contact", Enum.join(account.contact, "\n"))
          |> Map.put("terms_accepted", "false")

        {:noreply, assign(socket, account_edit_id: id, account_form: form)}
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
    case bindings(rows(params["bindings"]), socket.assigns.providers) do
      {:ok, bindings} ->
        attrs =
          Map.take(params, ~w(slug account_id key_policy))
          |> Map.put("identifiers", split_names(params["identifiers"] || ""))
          |> Map.put("bindings", bindings)

        result =
          if socket.assigns.managed_edit_id,
            do:
              Managed.update_managed(
                socket.assigns.managed_edit_id,
                Map.take(attrs, ~w(identifiers bindings key_policy))
              ),
            else: Managed.create_managed(attrs)

        respond(socket, result, "Certificate configuration saved", fn socket ->
          assign(socket,
            managed_edit_id: nil,
            managed_form: managed_defaults(),
            binding_rows: [%{}]
          )
        end)

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, error_text(reason))}
    end
  end

  defp do_handle_event("edit_managed", %{"id" => id}, socket) do
    case Enum.find(socket.assigns.certificates, &(&1.id == id)) do
      nil ->
        {:noreply, put_flash(socket, :error, "Certificate not found")}

      certificate ->
        form =
          stringify(AcmeController.public_managed(certificate))
          |> Map.put("identifiers", Enum.join(certificate.identifiers, "\n"))

        bindings =
          Enum.map(
            certificate.bindings,
            &Map.put(&1, "provider_zone", &1["provider_id"] <> "|" <> &1["zone_id"])
          )

        {:noreply,
         assign(socket, managed_edit_id: id, managed_form: form, binding_rows: bindings)}
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
  defp rows(nil), do: []
  defp rows(rows) when is_list(rows), do: rows

  defp rows(rows) when is_map(rows),
    do: rows |> Enum.sort_by(&elem(&1, 0)) |> Enum.map(&elem(&1, 1))

  defp split_names(text), do: String.split(text, ~r/[\s,]+/, trim: true)

  defp provider_defaults,
    do: %{
      "name" => "",
      "provider" => "cloudflare",
      "credential_mode" => "secret",
      "credential_secret_id" => ""
    }

  defp account_defaults,
    do: %{
      "name" => "",
      "environment" => "staging",
      "contact" => "",
      "terms_url" => "https://letsencrypt.org/repository/"
    }

  defp managed_defaults,
    do: %{"slug" => "", "account_id" => "", "identifiers" => "", "key_policy" => "ec_p256"}

  defp bindings(rows, providers) do
    Enum.reduce_while(rows, {:ok, []}, fn row, {:ok, acc} ->
      with [provider_id, zone_id] <- String.split(row["provider_zone"] || "", "|", parts: 2),
           provider when not is_nil(provider) <- Enum.find(providers, &(&1.id == provider_id)),
           zone when not is_nil(zone) <- Enum.find(provider.zones, &(&1["zone_id"] == zone_id)) do
        binding = %{
          "provider_id" => provider_id,
          "zone_id" => zone_id,
          "zone_name" => zone["zone_name"],
          "suffix" => row["suffix"]
        }

        binding = delegated_owner(binding, row["delegated_owner"])

        {:cont, {:ok, acc ++ [binding]}}
      else
        _ -> {:halt, {:error, :select_explicit_provider_zone}}
      end
    end)
  end

  defp delegated_owner(binding, value) when value in [nil, ""], do: binding
  defp delegated_owner(binding, value), do: Map.put(binding, "delegated_owner", value)

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
  def render(assigns) do
    ~H"""
    <div class="max-w-7xl mx-auto p-6 space-y-6" id="acme-management">
      <header class="flex flex-wrap justify-between items-start gap-4">
        <div>
          <h1 class="text-3xl font-bold">Public server certificates</h1><p class="text-on-surface-variant">
            Let's Encrypt DNS-01 · explicit staging or production accounts · durable renewal and cleanup
          </p>
        </div>
        <div class="flex gap-3">
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
        <.dm_table data={@certificates} compact>
          <:col :let={cert} label="Certificate">
            <.dm_btn variant="link" phx-click="select" phx-value-id={cert.id}>{cert.slug}</.dm_btn><div class="text-xs">
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
          Configure a provider and account below, then add a managed certificate.
        </p>
      </.dm_card>
      <.dm_card :if={@selected} variant="bordered">
        <:title>{@selected.slug}: versions and order progress</:title>
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
      <div class="grid gap-6 xl:grid-cols-2">
        <.dm_card variant="bordered">
          <:title>DNS providers</:title>
          <div :for={provider <- @providers} class="border-b border-outline-variant py-3 space-y-2">
            <p class="font-semibold">
              {provider.name} · {provider.provider} · {if provider.enabled,
                do: "enabled",
                else: "disabled"}
            </p>
            <p class="text-xs break-all">
              Credential: {provider.credential_secret_id || provider.credential_mode}
            </p>
            <div class="flex gap-2">
              <.dm_btn size="sm" variant="ghost" phx-click="edit_provider" phx-value-id={provider.id}>
                Edit / rotate reference
              </.dm_btn><.dm_btn
                size="sm"
                variant="outline"
                phx-click="toggle_provider"
                phx-value-id={provider.id}
              >
                {if provider.enabled, do: "Disable", else: "Enable"}
              </.dm_btn>
            </div>
          </div>
          <.form
            for={%{}}
            phx-change="provider_change"
            phx-submit="save_provider"
            id="provider-form"
            class="space-y-3"
          >
            <.dm_input
              name="provider[name]"
              value={@provider_form["name"]}
              label="Provider name"
              required
            />
            <.dm_select
              name="provider[provider]"
              value={@provider_form["provider"]}
              label="DNS service"
              options={[{"cloudflare", "Cloudflare"}, {"route53", "Route 53"}]}
            />
            <.dm_select
              name="provider[credential_mode]"
              value={@provider_form["credential_mode"]}
              label="Credentials"
              options={[
                {"secret", "Encrypted secret reference"},
                {"aws_environment", "AWS environment credential chain"}
              ]}
            />
            <.dm_input
              name="provider[credential_secret_id]"
              value={@provider_form["credential_secret_id"]}
              label="Credential secret ID"
              helper="Reference an existing encrypted DNS credential secret; no tokens are stored here."
            />
            <div :for={{zone, index} <- Enum.with_index(@zone_rows)} class="grid gap-3 sm:grid-cols-2">
              <.dm_input
                name={"provider[zones][#{index}][zone_id]"}
                value={zone["zone_id"]}
                label="Public zone ID"
                required
              />
              <.dm_input
                name={"provider[zones][#{index}][zone_name]"}
                value={zone["zone_name"]}
                label="Zone DNS name"
                placeholder="example.com"
                required
              />
            </div>
            <div class="flex gap-2">
              <.dm_btn type="button" variant="ghost" phx-click="add_zone">Add allowed zone</.dm_btn><.dm_btn
                native_submit
                variant="primary"
                disabled={!@acme_enabled}
              >
                {if @provider_edit_id, do: "Update provider", else: "Add provider"}
              </.dm_btn>
            </div>
          </.form>
        </.dm_card>
        <.dm_card variant="bordered">
          <:title>ACME accounts</:title>
          <div :for={account <- @accounts} class="border-b border-outline-variant py-3 space-y-2">
            <p class="font-semibold">{account.name} · {account.environment} · {account.status}</p>
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
          <.form
            for={%{}}
            phx-change="account_change"
            phx-submit="save_account"
            id="account-form"
            class="space-y-3"
          >
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
            <.dm_input
              name="account[terms_url]"
              value={@account_form["terms_url"]}
              label="Terms URL accepted"
              type="url"
              required
            />
            <.dm_checkbox
              name="account[terms_accepted]"
              checked={@account_form["terms_accepted"] == "true"}
              label="I have reviewed and accept the selected service Terms of Service"
            />
            <.dm_btn native_submit variant="primary" disabled={!@acme_enabled}>
              {if @account_edit_id,
                do: "Update accepted terms",
                else: "Create account and queue registration"}
            </.dm_btn>
          </.form>
        </.dm_card>
      </div>
      <.dm_card variant="bordered">
        <:title>
          {if @managed_edit_id, do: "Edit certificate configuration", else: "Add managed certificate"}
        </:title>
        <.form
          for={%{}}
          phx-change="managed_change"
          phx-submit="save_managed"
          id="managed-certificate-form"
          class="space-y-4"
        >
          <div class="grid gap-4 md:grid-cols-3">
            <.dm_input
              name="managed[slug]"
              value={@managed_form["slug"]}
              label="Stable slug"
              disabled={!is_nil(@managed_edit_id)}
              required
            />
            <.dm_select
              name="managed[account_id]"
              value={@managed_form["account_id"]}
              label="ACME account / environment"
              options={Enum.map(@accounts, &{&1.id, &1.name <> " · " <> &1.environment})}
              prompt="Select account"
              disabled={!is_nil(@managed_edit_id)}
            />
            <.dm_select
              name="managed[key_policy]"
              value={@managed_form["key_policy"]}
              label="Leaf key"
              options={[{"ec_p256", "ECDSA P-256"}, {"rsa_2048", "RSA 2048"}]}
            />
          </div>
          <.dm_textarea
            name="managed[identifiers]"
            value={@managed_form["identifiers"]}
            label="DNS names, one per line"
            placeholder="example.com\n*.example.com"
            required
          />
          <div
            :for={{binding, index} <- Enum.with_index(@binding_rows)}
            class="grid gap-4 md:grid-cols-3"
          >
            <.dm_input
              name={"managed[bindings][#{index}][suffix]"}
              value={binding["suffix"]}
              label="Name suffix"
              placeholder="example.com"
              required
            />
            <.dm_select
              name={"managed[bindings][#{index}][provider_zone]"}
              value={binding["provider_zone"]}
              label="Explicit provider and public zone"
              options={zone_options(@providers)}
              prompt="Select allowed zone"
            />
            <.dm_input
              name={"managed[bindings][#{index}][delegated_owner]"}
              value={binding["delegated_owner"]}
              label="Delegated TXT owner, if configured"
              placeholder="_acme-challenge.example.net"
            />
          </div>
          <div class="flex gap-3">
            <.dm_btn type="button" variant="ghost" phx-click="add_binding">
              Add provider binding
            </.dm_btn><.dm_btn native_submit variant="primary" disabled={!@acme_enabled}>
              Save certificate configuration
            </.dm_btn>
          </div>
        </.form>
      </.dm_card>
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
