defmodule SecretHub.Web.TrustStoresLive do
  @moduledoc "Offline, read-only Mozilla-derived public trust catalogue."
  use SecretHub.Web, :live_view
  alias SecretHub.Core.PKI.TrustStores

  @page_size 25

  @impl true
  def mount(_params, _session, socket) do
    socket =
      assign(socket,
        page_title: "Public trust",
        query: "",
        page: 1,
        pages: 1,
        roots: [],
        all_roots: [],
        matches: 0,
        catalogue: nil,
        error: nil
      )

    case TrustStores.catalogue("mozilla_webpki") do
      {:ok, catalogue} ->
        {:ok,
         socket |> assign(catalogue: catalogue, all_roots: catalogue.roots) |> filter_roots()}

      {:error, _} ->
        {:ok,
         assign(socket,
           error:
             "The packaged public trust bundle is unavailable. TLS verification remains required."
         )}
    end
  end

  @impl true
  def handle_event("search", %{"query" => query}, socket),
    do:
      {:noreply, socket |> assign(query: String.slice(query, 0, 200), page: 1) |> filter_roots()}

  def handle_event("page", %{"page" => page}, socket) do
    page =
      case Integer.parse(page) do
        {number, ""} -> number
        _ -> 1
      end

    {:noreply, socket |> assign(page: max(1, min(page, socket.assigns.pages))) |> filter_roots()}
  end

  defp filter_roots(socket) do
    query = String.downcase(socket.assigns.query)

    matching =
      Enum.filter(socket.assigns.all_roots, fn root ->
        String.contains?(
          String.downcase(root.subject <> " " <> root.issuer <> " " <> root.fingerprint_sha256),
          query
        )
      end)

    count = length(matching)

    assign(socket,
      roots: Enum.slice(matching, (socket.assigns.page - 1) * @page_size, @page_size),
      matches: count,
      pages: max(1, ceil(count / @page_size))
    )
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-7xl mx-auto p-6 space-y-6" id="public-trust">
      <header class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 class="text-3xl font-bold">Mozilla-derived TLS root CA bundle</h1>
          <p class="text-on-surface-variant">
            Public server trust, packaged with this release and available while the Vault is sealed.
          </p>
        </div>
        <.dm_btn navigate={~p"/admin/pki/acme"} variant="outline">Public certificates</.dm_btn>
      </header>
      <p :if={@error} role="alert" class="text-error">{@error}</p>
      <.dm_card :if={@catalogue} variant="bordered">
        <:title>mozilla_webpki</:title>
        <dl class="grid gap-3 md:grid-cols-2 text-sm">
          <div>
            <dt class="font-semibold">Snapshot</dt><dd>
              CAStore {@catalogue.package_version} · {@catalogue.root_count} roots
            </dd>
          </div>
          <div>
            <dt class="font-semibold">Source</dt><dd>{@catalogue.source}</dd>
          </div>
          <div class="md:col-span-2">
            <dt class="font-semibold">PEM SHA-256</dt><dd class="font-mono break-all">
              {@catalogue.sha256}
            </dd>
          </div>
          <div>
            <dt class="font-semibold">License</dt><dd>{@catalogue.license}</dd>
          </div>
          <div>
            <dt class="font-semibold">SecretHub release</dt><dd>{@catalogue.release}</dd>
          </div>
        </dl>
        <p class="text-sm text-on-surface-variant">
          This PEM snapshot does not reproduce every Firefox trust policy. Updates and removals arrive through a reviewed SecretHub release; a binary rollback can restore older roots.
        </p>
        <:action>
          <.dm_btn href={~p"/admin/pki/trust-stores/mozilla_webpki/pem"} variant="primary">
            Download public PEM
          </.dm_btn>
        </:action>
      </.dm_card>
      <.form for={%{}} phx-change="search" id="root-search">
        <.dm_input
          id="root-query"
          name="query"
          value={@query}
          label="Search roots"
          type="search"
          placeholder="Subject, issuer or fingerprint"
          phx-debounce="200"
        />
      </.form>
      <p class="text-sm text-on-surface-variant">
        {@matches} matching roots · page {@page} of {@pages}
      </p>
      <div class="overflow-x-auto">
        <.dm_table data={@roots} compact zebra>
          <:col :let={root} label="Subject"><span class="break-all">{root.subject}</span></:col>
          <:col :let={root} label="Issuer"><span class="break-all">{root.issuer}</span></:col>
          <:col :let={root} label="Validity">
            {Calendar.strftime(root.not_before, "%Y-%m-%d")} – {Calendar.strftime(
              root.not_after,
              "%Y-%m-%d"
            )}
          </:col>
          <:col :let={root} label="DER SHA-256">
            <code class="text-xs break-all">{root.fingerprint_sha256}</code>
          </:col>
        </.dm_table>
      </div>
      <div class="flex gap-3">
        <.dm_btn variant="outline" phx-click="page" phx-value-page={@page - 1} disabled={@page <= 1}>
          Previous
        </.dm_btn>
        <.dm_btn
          variant="outline"
          phx-click="page"
          phx-value-page={@page + 1}
          disabled={@page >= @pages}
        >
          Next
        </.dm_btn>
      </div>
    </div>
    """
  end
end
