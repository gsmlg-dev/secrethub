defmodule SecretHub.Web.Layouts do
  @moduledoc """
  This module holds layouts and related functionality
  used by your application.

  Layouts use DuskMoon UI components for navigation, theming,
  and page structure.
  """
  use SecretHub.Web, :html

  embed_templates "layouts/*"

  @doc "Shows the running version with build details in a tooltip."
  attr :id, :string, default: "app-version"
  attr :info, :map, default: nil

  def version_badge(assigns) do
    info = assigns.info || SecretHub.Web.BuildInfo.info()
    version = "v#{info.version}#{if info.environment == :dev, do: "-dev", else: ""}"

    details =
      [
        {"Version", version},
        {"Environment", info.environment},
        {"Git ref", info.git_ref || "Unavailable"},
        {"Git SHA", info.git_sha || "Unavailable"},
        {"Built at", info.built_at},
        {"Source time", info.source_date}
      ]
      |> Enum.reject(fn {_label, value} -> is_nil(value) end)
      |> Enum.map_join("\n", fn {label, value} -> "#{label}: #{value}" end)

    assigns = assign(assigns, version: version, details: details)

    ~H"""
    <.dm_tooltip
      :let={trigger_attrs}
      id={@id}
      content={@details}
      position="bottom"
      class="whitespace-pre-line max-w-[calc(100vw-2rem)] break-words text-left font-mono"
    >
      <button
        id={@id}
        type="button"
        class="ml-2 inline-flex shrink-0 rounded-full cursor-help focus-visible:outline-2 focus-visible:outline-offset-2"
        aria-label="Version details"
        {trigger_attrs}
      >
        <.dm_badge
          variant="secondary"
          size="lg"
          pill
          class="whitespace-nowrap text-lg leading-5 font-medium"
        >
          {@version}
        </.dm_badge>
      </button>
    </.dm_tooltip>
    """
  end

  @doc """
  Shows the flash group with standard titles and content.

  ## Examples

      <.flash_group flash={@flash} />
  """
  attr :flash, :map, required: true, doc: "the map of flash messages"
  attr :id, :string, default: "flash-group", doc: "the optional id of flash container"

  def flash_group(assigns) do
    ~H"""
    <div id={@id} aria-live="polite">
      <.flash kind={:info} flash={@flash} />
      <.flash kind={:error} flash={@flash} />

      <.flash
        id="client-error"
        kind={:error}
        title={gettext("We can't find the internet")}
        phx-disconnected={show(".phx-client-error #client-error") |> JS.remove_attribute("hidden")}
        phx-connected={hide("#client-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        {gettext("Attempting to reconnect")}
        <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>

      <.flash
        id="server-error"
        kind={:error}
        title={gettext("Something went wrong!")}
        phx-disconnected={show(".phx-server-error #server-error") |> JS.remove_attribute("hidden")}
        phx-connected={hide("#server-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        {gettext("Attempting to reconnect")}
        <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>
    </div>
    """
  end

  @doc """
  Shows a persistent admin warning when the vault is sealed.
  """
  attr :vault_status, :map, default: nil

  def vault_sealed_banner(assigns) do
    ~H"""
    <div
      :if={vault_sealed?(@vault_status)}
      id="vault-sealed-banner"
      class="border-b border-error/30 bg-error/10 px-6 py-3 text-error"
      role="alert"
      aria-live="polite"
    >
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-3">
          <.dm_mdi name="lock-alert" class="h-5 w-5 flex-none" color="currentcolor" />
          <div>
            <p class="font-semibold leading-5">Vault sealed</p>
            <p class="text-sm text-error/90">
              Secret and PKI operations are unavailable until the vault is unsealed.
            </p>
          </div>
        </div>
        <.dm_link
          href={~p"/vault/unseal"}
          class="inline-flex items-center gap-1 rounded-md border border-error/40 px-3 py-1.5 text-sm font-medium text-error hover:bg-error/10"
        >
          Unseal vault <.dm_mdi name="arrow-right" class="h-4 w-4" color="currentcolor" />
        </.dm_link>
      </div>
    </div>
    """
  end

  defp vault_sealed?(%{initialized: true, sealed: true}), do: true
  defp vault_sealed?(_vault_status), do: false
end
