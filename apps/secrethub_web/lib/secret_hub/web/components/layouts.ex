defmodule SecretHub.Web.Layouts do
  @moduledoc """
  This module holds layouts and related functionality
  used by your application.

  Layouts use DuskMoon UI components for navigation, theming,
  and page structure.
  """
  use SecretHub.Web, :html

  embed_templates "layouts/*"

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
