defmodule SecretHub.WebWeb.VaultUnsealLive do
  @moduledoc """
  LiveView for vault unsealing interface.

  Provides a user-friendly interface for administrators to:
  - Check vault seal status
  - Submit Shamir shares to unseal the vault
  - Monitor unseal progress
  - Re-seal the vault when needed
  """

  use SecretHub.WebWeb, :live_view
  require Logger

  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Shamir

  @impl true
  def mount(_params, _session, socket) do
    # Check initial vault status
    status = SealState.status()

    socket =
      socket
      |> assign(:vault_status, status)
      |> assign(:share_input, "")
      |> assign(:error_message, nil)
      |> assign(:success_message, nil)
      |> assign(:shares_submitted, [])

    # Set up periodic status refresh
    if connected?(socket) do
      :timer.send_interval(2000, self(), :refresh_status)
    end

    {:ok, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div class="max-w-3xl mx-auto">
        <!-- Header -->
        <div class="text-center mb-8">
          <h1 class="text-4xl font-bold text-gray-900 mb-2">SecretHub Vault</h1>
          <p class="text-lg text-gray-600">
            Secure Secrets Management Platform
          </p>
        </div>

        <!-- Vault Status Card -->
        <div class="bg-white shadow-lg rounded-lg overflow-hidden mb-6">
          <div class="px-6 py-4 border-b border-gray-200">
            <h2 class="text-xl font-semibold text-gray-800">Vault Status</h2>
          </div>

          <div class="px-6 py-6">
            <div class="grid grid-cols-2 gap-6">
              <!-- Initialized Status -->
              <div class="flex items-center space-x-3">
                <div class={"w-3 h-3 rounded-full #{if @vault_status.initialized, do: "bg-green-500", else: "bg-red-500"}"}>
                </div>
                <div>
                  <p class="text-sm text-gray-500">Initialized</p>
                  <p class="font-semibold text-gray-900">
                    <%= if @vault_status.initialized, do: "Yes", else: "No" %>
                  </p>
                </div>
              </div>

              <!-- Sealed Status -->
              <div class="flex items-center space-x-3">
                <div class={"w-3 h-3 rounded-full #{if @vault_status.sealed, do: "bg-red-500", else: "bg-green-500"}"}>
                </div>
                <div>
                  <p class="text-sm text-gray-500">Sealed</p>
                  <p class="font-semibold text-gray-900">
                    <%= if @vault_status.sealed, do: "Yes", else: "No" %>
                  </p>
                </div>
              </div>

              <!-- Progress -->
              <%= if @vault_status.initialized and @vault_status.threshold do %>
                <div class="col-span-2">
                  <p class="text-sm text-gray-500 mb-2">Unseal Progress</p>
                  <div class="flex items-center space-x-4">
                    <div class="flex-1 bg-gray-200 rounded-full h-3">
                      <div
                        class="bg-blue-600 h-3 rounded-full transition-all duration-300"
                        style={"width: #{(@vault_status.progress / @vault_status.threshold * 100)}%"}
                      >
                      </div>
                    </div>
                    <span class="text-sm font-semibold text-gray-700">
                      <%= @vault_status.progress %> / <%= @vault_status.threshold %>
                    </span>
                  </div>
                </div>
              <% end %>
            </div>
          </div>
        </div>

        <!-- Unseal Form (only show if vault is sealed) -->
        <%= if @vault_status.initialized and @vault_status.sealed do %>
          <div class="bg-white shadow-lg rounded-lg overflow-hidden mb-6">
            <div class="px-6 py-4 border-b border-gray-200">
              <h2 class="text-xl font-semibold text-gray-800">Unseal Vault</h2>
            </div>

            <div class="px-6 py-6">
              <form phx-submit="submit_share" class="space-y-4">
                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">
                    Enter Unseal Share
                  </label>
                  <input
                    type="text"
                    name="share"
                    value={@share_input}
                    phx-change="update_share"
                    placeholder="secrethub-share-xxxxxxxxxx"
                    class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
                    autocomplete="off"
                  />
                  <p class="mt-2 text-sm text-gray-500">
                    Paste one of your Shamir shares above. You need <%= @vault_status.threshold %> shares to unseal the vault.
                  </p>
                </div>

                <!-- Error Message -->
                <%= if @error_message do %>
                  <div class="bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded-lg">
                    <p class="font-medium">Error</p>
                    <p class="text-sm"><%= @error_message %></p>
                  </div>
                <% end %>

                <!-- Success Message -->
                <%= if @success_message do %>
                  <div class="bg-green-50 border border-green-200 text-green-800 px-4 py-3 rounded-lg">
                    <p class="font-medium">Success</p>
                    <p class="text-sm"><%= @success_message %></p>
                  </div>
                <% end %>

                <button
                  type="submit"
                  class="w-full bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 transition-colors duration-200"
                >
                  Submit Share
                </button>
              </form>

              <!-- Submitted Shares -->
              <%= if length(@shares_submitted) > 0 do %>
                <div class="mt-6">
                  <p class="text-sm font-medium text-gray-700 mb-2">
                    Shares Submitted: <%= length(@shares_submitted) %>
                  </p>
                  <div class="flex flex-wrap gap-2">
                    <%= for i <- 1..length(@shares_submitted) do %>
                      <div class="w-3 h-3 bg-green-500 rounded-full"></div>
                    <% end %>
                    <%= for _i <- 1..(@vault_status.threshold - length(@shares_submitted)) do %>
                      <div class="w-3 h-3 bg-gray-300 rounded-full"></div>
                    <% end %>
                  </div>
                </div>
              <% end %>
            </div>
          </div>
        <% end %>

        <!-- Unsealed Actions (only show if vault is unsealed) -->
        <%= if @vault_status.initialized and not @vault_status.sealed do %>
          <div class="bg-white shadow-lg rounded-lg overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200">
              <h2 class="text-xl font-semibold text-gray-800">Vault Unsealed</h2>
            </div>

            <div class="px-6 py-6">
              <div class="bg-green-50 border border-green-200 text-green-800 px-4 py-3 rounded-lg mb-4">
                <p class="font-medium">Vault is operational</p>
                <p class="text-sm">The vault is unsealed and ready to serve secrets.</p>
              </div>

              <div class="flex space-x-4">
                <a
                  href="/admin/dashboard"
                  class="flex-1 bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 transition-colors duration-200 text-center"
                >
                  Go to Dashboard
                </a>

                <button
                  phx-click="seal_vault"
                  data-confirm="Are you sure you want to seal the vault? This will stop all secret operations."
                  class="flex-1 bg-red-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-red-700 transition-colors duration-200"
                >
                  Seal Vault
                </button>
              </div>
            </div>
          </div>
        <% end %>

        <!-- Not Initialized Message -->
        <%= if not @vault_status.initialized do %>
          <div class="bg-white shadow-lg rounded-lg overflow-hidden">
            <div class="px-6 py-6">
              <div class="bg-yellow-50 border border-yellow-200 text-yellow-800 px-4 py-3 rounded-lg">
                <p class="font-medium">Vault not initialized</p>
                <p class="text-sm mt-1">
                  The vault needs to be initialized before it can be unsealed.
                  Use the API endpoint <code class="bg-yellow-100 px-2 py-1 rounded">POST /v1/sys/init</code> to initialize.
                </p>
              </div>

              <div class="mt-4">
                <p class="text-sm text-gray-600">
                  Use the System API to initialize. See documentation for curl examples.
                </p>
              </div>
            </div>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  @impl true
  def handle_event("update_share", %{"share" => share}, socket) do
    {:noreply, assign(socket, :share_input, share)}
  end

  @impl true
  def handle_event("submit_share", %{"share" => share}, socket) do
    case SealState.unseal(Shamir.decode_share(share) |> elem(1)) do
      {:ok, status} ->
        if status.sealed do
          # Still sealed, need more shares
          socket =
            socket
            |> assign(:vault_status, status)
            |> assign(:share_input, "")
            |> assign(:error_message, nil)
            |> assign(:success_message, "Share accepted! #{status.progress}/#{status.threshold} shares submitted.")
            |> assign(:shares_submitted, Enum.to_list(1..status.progress))

          {:noreply, socket}
        else
          # Unsealed!
          socket =
            socket
            |> assign(:vault_status, status)
            |> assign(:share_input, "")
            |> assign(:error_message, nil)
            |> assign(:success_message, "Vault unsealed successfully!")
            |> assign(:shares_submitted, [])

          Logger.info("Vault unsealed via UI")
          {:noreply, socket}
        end

      {:error, reason} ->
        socket =
          socket
          |> assign(:error_message, "Failed to accept share: #{reason}")
          |> assign(:success_message, nil)

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("seal_vault", _params, socket) do
    :ok = SealState.seal()

    status = SealState.status()

    socket =
      socket
      |> assign(:vault_status, status)
      |> assign(:shares_submitted, [])
      |> assign(:error_message, nil)
      |> assign(:success_message, "Vault sealed successfully!")

    Logger.info("Vault sealed via UI")
    {:noreply, socket}
  end

  @impl true
  def handle_info(:refresh_status, socket) do
    status = SealState.status()
    {:noreply, assign(socket, :vault_status, status)}
  end
end
