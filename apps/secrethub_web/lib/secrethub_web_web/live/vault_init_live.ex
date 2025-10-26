defmodule SecretHub.WebWeb.VaultInitLive do
  @moduledoc """
  LiveView for vault initialization.

  Provides interface to initialize the vault with Shamir secret sharing.
  Only shown when vault is not yet initialized.
  """

  use SecretHub.WebWeb, :live_view
  require Logger

  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Shamir

  @impl true
  def mount(_params, _session, socket) do
    status = SealState.status()

    socket =
      socket
      |> assign(:vault_status, status)
      |> assign(:total_shares, 5)
      |> assign(:threshold, 3)
      |> assign(:initialized_shares, nil)
      |> assign(:error_message, nil)

    {:ok, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div class="max-w-3xl mx-auto">
        <div class="text-center mb-8">
          <h1 class="text-4xl font-bold text-gray-900 mb-2">Initialize SecretHub Vault</h1>
          <p class="text-lg text-gray-600">
            Set up Shamir secret sharing for vault encryption
          </p>
        </div>

        <%= if @vault_status.initialized do %>
          <!-- Already Initialized -->
          <div class="bg-white shadow-lg rounded-lg overflow-hidden">
            <div class="px-6 py-6">
              <div class="bg-blue-50 border border-blue-200 text-blue-800 px-4 py-3 rounded-lg">
                <p class="font-medium">Vault Already Initialized</p>
                <p class="text-sm mt-1">
                  The vault has already been initialized. You can proceed to unseal it.
                </p>
              </div>

              <div class="mt-6">
                <a
                  href="/vault/unseal"
                  class="block w-full bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 transition-colors duration-200 text-center"
                >
                  Go to Unseal Page
                </a>
              </div>
            </div>
          </div>
        <% else %>
          <!-- Initialization Form -->
          <%= if @initialized_shares do %>
            <!-- Show Generated Shares -->
            <div class="bg-white shadow-lg rounded-lg overflow-hidden">
              <div class="px-6 py-4 border-b border-gray-200 bg-green-600">
                <h2 class="text-xl font-semibold text-white">Vault Initialized Successfully!</h2>
              </div>

              <div class="px-6 py-6">
                <div class="bg-yellow-50 border border-yellow-200 text-yellow-800 px-4 py-3 rounded-lg mb-6">
                  <p class="font-medium">⚠️ Important: Save These Shares Securely</p>
                  <p class="text-sm mt-1">
                    These shares will only be shown once. Store them in separate secure locations.
                    You need {@threshold} shares to unseal the vault.
                  </p>
                </div>

                <div class="space-y-4">
                  <%= for {share, index} <- Enum.with_index(@initialized_shares, 1) do %>
                    <div class="border border-gray-300 rounded-lg p-4">
                      <div class="flex items-center justify-between mb-2">
                        <span class="font-semibold text-gray-700">Share {index}</span>
                        <button
                          phx-click="copy_share"
                          phx-value-share={share}
                          class="text-sm bg-gray-100 hover:bg-gray-200 px-3 py-1 rounded transition-colors"
                        >
                          Copy
                        </button>
                      </div>
                      <code class="block bg-gray-900 text-gray-100 p-3 rounded text-xs break-all">
                        {share}
                      </code>
                    </div>
                  <% end %>
                </div>

                <div class="mt-6 flex space-x-4">
                  <button
                    phx-click="download_shares"
                    class="flex-1 bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 transition-colors duration-200"
                  >
                    Download Shares
                  </button>

                  <a
                    href="/vault/unseal"
                    class="flex-1 bg-green-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-green-700 transition-colors duration-200 text-center"
                  >
                    Continue to Unseal
                  </a>
                </div>
              </div>
            </div>
          <% else %>
            <!-- Configuration Form -->
            <div class="bg-white shadow-lg rounded-lg overflow-hidden">
              <div class="px-6 py-4 border-b border-gray-200">
                <h2 class="text-xl font-semibold text-gray-800">Configuration</h2>
              </div>

              <div class="px-6 py-6">
                <form phx-submit="initialize" class="space-y-6">
                  <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">
                      Total Shares
                    </label>
                    <input
                      type="number"
                      name="total_shares"
                      value={@total_shares}
                      min="1"
                      max="255"
                      phx-change="update_total_shares"
                      class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                    <p class="mt-2 text-sm text-gray-500">
                      Number of key shares to generate (recommended: 5)
                    </p>
                  </div>

                  <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">
                      Threshold
                    </label>
                    <input
                      type="number"
                      name="threshold"
                      value={@threshold}
                      min="1"
                      max={@total_shares}
                      phx-change="update_threshold"
                      class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                    <p class="mt-2 text-sm text-gray-500">
                      Number of shares required to unseal (recommended: 3)
                    </p>
                  </div>

                  <%= if @error_message do %>
                    <div class="bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded-lg">
                      <p class="font-medium">Error</p>
                      <p class="text-sm">{@error_message}</p>
                    </div>
                  <% end %>

                  <div class="bg-blue-50 border border-blue-200 text-blue-800 px-4 py-3 rounded-lg">
                    <p class="font-medium">What is Shamir Secret Sharing?</p>
                    <p class="text-sm mt-1">
                      The vault's master encryption key will be split into {@total_shares} shares.
                      Any {@threshold} shares can reconstruct the key to unseal the vault.
                      This prevents a single person from having complete access.
                    </p>
                  </div>

                  <button
                    type="submit"
                    class="w-full bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 transition-colors duration-200"
                  >
                    Initialize Vault
                  </button>
                </form>
              </div>
            </div>
          <% end %>
        <% end %>
      </div>
    </div>
    """
  end

  @impl true
  def handle_event("update_total_shares", %{"total_shares" => total}, socket) do
    total_int = String.to_integer(total)
    {:noreply, assign(socket, :total_shares, total_int)}
  end

  @impl true
  def handle_event("update_threshold", %{"threshold" => threshold}, socket) do
    threshold_int = String.to_integer(threshold)
    {:noreply, assign(socket, :threshold, threshold_int)}
  end

  @impl true
  def handle_event("initialize", _params, socket) do
    total = socket.assigns.total_shares
    threshold = socket.assigns.threshold

    case SealState.initialize(total, threshold) do
      {:ok, shares} ->
        # Encode shares for display
        encoded_shares = Enum.map(shares, &Shamir.encode_share/1)

        socket =
          socket
          |> assign(:initialized_shares, encoded_shares)
          |> assign(:error_message, nil)

        Logger.info("Vault initialized via UI with #{total} shares (threshold: #{threshold})")
        {:noreply, socket}

      {:error, reason} ->
        socket = assign(socket, :error_message, reason)
        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("copy_share", %{"share" => _share}, socket) do
    # Copy handled by JavaScript
    {:noreply, socket}
  end

  @impl true
  def handle_event("download_shares", _params, socket) do
    # Create downloadable text file with shares
    shares_text =
      socket.assigns.initialized_shares
      |> Enum.with_index(1)
      |> Enum.map_join("\n", fn {share, index} -> "Share #{index}:\n#{share}\n" end)

    content = """
    SecretHub Vault Unseal Shares
    =============================
    Generated: #{DateTime.utc_now() |> DateTime.to_string()}
    Threshold: #{socket.assigns.threshold}
    Total Shares: #{socket.assigns.total_shares}

    ⚠️  CRITICAL: Store these shares in separate secure locations.
    You need #{socket.assigns.threshold} shares to unseal the vault.

    #{shares_text}
    """

    # Send download event to client
    {:noreply, push_event(socket, "download", %{filename: "vault-shares.txt", content: content})}
  end
end
