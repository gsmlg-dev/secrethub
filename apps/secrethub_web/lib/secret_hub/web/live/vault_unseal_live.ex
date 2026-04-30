defmodule SecretHub.Web.VaultUnsealLive do
  @moduledoc """
  LiveView for vault unsealing interface.

  Provides a user-friendly interface for administrators to:
  - Check vault seal status
  - Submit Shamir shares to unseal the vault
  - Monitor unseal progress
  - Re-seal the vault when needed
  """

  use SecretHub.Web, :live_view
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
    <div class="min-h-screen bg-surface-container-low py-12 px-4 sm:px-6 lg:px-8">
      <div class="max-w-3xl mx-auto">
        <!-- Header -->
        <div class="text-center mb-8">
          <h1 class="text-4xl font-bold text-on-surface mb-2">SecretHub Vault</h1>
          <p class="text-lg text-on-surface-variant">
            Secure Secrets Management Platform
          </p>
        </div>
        
    <!-- Vault Status Card -->
        <div class="bg-surface-container shadow-lg rounded-lg overflow-hidden mb-6">
          <div class="px-6 py-4 border-b border-outline-variant">
            <h2 class="text-xl font-semibold text-on-surface">Vault Status</h2>
          </div>

          <div class="px-6 py-6">
            <div class="grid grid-cols-2 gap-6">
              <!-- Initialized Status -->
              <div class="flex items-center space-x-3">
                <div class={"w-3 h-3 rounded-full #{if @vault_status.initialized, do: "bg-success", else: "bg-error text-error-content"}"}>
                </div>
                <div>
                  <p class="text-sm text-on-surface-variant">Initialized</p>
                  <p class="font-semibold text-on-surface">
                    {if @vault_status.initialized, do: "Yes", else: "No"}
                  </p>
                </div>
              </div>
              
    <!-- Sealed Status -->
              <div class="flex items-center space-x-3">
                <div class={"w-3 h-3 rounded-full #{if @vault_status.sealed, do: "bg-error text-error-content", else: "bg-success"}"}>
                </div>
                <div>
                  <p class="text-sm text-on-surface-variant">Sealed</p>
                  <p class="font-semibold text-on-surface">
                    {if @vault_status.sealed, do: "Yes", else: "No"}
                  </p>
                </div>
              </div>
              
    <!-- Progress -->
              <%= if @vault_status.initialized and @vault_status.threshold do %>
                <div class="col-span-2">
                  <p class="text-sm text-on-surface-variant mb-2">Unseal Progress</p>
                  <div class="flex items-center space-x-4">
                    <div class="flex-1 bg-surface-container-high rounded-full h-3">
                      <div
                        class="bg-primary text-primary-content h-3 rounded-full transition-all duration-300"
                        style={"width: #{(@vault_status.progress / @vault_status.threshold * 100)}%"}
                      >
                      </div>
                    </div>
                    <span class="text-sm font-semibold text-on-surface">
                      {@vault_status.progress} / {@vault_status.threshold}
                    </span>
                  </div>
                </div>
              <% end %>
            </div>
          </div>
        </div>
        
    <!-- Unseal Form (only show if vault is sealed) -->
        <%= if @vault_status.initialized and @vault_status.sealed do %>
          <div class="bg-surface-container shadow-lg rounded-lg overflow-hidden mb-6">
            <div class="px-6 py-4 border-b border-outline-variant">
              <h2 class="text-xl font-semibold text-on-surface">Unseal Vault</h2>
            </div>

            <div class="px-6 py-6">
              <form phx-submit="submit_share" class="space-y-4">
                <div>
                  <label
                    for="unseal-share-input"
                    class="block text-sm font-medium text-on-surface mb-2"
                  >
                    Enter Unseal Shares
                  </label>
                  <textarea
                    id="unseal-share-input"
                    name="share"
                    phx-change="update_share"
                    placeholder="secrethub-share-xxxxxxxxxx\nsecrethub-share-yyyyyyyyyy\nsecrethub-share-zzzzzzzzzz"
                    class="w-full min-h-36 px-4 py-2 border border-outline-variant rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent font-mono text-sm"
                    autocomplete="off"
                  ><%= @share_input %></textarea>
                  <p class="mt-2 text-sm text-on-surface-variant">
                    Paste one or more Shamir shares above, separated by newlines, commas, or spaces. You need {@vault_status.threshold} shares to unseal the vault.
                  </p>
                </div>
                
    <!-- Error Message -->
                <%= if @error_message do %>
                  <div class="bg-error/5 border border-error text-error px-4 py-3 rounded-lg">
                    <p class="font-medium">Error</p>
                    <p class="text-sm">{@error_message}</p>
                  </div>
                <% end %>
                
    <!-- Success Message -->
                <%= if @success_message do %>
                  <div class="bg-success/5 border border-success text-success px-4 py-3 rounded-lg">
                    <p class="font-medium">Success</p>
                    <p class="text-sm">{@success_message}</p>
                  </div>
                <% end %>

                <button
                  type="submit"
                  class="w-full bg-primary text-primary-content px-6 py-3 rounded-lg font-semibold hover:bg-primary transition-colors duration-200"
                >
                  Submit Share(s)
                </button>
              </form>
              
    <!-- Submitted Shares -->
              <%= if length(@shares_submitted) > 0 do %>
                <div class="mt-6">
                  <p class="text-sm font-medium text-on-surface mb-2">
                    Shares Submitted: {length(@shares_submitted)}
                  </p>
                  <div class="flex flex-wrap gap-2">
                    <%= for i <- 1..length(@shares_submitted) do %>
                      <div class="w-3 h-3 bg-success rounded-full"></div>
                    <% end %>
                    <%= for _i <- 1..(@vault_status.threshold - length(@shares_submitted)) do %>
                      <div class="w-3 h-3 bg-outline-variant rounded-full"></div>
                    <% end %>
                  </div>
                </div>
              <% end %>
            </div>
          </div>
        <% end %>
        
    <!-- Unsealed Actions (only show if vault is unsealed) -->
        <%= if @vault_status.initialized and not @vault_status.sealed do %>
          <div class="bg-surface-container shadow-lg rounded-lg overflow-hidden">
            <div class="px-6 py-4 border-b border-outline-variant">
              <h2 class="text-xl font-semibold text-on-surface">Vault Unsealed</h2>
            </div>

            <div class="px-6 py-6">
              <%= if @success_message do %>
                <div class="bg-success/5 border border-success text-success px-4 py-3 rounded-lg mb-4">
                  <p class="font-medium">Success</p>
                  <p class="text-sm">{@success_message}</p>
                </div>
              <% end %>

              <div class="bg-success/5 border border-success text-success px-4 py-3 rounded-lg mb-4">
                <p class="font-medium">Vault is operational</p>
                <p class="text-sm">The vault is unsealed and ready to serve secrets.</p>
              </div>

              <div class="flex space-x-4">
                <a
                  href="/admin/dashboard"
                  class="flex-1 bg-primary text-primary-content px-6 py-3 rounded-lg font-semibold hover:bg-primary transition-colors duration-200 text-center"
                >
                  Go to Dashboard
                </a>
              </div>
            </div>
          </div>
        <% end %>
        
    <!-- Not Initialized Message -->
        <%= if not @vault_status.initialized do %>
          <div class="bg-surface-container shadow-lg rounded-lg overflow-hidden">
            <div class="px-6 py-6">
              <div class="bg-warning/5 border border-warning text-warning px-4 py-3 rounded-lg">
                <p class="font-medium">Vault not initialized</p>
                <p class="text-sm mt-1">
                  The vault needs to be initialized before it can be unsealed.
                  Use the API endpoint
                  <code class="bg-warning/10 px-2 py-1 rounded">POST /v1/sys/init</code>
                  to initialize.
                </p>
              </div>

              <div class="mt-4">
                <p class="text-sm text-on-surface-variant">
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
    with {:ok, decoded_shares} <- decode_share_input(share),
         {:ok, unseal_progress} <- unseal_shares(decoded_shares) do
      vault_status = SealState.status()

      if vault_status.sealed do
        # Still sealed, need more shares
        socket =
          socket
          |> assign(:vault_status, vault_status)
          |> assign(:share_input, "")
          |> assign(:error_message, nil)
          |> assign(
            :success_message,
            accepted_message(length(decoded_shares), unseal_progress)
          )
          |> assign(:shares_submitted, submitted_shares(unseal_progress.progress))

        {:noreply, socket}
      else
        # Unsealed!
        socket =
          socket
          |> assign(:vault_status, vault_status)
          |> assign(:share_input, "")
          |> assign(:error_message, nil)
          |> assign(:success_message, "Vault unsealed successfully!")
          |> assign(:shares_submitted, [])

        Logger.info("Vault unsealed via UI")
        {:noreply, socket}
      end
    else
      {:error, reason} ->
        socket =
          socket
          |> assign(:error_message, "Failed to accept share: #{reason}")
          |> assign(:success_message, nil)

        {:noreply, socket}
    end
  end

  @impl true
  def handle_info(:refresh_status, socket) do
    status = SealState.status()
    {:noreply, assign(socket, :vault_status, status)}
  end

  defp submitted_shares(progress) when progress > 0, do: Enum.to_list(1..progress)
  defp submitted_shares(_progress), do: []

  defp decode_share_input(input) do
    shares =
      input
      |> String.split(~r/[\s,]+/, trim: true)

    if Enum.empty?(shares) do
      {:error, "No unseal shares provided"}
    else
      decode_shares(shares, [])
    end
  end

  defp decode_shares([], decoded_shares), do: {:ok, Enum.reverse(decoded_shares)}

  defp decode_shares([share | remaining], decoded_shares) do
    case Shamir.decode_share(share) do
      {:ok, decoded_share} -> decode_shares(remaining, [decoded_share | decoded_shares])
      {:error, reason} -> {:error, reason}
    end
  end

  defp unseal_shares(decoded_shares) do
    Enum.reduce_while(decoded_shares, {:error, "No unseal shares provided"}, fn decoded_share,
                                                                                _last_result ->
      case SealState.unseal(decoded_share) do
        {:ok, %{sealed: false} = progress} -> {:halt, {:ok, progress}}
        {:ok, progress} -> {:cont, {:ok, progress}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp accepted_message(1, unseal_progress) do
    "Share accepted! #{unseal_progress.progress}/#{unseal_progress.threshold} shares submitted."
  end

  defp accepted_message(_share_count, unseal_progress) do
    "Shares accepted! #{unseal_progress.progress}/#{unseal_progress.threshold} shares submitted."
  end
end
