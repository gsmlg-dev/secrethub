defmodule SecretHub.Web.SecretRotatorLive do
  @moduledoc """
  LiveView for configuring per-secret rotators.
  """

  use SecretHub.Web, :live_view

  alias SecretHub.Core.{EngineConfigurations, Secrets}

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:rotators, [])
     |> assign(:engines, [])
     |> assign(:selected_rotator, nil)
     |> load_rotators()
     |> load_engines()}
  end

  @impl true
  def handle_params(%{"id" => id}, _url, socket) do
    case Secrets.get_secret_rotator(id) do
      {:ok, rotator} ->
        {:noreply, assign(socket, :selected_rotator, rotator)}

      {:error, :not_found} ->
        {:noreply,
         socket
         |> put_flash(:error, "Rotator not found")
         |> push_navigate(to: ~p"/admin/rotators")}
    end
  end

  @impl true
  def handle_params(_params, _url, socket) do
    {:noreply, assign(socket, :selected_rotator, nil)}
  end

  @impl true
  def handle_event("view_rotator", %{"id" => id}, socket) do
    {:noreply, push_patch(socket, to: ~p"/admin/rotators/#{id}")}
  end

  @impl true
  def handle_event("toggle_rotator", %{"id" => id}, socket) do
    with {:ok, rotator} <- Secrets.get_secret_rotator(id),
         {:ok, _updated} <- Secrets.update_secret_rotator(rotator, %{enabled: !rotator.enabled}) do
      {:noreply, load_rotators(socket)}
    else
      _ -> {:noreply, put_flash(socket, :error, "Failed to update rotator")}
    end
  end

  @impl true
  def handle_event("save_rotator", %{"rotator" => params}, socket) do
    rotator = socket.assigns.selected_rotator
    attrs = normalize_rotator_params(params)

    case Secrets.update_secret_rotator(rotator, attrs) do
      {:ok, updated} ->
        {:ok, updated} = Secrets.get_secret_rotator(updated.id)

        {:noreply,
         socket
         |> put_flash(:info, "Rotator updated")
         |> assign(:selected_rotator, updated)
         |> load_rotators()}

      {:error, changeset} ->
        {:noreply,
         put_flash(socket, :error, "Failed to update rotator: #{format_errors(changeset)}")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-semibold text-on-surface">Secret Rotators</h1>
          <p class="mt-2 text-sm text-on-surface-variant">
            Configure how each secret is rotated. Engines provide the backend rotation capability.
          </p>
        </div>
      </div>

      <%= if @selected_rotator do %>
        <.rotator_detail rotator={@selected_rotator} engines={@engines} />
      <% else %>
        <.rotator_table rotators={@rotators} />
      <% end %>
    </div>
    """
  end

  defp load_rotators(socket) do
    assign(socket, :rotators, Secrets.list_secret_rotators())
  end

  defp load_engines(socket) do
    assign(socket, :engines, EngineConfigurations.list_configurations())
  end

  defp rotator_table(assigns) do
    ~H"""
    <div class="overflow-hidden rounded-lg border border-outline-variant bg-surface-container">
      <table class="min-w-full divide-y divide-outline-variant">
        <thead class="bg-surface-container-low">
          <tr>
            <th class="px-4 py-3 text-left text-sm font-semibold text-on-surface">Secret</th>
            <th class="px-4 py-3 text-left text-sm font-semibold text-on-surface">Rotator</th>
            <th class="px-4 py-3 text-left text-sm font-semibold text-on-surface">Mode</th>
            <th class="px-4 py-3 text-left text-sm font-semibold text-on-surface">Engine</th>
            <th class="px-4 py-3 text-left text-sm font-semibold text-on-surface">Status</th>
            <th class="px-4 py-3 text-right text-sm font-semibold text-on-surface">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-outline-variant">
          <tr :for={rotator <- @rotators} class="hover:bg-surface-container-low">
            <td class="px-4 py-3 text-sm">
              <div class="font-medium text-on-surface">{secret_name(rotator)}</div>
              <div class="text-on-surface-variant">{secret_path(rotator)}</div>
            </td>
            <td class="px-4 py-3 text-sm">
              <div class="font-medium text-on-surface">{rotator.name}</div>
              <div class="text-on-surface-variant">{format_rotator_type(rotator.rotator_type)}</div>
            </td>
            <td class="px-4 py-3 text-sm text-on-surface">
              {format_mode(rotator.trigger_mode)}
            </td>
            <td class="px-4 py-3 text-sm text-on-surface">
              {engine_name(rotator)}
            </td>
            <td class="px-4 py-3 text-sm">
              <span class={status_class(rotator.enabled)}>
                {if rotator.enabled, do: "Enabled", else: "Disabled"}
              </span>
            </td>
            <td class="px-4 py-3 text-right text-sm">
              <button
                phx-click="view_rotator"
                phx-value-id={rotator.id}
                class="text-primary hover:text-primary/80"
              >
                Configure
              </button>
              <button
                phx-click="toggle_rotator"
                phx-value-id={rotator.id}
                class="ml-4 text-primary hover:text-primary/80"
              >
                {if rotator.enabled, do: "Disable", else: "Enable"}
              </button>
            </td>
          </tr>

          <tr :if={@rotators == []}>
            <td colspan="6" class="px-4 py-8 text-center text-sm text-on-surface-variant">
              No per-secret rotators exist yet. Create a secret to generate its default manual rotator.
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    """
  end

  defp rotator_detail(assigns) do
    ~H"""
    <div class="rounded-lg border border-outline-variant bg-surface-container p-6">
      <div class="flex items-start justify-between">
        <div>
          <h2 class="text-xl font-semibold text-on-surface">{@rotator.name}</h2>
          <p class="mt-1 text-sm text-on-surface-variant">{secret_path(@rotator)}</p>
        </div>
        <.link navigate={~p"/admin/rotators"} class="text-sm text-primary hover:text-primary/80">
          Back to Rotators
        </.link>
      </div>

      <dl class="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div>
          <dt class="text-sm text-on-surface-variant">Rotation Type</dt>
          <dd class="mt-1 text-sm font-medium text-on-surface">
            {format_rotator_type(@rotator.rotator_type)}
          </dd>
        </div>
        <div>
          <dt class="text-sm text-on-surface-variant">Trigger Mode</dt>
          <dd class="mt-1 text-sm font-medium text-on-surface">
            {format_mode(@rotator.trigger_mode)}
          </dd>
        </div>
        <div>
          <dt class="text-sm text-on-surface-variant">Engine</dt>
          <dd class="mt-1 text-sm font-medium text-on-surface">{engine_name(@rotator)}</dd>
        </div>
        <div>
          <dt class="text-sm text-on-surface-variant">Schedule</dt>
          <dd class="mt-1 text-sm font-mono text-on-surface">{@rotator.schedule_cron || "manual"}</dd>
        </div>
        <div>
          <dt class="text-sm text-on-surface-variant">Last Rotation</dt>
          <dd class="mt-1 text-sm font-medium text-on-surface">
            {format_datetime(@rotator.last_rotation_at)}
          </dd>
        </div>
        <div>
          <dt class="text-sm text-on-surface-variant">Last Status</dt>
          <dd class="mt-1 text-sm font-medium text-on-surface">
            {format_status(@rotator.last_rotation_status)}
          </dd>
        </div>
      </dl>

      <form phx-submit="save_rotator" class="mt-8 grid grid-cols-1 gap-5 sm:grid-cols-2">
        <div>
          <label for="rotator_trigger_mode" class="block text-sm font-medium text-on-surface">
            Trigger Mode
          </label>
          <select
            id="rotator_trigger_mode"
            name="rotator[trigger_mode]"
            class="select select-bordered mt-1 w-full"
          >
            <option value="manual" selected={@rotator.trigger_mode in [nil, :manual]}>Manual</option>
            <option value="scheduled" selected={@rotator.trigger_mode == :scheduled}>
              Scheduled
            </option>
          </select>
        </div>

        <div>
          <label for="rotator_engine" class="block text-sm font-medium text-on-surface">Engine</label>
          <select
            id="rotator_engine"
            name="rotator[engine_configuration_id]"
            class="select select-bordered mt-1 w-full"
          >
            <option value="">Manual Web UI</option>
            <%= for engine <- @engines do %>
              <option value={engine.id} selected={@rotator.engine_configuration_id == engine.id}>
                {engine.name}
              </option>
            <% end %>
          </select>
        </div>

        <div>
          <label for="rotator_schedule" class="block text-sm font-medium text-on-surface">
            Cron Schedule
          </label>
          <input
            id="rotator_schedule"
            name="rotator[schedule_cron]"
            value={@rotator.schedule_cron || ""}
            class="input input-bordered mt-1 w-full font-mono text-sm"
            placeholder="0 2 * * 0"
          />
        </div>

        <div class="flex items-end">
          <label class="flex items-center gap-2 text-sm text-on-surface">
            <input
              type="checkbox"
              name="rotator[enabled]"
              value="true"
              checked={@rotator.enabled}
              class="checkbox checkbox-primary"
            /> Enabled
          </label>
        </div>

        <div class="sm:col-span-2 flex justify-end">
          <button type="submit" class="btn btn-primary">Save Rotator</button>
        </div>
      </form>
    </div>
    """
  end

  defp normalize_rotator_params(params) do
    engine_configuration_id = blank_to_nil(params["engine_configuration_id"])

    %{
      "engine_configuration_id" => engine_configuration_id,
      "enabled" => params["enabled"] == "true",
      "trigger_mode" => params["trigger_mode"] || "manual",
      "schedule_cron" => blank_to_nil(params["schedule_cron"]),
      "rotator_type" => if(engine_configuration_id, do: "built_in", else: "manual")
    }
  end

  defp secret_name(%{secret: %{name: name}}) when is_binary(name), do: name
  defp secret_name(_rotator), do: "Unknown secret"

  defp secret_path(%{secret: %{secret_path: path}}) when is_binary(path), do: path
  defp secret_path(_rotator), do: "-"

  defp engine_name(%{engine_configuration: %{name: name}}) when is_binary(name), do: name
  defp engine_name(_rotator), do: "Manual Web UI"

  defp format_mode(nil), do: "Manual"

  defp format_mode(mode),
    do: mode |> to_string() |> String.replace("_", " ") |> String.capitalize()

  defp format_rotator_type(nil), do: "-"

  defp format_rotator_type(type) do
    type
    |> to_string()
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  defp format_status(nil), do: "Never run"
  defp format_status(status), do: format_rotator_type(status)

  defp format_datetime(nil), do: "Never"

  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M UTC")
  end

  defp status_class(true), do: "badge badge-success"
  defp status_class(false), do: "badge badge-ghost"

  defp blank_to_nil(nil), do: nil
  defp blank_to_nil(""), do: nil
  defp blank_to_nil(value), do: value

  defp format_errors(changeset) do
    changeset.errors
    |> Enum.map(fn {field, {message, _opts}} -> "#{field} #{message}" end)
    |> Enum.join(", ")
  end
end
