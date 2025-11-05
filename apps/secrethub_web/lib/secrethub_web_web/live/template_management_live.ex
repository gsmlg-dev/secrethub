defmodule SecretHub.WebWeb.TemplateManagementLive do
  @moduledoc """
  LiveView for template and sink management.

  Provides UI for creating, editing, and managing templates and their associated sinks.
  """

  use SecretHub.WebWeb, :live_view
  require Logger
  alias SecretHub.Core.Templates

  @impl true
  def mount(_params, _session, socket) do
    templates = Templates.list_templates(preload_sinks: true)

    socket =
      socket
      |> assign(:templates, templates)
      |> assign(:selected_template, nil)
      |> assign(:show_template_form, false)
      |> assign(:show_sink_form, false)
      |> assign(:form_mode, :create)
      |> assign(:template_form, to_form(%{}))
      |> assign(:sink_form, to_form(%{}))
      |> assign(:preview_content, nil)
      |> assign(:preview_error, nil)

    {:ok, socket}
  end

  @impl true
  def handle_params(%{"template_id" => template_id}, _url, socket) do
    template = Templates.get_template(template_id, preload_sinks: true)

    socket =
      socket
      |> assign(:selected_template, template)
      |> assign(:show_template_form, false)
      |> assign(:show_sink_form, false)

    {:noreply, socket}
  end

  def handle_params(_params, _url, socket) do
    socket = assign(socket, :selected_template, nil)
    {:noreply, socket}
  end

  @impl true
  def handle_event("new_template", _params, socket) do
    template_form =
      to_form(%{
        "name" => "",
        "description" => "",
        "template_content" => "",
        "variable_bindings" => %{},
        "status" => "active"
      })

    socket =
      socket
      |> assign(:show_template_form, true)
      |> assign(:form_mode, :create)
      |> assign(:template_form, template_form)
      |> assign(:selected_template, nil)

    {:noreply, socket}
  end

  @impl true
  def handle_event("edit_template", %{"id" => template_id}, socket) do
    case Templates.get_template(template_id, preload_sinks: true) do
      nil ->
        {:noreply, put_flash(socket, :error, "Template not found")}

      template ->
        template_form =
          to_form(%{
            "name" => template.name,
            "description" => template.description || "",
            "template_content" => template.template_content,
            "variable_bindings" => template.variable_bindings,
            "status" => template.status
          })

        socket =
          socket
          |> assign(:show_template_form, true)
          |> assign(:form_mode, :edit)
          |> assign(:selected_template, template)
          |> assign(:template_form, template_form)

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("save_template", %{"template" => template_params}, socket) do
    case socket.assigns.form_mode do
      :create ->
        create_template(socket, template_params)

      :edit ->
        update_template(socket, template_params)
    end
  end

  @impl true
  def handle_event("delete_template", %{"id" => template_id}, socket) do
    case Templates.get_template(template_id) do
      nil ->
        {:noreply, put_flash(socket, :error, "Template not found")}

      template ->
        case Templates.delete_template(template) do
          {:ok, _} ->
            templates = Templates.list_templates(preload_sinks: true)

            socket =
              socket
              |> assign(:templates, templates)
              |> assign(:selected_template, nil)
              |> put_flash(:info, "Template deleted successfully")

            {:noreply, socket}

          {:error, _changeset} ->
            {:noreply, put_flash(socket, :error, "Failed to delete template")}
        end
    end
  end

  @impl true
  def handle_event("cancel_template_form", _params, socket) do
    socket =
      socket
      |> assign(:show_template_form, false)
      |> assign(:template_form, to_form(%{}))

    {:noreply, socket}
  end

  @impl true
  def handle_event("new_sink", %{"template_id" => template_id}, socket) do
    template = Templates.get_template(template_id)

    sink_form =
      to_form(%{
        "name" => "",
        "template_id" => template_id,
        "file_path" => "",
        "permissions" => %{},
        "backup_enabled" => false,
        "reload_trigger" => %{},
        "status" => "active"
      })

    socket =
      socket
      |> assign(:show_sink_form, true)
      |> assign(:form_mode, :create)
      |> assign(:sink_form, sink_form)
      |> assign(:selected_template, template)

    {:noreply, socket}
  end

  @impl true
  def handle_event("edit_sink", %{"id" => sink_id}, socket) do
    case Templates.get_sink(sink_id, preload_template: true) do
      nil ->
        {:noreply, put_flash(socket, :error, "Sink not found")}

      sink ->
        sink_form =
          to_form(%{
            "name" => sink.name,
            "template_id" => sink.template_id,
            "file_path" => sink.file_path,
            "permissions" => sink.permissions,
            "backup_enabled" => sink.backup_enabled,
            "reload_trigger" => sink.reload_trigger || %{},
            "status" => sink.status
          })

        socket =
          socket
          |> assign(:show_sink_form, true)
          |> assign(:form_mode, :edit)
          |> assign(:selected_sink, sink)
          |> assign(:sink_form, sink_form)

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("save_sink", %{"sink" => sink_params}, socket) do
    case socket.assigns.form_mode do
      :create ->
        create_sink(socket, sink_params)

      :edit ->
        update_sink(socket, sink_params)
    end
  end

  @impl true
  def handle_event("delete_sink", %{"id" => sink_id}, socket) do
    case Templates.get_sink(sink_id) do
      nil ->
        {:noreply, put_flash(socket, :error, "Sink not found")}

      sink ->
        case Templates.delete_sink(sink) do
          {:ok, _} ->
            template = Templates.get_template(sink.template_id, preload_sinks: true)

            socket =
              socket
              |> assign(:selected_template, template)
              |> put_flash(:info, "Sink deleted successfully")

            {:noreply, socket}

          {:error, _changeset} ->
            {:noreply, put_flash(socket, :error, "Failed to delete sink")}
        end
    end
  end

  @impl true
  def handle_event("cancel_sink_form", _params, socket) do
    socket =
      socket
      |> assign(:show_sink_form, false)
      |> assign(:sink_form, to_form(%{}))

    {:noreply, socket}
  end

  @impl true
  def handle_event(
        "preview_template",
        %{"template_content" => content, "mock_data" => mock_data_json},
        socket
      ) do
    try do
      mock_data = Jason.decode!(mock_data_json)

      # TODO: Call Agent's template preview API
      socket =
        socket
        |> assign(:preview_content, "Preview: #{content}")
        |> assign(:preview_error, nil)

      {:noreply, socket}
    rescue
      e ->
        socket =
          socket
          |> assign(:preview_content, nil)
          |> assign(:preview_error, Exception.message(e))

        {:noreply, socket}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 py-8">
      <div class="flex justify-between items-center mb-6">
        <h1 class="text-3xl font-bold">Template Management</h1>
        <button
          phx-click="new_template"
          class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
        >
          New Template
        </button>
      </div>

      <%= if @show_template_form do %>
        <div class="bg-white shadow-md rounded-lg p-6 mb-6">
          <h2 class="text-xl font-semibold mb-4">
            {if @form_mode == :create, do: "Create Template", else: "Edit Template"}
          </h2>

          <.form for={@template_form} phx-submit="save_template">
            <div class="grid grid-cols-1 gap-4">
              <div>
                <label class="block text-sm font-medium mb-1">Name</label>
                <input
                  type="text"
                  name="template[name]"
                  value={@template_form.data["name"]}
                  class="w-full border rounded px-3 py-2"
                  required
                />
              </div>

              <div>
                <label class="block text-sm font-medium mb-1">Description</label>
                <textarea
                  name="template[description]"
                  class="w-full border rounded px-3 py-2"
                  rows="2"
                ><%= @template_form.data["description"] %></textarea>
              </div>

              <div>
                <label class="block text-sm font-medium mb-1">Template Content</label>
                <textarea
                  name="template[template_content]"
                  class="w-full border rounded px-3 py-2 font-mono text-sm"
                  rows="10"
                  placeholder="Example: DB_PASS={{db.password}}"
                  required
                ><%= @template_form.data["template_content"] %></textarea>
                <p class="text-xs text-gray-500 mt-1">
                  Use EEx syntax: &lt;%= variable %&gt; for output, &lt;% code %&gt; for logic
                </p>
              </div>

              <div>
                <label class="block text-sm font-medium mb-1">Variable Bindings (JSON)</label>
                <textarea
                  name="template[variable_bindings]"
                  class="w-full border rounded px-3 py-2 font-mono text-sm"
                  rows="4"
                  placeholder='{"db": "prod.database.password", "api_key": "prod.api.key"}'
                ><%= Jason.encode!(@template_form.data["variable_bindings"] || %{}) %></textarea>
                <p class="text-xs text-gray-500 mt-1">
                  Map variable names to secret paths
                </p>
              </div>

              <div>
                <label class="block text-sm font-medium mb-1">Status</label>
                <select name="template[status]" class="w-full border rounded px-3 py-2">
                  <option value="active" selected={@template_form.data["status"] == "active"}>
                    Active
                  </option>
                  <option value="inactive" selected={@template_form.data["status"] == "inactive"}>
                    Inactive
                  </option>
                  <option value="archived" selected={@template_form.data["status"] == "archived"}>
                    Archived
                  </option>
                </select>
              </div>
            </div>

            <div class="flex gap-2 mt-6">
              <button
                type="submit"
                class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
              >
                Save Template
              </button>
              <button
                type="button"
                phx-click="cancel_template_form"
                class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded"
              >
                Cancel
              </button>
            </div>
          </.form>
        </div>
      <% end %>

      <%= if @show_sink_form do %>
        <div class="bg-white shadow-md rounded-lg p-6 mb-6">
          <h2 class="text-xl font-semibold mb-4">
            {if @form_mode == :create, do: "Create Sink", else: "Edit Sink"}
          </h2>

          <.form for={@sink_form} phx-submit="save_sink">
            <input type="hidden" name="sink[template_id]" value={@sink_form.data["template_id"]} />

            <div class="grid grid-cols-1 gap-4">
              <div>
                <label class="block text-sm font-medium mb-1">Name</label>
                <input
                  type="text"
                  name="sink[name]"
                  value={@sink_form.data["name"]}
                  class="w-full border rounded px-3 py-2"
                  required
                />
              </div>

              <div>
                <label class="block text-sm font-medium mb-1">File Path</label>
                <input
                  type="text"
                  name="sink[file_path]"
                  value={@sink_form.data["file_path"]}
                  class="w-full border rounded px-3 py-2"
                  placeholder="/etc/myapp/config.conf"
                  required
                />
              </div>

              <div>
                <label class="block text-sm font-medium mb-1">Permissions (JSON)</label>
                <textarea
                  name="sink[permissions]"
                  class="w-full border rounded px-3 py-2 font-mono text-sm"
                  rows="3"
                  placeholder='{"mode": 384, "owner": "myapp", "group": "myapp"}'
                ><%= Jason.encode!(@sink_form.data["permissions"] || %{}) %></textarea>
                <p class="text-xs text-gray-500 mt-1">
                  Mode: decimal (e.g., 384 = 0o600)
                </p>
              </div>

              <div>
                <label class="flex items-center">
                  <input
                    type="checkbox"
                    name="sink[backup_enabled]"
                    checked={@sink_form.data["backup_enabled"]}
                    class="mr-2"
                  />
                  <span class="text-sm font-medium">Enable Backup</span>
                </label>
              </div>

              <div>
                <label class="block text-sm font-medium mb-1">Reload Trigger (JSON)</label>
                <textarea
                  name="sink[reload_trigger]"
                  class="w-full border rounded px-3 py-2 font-mono text-sm"
                  rows="3"
                  placeholder='{"type": "signal", "value": "HUP", "target": "myapp"}'
                ><%= Jason.encode!(@sink_form.data["reload_trigger"] || %{}) %></textarea>
                <p class="text-xs text-gray-500 mt-1">
                  Types: signal, http, script
                </p>
              </div>

              <div>
                <label class="block text-sm font-medium mb-1">Status</label>
                <select name="sink[status]" class="w-full border rounded px-3 py-2">
                  <option value="active" selected={@sink_form.data["status"] == "active"}>
                    Active
                  </option>
                  <option value="inactive" selected={@sink_form.data["status"] == "inactive"}>
                    Inactive
                  </option>
                </select>
              </div>
            </div>

            <div class="flex gap-2 mt-6">
              <button
                type="submit"
                class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
              >
                Save Sink
              </button>
              <button
                type="button"
                phx-click="cancel_sink_form"
                class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded"
              >
                Cancel
              </button>
            </div>
          </.form>
        </div>
      <% end %>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Templates List -->
        <div class="bg-white shadow-md rounded-lg p-6">
          <h2 class="text-xl font-semibold mb-4">Templates</h2>

          <%= if Enum.empty?(@templates) do %>
            <p class="text-gray-500">No templates yet. Create one to get started.</p>
          <% else %>
            <div class="space-y-2">
              <%= for template <- @templates do %>
                <div class="border rounded p-4 hover:bg-gray-50">
                  <div class="flex justify-between items-start">
                    <div class="flex-1">
                      <h3 class="font-semibold">{template.name}</h3>
                      <%= if template.description do %>
                        <p class="text-sm text-gray-600">{template.description}</p>
                      <% end %>
                      <div class="mt-2 flex gap-2 text-xs">
                        <span class="bg-blue-100 text-blue-800 px-2 py-1 rounded">
                          {template.status}
                        </span>
                        <span class="bg-gray-100 text-gray-800 px-2 py-1 rounded">
                          {length(template.sinks)} sinks
                        </span>
                      </div>
                    </div>
                    <div class="flex gap-1">
                      <button
                        phx-click="edit_template"
                        phx-value-id={template.id}
                        class="text-blue-600 hover:text-blue-800 px-2 py-1"
                      >
                        Edit
                      </button>
                      <button
                        phx-click="delete_template"
                        phx-value-id={template.id}
                        data-confirm="Are you sure?"
                        class="text-red-600 hover:text-red-800 px-2 py-1"
                      >
                        Delete
                      </button>
                    </div>
                  </div>

                  <%= if @selected_template && @selected_template.id == template.id do %>
                    <div class="mt-4 pt-4 border-t">
                      <div class="flex justify-between items-center mb-2">
                        <h4 class="font-semibold text-sm">Sinks</h4>
                        <button
                          phx-click="new_sink"
                          phx-value-template_id={template.id}
                          class="text-blue-600 hover:text-blue-800 text-sm"
                        >
                          + Add Sink
                        </button>
                      </div>

                      <%= if Enum.empty?(template.sinks) do %>
                        <p class="text-sm text-gray-500">No sinks configured</p>
                      <% else %>
                        <div class="space-y-2">
                          <%= for sink <- template.sinks do %>
                            <div class="bg-gray-50 rounded p-2 text-sm">
                              <div class="flex justify-between items-start">
                                <div>
                                  <div class="font-medium">{sink.name}</div>
                                  <div class="text-gray-600">{sink.file_path}</div>
                                  <%= if sink.last_write_status do %>
                                    <div class="mt-1">
                                      <span class={[
                                        "text-xs px-2 py-0.5 rounded",
                                        sink.last_write_status == "success" &&
                                          "bg-green-100 text-green-800",
                                        sink.last_write_status == "failure" &&
                                          "bg-red-100 text-red-800"
                                      ]}>
                                        {sink.last_write_status}
                                      </span>
                                    </div>
                                  <% end %>
                                </div>
                                <div class="flex gap-1">
                                  <button
                                    phx-click="edit_sink"
                                    phx-value-id={sink.id}
                                    class="text-blue-600 hover:text-blue-800"
                                  >
                                    Edit
                                  </button>
                                  <button
                                    phx-click="delete_sink"
                                    phx-value-id={sink.id}
                                    data-confirm="Are you sure?"
                                    class="text-red-600 hover:text-red-800"
                                  >
                                    Delete
                                  </button>
                                </div>
                              </div>
                            </div>
                          <% end %>
                        </div>
                      <% end %>
                    </div>
                  <% else %>
                    <button
                      phx-click={JS.patch(~p"/admin/templates/#{template.id}")}
                      class="mt-2 text-sm text-blue-600 hover:text-blue-800"
                    >
                      View Details →
                    </button>
                  <% end %>
                </div>
              <% end %>
            </div>
          <% end %>
        </div>
        
    <!-- Template Details / Preview -->
        <div class="bg-white shadow-md rounded-lg p-6">
          <h2 class="text-xl font-semibold mb-4">Template Details</h2>

          <%= if @selected_template do %>
            <div class="space-y-4">
              <div>
                <h3 class="font-semibold text-sm text-gray-600">Template Content</h3>
                <pre class="mt-2 bg-gray-50 rounded p-3 text-sm overflow-x-auto"><%= @selected_template.template_content %></pre>
              </div>

              <div>
                <h3 class="font-semibold text-sm text-gray-600">Variable Bindings</h3>
                <pre class="mt-2 bg-gray-50 rounded p-3 text-sm overflow-x-auto"><%= Jason.encode!(@selected_template.variable_bindings, pretty: true) %></pre>
              </div>

              <div>
                <h3 class="font-semibold text-sm text-gray-600">Statistics</h3>
                <div class="mt-2 grid grid-cols-2 gap-2">
                  <div class="bg-blue-50 rounded p-2">
                    <div class="text-xs text-blue-600">Sinks</div>
                    <div class="text-lg font-semibold">{length(@selected_template.sinks)}</div>
                  </div>
                  <div class="bg-green-50 rounded p-2">
                    <div class="text-xs text-green-600">Version</div>
                    <div class="text-lg font-semibold">{@selected_template.version}</div>
                  </div>
                </div>
              </div>
            </div>
          <% else %>
            <p class="text-gray-500">Select a template to view details</p>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  ## Private Functions

  defp create_template(socket, params) do
    # Parse JSON fields
    params = parse_template_params(params)

    case Templates.create_template(params) do
      {:ok, _template} ->
        templates = Templates.list_templates(preload_sinks: true)

        socket =
          socket
          |> assign(:templates, templates)
          |> assign(:show_template_form, false)
          |> put_flash(:info, "Template created successfully")

        {:noreply, socket}

      {:error, changeset} ->
        Logger.error("Failed to create template: #{inspect(changeset)}")

        socket =
          socket
          |> put_flash(:error, "Failed to create template: #{format_errors(changeset)}")

        {:noreply, socket}
    end
  end

  defp update_template(socket, params) do
    template = socket.assigns.selected_template
    params = parse_template_params(params)

    case Templates.update_template(template, params) do
      {:ok, _template} ->
        templates = Templates.list_templates(preload_sinks: true)

        socket =
          socket
          |> assign(:templates, templates)
          |> assign(:show_template_form, false)
          |> assign(:selected_template, nil)
          |> put_flash(:info, "Template updated successfully")

        {:noreply, socket}

      {:error, changeset} ->
        Logger.error("Failed to update template: #{inspect(changeset)}")

        socket =
          socket
          |> put_flash(:error, "Failed to update template: #{format_errors(changeset)}")

        {:noreply, socket}
    end
  end

  defp create_sink(socket, params) do
    params = parse_sink_params(params)

    case Templates.create_sink(params) do
      {:ok, sink} ->
        template = Templates.get_template(sink.template_id, preload_sinks: true)

        socket =
          socket
          |> assign(:selected_template, template)
          |> assign(:show_sink_form, false)
          |> put_flash(:info, "Sink created successfully")

        {:noreply, socket}

      {:error, changeset} ->
        Logger.error("Failed to create sink: #{inspect(changeset)}")

        socket =
          socket
          |> put_flash(:error, "Failed to create sink: #{format_errors(changeset)}")

        {:noreply, socket}
    end
  end

  defp update_sink(socket, params) do
    sink = socket.assigns.selected_sink
    params = parse_sink_params(params)

    case Templates.update_sink(sink, params) do
      {:ok, updated_sink} ->
        template = Templates.get_template(updated_sink.template_id, preload_sinks: true)

        socket =
          socket
          |> assign(:selected_template, template)
          |> assign(:show_sink_form, false)
          |> put_flash(:info, "Sink updated successfully")

        {:noreply, socket}

      {:error, changeset} ->
        Logger.error("Failed to update sink: #{inspect(changeset)}")

        socket =
          socket
          |> put_flash(:error, "Failed to update sink: #{format_errors(changeset)}")

        {:noreply, socket}
    end
  end

  defp parse_template_params(params) do
    params
    |> Map.update("variable_bindings", %{}, &parse_json/1)
  end

  defp parse_sink_params(params) do
    params
    |> Map.update("permissions", %{}, &parse_json/1)
    |> Map.update("reload_trigger", %{}, &parse_json/1)
    |> Map.update("backup_enabled", false, &(&1 == "true" || &1 == true))
  end

  defp parse_json(value) when is_binary(value) do
    case Jason.decode(value) do
      {:ok, decoded} -> decoded
      {:error, _} -> %{}
    end
  end

  defp parse_json(value), do: value

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Enum.map(fn {field, errors} -> "#{field}: #{Enum.join(errors, ", ")}" end)
    |> Enum.join("; ")
  end
end
