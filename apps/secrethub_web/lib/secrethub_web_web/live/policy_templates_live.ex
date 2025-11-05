defmodule SecretHub.WebWeb.PolicyTemplatesLive do
  @moduledoc """
  LiveView for browsing and using policy templates.

  Features:
  - Display all available templates grouped by category
  - Preview template details and policy documents
  - Quick "Use Template" action
  """

  use SecretHub.WebWeb, :live_view
  require Logger

  alias SecretHub.Core.PolicyTemplates

  @impl true
  def mount(_params, _session, socket) do
    templates = PolicyTemplates.list_templates()
    categories = PolicyTemplates.get_categories()

    socket =
      socket
      |> assign(:templates, templates)
      |> assign(:categories, categories)
      |> assign(:selected_category, "all")
      |> assign(:preview_template, nil)
      |> assign(:page_title, "Policy Templates")

    {:ok, socket}
  end

  @impl true
  def handle_event("filter_category", %{"category" => category}, socket) do
    socket = assign(socket, :selected_category, category)
    {:noreply, socket}
  end

  @impl true
  def handle_event("preview_template", %{"template" => template_name}, socket) do
    template = PolicyTemplates.get_template(template_name)
    socket = assign(socket, :preview_template, template)
    {:noreply, socket}
  end

  @impl true
  def handle_event("close_preview", _params, socket) do
    socket = assign(socket, :preview_template, nil)
    {:noreply, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div class="mb-8">
        <div class="flex items-center justify-between">
          <div>
            <h1 class="text-3xl font-bold text-gray-900">Policy Templates</h1>
            <p class="mt-2 text-sm text-gray-600">
              Start with a pre-configured template for common use cases
            </p>
          </div>
          <.link
            navigate="/admin/policies"
            class="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
          >
            Back to Policies
          </.link>
        </div>
      </div>
      <!-- Category Filter -->
      <div class="mb-6">
        <nav class="flex space-x-4" aria-label="Categories">
          <button
            type="button"
            phx-click="filter_category"
            phx-value-category="all"
            class={"px-3 py-2 font-medium text-sm rounded-md #{if @selected_category == "all", do: "bg-blue-100 text-blue-700", else: "text-gray-500 hover:text-gray-700"}"}
          >
            All Templates
          </button>
          <%= for category <- @categories do %>
            <button
              type="button"
              phx-click="filter_category"
              phx-value-category={category.id}
              class={"px-3 py-2 font-medium text-sm rounded-md #{if @selected_category == category.id, do: "bg-blue-100 text-blue-700", else: "text-gray-500 hover:text-gray-700"}"}
            >
              {category.name}
            </button>
          <% end %>
        </nav>
      </div>
      <!-- Templates Grid -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <%= for template <- filtered_templates(@templates, @selected_category) do %>
          <div class="bg-white shadow rounded-lg overflow-hidden hover:shadow-lg transition-shadow">
            <div class="p-6">
              <div class="flex items-center justify-between mb-3">
                <h3 class="text-lg font-semibold text-gray-900">{template.display_name}</h3>
                <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{category_color(template.category)}"}>
                  {category_name(template.category, @categories)}
                </span>
              </div>

              <p class="text-sm text-gray-600 mb-4">{template.description}</p>

              <div class="mb-4">
                <h4 class="text-xs font-medium text-gray-700 mb-2">Features:</h4>
                <ul class="text-xs text-gray-600 space-y-1">
                  <%= if template.policy_document["allowed_operations"] do %>
                    <li>
                      Operations:
                      <span class="font-medium">
                        {Enum.join(template.policy_document["allowed_operations"], ", ")}
                      </span>
                    </li>
                  <% end %>
                  <%= if template.policy_document["conditions"]["time_of_day"] do %>
                    <li>
                      Time restriction:
                      <span class="font-medium">
                        {template.policy_document["conditions"]["time_of_day"]}
                      </span>
                    </li>
                  <% end %>
                  <%= if template.policy_document["conditions"]["days_of_week"] do %>
                    <li>
                      Days:
                      <span class="font-medium">
                        {length(template.policy_document["conditions"]["days_of_week"])} days
                      </span>
                    </li>
                  <% end %>
                  <%= if template.policy_document["conditions"]["ip_ranges"] do %>
                    <li>
                      IP restrictions:
                      <span class="font-medium">
                        {length(template.policy_document["conditions"]["ip_ranges"])} ranges
                      </span>
                    </li>
                  <% end %>
                </ul>
              </div>

              <div class="flex gap-2">
                <.link
                  navigate={"/admin/policies/new?template=#{template.name}"}
                  class="flex-1 inline-flex justify-center items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
                >
                  Use Template
                </.link>
                <button
                  type="button"
                  phx-click="preview_template"
                  phx-value-template={template.name}
                  class="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
                >
                  <svg
                    class="h-5 w-5"
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                    />
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"
                    />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        <% end %>
      </div>
      <!-- Preview Modal -->
      <%= if @preview_template do %>
        <div class="fixed inset-0 bg-gray-500 bg-opacity-75 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-lg shadow-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto">
            <div class="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
              <div>
                <h3 class="text-lg font-medium text-gray-900">
                  {@preview_template.display_name}
                </h3>
                <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium mt-1 #{category_color(@preview_template.category)}"}>
                  {category_name(@preview_template.category, @categories)}
                </span>
              </div>
              <button
                type="button"
                phx-click="close_preview"
                class="text-gray-400 hover:text-gray-500"
              >
                <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>
            </div>

            <div class="px-6 py-4 space-y-4">
              <div>
                <h4 class="text-sm font-medium text-gray-900 mb-2">Description</h4>
                <p class="text-sm text-gray-600">{@preview_template.description}</p>
              </div>

              <div>
                <h4 class="text-sm font-medium text-gray-900 mb-2">Example Usage</h4>
                <p class="text-sm text-gray-600 whitespace-pre-line">
                  {@preview_template.example_usage}
                </p>
              </div>

              <div>
                <h4 class="text-sm font-medium text-gray-900 mb-2">Customizable Fields</h4>
                <div class="flex flex-wrap gap-2">
                  <%= for field <- @preview_template.customizable_fields do %>
                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                      {field}
                    </span>
                  <% end %>
                </div>
              </div>

              <div>
                <h4 class="text-sm font-medium text-gray-900 mb-2">Policy Document</h4>
                <div class="bg-gray-50 rounded-md p-3 overflow-x-auto">
                  <pre class="text-xs text-gray-800">{Jason.encode!(@preview_template.policy_document, pretty: true)}</pre>
                </div>
              </div>
            </div>

            <div class="px-6 py-4 border-t border-gray-200 flex justify-end space-x-3">
              <button
                type="button"
                phx-click="close_preview"
                class="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
              >
                Close
              </button>
              <.link
                navigate={"/admin/policies/new?template=#{@preview_template.name}"}
                class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700"
              >
                Use This Template
              </.link>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  # Private functions

  defp filtered_templates(templates, "all"), do: templates

  defp filtered_templates(templates, category) do
    Enum.filter(templates, fn t -> t.category == category end)
  end

  defp category_name(category_id, categories) do
    case Enum.find(categories, fn c -> c.id == category_id end) do
      nil -> String.capitalize(category_id)
      category -> category.name
    end
  end

  defp category_color(category) do
    case category do
      "time_based" -> "bg-blue-100 text-blue-800"
      "network_security" -> "bg-purple-100 text-purple-800"
      "permissions" -> "bg-green-100 text-green-800"
      "environment" -> "bg-yellow-100 text-yellow-800"
      "emergency" -> "bg-red-100 text-red-800"
      "production" -> "bg-indigo-100 text-indigo-800"
      _ -> "bg-gray-100 text-gray-800"
    end
  end
end
