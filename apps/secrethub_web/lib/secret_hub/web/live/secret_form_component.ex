defmodule SecretHub.Web.SecretFormComponent do
  @moduledoc """
  LiveComponent for secret creation and editing form.
  """

  use SecretHub.Web, :live_component
  require Logger

  alias Phoenix.HTML.Form

  @impl true
  def update(assigns, socket) do
    changeset = assigns.changeset
    form_context = form_context(assigns)

    form_params =
      if socket.assigns[:form_context] == form_context && socket.assigns[:form_params] do
        if submitted_changeset?(changeset) do
          form_params_from_changeset(changeset)
        else
          merge_form_params(form_params_from_changeset(changeset), socket.assigns.form_params)
        end
      else
        form_params_from_changeset(changeset)
      end

    form =
      Phoenix.Component.to_form(form_params,
        as: :secret,
        errors: visible_errors(changeset)
      )

    socket =
      socket
      |> assign(assigns)
      |> assign(:form_context, form_context)
      |> assign(:form_params, form_params)
      |> assign(:form, form)

    {:ok, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="fixed inset-0 z-50 flex items-center justify-center bg-surface-container-highest/75 px-4 py-6">
      <div class="max-h-full w-full max-w-3xl overflow-y-auto rounded-lg bg-surface-container shadow-xl">
        <div class="border-b border-outline-variant px-6 py-4">
          <h3 class="text-lg font-semibold text-on-surface">
            <%= if @mode == :create do %>
              Create New Secret
            <% else %>
              Edit Secret
            <% end %>
          </h3>
        </div>

        <.dm_form
          :let={f}
          id="secret-form"
          for={@form}
          as={:secret}
          phx-target={@myself}
          phx-change="update_form_values"
          phx-submit="save"
          phx-hook="PreserveFormValues"
          class="p-6"
          actions_align="right"
        >
          <div class="space-y-6">
            <.dm_form_section title="Basic Information">
              <.dm_form_grid cols={2}>
                <.dm_input
                  field={f[:name]}
                  label="Secret Name"
                  placeholder="e.g., Production Database"
                  errors={field_errors(@form, :name)}
                  field_class="md:col-span-2"
                />
                <.dm_textarea
                  field={f[:description]}
                  label="Description"
                  rows={2}
                  placeholder="Brief description of what this secret provides access to"
                  errors={field_errors(@form, :description)}
                  class="md:col-span-2"
                />
                <.dm_input
                  field={f[:secret_path]}
                  label="Secret Path"
                  placeholder="e.g., prod.db.postgres"
                  helper="Use reverse domain notation such as environment.service.credential."
                  errors={field_errors(@form, :secret_path)}
                  field_class="md:col-span-2"
                />
              </.dm_form_grid>
            </.dm_form_section>

            <.dm_form_section title="Secret Value">
              <.dm_textarea
                field={f[:value]}
                label="Value"
                rows={4}
                placeholder="Paste or type the secret value"
                helper={value_helper(@mode)}
                errors={field_errors(@form, :value)}
              />
            </.dm_form_section>

            <.dm_form_section title="Rotation and Lifetime">
              <.dm_form_grid cols={2}>
                <.dm_select
                  field={f[:rotator_id]}
                  label="Rotator"
                  options={rotator_options(@rotators)}
                  helper="The selected rotator is responsible for future value updates."
                  errors={field_errors(@form, :rotator_id)}
                />
                <.dm_input
                  field={f[:ttl_seconds]}
                  type="number"
                  label="TTL (seconds)"
                  min="0"
                  placeholder="0"
                  helper="0 means always alive."
                  errors={field_errors(@form, :ttl_seconds)}
                />
              </.dm_form_grid>
            </.dm_form_section>

            <.dm_form_section title="Access Policies">
              <%= if Enum.empty?(@policies) do %>
                <.dm_alert variant="info" outlined>
                  No policies are available yet.
                </.dm_alert>
              <% else %>
                <.dm_input
                  field={f[:policies]}
                  type="checkbox_group"
                  label="Policies"
                  options={policy_options(@policies)}
                  helper={policies_helper(@policies)}
                />
              <% end %>
            </.dm_form_section>
          </div>

          <:actions>
            <.dm_btn
              type="button"
              variant="ghost"
              phx-click="cancel"
              phx-target={@myself}
            >
              Cancel
            </.dm_btn>
            <.dm_btn
              type="submit"
              variant="primary"
              phx-disable-with="Saving..."
            >
              <%= if @mode == :create do %>
                Create Secret
              <% else %>
                Update Secret
              <% end %>
            </.dm_btn>
          </:actions>
        </.dm_form>
      </div>
    </div>
    """
  end

  @impl true
  def handle_event("save", %{"secret" => secret_params}, socket) do
    secret_params = merge_form_params(socket.assigns.form_params, secret_params)

    case socket.assigns.mode do
      :create ->
        send(self(), {:save_secret, secret_params})
        {:noreply, socket}

      :edit ->
        send(self(), {:update_secret, socket.assigns.secret.id, secret_params})
        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("update_form_values", %{"secret" => secret_params}, socket) do
    form_params = merge_form_params(socket.assigns.form_params, secret_params)
    form = Phoenix.Component.to_form(form_params, as: :secret)

    socket =
      socket
      |> assign(:form_params, form_params)
      |> assign(:form, form)

    {:noreply, socket}
  end

  @impl true
  def handle_event("cancel", _params, socket) do
    send(self(), {:cancel_form})
    {:noreply, socket}
  end

  defp field_errors(form, field) do
    form.errors
    |> Keyword.get_values(field)
    |> Enum.map(&format_error/1)
  end

  defp format_error({msg, opts}) do
    Enum.reduce(opts, msg, fn {key, value}, acc ->
      String.replace(acc, "%{#{key}}", to_string(value))
    end)
  end

  defp format_error(msg), do: to_string(msg)

  defp submitted_changeset?(%{action: action}), do: action in [:insert, :update]

  defp visible_errors(%{action: nil}), do: []
  defp visible_errors(changeset), do: changeset.errors

  defp form_context(assigns) do
    {assigns.mode, selected_secret_id(assigns[:secret])}
  end

  defp selected_secret_id(%{id: id}), do: id
  defp selected_secret_id(_secret), do: nil

  defp form_params_from_changeset(changeset) do
    data = changeset.data
    changes = changeset.changes

    %{
      "name" => Map.get(changes, :name, data.name || ""),
      "description" => Map.get(changes, :description, data.description || ""),
      "secret_path" => Map.get(changes, :secret_path, data.secret_path || ""),
      "value" => Map.get(changes, :value, ""),
      "rotator_id" => Map.get(changes, :rotator_id, data.rotator_id || ""),
      "ttl_seconds" => Map.get(changes, :ttl_seconds, data.ttl_seconds || 0),
      "policies" => selected_policy_ids(data)
    }
  end

  defp merge_form_params(current_params, incoming_params) do
    Map.merge(current_params || %{}, incoming_params || %{}, fn
      "engine_config", current_config, incoming_config
      when is_map(current_config) and is_map(incoming_config) ->
        Map.merge(current_config, incoming_config)

      _key, _current_value, incoming_value ->
        incoming_value
    end)
  end

  defp rotator_options(rotators) do
    Enum.map(rotators, &{&1.id, rotator_label(&1)})
  end

  defp rotator_label(%{name: name, rotator_type: type}) when not is_nil(type) do
    "#{name} (#{type |> to_string() |> String.replace("_", " ")})"
  end

  defp rotator_label(%{name: name}), do: name

  defp policy_options(policies), do: Enum.map(policies, &{&1.name, &1.id})

  defp selected_policy_ids(%Phoenix.HTML.Form{} = form) do
    case Form.input_value(form, :policies) do
      policy_ids when is_list(policy_ids) -> policy_ids
      _ -> []
    end
  end

  defp selected_policy_ids(%{policies: policies}) when is_list(policies) do
    Enum.map(policies, & &1.id)
  end

  defp selected_policy_ids(_), do: []

  defp policies_helper([]), do: "No policies are available yet."
  defp policies_helper(_policies), do: "Select policies that can access this secret."

  defp value_helper(:edit), do: "Leave blank to keep the current encrypted value."
  defp value_helper(_mode), do: "This value is encrypted before storage."
end
