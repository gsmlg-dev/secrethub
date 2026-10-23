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
        socket.assigns.form_params
      else
        initial_form_params(assigns)
      end

    form =
      Phoenix.Component.to_form(form_params,
        as: :secret,
        errors: visible_errors(changeset)
      )

    socket =
      socket
      |> assign(assigns)
      |> assign_new(:editor_errors, fn -> [] end)
      |> assign(:original_format, original_format(assigns))
      |> assign(
        :stored_value?,
        is_nil(assigns[:secret]) ||
          Map.get(assigns.secret, :secret_type) not in [:dynamic, "dynamic"]
      )
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
                  errors={local_field_errors(@form, :name)}
                  field_class="md:col-span-2"
                />
                <.dm_textarea
                  field={f[:description]}
                  label="Description"
                  rows={2}
                  placeholder="Brief description of what this secret provides access to"
                  errors={local_field_errors(@form, :description)}
                  class="md:col-span-2"
                />
                <.dm_input
                  field={f[:secret_path]}
                  label="Secret Path"
                  placeholder="e.g., prod.db.postgres"
                  helper="Use reverse domain notation such as environment.service.credential."
                  errors={local_field_errors(@form, :secret_path)}
                  field_class="md:col-span-2"
                />
              </.dm_form_grid>
            </.dm_form_section>

            <.dm_form_section :if={@stored_value?} title="Secret Value">
              <.dm_select
                field={f[:value_format]}
                label="Value format"
                options={[{"text", "Text"}, {"structured", "Structured data"}]}
                prompt={if @mode == :edit && is_nil(@original_format), do: "Format not specified"}
                helper="Value format is independent of credential generation and rotation."
                errors={local_field_errors(@form, :value_format)}
              />
              <p
                :if={@mode == :edit && is_nil(@original_format)}
                class="text-sm text-on-surface-variant"
              >
                Choosing Structured data preserves every field and changes legacy Agent delivery
                to return the complete object, including any value field.
              </p>
              <p
                :if={format_replacement?(@mode, @original_format, @form_params)}
                class="text-sm text-on-surface-variant"
              >
                Changing the format requires a complete replacement. Saved values remain hidden.
              </p>
              <.dm_alert :for={error <- @editor_errors} variant="error">{error}</.dm_alert>
              <%= if @form_params["value_format"] == "structured" do %>
                <div
                  :for={{index, row} <- field_rows(@form_params)}
                  :if={row["operation"] != "remove"}
                  id={"secret-field-#{index}"}
                  class="space-y-2 rounded border border-outline-variant p-3"
                >
                  <.dm_input
                    id={"secret-field-name-#{index}"}
                    name={"secret[fields][#{index}][name]"}
                    value={row["name"]}
                    label="Field name"
                  />
                  <%= if row["original_key"] do %>
                    <.dm_select
                      id={"secret-field-operation-#{index}"}
                      name={"secret[fields][#{index}][operation]"}
                      value={row["operation"]}
                      label="Field value"
                      options={[{"keep", "Keep value"}, {"replace", "Replace value"}]}
                    />
                    <p class="text-sm text-on-surface-variant">
                      Stored {row["kind"]} value is hidden
                    </p>
                  <% end %>
                  <.dm_input
                    :if={row["operation"] == "replace"}
                    type="password"
                    id={"secret-field-value-#{index}"}
                    name={"secret[fields][#{index}][value]"}
                    value={row["value"]}
                    label="New string value"
                    autocomplete="new-password"
                  />
                  <.dm_btn
                    type="button"
                    variant="ghost"
                    phx-click="remove_field"
                    phx-value-index={index}
                    phx-target={@myself}
                  >
                    Remove field
                  </.dm_btn>
                </div>
                <.dm_btn
                  id="add-secret-field"
                  type="button"
                  variant="outline"
                  phx-click="add_field"
                  phx-target={@myself}
                >
                  Add field
                </.dm_btn>
              <% else %>
                <.dm_select
                  :if={@mode == :edit && !format_replacement?(@mode, @original_format, @form_params)}
                  field={f[:value_action]}
                  label="Stored value"
                  options={[{"keep", "Keep current value"}, {"replace", "Replace value"}]}
                />
                <.dm_textarea
                  :if={
                    @mode == :create || @form_params["value_action"] == "replace" ||
                      format_replacement?(@mode, @original_format, @form_params)
                  }
                  field={f[:value]}
                  label="Value"
                  rows={4}
                  placeholder="Paste or type the secret value"
                  helper="Stored exactly as entered, including empty text and whitespace."
                  errors={local_field_errors(@form, :value)}
                />
              <% end %>
            </.dm_form_section>

            <.dm_form_section title="Rotation and Lifetime">
              <.dm_form_grid cols={2}>
                <.dm_select
                  field={f[:rotator_id]}
                  label="Rotator"
                  options={rotator_options(@rotators)}
                  helper="The selected rotator is responsible for future value updates."
                  errors={local_field_errors(@form, :rotator_id)}
                />
                <.dm_input
                  field={f[:ttl_seconds]}
                  type="number"
                  label="TTL (seconds)"
                  min="0"
                  placeholder="0"
                  helper="0 means always alive."
                  errors={local_field_errors(@form, :ttl_seconds)}
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
    form_params = merge_form_params(socket.assigns.form_params, secret_params)
    socket = put_form_params(socket, form_params)

    case submission_params(socket) do
      {:ok, params} ->
        case socket.assigns.mode do
          :create -> send(self(), {:save_secret, params})
          :edit -> send(self(), {:update_secret, socket.assigns.secret.id, params})
        end

        {:noreply, assign(socket, :editor_errors, [])}

      {:error, errors} ->
        {:noreply, assign(socket, :editor_errors, errors)}
    end
  end

  @impl true
  def handle_event("update_form_values", %{"secret" => secret_params}, socket) do
    params = merge_form_params(socket.assigns.form_params, secret_params)

    params =
      if params["value_format"] != socket.assigns.form_params["value_format"] do
        fields =
          if format_replacement?(socket.assigns.mode, socket.assigns.original_format, params),
            do: %{},
            else: descriptor_rows(socket.assigns[:editor])

        params
        |> Map.put("fields", fields)
        |> Map.put("value", "")
        |> Map.put("value_action", "keep")
      else
        params
      end

    {:noreply, put_form_params(socket, params)}
  end

  @impl true
  def handle_event("add_field", _params, socket) do
    fields = socket.assigns.form_params["fields"]

    index =
      fields
      |> Map.keys()
      |> Enum.map(&String.to_integer/1)
      |> Enum.max(fn -> -1 end)
      |> Kernel.+(1)
      |> to_string()

    fields = Map.put(fields, index, %{"name" => "", "operation" => "replace", "value" => ""})
    {:noreply, put_form_params(socket, Map.put(socket.assigns.form_params, "fields", fields))}
  end

  @impl true
  def handle_event("remove_field", %{"index" => index}, socket) do
    fields =
      Map.update!(
        socket.assigns.form_params["fields"],
        index,
        &Map.put(&1, "operation", "remove")
      )

    {:noreply, put_form_params(socket, Map.put(socket.assigns.form_params, "fields", fields))}
  end

  @impl true
  def handle_event("cancel", _params, socket) do
    send(self(), {:cancel_form})
    {:noreply, socket}
  end

  defp local_field_errors(form, field) do
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

  defp initial_form_params(assigns) do
    form_params_from_changeset(assigns.changeset)
    |> Map.put(
      "value_format",
      original_format(assigns) || if(assigns.mode == :create, do: "text", else: "")
    )
    |> Map.put("value_action", "keep")
    |> Map.put("fields", descriptor_rows(assigns[:editor]))
    |> then(fn params ->
      if assigns.mode == :edit, do: Map.put(params, "value", ""), else: params
    end)
  end

  defp original_format(assigns), do: assigns[:secret] && Map.get(assigns.secret, :value_format)

  defp descriptor_rows(nil), do: %{}

  defp descriptor_rows(editor) do
    editor.fields
    |> Enum.with_index()
    |> Map.new(fn {field, index} ->
      {to_string(index),
       %{
         "original_key" => field.key,
         "name" => field.key,
         "kind" => field.kind,
         "operation" => "keep",
         "value" => ""
       }}
    end)
  end

  defp field_rows(params),
    do: Enum.sort_by(params["fields"], fn {index, _} -> String.to_integer(index) end)

  defp merge_form_params(current, incoming) do
    # Original keys and kinds stay server-owned; the browser only changes authoring fields.
    fields =
      Enum.reduce(Map.get(incoming, "fields", %{}), current["fields"], fn {index, attrs}, rows ->
        if Map.has_key?(rows, index),
          do:
            Map.update!(
              rows,
              index,
              &Map.merge(&1, Map.take(attrs, ["name", "operation", "value"]))
            ),
          else: rows
      end)

    current
    |> Map.merge(
      Map.take(incoming, [
        "name",
        "description",
        "secret_path",
        "value",
        "value_format",
        "value_action",
        "rotator_id",
        "ttl_seconds",
        "policies"
      ])
    )
    |> Map.put("fields", fields)
  end

  defp put_form_params(socket, params) do
    socket
    |> assign(:form_params, params)
    |> assign(:form, Phoenix.Component.to_form(params, as: :secret))
  end

  defp format_replacement?(:edit, original, params) when original in ["text", "structured"],
    do: params["value_format"] != original

  defp format_replacement?(_, _, _), do: false

  defp submission_params(%{assigns: %{stored_value?: false}} = socket) do
    {:ok, socket.assigns.form_params |> submission_attrs() |> Map.delete("value_format")}
  end

  defp submission_params(socket) do
    params = socket.assigns.form_params
    rows = field_rows(params) |> Enum.map(&elem(&1, 1))
    format = params["value_format"]

    replacement? =
      socket.assigns.mode == :create ||
        format_replacement?(socket.assigns.mode, socket.assigns.original_format, params)

    errors = if format == "structured", do: structured_field_errors(rows, replacement?), else: []

    case value_format_errors(socket.assigns, params) ++ errors do
      [] -> {:ok, value_submission(submission_attrs(params), format, replacement?, rows, params)}
      errors -> {:error, errors}
    end
  end

  defp submission_attrs(params) do
    attrs = Map.drop(params, ["fields", "value_action", "value"])
    if params["value_format"] == "", do: Map.delete(attrs, "value_format"), else: attrs
  end

  defp value_format_errors(assigns, params) do
    needs_format? =
      assigns.mode == :create || !is_nil(assigns.original_format) ||
        params["value_action"] == "replace"

    if params["value_format"] not in ["text", "structured"] && needs_format?,
      do: ["Choose a value format."],
      else: []
  end

  defp value_submission(attrs, "structured", true, rows, _params) do
    data =
      rows |> Enum.reject(&(&1["operation"] == "remove")) |> Map.new(&{&1["name"], &1["value"]})

    Map.put(attrs, "secret_data", data)
  end

  defp value_submission(attrs, "structured", false, rows, _params) do
    changed? = Enum.any?(rows, &(&1["operation"] != "keep" || &1["name"] != &1["original_key"]))
    operations = Enum.map(rows, &field_operation/1) |> Enum.reject(&is_nil/1)
    if changed?, do: Map.put(attrs, "field_operations", operations), else: attrs
  end

  defp value_submission(attrs, _format, true, _rows, params),
    do: Map.put(attrs, "value", params["value"])

  defp value_submission(attrs, _format, false, _rows, %{"value_action" => "replace"} = params),
    do: Map.put(attrs, "value", params["value"])

  defp value_submission(attrs, _format, false, _rows, _params), do: attrs

  defp structured_field_errors(rows, replacement?) do
    active = Enum.reject(rows, &(&1["operation"] == "remove"))

    blank? =
      Enum.any?(active, fn row ->
        String.trim(row["name"] || "") == "" &&
          (replacement? || !Map.has_key?(row, "original_key") ||
             row["name"] != row["original_key"])
      end)

    saved_rows? = replacement? && Enum.any?(active, &Map.has_key?(&1, "original_key"))
    names = Enum.map(active, & &1["name"])

    []
    |> then(
      &if(saved_rows?,
        do: ["Changing the format requires new replacement fields." | &1],
        else: &1
      )
    )
    |> then(&if(blank?, do: ["New or renamed field names must not be blank." | &1], else: &1))
    |> then(
      &if(length(names) != length(Enum.uniq(names)),
        do: ["Field names must be unique." | &1],
        else: &1
      )
    )
  end

  defp field_operation(%{"operation" => "remove", "original_key" => original}),
    do: %{"original_key" => original, "operation" => "remove"}

  defp field_operation(%{"operation" => "remove"}), do: nil

  defp field_operation(row) do
    operation = Map.take(row, ["original_key", "name", "operation"])

    if row["operation"] == "replace",
      do: Map.put(operation, "value", row["value"]),
      else: operation
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
end
