defmodule SecretHub.Web.SecretFormComponentTest do
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias SecretHub.Shared.Schemas.Secret
  alias SecretHub.Web.SecretFormComponent

  @rotators [
    %{id: "rotator-manual", slug: "manual-web-ui", name: "Manual Web UI", rotator_type: :manual},
    %{id: "rotator-api", slug: "api", name: "API Rotator", rotator_type: :api}
  ]

  test "renders create form with DuskMoon inputs" do
    html = render_secret_form(%{})

    assert html =~ "Create New Secret"
    assert html =~ ~s(class="input)
    assert html =~ ~s(class="select)
    assert html =~ ~s(class="textarea)
    refute html =~ "form-input"
    refute html =~ "form-select"
  end

  test "renders the simplified secret fields" do
    html = render_secret_form(%{})

    assert html =~ "Secret Name"
    assert html =~ "Description"
    assert html =~ "Secret Path"
    assert html =~ "Value"
    assert html =~ "Rotator"
    assert html =~ "TTL (seconds)"
    assert html =~ "0 means always alive."
    assert html =~ ~s(name="secret[ttl_seconds]")
    assert html =~ ~s(value="0")

    refute html =~ "Secret Engine"
    refute html =~ "Secret Type"
    refute html =~ "Enable automatic rotation"
    refute html =~ "Rotation Period"
    refute html =~ "Engine-Specific Configuration"
  end

  test "renders policies as a styled DuskMoon checkbox group" do
    html =
      render_secret_form(%{},
        policies: [
          %{id: "policy-1", name: "apikey-readonly"},
          %{id: "policy-2", name: "database-access"}
        ]
      )

    assert html =~ "apikey-readonly"
    assert html =~ "database-access"
    assert html =~ ~s(name="secret[policies][]")
    assert html =~ ~s(class="checkbox)
    refute html =~ ~s(<select id="secret_policies")
  end

  test "checks assigned policies when editing a secret" do
    html =
      render_secret_form(
        %{"policies" => ["policy-1"]},
        mode: :edit,
        policies: [
          %{id: "policy-1", name: "apikey-readonly"},
          %{id: "policy-2", name: "database-access"}
        ]
      )

    assert html =~ "Edit Secret"
    assert html =~ ~r/<input(?=[^>]*value="policy-1")(?=[^>]*checked)[^>]*>/
    refute html =~ ~r/<input(?=[^>]*value="policy-2")(?=[^>]*checked)[^>]*>/
  end

  test "creation offers exactly Text and Structured data formats" do
    html = render_secret_form(%{})
    assert html =~ ~s(name="secret[value_format]")
    assert html =~ "Text"
    assert html =~ "Structured data"
    refute html =~ "Format not specified"
  end

  test "editing Text starts with keep and never exposes a saved value" do
    html = render_secret_form(%{}, mode: :edit, secret: %{id: "saved", value_format: "text"})
    assert html =~ "Keep current value"
    refute html =~ ~s(name="secret[value]")
    refute html =~ "secret-value"
  end

  test "structured editing renders only descriptors including unusual keys and JSON kinds" do
    html =
      render_secret_form(%{},
        mode: :edit,
        secret: %{id: "saved", value_format: "structured"},
        editor: %{
          version: 4,
          fields: [%{key: "value", kind: "object"}, %{key: "  ", kind: "null"}]
        }
      )

    assert html =~ "Stored object value is hidden"
    assert html =~ "Stored null value is hidden"
    assert html =~ ~s(value="  ")
    refute html =~ "secret-value"
  end

  test "Text keep omits value while explicit replacement preserves an empty or whitespace string" do
    socket = editor_socket("text")
    {:noreply, socket} = SecretFormComponent.handle_event("save", %{"secret" => %{}}, socket)
    assert_receive {:update_secret, "saved", kept}
    refute Map.has_key?(kept, "value")

    for value <- ["", " \n "] do
      SecretFormComponent.handle_event(
        "save",
        %{"secret" => %{"value_action" => "replace", "value" => value}},
        socket
      )

      assert_receive {:update_secret, "saved", replaced}
      assert replaced["value"] == value
    end
  end

  test "field editing submits rename, replacement and removal without saved values" do
    socket =
      editor_socket("structured", [
        %{key: "old", kind: "object"},
        %{key: "remove", kind: "string"}
      ])

    {:noreply, socket} = SecretFormComponent.handle_event("add_field", %{}, socket)

    SecretFormComponent.handle_event(
      "save",
      %{
        "secret" => %{
          "fields" => %{
            "0" => %{"name" => "renamed", "operation" => "keep"},
            "1" => %{"operation" => "remove"},
            "2" => %{"name" => "new", "operation" => "replace", "value" => ""}
          }
        }
      },
      socket
    )

    assert_receive {:update_secret, "saved", params}

    assert params["field_operations"] == [
             %{"original_key" => "old", "name" => "renamed", "operation" => "keep"},
             %{"original_key" => "remove", "operation" => "remove"},
             %{"name" => "new", "operation" => "replace", "value" => ""}
           ]

    refute Map.has_key?(params, "data")
  end

  test "legacy classification without field edits omits operations and preserves original keys" do
    socket = editor_socket(nil, [%{key: " ", kind: "array"}])

    SecretFormComponent.handle_event(
      "save",
      %{"secret" => %{"value_format" => "structured"}},
      socket
    )

    assert_receive {:update_secret, "saved", params}
    assert params["value_format"] == "structured"
    refute Map.has_key?(params, "field_operations")
    refute Map.has_key?(params, "data")
  end

  test "legacy value replacement requires selecting one of the explicit formats" do
    socket = editor_socket(nil, [%{key: "value", kind: "string"}])

    {:noreply, invalid} =
      SecretFormComponent.handle_event(
        "save",
        %{"secret" => %{"value_action" => "replace", "value" => ""}},
        socket
      )

    refute_receive {:update_secret, _, _}
    assert "Choose a value format." in invalid.assigns.editor_errors
  end

  test "duplicate or blank new field names block saving without echoing values" do
    socket = editor_socket("structured", [%{key: "old", kind: "object"}])
    {:noreply, socket} = SecretFormComponent.handle_event("add_field", %{}, socket)

    {:noreply, invalid} =
      SecretFormComponent.handle_event(
        "save",
        %{
          "secret" => %{
            "fields" => %{
              "1" => %{"name" => "old", "value" => "replacement-sensitive"}
            }
          }
        },
        socket
      )

    refute_receive {:update_secret, _, _}
    assert Enum.join(invalid.assigns.editor_errors) =~ "unique"
    refute Enum.join(invalid.assigns.editor_errors) =~ "replacement-sensitive"
  end

  defp editor_socket(format, fields \\ []) do
    assigns = %{
      changeset: Secret.changeset(%Secret{}, %{}),
      mode: :edit,
      secret: %{id: "saved", value_format: format},
      rotators: @rotators,
      policies: [],
      editor: %{version: 4, fields: fields}
    }

    {:ok, socket} = SecretFormComponent.update(assigns, %Phoenix.LiveView.Socket{})
    socket
  end

  defp render_secret_form(attrs, opts \\ []) do
    selected_policy_ids = Map.get(attrs, "policies", [])
    attrs = Map.delete(attrs, "policies")

    changeset =
      %Secret{policies: Enum.map(selected_policy_ids, &%{id: &1})}
      |> Secret.changeset(
        Map.merge(
          %{
            name: "Example Secret",
            secret_path: "prod.db.example",
            value: "secret-value",
            rotator_id: "rotator-manual",
            ttl_seconds: 0,
            secret_type: "static",
            engine_type: "static"
          },
          attrs
        )
      )

    render_component(SecretFormComponent,
      id: "secret-form",
      changeset: changeset,
      mode: Keyword.get(opts, :mode, :create),
      secret: Keyword.get(opts, :secret),
      editor: Keyword.get(opts, :editor, %{version: 1, fields: []}),
      rotators: @rotators,
      policies: Keyword.get(opts, :policies, []),
      return_to: "/admin/secrets"
    )
  end
end
