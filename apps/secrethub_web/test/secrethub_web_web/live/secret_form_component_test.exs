defmodule SecretHub.Web.SecretFormComponentTest do
  use SecretHub.Web.ConnCase, async: true

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
      secret: nil,
      rotators: @rotators,
      policies: Keyword.get(opts, :policies, []),
      return_to: "/admin/secrets"
    )
  end
end
