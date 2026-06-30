defmodule SecretHub.Web.AppRoleManagementLiveTest do
  use SecretHub.Web.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Policy, Role}

  setup %{conn: conn} do
    ensure_current_audit_partition!()

    conn = init_test_session(conn, %{admin_id: "test-admin"})

    {:ok, conn: conn}
  end

  test "view details opens the AppRole details modal", %{conn: conn} do
    role_id = Ecto.UUID.generate()
    role_name = "Detail Role #{System.unique_integer([:positive])}"

    {:ok, _role} =
      %Role{}
      |> Role.changeset(%{
        role_id: role_id,
        role_name: role_name,
        auth_type: "approle",
        policies: ["database-access"],
        metadata: %{
          "policies" => ["database-access"],
          "secret_id_ttl" => 600,
          "secret_id_num_uses" => 1,
          "secret_id_uses" => 0,
          "bound_cidr_list" => ["10.0.0.0/8"]
        }
      })
      |> Repo.insert()

    {:ok, view, _html} = live(conn, "/admin/approles")

    html =
      view
      |> element("button[phx-click='view_role'][phx-value-role_id='#{role_id}']", "View Details")
      |> render_click()

    assert html =~ "AppRole Details"
    assert html =~ role_name
    assert html =~ role_id
    assert html =~ "database-access"
    assert html =~ "10.0.0.0/8"
    assert html =~ ~s(data-role-details-modal-panel)
    assert html =~ "items-center justify-center"
    assert html =~ "bg-surface-container-low/80"
    assert html =~ ~s(data-copyable-credential="selected-role-id")
    assert html =~ ~s(id="copy-selected-approle-role-id")
    assert html =~ ~s(phx-hook="CopyToClipboard")
    assert html =~ "select-all"

    html = render_click(view, "close_role_details")

    refute html =~ "AppRole Details"
  end

  test "create AppRole opens a modal form" do
    html =
      render_approle_management(%{
        creating_role: true,
        available_policies: [
          %{name: "database-access", description: "Database access"}
        ],
        new_role_name: "production-app",
        new_role_policies: ["database-access"]
      })

    assert html =~ ~s(data-create-role-modal-panel)
    assert html =~ ~s(role="dialog")
    assert html =~ ~s(aria-labelledby="create-approle-title")
    assert html =~ ~s(phx-submit="create_role")
    assert html =~ ~s(name="role_name")
    assert html =~ ~s(id="policies")
    policy_select_tag = policy_select_tag(html)
    refute policy_select_tag =~ ~r/class="[^"]*\bselect\b/
    assert policy_select_tag =~ ~r/class="[^"]*\boverflow-y-auto\b/
    assert policy_select_tag =~ ~r/class="[^"]*\bbg-surface-container\b/
    assert html =~ ~s(phx-click="close_create_form")
    assert html =~ "items-center justify-center"
    refute html =~ "items-end"
    refute html =~ "sm:block"
    assert html =~ "production-app"
    assert html =~ "database-access"

    refute render_approle_management() =~ ~s(data-create-role-modal-panel)
  end

  test "created AppRole credentials are selectable and copyable", %{conn: _conn} do
    role_name = "Copyable Role #{System.unique_integer([:positive])}"
    role_id = Ecto.UUID.generate()
    secret_id = Ecto.UUID.generate()

    html =
      render_approle_management(%{
        new_role_result: %{role_name: role_name, role_id: role_id, secret_id: secret_id}
      })

    assert html =~ "AppRole Created Successfully"
    assert html =~ role_name
    assert html =~ role_id
    assert html =~ secret_id

    assert html =~ ~s(data-credential-modal-panel)
    assert html =~ "items-center justify-center"
    assert html =~ "bg-surface-container-low/80"
    assert html =~ ~s(data-copyable-credential="role-name")
    assert html =~ ~s(data-copyable-credential="role-id")
    assert html =~ ~s(data-copyable-credential="secret-id")
    assert html =~ "select-text"
    assert html =~ "select-all"

    refute html =~ ~s(id="new-approle-credential-role-id")
    refute html =~ ~s(id="new-approle-credential-secret-id")

    assert html =~ ~s(id="copy-new-approle-credentials")
    assert html =~ ~s(id="copy-new-approle-role-id")
    assert html =~ ~s(id="copy-new-approle-secret-id")
    assert html =~ ~s(phx-hook="CopyToClipboard")
  end

  test "generated SecretID is shown once with copy controls", %{conn: _conn} do
    role_name = "Generated Secret Role #{System.unique_integer([:positive])}"
    role_id = Ecto.UUID.generate()
    secret_id = Ecto.UUID.generate()

    html =
      render_approle_management(%{
        new_secret_id: %{role_name: role_name, role_id: role_id, secret_id: secret_id}
      })

    assert html =~ "SecretID Generated"
    assert html =~ role_name
    assert html =~ role_id
    assert html =~ secret_id
    assert html =~ ~s(data-generated-secret-id-modal-panel)
    assert html =~ "items-center justify-center"
    assert html =~ "bg-surface-container-low/80"
    assert html =~ ~s(data-copyable-credential="generated-secret-id")
    assert html =~ ~s(id="copy-generated-approle-generated-secret-id")
    assert html =~ ~s(id="copy-generated-approle-secret-id-details")
    assert html =~ ~s(phx-click="close_generated_secret_id")
    assert html =~ ~s(phx-hook="CopyToClipboard")
    assert html =~ "select-all"
  end

  test "delete AppRole uses a modal confirmation instead of native confirm", %{conn: _conn} do
    role_id = Ecto.UUID.generate()
    role_name = "Delete Modal Role #{System.unique_integer([:positive])}"

    html =
      render_approle_management(%{
        roles: [
          %Role{
            role_id: role_id,
            role_name: role_name,
            metadata: %{"policies" => []}
          }
        ],
        delete_role_target: %{role_id: role_id, role_name: role_name}
      })

    assert html =~ ~s(data-delete-role-modal-panel)
    assert html =~ "Delete AppRole"
    assert html =~ role_name
    assert html =~ role_id
    assert html =~ "items-center justify-center"
    assert html =~ ~s(phx-click="show_delete_role_modal")
    assert html =~ ~s(phx-click="confirm_delete_role")
    assert html =~ ~s(phx-value-role_id="#{role_id}")
    refute html =~ "data-confirm"
    refute html =~ "phx-confirm"
  end

  test "updates AppRole policies from the edit policies modal", %{conn: conn} do
    role_id = Ecto.UUID.generate()
    role_name = "Editable Policy Role #{System.unique_integer([:positive])}"
    initial_policy = "database-access-#{System.unique_integer([:positive])}"
    updated_policy = "webapp-secrets-#{System.unique_integer([:positive])}"

    insert_policy!(initial_policy)
    insert_policy!(updated_policy)

    {:ok, _role} =
      %Role{}
      |> Role.changeset(%{
        role_id: role_id,
        role_name: role_name,
        auth_type: "approle",
        policies: [initial_policy],
        metadata: %{"policies" => [initial_policy]}
      })
      |> Repo.insert()

    {:ok, view, _html} = live(conn, "/admin/approles")

    html =
      view
      |> element("button[phx-click='edit_role_policies'][phx-value-role_id='#{role_id}']")
      |> render_click()

    assert html =~ "Edit AppRole Policies"
    assert html =~ role_name
    assert html =~ ~s(data-edit-policies-modal-panel)
    assert html =~ ~s(name="policies[]")
    assert html =~ ~s(value="#{initial_policy}" selected)
    assert html =~ ~s(value="#{updated_policy}")

    html =
      view
      |> form("form[phx-submit='update_role_policies']", %{
        "role_id" => role_id,
        "policies" => [updated_policy]
      })
      |> render_submit()

    assert html =~ "AppRole policies updated successfully"
    assert html =~ updated_policy
    refute html =~ ~s(data-edit-policies-modal-panel)

    persisted = Repo.get_by!(Role, role_id: role_id, auth_type: "approle")
    assert persisted.policies == [updated_policy]
    assert persisted.metadata["policies"] == [updated_policy]
  end

  test "all rendered AppRole buttons use a pointer cursor" do
    role_id = Ecto.UUID.generate()
    role_name = "Cursor Role #{System.unique_integer([:positive])}"
    secret_id = Ecto.UUID.generate()

    html =
      render_approle_management(%{
        roles: [
          %Role{
            role_id: role_id,
            role_name: role_name,
            metadata: %{"policies" => ["database-access"]}
          }
        ],
        available_policies: [
          %{name: "database-access", description: "Database access"}
        ],
        creating_role: true,
        new_role_name: role_name,
        new_role_policies: ["database-access"],
        new_role_result: %{role_name: role_name, role_id: role_id, secret_id: secret_id},
        new_secret_id: %{role_name: role_name, role_id: role_id, secret_id: secret_id},
        selected_role: %{
          role_name: role_name,
          role_id: role_id,
          policies: ["database-access"],
          bound_cidr_list: [],
          secret_id_ttl: 600,
          secret_id_uses: 0,
          secret_id_num_uses: 1,
          created_at: nil
        },
        editing_role_policies: %{
          role_name: role_name,
          role_id: role_id,
          policies: ["database-access"]
        },
        delete_role_target: %{role_id: role_id, role_name: role_name}
      })

    button_tags =
      Regex.scan(~r/<button\b[^>]*>/s, html)
      |> Enum.map(&hd/1)

    missing_pointer =
      Enum.reject(button_tags, fn tag ->
        tag =~ ~r/class="[^"]*\bcursor-pointer\b/
      end)

    assert button_tags != []
    assert missing_pointer == []
  end

  defp render_approle_management(assigns \\ %{}) do
    %{
      roles: [],
      available_policies: [],
      creating_role: false,
      new_role_name: "",
      new_role_policies: [],
      new_role_result: nil,
      new_secret_id: nil,
      selected_role: nil,
      delete_role_target: nil,
      editing_role_policies: nil,
      page_title: "AppRole Management"
    }
    |> Map.merge(assigns)
    |> SecretHub.Web.AppRoleManagementLive.render()
    |> rendered_to_string()
  end

  defp policy_select_tag(html) do
    [tag] = Regex.run(~r/<select\b[^>]*id="policies"[^>]*>/s, html)
    tag
  end

  defp insert_policy!(name) do
    %Policy{}
    |> Policy.changeset(%{
      name: name,
      description: "#{name} policy",
      policy_document: %{
        "version" => "1.0",
        "allowed_secrets" => ["*"],
        "allowed_operations" => ["read"]
      }
    })
    |> Repo.insert!()
  end

  defp ensure_current_audit_partition! do
    today = Date.utc_today()
    month = String.pad_leading(to_string(today.month), 2, "0")
    partition_name = "audit_logs_y#{today.year}m#{month}"
    from_date = %Date{today | day: 1}
    to_date = Date.add(from_date, Date.days_in_month(from_date))

    Repo.query!("""
    CREATE TABLE IF NOT EXISTS #{partition_name} PARTITION OF audit_logs
    FOR VALUES FROM ('#{Date.to_iso8601(from_date)}') TO ('#{Date.to_iso8601(to_date)}')
    """)
  end
end
