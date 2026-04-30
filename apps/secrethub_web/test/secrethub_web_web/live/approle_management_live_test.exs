defmodule SecretHub.Web.AppRoleManagementLiveTest do
  use SecretHub.Web.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.Role

  setup %{conn: conn} do
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

    html = render_click(view, "close_role_details")

    refute html =~ "AppRole Details"
  end
end
