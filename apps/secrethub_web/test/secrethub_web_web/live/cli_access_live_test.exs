defmodule SecretHub.Web.CliAccessLiveTest do
  use SecretHub.Web.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias SecretHub.Core.Auth.{AppRole, CliAccess}
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.CliAccessRequest

  setup %{conn: conn} do
    ensure_current_audit_partition!()
    conn = init_test_session(conn, %{admin_id: "test-admin"})
    {:ok, conn: conn}
  end

  test "lists pending CLI clients and approves one with an AppRole", %{conn: conn} do
    {:ok, role} =
      AppRole.create_role("cli-access-live-role",
        policies: ["secret-read"],
        secret_id_num_uses: 0
      )

    {:ok, request} =
      CliAccess.create_request(
        %{"client_name" => "gao-laptop", "cli_version" => "0.1.0"},
        "127.0.0.1"
      )

    {:ok, view, html} = live(conn, "/admin/cli-access")

    assert html =~ "CLI Access"
    assert html =~ request.user_code
    assert html =~ "gao-laptop"
    assert html =~ "cli-access-live-role"
    assert html =~ ~s(name="role_id")

    html =
      view
      |> form("form[phx-submit='approve_cli_access'][phx-value-id='#{request.id}']", %{
        "role_id" => role.role_id
      })
      |> render_submit()

    assert html =~ "CLI access approved"
    assert html =~ request.user_code
    assert html =~ "Approved"
    assert html =~ "Revoke"

    persisted = Repo.get!(CliAccessRequest, request.id)
    assert persisted.status == :approved
    assert persisted.role_id == role.role_id
  end

  test "revokes approved CLI access from the table", %{conn: conn} do
    {:ok, role} =
      AppRole.create_role("cli-access-revoke-live-role",
        policies: ["secret-read"],
        secret_id_num_uses: 0
      )

    {:ok, request} =
      CliAccess.create_request(
        %{"client_name" => "revoked-laptop", "cli_version" => "0.1.0"},
        "127.0.0.1"
      )

    {:ok, _approved} = CliAccess.approve_request(request.id, role.role_id, "admin")

    {:ok, view, html} = live(conn, "/admin/cli-access")

    assert html =~ request.user_code
    assert html =~ "revoked-laptop"
    assert html =~ "Approved"

    html =
      view
      |> element("button[phx-click='revoke_cli_access'][phx-value-id='#{request.id}']", "Revoke")
      |> render_click()

    assert html =~ "CLI access revoked"
    assert html =~ request.user_code
    assert html =~ "Revoked"
    refute html =~ ~s(phx-click="revoke_cli_access" phx-value-id="#{request.id}")

    assert %{status: :revoked, revoked_by: "admin"} = Repo.get!(CliAccessRequest, request.id)
  end

  test "admin navigation exposes CLI Access under Access Control", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/admin/cli-access")

    assert html =~ ~s(href="/admin/cli-access")
    assert html =~ "CLI Access"
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
