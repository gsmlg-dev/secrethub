defmodule SecretHub.Web.AgentPendingLiveTest do
  use SecretHub.Web.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias SecretHub.Core.Agents.Enrollment
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Agent, Certificate}

  @ssh_host_public_key "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzfBY98CsoKIQiaRg4dDON+o4mkz3vtNSslq+drKM97GAhSvE1+pjp4Iy1udn/tEsRiqzeOqgVG0vTTrKhH0Hn4eUB5NO1KeENUwSFafIgbeYzK5P1rWY65IyccP6nfGzslQALVTVPLMQ9P0vzbCjGqBbIvHxARvq78sp2Pxa92PHFuPkzgfhus7IXMsgJpd5bBhdjSlRxSFqUt21x4dtmwNpxdfL93Up6LWPmtItCz2whuZMabr2FbMcWCZS6b07sOBa1oqIjwUihHwGxP45r/BV6q6jtvMJAsE1QIAOxXDlhqosqhWJwGuhdwani/IlhNT2ruXObjeA8t14nirnz"
  @ssh_host_key_fingerprint "SHA256:msje3DyBcXxXmuF1TilCDOvsvGvnuZdHQ5YSS8BVoz4"

  setup %{conn: conn} do
    Repo.delete_all(Certificate)
    conn = init_test_session(conn, %{admin_id: "test-admin"})

    {:ok, conn: conn}
  end

  test "approve shows a create CA notice when no active CA exists", %{conn: conn} do
    {:ok, %{enrollment: enrollment}} =
      Enrollment.create_pending(
        %{
          hostname: "pending-no-ca",
          fqdn: "pending-no-ca.internal.example",
          machine_id: "machine-no-ca",
          os: "linux",
          arch: "x86_64",
          agent_version: "1.2.3",
          ssh_host_key_algorithm: "rsa",
          ssh_host_key_fingerprint: @ssh_host_key_fingerprint,
          ssh_host_public_key: @ssh_host_public_key,
          capabilities: %{}
        },
        "203.0.113.10"
      )

    {:ok, view, html} = live(conn, "/admin/pending-agents")

    assert html =~ "Agent approval requires an active Root CA"

    html =
      view
      |> element("button[phx-value-id='#{enrollment.id}']", "Approve")
      |> render_click()

    assert html =~ "Create an active Root CA before approving agents."
    assert html =~ "Create Root CA"
    assert html =~ ~s(href="/admin/pki")
    refute Repo.get_by(Agent, ssh_host_key_fingerprint: @ssh_host_key_fingerprint)
  end
end
