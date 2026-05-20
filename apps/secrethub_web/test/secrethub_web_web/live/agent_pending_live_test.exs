defmodule SecretHub.Web.AgentPendingLiveTest do
  use SecretHub.Web.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias SecretHub.Core.Agents.Enrollment
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Agent, Certificate}

  setup %{conn: conn} do
    Repo.delete_all(Certificate)
    conn = init_test_session(conn, %{admin_id: "test-admin"})

    {:ok, conn: conn}
  end

  test "approve shows a create CA notice when no active CA exists", %{conn: conn} do
    fingerprint = "SHA256:pending-no-ca-#{System.unique_integer([:positive])}"

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
          ssh_host_key_fingerprint: fingerprint,
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
    refute Repo.get_by(Agent, ssh_host_key_fingerprint: fingerprint)
  end
end
