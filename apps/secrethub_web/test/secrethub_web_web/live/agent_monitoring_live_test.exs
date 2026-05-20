defmodule SecretHub.Web.AgentMonitoringLiveTest do
  use SecretHub.Web.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias SecretHub.Core.Agents

  setup %{conn: conn} do
    conn = init_test_session(conn, %{admin_id: "test-admin"})

    {:ok, conn: conn}
  end

  test "remove agent action deletes the selected agent", %{conn: conn} do
    agent_id = "agent-remove-#{System.unique_integer([:positive])}"

    {:ok, agent} =
      Agents.register_agent(%{
        agent_id: agent_id,
        name: "Remove Agent Test",
        auth_method: "approle"
      })

    {:ok, view, html} = live(conn, "/admin/agents/#{agent.agent_id}")

    assert html =~ "Remove Agent Test"
    assert html =~ "Remove Agent"

    html =
      view
      |> element("#remove-agent-action", "Remove Agent")
      |> render_click()

    assert html =~ "Type this exact text to continue"
    assert html =~ "I know this is dangerous"

    html =
      view
      |> form("form[phx-submit='confirm_remove_agent']", %{
        "remove" => %{"confirmation" => "remove"}
      })
      |> render_submit()

    assert html =~ "Confirmation text does not match"
    assert Agents.get_agent(agent.agent_id)

    view
    |> form("form[phx-submit='confirm_remove_agent']", %{
      "remove" => %{"confirmation" => "I know this is dangerous"}
    })
    |> render_submit()

    assert_patch(view, "/admin/agents")
    assert nil == Agents.get_agent(agent.agent_id)
    refute render(view) =~ "Remove Agent Test"
  end
end
