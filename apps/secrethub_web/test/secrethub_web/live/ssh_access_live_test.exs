defmodule SecretHub.Web.SSHAccessLiveTest do
  use ExUnit.Case, async: false
  import Phoenix.LiveViewTest
  import Phoenix.ConnTest
  alias SecretHub.Core.{Repo, RuntimeDatabaseFixture, SSH}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.Agent
  alias SecretHub.Shared.SSH.Key
  alias SecretHub.Web.SSHAccessLive
  @endpoint SecretHub.Web.Endpoint

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup tags do
    RuntimeDatabaseFixture.setup(tags, default_repo: true)

    unless Process.whereis(SecretHub.Web.PubSub) do
      start_supervised!({Phoenix.PubSub, name: SecretHub.Web.PubSub})
    end

    unless Process.whereis(SecretHub.Web.Endpoint) do
      start_supervised!(SecretHub.Web.Endpoint)
    end

    start_supervised!(SealState)
    await_vault()
    {:ok, shares} = SealState.initialize(3, 2)
    Enum.each(Enum.take(shares, 2), &SealState.unseal/1)

    for name <- ["source", "destination"] do
      Repo.insert!(%Agent{
        agent_id: name,
        name: name,
        status: :trusted_connected,
        runtime_capabilities: ["ssh_lookup_v1", "ssh_signing_v1"]
      })
    end

    %{conn: build_conn()}
  end

  test "renders public empty inventory and adds no application login", %{conn: conn} do
    {:ok, _, html} = live_isolated(conn, SSHAccessLive)
    assert html =~ "SSH Access"
    assert html =~ "Default deny"
    assert html =~ "No source identities"
    assert html =~ "Prerequisites unverified"
    refute html =~ "PRIVATE KEY"

    assert %{plug: Phoenix.LiveView.Plug} =
             Phoenix.Router.route_info(
               SecretHub.Web.Router,
               "GET",
               "/admin/ssh-access",
               "localhost"
             )
  end

  test "group changes preview without mutation then commit the exact revision", %{conn: conn} do
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)

    html =
      view
      |> form("#ssh-group-form", %{"group" => %{"id" => "build", "name" => "Build"}})
      |> render_submit()

    assert html =~ "Confirm changes"
    assert SSH.snapshot().groups == []
    view |> element("#ssh-confirm") |> render_click()
    assert [%{id: "build", name: "Build"}] = SSH.snapshot().groups

    view
    |> form("#ssh-members-form", %{
      "members" => %{"group_id" => "build", "agent_ids" => ["source"]}
    })
    |> render_submit()

    view |> element("#ssh-confirm") |> render_click()
    assert [%{agent_ids: ["source"]}] = SSH.snapshot().groups
  end

  test "private import is absent from render and pending status after preview and persistence", %{
    conn: conn
  } do
    {:ok, key} = Key.generate("ed25519")
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)

    html =
      view
      |> form("#ssh-identity-form", %{
        "identity" => %{
          "agent_id" => "source",
          "username" => "deploy",
          "uid" => "1000",
          "algorithm" => "ed25519",
          "private_key" => key.private_pem
        }
      })
      |> render_submit()

    refute html =~ key.private_pem
    refute inspect(:sys.get_state(view.pid)) =~ key.private_pem
    view |> element("#ssh-confirm") |> render_click()
    assert [%{public_key: public}] = SSH.snapshot().identities
    assert public == key.public.public_line
    refute render(view) =~ "BEGIN"
  end

  test "stale previews cannot commit and can be refreshed", %{conn: conn} do
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)

    view
    |> form("#ssh-group-form", %{"group" => %{"id" => "build", "name" => "Build"}})
    |> render_submit()

    assert {:ok, _} =
             SSH.apply_changes([%{"op" => "group_upsert", "id" => "other", "name" => "Other"}], 0)

    html = view |> element("#ssh-confirm") |> render_click()
    assert html =~ "changed"
    assert [%{id: "other"}] = SSH.snapshot().groups
    refute has_element?(view, "#ssh-confirm")
  end

  test "bulk group rules and matrix use the same allow/deny explanations", %{conn: conn} do
    {:ok, host} = Key.generate("ed25519")

    {:ok, _} =
      SSH.apply_changes(
        [
          %{
            "op" => "identity_upsert",
            "agent_id" => "source",
            "username" => "deploy",
            "uid" => 1000
          },
          %{
            "op" => "endpoint_upsert",
            "agent_id" => "destination",
            "aliases" => ["destination.test"],
            "port" => 22,
            "host_keys" => [host.public.public_line],
            "approved" => true
          }
        ],
        0
      )

    {:ok, view, _} = live_isolated(conn, SSHAccessLive)

    html =
      view
      |> form("#ssh-rule-form", %{
        "rule" => %{
          "sources" => ["agent/source"],
          "destinations" => ["agent/destination"],
          "source_user" => "deploy",
          "destination_user" => "app",
          "effect" => "allow"
        }
      })
      |> render_submit()

    assert html =~ "Gained: 1"
    view |> element("#ssh-confirm") |> render_click()
    assert render(view) =~ "allow:"
    [grant] = SSH.snapshot().rules

    view |> element("[phx-click=edit_rule][phx-value-id='#{grant.id}']") |> render_click()
    assert has_element?(view, "input[name='rule[id]'][value='#{grant.id}']")
    view |> element("#ssh-cancel-rule-edit") |> render_click()
    assert has_element?(view, "input[name='rule[id]'][value='']")

    cell =
      Jason.encode!(["source", "deploy", "destination", "app"])
      |> Base.url_encode64(padding: false)

    view
    |> form("#ssh-matrix-form", %{"cells" => [cell]})
    |> render_submit(%{"effect" => "deny"})

    view |> element("#ssh-confirm") |> render_click()
    assert render(view) =~ "deny:"
    assert SSH.snapshot().edges == []
    view |> form("#ssh-revoke-form", %{"revoke" => %{"ids" => [grant.id]}}) |> render_submit()
    view |> element("#ssh-confirm") |> render_click()
    assert [%{effect: "deny"}] = SSH.snapshot().rules
  end

  test "host-key approval and managed profile forms preserve explicit trust settings", %{
    conn: conn
  } do
    {:ok, host} = Key.generate("ed25519")
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)

    view
    |> form("#ssh-endpoint-form", %{
      "endpoint" => %{
        "agent_id" => "destination",
        "aliases" => "destination.test, 192.0.2.10",
        "port" => "2222",
        "host_keys" => host.public.public_line,
        "approved" => "true"
      }
    })
    |> render_submit()

    assert SSH.snapshot().endpoints == []
    view |> element("#ssh-confirm") |> render_click()
    assert [%{approved: true, port: 2222, host_keys: [key]}] = SSH.snapshot().endpoints
    assert key == host.public.public_line

    html =
      view
      |> form("#ssh-profile-form", %{
        "profile" => %{
          "base" => "/opt/secrethub",
          "hosts" => "destination.test 192.0.2.10",
          "users" => "deploy, app",
          "lookup_socket" => "/run/secrethub-ssh/lookup.sock",
          "signing_socket" => "/run/secrethub-ssh-signing/agent.sock"
        }
      })
      |> render_submit()

    assert html =~ "StrictHostKeyChecking yes"
    assert html =~ "VerifyHostKeyDNS no"
    assert html =~ "AuthorizedKeysFile none"
    assert html =~ "TrustedUserCAKeys none"
    assert html =~ "Match User deploy,app"
  end

  defp await_vault(attempts \\ 400)
  defp await_vault(0), do: flunk("Vault did not load")

  defp await_vault(attempts) do
    if SealState.status().state == :loading do
      Process.sleep(25)
      await_vault(attempts - 1)
    end
  end
end
