defmodule SecretHub.Web.SSHAccessLiveTest do
  use ExUnit.Case, async: false
  import Phoenix.LiveViewTest
  import Phoenix.ConnTest
  alias SecretHub.Core.{Repo, RuntimeDatabaseFixture, SSH}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.{Agent, Certificate}
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

    now = DateTime.utc_now() |> DateTime.truncate(:second)

    for name <- ["source", "destination"] do
      cert =
        Repo.insert!(%Certificate{
          serial_number: Ecto.UUID.generate(),
          fingerprint: Ecto.UUID.generate(),
          certificate_pem: "fixture",
          subject: name,
          issuer: "fixture",
          common_name: name,
          cert_type: :agent_client,
          entity_type: "agent",
          entity_id: name,
          valid_from: DateTime.add(now, -60),
          valid_until: DateTime.add(now, 3600)
        })

      Repo.insert!(%Agent{
        agent_id: name,
        name: name,
        status: :trusted_connected,
        certificate_id: cert.id,
        runtime_capabilities: ["ssh_lookup_v1", "ssh_signing_v1"]
      })
    end

    %{conn: build_conn()}
  end

  test "renders three tabs, default deny and no application login", %{conn: conn} do
    {:ok, view, html} = live_isolated(conn, SSHAccessLive)
    assert html =~ "SSH Access"
    assert html =~ "Default deny"
    assert has_element?(view, "#ssh-tab-devices")
    assert has_element?(view, "#ssh-tab-identities")
    assert has_element?(view, "#ssh-tab-access")
    refute html =~ "PRIVATE KEY"
    view |> element("#ssh-tab-identities") |> render_click()
    assert has_element?(view, "#identities-tab")
    refute has_element?(view, "#ssh-profile-form")

    assert %{plug: Phoenix.LiveView.Plug} =
             Phoenix.Router.route_info(
               SecretHub.Web.Router,
               "GET",
               "/admin/ssh-access",
               "localhost"
             )
  end

  test "reported host keys appear as pending and trust stages a readable preview", %{conn: conn} do
    {:ok, host} = Key.generate("ed25519")
    report_host_key("destination", host.public.public_line)
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    assert has_element?(view, "#pending-host-destination")
    assert has_element?(view, "#ssh-tab-count-devices", "1")
    assert has_element?(view, "#trust-destination")
    refute has_element?(view, "#keep-destination")

    html =
      view
      |> form("#endpoint-form-destination", %{
        "endpoint" => %{"aliases" => "dest.example", "port" => "22"}
      })
      |> render_submit(%{"trust" => "candidates"})

    assert html =~ "Trust 1 host key for destination"
    assert SSH.snapshot().endpoints |> Enum.all?(&(not &1.approved))
    view |> element("#ssh-confirm") |> render_click()
    assert [%{approved: true, host_keys: [_]}] = SSH.snapshot().endpoints
  end

  test "pending Agent identities can be approved and rotated from the identities tab", %{
    conn: conn
  } do
    {:ok, key} = Key.generate("ed25519")
    report_identity("source", key.public.public_line)

    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-identities") |> render_click()
    [identity] = SSH.snapshot().identities
    assert has_element?(view, "#identity-#{identity.id}", "pending")

    html = view |> element("#approve-#{identity.id}") |> render_click()
    assert html =~ "Approve identity gao@source"
    view |> element("#ssh-confirm") |> render_click()
    assert [%{status: "active"}] = SSH.snapshot().identities

    html = view |> element("#rotate-#{identity.id}") |> render_click()
    assert html =~ "Rotate identity gao@source now"
  end

  test "revoked identities can be deleted from the identities tab", %{conn: conn} do
    {:ok, key} = Key.generate("ed25519")
    report_identity("source", key.public.public_line)

    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-identities") |> render_click()
    [identity] = SSH.snapshot().identities

    view |> element("#revoke-#{identity.id}") |> render_click()
    view |> element("#ssh-confirm") |> render_click()
    assert [%{status: "retired"}] = SSH.snapshot().identities
    refute has_element?(view, "#revoke-#{identity.id}")

    html = view |> element("#delete-#{identity.id}") |> render_click()
    assert html =~ "Delete identity gao@source"
    view |> element("#ssh-confirm") |> render_click()
    assert [] = SSH.snapshot().identities
    refute has_element?(view, "#identity-#{identity.id}")
  end

  test "external public keys are added with validation and never render private material", %{
    conn: conn
  } do
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-identities") |> render_click()

    html =
      view
      |> form("#external-form", %{
        "external" => %{
          "name" => "gh-deploy",
          "public_key" => "not a key",
          "rotation_days" => "90"
        }
      })
      |> render_submit()

    assert html =~ "Paste one OpenSSH public key line."

    {:ok, key} = Key.generate("ed25519")

    html =
      view
      |> form("#external-form", %{
        "external" => %{
          "name" => "gh-deploy",
          "public_key" => key.public.public_line,
          "rotation_days" => "90"
        }
      })
      |> render_submit()

    assert html =~ "Add external identity gh-deploy"
    view |> element("#ssh-confirm") |> render_click()
    assert [%{name: "gh-deploy", origin: "external"}] = SSH.snapshot().identities
    refute render(view) =~ "PRIVATE KEY"
  end

  test "matrix cells allow a reported destination user and preview readable gains", %{
    conn: conn
  } do
    {:ok, host} = Key.generate("ed25519")
    {:ok, user} = Key.generate("ed25519")

    {:ok, %{identities: [identity]}} =
      SSH.apply_changes(
        [
          %{
            "op" => "endpoint_upsert",
            "agent_id" => "destination",
            "aliases" => ["dest.example"],
            "port" => 22,
            "host_keys" => [host.public.public_line],
            "approved" => true
          },
          %{
            "op" => "identity_external_add",
            "name" => "gh-deploy",
            "public_key" => user.public.public_line,
            "rotation_days" => 90
          }
        ],
        0
      )

    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-access") |> render_click()

    html =
      view
      |> form("#cell-identity-#{identity.id}-endpoint-destination", %{
        "cell" => %{"user" => "deploy"}
      })
      |> render_submit(%{"cell" => %{"effect" => "allow"}})

    assert html =~ "+ gh-deploy can log in as deploy on destination"
    view |> element("#ssh-confirm") |> render_click()
    assert [%{effect: "allow", destination_user: "deploy"}] = SSH.snapshot().rules

    html =
      view
      |> form("#cell-identity-#{identity.id}-endpoint-destination", %{"cell" => %{"user" => ""}})
      |> render_submit(%{"cell" => %{"effect" => "clear"}})

    assert html =~ "− gh-deploy can no longer log in as deploy on destination"
  end

  test "groups are created in the drawer with typed members", %{conn: conn} do
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-access") |> render_click()
    view |> element("#new-host-group") |> render_click()

    html =
      view
      |> form("#group-form", %{
        "group" => %{"name" => "Servers", "kind" => "host", "member_ids" => ["destination"]}
      })
      |> render_submit()

    assert html =~ "Save group Servers"
    view |> element("#ssh-confirm") |> render_click()
    assert [%{name: "Servers", kind: "host", agent_ids: ["destination"]}] = SSH.snapshot().groups
  end

  test "signing-only Agents show no pending host keys and no devices count", %{conn: conn} do
    Agent
    |> Repo.get_by!(agent_id: "source")
    |> Ecto.Changeset.change(runtime_capabilities: ["ssh_signing_v1"])
    |> Repo.update!()

    {:ok, host} = Key.generate("ed25519")
    report_host_key("source", host.public.public_line)
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    assert has_element?(view, "#device-source")
    refute has_element?(view, "#pending-host-source")
    refute has_element?(view, "#ssh-tab-count-devices")
  end

  test "matrix cells edit one destination user at a time across several rows", %{conn: conn} do
    [first, second] = matrix_fixture(["gh-deploy", "ci"])
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-access") |> render_click()

    assert has_element?(view, "#cell-identity-#{first.id}-endpoint-destination")
    assert has_element?(view, "#cell-identity-#{second.id}-endpoint-destination")
    html = render(view)
    assert length(String.split(html, ~s(id="users-endpoint-destination"))) == 2

    assert edit_cell(view, second, "a", "allow") =~ "+ ci can log in as a on destination"
    confirm(view)
    edit_cell(view, second, "b", "allow")
    confirm(view)
    assert rule_effects() == %{"a" => "allow", "b" => "allow"}
    b_rule = Enum.find(SSH.snapshot().rules, &(&1.destination_user == "b"))

    edit_cell(view, second, "a", "deny")
    confirm(view)
    assert rule_effects() == %{"a" => "deny", "b" => "allow"}
    assert Enum.any?(SSH.snapshot().rules, &(&1.id == b_rule.id))
    assert Enum.all?(SSH.snapshot().rules, &(&1.source_id == second.id))

    html = edit_cell(view, first, "  ", "allow")
    assert html =~ "Enter a destination user."
    refute has_element?(view, "#ssh-preview")

    edit_cell(view, second, "", "clear")
    confirm(view)
    assert [] = SSH.snapshot().rules
  end

  test "external public keys can be replaced", %{conn: conn} do
    [identity] = matrix_fixture(["gh-deploy"])
    {:ok, key} = Key.generate("ed25519")
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-identities") |> render_click()

    html =
      view
      |> form("#replace-form", %{
        "replace" => %{"id" => identity.id, "public_key" => key.public.public_line}
      })
      |> render_submit()

    assert html =~ "Replace the public key of gh-deploy"
    confirm(view)
    [updated] = SSH.snapshot().identities
    assert Enum.any?(updated.keys, &(&1.fingerprint == key.public.fingerprint))
  end

  test "blank rotation days disable rotation and other text is rejected", %{conn: conn} do
    [identity] = matrix_fixture(["gh-deploy"])
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-identities") |> render_click()

    html =
      view
      |> form("#rotation-#{identity.id}", %{"rotation" => %{"days" => ""}})
      |> render_submit()

    assert html =~ "Disable scheduled rotation for gh-deploy"

    html =
      view
      |> form("#rotation-#{identity.id}", %{"rotation" => %{"days" => "30d"}})
      |> render_submit()

    assert html =~ "Rotation days must be between 1 and 3650, or blank to disable."
    refute has_element?(view, "#ssh-preview")
  end

  test "a preview staged before another change is rejected as stale", %{conn: conn} do
    [identity] = matrix_fixture(["gh-deploy"])
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-identities") |> render_click()
    view |> element("#revoke-#{identity.id}") |> render_click()

    {:ok, _} =
      SSH.apply_changes(
        [%{"op" => "identity_rotation", "id" => identity.id, "rotation_days" => 30}],
        SSH.snapshot().revision
      )

    html = view |> element("#ssh-confirm") |> render_click()
    assert html =~ "SSH configuration changed. Review a new preview before saving."
    assert [%{status: "active", rotation_days: 30}] = SSH.snapshot().identities
  end

  test "groups can be edited and deleted from the drawer", %{conn: conn} do
    id = host_group_fixture("Servers")
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-access") |> render_click()
    view |> element("#edit-group-#{id}") |> render_click()
    assert has_element?(view, "#group-drawer", "Edit group")

    html =
      view
      |> form("#group-form", %{
        "group" => %{"name" => "Hosts", "member_ids" => ["destination", "source"]}
      })
      |> render_submit()

    assert html =~ "Save group Hosts"
    confirm(view)
    assert [%{id: ^id, name: "Hosts", agent_ids: members}] = SSH.snapshot().groups
    assert Enum.sort(members) == ["destination", "source"]
    refute has_element?(view, "#group-drawer")

    assert view |> element("#delete-group-#{id}") |> render_click() =~ "Delete group Hosts"
    confirm(view)
    assert [] = SSH.snapshot().groups
  end

  test "an open group drawer follows policy reloads", %{conn: conn} do
    id = host_group_fixture("Servers")
    {:ok, view, _} = live_isolated(conn, SSHAccessLive)
    view |> element("#ssh-tab-access") |> render_click()
    view |> element("#edit-group-#{id}") |> render_click()

    {:ok, _} =
      SSH.apply_changes(
        [%{"op" => "group_upsert", "id" => id, "name" => "Renamed", "kind" => "host"}],
        SSH.snapshot().revision
      )

    assert render(view) =~ ~s(value="Renamed")
    assert has_element?(view, "#group-drawer")

    {:ok, _} =
      SSH.apply_changes([%{"op" => "group_delete", "id" => id}], SSH.snapshot().revision)

    render(view)
    refute has_element?(view, "#group-drawer")
  end

  defp matrix_fixture(names) do
    {:ok, host} = Key.generate("ed25519")

    externals =
      for name <- names do
        {:ok, key} = Key.generate("ed25519")

        %{
          "op" => "identity_external_add",
          "name" => name,
          "public_key" => key.public.public_line,
          "rotation_days" => 90
        }
      end

    {:ok, %{identities: identities}} =
      SSH.apply_changes(
        [
          %{
            "op" => "endpoint_upsert",
            "agent_id" => "destination",
            "aliases" => ["dest.example"],
            "port" => 22,
            "host_keys" => [host.public.public_line],
            "approved" => true
          }
          | externals
        ],
        SSH.snapshot().revision
      )

    Enum.map(names, fn name -> Enum.find(identities, &(&1.name == name)) end)
  end

  defp host_group_fixture(name) do
    id = Ecto.UUID.generate()

    {:ok, _} =
      SSH.apply_changes(
        [
          %{"op" => "group_upsert", "id" => id, "name" => name, "kind" => "host"},
          %{"op" => "group_members", "group_id" => id, "member_ids" => ["destination"]}
        ],
        SSH.snapshot().revision
      )

    id
  end

  defp edit_cell(view, identity, user, effect) do
    view
    |> form("#cell-identity-#{identity.id}-endpoint-destination", %{"cell" => %{"user" => user}})
    |> render_submit(%{"cell" => %{"effect" => effect}})
  end

  defp confirm(view), do: view |> element("#ssh-confirm") |> render_click()

  defp rule_effects,
    do: Map.new(SSH.snapshot().rules, &{&1.destination_user, &1.effect})

  defp report_identity(agent_id, public_line) do
    agent = Repo.get_by!(Agent, agent_id: agent_id)

    {:ok, _} =
      SSH.runtime_operation(
        %{agent_id: agent_id, certificate_id: agent.certificate_id},
        "identity_report",
        %{"uid" => 1000, "username" => "gao", "generation" => 1, "public_key" => public_line}
      )
  end

  defp report_host_key(agent_id, key) do
    agent = Repo.get_by!(Agent, agent_id: agent_id)

    {:ok, _} =
      SSH.runtime_operation(
        %{agent_id: agent_id, certificate_id: agent.certificate_id},
        "inventory",
        %{"host_keys" => [key], "users" => []}
      )
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
