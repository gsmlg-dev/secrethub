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
    assert render(element(view, "#ssh-tab-devices")) =~ "1"

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
