defmodule SecretHub.Web.SecretRotatorLiveTest do
  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  @endpoint SecretHub.Web.Endpoint

  alias SecretHub.Core.{Repo, RuntimeDatabaseFixture, Secrets}
  alias SecretHub.Shared.Schemas.{Secret, SecretRotator}

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup context do
    :ok = RuntimeDatabaseFixture.setup(context, default_repo: true)

    secret =
      %Secret{}
      |> Secret.changeset(%{
        name: "Rotator modal secret",
        secret_path: "test.rotator.modal",
        encrypted_data: <<1>>
      })
      |> Repo.insert!()

    rotator =
      %SecretRotator{}
      |> SecretRotator.changeset(%{
        name: "Modal rotator",
        slug: "modal-rotator",
        secret_id: secret.id,
        rotator_type: :manual,
        trigger_mode: :manual,
        enabled: true,
        config: %{"preserved" => true}
      })
      |> Repo.insert!()

    {:ok, conn: init_test_session(build_conn(), %{}), rotator: rotator}
  end

  test "the list opens configuration in a modal while keeping rows visible", %{
    conn: conn,
    rotator: rotator
  } do
    {:ok, view, _html} = live(conn, "/admin/rotators")

    assert has_element?(view, "table", "Modal rotator")
    refute has_element?(view, "#rotator-form")

    configure(view, rotator)

    assert has_element?(view, "table", "Modal rotator")
    assert has_element?(view, "dialog#rotator-modal[phx-hook=FormModal]")
    assert has_element?(view, "#rotator-modal[data-close-event=close_rotator_modal]")
    assert has_element?(view, "#rotator-form")
  end

  test "cancel and native close discard edits without changing the stored rotator", %{
    conn: conn,
    rotator: rotator
  } do
    {:ok, view, _html} = live(conn, "/admin/rotators")
    configure(view, rotator)

    view
    |> form("#rotator-form")
    |> render_change(%{"rotator" => %{"schedule_cron" => "0 3 * * *"}})

    assert has_element?(view, "#rotator_schedule[value='0 3 * * *']")
    view |> element("#rotator-modal button", "Cancel") |> render_click()

    refute has_element?(view, "#rotator-form")
    assert {:ok, %{schedule_cron: nil}} = Secrets.get_secret_rotator(rotator.id)

    configure(view, rotator)
    assert has_element?(view, "#rotator_schedule[value='']")
    render_click(view, "close_rotator_modal")
    refute has_element?(view, "#rotator-form")
  end

  test "saving closes the modal and persists only editable configuration fields", %{
    conn: conn,
    rotator: rotator
  } do
    {:ok, view, _html} = live(conn, "/admin/rotators")
    configure(view, rotator)

    render_submit(view, "save_rotator", %{
      "rotator" => %{
        "trigger_mode" => "scheduled",
        "engine_configuration_id" => "",
        "schedule_cron" => "0 3 * * *",
        "enabled" => "true",
        "name" => "Unexpected name",
        "slug" => "unexpected-slug",
        "rotation_count" => "9000",
        "config" => %{"unexpected" => true}
      }
    })

    refute has_element?(view, "#rotator-form")
    assert render(view) =~ "Rotator updated"
    assert has_element?(view, "table", "Modal rotator")
    assert {:ok, updated} = Secrets.get_secret_rotator(rotator.id)
    assert updated.trigger_mode == :scheduled
    assert updated.schedule_cron == "0 3 * * *"
    assert updated.enabled
    assert updated.rotator_type == :manual
    assert updated.engine_configuration_id == nil
    assert updated.name == rotator.name
    assert updated.slug == rotator.slug
    assert updated.rotation_count == 0
    assert updated.config == %{"preserved" => true}
  end

  test "validation failure keeps the modal and submitted values", %{conn: conn, rotator: rotator} do
    {:ok, view, _html} = live(conn, "/admin/rotators")
    configure(view, rotator)

    render_submit(view, "save_rotator", %{
      "rotator" => %{
        "trigger_mode" => "invalid-mode",
        "engine_configuration_id" => "",
        "schedule_cron" => "0 4 * * *"
      }
    })

    assert has_element?(view, "#rotator-form")
    assert has_element?(view, "#rotator_schedule[value='0 4 * * *']")
    refute has_element?(view, "#rotator-form input[name='rotator[enabled]'][checked]")
    assert has_element?(view, "#rotator-modal [role=alert]", "Failed to update rotator")

    assert {:ok, %{trigger_mode: :manual, schedule_cron: nil, enabled: true}} =
             Secrets.get_secret_rotator(rotator.id)
  end

  test "the existing detail URL stays readable and opens its editor on demand", %{
    conn: conn,
    rotator: rotator
  } do
    {:ok, view, html} = live(conn, "/admin/rotators/#{rotator.id}")

    assert html =~ "Modal rotator"
    assert html =~ "Last Rotation"
    refute has_element?(view, "#rotator-form")

    configure(view, rotator)
    assert has_element?(view, "#rotator-form")

    render_click(view, "close_rotator_modal")
    refute has_element?(view, "#rotator-form")
    assert render(view) =~ "Last Rotation"
  end

  defp configure(view, rotator) do
    view
    |> element("button[phx-click='view_rotator'][phx-value-id='#{rotator.id}']", "Configure")
    |> render_click()
  end
end
