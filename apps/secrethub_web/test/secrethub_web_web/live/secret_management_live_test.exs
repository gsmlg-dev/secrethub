defmodule SecretHub.Web.SecretManagementLiveTest do
  use SecretHub.Web.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.VaultConfig

  setup %{conn: conn} do
    conn = init_test_session(conn, %{admin_id: "test-admin"})

    {:ok, conn: conn}
  end

  test "filter toolbar uses DuskMoon styled controls", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/admin/secrets")

    assert html =~ ~s(id="secret-rotator-filter")
    assert html =~ ~s(name="rotator")
    assert html =~ ~s(phx-change="filter_secrets")
    assert html =~ ~s(class="select)

    assert html =~ ~s(id="secret-search-input")
    assert html =~ ~s(name="query")
    assert html =~ ~s(phx-change="search_secrets")
    assert html =~ "w-full input"

    refute html =~ "form-select"
    refute html =~ "form-input"
  end

  test "new secret button opens the create form", %{conn: conn} do
    {:ok, view, html} = live(conn, "/admin/secrets")

    assert html =~ "New Secret"
    assert html =~ ~s(id="new-secret-button")
    assert html =~ ~s(<el-dm-button)

    html =
      view
      |> element("#new-secret-button", "New Secret")
      |> render_click()

    assert html =~ "Create New Secret"
    assert html =~ "Secret Name"
    assert html =~ "Value"
    assert html =~ "Rotator"
    assert html =~ "TTL (seconds)"
    assert html =~ ~s(phx-hook="PreserveFormValues")
    assert html =~ ~s(phx-change="update_form_values")
    assert html =~ ~s(name="secret[name]")
    assert html =~ ~s(name="secret[description]")
    assert html =~ ~s(name="secret[value]")
    assert html =~ ~s(name="secret[ttl_seconds]")
    refute html =~ "Secret Engine"
    refute html =~ "Secret Type"
    refute html =~ ~s(phx-change="validate")
  end

  test "sealed vault prevents opening the create form", %{conn: conn} do
    with pid when is_pid(pid) <- Process.whereis(SealState) do
      GenServer.stop(pid)
    end

    Repo.delete_all(VaultConfig)
    start_supervised!(SealState)
    {:ok, _shares} = SealState.initialize(3, 2)

    on_exit(fn ->
      with pid when is_pid(pid) <- Process.whereis(SealState) do
        GenServer.stop(pid)
      end
    end)

    {:ok, view, html} = live(conn, "/admin/secrets")

    assert html =~ ~s(id="vault-sealed-banner")
    assert html =~ "Vault sealed"

    html =
      view
      |> element("#new-secret-button", "New Secret")
      |> render_click()

    assert html =~ "Vault is sealed. Unseal the vault before creating secrets."
    assert html =~ ~s(href="/vault/unseal")
    refute html =~ "Create New Secret"
  end

  test "create form keeps typed values while moving between fields", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/admin/secrets")

    view
    |> element("#new-secret-button", "New Secret")
    |> render_click()

    html =
      view
      |> element("#secret-form")
      |> render_change(%{"secret" => %{"name" => "Mini DB"}})

    assert html =~ ~s(value="Mini DB")

    html =
      view
      |> element("#secret-form")
      |> render_change(%{"secret" => %{"description" => "mini"}})

    assert html =~ ~s(value="Mini DB")
    assert html =~ ">mini</textarea>"
  end

  test "create form keeps a stable simplified model while fields change", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/admin/secrets")

    html =
      view
      |> element("#new-secret-button", "New Secret")
      |> render_click()

    assert html =~ "TTL (seconds)"
    assert html =~ "0 means always alive."
    assert html =~ "Manual Web UI"
    refute html =~ "Rotation Period"
    refute html =~ "Secret Engine"
    refute html =~ "can't be blank"
    refute html =~ "can&#39;t be blank"

    html =
      view
      |> element("#secret-form")
      |> render_change(%{"secret" => %{"ttl_seconds" => "3600"}})

    assert html =~ ~s(value="3600")
    assert html =~ "TTL (seconds)"
    refute html =~ "Rotation Period"
    refute html =~ "can't be blank"
    refute html =~ "can&#39;t be blank"
  end
end
