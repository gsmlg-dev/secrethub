defmodule SecretHub.Web.SecretManagementLiveTest do
  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  @endpoint SecretHub.Web.Endpoint

  import Phoenix.LiveViewTest

  alias SecretHub.Core.{Repo, RuntimeDatabaseFixture, Secrets}
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Core.VaultTestHelpers
  alias SecretHub.Shared.Schemas.VaultConfig

  setup_all do
    RuntimeDatabaseFixture.prepare_template()
  end

  setup context do
    :ok = RuntimeDatabaseFixture.setup(context, default_repo: true)
    conn = init_test_session(build_conn(), %{admin_id: "test-admin"})

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

  test "structured edits preserve hidden non-string values and reject stale field operations", %{
    conn: conn
  } do
    unseal_test_vault()

    {:ok, secret} =
      Secrets.create_secret(%{
        "name" => "Hidden fields",
        "secret_path" => "test.ui.hidden",
        "value_format" => "structured",
        "secret_data" => %{
          "value" => "saved-sensitive",
          "object" => %{"private-object-field-marker" => true}
        }
      })

    {:ok, view, html} = live(conn, "/admin/secrets")
    assert html =~ "Structured data"

    html =
      view
      |> element("button[phx-click=edit_secret][phx-value-id='#{secret.id}']")
      |> render_click()

    refute html =~ "saved-sensitive"
    refute html =~ "private-object-field-marker"
    assert html =~ "Stored object value is hidden"
    assert {:ok, _} = Secrets.update_secret(secret.id, %{"description" => "concurrent update"})

    view
    |> element("#secret-form")
    |> render_submit(%{
      "secret" => %{
        "fields" => %{
          "0" => %{"name" => "renamed"}
        }
      }
    })

    assert render(view) =~ "changed since this editor was opened"
    refute render(view) =~ "saved-sensitive"
  end

  test "structured creation accepts arbitrary protocol-like keys and empty values", %{conn: conn} do
    unseal_test_vault()
    {:ok, view, _} = live(conn, "/admin/secrets")
    view |> element("#new-secret-button") |> render_click()

    view
    |> element("#secret-form")
    |> render_change(%{"secret" => %{"value_format" => "structured"}})

    for _ <- 1..4, do: view |> element("#add-secret-field") |> render_click()

    fields =
      ["value", "data", "format", "value_format"]
      |> Enum.with_index()
      |> Map.new(fn {name, index} ->
        {to_string(index), %{"name" => name, "value" => ""}}
      end)

    view
    |> element("#secret-form")
    |> render_submit(%{
      "secret" => %{
        "name" => "Arbitrary fields",
        "secret_path" => "test.ui.fields",
        "value_format" => "structured",
        "fields" => fields
      }
    })

    assert render(view) =~ "Secret created successfully"
    secret = Secrets.list_secrets() |> Enum.find(&(&1.secret_path == "test.ui.fields"))
    assert secret.value_format == "structured"
    assert {:ok, data, _} = Secrets.read_decrypted(secret.secret_path)
    assert data == Map.new(["value", "data", "format", "value_format"], &{&1, ""})
  end

  defp unseal_test_vault do
    start_supervised!({SealState, repo: Repo})
    :ok = VaultTestHelpers.await_vault_state(:not_initialized)
    {:ok, shares} = SealState.initialize(3, 2)
    for share <- Enum.take(shares, 2), do: assert({:ok, _} = SealState.unseal(share))
  end

  test "sealed vault prevents opening the create form", %{conn: conn} do
    with pid when is_pid(pid) <- Process.whereis(SealState) do
      GenServer.stop(pid)
    end

    Repo.delete_all(VaultConfig)
    start_supervised!({SealState, repo: Repo})
    :ok = VaultTestHelpers.await_vault_state(:not_initialized)
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
