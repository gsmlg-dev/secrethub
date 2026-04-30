defmodule SecretHub.Web.AdminVaultBannerTest do
  use SecretHub.Web.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Schemas.VaultConfig

  setup %{conn: conn} do
    if pid = Process.whereis(SealState) do
      GenServer.stop(pid)
    end

    Repo.delete_all(VaultConfig)

    start_supervised!(SealState)
    {:ok, _shares} = SealState.initialize(3, 2)

    conn = init_test_session(conn, %{admin_id: "test-admin"})

    on_exit(fn ->
      if pid = Process.whereis(SealState) do
        GenServer.stop(pid)
      end
    end)

    {:ok, conn: conn}
  end

  test "admin layout shows a vault sealed banner with unseal link", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/admin/pki")

    assert html =~ ~s(id="vault-sealed-banner")
    assert html =~ "Vault sealed"
    assert html =~ "Secret and PKI operations are unavailable until the vault is unsealed."
    assert html =~ ~s(href="/vault/unseal")
    assert html =~ "Unseal vault"
  end

  test "sealed root CA generation uses the app banner instead of form validation", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/admin/pki")

    view
    |> element("button", "Generate Root CA")
    |> render_click()

    html =
      view
      |> form("form[phx-submit='generate_ca']", %{
        "ca" => %{
          "common_name" => "SecretHub Root CA",
          "organization" => "SecretHub",
          "country" => "US",
          "key_type" => "rsa",
          "key_bits" => "2048",
          "ttl_days" => "3650"
        }
      })
      |> render_submit()

    assert html =~ ~s(id="vault-sealed-banner")
    assert html =~ "Vault sealed"
    refute html =~ "Unseal the vault before generating CA certificates."
  end
end
