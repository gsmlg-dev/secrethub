defmodule SecretHub.Web.VaultUnsealLiveTest do
  use SecretHub.Web.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Shamir
  alias SecretHub.Shared.Schemas.VaultConfig

  setup do
    if pid = Process.whereis(SealState) do
      GenServer.stop(pid)
    end

    Repo.delete_all(VaultConfig)

    start_supervised!(SealState)
    {:ok, shares} = SealState.initialize(5, 3)

    on_exit(fn ->
      if pid = Process.whereis(SealState) do
        GenServer.stop(pid)
      end
    end)

    {:ok, shares: shares}
  end

  test "submitting an unseal share keeps the full vault status shape", %{
    conn: conn,
    shares: shares
  } do
    {:ok, view, html} = live(conn, "/vault/unseal")

    assert html =~ "Initialized"
    assert html =~ "Sealed"
    assert html =~ "0 / 3"

    html =
      view
      |> form("form[phx-submit='submit_share']", %{
        "share" => Shamir.encode_share(Enum.at(shares, 0))
      })
      |> render_submit()

    assert html =~ "Share accepted! 1/3 shares submitted."
    assert html =~ "Initialized"
    assert html =~ "Sealed"
    assert html =~ "1 / 3"
  end

  test "submitting threshold shares renders the unsealed state", %{conn: conn, shares: shares} do
    {:ok, view, _html} = live(conn, "/vault/unseal")

    Enum.take(shares, 2)
    |> Enum.each(fn share ->
      view
      |> form("form[phx-submit='submit_share']", %{"share" => Shamir.encode_share(share)})
      |> render_submit()
    end)

    html =
      view
      |> form("form[phx-submit='submit_share']", %{
        "share" => Shamir.encode_share(Enum.at(shares, 2))
      })
      |> render_submit()

    assert html =~ "Vault unsealed successfully!"
    assert html =~ "Vault is operational"
    assert html =~ "The vault is unsealed and ready to serve secrets."
  end

  test "submitting threshold shares at once renders the unsealed state", %{
    conn: conn,
    shares: shares
  } do
    {:ok, view, _html} = live(conn, "/vault/unseal")

    share_input =
      shares
      |> Enum.take(3)
      |> Enum.map(&Shamir.encode_share/1)
      |> Enum.join("\n")

    html =
      view
      |> form("form[phx-submit='submit_share']", %{"share" => share_input})
      |> render_submit()

    assert html =~ "Vault unsealed successfully!"
    assert html =~ "Vault is operational"
    assert html =~ "The vault is unsealed and ready to serve secrets."
  end

  test "invalid share text shows an error instead of crashing", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/vault/unseal")

    html =
      view
      |> form("form[phx-submit='submit_share']", %{"share" => "not-a-share"})
      |> render_submit()

    assert html =~ "Failed to accept share: Invalid share format"
  end
end
