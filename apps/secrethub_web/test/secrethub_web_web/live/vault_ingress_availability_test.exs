defmodule SecretHub.Web.VaultIngressAvailabilityTest do
  use ExUnit.Case, async: true
  import Phoenix.LiveViewTest

  test "unavailable persisted state never offers Vault initialization" do
    html = render_component(&SecretHub.Web.VaultInitLive.render/1, init_assigns(:unavailable))
    assert html =~ "unavailable"
    refute html =~ "phx-submit=\"initialize\""
    refute html =~ ~s(href="/vault/recover")
  end

  test "legacy recovery state never offers a fresh Vault initialization" do
    html =
      render_component(
        &SecretHub.Web.VaultInitLive.render/1,
        Map.put(init_assigns(:sealed), :vault_status, %{
          state: :sealed,
          initialized: true,
          sealed: true,
          recovery_required: true
        })
      )

    assert html =~ "recovery"
    assert html =~ ~s(href="/vault/recover")
    assert html =~ "Recover vault"
    refute html =~ "phx-submit=\"initialize\""
  end

  test "unavailable unseal page never offers initialization or share submission" do
    assigns = %{
      vault_status: %{
        state: :unavailable,
        initialized: false,
        sealed: true,
        threshold: nil,
        progress: 0
      },
      share_input: "",
      error_message: nil,
      success_message: nil,
      shares_submitted: []
    }

    html = render_component(&SecretHub.Web.VaultUnsealLive.render/1, assigns)
    assert html =~ "unavailable"
    refute html =~ "href=\"/vault/init\""
    refute html =~ "phx-submit=\"submit_share\""
    refute html =~ ~s(href="/vault/recover")
  end

  test "legacy unseal page links to recovery instead of collecting shares" do
    html =
      render_component(&SecretHub.Web.VaultUnsealLive.render/1, %{
        vault_status: legacy_status()
      })

    assert html =~ ~s(href="/vault/recover")
    assert html =~ "Recover vault"
    refute html =~ "phx-submit=\"submit_share\""
  end

  test "legacy admin banner links to recovery before manual unseal" do
    html =
      render_component(&SecretHub.Web.Layouts.vault_sealed_banner/1, %{
        vault_status: legacy_status()
      })

    assert html =~ "Vault recovery required"
    assert html =~ "Recover vault"
    assert html =~ ~s(href="/vault/recover")
    refute html =~ ~s(href="/vault/unseal")
  end

  test "ordinary sealed admin banner keeps the unseal link" do
    html =
      render_component(&SecretHub.Web.Layouts.vault_sealed_banner/1, %{
        vault_status: %{legacy_status() | recovery_required: false}
      })

    assert html =~ "Vault sealed"
    assert html =~ "Unseal vault"
    assert html =~ ~s(href="/vault/unseal")
    refute html =~ ~s(href="/vault/recover")
  end

  test "unavailable legacy storage never offers recovery" do
    status = %{legacy_status() | state: :unavailable}

    for render <- [
          &SecretHub.Web.VaultInitLive.render/1,
          &SecretHub.Web.VaultUnsealLive.render/1,
          &SecretHub.Web.Layouts.vault_sealed_banner/1
        ] do
      html = render_component(render, %{vault_status: status})
      refute html =~ ~s(href="/vault/recover")
    end
  end

  test "initialization input uses the v4 public maximum of 251 shares" do
    html = render_component(&SecretHub.Web.VaultInitLive.render/1, init_assigns(:empty))
    assert html =~ "max=\"251\""
    refute html =~ "max=\"255\""
  end

  defp legacy_status do
    %{state: :sealed, initialized: true, sealed: true, recovery_required: true}
  end

  defp init_assigns(state) do
    %{
      vault_status: %{state: state, initialized: false, sealed: true},
      total_shares: 5,
      threshold: 3,
      initialized_shares: nil,
      error_message: nil
    }
  end
end
