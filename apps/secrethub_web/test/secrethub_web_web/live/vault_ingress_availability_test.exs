defmodule SecretHub.Web.VaultIngressAvailabilityTest do
  use ExUnit.Case, async: true
  import Phoenix.LiveViewTest

  test "unavailable persisted state never offers Vault initialization" do
    html = render_component(&SecretHub.Web.VaultInitLive.render/1, init_assigns(:unavailable))
    assert html =~ "unavailable"
    refute html =~ "phx-submit=\"initialize\""
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
  end

  test "initialization input uses the v4 public maximum of 251 shares" do
    html = render_component(&SecretHub.Web.VaultInitLive.render/1, init_assigns(:empty))
    assert html =~ "max=\"251\""
    refute html =~ "max=\"255\""
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
