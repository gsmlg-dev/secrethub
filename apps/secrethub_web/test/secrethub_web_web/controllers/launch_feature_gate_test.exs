defmodule SecretHub.Web.LaunchFeatureGateTest do
  use SecretHub.Web.ConnCase, async: false
  alias SecretHub.Core.Auth.AppRole

  setup do
    profile = Application.get_env(:secrethub_core, :launch_profile)
    features = Application.get_env(:secrethub_core, :enabled_features)
    Application.put_env(:secrethub_core, :launch_profile, :single_operator)
    Application.put_env(:secrethub_core, :enabled_features, [:static_secrets, :client_auth_pki])

    on_exit(fn ->
      Application.put_env(:secrethub_core, :launch_profile, profile)
      Application.put_env(:secrethub_core, :enabled_features, features)
    end)

    :ok
  end

  test "dynamic and lease APIs preserve authentication before feature availability" do
    for path <- ["/v1/secrets/dynamic/blocked", "/v1/sys/leases/renew"] do
      conn = dispatch(build_conn(), SecretHub.Web.MachineEndpoint, :post, path, %{})
      assert conn.status == 401
    end
  end

  test "an authenticated machine still cannot use disabled dynamic or lease operations" do
    {:ok, role} =
      AppRole.create_role("launch-gate-#{System.unique_integer([:positive])}",
        secret_id_num_uses: 0
      )

    {:ok, %{token: token}} = AppRole.login(role.role_id, role.secret_id)

    for {method, path} <- [
          {:post, "/v1/secrets/dynamic/blocked"},
          {:post, "/v1/sys/leases/renew"},
          {:post, "/v1/sys/leases/revoke"},
          {:get, "/v1/sys/leases/"}
        ] do
      conn =
        build_conn()
        |> put_req_header("x-vault-token", token)
        |> dispatch(SecretHub.Web.MachineEndpoint, method, path, %{})

      assert json_response(conn, 503) == %{"error" => "feature_unavailable"}
    end
  end

  test "unsupported management workflows are unavailable in the launch profile" do
    for path <- [
          "/admin/dynamic/postgresql",
          "/admin/leases",
          "/admin/rotators",
          "/admin/rotations",
          "/admin/engines"
        ] do
      assert build_conn() |> get(path) |> response(503) =~ "feature_unavailable"
    end
  end

  test "connected management mounts cannot bypass the disabled workflow gate" do
    socket = %Phoenix.LiveView.Socket{
      endpoint: SecretHub.Web.Endpoint,
      view: SecretHub.Web.DynamicPostgreSQLConfigLive,
      assigns: %{__changed__: %{}, flash: %{}}
    }

    assert {:halt, %{redirected: {:redirect, %{to: "/admin/dashboard"}}}} =
             SecretHub.Web.AdminLayoutHook.on_mount(:default, %{}, %{}, socket)
  end
end
