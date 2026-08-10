defmodule SecretHub.HumanWeb.EndpointIsolationTest do
  use ExUnit.Case, async: false

  test "normal applications start both endpoints and Human runtime dependencies" do
    assert {:ok, _started} = Application.ensure_all_started(:secrethub_human)
    assert {:ok, _started} = Application.ensure_all_started(:secrethub_web)

    for name <- [
          SecretHub.Human.Repo,
          SecretHub.Human.PubSub,
          SecretHub.HumanWeb.Endpoint,
          SecretHub.Web.Endpoint
        ] do
      assert is_pid(Process.whereis(name)), "expected #{inspect(name)} to be running"
    end
  end

  test "Core and Human endpoints bind simultaneously and serve their root routes" do
    assert {:ok, _started} = Application.ensure_all_started(:inets)
    assert {:ok, _started} = Application.ensure_all_started(:secrethub_web)

    core_pid = start_listener!(SecretHub.Web.Endpoint, :secrethub_web)
    human_pid = start_listener!(SecretHub.HumanWeb.Endpoint, :secrethub_human)

    assert {:ok, {{127, 0, 0, 1}, core_port}} = ThousandIsland.listener_info(core_pid)
    assert {:ok, {{127, 0, 0, 1}, human_port}} = ThousandIsland.listener_info(human_pid)
    refute core_port == human_port

    assert http_status(core_port, "/") == 200
    assert http_status(human_port, "/") == 200
    assert http_status(human_port, "/health") == 200
  end

  defp start_listener!(endpoint, otp_app) do
    [spec] =
      Bandit.PhoenixAdapter.child_specs(endpoint,
        otp_app: otp_app,
        http: [ip: {127, 0, 0, 1}, port: 0, startup_log: false]
      )

    spec =
      Supervisor.child_spec(spec,
        id: {endpoint, :isolation_test, System.unique_integer([:positive])},
        restart: :temporary
      )

    start_supervised!(spec)
  end

  defp http_status(port, path) do
    url = String.to_charlist("http://127.0.0.1:#{port}#{path}")

    assert {:ok, {{_version, status, _reason}, _headers, _body}} =
             :httpc.request(:get, {url, []}, [], [])

    status
  end
end
