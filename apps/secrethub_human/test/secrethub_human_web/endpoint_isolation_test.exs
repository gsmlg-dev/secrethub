defmodule SecretHub.HumanWeb.EndpointIsolationTest do
  use ExUnit.Case, async: false

  setup_all do
    {:ok, inets_started} = Application.ensure_all_started(:inets)
    {:ok, web_started} = Application.ensure_all_started(:secrethub_web)
    started_apps = inets_started ++ web_started

    on_exit(fn ->
      started_apps
      |> Enum.reverse()
      |> Enum.each(&Application.stop/1)
    end)

    :ok
  end

  test "Human runtime processes and the Core endpoint are currently supervised" do
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
    core_pid = start_listener!(SecretHub.Web.Endpoint, :secrethub_web)
    human_pid = start_listener!(SecretHub.HumanWeb.Endpoint, :secrethub_human)

    assert {:ok, {{127, 0, 0, 1}, core_port}} = ThousandIsland.listener_info(core_pid)
    assert {:ok, {{127, 0, 0, 1}, human_port}} = ThousandIsland.listener_info(human_pid)
    refute core_port == human_port

    assert {{_version, 200, _reason}, _headers, _body} = http_get(core_port, "/")

    assert {{_version, 200, _reason}, root_headers, root_body} = http_get(human_port, "/")
    assert String.starts_with?(header(root_headers, "content-type"), "application/json")
    assert %{"service" => "secrethub_human"} = Jason.decode!(root_body)

    assert {{_version, 200, _reason}, health_headers, health_body} =
             http_get(human_port, "/health")

    assert String.starts_with?(header(health_headers, "content-type"), "application/json")

    assert %{"service" => "secrethub_human", "status" => "ok"} =
             Jason.decode!(health_body)
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

  defp http_get(port, path) do
    url = String.to_charlist("http://127.0.0.1:#{port}#{path}")

    assert {:ok, response} =
             :httpc.request(:get, {url, []}, [], body_format: :binary)

    response
  end

  defp header(headers, name) do
    {_header_name, value} =
      Enum.find(headers, fn {header_name, _value} ->
        String.downcase(to_string(header_name)) == name
      end)

    to_string(value)
  end
end
