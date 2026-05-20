defmodule SecretHub.Web.AgentEndpointManagerTest do
  use SecretHub.Web.ConnCase, async: false

  alias SecretHub.Core.PKI.CA
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.Certificate
  alias SecretHub.Web.AgentEndpointManager

  setup do
    old_dev_mode = Application.get_env(:secrethub_web, :dev_mode)
    old_endpoint_url = Application.get_env(:secrethub_web, :agent_trusted_endpoint)
    old_endpoint_config = Application.get_env(:secrethub_web, SecretHub.Web.AgentEndpoint)

    if pid = Process.whereis(SecretHub.Web.AgentEndpoint) do
      Supervisor.terminate_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint)
      Process.exit(pid, :normal)
    end

    Supervisor.delete_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint)
    Repo.delete_all(Certificate)

    Application.put_env(:secrethub_web, :dev_mode, true)

    Application.put_env(
      :secrethub_web,
      :agent_trusted_endpoint,
      "wss://localhost:0/agent/socket/websocket"
    )

    Application.put_env(:secrethub_web, SecretHub.Web.AgentEndpoint, server: false)

    {:ok, _root} =
      CA.generate_root_ca("Runtime Endpoint Test Root", "SecretHub Test", key_size: 2048)

    on_exit(fn ->
      if Process.whereis(SecretHub.Web.AgentEndpoint) do
        Supervisor.terminate_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint)
      end

      Supervisor.delete_child(SecretHub.Web.Supervisor, SecretHub.Web.AgentEndpoint)
      restore_env(:dev_mode, old_dev_mode)
      restore_env(:agent_trusted_endpoint, old_endpoint_url)
      restore_endpoint_config(old_endpoint_config)
    end)

    :ok
  end

  test "starts the dev trusted endpoint when a CA exists" do
    assert :ok = AgentEndpointManager.ensure_started()
    assert Process.whereis(SecretHub.Web.AgentEndpoint)

    config = Application.fetch_env!(:secrethub_web, SecretHub.Web.AgentEndpoint)
    assert config[:server]
    assert config[:pubsub_server] == SecretHub.Web.PubSub
    transport_options = get_in(config, [:https, :thousand_island_options, :transport_options])
    assert transport_options[:verify] == :verify_peer
    assert transport_options[:fail_if_no_peer_cert]
  end

  defp restore_env(key, nil), do: Application.delete_env(:secrethub_web, key)
  defp restore_env(key, value), do: Application.put_env(:secrethub_web, key, value)

  defp restore_endpoint_config(nil),
    do: Application.delete_env(:secrethub_web, SecretHub.Web.AgentEndpoint)

  defp restore_endpoint_config(value),
    do: Application.put_env(:secrethub_web, SecretHub.Web.AgentEndpoint, value)
end
