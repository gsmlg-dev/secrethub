defmodule SecretHub.Agent.TrustedConnection do
  @moduledoc """
  Starts the Agent runtime WebSocket over mTLS using Core-issued enrollment
  material and the existing SSH host key.
  """

  alias SecretHub.Agent.{Connection, HostKey}

  def start_link(opts) do
    connect_info = Keyword.fetch!(opts, :connect_info)
    %HostKey{} = host_key = Keyword.fetch!(opts, :host_key)
    certificate_pem = Keyword.fetch!(opts, :certificate_pem)

    Connection.start_link(
      agent_id: Keyword.get(opts, :agent_id, "certificate-derived"),
      core_url: fetch_connect_value(connect_info, "trusted_websocket_endpoint"),
      cert_pem: certificate_pem,
      private_key: host_key.private_key,
      ca_pem: Keyword.get(opts, :ca_pem) || fetch_connect_value(connect_info, "core_ca_cert_pem"),
      expected_server_name: fetch_connect_value(connect_info, "expected_core_server_name")
    )
  end

  defp fetch_connect_value(connect_info, key) do
    Map.get(connect_info, key) || Map.fetch!(connect_info, atom_key(key))
  end

  defp atom_key("trusted_websocket_endpoint"), do: :trusted_websocket_endpoint
  defp atom_key("core_ca_cert_pem"), do: :core_ca_cert_pem
  defp atom_key("expected_core_server_name"), do: :expected_core_server_name
end
