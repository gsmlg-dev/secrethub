defmodule SecretHub.Agent.TrustedConnection do
  @moduledoc """
  Starts the Agent runtime WebSocket over mTLS using Core-issued enrollment
  material and the existing SSH host key.
  """

  alias SecretHub.Agent.{Connection, HostKey}

  def start_link(opts) do
    with {:ok, private_key} <- private_key(opts) do
      connect_info = Keyword.fetch!(opts, :connect_info)
      certificate_pem = Keyword.fetch!(opts, :certificate_pem)

      Connection.start_link(
        agent_id: Keyword.get(opts, :agent_id, "certificate-derived"),
        core_url: fetch_connect_value(connect_info, "trusted_websocket_endpoint"),
        cert_pem: certificate_pem,
        private_key: private_key,
        ca_pem:
          Keyword.get(opts, :ca_pem) || fetch_connect_value(connect_info, "core_ca_cert_pem"),
        expected_server_name: optional_connect_value(connect_info, "expected_core_server_name"),
        on_runtime_accepted: Keyword.get(opts, :on_runtime_accepted)
      )
    end
  end

  defp private_key(opts) do
    case Keyword.get(opts, :private_key_pem) do
      pem when is_binary(pem) ->
        private_key_from_pem(pem)

      _missing ->
        case Keyword.fetch(opts, :private_key) do
          {:ok, private_key} ->
            {:ok, private_key}

          :error ->
            case Keyword.fetch(opts, :host_key) do
              {:ok, %HostKey{} = host_key} -> {:ok, host_key.private_key}
              {:ok, _invalid} -> {:error, :invalid_host_key}
              :error -> {:error, :missing_private_key}
            end
        end
    end
  end

  defp private_key_from_pem(pem) do
    case X509.PrivateKey.from_pem(pem) do
      {:ok, private_key} -> {:ok, private_key}
      {:error, reason} -> {:error, {:invalid_private_key, reason}}
    end
  rescue
    error -> {:error, {:invalid_private_key, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:invalid_private_key, {kind, reason}}}
  end

  defp fetch_connect_value(connect_info, key) do
    Map.get(connect_info, key) || Map.fetch!(connect_info, atom_key(key))
  end

  defp optional_connect_value(connect_info, key) do
    Map.get(connect_info, key) || Map.get(connect_info, atom_key(key))
  end

  defp atom_key("trusted_websocket_endpoint"), do: :trusted_websocket_endpoint
  defp atom_key("core_ca_cert_pem"), do: :core_ca_cert_pem
  defp atom_key("expected_core_server_name"), do: :expected_core_server_name
end
