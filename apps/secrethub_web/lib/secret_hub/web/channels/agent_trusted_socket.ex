defmodule SecretHub.Web.AgentTrustedSocket do
  @moduledoc """
  mTLS-only socket for trusted Agent runtime connections.
  """

  use Phoenix.Socket

  channel "agent:runtime", SecretHub.Web.AgentRuntimeChannel

  @impl true
  def connect(_params, socket, connect_info) do
    with {:ok, cert_der} <- peer_certificate(connect_info),
         {:ok, identity} <- SecretHub.Core.PKI.Verifier.verify_agent_certificate(cert_der) do
      socket =
        socket
        |> assign(:agent_id, identity.agent_id)
        |> assign(:certificate_serial, identity.certificate_serial)
        |> assign(:certificate_fingerprint, identity.certificate_fingerprint)
        |> assign(:certificate_id, identity.certificate_id)

      {:ok, socket}
    else
      {:error, _reason} -> :error
    end
  end

  @impl true
  def id(%{assigns: %{agent_id: agent_id}}), do: "trusted_agent:#{agent_id}"
  def id(_socket), do: nil

  defp peer_certificate(%{peer_data: %{ssl_cert: cert_der}}) when is_binary(cert_der) do
    {:ok, cert_der}
  end

  defp peer_certificate(%{peer_data: %{cert: cert_der}}) when is_binary(cert_der) do
    {:ok, cert_der}
  end

  defp peer_certificate(_), do: {:error, :no_peer_certificate}
end
