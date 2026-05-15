defmodule SecretHub.Core.PKI.Verifier do
  @moduledoc """
  Verification for Core-issued Agent certificates.
  """

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Agent, Certificate}

  def verify_agent_certificate(cert_der) when is_binary(cert_der) do
    cert_pem = der_to_pem(cert_der)
    fingerprint = Certificate.fingerprint_from_pem(cert_pem)

    with %Certificate{} = stored <- Repo.get_by(Certificate, fingerprint: fingerprint),
         :ok <- verify_not_revoked(stored),
         :ok <- verify_not_expired(stored),
         %Agent{} = agent <- Repo.get_by(Agent, agent_id: stored.entity_id),
         :ok <- verify_agent_active(agent),
         :ok <- verify_agent_uri(stored, agent.agent_id) do
      {:ok,
       %{
         agent_id: agent.agent_id,
         certificate_id: stored.id,
         certificate_serial: stored.serial_number,
         certificate_fingerprint: stored.fingerprint
       }}
    else
      nil -> {:error, :certificate_not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  def verify_agent_certificate(_), do: {:error, :invalid_certificate}

  defp verify_not_revoked(%Certificate{revoked: true}), do: {:error, :revoked}
  defp verify_not_revoked(_), do: :ok

  defp verify_not_expired(%Certificate{valid_until: valid_until}) do
    if DateTime.compare(DateTime.utc_now(), valid_until) == :gt do
      {:error, :expired}
    else
      :ok
    end
  end

  defp verify_agent_active(%Agent{status: status}) when status in [:active, :trusted_connected],
    do: :ok

  defp verify_agent_active(_), do: {:error, :agent_not_active}

  defp verify_agent_uri(certificate, agent_id) do
    san_uri = get_in(certificate.metadata || %{}, ["san_uri"]) || []

    if "urn:secrethub:agent:#{agent_id}" in san_uri do
      :ok
    else
      {:error, :missing_agent_san}
    end
  end

  defp der_to_pem(der) do
    :public_key.pem_encode([{:Certificate, der, :not_encrypted}])
  end
end
