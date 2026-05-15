defmodule SecretHub.Agent.Bootstrap do
  @moduledoc """
  Compatibility facade for the retired AppRole/bootstrap path.

  Agent enrollment now uses `SecretHub.Agent.Enrollment` with an existing SSH
  host key and a Core-issued mTLS certificate.
  """

  @disabled_error :legacy_approle_bootstrap_disabled

  def needs_bootstrap?, do: true

  def bootstrap_with_approle(_opts), do: {:error, @disabled_error}

  def renew_certificate(_agent_id, _core_url), do: {:error, :renewal_requires_trusted_identity}

  def get_certificate_info do
    cert_file = Path.join(["priv", "cert", "agent-cert.pem"])

    if File.exists?(cert_file) do
      {:ok, %{cert_path: cert_file}}
    else
      {:error, :certificate_not_found}
    end
  end
end
