defmodule SecretHub.Core.PKI.Issuer do
  @moduledoc """
  Agent certificate issuance from approved CSRs.
  """

  alias SecretHub.Core.PKI.RootCA
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.Encryption
  alias SecretHub.Shared.Schemas.Certificate
  alias X509.Certificate.Extension

  @default_agent_certificate_ttl_seconds 30 * 24 * 60 * 60
  @default_agent_certificate_max_ttl_seconds 90 * 24 * 60 * 60

  def active_signing_ca do
    with {:ok, ca, _ca_key} <- active_signing_ca_with_key() do
      {:ok, ca}
    end
  end

  def issue_server_certificate(common_name, dns_names) do
    with {:ok, ca, ca_key} <- active_signing_ca_with_key() do
      private_key = X509.PrivateKey.new_rsa(2048)

      cert =
        X509.Certificate.new(
          X509.PublicKey.derive(private_key),
          "/O=SecretHub/CN=#{common_name}",
          X509.Certificate.from_pem!(ca.certificate_pem),
          ca_key,
          extensions: [
            subject_alt_name: Extension.subject_alt_name(server_subject_alt_names(dns_names)),
            ext_key_usage: Extension.ext_key_usage([:serverAuth])
          ],
          validity: 365
        )

      {:ok,
       %{
         certificate_pem: X509.Certificate.to_pem(cert),
         private_key_pem: X509.PrivateKey.to_pem(private_key),
         ca_certificate_pem: ca.certificate_pem,
         ca_fingerprint: ca.fingerprint
       }}
    end
  end

  def issue_agent_certificate_from_csr(enrollment, csr) do
    with {:ok, ca, ca_key} <- active_signing_ca_with_key(),
         cert <- build_certificate(enrollment, csr, ca, ca_key),
         cert_pem <- X509.Certificate.to_pem(cert),
         {:ok, attrs} <- Certificate.from_pem(cert_pem) do
      %Certificate{}
      |> Certificate.changeset(%{
        serial_number: attrs.serial_number,
        fingerprint: attrs.fingerprint,
        certificate_pem: cert_pem,
        subject: attrs.subject,
        issuer: attrs.issuer,
        common_name: attrs.common_name || enrollment.agent_id,
        organization: attrs.organization || "SecretHub Agents",
        organizational_unit: attrs.organizational_unit,
        valid_from: attrs.valid_from,
        valid_until: attrs.valid_until,
        cert_type: :agent_client,
        key_usage: ["digitalSignature"],
        issuer_id: ca.id,
        enrollment_id: enrollment.id,
        ssh_host_key_fingerprint: enrollment.ssh_host_key_fingerprint,
        entity_id: enrollment.agent_id,
        entity_type: "agent",
        metadata: %{
          "san_uri" => get_in(enrollment.required_csr_fields, ["san", "uri"]) || [],
          "san_dns" => get_in(enrollment.required_csr_fields, ["san", "dns"]) || [],
          "extended_key_usage" => ["clientAuth"]
        }
      })
      |> Repo.insert()
    end
  end

  defp active_signing_ca_with_key do
    with {:ok, ca} <- RootCA.active_ca(),
         {:ok, ca_key} <- decrypt_private_key(ca.private_key_encrypted) do
      {:ok, ca, ca_key}
    else
      {:error, :no_active_ca} -> {:error, :no_active_ca}
      {:error, _reason} -> {:error, :ca_private_key_unavailable}
    end
  end

  defp build_certificate(enrollment, csr, ca, ca_key) do
    san_uri =
      enrollment.required_csr_fields
      |> get_in(["san", "uri"])
      |> List.wrap()
      |> Enum.map(&{:uniformResourceIdentifier, to_charlist(&1)})

    san_dns =
      enrollment.required_csr_fields
      |> get_in(["san", "dns"])
      |> List.wrap()
      |> Enum.map(&{:dNSName, to_charlist(&1)})

    extensions = [
      basic_constraints: Extension.basic_constraints(false),
      key_usage: Extension.key_usage([:digitalSignature]),
      ext_key_usage: Extension.ext_key_usage([:clientAuth]),
      subject_alt_name: Extension.subject_alt_name(san_uri ++ san_dns)
    ]

    X509.Certificate.new(
      X509.CSR.public_key(csr),
      "/O=SecretHub Agents/CN=#{enrollment.agent_id}",
      X509.Certificate.from_pem!(ca.certificate_pem),
      ca_key,
      extensions: extensions,
      validity: validity_days()
    )
  end

  defp decrypt_private_key(encrypted_key) do
    case Encryption.decrypt_from_blob(encrypted_key, master_key()) do
      {:ok, key_pem} -> X509.PrivateKey.from_pem(key_pem)
      {:error, reason} -> {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp master_key do
    case Process.whereis(SealState) do
      nil ->
        dev_fallback_key()

      _pid ->
        case SealState.get_master_key() do
          {:ok, key} -> key
          {:error, _reason} -> if(dev_pki_unsealed_fallback?(), do: dev_fallback_key())
        end
    end
  end

  defp dev_pki_unsealed_fallback? do
    Application.get_env(:secrethub_core, :dev_pki_unsealed_fallback, false)
  end

  defp dev_fallback_key do
    :crypto.hash(:sha256, "test-encryption-key-for-pki-testing")
  end

  def validity_days do
    agent_certificate_ttl_seconds()
    |> div(86_400)
  end

  def agent_certificate_ttl_seconds do
    ttl_seconds =
      Application.get_env(
        :secrethub_core,
        :agent_certificate_ttl_seconds,
        @default_agent_certificate_ttl_seconds
      )

    max_ttl_seconds =
      Application.get_env(
        :secrethub_core,
        :agent_certificate_max_ttl_seconds,
        @default_agent_certificate_max_ttl_seconds
      )

    ttl_seconds
    |> min(max_ttl_seconds)
    |> ceil_days()
    |> Kernel.*(86_400)
  end

  defp ceil_days(seconds) when seconds <= 86_400, do: 1
  defp ceil_days(seconds), do: ceil(seconds / 86_400)

  defp server_subject_alt_names(dns_names) do
    dns_names
    |> List.wrap()
    |> Enum.flat_map(fn
      "127.0.0.1" -> [{:iPAddress, {127, 0, 0, 1}}]
      "::1" -> [{:iPAddress, {0, 0, 0, 0, 0, 0, 0, 1}}]
      name when is_binary(name) -> [name]
      _other -> []
    end)
    |> Enum.uniq()
  end
end
