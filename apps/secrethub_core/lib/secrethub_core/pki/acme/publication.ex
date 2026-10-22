defmodule SecretHub.Core.PKI.ACME.Publication do
  @moduledoc "Atomic publication of a validated immutable server-certificate generation."
  alias Ecto.Changeset
  alias SecretHub.Core.AuthorizationVersions
  alias SecretHub.Core.PKI.ACME.CertificateValidation
  alias SecretHub.Core.PKI.ACME.Renewal
  alias SecretHub.Core.PKI.ManagedCertificates, as: Managed
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Secrets
  alias SecretHub.Shared.Schemas.AcmeOrder
  alias SecretHub.Shared.Schemas.ManagedCertificate
  alias SecretHub.Shared.Schemas.ManagedCertificateVersion

  def publish(order_id, claim_token, opts \\ []) do
    with {:ok, order} <- Managed.get_order(order_id) do
      if order.state == "published" do
        {:ok, Repo.get_by!(ManagedCertificateVersion, order_id: order.id)}
      else
        publish_pending(order, claim_token, opts)
      end
    end
  end

  defp publish_pending(order, claim_token, opts) do
    with {:ok, key} <- Managed.decrypt(order.encrypted_pending_key),
         {:ok, material} <-
           CertificateValidation.validate(
             order.downloaded_chain,
             key,
             order.identifiers,
             order.account_snapshot["environment"],
             opts
           ) do
      version_id = Ecto.UUID.generate()

      payload = %{
        "certificate_version_id" => version_id,
        "fingerprint" => material.fingerprint_sha256,
        "certificate" => material.certificate_pem,
        "chain" => material.chain_pem,
        "fullchain" => material.fullchain_pem,
        "private_key" => key,
        "combined_pem" => material.fullchain_pem <> key,
        "environment" => material.environment,
        "identifiers" => material.identifiers,
        "not_before" => DateTime.to_iso8601(material.not_before),
        "not_after" => DateTime.to_iso8601(material.not_after)
      }

      with {:ok, encrypted} <- Managed.encrypt(Jason.encode!(payload)) do
        commit(order, claim_token, version_id, material, encrypted, opts)
      end
    end
  end

  defp commit(original, token, version_id, material, encrypted, opts) do
    Repo.transaction(fn ->
      AuthorizationVersions.lock_global()
      resource = Managed.locked!(ManagedCertificate, original.managed_certificate_id)
      order = Managed.locked!(AcmeOrder, original.id)

      publish_locked(resource, order, token, version_id, material, encrypted, opts)
    end)
  end

  defp publish_locked(_, %{state: "published"} = order, _, _, _, _, _),
    do: Repo.get_by!(ManagedCertificateVersion, order_id: order.id)

  defp publish_locked(resource, order, token, version_id, material, encrypted, opts) do
    Managed.require_enabled!(resource)

    verify_generation!(resource, order, token)
    secret = write_secret!(resource, encrypted)

    checkpoint(opts, :secret_written)
    due = Renewal.fallback(material.not_before, material.not_after)

    version =
      Managed.insert!(
        ManagedCertificateVersion.changeset(%ManagedCertificateVersion{id: version_id}, %{
          managed_certificate_id: resource.id,
          order_id: order.id,
          publication_sequence: resource.publication_sequence + 1,
          environment: material.environment,
          fingerprint: material.fingerprint_sha256,
          certificate_pem: material.certificate_pem,
          chain_pem: material.chain_pem,
          fullchain_pem: material.fullchain_pem,
          identifiers: material.identifiers,
          not_before: DateTime.truncate(material.not_before, :second),
          not_after: DateTime.truncate(material.not_after, :second),
          key_policy: resource.key_policy,
          output_secret_id: secret.id,
          secret_version_number: secret.version,
          renewal_due_at: DateTime.truncate(due, :second),
          ari_refresh_at: Managed.now(),
          ari: %{"certificate_id" => material.ari_certificate_id}
        })
      )

    checkpoint(opts, :version_written)

    Managed.update!(
      Changeset.change(resource,
        current_version_id: version.id,
        publication_sequence: version.publication_sequence,
        output_secret_id: secret.id,
        next_renewal_at: version.renewal_due_at,
        last_error: %{}
      )
    )

    Managed.update!(
      Changeset.change(order,
        state: "published",
        phase: "published",
        encrypted_pending_key: nil,
        claim_token: nil,
        claim_expires_at: nil,
        last_error: %{}
      )
    )

    checkpoint(opts, :pointer_switched)

    Managed.audit!("acme.certificate.published", resource.id, %{
      version_id: version.id,
      order_id: order.id,
      fingerprint: version.fingerprint,
      publication_sequence: version.publication_sequence
    })

    checkpoint(opts, :audit_appended)
    version
  end

  defp verify_generation!(resource, order, token) do
    unless order.claim_token == token and not is_nil(token) and
             order.configuration_revision == resource.configuration_revision and
             order.expected_prior_version_id == resource.current_version_id and
             order.state not in ["failed", "cancelled"] and not is_nil(order.claim_expires_at) and
             DateTime.compare(order.claim_expires_at, Managed.now()) == :gt,
           do: Repo.rollback(:stale_publication)
  end

  defp write_secret!(resource, encrypted) do
    case Secrets.write_managed_output_locked(resource, encrypted) do
      {:ok, secret} -> secret
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp checkpoint(opts, step) do
    if hook = opts[:publication_checkpoint], do: hook.(step)
  end
end
