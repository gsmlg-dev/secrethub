defmodule SecretHub.Core.PKI.ACME.Revocation do
  @moduledoc "Remote revocation evidence never overrides a local quarantine."
  alias Ecto.Changeset
  alias SecretHub.Core.PKI.ACME.{Client, Workflow}
  alias SecretHub.Core.PKI.ManagedCertificates, as: Managed
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{AcmeAccount, AcmeOrder, ManagedCertificateVersion}

  def run(id, opts \\ []) do
    version = Repo.get!(ManagedCertificateVersion, id)

    if version.revocation_state == "confirmed" do
      :ok
    else
      revoke(version, opts)
    end
  end

  defp revoke(version, opts) do
    order = Repo.get!(AcmeOrder, version.order_id)
    account = Repo.get!(AcmeAccount, order.account_snapshot["id"])

    result =
      with {:ok, key} <- Managed.decrypt(account.encrypted_key),
           {:ok, directory} <- Client.directory(account.directory_url, opts),
           {:ok, cert} <- X509.Certificate.from_pem(version.certificate_pem) do
        Client.revoke(
          directory,
          %{key_pem: key, kid: account.account_url},
          X509.Certificate.to_der(cert),
          version.revocation_reason,
          opts
        )
      end

    case result do
      {:ok, _} ->
        confirm(version)

      {:error, %{type: "urn:ietf:params:acme:error:alreadyRevoked"}} ->
        confirm(version)

      {:error, reason} ->
        record_failure(version.id, Workflow.error(reason))
    end
  end

  defp record_failure(id, error) do
    result =
      Repo.transaction(fn ->
        current = Managed.locked!(ManagedCertificateVersion, id)

        if current.revocation_state == "confirmed" do
          :confirmed
        else
          Managed.update!(
            Changeset.change(current,
              revocation_state: "failed",
              revocation_error: error,
              revocation_next_attempt_at: DateTime.add(Managed.now(), 300)
            )
          )

          :failed
        end
      end)

    case result do
      {:ok, :confirmed} -> :ok
      {:ok, :failed} -> {:error, error}
      {:error, _} = failure -> failure
    end
  end

  defp confirm(version) do
    case Repo.transaction(fn ->
           current = Managed.locked!(ManagedCertificateVersion, version.id)

           Managed.update!(
             Changeset.change(current,
               revocation_state: "confirmed",
               revocation_error: %{},
               revocation_next_attempt_at: nil
             )
           )

           Managed.audit!("acme.revocation.confirmed", version.id)
         end) do
      {:ok, _} -> :ok
      error -> error
    end
  end
end
