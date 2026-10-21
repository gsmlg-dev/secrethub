defmodule SecretHub.Core.PKI.ACME.RenewalScheduler do
  @moduledoc "Persists current-generation ARI windows and refresh timing."
  alias Ecto.Changeset
  alias SecretHub.Core.PKI.ACME.{Client, Renewal, Workflow}
  alias SecretHub.Core.PKI.ManagedCertificates, as: Managed
  alias SecretHub.Core.Repo

  alias SecretHub.Shared.Schemas.{
    AcmeAccount,
    AcmeOrder,
    ManagedCertificate,
    ManagedCertificateVersion
  }

  def refresh(version, opts \\ []) do
    order = Repo.get!(AcmeOrder, version.order_id)
    account = Repo.get!(AcmeAccount, order.account_snapshot["id"])
    resource = Repo.get!(ManagedCertificate, version.managed_certificate_id)

    result = fetch_window(resource, version, account, opts)

    Repo.transaction(fn ->
      resource = Managed.locked!(ManagedCertificate, version.managed_certificate_id)
      current = Managed.locked!(ManagedCertificateVersion, version.id)

      if active_current?(resource, current), do: persist_result(resource, current, result)
    end)
  end

  defp fetch_window(resource, version, account, opts) do
    if Managed.enabled?(resource) and active_current?(resource, version) do
      with {:ok, directory} <- Client.directory(account.directory_url, opts),
           {:ok, response} <-
             Client.renewal_info(directory, version.ari["certificate_id"], opts),
           {:ok, window} <- Renewal.window(response.body, response.headers, opts),
           true <- DateTime.compare(window.renew_at, version.not_after) == :lt do
        {:ok, window}
      end
    else
      {:error, :disabled}
    end
  end

  defp active_current?(resource, version) do
    resource.current_version_id == version.id and is_nil(version.quarantined_at) and
      DateTime.compare(version.not_after, Managed.now()) == :gt
  end

  defp persist_result(resource, current, {:ok, window}) do
    same =
      current.ari["start"] == DateTime.to_iso8601(window.window_start) and
        current.ari["end"] == DateTime.to_iso8601(window.window_end)

    due = if same, do: current.renewal_due_at, else: DateTime.truncate(window.renew_at, :second)

    Managed.update!(
      Changeset.change(current,
        ari:
          Map.merge(Map.delete(current.ari, "error"), %{
            "start" => DateTime.to_iso8601(window.window_start),
            "end" => DateTime.to_iso8601(window.window_end)
          }),
        renewal_due_at: due,
        ari_refresh_at: DateTime.truncate(window.refresh_at, :second)
      )
    )

    Managed.update!(Changeset.change(resource, next_renewal_at: retry_due(resource, due)))
  end

  defp persist_result(_, current, failure) do
    reason =
      case failure do
        {:error, reason} -> reason
        _ -> :invalid_ari_window
      end

    Managed.update!(
      Changeset.change(current,
        ari_refresh_at: DateTime.add(Managed.now(), 3600),
        ari: Map.put(current.ari, "error", Workflow.error(reason))
      )
    )
  end

  defp retry_due(resource, due) do
    if (resource.last_error != %{} and resource.next_renewal_at) &&
         DateTime.compare(resource.next_renewal_at, due) == :gt,
       do: resource.next_renewal_at,
       else: due
  end
end
