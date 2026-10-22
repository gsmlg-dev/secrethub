defmodule SecretHub.Core.PKI.ACME.Reconciler do
  @moduledoc "Finds due work independently of an individual job's retry budget."
  use Oban.Worker,
    queue: :acme,
    max_attempts: 3,
    unique: [period: 45, states: [:available, :scheduled, :executing, :retryable]]

  import Ecto.Query
  alias SecretHub.Core.PKI.ManagedCertificates, as: Managed
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.LaunchProfile

  alias SecretHub.Shared.Schemas.{
    AcmeAccount,
    AcmeOrder,
    DNSChallengeOperation,
    ManagedCertificate,
    ManagedCertificateVersion
  }

  @impl true
  def perform(_) do
    now = Managed.now()

    reconcile_orders(now)
    reconcile_cleanup(now)
    reconcile_revocations(now)
    reconcile_renewals(now)

    :ok
  end

  defp reconcile_orders(now) do
    Repo.all(
      from(o in AcmeOrder,
        where:
          o.state not in ["published", "failed", "cancelled"] and
            (is_nil(o.next_attempt_at) or o.next_attempt_at <= ^now) and
            (is_nil(o.claim_expires_at) or o.claim_expires_at <= ^now),
        limit: 100
      )
    )
    |> Enum.each(&Managed.enqueue(%{"order_id" => &1.id}))
  end

  defp reconcile_cleanup(now) do
    Repo.all(
      from(d in DNSChallengeOperation,
        join: o in AcmeOrder,
        on: o.id == d.order_id,
        where:
          d.cleanup_status != "cleaned" and o.state in ["published", "failed", "cancelled"] and
            (is_nil(d.next_attempt_at) or d.next_attempt_at <= ^now),
        select: d.id,
        limit: 100
      )
    )
    |> Enum.each(&Managed.enqueue(%{"cleanup_operation_id" => &1}, :cleanup))
  end

  defp reconcile_revocations(now) do
    Repo.all(
      from(v in ManagedCertificateVersion,
        where:
          v.revocation_state in ["pending", "failed"] and
            (is_nil(v.revocation_next_attempt_at) or v.revocation_next_attempt_at <= ^now),
        limit: 100
      )
    )
    |> Enum.each(&Managed.enqueue(%{"revoke_version_id" => &1.id}, :cleanup))
  end

  defp reconcile_renewals(now) do
    if LaunchProfile.enabled?(:acme) do
      Repo.all(from(a in AcmeAccount, where: a.enabled and a.status == "pending", limit: 100))
      |> Enum.each(&Managed.enqueue(%{"account_id" => &1.id}))

      Repo.all(
        from([m, v] in enabled_resources(),
          where:
            (not is_nil(m.next_renewal_at) and m.next_renewal_at <= ^now) or
              (is_nil(v.quarantined_at) and v.not_after > ^now and
                 (is_nil(v.ari_refresh_at) or v.ari_refresh_at <= ^now)),
          limit: 100
        )
      )
      |> Enum.each(&reconcile_resource(&1, now))
    end
  end

  defp enabled_resources do
    from(m in ManagedCertificate,
      join: v in ManagedCertificateVersion,
      on: v.id == m.current_version_id,
      join: a in AcmeAccount,
      on: a.id == m.account_id,
      where:
        m.enabled and a.enabled and
          fragment(
            "NOT EXISTS (SELECT 1 FROM unnest(?) AS bindings(binding) LEFT JOIN acme_dns_providers p ON p.id::text = lower(binding->>'provider_id') WHERE p.id IS NULL OR NOT p.enabled)",
            m.bindings
          )
    )
  end

  defp reconcile_resource(resource, now) do
    if Managed.enabled?(resource) do
      version = Repo.get!(ManagedCertificateVersion, resource.current_version_id)

      if is_nil(version.quarantined_at) and DateTime.compare(version.not_after, now) == :gt and
           (is_nil(version.ari_refresh_at) or
              DateTime.compare(version.ari_refresh_at, now) != :gt),
         do: Managed.enqueue(%{"renewal_info_id" => version.id})

      resource = Repo.get!(ManagedCertificate, resource.id)

      if resource.next_renewal_at && DateTime.compare(resource.next_renewal_at, now) != :gt,
        do: renew(resource, version)
    end
  end

  defp renew(resource, version) do
    failures =
      Repo.aggregate(
        from(o in AcmeOrder,
          where:
            o.managed_certificate_id == ^resource.id and
              o.expected_prior_version_id == ^version.id and o.state in ["failed", "cancelled"]
        ),
        :count
      )

    Managed.request_issue(resource.id, "renewal:" <> version.id <> ":" <> to_string(failures))
  end
end
