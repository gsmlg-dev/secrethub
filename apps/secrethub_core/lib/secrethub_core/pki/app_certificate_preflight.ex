defmodule SecretHub.Core.PKI.AppCertificatePreflight do
  @moduledoc """
  Reports legacy certificate rows that block canonical application authentication.

  Findings contain only stable database identifiers and public reason codes.
  Certificate material, fingerprints, application names, and other metadata are
  deliberately excluded from the operator-facing report.
  """

  import Ecto.Changeset, only: [change: 2, check_constraint: 3, unique_constraint: 3]
  import Ecto.Query

  alias SecretHub.Core.PKI.CertificateIdentity
  alias SecretHub.Core.Repo

  alias SecretHub.Shared.Schemas.{
    Agent,
    AppCertificate,
    Application,
    Certificate
  }

  @report_format "secrethub.upgrade-gate-report.v1"
  @gate "app_certificate_v2"
  @preflight_version "1"

  @type finding :: %{
          required(:code) => atom(),
          required(:kind) => String.t(),
          required(:identifier) => String.t(),
          optional(:certificate_id) => Ecto.UUID.t(),
          optional(:application_id) => Ecto.UUID.t(),
          optional(:association_id) => Ecto.UUID.t()
        }

  @doc """
  Returns a deterministic, sanitized report for the application-certificate gate.
  """
  @spec report() :: %{
          format: String.t(),
          gate: String.t(),
          preflight_version: String.t(),
          findings: [finding()]
        }
  def report do
    certificates =
      Certificate
      |> order_by([certificate], asc: certificate.id)
      |> Repo.all()

    associations =
      from(app_certificate in AppCertificate,
        join: certificate in Certificate,
        on: certificate.id == app_certificate.certificate_id,
        join: application in Application,
        on: application.id == app_certificate.app_id,
        order_by: [
          asc: app_certificate.certificate_id,
          asc: app_certificate.app_id,
          asc: app_certificate.id
        ],
        select: {app_certificate, certificate, application}
      )
      |> Repo.all()

    associated_certificate_ids =
      MapSet.new(associations, fn {_association, certificate, _application} ->
        certificate.id
      end)

    association_by_certificate =
      Enum.reduce(associations, %{}, fn {association, certificate, application}, index ->
        Map.put_new(index, certificate.id, {association, application})
      end)

    now = DateTime.utc_now() |> DateTime.truncate(:second)

    findings =
      certificate_findings(certificates, association_by_certificate) ++
        association_findings(associations, now) ++
        missing_association_findings(certificates, associated_certificate_ids, now) ++
        orphan_agent_findings()

    %{
      format: @report_format,
      gate: @gate,
      preflight_version: @preflight_version,
      findings: Enum.sort_by(findings, &finding_sort_key/1)
    }
  end

  @doc """
  Backfills missing canonical fingerprints in ordered, row-locked batches.

  A full read-only scan runs first so known malformed or colliding rows cannot
  leave partial progress. Each write batch is its own transaction; a race that
  introduces a collision rolls back that complete batch.
  """
  @spec backfill_canonical_fingerprints(keyword()) ::
          {:ok, non_neg_integer()} | {:error, :invalid_batch_size | finding()}
  def backfill_canonical_fingerprints(opts \\ []) do
    with {:ok, batch_size} <- validate_batch_size(Keyword.get(opts, :batch_size, 100)),
         :ok <- validate_backfill_sources() do
      backfill_batches(batch_size, 0)
    end
  end

  defp certificate_findings(certificates, association_by_certificate) do
    parsed =
      Enum.map(certificates, fn certificate ->
        {certificate,
         CertificateIdentity.canonical_fingerprint_from_pem(certificate.certificate_pem)}
      end)

    colliding_ids = colliding_certificate_ids(parsed)

    Enum.flat_map(parsed, fn {certificate, result} ->
      fingerprint_findings(
        certificate,
        result,
        colliding_ids,
        Map.get(association_by_certificate, certificate.id)
      )
    end)
  end

  defp fingerprint_findings(
         certificate,
         {:error, _reason},
         _colliding_ids,
         association_context
       ) do
    missing =
      if is_nil(certificate.canonical_fingerprint),
        do: [
          certificate_finding(
            :canonical_fingerprint_missing,
            certificate,
            association_context
          )
        ],
        else: []

    [certificate_finding(:malformed_pem, certificate, association_context) | missing]
  end

  defp fingerprint_findings(certificate, {:ok, computed}, colliding_ids, association_context) do
    canonical =
      cond do
        is_nil(certificate.canonical_fingerprint) ->
          [
            certificate_finding(
              :canonical_fingerprint_missing,
              certificate,
              association_context
            )
          ]

        certificate.canonical_fingerprint != computed ->
          [
            certificate_finding(
              :canonical_fingerprint_mismatch,
              certificate,
              association_context
            )
          ]

        true ->
          []
      end

    collision =
      if MapSet.member?(colliding_ids, certificate.id),
        do: [
          certificate_finding(
            :canonical_fingerprint_collision,
            certificate,
            association_context
          )
        ],
        else: []

    canonical ++ collision
  end

  defp colliding_certificate_ids(parsed) do
    parsed
    |> Enum.reduce(%{}, fn
      {certificate, {:ok, fingerprint}}, groups ->
        Map.update(groups, fingerprint, [certificate.id], &[certificate.id | &1])

      {_certificate, {:error, _reason}}, groups ->
        groups
    end)
    |> Enum.reduce(MapSet.new(), fn
      {_fingerprint, [_single]}, ids -> ids
      {_fingerprint, duplicates}, ids -> Enum.reduce(duplicates, ids, &MapSet.put(&2, &1))
    end)
  end

  defp association_findings(associations, now) do
    Enum.flat_map(associations, fn {association, certificate, application} ->
      entity_findings(association, certificate, application) ++
        lifecycle_findings(association, certificate, application, now) ++
        identity_findings(association, certificate, application, now)
    end)
  end

  defp entity_findings(association, certificate, application) do
    if certificate.cert_type == :app_client and certificate.entity_type == "app" and
         certificate.entity_id == application.id do
      []
    else
      [association_finding(:entity_mismatch, association, certificate, application)]
    end
  end

  defp lifecycle_findings(association, certificate, application, now) do
    revocation =
      if certificate_revoked?(certificate) == association_revoked?(association) do
        []
      else
        [
          association_finding(
            :revoked_association_mismatch,
            association,
            certificate,
            application
          )
        ]
      end

    expiration_mismatch? =
      not same_timestamp?(association.expires_at, certificate.valid_until) or
        (not certificate_revoked?(certificate) and not association_revoked?(association) and
           (DateTime.compare(certificate.valid_until, now) != :gt or
              DateTime.compare(association.expires_at, now) != :gt))

    expiration =
      if expiration_mismatch? do
        [
          association_finding(
            :expired_association_mismatch,
            association,
            certificate,
            application
          )
        ]
      else
        []
      end

    revocation ++ expiration
  end

  defp identity_findings(association, certificate, application, now) do
    if active_canonical_entity?(association, certificate, application, now) do
      certificate.certificate_pem
      |> CertificateIdentity.validate_app_certificate(application.id)
      |> identity_result_findings(association, certificate, application)
    else
      []
    end
  end

  defp identity_result_findings({:ok, _metadata}, _association, _certificate, _application),
    do: []

  defp identity_result_findings(
         {:error, :invalid_common_name},
         association,
         certificate,
         application
       ) do
    code =
      if name_based_common_name?(certificate.certificate_pem),
        do: :name_based_identity,
        else: :invalid_common_name

    [association_finding(code, association, certificate, application)]
  end

  defp identity_result_findings(
         {:error, :invalid_organization},
         association,
         certificate,
         application
       ) do
    [association_finding(:invalid_organization, association, certificate, application)]
  end

  defp identity_result_findings(
         {:error, :missing_app_uri_san},
         association,
         certificate,
         application
       ) do
    [association_finding(:missing_app_uri_san, association, certificate, application)]
  end

  defp identity_result_findings(
         {:error, :missing_client_auth},
         association,
         certificate,
         application
       ) do
    [association_finding(:missing_client_auth, association, certificate, application)]
  end

  defp identity_result_findings(
         {:error, :invalid_application_id},
         association,
         certificate,
         application
       ) do
    [association_finding(:entity_mismatch, association, certificate, application)]
  end

  defp identity_result_findings(
         {:error, :invalid_certificate},
         _association,
         _certificate,
         _application
       ),
       do: []

  defp active_canonical_entity?(association, certificate, application, now) do
    certificate.cert_type == :app_client and
      certificate.entity_type == "app" and
      certificate.entity_id == application.id and
      not certificate_revoked?(certificate) and
      not association_revoked?(association) and
      DateTime.compare(certificate.valid_until, now) == :gt and
      DateTime.compare(association.expires_at, now) == :gt
  end

  defp missing_association_findings(certificates, associated_certificate_ids, now) do
    certificates
    |> Enum.filter(fn certificate ->
      certificate.cert_type == :app_client and
        not MapSet.member?(associated_certificate_ids, certificate.id) and
        not certificate_revoked?(certificate) and
        DateTime.compare(certificate.valid_until, now) == :gt
    end)
    |> Enum.map(&certificate_finding(:entity_mismatch, &1))
  end

  defp orphan_agent_findings do
    from(application in Application,
      left_join: agent in Agent,
      on: agent.id == application.agent_id,
      where: is_nil(agent.id),
      order_by: [asc: application.id],
      select: application.id
    )
    |> Repo.all()
    |> Enum.map(fn application_id ->
      %{
        code: :orphan_agent_assignment,
        kind: "application",
        identifier: "application:#{application_id}",
        application_id: application_id
      }
    end)
  end

  defp certificate_common_names(pem) do
    case X509.Certificate.from_pem(pem) do
      {:ok, certificate} -> X509.Certificate.subject(certificate, "CN")
      _other -> []
    end
  rescue
    _error -> []
  end

  defp name_based_common_name?(pem) do
    case certificate_common_names(pem) do
      [common_name] -> not match?({:ok, _uuid}, Ecto.UUID.cast(common_name))
      _other -> false
    end
  end

  defp certificate_revoked?(certificate) do
    certificate.revoked or not is_nil(certificate.revoked_at)
  end

  defp association_revoked?(association), do: not is_nil(association.revoked_at)

  defp same_timestamp?(left, right) do
    DateTime.compare(left, right) == :eq
  end

  defp certificate_finding(code, certificate, association_context \\ nil)

  defp certificate_finding(code, certificate, {association, application}) do
    %{
      code: code,
      kind: "application_certificate",
      identifier: "certificate:#{certificate.id}",
      certificate_id: certificate.id,
      application_id: application.id,
      association_id: association.id
    }
  end

  defp certificate_finding(code, certificate, nil) do
    %{
      code: code,
      kind: "certificate",
      identifier: "certificate:#{certificate.id}",
      certificate_id: certificate.id
    }
  end

  defp association_finding(code, association, certificate, application) do
    %{
      code: code,
      kind: "application_certificate",
      identifier: "certificate:#{certificate.id}",
      certificate_id: certificate.id,
      application_id: application.id,
      association_id: association.id
    }
  end

  defp finding_sort_key(finding) do
    {
      finding.identifier,
      Atom.to_string(finding.code),
      Map.get(finding, :application_id, ""),
      Map.get(finding, :association_id, "")
    }
  end

  defp validate_batch_size(batch_size) when is_integer(batch_size) and batch_size > 0,
    do: {:ok, batch_size}

  defp validate_batch_size(_batch_size), do: {:error, :invalid_batch_size}

  defp validate_backfill_sources do
    certificates =
      from(certificate in Certificate,
        order_by: [asc: certificate.id],
        select: %{
          id: certificate.id,
          certificate_pem: certificate.certificate_pem,
          canonical_fingerprint: certificate.canonical_fingerprint
        }
      )
      |> Repo.all()

    with {:ok, prepared} <- prepare_backfill(certificates),
         :ok <- reject_computed_collisions(prepared) do
      reject_stored_collisions(prepared)
    end
  end

  defp prepare_backfill(certificates) do
    Enum.reduce_while(certificates, {:ok, []}, fn certificate, {:ok, prepared} ->
      case CertificateIdentity.canonical_fingerprint_from_pem(certificate.certificate_pem) do
        {:ok, fingerprint} ->
          {:cont, {:ok, [{certificate, fingerprint} | prepared]}}

        {:error, _reason} ->
          {:halt, {:error, certificate_finding(:malformed_pem, certificate)}}
      end
    end)
    |> case do
      {:ok, prepared} -> {:ok, Enum.reverse(prepared)}
      {:error, finding} -> {:error, finding}
    end
  end

  defp reject_computed_collisions(prepared) do
    collision =
      prepared
      |> Enum.group_by(fn {_certificate, fingerprint} -> fingerprint end)
      |> Enum.flat_map(fn
        {_fingerprint, [_single]} ->
          []

        {_fingerprint, duplicates} ->
          missing =
            Enum.filter(duplicates, fn {certificate, _fingerprint} ->
              is_nil(certificate.canonical_fingerprint)
            end)

          candidates = if missing == [], do: duplicates, else: missing
          [candidates |> Enum.map(&elem(&1, 0)) |> Enum.min_by(& &1.id)]
      end)
      |> case do
        [] -> nil
        certificates -> Enum.min_by(certificates, & &1.id)
      end

    collision
    |> case do
      nil -> :ok
      certificate -> {:error, certificate_finding(:canonical_fingerprint_collision, certificate)}
    end
  end

  defp reject_stored_collisions(prepared) do
    stored_owners =
      prepared
      |> Enum.reduce(%{}, fn
        {%{canonical_fingerprint: nil}, _computed}, owners ->
          owners

        {%{id: id, canonical_fingerprint: stored}, _computed}, owners ->
          Map.put(owners, stored, id)
      end)

    prepared
    |> Enum.find(fn
      {%{canonical_fingerprint: nil, id: id}, computed} ->
        case Map.fetch(stored_owners, computed) do
          {:ok, owner_id} -> owner_id != id
          :error -> false
        end

      {_certificate, _computed} ->
        false
    end)
    |> case do
      nil ->
        :ok

      {certificate, _computed} ->
        {:error, certificate_finding(:canonical_fingerprint_collision, certificate)}
    end
  end

  defp backfill_batches(batch_size, total) do
    case backfill_batch(batch_size) do
      {:ok, 0} -> {:ok, total}
      {:ok, count} -> backfill_batches(batch_size, total + count)
      {:error, finding} -> {:error, finding}
    end
  end

  defp backfill_batch(batch_size) do
    Repo.transaction(fn ->
      certificates =
        from(certificate in Certificate,
          where: is_nil(certificate.canonical_fingerprint),
          order_by: [asc: certificate.id],
          limit: ^batch_size,
          lock: "FOR UPDATE"
        )
        |> Repo.all()

      with {:ok, prepared} <- prepare_backfill(certificates),
           :ok <- reject_computed_collisions(prepared),
           :ok <- reject_batch_stored_collisions(prepared),
           :ok <- write_backfill(prepared) do
        length(prepared)
      else
        {:error, finding} -> Repo.rollback(finding)
      end
    end)
  end

  defp reject_batch_stored_collisions([]), do: :ok

  defp reject_batch_stored_collisions(prepared) do
    ids = Enum.map(prepared, fn {certificate, _fingerprint} -> certificate.id end)
    fingerprints = Enum.map(prepared, &elem(&1, 1))

    existing_fingerprints =
      from(certificate in Certificate,
        where:
          certificate.id not in ^ids and
            certificate.canonical_fingerprint in ^fingerprints,
        select: certificate.canonical_fingerprint
      )
      |> Repo.all()
      |> MapSet.new()

    case Enum.find(prepared, fn {_certificate, fingerprint} ->
           MapSet.member?(existing_fingerprints, fingerprint)
         end) do
      nil ->
        :ok

      {certificate, _fingerprint} ->
        {:error, certificate_finding(:canonical_fingerprint_collision, certificate)}
    end
  end

  defp write_backfill(prepared) do
    Enum.reduce_while(prepared, :ok, fn {certificate, fingerprint}, :ok ->
      changeset =
        certificate
        |> change(canonical_fingerprint: fingerprint)
        |> unique_constraint(:canonical_fingerprint,
          name: :certificates_canonical_fingerprint_unique
        )
        |> check_constraint(:canonical_fingerprint,
          name: :certificates_canonical_fingerprint_format
        )

      case Repo.update(changeset) do
        {:ok, _certificate} ->
          {:cont, :ok}

        {:error, _changeset} ->
          {:halt, {:error, certificate_finding(:canonical_fingerprint_collision, certificate)}}
      end
    end)
  end
end
