defmodule SecretHub.Core.PKI.AppCertificatePreflightTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.{Agents, Apps, Repo}
  alias SecretHub.Core.PKI.{AppCertificatePreflight, CertificateIdentity}

  alias SecretHub.Shared.Schemas.{
    AppCertificate,
    Application,
    AuditLog,
    Certificate
  }

  alias X509.Certificate, as: X509Certificate
  alias X509.Certificate.{Extension, Validity}

  @certificate_id_1 "00000000-0000-0000-0000-000000000001"
  @certificate_id_2 "00000000-0000-0000-0000-000000000002"
  @certificate_id_3 "00000000-0000-0000-0000-000000000003"

  describe "report/0" do
    test "returns the upgrade-gate envelope with deterministic sanitized public identifiers" do
      app = register_app!()
      material = app_certificate_material(app.id)

      mismatch =
        insert_app_certificate!(
          app,
          material,
          %{
            id: @certificate_id_1,
            canonical_fingerprint: canonical_hex("stored-mismatch")
          }
        )

      malformed =
        insert_app_certificate!(
          app,
          malformed_material(),
          %{
            id: @certificate_id_2,
            canonical_fingerprint: canonical_hex("malformed-row")
          }
        )

      assert %{
               format: "secrethub.upgrade-gate-report.v1",
               gate: "app_certificate_v2",
               preflight_version: "1",
               findings: findings
             } = AppCertificatePreflight.report()

      assert [
               %{
                 code: :canonical_fingerprint_mismatch,
                 kind: "application_certificate",
                 identifier: "certificate:" <> mismatch_id,
                 certificate_id: mismatch_id,
                 application_id: app_id
               },
               %{
                 code: :malformed_pem,
                 kind: "application_certificate",
                 identifier: "certificate:" <> malformed_id,
                 certificate_id: malformed_id,
                 application_id: app_id
               }
             ] = findings

      assert mismatch_id == mismatch.id
      assert malformed_id == malformed.id
      assert app_id == app.id
      assert findings == Enum.sort_by(findings, &{&1.identifier, to_string(&1.code)})

      encoded_findings = JSON.encode!(findings)

      refute encoded_findings =~ "BEGIN CERTIFICATE"
      refute encoded_findings =~ material.canonical_fingerprint
      refute encoded_findings =~ canonical_hex("stored-mismatch")
      refute encoded_findings =~ "malformed certificate body"

      Enum.each(findings, fn finding ->
        refute Map.has_key?(finding, :certificate_pem)
        refute Map.has_key?(finding, :canonical_fingerprint)
        refute Map.has_key?(finding, :fingerprint)
        refute Map.has_key?(finding, :metadata)
      end)
    end

    test "reports missing, mismatched, and computed fingerprint collisions separately" do
      app = register_app!()
      missing_material = app_certificate_material(app.id)
      mismatch_material = app_certificate_material(app.id)
      collision_material = app_certificate_material(app.id)

      missing =
        insert_app_certificate!(app, missing_material, %{canonical_fingerprint: nil})

      mismatch =
        insert_app_certificate!(
          app,
          mismatch_material,
          %{canonical_fingerprint: canonical_hex("different-fingerprint")}
        )

      collision_stored = insert_app_certificate!(app, collision_material)

      collision_missing =
        insert_app_certificate!(
          app,
          collision_material,
          %{canonical_fingerprint: nil}
        )

      %{findings: findings} = AppCertificatePreflight.report()

      assert :canonical_fingerprint_missing in codes_for(findings, missing.id)
      assert :canonical_fingerprint_mismatch in codes_for(findings, mismatch.id)

      assert :canonical_fingerprint_collision in codes_for(findings, collision_stored.id)

      assert :canonical_fingerprint_collision in codes_for(findings, collision_missing.id)
    end

    test "reports missing clientAuth and missing or wrong application URI SAN" do
      app = register_app!()

      missing_eku =
        insert_app_certificate!(
          app,
          app_certificate_material(app.id, client_auth?: false)
        )

      missing_san =
        insert_app_certificate!(
          app,
          app_certificate_material(app.id, uri_san: false)
        )

      wrong_san =
        insert_app_certificate!(
          app,
          app_certificate_material(
            app.id,
            uri_san: "urn:secrethub:app:#{Ecto.UUID.generate()}"
          )
        )

      %{findings: findings} = AppCertificatePreflight.report()

      assert :missing_client_auth in codes_for(findings, missing_eku.id)
      assert :missing_app_uri_san in codes_for(findings, missing_san.id)
      assert :missing_app_uri_san in codes_for(findings, wrong_san.id)
    end

    test "reports legacy name-based identity instead of treating the mutable app name as identity" do
      app = register_app!()

      certificate =
        insert_app_certificate!(
          app,
          app_certificate_material(app.id, common_name: app.name)
        )

      app
      |> Application.changeset(%{
        name: "renamed-preflight-app-#{System.unique_integer([:positive])}"
      })
      |> Repo.update!()

      %{findings: findings} = AppCertificatePreflight.report()

      assert :name_based_identity in codes_for(findings, certificate.id)
    end

    test "reports entity id, entity type, and certificate type mismatches" do
      app = register_app!()

      wrong_entity_id =
        insert_app_certificate!(
          app,
          app_certificate_material(app.id),
          %{entity_id: Ecto.UUID.generate()}
        )

      wrong_entity_type =
        insert_app_certificate!(
          app,
          app_certificate_material(app.id),
          %{entity_type: "agent"}
        )

      wrong_certificate_type =
        insert_app_certificate!(
          app,
          app_certificate_material(app.id),
          %{cert_type: :agent_client}
        )

      %{findings: findings} = AppCertificatePreflight.report()

      assert :entity_mismatch in codes_for(findings, wrong_entity_id.id)
      assert :entity_mismatch in codes_for(findings, wrong_entity_type.id)
      assert :entity_mismatch in codes_for(findings, wrong_certificate_type.id)
    end

    test "reports expired active associations and both directions of revocation mismatch" do
      app = register_app!()
      now = now()

      expired_material =
        app_certificate_material(
          app.id,
          valid_from: DateTime.add(now, -7_200, :second),
          valid_until: DateTime.add(now, -3_600, :second)
        )

      expired_active = insert_app_certificate!(app, expired_material)

      revoked_certificate =
        insert_app_certificate!(
          app,
          app_certificate_material(app.id),
          %{
            revoked: true,
            revoked_at: now,
            revocation_reason: "operator_revoked"
          }
        )

      association_revoked_only =
        insert_app_certificate!(
          app,
          app_certificate_material(app.id),
          %{},
          %{revoked_at: now, revocation_reason: "operator_revoked"}
        )

      %{findings: findings} = AppCertificatePreflight.report()

      assert :expired_association_mismatch in codes_for(findings, expired_active.id)

      assert :revoked_association_mismatch in codes_for(findings, revoked_certificate.id)

      assert :revoked_association_mismatch in codes_for(findings, association_revoked_only.id)
    end

    test "reports certificate and association expiry disagreement" do
      app = register_app!()
      material = app_certificate_material(app.id)

      certificate =
        insert_app_certificate!(
          app,
          material,
          %{},
          %{expires_at: DateTime.add(material.valid_until, -60, :second)}
        )

      %{findings: findings} = AppCertificatePreflight.report()

      assert :expired_association_mismatch in codes_for(findings, certificate.id)
    end

    test "reports applications assigned to a missing Agent without guessing an identity" do
      orphan_app_id = Ecto.UUID.generate()
      missing_agent_id = Ecto.UUID.generate()

      insert_orphan_application!(orphan_app_id, missing_agent_id)

      %{findings: findings} = AppCertificatePreflight.report()

      assert [
               %{
                 code: :orphan_agent_assignment,
                 kind: "application",
                 identifier: "application:" <> application_id,
                 application_id: application_id
               }
             ] = findings

      assert application_id == orphan_app_id
      refute hd(findings)[:agent_id]
    end

    test "returns zero findings for a canonical active application certificate" do
      app = register_app!()
      insert_app_certificate!(app, app_certificate_material(app.id))

      assert %{
               format: "secrethub.upgrade-gate-report.v1",
               gate: "app_certificate_v2",
               preflight_version: "1",
               findings: []
             } = AppCertificatePreflight.report()
    end
  end

  describe "backfill_canonical_fingerprints/1" do
    test "processes every ordered batch and returns the number of updated rows" do
      app = register_app!()

      certificates =
        for _index <- 1..3 do
          insert_app_certificate!(
            app,
            app_certificate_material(app.id),
            %{canonical_fingerprint: nil}
          )
        end

      assert {:ok, 3} =
               AppCertificatePreflight.backfill_canonical_fingerprints(batch_size: 2)

      Enum.each(certificates, fn certificate ->
        stored = Repo.get!(Certificate, certificate.id)

        assert {:ok, expected} =
                 CertificateIdentity.canonical_fingerprint_from_pem(stored.certificate_pem)

        assert stored.canonical_fingerprint == expected
      end)
    end

    test "pre-scans malformed PEM beyond the first batch and leaves every row untouched" do
      app = register_app!()

      valid_1 =
        insert_app_certificate!(
          app,
          app_certificate_material(app.id),
          %{id: @certificate_id_1, canonical_fingerprint: nil}
        )

      valid_2 =
        insert_app_certificate!(
          app,
          app_certificate_material(app.id),
          %{id: @certificate_id_2, canonical_fingerprint: nil}
        )

      malformed =
        insert_app_certificate!(
          app,
          malformed_material(),
          %{id: @certificate_id_3, canonical_fingerprint: nil}
        )

      assert {:error,
              %{
                code: :malformed_pem,
                identifier: "certificate:" <> malformed_id,
                certificate_id: malformed_id
              }} =
               AppCertificatePreflight.backfill_canonical_fingerprints(batch_size: 2)

      assert malformed_id == malformed.id

      assert Enum.all?([valid_1, valid_2, malformed], fn certificate ->
               is_nil(Repo.get!(Certificate, certificate.id).canonical_fingerprint)
             end)
    end

    test "aborts a same-batch computed collision without writing either row" do
      app = register_app!()
      duplicate_material = app_certificate_material(app.id)

      duplicate_1 =
        insert_app_certificate!(
          app,
          duplicate_material,
          %{id: @certificate_id_1, canonical_fingerprint: nil}
        )

      duplicate_2 =
        insert_app_certificate!(
          app,
          duplicate_material,
          %{id: @certificate_id_2, canonical_fingerprint: nil}
        )

      assert {:error,
              %{
                code: :canonical_fingerprint_collision,
                identifier: "certificate:" <> collision_id,
                certificate_id: collision_id
              }} =
               AppCertificatePreflight.backfill_canonical_fingerprints(batch_size: 10)

      assert collision_id in [duplicate_1.id, duplicate_2.id]
      assert Repo.get!(Certificate, duplicate_1.id).canonical_fingerprint == nil
      assert Repo.get!(Certificate, duplicate_2.id).canonical_fingerprint == nil
    end

    test "aborts when a pending row collides with an existing canonical fingerprint" do
      app = register_app!()
      duplicate_material = app_certificate_material(app.id)

      existing = insert_app_certificate!(app, duplicate_material)

      pending =
        insert_app_certificate!(
          app,
          duplicate_material,
          %{canonical_fingerprint: nil}
        )

      assert {:error,
              %{
                code: :canonical_fingerprint_collision,
                identifier: "certificate:" <> pending_id,
                certificate_id: pending_id
              }} =
               AppCertificatePreflight.backfill_canonical_fingerprints(batch_size: 10)

      assert pending_id in [existing.id, pending.id]

      assert Repo.get!(Certificate, existing.id).canonical_fingerprint ==
               duplicate_material.canonical_fingerprint

      assert Repo.get!(Certificate, pending.id).canonical_fingerprint == nil
    end

    test "locks each backfill batch with FOR UPDATE and does not skip locked rows" do
      app = register_app!()

      insert_app_certificate!(
        app,
        app_certificate_material(app.id),
        %{canonical_fingerprint: nil}
      )

      handler_id = {__MODULE__, self(), :backfill_queries}

      :ok =
        :telemetry.attach(
          handler_id,
          [:secret_hub, :core, :repo, :query],
          fn _event, _measurements, metadata, test_pid ->
            send(test_pid, {:preflight_repo_query, metadata.query})
          end,
          self()
        )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      assert {:ok, 1} =
               AppCertificatePreflight.backfill_canonical_fingerprints(batch_size: 1)

      locking_queries =
        drain_repo_queries()
        |> Enum.map(&String.upcase/1)
        |> Enum.filter(&String.contains?(&1, "FOR UPDATE"))

      assert [_ | _] = locking_queries
      assert Enum.all?(locking_queries, &(not String.contains?(&1, "SKIP LOCKED")))
    end

    test "does not create or rewrite audit-chain evidence" do
      app = register_app!()

      insert_app_certificate!(
        app,
        app_certificate_material(app.id),
        %{canonical_fingerprint: nil}
      )

      before = Repo.all(from(log in AuditLog, order_by: [asc: log.id]))

      assert {:ok, 1} =
               AppCertificatePreflight.backfill_canonical_fingerprints(batch_size: 1)

      assert Repo.all(from(log in AuditLog, order_by: [asc: log.id])) == before
    end
  end

  defp register_app! do
    suffix = System.unique_integer([:positive])

    {:ok, agent} =
      Agents.register_agent(%{
        agent_id: "preflight-agent-#{suffix}",
        name: "Preflight Agent #{suffix}",
        auth_method: "approle"
      })

    {:ok, %{app: app}} =
      Apps.register_app(%{
        name: "preflight-app-#{suffix}",
        agent_id: agent.id
      })

    app
  end

  defp app_certificate_material(app_id, opts \\ []) do
    now = now()
    valid_from = Keyword.get(opts, :valid_from, DateTime.add(now, -60, :second))
    valid_until = Keyword.get(opts, :valid_until, DateTime.add(now, 3_600, :second))
    common_name = Keyword.get(opts, :common_name, app_id)
    organization = Keyword.get(opts, :organization, "SecretHub Applications")

    subject_alt_name =
      case Keyword.get(opts, :uri_san, "urn:secrethub:app:#{app_id}") do
        false ->
          false

        uri ->
          Extension.subject_alt_name([
            {:uniformResourceIdentifier, to_charlist(uri)}
          ])
      end

    ext_key_usage =
      if Keyword.get(opts, :client_auth?, true),
        do: Extension.ext_key_usage([:clientAuth]),
        else: false

    private_key = X509.PrivateKey.new_rsa(2048)

    certificate =
      X509Certificate.self_signed(
        private_key,
        "/O=#{organization}/CN=#{common_name}",
        validity: Validity.new(valid_from, valid_until),
        extensions: [
          subject_alt_name: subject_alt_name,
          ext_key_usage: ext_key_usage
        ]
      )

    pem = X509Certificate.to_pem(certificate)
    {:ok, canonical_fingerprint} = CertificateIdentity.canonical_fingerprint_from_pem(pem)

    %{
      pem: pem,
      canonical_fingerprint: canonical_fingerprint,
      common_name: common_name,
      organization: organization,
      valid_from: valid_from,
      valid_until: valid_until
    }
  end

  defp malformed_material do
    now = now()

    %{
      pem: "-----BEGIN CERTIFICATE-----\nmalformed certificate body\n-----END CERTIFICATE-----",
      canonical_fingerprint: canonical_hex("malformed-material"),
      common_name: Ecto.UUID.generate(),
      organization: "SecretHub Applications",
      valid_from: DateTime.add(now, -60, :second),
      valid_until: DateTime.add(now, 3_600, :second)
    }
  end

  defp insert_app_certificate!(
         app,
         material,
         certificate_overrides \\ %{},
         association_overrides \\ %{}
       ) do
    certificate =
      insert_certificate!(
        material,
        Map.merge(
          %{
            entity_id: app.id,
            entity_type: "app"
          },
          certificate_overrides
        )
      )

    association_attrs =
      Map.merge(
        %{
          app_id: app.id,
          certificate_id: certificate.id,
          issued_at: material.valid_from,
          expires_at: material.valid_until
        },
        association_overrides
      )

    %AppCertificate{}
    |> AppCertificate.changeset(association_attrs)
    |> Repo.insert!()

    certificate
  end

  defp insert_certificate!(material, overrides) do
    suffix = System.unique_integer([:positive])
    {id, overrides} = Map.pop(overrides, :id)

    attrs =
      Map.merge(
        %{
          serial_number: "serial-#{suffix}",
          fingerprint: "legacy-#{suffix}",
          canonical_fingerprint: material.canonical_fingerprint,
          certificate_pem: material.pem,
          subject: "CN=#{material.common_name},O=#{material.organization}",
          issuer: "preflight-test-issuer",
          common_name: material.common_name,
          organization: material.organization,
          valid_from: material.valid_from,
          valid_until: material.valid_until,
          cert_type: :app_client,
          revoked: false
        },
        overrides
      )

    %Certificate{id: id}
    |> Certificate.changeset(attrs)
    |> Repo.insert!()
  end

  defp insert_orphan_application!(application_id, missing_agent_id) do
    try do
      Repo.query!("ALTER TABLE applications DISABLE TRIGGER ALL")

      Repo.query!(
        """
        INSERT INTO applications (
          id,
          name,
          agent_id,
          status,
          policies,
          metadata,
          inserted_at,
          updated_at
        )
        VALUES (
          $1::uuid,
          $2,
          $3::uuid,
          'active',
          ARRAY[]::varchar[],
          '{}'::jsonb,
          NOW(),
          NOW()
        )
        """,
        [
          Ecto.UUID.dump!(application_id),
          "orphan-preflight-#{System.unique_integer([:positive])}",
          Ecto.UUID.dump!(missing_agent_id)
        ]
      )
    after
      Repo.query!("ALTER TABLE applications ENABLE TRIGGER ALL")
    end

    Repo.get!(Application, application_id)
  end

  defp codes_for(findings, certificate_id) do
    findings
    |> Enum.filter(&(&1[:certificate_id] == certificate_id))
    |> Enum.map(& &1.code)
  end

  defp drain_repo_queries(acc \\ []) do
    receive do
      {:preflight_repo_query, query} -> drain_repo_queries([query | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp canonical_hex(value) do
    :crypto.hash(:sha256, value)
    |> Base.encode16(case: :lower)
  end

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)
end
