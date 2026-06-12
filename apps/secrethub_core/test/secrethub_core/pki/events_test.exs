defmodule SecretHub.Core.PKI.EventsTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.PKI.Events
  alias SecretHub.Core.PKI.CA
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Certificate, PKIEvent}

  describe "append/3" do
    test "stores immutable events with per-CA sequences" do
      ca_id = "ca:test-root"

      assert {:ok, first} =
               Events.append(
                 :ca_initialized,
                 %{subject: "/CN=SecretHub Root CA", serial: "100"},
                 ca_id: ca_id,
                 actor: "admin@example.test",
                 timestamp: ~U[2026-06-12 01:00:00Z]
               )

      assert {:ok, second} =
               Events.append(
                 :certificate_issued,
                 %{serial: "101", subject: "/CN=agent-1"},
                 ca_id: ca_id,
                 correlation_id: "request-1",
                 timestamp: ~U[2026-06-12 01:01:00Z]
               )

      assert "event:" <> _ = first.id
      assert first.sequence == 1
      assert second.sequence == 2
      assert second.correlation_id == "request-1"

      assert {:ok, [^first, ^second]} = Events.query_by_ca(ca_id)
    end
  end

  describe "queries" do
    test "finds events by type and certificate serial" do
      ca_id = "ca:test-query"

      {:ok, issued} =
        Events.append(
          :certificate_issued,
          %{serial: "200", subject: "/CN=query-agent"},
          ca_id: ca_id,
          timestamp: ~U[2026-06-12 01:00:00Z]
        )

      {:ok, revoked} =
        Events.append(
          :certificate_revoked,
          %{serial: "200", reason: "keyCompromise", revocation_date: "2026-06-12T01:05:00Z"},
          ca_id: ca_id,
          timestamp: ~U[2026-06-12 01:05:00Z]
        )

      assert {:ok, [^issued]} = Events.query_by_type(:certificate_issued)
      assert {:ok, [^issued, ^revoked]} = Events.query_by_serial("200")
    end
  end

  describe "certificate state replay" do
    test "marks revoked certificates and returns revocation entries" do
      ca_id = "ca:test-state"

      {:ok, _issued} =
        Events.append(
          :certificate_issued,
          %{
            serial: "300",
            subject: "/CN=state-agent",
            not_before: "2026-06-12T01:00:00Z",
            not_after: "2026-07-12T01:00:00Z"
          },
          ca_id: ca_id,
          timestamp: ~U[2026-06-12 01:00:00Z]
        )

      {:ok, _revoked} =
        Events.append(
          :certificate_revoked,
          %{
            serial: "300",
            reason: "cessationOfOperation",
            revocation_date: "2026-06-13T01:00:00Z"
          },
          ca_id: ca_id,
          timestamp: ~U[2026-06-13 01:00:00Z]
        )

      assert {:ok, %{status: :revoked, serial: "300", revocation_reason: :cessationOfOperation}} =
               Events.get_certificate_state("300")

      assert {:ok, [%{serial: "300", reason: :cessationOfOperation}]} =
               Events.get_revocations(ca_id)
    end
  end

  describe "CA lifecycle integration" do
    test "revoking a certificate appends a revocation event" do
      certificate =
        %Certificate{}
        |> Certificate.changeset(%{
          serial_number: "400",
          fingerprint: "sha256:40",
          certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
          subject: "CN=agent-400,O=SecretHub",
          issuer: "CN=SecretHub Root CA,O=SecretHub",
          common_name: "agent-400",
          organization: "SecretHub",
          valid_from: ~U[2026-06-12 01:00:00Z],
          valid_until: ~U[2026-07-12 01:00:00Z],
          cert_type: :agent_client
        })
        |> Repo.insert!()

      assert {:ok, revoked} = CA.revoke_certificate(certificate.id, "keyCompromise")
      assert revoked.revoked

      assert {:ok, [%{event_type: :certificate_revoked, metadata: metadata}]} =
               Events.query_by_serial("400")

      assert metadata.reason == "keyCompromise"
      assert metadata.cert_id == certificate.id
    end
  end

  describe "PKIEvent changeset" do
    test "requires valid event type and positive sequence" do
      changeset =
        PKIEvent.changeset(%PKIEvent{}, %{
          id: "event:invalid",
          event_type: :certificate_issued,
          timestamp: ~U[2026-06-12 01:00:00Z],
          sequence: 0,
          ca_id: "ca:test"
        })

      refute changeset.valid?
      assert %{sequence: ["must be greater than 0"]} = errors_on(changeset)
    end
  end
end
