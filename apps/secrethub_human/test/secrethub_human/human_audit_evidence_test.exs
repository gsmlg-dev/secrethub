defmodule SecretHub.Human.HumanAuditEvidenceTest do
  use ExUnit.Case, async: true

  alias SecretHub.Shared.HumanAuditEvidence
  alias SecretHub.Shared.Schemas.AuditLog

  test "accepts bounded identifiers but rejects secret-shaped and unknown metadata" do
    user_id = Ecto.UUID.generate()

    assert {:ok, %{"user_id" => ^user_id}} =
             HumanAuditEvidence.validate("human.login.succeeded", %{user_id: user_id})

    assert {:error, :invalid_evidence} =
             HumanAuditEvidence.validate("human.login.failed", %{password: "never-record-this"})

    assert {:error, :invalid_evidence} =
             HumanAuditEvidence.validate("human.login.failed", %{reason: "secret-in-reason"})

    assert {:error, :invalid_evidence} =
             HumanAuditEvidence.validate("human.login.failed", %{user_id: %{token: "hidden"}})
  end

  test "Human audit requires version 2 with validated canonical evidence" do
    attrs = %{
      event_id: Ecto.UUID.generate(),
      sequence_number: 1,
      timestamp: DateTime.utc_now(),
      event_type: "human.login.failed",
      hash_version: 2,
      event_data: %{reason: "invalid_credentials"}
    }

    assert AuditLog.changeset(%AuditLog{}, attrs).valid?
    refute AuditLog.changeset(%AuditLog{}, %{attrs | hash_version: 1}).valid?
    refute AuditLog.changeset(%AuditLog{}, %{attrs | event_data: %{password: "secret"}}).valid?
  end
end
