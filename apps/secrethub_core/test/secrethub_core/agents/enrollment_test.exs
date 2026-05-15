defmodule SecretHub.Core.Agents.EnrollmentTest do
  use SecretHub.Core.DataCase, async: true

  alias SecretHub.Core.Agents.Enrollment
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Agent, AgentEnrollment}

  @pending_attrs %{
    hostname: "build-01",
    fqdn: "build-01.internal.example",
    machine_id: "machine-123",
    os: "linux",
    arch: "x86_64",
    agent_version: "1.2.3",
    ssh_host_key_algorithm: "rsa",
    ssh_host_key_fingerprint: "SHA256:host-key-fingerprint",
    capabilities: %{"templates" => true}
  }

  describe "create_pending/2" do
    test "stores a hashed pending token and returns the plaintext token once" do
      assert {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
               Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      assert enrollment.status == :pending_registered
      assert enrollment.source_ip == "203.0.113.10"
      assert is_binary(pending_token)
      assert byte_size(pending_token) >= 32
      refute enrollment.pending_token_hash == pending_token
      assert Enrollment.authorize(enrollment.id, pending_token) == {:ok, enrollment}
      assert {:error, :invalid_pending_token} = Enrollment.authorize(enrollment.id, "wrong")
    end
  end

  describe "approve/2" do
    test "assigns a Core-owned agent id and publishes required CSR fields" do
      {:ok, %{enrollment: enrollment}} = Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      assert {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
      assert approved.status == :approved_waiting_for_csr
      assert approved.approved_by == "operator-1"
      assert approved.agent_id =~ "agent-"
      assert approved.required_csr_fields["subject"]["O"] == "SecretHub Agents"
      assert approved.required_csr_fields["subject"]["CN"] == approved.agent_id

      assert "urn:secrethub:agent:#{approved.agent_id}" in approved.required_csr_fields["san"][
               "uri"
             ]

      assert %Agent{agent_id: agent_id} = Repo.get_by(Agent, agent_id: approved.agent_id)
      assert agent_id == approved.agent_id
    end
  end

  describe "status and finalization" do
    test "rejects status reads for expired or invalid pending tokens" do
      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      assert {:ok, %{status: :pending_registered}} =
               Enrollment.status(enrollment.id, pending_token)

      assert {:error, :invalid_pending_token} = Enrollment.status(enrollment.id, "wrong")

      expired =
        enrollment
        |> Ecto.Changeset.change(expires_at: DateTime.add(DateTime.utc_now(), -60, :second))
        |> Repo.update!()

      assert {:error, :expired} = Enrollment.status(expired.id, pending_token)
    end

    test "records trusted endpoint failures for admin review" do
      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      error = %{
        "phase" => "tls_handshake",
        "message" => "unknown ca",
        "endpoint" => "wss://core-agent.example.com/agent/socket/websocket"
      }

      assert {:ok, finalized} =
               Enrollment.finalize(enrollment.id, pending_token, %{
                 "status" => "trusted_endpoint_failed",
                 "error" => error
               })

      assert finalized.status == :trusted_endpoint_failed
      assert finalized.last_error == error
    end
  end

  describe "submit_csr/3" do
    test "marks invalid CSR submissions as csr_invalid" do
      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")

      assert {:error, :csr_invalid} =
               Enrollment.submit_csr(approved.id, pending_token, "not a csr")

      assert %AgentEnrollment{status: :csr_invalid, last_error: %{"reason" => reason}} =
               Repo.get!(AgentEnrollment, approved.id)

      assert reason =~ "CSR"
    end
  end
end
