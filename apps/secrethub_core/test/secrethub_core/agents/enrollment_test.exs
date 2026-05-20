defmodule SecretHub.Core.Agents.EnrollmentTest do
  use SecretHub.Core.DataCase, async: true

  alias SecretHub.Core.Agents.Enrollment
  alias SecretHub.Core.PKI.Verifier
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.{Agent, AgentEnrollment, Certificate}

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
      generate_active_ca!()

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

    test "requires an active CA before approval creates an agent" do
      Repo.delete_all(Certificate)

      {:ok, %{enrollment: enrollment}} = Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      assert {:error, :no_active_ca} = Enrollment.approve(enrollment.id, "operator-1")
      assert Repo.get!(AgentEnrollment, enrollment.id).status == :pending_registered
      refute Repo.get_by(Agent, ssh_host_key_fingerprint: @pending_attrs.ssh_host_key_fingerprint)
    end

    test "requires usable active CA signing material before approval creates an agent" do
      insert_active_ca!()

      {:ok, %{enrollment: enrollment}} = Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      assert {:error, :ca_private_key_unavailable} =
               Enrollment.approve(enrollment.id, "operator-1")

      assert Repo.get!(AgentEnrollment, enrollment.id).status == :pending_registered
      refute Repo.get_by(Agent, ssh_host_key_fingerprint: @pending_attrs.ssh_host_key_fingerprint)
    end
  end

  describe "status and finalization" do
    test "status polling refreshes pending agent presence" do
      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      stale_time =
        DateTime.utc_now()
        |> DateTime.add(-60, :second)
        |> DateTime.truncate(:second)

      enrollment
      |> Ecto.Changeset.change(updated_at: stale_time)
      |> Repo.update!()

      assert {:ok, %{status: :pending_registered}} =
               Enrollment.status(enrollment.id, pending_token)

      refreshed = Repo.get!(AgentEnrollment, enrollment.id)
      assert DateTime.compare(refreshed.updated_at, stale_time) == :gt
    end

    test "list_pending removes pending enrollments whose agent stopped polling" do
      {:ok, %{enrollment: enrollment}} = Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      stale_time =
        DateTime.utc_now()
        |> DateTime.add(-60, :second)
        |> DateTime.truncate(:second)

      enrollment
      |> Ecto.Changeset.change(updated_at: stale_time)
      |> Repo.update!()

      assert [] = Enrollment.list_pending(stale_after_ms: 1_000)
      refute Repo.get(AgentEnrollment, enrollment.id)
    end

    test "approved enrollments leave the pending agents list" do
      generate_active_ca!()

      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      assert Enum.any?(Enrollment.list_pending(), &(&1.id == enrollment.id))

      assert {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
      assert approved.status == :approved_waiting_for_csr

      refute Enum.any?(Enrollment.list_pending(), &(&1.id == enrollment.id))

      approved
      |> Ecto.Changeset.change(
        updated_at: DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)
      )
      |> Repo.update!()

      refute Enum.any?(Enrollment.list_pending(stale_after_ms: 1_000), &(&1.id == enrollment.id))
      assert Repo.get(AgentEnrollment, enrollment.id)

      assert {:ok, %{status: :approved_waiting_for_csr}} =
               Enrollment.status(enrollment.id, pending_token)
    end

    test "rejects status reads for expired or invalid pending tokens" do
      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      assert {:ok, %{status: :pending_registered}} =
               Enrollment.status(enrollment.id, pending_token)

      assert {:error, :invalid_pending_token} = Enrollment.status(enrollment.id, "wrong")

      expired =
        enrollment
        |> Ecto.Changeset.change(
          expires_at:
            DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)
        )
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
      generate_active_ca!()

      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")

      assert {:error, :csr_invalid} =
               Enrollment.submit_csr(approved.id, pending_token, "not a csr")

      assert %AgentEnrollment{status: :csr_invalid, last_error: %{"reason" => reason}} =
               Repo.get!(AgentEnrollment, approved.id)

      assert reason =~ "CSR"
    end

    test "issues a certificate and binds it to the agent after approval" do
      private_key = :public_key.generate_key({:rsa, 2048, 65_537})
      {:RSAPrivateKey, :"two-prime", modulus, exponent, _, _, _, _, _, _, _} = private_key
      fingerprint = rsa_fingerprint(modulus, exponent)

      {:ok, %{cert_record: ca}} =
        SecretHub.Core.PKI.CA.generate_root_ca(
          "Agent Enrollment Test Root CA",
          "SecretHub Test",
          key_size: 2048
        )

      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        @pending_attrs
        |> Map.put(:machine_id, "auto-ca-#{System.unique_integer([:positive])}")
        |> Map.put(:ssh_host_key_fingerprint, fingerprint)
        |> Enrollment.create_pending("203.0.113.10")

      {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
      csr = X509.CSR.new(private_key, "/O=SecretHub Agents/CN=#{approved.agent_id}")

      assert {:ok, %{certificate: certificate, enrollment: issued}} =
               Enrollment.submit_csr(approved.id, pending_token, X509.CSR.to_pem(csr))

      assert issued.status == :certificate_issued
      assert certificate.cert_type == :agent_client

      assert %Agent{status: :certificate_issued, certificate_id: certificate_id} =
               Repo.get_by!(Agent, agent_id: approved.agent_id)

      assert certificate_id == certificate.id

      [{:Certificate, cert_der, :not_encrypted}] =
        :public_key.pem_decode(certificate.certificate_pem)

      assert {:ok, %{agent_id: agent_id}} = Verifier.verify_agent_certificate(cert_der)
      assert agent_id == approved.agent_id
      assert certificate.issuer_id == ca.id
    end
  end

  defp insert_active_ca! do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    suffix = System.unique_integer([:positive])

    %Certificate{}
    |> Certificate.changeset(%{
      serial_number: "test-ca-serial-#{suffix}",
      fingerprint: "test-ca-fingerprint-#{suffix}",
      certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
      subject: "CN=Test Root CA,O=SecretHub Test",
      issuer: "CN=Test Root CA,O=SecretHub Test",
      common_name: "Test Root CA",
      organization: "SecretHub Test",
      valid_from: now,
      valid_until: DateTime.add(now, 3600, :second),
      cert_type: :root_ca,
      revoked: false
    })
    |> Repo.insert!()
  end

  defp generate_active_ca! do
    {:ok, %{cert_record: cert}} =
      SecretHub.Core.PKI.CA.generate_root_ca(
        "Agent Enrollment Test Root CA #{System.unique_integer([:positive])}",
        "SecretHub Test",
        key_size: 2048
      )

    cert
  end

  defp rsa_fingerprint(modulus, exponent) do
    (("ssh-rsa" |> ssh_string()) <> ssh_mpint(exponent) <> ssh_mpint(modulus))
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode64(padding: false)
    |> then(&"SHA256:#{&1}")
  end

  defp ssh_string(value), do: <<byte_size(value)::32, value::binary>>

  defp ssh_mpint(integer) do
    bytes = :binary.encode_unsigned(integer)
    bytes = if match?(<<1::1, _::bitstring>>, bytes), do: <<0, bytes::binary>>, else: bytes
    <<byte_size(bytes)::32, bytes::binary>>
  end
end
