defmodule SecretHub.Core.Agents.EnrollmentTest do
  use SecretHub.Core.DataCase, async: false

  alias SecretHub.Core.Agents.{ConnectionManager, Enrollment}
  alias SecretHub.Core.PKI.{CSR, Issuer, Verifier}
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Crypto.AgentCSRProof
  alias SecretHub.Shared.Schemas.{Agent, AgentEnrollment, Certificate}

  @ssh_host_public_key "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzfBY98CsoKIQiaRg4dDON+o4mkz3vtNSslq+drKM97GAhSvE1+pjp4Iy1udn/tEsRiqzeOqgVG0vTTrKhH0Hn4eUB5NO1KeENUwSFafIgbeYzK5P1rWY65IyccP6nfGzslQALVTVPLMQ9P0vzbCjGqBbIvHxARvq78sp2Pxa92PHFuPkzgfhus7IXMsgJpd5bBhdjSlRxSFqUt21x4dtmwNpxdfL93Up6LWPmtItCz2whuZMabr2FbMcWCZS6b07sOBa1oqIjwUihHwGxP45r/BV6q6jtvMJAsE1QIAOxXDlhqosqhWJwGuhdwani/IlhNT2ruXObjeA8t14nirnz"
  @ssh_host_key_fingerprint "SHA256:msje3DyBcXxXmuF1TilCDOvsvGvnuZdHQ5YSS8BVoz4"

  @pending_attrs %{
    hostname: "build-01",
    fqdn: "build-01.internal.example",
    machine_id: "machine-123",
    os: "linux",
    arch: "x86_64",
    agent_version: "1.2.3",
    ssh_host_key_algorithm: "rsa",
    ssh_host_key_fingerprint: @ssh_host_key_fingerprint,
    ssh_host_public_key: @ssh_host_public_key,
    capabilities: %{"templates" => true}
  }

  setup do
    original_ttl = Application.get_env(:secrethub_core, :agent_certificate_ttl_seconds)
    original_max_ttl = Application.get_env(:secrethub_core, :agent_certificate_max_ttl_seconds)

    on_exit(fn ->
      restore_env(:agent_certificate_ttl_seconds, original_ttl)
      restore_env(:agent_certificate_max_ttl_seconds, original_max_ttl)
    end)

    :ok
  end

  describe "create_pending/2" do
    test "stores a hashed pending token and returns the plaintext token once" do
      assert {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
               Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      assert enrollment.status == :pending_registered
      assert enrollment.source_ip == "203.0.113.10"
      assert Map.fetch!(enrollment, :ssh_host_public_key) == @ssh_host_public_key
      assert is_binary(pending_token)
      assert byte_size(pending_token) >= 32
      refute enrollment.pending_token_hash == pending_token
      assert Enrollment.authorize(enrollment.id, pending_token) == {:ok, enrollment}
      assert {:error, :invalid_pending_token} = Enrollment.authorize(enrollment.id, "wrong")
    end

    test "requires the OpenSSH host public key" do
      attrs = Map.delete(@pending_attrs, :ssh_host_public_key)

      assert {:error, changeset} = Enrollment.create_pending(attrs, "203.0.113.10")
      assert %{ssh_host_public_key: ["can't be blank"]} = errors_on(changeset)
    end

    test "stores normalized OpenSSH host public key text" do
      attrs = Map.put(@pending_attrs, :ssh_host_public_key, "  #{@ssh_host_public_key}\n")

      assert {:ok, %{enrollment: enrollment}} = Enrollment.create_pending(attrs, "203.0.113.10")
      assert enrollment.ssh_host_public_key == @ssh_host_public_key
    end

    test "rejects a public key whose fingerprint does not match the claimed fingerprint" do
      attrs = Map.put(@pending_attrs, :ssh_host_key_fingerprint, "SHA256:wrong")

      assert {:error, changeset} = Enrollment.create_pending(attrs, "203.0.113.10")

      assert %{ssh_host_public_key: ["does not match ssh_host_key_fingerprint"]} =
               errors_on(changeset)
    end

    test "rejects public key text with unsafe or invalid encoding" do
      oversized_key = String.duplicate("a", 16_385)

      invalid_attrs = [
        Map.put(@pending_attrs, :ssh_host_public_key, @ssh_host_public_key <> <<0>>),
        Map.put(@pending_attrs, :ssh_host_public_key, @ssh_host_public_key <> "\nssh-rsa AAAA"),
        Map.put(@pending_attrs, :ssh_host_public_key, oversized_key),
        Map.put(@pending_attrs, :ssh_host_public_key, "not an openssh public key")
      ]

      for attrs <- invalid_attrs do
        assert {:error, changeset} = Enrollment.create_pending(attrs, "203.0.113.10")
        assert %{ssh_host_public_key: [_message]} = errors_on(changeset)
      end
    end

    test "rejects a public key whose algorithm does not match the claimed algorithm" do
      attrs = Map.put(@pending_attrs, :ssh_host_key_algorithm, "ecdsa")

      assert {:error, changeset} = Enrollment.create_pending(attrs, "203.0.113.10")

      assert %{ssh_host_public_key: ["does not match ssh_host_key_algorithm"]} =
               errors_on(changeset)
    end

    @tag :tmp_dir
    test "rejects Ed25519 public keys even with claimed ecdsa algorithm and matching fingerprint",
         %{
           tmp_dir: tmp_dir
         } do
      public_key_text = generate_public_key!(tmp_dir, "ssh_host_ed25519_key", "ed25519")
      [{public_key, _attrs}] = :ssh_file.decode(public_key_text, :public_key)

      attrs =
        @pending_attrs
        |> Map.put(:ssh_host_key_algorithm, "ecdsa")
        |> Map.put(:ssh_host_key_fingerprint, CSR.ssh_fingerprint(public_key))
        |> Map.put(:ssh_host_public_key, public_key_text)

      assert {:error, changeset} = Enrollment.create_pending(attrs, "203.0.113.10")
      assert %{ssh_host_public_key: [_message]} = errors_on(changeset)
    end
  end

  describe "approve/2" do
    test "assigns a Core-owned agent id and publishes required CSR fields" do
      generate_active_ca!()

      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      assert {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
      assert approved.status == :approved_waiting_for_csr
      assert approved.approved_by == "operator-1"
      assert approved.agent_id =~ "agent-"
      assert approved.required_csr_fields["subject"]["O"] == "SecretHub Agents"
      assert approved.required_csr_fields["subject"]["CN"] == approved.agent_id
      assert is_binary(approved.required_csr_fields["challenge"])

      assert "urn:secrethub:agent:#{approved.agent_id}" in approved.required_csr_fields["san"][
               "uri"
             ]

      assert "urn:secrethub:hostkey-sha256:msje3DyBcXxXmuF1TilCDOvsvGvnuZdHQ5YSS8BVoz4" in approved.required_csr_fields[
               "san"
             ]["uri"]

      refute "urn:secrethub:ssh-hostkey-sha256:msje3DyBcXxXmuF1TilCDOvsvGvnuZdHQ5YSS8BVoz4" in approved.required_csr_fields[
               "san"
             ]["uri"]

      assert approved.required_csr_fields["validity"]["ttl_seconds"] == 30 * 24 * 60 * 60

      assert {:ok, %{required_csr_fields: required_csr_fields}} =
               Enrollment.status(enrollment.id, pending_token)

      assert required_csr_fields["challenge"] == approved.required_csr_fields["challenge"]

      assert %Agent{agent_id: agent_id} = Repo.get_by(Agent, agent_id: approved.agent_id)
      assert agent_id == approved.agent_id

      assert Map.fetch!(Repo.get_by!(Agent, agent_id: approved.agent_id), :ssh_host_public_key) ==
               @ssh_host_public_key
    end

    test "updates a reused agent with the enrollment public key" do
      generate_active_ca!()

      {:ok, existing_agent} =
        %Agent{}
        |> Agent.changeset(%{
          agent_id: "agent-existing",
          name: "existing",
          status: :pending_registered,
          ssh_host_key_algorithm: @pending_attrs.ssh_host_key_algorithm,
          ssh_host_key_fingerprint: @pending_attrs.ssh_host_key_fingerprint
        })
        |> Repo.insert()

      {:ok, %{enrollment: enrollment}} = Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      assert {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
      assert approved.agent_id == existing_agent.agent_id

      assert Map.fetch!(Repo.get!(Agent, existing_agent.id), :ssh_host_public_key) ==
               @ssh_host_public_key
    end

    test "updates reused active agent public key without running unrelated agent validations" do
      generate_active_ca!()

      {:ok, existing_agent} =
        %Agent{}
        |> Ecto.Changeset.change(%{
          agent_id: "agent-broad-validation-would-fail",
          name: "existing",
          status: :active,
          ssh_host_key_algorithm: @pending_attrs.ssh_host_key_algorithm,
          ssh_host_key_fingerprint: @pending_attrs.ssh_host_key_fingerprint
        })
        |> Repo.insert()

      {:ok, %{enrollment: enrollment}} = Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      assert {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
      assert approved.agent_id == existing_agent.agent_id

      assert Map.fetch!(Repo.get!(Agent, existing_agent.id), :ssh_host_public_key) ==
               @ssh_host_public_key
    end

    test "rejects approval when the host key belongs to a revoked or suspended agent" do
      generate_active_ca!()

      for status <- [:revoked, :suspended] do
        ssh_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
        ssh_public_key = public_key_from_private_key(ssh_private_key)
        fingerprint = CSR.ssh_fingerprint(ssh_public_key)
        public_key = openssh_public_key(ssh_public_key)

        {:ok, existing_agent} =
          %Agent{}
          |> Ecto.Changeset.change(%{
            agent_id: "agent-#{status}-#{System.unique_integer([:positive])}",
            name: "existing #{status}",
            status: status,
            ssh_host_key_algorithm: "rsa",
            ssh_host_key_fingerprint: fingerprint,
            ssh_host_public_key: public_key
          })
          |> Repo.insert()

        {:ok, %{enrollment: enrollment}} =
          @pending_attrs
          |> Map.put(:machine_id, "#{status}-reenroll-#{System.unique_integer([:positive])}")
          |> Map.put(:ssh_host_key_fingerprint, fingerprint)
          |> Map.put(:ssh_host_public_key, public_key)
          |> Enrollment.create_pending("203.0.113.10")

        assert {:error, :agent_reenrollment_blocked} =
                 Enrollment.approve(enrollment.id, "operator-1")

        assert Repo.get!(AgentEnrollment, enrollment.id).status == :pending_registered
        assert Repo.get!(Agent, existing_agent.id).status == status
      end
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

    test "caps configured certificate TTL at the default maximum" do
      generate_active_ca!()
      Application.put_env(:secrethub_core, :agent_certificate_ttl_seconds, 120 * 24 * 60 * 60)

      {:ok, %{enrollment: enrollment}} = Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      assert {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
      assert approved.required_csr_fields["validity"]["ttl_seconds"] == 90 * 24 * 60 * 60
    end

    test "advertises sub-day certificate TTL as the one-day issued TTL" do
      generate_active_ca!()
      Application.put_env(:secrethub_core, :agent_certificate_ttl_seconds, 1)

      {:ok, %{enrollment: enrollment}} = Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      assert {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
      assert approved.required_csr_fields["validity"]["ttl_seconds"] == 24 * 60 * 60
    end

    test "advertises non-whole-day certificate TTL as the rounded-up issued TTL" do
      generate_active_ca!()
      Application.put_env(:secrethub_core, :agent_certificate_ttl_seconds, 36 * 60 * 60)

      {:ok, %{enrollment: enrollment}} = Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      assert {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
      assert approved.required_csr_fields["validity"]["ttl_seconds"] == 2 * 24 * 60 * 60
    end
  end

  describe "issuer validity policy" do
    test "defaults agent certificate validity to 30 days" do
      Application.delete_env(:secrethub_core, :agent_certificate_ttl_seconds)
      Application.delete_env(:secrethub_core, :agent_certificate_max_ttl_seconds)

      assert Issuer.validity_days() == 30
      assert Issuer.agent_certificate_ttl_seconds() == 30 * 24 * 60 * 60
    end

    test "caps configured agent certificate validity at the default 90-day maximum" do
      Application.put_env(:secrethub_core, :agent_certificate_ttl_seconds, 120 * 24 * 60 * 60)
      Application.delete_env(:secrethub_core, :agent_certificate_max_ttl_seconds)

      assert Issuer.validity_days() == 90
      assert Issuer.agent_certificate_ttl_seconds() == 90 * 24 * 60 * 60
    end

    test "rounds sub-day certificate validity up to one issued day" do
      Application.put_env(:secrethub_core, :agent_certificate_ttl_seconds, 1)
      Application.delete_env(:secrethub_core, :agent_certificate_max_ttl_seconds)

      assert Issuer.validity_days() == 1
      assert Issuer.agent_certificate_ttl_seconds() == 24 * 60 * 60
    end

    test "rounds non-whole-day certificate validity up to whole issued days" do
      Application.put_env(:secrethub_core, :agent_certificate_ttl_seconds, 36 * 60 * 60)
      Application.delete_env(:secrethub_core, :agent_certificate_max_ttl_seconds)

      assert Issuer.validity_days() == 2
      assert Issuer.agent_certificate_ttl_seconds() == 2 * 24 * 60 * 60
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

      enrollment =
        enrollment
        |> Ecto.Changeset.change(status: :connect_info_delivered)
        |> Repo.update!()

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

    test "trusted connected finalization is idempotent and terminal" do
      %{certificate: certificate, enrollment: enrollment, pending_token: pending_token} =
        issue_valid_agent_certificate!()

      agent =
        enrollment.agent_id
        |> then(&Repo.get_by!(Agent, agent_id: &1))
        |> Agent.changeset(%{status: :trusted_connected})
        |> Repo.update!()

      register_runtime_connection!(agent, certificate)

      enrollment =
        enrollment
        |> Ecto.Changeset.change(
          status: :connect_info_delivered,
          last_error: %{"reason" => "previous transient error"}
        )
        |> Repo.update!()

      assert {:ok, finalized} =
               Enrollment.finalize(enrollment.id, pending_token, %{
                 "status" => "trusted_connected"
               })

      assert finalized.status == :finalized
      assert finalized.last_error == nil

      assert {:ok, finalized_again} =
               Enrollment.finalize(enrollment.id, pending_token, %{
                 "status" => "trusted_connected"
               })

      assert finalized_again.status == :finalized

      assert {:error, :invalid_status} =
               Enrollment.finalize(enrollment.id, pending_token, %{
                 "status" => "trusted_endpoint_failed",
                 "error" => %{"message" => "late stale failure"}
               })

      assert Repo.get!(AgentEnrollment, enrollment.id).status == :finalized
    end

    test "trusted connected finalization rejects a runtime connection for a different certificate" do
      %{enrollment: enrollment, pending_token: pending_token} = issue_valid_agent_certificate!()

      agent =
        enrollment.agent_id
        |> then(&Repo.get_by!(Agent, agent_id: &1))
        |> Agent.changeset(%{status: :trusted_connected})
        |> Repo.update!()

      register_runtime_connection!(agent, %{
        id: Ecto.UUID.generate(),
        serial_number: "wrong-cert"
      })

      enrollment
      |> Ecto.Changeset.change(status: :connect_info_delivered)
      |> Repo.update!()

      assert {:error, :runtime_not_connected} =
               Enrollment.finalize(enrollment.id, pending_token, %{
                 "status" => "trusted_connected"
               })
    end

    test "trusted connected finalization requires a live runtime registry entry" do
      %{enrollment: enrollment, pending_token: pending_token} = issue_valid_agent_certificate!()

      enrollment.agent_id
      |> then(&Repo.get_by!(Agent, agent_id: &1))
      |> Agent.changeset(%{status: :trusted_connected})
      |> Repo.update!()

      enrollment
      |> Ecto.Changeset.change(status: :connect_info_delivered)
      |> Repo.update!()

      assert {:error, :runtime_not_connected} =
               Enrollment.finalize(enrollment.id, pending_token, %{
                 "status" => "trusted_connected"
               })
    end

    test "trusted connected finalization requires accepted mTLS runtime state" do
      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      agent = insert_agent!(status: :connect_info_delivered)

      enrollment
      |> Ecto.Changeset.change(agent_id: agent.agent_id, status: :connect_info_delivered)
      |> Repo.update!()

      assert {:error, :runtime_not_connected} =
               Enrollment.finalize(enrollment.id, pending_token, %{
                 "status" => "trusted_connected"
               })
    end

    test "trusted endpoint failure is terminal" do
      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      agent = insert_agent!(status: :connect_info_delivered)

      enrollment =
        enrollment
        |> Ecto.Changeset.change(agent_id: agent.agent_id, status: :connect_info_delivered)
        |> Repo.update!()

      certificate = insert_agent_certificate!(enrollment, agent)

      agent
      |> Ecto.Changeset.change(certificate_id: certificate.id)
      |> Repo.update!()

      assert {:ok, failed} =
               Enrollment.finalize(enrollment.id, pending_token, %{
                 "status" => "trusted_endpoint_failed",
                 "error" => %{"message" => "handshake failed"}
               })

      assert failed.status == :trusted_endpoint_failed
      assert Repo.get!(Agent, agent.id).status == :trusted_endpoint_failed

      assert {:error, :invalid_status} =
               Enrollment.finalize(enrollment.id, pending_token, %{
                 "status" => "trusted_connected"
               })
    end

    test "trusted endpoint failure does not downgrade an agent using a newer enrollment certificate" do
      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      agent = insert_agent!(status: :connect_info_delivered)

      enrollment =
        enrollment
        |> Ecto.Changeset.change(agent_id: agent.agent_id, status: :connect_info_delivered)
        |> Repo.update!()

      {:ok, %{enrollment: newer_enrollment}} =
        @pending_attrs
        |> Map.put(:machine_id, "newer-cert-#{System.unique_integer([:positive])}")
        |> Enrollment.create_pending("203.0.113.10")

      newer_certificate = insert_agent_certificate!(newer_enrollment, agent)

      agent
      |> Ecto.Changeset.change(certificate_id: newer_certificate.id)
      |> Repo.update!()

      assert {:ok, failed} =
               Enrollment.finalize(enrollment.id, pending_token, %{
                 "status" => "trusted_endpoint_failed",
                 "error" => %{"message" => "stale failure"}
               })

      assert failed.status == :trusted_endpoint_failed
      assert Repo.get!(Agent, agent.id).status == :connect_info_delivered
    end

    test "trusted endpoint failure does not downgrade a revoked agent" do
      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      agent = insert_agent!(status: :connect_info_delivered)

      enrollment =
        enrollment
        |> Ecto.Changeset.change(agent_id: agent.agent_id, status: :connect_info_delivered)
        |> Repo.update!()

      agent
      |> Ecto.Changeset.change(status: :revoked)
      |> Repo.update!()

      assert {:ok, failed} =
               Enrollment.finalize(enrollment.id, pending_token, %{
                 "status" => "trusted_endpoint_failed",
                 "error" => %{"message" => "handshake failed"}
               })

      assert failed.status == :trusted_endpoint_failed
      assert Repo.get!(Agent, agent.id).status == :revoked
    end

    test "trusted endpoint failure finalization is idempotent" do
      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      enrollment =
        enrollment
        |> Ecto.Changeset.change(status: :connect_info_delivered)
        |> Repo.update!()

      error = %{"message" => "handshake failed"}

      assert {:ok, failed} =
               Enrollment.finalize(enrollment.id, pending_token, %{
                 "status" => "trusted_endpoint_failed",
                 "error" => error
               })

      assert failed.status == :trusted_endpoint_failed
      assert failed.last_error == error

      late_error = %{"message" => "late retry after lost response"}

      assert {:ok, failed_again} =
               Enrollment.finalize(enrollment.id, pending_token, %{
                 "status" => "trusted_endpoint_failed",
                 "error" => late_error
               })

      assert failed_again.status == :trusted_endpoint_failed
      assert failed_again.last_error == error
    end
  end

  describe "submit_csr/3" do
    test "marks invalid CSR submissions as csr_invalid" do
      generate_active_ca!()
      ssh_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
      ssh_public_key = public_key_from_private_key(ssh_private_key)
      fingerprint = CSR.ssh_fingerprint(ssh_public_key)

      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        @pending_attrs
        |> Map.put(:machine_id, "invalid-csr-#{System.unique_integer([:positive])}")
        |> Map.put(:ssh_host_key_fingerprint, fingerprint)
        |> Map.put(:ssh_host_public_key, openssh_public_key(ssh_public_key))
        |> Enrollment.create_pending("203.0.113.10")

      {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
      csr_pem = "not a csr"

      proof =
        AgentCSRProof.sign(ssh_private_key, %{
          enrollment_id: approved.id,
          challenge: approved.required_csr_fields["challenge"],
          csr_pem: csr_pem
        })

      assert {:error, :csr_invalid} =
               Enrollment.submit_csr(approved.id, pending_token, %{
                 "csr_pem" => csr_pem,
                 "ssh_proof" => proof
               })

      assert %AgentEnrollment{status: :csr_invalid, last_error: %{"reason" => reason}} =
               Repo.get!(AgentEnrollment, approved.id)

      assert reason =~ "CSR"
    end

    test "returns missing_proof without marking the enrollment csr_invalid" do
      generate_active_ca!()
      tls_private_key = :public_key.generate_key({:rsa, 2048, 65_537})

      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        Enrollment.create_pending(@pending_attrs, "203.0.113.10")

      {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
      csr_pem = csr_pem_for_required_fields(tls_private_key, approved.required_csr_fields)

      assert {:error, :missing_proof} =
               Enrollment.submit_csr(approved.id, pending_token, %{"csr_pem" => csr_pem})

      assert %AgentEnrollment{status: :approved_waiting_for_csr, last_error: nil} =
               Repo.get!(AgentEnrollment, approved.id)
    end

    test "issues a certificate and binds it to the agent after approval" do
      %{
        certificate: certificate,
        enrollment: issued,
        approved: approved,
        ca: ca,
        cert_der: cert_der
      } =
        issue_valid_agent_certificate!()

      assert issued.status == :certificate_issued
      assert certificate.cert_type == :agent_client

      assert %Agent{status: :certificate_issued, certificate_id: certificate_id} =
               Repo.get_by!(Agent, agent_id: approved.agent_id)

      assert certificate_id == certificate.id

      assert {:ok, %{agent_id: agent_id}} = Verifier.verify_agent_certificate(cert_der)
      assert agent_id == approved.agent_id
      assert certificate.issuer_id == ca.id
    end

    test "refuses certificate issuance if the approved agent is revoked before CSR submission" do
      generate_active_ca!()
      ssh_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
      ssh_public_key = public_key_from_private_key(ssh_private_key)
      tls_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
      fingerprint = CSR.ssh_fingerprint(ssh_public_key)

      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        @pending_attrs
        |> Map.put(:machine_id, "revoked-before-csr-#{System.unique_integer([:positive])}")
        |> Map.put(:ssh_host_key_fingerprint, fingerprint)
        |> Map.put(:ssh_host_public_key, openssh_public_key(ssh_public_key))
        |> Enrollment.create_pending("203.0.113.10")

      {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")

      approved.agent_id
      |> then(&Repo.get_by!(Agent, agent_id: &1))
      |> Ecto.Changeset.change(status: :revoked)
      |> Repo.update!()

      csr_pem = csr_pem_for_required_fields(tls_private_key, approved.required_csr_fields)

      proof =
        AgentCSRProof.sign(ssh_private_key, %{
          enrollment_id: approved.id,
          challenge: approved.required_csr_fields["challenge"],
          csr_pem: csr_pem
        })

      assert {:error, :agent_reenrollment_blocked} =
               Enrollment.submit_csr(approved.id, pending_token, %{
                 "csr_pem" => csr_pem,
                 "ssh_proof" => proof
               })

      assert Repo.get!(AgentEnrollment, approved.id).status == :approved_waiting_for_csr

      refute Repo.get_by(Certificate,
               cert_type: :agent_client,
               enrollment_id: approved.id
             )
    end

    test "refuses stale CSR from older enrollment after newer certificate is bound" do
      generate_active_ca!()
      ssh_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
      ssh_public_key = public_key_from_private_key(ssh_private_key)
      fingerprint = CSR.ssh_fingerprint(ssh_public_key)

      attrs =
        @pending_attrs
        |> Map.put(:ssh_host_key_fingerprint, fingerprint)
        |> Map.put(:ssh_host_public_key, openssh_public_key(ssh_public_key))

      {:ok, %{enrollment: older, pending_token: older_token}} =
        attrs
        |> Map.put(:machine_id, "stale-older-#{System.unique_integer([:positive])}")
        |> Enrollment.create_pending("203.0.113.10")

      {:ok, older_approved} = Enrollment.approve(older.id, "operator-1")

      {:ok, %{enrollment: newer, pending_token: newer_token}} =
        attrs
        |> Map.put(:machine_id, "stale-newer-#{System.unique_integer([:positive])}")
        |> Enrollment.create_pending("203.0.113.10")

      {:ok, newer_approved} = Enrollment.approve(newer.id, "operator-1")

      newer_tls_private_key = tls_private_key()

      newer_csr_pem =
        csr_pem_for_required_fields(newer_tls_private_key, newer_approved.required_csr_fields)

      newer_proof =
        AgentCSRProof.sign(ssh_private_key, %{
          enrollment_id: newer_approved.id,
          challenge: newer_approved.required_csr_fields["challenge"],
          csr_pem: newer_csr_pem
        })

      assert {:ok, %{certificate: newer_certificate}} =
               Enrollment.submit_csr(newer_approved.id, newer_token, %{
                 "csr_pem" => newer_csr_pem,
                 "ssh_proof" => newer_proof
               })

      assert %Agent{certificate_id: newer_certificate_id} =
               Repo.get_by!(Agent, agent_id: newer_approved.agent_id)

      assert newer_certificate_id == newer_certificate.id

      older_tls_private_key = tls_private_key()

      older_csr_pem =
        csr_pem_for_required_fields(older_tls_private_key, older_approved.required_csr_fields)

      older_proof =
        AgentCSRProof.sign(ssh_private_key, %{
          enrollment_id: older_approved.id,
          challenge: older_approved.required_csr_fields["challenge"],
          csr_pem: older_csr_pem
        })

      assert {:error, {:certificate_issue_failed, :agent_certificate_bind_conflict}} =
               Enrollment.submit_csr(older_approved.id, older_token, %{
                 "csr_pem" => older_csr_pem,
                 "ssh_proof" => older_proof
               })

      assert Repo.get_by!(Agent, agent_id: newer_approved.agent_id).certificate_id ==
               newer_certificate.id

      assert Repo.get!(AgentEnrollment, older_approved.id).status == :certificate_issue_failed

      refute Repo.get_by(Certificate,
               cert_type: :agent_client,
               enrollment_id: older_approved.id
             )
    end

    test "allows newer enrollment to replace an older certificate for the same agent" do
      generate_active_ca!()
      ssh_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
      ssh_public_key = public_key_from_private_key(ssh_private_key)
      fingerprint = CSR.ssh_fingerprint(ssh_public_key)

      attrs =
        @pending_attrs
        |> Map.put(:ssh_host_key_fingerprint, fingerprint)
        |> Map.put(:ssh_host_public_key, openssh_public_key(ssh_public_key))

      {:ok, %{enrollment: older, pending_token: older_token}} =
        attrs
        |> Map.put(:machine_id, "replace-older-#{System.unique_integer([:positive])}")
        |> Enrollment.create_pending("203.0.113.10")

      {:ok, older_approved} = Enrollment.approve(older.id, "operator-1")

      older_tls_private_key = tls_private_key()

      older_csr_pem =
        csr_pem_for_required_fields(older_tls_private_key, older_approved.required_csr_fields)

      older_proof =
        AgentCSRProof.sign(ssh_private_key, %{
          enrollment_id: older_approved.id,
          challenge: older_approved.required_csr_fields["challenge"],
          csr_pem: older_csr_pem
        })

      assert {:ok, %{certificate: older_certificate}} =
               Enrollment.submit_csr(older_approved.id, older_token, %{
                 "csr_pem" => older_csr_pem,
                 "ssh_proof" => older_proof
               })

      {:ok, %{enrollment: newer, pending_token: newer_token}} =
        attrs
        |> Map.put(:machine_id, "replace-newer-#{System.unique_integer([:positive])}")
        |> Enrollment.create_pending("203.0.113.10")

      {:ok, newer_approved} = Enrollment.approve(newer.id, "operator-1")

      newer_tls_private_key = tls_private_key()

      newer_csr_pem =
        csr_pem_for_required_fields(newer_tls_private_key, newer_approved.required_csr_fields)

      newer_proof =
        AgentCSRProof.sign(ssh_private_key, %{
          enrollment_id: newer_approved.id,
          challenge: newer_approved.required_csr_fields["challenge"],
          csr_pem: newer_csr_pem
        })

      assert {:ok, %{certificate: newer_certificate}} =
               Enrollment.submit_csr(newer_approved.id, newer_token, %{
                 "csr_pem" => newer_csr_pem,
                 "ssh_proof" => newer_proof
               })

      assert older_certificate.id != newer_certificate.id

      assert Repo.get_by!(Agent, agent_id: newer_approved.agent_id).certificate_id ==
               newer_certificate.id
    end

    test "verifier rejects issued certificates missing clientAuth metadata" do
      %{certificate: certificate, cert_der: cert_der} = issue_valid_agent_certificate!()

      certificate
      |> Ecto.Changeset.change(
        metadata: Map.delete(certificate.metadata || %{}, "extended_key_usage")
      )
      |> Repo.update!()

      assert {:error, :missing_client_auth} = Verifier.verify_agent_certificate(cert_der)
    end

    test "verifier accepts a disconnected agent so it can reconnect with its valid certificate" do
      %{approved: approved, cert_der: cert_der} = issue_valid_agent_certificate!()

      approved.agent_id
      |> then(&Repo.get_by!(Agent, agent_id: &1))
      |> Ecto.Changeset.change(status: :disconnected)
      |> Repo.update!()

      assert {:ok, %{agent_id: agent_id}} = Verifier.verify_agent_certificate(cert_der)
      assert agent_id == approved.agent_id
    end

    test "verifier rejects issued certificates missing the host-key SAN" do
      %{certificate: certificate, cert_der: cert_der} = issue_valid_agent_certificate!()

      metadata =
        update_in(certificate.metadata, ["san_uri"], fn san_uri ->
          Enum.reject(san_uri || [], &String.starts_with?(&1, "urn:secrethub:hostkey-sha256:"))
        end)

      certificate
      |> Ecto.Changeset.change(metadata: metadata)
      |> Repo.update!()

      assert {:error, :missing_host_key_san} = Verifier.verify_agent_certificate(cert_der)
    end

    test "verifier rejects certificates with the wrong stored certificate type" do
      %{certificate: certificate, cert_der: cert_der} = issue_valid_agent_certificate!()

      certificate
      |> Ecto.Changeset.change(cert_type: :app_client)
      |> Repo.update!()

      assert {:error, :invalid_certificate_type} = Verifier.verify_agent_certificate(cert_der)
    end

    test "rejects a valid CSR when the SSH proof was signed for a different CSR" do
      generate_active_ca!()
      ssh_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
      ssh_public_key = public_key_from_private_key(ssh_private_key)
      fingerprint = CSR.ssh_fingerprint(ssh_public_key)

      {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
        @pending_attrs
        |> Map.put(:machine_id, "tampered-csr-#{System.unique_integer([:positive])}")
        |> Map.put(:ssh_host_key_fingerprint, fingerprint)
        |> Map.put(:ssh_host_public_key, openssh_public_key(ssh_public_key))
        |> Enrollment.create_pending("203.0.113.10")

      {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")

      signed_csr_pem =
        csr_pem_for_required_fields(tls_private_key(), approved.required_csr_fields)

      submitted_csr_pem =
        csr_pem_for_required_fields(tls_private_key(), approved.required_csr_fields)

      proof =
        AgentCSRProof.sign(ssh_private_key, %{
          enrollment_id: approved.id,
          challenge: approved.required_csr_fields["challenge"],
          csr_pem: signed_csr_pem
        })

      assert {:error, :csr_invalid} =
               Enrollment.submit_csr(approved.id, pending_token, %{
                 "csr_pem" => submitted_csr_pem,
                 "ssh_proof" => proof
               })

      assert %AgentEnrollment{status: :csr_invalid, last_error: %{"reason" => reason}} =
               Repo.get!(AgentEnrollment, approved.id)

      assert reason =~ "invalid_signature"
    end
  end

  defp issue_valid_agent_certificate! do
    ssh_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    ssh_public_key = public_key_from_private_key(ssh_private_key)
    tls_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    fingerprint = CSR.ssh_fingerprint(ssh_public_key)

    ca = generate_active_ca!()

    {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
      @pending_attrs
      |> Map.put(:machine_id, "valid-cert-#{System.unique_integer([:positive])}")
      |> Map.put(:ssh_host_key_fingerprint, fingerprint)
      |> Map.put(:ssh_host_public_key, openssh_public_key(ssh_public_key))
      |> Enrollment.create_pending("203.0.113.10")

    {:ok, approved} = Enrollment.approve(enrollment.id, "operator-1")
    csr_pem = csr_pem_for_required_fields(tls_private_key, approved.required_csr_fields)

    proof =
      AgentCSRProof.sign(ssh_private_key, %{
        enrollment_id: approved.id,
        challenge: approved.required_csr_fields["challenge"],
        csr_pem: csr_pem
      })

    {:ok, %{certificate: certificate, enrollment: issued}} =
      Enrollment.submit_csr(approved.id, pending_token, %{
        "csr_pem" => csr_pem,
        "ssh_proof" => proof
      })

    [{:Certificate, cert_der, :not_encrypted}] =
      :public_key.pem_decode(certificate.certificate_pem)

    %{
      approved: approved,
      ca: ca,
      certificate: certificate,
      cert_der: cert_der,
      enrollment: issued,
      pending_token: pending_token
    }
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

  defp openssh_public_key(public_key) do
    [{public_key, []}]
    |> :ssh_file.encode(:openssh_key)
    |> IO.iodata_to_binary()
    |> String.trim()
  end

  defp public_key_from_private_key(private_key), do: :ssh_file.extract_public_key(private_key)

  defp tls_private_key, do: :public_key.generate_key({:rsa, 2048, 65_537})

  defp insert_agent!(attrs) do
    status = Keyword.fetch!(attrs, :status)

    %Agent{}
    |> Agent.pki_registration_changeset(%{
      agent_id: "agent-#{System.unique_integer([:positive])}",
      name: "test-agent",
      ssh_host_key_algorithm: "rsa",
      ssh_host_key_fingerprint: @ssh_host_key_fingerprint,
      ssh_host_public_key: @ssh_host_public_key,
      status: status
    })
    |> Repo.insert!()
  end

  defp insert_agent_certificate!(enrollment, agent) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    suffix = System.unique_integer([:positive])

    %Certificate{}
    |> Certificate.changeset(%{
      serial_number: "test-agent-serial-#{suffix}",
      fingerprint: "test-agent-fingerprint-#{suffix}",
      certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
      subject: "CN=#{agent.agent_id},O=SecretHub Agents",
      issuer: "CN=Test Root CA,O=SecretHub Test",
      common_name: agent.agent_id,
      organization: "SecretHub Agents",
      valid_from: now,
      valid_until: DateTime.add(now, 3600, :second),
      cert_type: :agent_client,
      enrollment_id: enrollment.id,
      entity_id: agent.agent_id,
      entity_type: "agent",
      revoked: false
    })
    |> Repo.insert!()
  end

  defp register_runtime_connection!(agent, certificate) do
    ensure_connection_manager_started!()
    certificate_id = certificate && certificate.id
    certificate_serial = (certificate && certificate.serial_number) || "test-cert"

    assert :ok =
             ConnectionManager.register_connection(
               agent.agent_id,
               "#{certificate_serial}-#{System.unique_integer([:positive])}",
               self(),
               %{certificate_id: certificate_id}
             )
  end

  defp ensure_connection_manager_started! do
    if Process.whereis(ConnectionManager) do
      :ok
    else
      start_supervised!({ConnectionManager, name: ConnectionManager})
      :ok
    end
  end

  defp csr_pem_for_required_fields(private_key, required_fields) do
    required_fields
    |> csr_for_required_fields(private_key)
    |> X509.CSR.to_pem()
  end

  defp csr_for_required_fields(required_fields, private_key) do
    subject = required_fields["subject"]
    sans = required_fields["san"] || %{}

    uri_sans =
      sans
      |> Map.get("uri", [])
      |> List.wrap()
      |> Enum.map(&{:uniformResourceIdentifier, to_charlist(&1)})

    dns_sans =
      sans
      |> Map.get("dns", [])
      |> List.wrap()
      |> Enum.map(&{:dNSName, to_charlist(&1)})

    X509.CSR.new(private_key, [{"O", subject["O"]}, {"CN", subject["CN"]}],
      extension_request: [
        X509.Certificate.Extension.subject_alt_name(uri_sans ++ dns_sans),
        X509.Certificate.Extension.key_usage([:digitalSignature]),
        X509.Certificate.Extension.ext_key_usage([:clientAuth])
      ]
    )
  end

  defp generate_public_key!(tmp_dir, name, type) do
    path = Path.join(tmp_dir, name)

    {_, 0} =
      System.cmd("ssh-keygen", [
        "-q",
        "-t",
        type,
        "-N",
        "",
        "-f",
        path
      ])

    path
    |> then(&"#{&1}.pub")
    |> File.read!()
    |> String.trim()
  end

  defp restore_env(key, nil), do: Application.delete_env(:secrethub_core, key)
  defp restore_env(key, value), do: Application.put_env(:secrethub_core, key, value)
end
