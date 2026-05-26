defmodule SecretHub.Web.AgentRuntimeChannelTest do
  use SecretHub.Web.ChannelCase, async: false

  alias SecretHub.Core.Agents
  alias SecretHub.Core.Agents.ConnectionManager
  alias SecretHub.Core.Agents.Enrollment
  alias SecretHub.Core.{Policies, Secrets}
  alias SecretHub.Core.PKI.CSR
  alias SecretHub.Core.Repo
  alias SecretHub.Core.Vault.SealState
  alias SecretHub.Shared.Crypto.AgentCSRProof
  alias SecretHub.Shared.Schemas.{Agent, Certificate}
  alias SecretHub.Web.{AgentRuntimeChannel, AgentTrustedSocket}

  @pending_attrs %{
    hostname: "runtime-channel-01",
    fqdn: "runtime-channel-01.internal.example",
    machine_id: "runtime-channel-machine",
    os: "linux",
    arch: "x86_64",
    agent_version: "1.2.3",
    ssh_host_key_algorithm: "rsa",
    capabilities: %{"templates" => true}
  }

  setup do
    start_supervised!({ConnectionManager, name: ConnectionManager})
    :ok
  end

  test "rejects runtime joins when socket has no certificate-derived identity" do
    assert {:error, %{reason: "mtls_required"}} =
             subscribe_and_join(
               socket(AgentTrustedSocket, "agent:test", %{}),
               AgentRuntimeChannel,
               "agent:runtime"
             )
  end

  test "connects and joins trusted runtime using certificate-derived identity" do
    %{certificate: certificate, cert_der: cert_der, enrollment: enrollment} =
      issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, reply, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{
               "agent_id" => "client-spoof",
               "certificate_serial" => "spoofed-serial"
             })

    agent_id = enrollment.agent_id
    certificate_serial = certificate.serial_number
    certificate_fingerprint = certificate.fingerprint
    certificate_id = certificate.id

    assert %{
             status: "accepted",
             agent_id: ^agent_id,
             certificate_serial: ^certificate_serial,
             certificate_fingerprint: ^certificate_fingerprint,
             certificate_id: ^certificate_id
           } = reply

    assert socket.assigns.agent_id == agent_id
    assert socket.assigns.certificate_id == certificate_id
    assert ConnectionManager.connected?(agent_id)

    assert {:ok, connection} = ConnectionManager.get_connection(agent_id)
    assert connection.metadata.certificate_id == certificate_id
    assert connection.metadata.certificate_serial == certificate_serial
  end

  test "rejects runtime join if agent is revoked after socket connect" do
    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    revoke_agent_row!(enrollment.agent_id)

    assert {:error, %{reason: "runtime_not_authorized"}} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{})

    refute ConnectionManager.connected?(enrollment.agent_id)
    assert Agents.get_agent(enrollment.agent_id).status == :revoked
  end

  test "secret reads re-check runtime authorization before serving requests" do
    previous_trap_exit = Process.flag(:trap_exit, true)
    on_exit(fn -> Process.flag(:trap_exit, previous_trap_exit) end)

    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _reply, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{})

    channel_pid = socket.channel_pid
    revoke_agent_row!(enrollment.agent_id)

    ref = push(socket, "secret:read", %{"path" => "e2e/ws/test-secret"})

    assert_reply ref, :error, %{reason: "runtime_not_authorized"}, 1_000
    assert_receive {:EXIT, ^channel_pid, {:shutdown, :agent_not_active}}, 1_000
    refute ConnectionManager.connected?(enrollment.agent_id)
  end

  test "secret reads do not release decrypted data when authorization is revoked during the read" do
    previous_trap_exit = Process.flag(:trap_exit, true)
    on_exit(fn -> Process.flag(:trap_exit, previous_trap_exit) end)

    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()
    secret_path = "runtime.revoked.during.read.#{System.unique_integer([:positive])}"

    create_readable_secret!(enrollment.agent_id, secret_path)
    install_revoke_after_secret_access_trigger!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _reply, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{})

    channel_pid = socket.channel_pid

    ref = push(socket, "secret:read", %{"path" => secret_path})

    assert_reply ref, :error, %{reason: "runtime_not_authorized"}, 1_000
    assert_receive {:EXIT, ^channel_pid, {:shutdown, :agent_not_active}}, 1_000
    refute_receive %{payload: %{data: %{"value" => "must-not-leak"}}}, 100
    assert Agents.get_agent(enrollment.agent_id).status == :revoked
  end

  test "Core disconnect stops an open trusted runtime channel" do
    previous_trap_exit = Process.flag(:trap_exit, true)
    on_exit(fn -> Process.flag(:trap_exit, previous_trap_exit) end)

    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()

    assert {:ok, socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _reply, socket} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{})

    channel_pid = socket.channel_pid
    monitor_ref = Process.monitor(channel_pid)

    assert :ok = ConnectionManager.disconnect_agent(enrollment.agent_id, :revoked)

    assert_receive {:DOWN, ^monitor_ref, :process, ^channel_pid, _reason}, 1_000
    assert_receive {:EXIT, ^channel_pid, {:shutdown, :revoked}}, 1_000
    refute ConnectionManager.connected?(enrollment.agent_id)
    assert Agents.get_agent(enrollment.agent_id).status == :disconnected
  end

  test "replaced channel termination does not mark the newer connection disconnected" do
    previous_trap_exit = Process.flag(:trap_exit, true)
    on_exit(fn -> Process.flag(:trap_exit, previous_trap_exit) end)

    %{cert_der: cert_der, enrollment: enrollment} = issue_valid_agent_certificate!()

    assert {:ok, first_socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _reply, first_socket} =
             subscribe_and_join(first_socket, AgentRuntimeChannel, "agent:runtime", %{})

    first_channel_pid = first_socket.channel_pid
    first_monitor_ref = Process.monitor(first_channel_pid)

    assert {:ok, second_socket} =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})

    assert {:ok, _reply, second_socket} =
             subscribe_and_join(second_socket, AgentRuntimeChannel, "agent:runtime", %{})

    assert_receive {:DOWN, ^first_monitor_ref, :process, ^first_channel_pid, _reason}, 1_000
    assert Agents.get_agent(enrollment.agent_id).status == :trusted_connected
    assert ConnectionManager.connected?(enrollment.agent_id)

    leave(second_socket)
  end

  test "rejects trusted socket connection without a peer certificate" do
    assert :error = connect(AgentTrustedSocket, %{}, connect_info: %{})
  end

  test "rejects trusted socket connection when stored certificate is revoked" do
    %{certificate: certificate, cert_der: cert_der} = issue_valid_agent_certificate!()

    certificate
    |> Certificate.revoke_changeset("test_revocation")
    |> Repo.update!()

    assert :error =
             connect(AgentTrustedSocket, %{}, connect_info: %{peer_data: %{ssl_cert: cert_der}})
  end

  test "rejects hand-seeded socket identity that is not backed by Core certificate state" do
    socket =
      socket(AgentTrustedSocket, "agent:test", %{
        agent_id: "agent-from-cert",
        certificate_serial: "serial-1",
        certificate_fingerprint: "fingerprint-1",
        certificate_id: "certificate-id-1"
      })

    assert {:error, %{reason: "runtime_not_authorized"}} =
             subscribe_and_join(socket, AgentRuntimeChannel, "agent:runtime", %{
               "agent_id" => "client-spoof",
               "certificate_serial" => "spoofed-serial",
               "certificate_fingerprint" => "spoofed-fingerprint",
               "certificate_id" => "spoofed-certificate-id"
             })
  end

  defp issue_valid_agent_certificate! do
    ssh_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    ssh_public_key = :ssh_file.extract_public_key(ssh_private_key)
    tls_private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    fingerprint = CSR.ssh_fingerprint(ssh_public_key)

    generate_active_ca!()

    {:ok, %{enrollment: enrollment, pending_token: pending_token}} =
      @pending_attrs
      |> Map.put(:machine_id, "runtime-channel-#{System.unique_integer([:positive])}")
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

    %{certificate: certificate, cert_der: cert_der, enrollment: issued}
  end

  defp revoke_agent_row!(agent_id) do
    agent = Repo.get_by!(Agent, agent_id: agent_id)

    agent
    |> Ecto.Changeset.change(status: :revoked)
    |> Repo.update!()
  end

  defp create_readable_secret!(agent_id, secret_path) do
    restart_seal_state!()
    unseal_vault!()

    assert {:ok, _secret} =
             Secrets.create_secret(%{
               "name" => "Runtime Secret #{System.unique_integer([:positive])}",
               "secret_path" => secret_path,
               "secret_type" => "static",
               "secret_data" => %{"value" => "must-not-leak"},
               "created_by" => agent_id
             })

    assert {:ok, _policy} =
             Policies.create_policy(%{
               name: "runtime-read-#{System.unique_integer([:positive])}",
               description: "Allow runtime channel read test",
               policy_document: %{
                 "version" => "1.0",
                 "allowed_secrets" => [secret_path],
                 "allowed_operations" => ["read"]
               },
               entity_bindings: [agent_id]
             })

    :ok
  end

  defp install_revoke_after_secret_access_trigger! do
    suffix = System.unique_integer([:positive])
    function_name = "revoke_agent_after_secret_access_#{suffix}"
    trigger_name = "revoke_agent_after_secret_access_trigger_#{suffix}"

    Repo.query!("""
    CREATE FUNCTION #{function_name}() RETURNS trigger AS $$
    BEGIN
      IF NEW.event_type = 'secret.accessed' THEN
        UPDATE agents
        SET status = 'revoked', updated_at = NOW()
        WHERE agent_id = NEW.actor_id;
      END IF;

      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    """)

    Repo.query!("""
    CREATE TRIGGER #{trigger_name}
    AFTER INSERT ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION #{function_name}();
    """)

    on_exit(fn ->
      Repo.query!("DROP TRIGGER IF EXISTS #{trigger_name} ON audit_logs")
      Repo.query!("DROP FUNCTION IF EXISTS #{function_name}()")
    end)
  end

  defp restart_seal_state! do
    case Process.whereis(SealState) do
      nil ->
        :ok

      pid ->
        GenServer.stop(pid, :normal)
        wait_until_unregistered(SealState)
    end

    case SealState.start_link([]) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end
  end

  defp unseal_vault! do
    {:ok, shares} = SealState.initialize(3, 2)
    {:ok, _} = SealState.unseal(Enum.at(shares, 0))
    {:ok, _} = SealState.unseal(Enum.at(shares, 1))
    :ok
  end

  defp wait_until_unregistered(name) do
    if Process.whereis(name) do
      Process.sleep(10)
      wait_until_unregistered(name)
    else
      :ok
    end
  end

  defp generate_active_ca! do
    {:ok, %{cert_record: cert}} =
      SecretHub.Core.PKI.CA.generate_root_ca(
        "Agent Runtime Channel Test Root CA #{System.unique_integer([:positive])}",
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
end
