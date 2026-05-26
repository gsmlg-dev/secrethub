defmodule SecretHub.Agent.EnrollmentTest do
  use ExUnit.Case, async: false

  alias SecretHub.Agent.{Enrollment, HostKey, TLSIdentity}
  alias SecretHub.Shared.Crypto.AgentCSRProof

  @tag :tmp_dir
  test "pending_payload includes the OpenSSH host public key", %{tmp_dir: tmp_dir} do
    host_key_path = generate_key!(tmp_dir, "ssh_host_rsa_key", "rsa")
    {:ok, host_key} = HostKey.discover(paths: [rsa: host_key_path])

    payload =
      Enrollment.pending_payload(host_key,
        hostname: "build-01",
        fqdn: "build-01.internal.example",
        machine_id: "machine-123"
      )

    assert payload["ssh_host_public_key"] == HostKey.public_key_openssh(host_key)

    assert [{decoded_public_key, []}] =
             :ssh_file.decode(payload["ssh_host_public_key"], :public_key)

    assert decoded_public_key == host_key.public_key
  end

  @tag :tmp_dir
  test "create_pending rejects insecure enrollment URLs when disabled", %{tmp_dir: tmp_dir} do
    original_allow = Application.get_env(:secrethub_agent, :allow_insecure_enrollment)
    original_req_options = Application.get_env(:secrethub_agent, :enrollment_req_options)

    on_exit(fn ->
      restore_env(:allow_insecure_enrollment, original_allow)
      restore_env(:enrollment_req_options, original_req_options)
    end)

    Application.put_env(:secrethub_agent, :allow_insecure_enrollment, false)
    Application.put_env(:secrethub_agent, :enrollment_req_options, plug: {Req.Test, __MODULE__})

    Req.Test.stub(__MODULE__, fn _conn ->
      flunk("insecure enrollment URL must be rejected before an HTTP request")
    end)

    host_key_path = generate_key!(tmp_dir, "ssh_host_rsa_key", "rsa")
    {:ok, host_key} = HostKey.discover(paths: [rsa: host_key_path])

    assert {:error, :insecure_enrollment_url} =
             Enrollment.create_pending("http://core.invalid", host_key)
  end

  @tag :tmp_dir
  test "create_pending does not follow enrollment redirects", %{tmp_dir: tmp_dir} do
    original_req_options = Application.get_env(:secrethub_agent, :enrollment_req_options)

    on_exit(fn ->
      restore_env(:enrollment_req_options, original_req_options)
    end)

    Application.put_env(:secrethub_agent, :enrollment_req_options, plug: {Req.Test, __MODULE__})

    Req.Test.expect(__MODULE__, fn conn ->
      conn
      |> Plug.Conn.put_resp_header("location", "http://core.invalid/v1/agent/enrollments")
      |> Plug.Conn.resp(302, "redirect")
    end)

    host_key_path = generate_key!(tmp_dir, "ssh_host_rsa_key", "rsa")
    {:ok, host_key} = HostKey.discover(paths: [rsa: host_key_path])

    assert {:error, {:http_error, 302, "redirect"}} =
             Enrollment.create_pending("https://core.example", host_key)
  end

  @tag :tmp_dir
  test "store_material writes a TLS PEM key separate from the OpenSSH host key", %{
    tmp_dir: tmp_dir
  } do
    host_key_path = generate_key!(tmp_dir, "ssh_host_rsa_key", "rsa")
    {:ok, host_key} = HostKey.discover(paths: [rsa: host_key_path])
    {:ok, tls_identity} = TLSIdentity.generate(required_csr_fields())

    storage_dir = Path.join(tmp_dir, "certs")

    assert :ok =
             Enrollment.store_material(
               storage_dir,
               %{"enrollment_id" => "enrollment-1", "pending_token" => "token"},
               %{
                 "agent_id" => "agent-1",
                 "certificate_pem" =>
                   "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                 "ca_chain_pem" =>
                   "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"
               },
               %{"trusted_websocket_endpoint" => "wss://localhost:4665/agent/socket/websocket"},
               tls_identity
             )

    assert File.read!(Path.join(storage_dir, "agent-key.pem")) == tls_identity.private_key_pem
    refute File.read!(Path.join(storage_dir, "agent-key.pem")) == host_key.private_key_pem
    assert File.read!(host_key_path) =~ "BEGIN OPENSSH PRIVATE KEY"
  end

  @tag :tmp_dir
  test "store_material persists trusted identity and keeps pending token private", %{
    tmp_dir: tmp_dir
  } do
    {:ok, tls_identity} = TLSIdentity.generate(required_csr_fields())
    storage_dir = Path.join(tmp_dir, "certs")

    pending = %{
      "enrollment_id" => "enrollment-1",
      "pending_token" => "token",
      "hostname" => "build-01",
      "fqdn" => "build-01.internal.example",
      "machine_id" => "machine-123",
      "ssh_host_key_fingerprint" => "SHA256:host"
    }

    issued = %{
      "agent_id" => "agent-1",
      "certificate_pem" => "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
      "ca_chain_pem" => "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n",
      "certificate_fingerprint" => "SHA256:certificate",
      "certificate_serial" => "1234",
      "valid_until" => "2026-06-01T00:00:00Z"
    }

    connect_info = %{
      "trusted_websocket_endpoint" => "wss://localhost:4665/agent/socket/websocket"
    }

    assert :ok =
             Enrollment.store_material(storage_dir, pending, issued, connect_info, tls_identity)

    assert %{
             "agent_id" => "agent-1",
             "enrollment_id" => "enrollment-1",
             "certificate_fingerprint" => "SHA256:certificate",
             "certificate_serial" => "1234",
             "valid_until" => "2026-06-01T00:00:00Z",
             "ssh_host_key_fingerprint" => "SHA256:host",
             "hostname" => "build-01",
             "fqdn" => "build-01.internal.example",
             "machine_id" => "machine-123"
           } == storage_dir |> Path.join("identity.json") |> File.read!() |> Jason.decode!()

    assert mode(storage_dir) == 0o700
    assert mode(Path.join(storage_dir, "agent-key.pem")) == 0o600
    assert mode(Path.join(storage_dir, "pending.json")) == 0o600
  end

  @tag :tmp_dir
  test "store_material writes pending token before trusted identity can load", %{tmp_dir: tmp_dir} do
    {:ok, tls_identity} = TLSIdentity.generate(required_csr_fields())
    storage_dir = Path.join(tmp_dir, "certs")

    pending = %{
      "enrollment_id" => "enrollment-1",
      "pending_token" => "token",
      "enrollment_core_url" => "https://core.example"
    }

    issued = %{
      "agent_id" => "agent-1",
      "certificate_pem" => "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
      "ca_chain_pem" => "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"
    }

    connect_info = %{
      "trusted_websocket_endpoint" => "wss://localhost:4665/agent/socket/websocket",
      "invalid_json" => fn -> :ok end
    }

    assert {:error, {:invalid_json, :connect_info}} =
             Enrollment.store_material(storage_dir, pending, issued, connect_info, tls_identity)

    assert pending == storage_dir |> Path.join("pending.json") |> File.read!() |> Jason.decode!()
    refute File.exists?(Path.join(storage_dir, "agent-cert.pem"))
  end

  @tag :tmp_dir
  test "TLS CSR public key differs from the discovered HostKey public key", %{tmp_dir: tmp_dir} do
    host_key_path = generate_key!(tmp_dir, "ssh_host_rsa_key", "rsa")
    {:ok, host_key} = HostKey.discover(paths: [rsa: host_key_path])
    {:ok, tls_identity} = TLSIdentity.generate(required_csr_fields())
    {:ok, csr} = X509.CSR.from_pem(tls_identity.csr_pem)

    assert X509.CSR.public_key(csr) == :ssh_file.extract_public_key(tls_identity.private_key)
    refute X509.CSR.public_key(csr) == host_key.public_key
  end

  @tag :tmp_dir
  test "submit_csr posts ssh_proof bound to the TLS CSR", %{tmp_dir: tmp_dir} do
    Req.Test.verify_on_exit!()

    host_key_path = generate_key!(tmp_dir, "ssh_host_rsa_key", "rsa")
    {:ok, host_key} = HostKey.discover(paths: [rsa: host_key_path])
    {:ok, tls_identity} = TLSIdentity.generate(required_csr_fields())

    pending = %{
      "enrollment_id" => "enrollment-1",
      "pending_token" => "pending-token"
    }

    approved = %{
      "required_csr_fields" => Map.put(required_csr_fields(), "challenge", "challenge-1")
    }

    Req.Test.expect(__MODULE__, fn conn ->
      assert conn.method == "POST"
      assert conn.request_path == "/v1/agent/enrollments/enrollment-1/csr"
      assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer pending-token"]

      assert %{"csr_pem" => csr_pem, "ssh_proof" => ssh_proof} = conn.body_params
      assert csr_pem == tls_identity.csr_pem

      assert {:ok, %{algorithm: "rsa"}} =
               AgentCSRProof.verify(
                 host_key.public_key,
                 %{
                   enrollment_id: pending["enrollment_id"],
                   challenge: "challenge-1",
                   csr_pem: csr_pem,
                   proof: ssh_proof
                 }
               )

      Req.Test.json(conn, %{"agent_id" => "agent-1"})
    end)

    Application.put_env(:secrethub_agent, :enrollment_req_options, plug: {Req.Test, __MODULE__})

    on_exit(fn ->
      Application.delete_env(:secrethub_agent, :enrollment_req_options)
    end)

    assert {:ok, %{"agent_id" => "agent-1"}} =
             Enrollment.submit_csr(
               "http://core.invalid",
               pending,
               approved,
               tls_identity,
               host_key
             )
  end

  @tag :tmp_dir
  test "submit_csr returns a controlled error when the CSR challenge is missing", %{
    tmp_dir: tmp_dir
  } do
    host_key_path = generate_key!(tmp_dir, "ssh_host_rsa_key", "rsa")
    {:ok, host_key} = HostKey.discover(paths: [rsa: host_key_path])
    {:ok, tls_identity} = TLSIdentity.generate(required_csr_fields())

    pending = %{
      "enrollment_id" => "enrollment-1",
      "pending_token" => "pending-token"
    }

    Req.Test.stub(__MODULE__, fn _conn ->
      flunk("submit_csr/5 should not post without a binary non-empty challenge")
    end)

    Application.put_env(:secrethub_agent, :enrollment_req_options, plug: {Req.Test, __MODULE__})

    on_exit(fn ->
      Application.delete_env(:secrethub_agent, :enrollment_req_options)
    end)

    for approved <- [
          %{"required_csr_fields" => required_csr_fields()},
          %{"required_csr_fields" => Map.put(required_csr_fields(), "challenge", nil)},
          %{"required_csr_fields" => Map.put(required_csr_fields(), "challenge", "")},
          %{"required_csr_fields" => Map.put(required_csr_fields(), "challenge", 123)}
        ] do
      assert {:error, :missing_csr_challenge} =
               Enrollment.submit_csr(
                 "http://core.invalid",
                 pending,
                 approved,
                 tls_identity,
                 host_key
               )
    end
  end

  defp generate_key!(tmp_dir, name, type) do
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
  end

  defp required_csr_fields do
    %{
      "subject" => %{
        "O" => "SecretHub Agents",
        "CN" => "agent-123"
      },
      "san" => %{
        "uri" => ["spiffe://secrethub/agent/agent-123"],
        "dns" => ["agent-123.internal.example"]
      }
    }
  end

  defp mode(path) do
    {:ok, stat} = File.stat(path)
    Bitwise.band(stat.mode, 0o777)
  end

  defp restore_env(key, nil), do: Application.delete_env(:secrethub_agent, key)
  defp restore_env(key, value), do: Application.put_env(:secrethub_agent, key, value)
end
