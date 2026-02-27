defmodule SecretHub.Web.Plugs.VerifyClientCertificateTest do
  use SecretHub.Web.ConnCase, async: false

  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.Certificate
  alias SecretHub.Web.Plugs.VerifyClientCertificate

  # ── Helpers for generating test certificates via OpenSSL ──────────────

  defp setup_temp_dir do
    tmp =
      Path.join(System.tmp_dir!(), "secrethub_cert_test_#{:erlang.unique_integer([:positive])}")

    File.mkdir_p!(tmp)
    tmp
  end

  defp generate_ca(tmp, cn) do
    ca_key_path = Path.join(tmp, "ca.key")
    ca_cert_path = Path.join(tmp, "ca.crt")

    {_, 0} =
      System.cmd("openssl", ["genrsa", "-out", ca_key_path, "2048"], stderr_to_stdout: true)

    {_, 0} =
      System.cmd(
        "openssl",
        [
          "req",
          "-new",
          "-x509",
          "-key",
          ca_key_path,
          "-out",
          ca_cert_path,
          "-days",
          "3650",
          "-subj",
          "/CN=#{cn}/O=SecretHub Test"
        ],
        stderr_to_stdout: true
      )

    ca_pem = File.read!(ca_cert_path)
    [{:Certificate, ca_der, _}] = :public_key.pem_decode(ca_pem)

    %{
      key_path: ca_key_path,
      cert_path: ca_cert_path,
      pem: ca_pem,
      der: ca_der,
      cn: cn
    }
  end

  defp generate_client_cert(tmp, ca, cn, opts \\ []) do
    days = Keyword.get(opts, :days, "365")
    start_date = Keyword.get(opts, :start_date, nil)
    end_date = Keyword.get(opts, :end_date, nil)

    suffix = :erlang.unique_integer([:positive])
    client_key_path = Path.join(tmp, "client_#{suffix}.key")
    client_csr_path = Path.join(tmp, "client_#{suffix}.csr")
    client_cert_path = Path.join(tmp, "client_#{suffix}.crt")

    {_, 0} =
      System.cmd("openssl", ["genrsa", "-out", client_key_path, "2048"], stderr_to_stdout: true)

    {_, 0} =
      System.cmd(
        "openssl",
        [
          "req",
          "-new",
          "-key",
          client_key_path,
          "-out",
          client_csr_path,
          "-subj",
          "/CN=#{cn}/O=SecretHub Test"
        ],
        stderr_to_stdout: true
      )

    sign_args =
      [
        "x509",
        "-req",
        "-in",
        client_csr_path,
        "-CA",
        ca.cert_path,
        "-CAkey",
        ca.key_path,
        "-CAcreateserial",
        "-out",
        client_cert_path
      ] ++
        if start_date && end_date do
          # Use -not_before and -not_after for custom dates if OpenSSL supports them
          # Fallback: use -days for basic tests
          ["-days", days]
        else
          ["-days", days]
        end

    {_, 0} = System.cmd("openssl", sign_args, stderr_to_stdout: true)

    client_pem = File.read!(client_cert_path)
    [{:Certificate, client_der, _}] = :public_key.pem_decode(client_pem)

    # Extract serial number from the cert
    otp_cert = :public_key.pkix_decode_cert(client_der, :otp)
    serial = extract_serial(otp_cert)

    %{
      key_path: client_key_path,
      cert_path: client_cert_path,
      pem: client_pem,
      der: client_der,
      serial_number: serial,
      cn: cn
    }
  end

  defp generate_expired_cert(tmp, ca, cn) do
    # Generate a certificate, then use a config to make it expire
    suffix = :erlang.unique_integer([:positive])
    client_key_path = Path.join(tmp, "expired_#{suffix}.key")
    client_cert_path = Path.join(tmp, "expired_#{suffix}.crt")
    client_csr_path = Path.join(tmp, "expired_#{suffix}.csr")

    {_, 0} =
      System.cmd("openssl", ["genrsa", "-out", client_key_path, "2048"], stderr_to_stdout: true)

    {_, 0} =
      System.cmd(
        "openssl",
        [
          "req",
          "-new",
          "-key",
          client_key_path,
          "-out",
          client_csr_path,
          "-subj",
          "/CN=#{cn}/O=SecretHub Test"
        ],
        stderr_to_stdout: true
      )

    # Sign with 1 day validity, but set startdate to far in the past
    # Use faketime approach: sign normally then manipulate the validity via raw cert
    # Simpler approach: generate a self-signed cert with past dates using -days 1 and startdate
    {_, 0} =
      System.cmd(
        "openssl",
        [
          "x509",
          "-req",
          "-in",
          client_csr_path,
          "-CA",
          ca.cert_path,
          "-CAkey",
          ca.key_path,
          "-CAcreateserial",
          "-out",
          client_cert_path,
          "-days",
          "1",
          "-not_before",
          "20240101000000Z",
          "-not_after",
          "20240102000000Z"
        ],
        stderr_to_stdout: true
      )

    client_pem = File.read!(client_cert_path)
    [{:Certificate, client_der, _}] = :public_key.pem_decode(client_pem)
    otp_cert = :public_key.pkix_decode_cert(client_der, :otp)
    serial = extract_serial(otp_cert)

    %{
      key_path: client_key_path,
      cert_path: client_cert_path,
      pem: client_pem,
      der: client_der,
      serial_number: serial,
      cn: cn
    }
  end

  defp generate_not_yet_valid_cert(tmp, ca, cn) do
    suffix = :erlang.unique_integer([:positive])
    client_key_path = Path.join(tmp, "future_#{suffix}.key")
    client_cert_path = Path.join(tmp, "future_#{suffix}.crt")
    client_csr_path = Path.join(tmp, "future_#{suffix}.csr")

    {_, 0} =
      System.cmd("openssl", ["genrsa", "-out", client_key_path, "2048"], stderr_to_stdout: true)

    {_, 0} =
      System.cmd(
        "openssl",
        [
          "req",
          "-new",
          "-key",
          client_key_path,
          "-out",
          client_csr_path,
          "-subj",
          "/CN=#{cn}/O=SecretHub Test"
        ],
        stderr_to_stdout: true
      )

    # Certificate valid from far future
    {_, 0} =
      System.cmd(
        "openssl",
        [
          "x509",
          "-req",
          "-in",
          client_csr_path,
          "-CA",
          ca.cert_path,
          "-CAkey",
          ca.key_path,
          "-CAcreateserial",
          "-out",
          client_cert_path,
          "-days",
          "365",
          "-not_before",
          "20500101000000Z",
          "-not_after",
          "20510101000000Z"
        ],
        stderr_to_stdout: true
      )

    client_pem = File.read!(client_cert_path)
    [{:Certificate, client_der, _}] = :public_key.pem_decode(client_pem)
    otp_cert = :public_key.pkix_decode_cert(client_der, :otp)
    serial = extract_serial(otp_cert)

    %{
      key_path: client_key_path,
      cert_path: client_cert_path,
      pem: client_pem,
      der: client_der,
      serial_number: serial,
      cn: cn
    }
  end

  defp generate_self_signed_cert(tmp, cn) do
    suffix = :erlang.unique_integer([:positive])
    key_path = Path.join(tmp, "selfsigned_#{suffix}.key")
    cert_path = Path.join(tmp, "selfsigned_#{suffix}.crt")

    {_, 0} =
      System.cmd("openssl", ["genrsa", "-out", key_path, "2048"], stderr_to_stdout: true)

    {_, 0} =
      System.cmd(
        "openssl",
        [
          "req",
          "-new",
          "-x509",
          "-key",
          key_path,
          "-out",
          cert_path,
          "-days",
          "365",
          "-subj",
          "/CN=#{cn}/O=SecretHub Test"
        ],
        stderr_to_stdout: true
      )

    pem = File.read!(cert_path)
    [{:Certificate, der, _}] = :public_key.pem_decode(pem)
    otp_cert = :public_key.pkix_decode_cert(der, :otp)
    serial = extract_serial(otp_cert)

    %{
      key_path: key_path,
      cert_path: cert_path,
      pem: pem,
      der: der,
      serial_number: serial,
      cn: cn
    }
  end

  defp extract_serial(
         {:OTPCertificate, {:OTPTBSCertificate, _, serial, _, _, _, _, _, _, _, _}, _, _}
       ) do
    Integer.to_string(serial, 16)
  end

  defp calculate_fingerprint(cert_pem) do
    hash =
      :crypto.hash(:sha256, cert_pem)
      |> Base.encode16(case: :lower)
      |> String.graphemes()
      |> Enum.chunk_every(2)
      |> Enum.map_join(":", &Enum.join/1)

    "sha256:#{hash}"
  end

  defp inject_peer_cert(conn, cert_der) do
    Plug.Conn.put_private(conn, :peer_cert_der, cert_der)
  end

  defp store_ca_cert!(ca) do
    insert_certificate_record!(%{
      serial_number: extract_serial(:public_key.pkix_decode_cert(ca.der, :otp)),
      fingerprint: calculate_fingerprint(ca.pem),
      certificate_pem: ca.pem,
      subject: "CN=#{ca.cn}, O=SecretHub Test",
      issuer: "CN=#{ca.cn}, O=SecretHub Test",
      common_name: ca.cn,
      valid_from:
        DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.truncate(:second),
      valid_until:
        DateTime.utc_now() |> DateTime.add(3650 * 86_400, :second) |> DateTime.truncate(:second),
      cert_type: :root_ca,
      revoked: false
    })
  end

  defp store_client_cert!(client, ca_cn, opts \\ []) do
    revoked = Keyword.get(opts, :revoked, false)

    attrs = %{
      serial_number: client.serial_number,
      fingerprint: calculate_fingerprint(client.pem),
      certificate_pem: client.pem,
      subject: "CN=#{client.cn}, O=SecretHub Test",
      issuer: "CN=#{ca_cn}, O=SecretHub Test",
      common_name: client.cn,
      valid_from:
        DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.truncate(:second),
      valid_until:
        DateTime.utc_now() |> DateTime.add(365 * 86_400, :second) |> DateTime.truncate(:second),
      cert_type: :agent_client,
      revoked: revoked
    }

    attrs =
      if revoked do
        Map.merge(attrs, %{
          revoked_at: DateTime.utc_now() |> DateTime.truncate(:second),
          revocation_reason: "key_compromise"
        })
      else
        attrs
      end

    insert_certificate_record!(attrs)
  end

  defp insert_certificate_record!(attrs) do
    %Certificate{}
    |> Certificate.changeset(attrs)
    |> Repo.insert!()
  end

  # ── Tests ─────────────────────────────────────────────────────────────

  describe "connection with no client certificate" do
    test "rejects request when certificate is required", %{conn: conn} do
      opts = VerifyClientCertificate.init(required: true)
      conn = VerifyClientCertificate.call(conn, opts)

      assert conn.halted
      assert conn.status == 401

      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "Unauthorized"
      # Test conn has no TLS, so it returns :not_tls_connection which maps to
      # "Invalid client certificate" (the generic error path)
      assert is_binary(body["message"])
    end

    test "allows request when certificate is optional", %{conn: conn} do
      opts = VerifyClientCertificate.init(required: false)
      conn = VerifyClientCertificate.call(conn, opts)

      refute conn.halted
      refute Map.has_key?(conn.assigns, :mtls_authenticated)
      refute Map.has_key?(conn.assigns, :agent_id)
    end
  end

  describe "connection with valid certificate" do
    setup do
      tmp = setup_temp_dir()
      ca = generate_ca(tmp, "Valid Test CA")
      _ca_record = store_ca_cert!(ca)

      client = generate_client_cert(tmp, ca, "test-agent-01")
      _client_record = store_client_cert!(client, ca.cn)

      on_exit(fn -> File.rm_rf!(tmp) end)

      %{ca: ca, client: client}
    end

    test "allows request and sets assigns with valid CA-signed certificate", %{
      conn: conn,
      client: client
    } do
      opts = VerifyClientCertificate.init(required: true, check_revocation: true)

      conn =
        conn
        |> inject_peer_cert(client.der)
        |> VerifyClientCertificate.call(opts)

      refute conn.halted
      assert conn.assigns[:mtls_authenticated] == true
      assert conn.assigns[:agent_id] == "test-agent-01"
      assert is_binary(conn.assigns[:certificate_serial])
      assert conn.assigns[:certificate_serial] == client.serial_number

      # Verify client_certificate info map
      cert_info = conn.assigns[:client_certificate]
      assert is_map(cert_info)
      assert cert_info.serial_number == client.serial_number
      assert %DateTime{} = cert_info.valid_from
      assert %DateTime{} = cert_info.valid_until
      assert is_binary(cert_info.subject)
    end

    test "allows request without revocation check", %{conn: conn, client: client} do
      opts = VerifyClientCertificate.init(required: true, check_revocation: false)

      conn =
        conn
        |> inject_peer_cert(client.der)
        |> VerifyClientCertificate.call(opts)

      refute conn.halted
      assert conn.assigns[:mtls_authenticated] == true
      assert conn.assigns[:agent_id] == "test-agent-01"
    end
  end

  describe "connection with expired certificate" do
    setup do
      tmp = setup_temp_dir()
      ca = generate_ca(tmp, "Expired Test CA")
      on_exit(fn -> File.rm_rf!(tmp) end)
      %{tmp: tmp, ca: ca}
    end

    test "rejects certificate that has already expired", %{conn: conn, tmp: tmp, ca: ca} do
      expired = generate_expired_cert(tmp, ca, "expired-agent")

      opts = VerifyClientCertificate.init(required: true, check_revocation: false)

      conn =
        conn
        |> inject_peer_cert(expired.der)
        |> VerifyClientCertificate.call(opts)

      assert conn.halted
      assert conn.status == 401

      body = Jason.decode!(conn.resp_body)
      assert body["message"] == "Certificate expired"
    end

    test "rejects certificate that is not yet valid", %{conn: conn, tmp: tmp, ca: ca} do
      future = generate_not_yet_valid_cert(tmp, ca, "future-agent")

      opts = VerifyClientCertificate.init(required: true, check_revocation: false)

      conn =
        conn
        |> inject_peer_cert(future.der)
        |> VerifyClientCertificate.call(opts)

      assert conn.halted
      assert conn.status == 401

      body = Jason.decode!(conn.resp_body)
      assert body["message"] == "Certificate expired"
    end
  end

  describe "connection with revoked certificate" do
    setup do
      tmp = setup_temp_dir()
      ca = generate_ca(tmp, "Revocation Test CA")
      _ca_record = store_ca_cert!(ca)

      client = generate_client_cert(tmp, ca, "revoked-agent")
      _client_record = store_client_cert!(client, ca.cn, revoked: true)

      on_exit(fn -> File.rm_rf!(tmp) end)

      %{ca: ca, client: client}
    end

    test "rejects certificate that is revoked in the database", %{conn: conn, client: client} do
      opts = VerifyClientCertificate.init(required: true, check_revocation: true)

      conn =
        conn
        |> inject_peer_cert(client.der)
        |> VerifyClientCertificate.call(opts)

      assert conn.halted
      assert conn.status == 401

      body = Jason.decode!(conn.resp_body)
      assert body["message"] == "Certificate revoked"
    end

    test "allows revoked certificate when revocation check is disabled", %{
      conn: conn,
      client: client
    } do
      opts = VerifyClientCertificate.init(required: true, check_revocation: false)

      conn =
        conn
        |> inject_peer_cert(client.der)
        |> VerifyClientCertificate.call(opts)

      # Without revocation check, it proceeds to CA chain verification
      # Since the CA is in the DB, it should validate successfully
      refute conn.halted
      assert conn.assigns[:mtls_authenticated] == true
      assert conn.assigns[:agent_id] == "revoked-agent"
    end
  end

  describe "connection with self-signed/untrusted certificate" do
    setup do
      tmp = setup_temp_dir()
      on_exit(fn -> File.rm_rf!(tmp) end)
      %{tmp: tmp}
    end

    test "rejects self-signed certificate not in CA chain", %{conn: conn, tmp: tmp} do
      # Generate a self-signed certificate (not issued by any trusted CA)
      untrusted = generate_self_signed_cert(tmp, "untrusted-agent")

      # Store the cert serial in DB as not revoked so revocation check passes
      store_client_cert!(untrusted, untrusted.cn)

      opts = VerifyClientCertificate.init(required: true, check_revocation: true)

      conn =
        conn
        |> inject_peer_cert(untrusted.der)
        |> VerifyClientCertificate.call(opts)

      assert conn.halted
      assert conn.status == 401

      body = Jason.decode!(conn.resp_body)
      assert body["message"] == "Certificate validation failed"
    end

    test "rejects certificate signed by a different CA", %{conn: conn, tmp: tmp} do
      # Create a trusted CA in the DB
      trusted_ca = generate_ca(tmp, "Trusted CA")
      store_ca_cert!(trusted_ca)

      # Generate a client cert signed by a DIFFERENT CA (not in DB)
      rogue_ca = generate_ca(tmp, "Rogue CA")
      rogue_client = generate_client_cert(tmp, rogue_ca, "rogue-agent")

      opts = VerifyClientCertificate.init(required: true, check_revocation: false)

      conn =
        conn
        |> inject_peer_cert(rogue_client.der)
        |> VerifyClientCertificate.call(opts)

      assert conn.halted
      assert conn.status == 401

      body = Jason.decode!(conn.resp_body)
      assert body["message"] == "Certificate validation failed"
    end
  end

  describe "certificate fingerprint and info extraction" do
    setup do
      tmp = setup_temp_dir()
      ca = generate_ca(tmp, "Extraction Test CA")
      store_ca_cert!(ca)

      client = generate_client_cert(tmp, ca, "agent-fingerprint-test")
      store_client_cert!(client, ca.cn)

      on_exit(fn -> File.rm_rf!(tmp) end)

      %{ca: ca, client: client}
    end

    test "extracts agent_id from certificate CN", %{conn: conn, client: client} do
      opts = VerifyClientCertificate.init(required: true, check_revocation: true)

      conn =
        conn
        |> inject_peer_cert(client.der)
        |> VerifyClientCertificate.call(opts)

      refute conn.halted
      assert conn.assigns[:agent_id] == "agent-fingerprint-test"
    end

    test "extracts serial number from certificate", %{conn: conn, client: client} do
      opts = VerifyClientCertificate.init(required: true, check_revocation: true)

      conn =
        conn
        |> inject_peer_cert(client.der)
        |> VerifyClientCertificate.call(opts)

      refute conn.halted
      assert conn.assigns[:certificate_serial] == client.serial_number
    end

    test "populates client_certificate with parsed info", %{conn: conn, client: client} do
      opts = VerifyClientCertificate.init(required: true, check_revocation: true)

      conn =
        conn
        |> inject_peer_cert(client.der)
        |> VerifyClientCertificate.call(opts)

      refute conn.halted

      cert_info = conn.assigns[:client_certificate]
      assert is_map(cert_info)
      assert cert_info.serial_number == client.serial_number
      assert %DateTime{} = cert_info.valid_from
      assert %DateTime{} = cert_info.valid_until
      assert DateTime.compare(cert_info.valid_from, cert_info.valid_until) == :lt

      # Subject string should contain the CN
      assert cert_info.subject =~ "agent-fingerprint-test"
    end
  end

  describe "certificate validation edge cases" do
    test "returns 401 with JSON body for certificate verification errors", %{conn: conn} do
      # Inject garbage data as a certificate - should trigger rescue
      opts = VerifyClientCertificate.init(required: true)

      conn =
        conn
        |> inject_peer_cert("not-a-valid-der-certificate")
        |> VerifyClientCertificate.call(opts)

      assert conn.halted
      assert conn.status == 401

      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "Unauthorized"
      assert is_binary(body["message"])
    end

    test "certificate with unknown serial passes revocation check as not_revoked", %{conn: conn} do
      # A certificate whose serial is not in the database should be treated as not_revoked
      # (per the plug's check_revocation_status logic)
      tmp = setup_temp_dir()
      ca = generate_ca(tmp, "Unknown Serial CA")
      store_ca_cert!(ca)

      # Generate client cert but do NOT store its serial in the DB
      client = generate_client_cert(tmp, ca, "unknown-serial-agent")

      on_exit(fn -> File.rm_rf!(tmp) end)

      opts = VerifyClientCertificate.init(required: true, check_revocation: true)

      conn =
        conn
        |> inject_peer_cert(client.der)
        |> VerifyClientCertificate.call(opts)

      # Should pass revocation check (serial not found = not_revoked)
      # and pass CA chain validation
      refute conn.halted
      assert conn.assigns[:mtls_authenticated] == true
      assert conn.assigns[:agent_id] == "unknown-serial-agent"
    end
  end

  describe "plug init/1" do
    test "defaults required to true" do
      opts = VerifyClientCertificate.init([])
      assert opts.required == true
    end

    test "defaults check_revocation to true" do
      opts = VerifyClientCertificate.init([])
      assert opts.check_revocation == true
    end

    test "accepts required: false" do
      opts = VerifyClientCertificate.init(required: false)
      assert opts.required == false
    end

    test "accepts check_revocation: false" do
      opts = VerifyClientCertificate.init(check_revocation: false)
      assert opts.check_revocation == false
    end
  end
end
