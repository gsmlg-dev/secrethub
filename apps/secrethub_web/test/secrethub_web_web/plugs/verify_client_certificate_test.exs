defmodule SecretHub.Web.Plugs.VerifyClientCertificateTest do
  use SecretHub.Web.ConnCase, async: false

  alias SecretHub.Core.PKI.CertificateIdentity
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

  defp generate_intermediate_ca(tmp, root, cn) do
    suffix = :erlang.unique_integer([:positive])
    key_path = Path.join(tmp, "intermediate_#{suffix}.key")
    csr_path = Path.join(tmp, "intermediate_#{suffix}.csr")
    cert_path = Path.join(tmp, "intermediate_#{suffix}.crt")
    extensions_path = Path.join(tmp, "intermediate_#{suffix}.ext")

    File.write!(extensions_path, """
    basicConstraints=critical,CA:TRUE,pathlen:0
    keyUsage=critical,keyCertSign,cRLSign
    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid,issuer
    """)

    {_, 0} = System.cmd("openssl", ["genrsa", "-out", key_path, "2048"], stderr_to_stdout: true)

    {_, 0} =
      System.cmd(
        "openssl",
        [
          "req",
          "-new",
          "-key",
          key_path,
          "-out",
          csr_path,
          "-subj",
          "/CN=#{cn}/O=SecretHub Test"
        ],
        stderr_to_stdout: true
      )

    {_, 0} =
      System.cmd(
        "openssl",
        [
          "x509",
          "-req",
          "-in",
          csr_path,
          "-CA",
          root.cert_path,
          "-CAkey",
          root.key_path,
          "-CAcreateserial",
          "-out",
          cert_path,
          "-days",
          "1825",
          "-extfile",
          extensions_path
        ],
        stderr_to_stdout: true
      )

    pem = File.read!(cert_path)
    [{:Certificate, der, _}] = :public_key.pem_decode(pem)

    %{
      key_path: key_path,
      cert_path: cert_path,
      pem: pem,
      der: der,
      cn: cn
    }
  end

  defp with_certificate_chain(client, certificates) do
    chain_path = client.cert_path <> ".chain.pem"
    File.write!(chain_path, client.pem <> Enum.map_join(certificates, & &1.pem))
    %{client | cert_path: chain_path}
  end

  defp generate_expired_cert(tmp, ca, cn) do
    generate_cert_with_dates(tmp, ca, cn, "expired",
      not_before: "20240101000000Z",
      not_after: "20240102000000Z"
    )
  end

  defp generate_not_yet_valid_cert(tmp, ca, cn) do
    generate_cert_with_dates(tmp, ca, cn, "future",
      not_before: "20500101000000Z",
      not_after: "20510101000000Z"
    )
  end

  defp generate_cert_with_dates(tmp, ca, cn, prefix, opts) do
    not_before = Keyword.fetch!(opts, :not_before)
    not_after = Keyword.fetch!(opts, :not_after)

    suffix = :erlang.unique_integer([:positive])
    client_key_path = Path.join(tmp, "#{prefix}_#{suffix}.key")
    client_cert_path = Path.join(tmp, "#{prefix}_#{suffix}.crt")
    client_csr_path = Path.join(tmp, "#{prefix}_#{suffix}.csr")

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

    # Try using -not_before/-not_after (OpenSSL 3.2+), fall back to OpenSSL conf approach
    sign_result =
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
          not_before,
          "-not_after",
          not_after
        ],
        stderr_to_stdout: true
      )

    case sign_result do
      {_, 0} ->
        :ok

      _ ->
        # Fallback for OpenSSL < 3.2 which lacks -not_before/-not_after.
        # Use an openssl.cnf with copy_extensions and a v3 ext file to embed dates.
        # Simplest portable fallback: use `openssl ca` with a minimal config.
        config_path = Path.join(tmp, "mini_ca_#{suffix}.cnf")
        serial_path = Path.join(tmp, "mini_ca_serial_#{suffix}")
        index_path = Path.join(tmp, "mini_ca_index_#{suffix}.txt")
        newcerts_dir = Path.join(tmp, "newcerts_#{suffix}")
        File.mkdir_p!(newcerts_dir)
        File.write!(index_path, "")
        File.write!(serial_path, "01\n")

        config_content = """
        [ca]
        default_ca = mini_ca

        [mini_ca]
        certificate = #{ca.cert_path}
        private_key = #{ca.key_path}
        new_certs_dir = #{newcerts_dir}
        database = #{index_path}
        serial = #{serial_path}
        default_md = sha256
        policy = policy_any
        copy_extensions = none

        [policy_any]
        countryName = optional
        stateOrProvinceName = optional
        organizationName = optional
        organizationalUnitName = optional
        commonName = supplied
        emailAddress = optional
        """

        File.write!(config_path, config_content)

        {_, 0} =
          System.cmd(
            "openssl",
            [
              "ca",
              "-batch",
              "-config",
              config_path,
              "-in",
              client_csr_path,
              "-out",
              client_cert_path,
              "-startdate",
              not_before,
              "-enddate",
              not_after,
              "-notext"
            ],
            stderr_to_stdout: true
          )
    end

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

  defp put_peer_cert(conn, cert_der) do
    {adapter, payload} = conn.adapter
    peer_data = Map.put(payload.peer_data, :ssl_cert, cert_der)
    %{conn | adapter: {adapter, %{payload | peer_data: peer_data}}}
  end

  defp mtls_get(port, client, path, headers \\ []) do
    ssl_options = [
      certfile: String.to_charlist(client.cert_path),
      keyfile: String.to_charlist(client.key_path),
      verify: :verify_none,
      active: false,
      mode: :binary,
      versions: [:"tlsv1.2", :"tlsv1.3"]
    ]

    {:ok, socket} = :ssl.connect(~c"localhost", port, ssl_options, 5_000)

    request =
      [
        "GET #{path} HTTP/1.1\r\n",
        "Host: localhost\r\n",
        Enum.map(headers, fn {name, value} -> "#{name}: #{value}\r\n" end),
        "Connection: close\r\n\r\n"
      ]

    :ok = :ssl.send(socket, request)
    receive_ssl_response(socket, "")
  end

  defp receive_ssl_response(socket, response) do
    case :ssl.recv(socket, 0, 5_000) do
      {:ok, data} -> receive_ssl_response(socket, response <> data)
      {:error, :closed} -> response
    end
  end

  defp assert_client_certificate_required(port) do
    options = [verify: :verify_none, active: false, mode: :binary]

    case :ssl.connect(~c"localhost", port, options, 5_000) do
      {:error, _reason} ->
        :ok

      {:ok, socket} ->
        case :ssl.send(socket, "GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n") do
          {:error, _reason} ->
            :ok

          :ok ->
            assert {:error, _reason} = :ssl.recv(socket, 0, 5_000)
            :ok
        end
    end
  end

  defp store_ca_cert!(ca, opts \\ []) do
    insert_certificate_record!(%{
      serial_number: extract_serial(:public_key.pkix_decode_cert(ca.der, :otp)),
      fingerprint: calculate_fingerprint(ca.pem),
      certificate_pem: ca.pem,
      subject: "CN=#{ca.cn}, O=SecretHub Test",
      issuer: Keyword.get(opts, :issuer, "CN=#{ca.cn}, O=SecretHub Test"),
      issuer_id: Keyword.get(opts, :issuer_id),
      common_name: ca.cn,
      valid_from:
        DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.truncate(:second),
      valid_until:
        DateTime.utc_now() |> DateTime.add(3650 * 86_400, :second) |> DateTime.truncate(:second),
      cert_type: Keyword.get(opts, :cert_type, :root_ca),
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

      assert cert_info.fingerprint ==
               CertificateIdentity.canonical_fingerprint_from_der(client.der)
    end

    test "reads the certificate from connection peer data", %{conn: conn, client: client} do
      opts = VerifyClientCertificate.init(required: true, check_revocation: true)

      conn =
        conn
        |> put_peer_cert(client.der)
        |> VerifyClientCertificate.call(opts)

      refute conn.halted
      assert conn.assigns.mtls_authenticated

      assert conn.assigns.client_certificate.fingerprint ==
               CertificateIdentity.canonical_fingerprint_from_der(client.der)
    end

    test "verified peer certificates authenticate configured production admins", %{
      conn: conn,
      client: client
    } do
      previous_dev_mode = Application.get_env(:secrethub_web, :dev_mode)
      previous_fingerprints = Application.get_env(:secrethub_web, :ADMIN_CERT_FINGERPRINTS)
      fingerprint = CertificateIdentity.canonical_fingerprint_from_der(client.der)

      Application.put_env(:secrethub_web, :dev_mode, false)
      Application.put_env(:secrethub_web, :ADMIN_CERT_FINGERPRINTS, [fingerprint])

      on_exit(fn ->
        restore_app_env(:dev_mode, previous_dev_mode)
        restore_app_env(:ADMIN_CERT_FINGERPRINTS, previous_fingerprints)
      end)

      conn =
        conn
        |> init_test_session(%{})
        |> put_peer_cert(client.der)
        |> post(~p"/admin/auth/login", %{})

      assert redirected_to(conn, 302) == ~p"/admin/dashboard"
      assert get_session(conn, :admin_id) =~ "test-agent-01"
    end

    test "dedicated HTTPS listener authenticates the allowlisted TLS peer after CA rotation", %{
      ca: ca,
      client: root_signed_client
    } do
      previous_dev_mode = Application.get_env(:secrethub_web, :dev_mode)
      previous_fingerprints = Application.get_env(:secrethub_web, :ADMIN_CERT_FINGERPRINTS)
      intermediate_tmp = setup_temp_dir()
      old_intermediate = generate_intermediate_ca(intermediate_tmp, ca, "Admin Intermediate CA")
      intermediate = generate_intermediate_ca(intermediate_tmp, ca, "Admin Intermediate CA")

      root_record =
        Repo.get_by!(Certificate,
          serial_number: extract_serial(:public_key.pkix_decode_cert(ca.der, :otp))
        )

      old_intermediate_record =
        store_ca_cert!(old_intermediate,
          cert_type: :intermediate_ca,
          issuer: "CN=#{ca.cn}, O=SecretHub Test",
          issuer_id: root_record.id
        )

      old_intermediate_record
      |> Ecto.Changeset.change(
        inserted_at:
          DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)
      )
      |> Repo.update!()

      store_ca_cert!(intermediate,
        cert_type: :intermediate_ca,
        issuer: "CN=#{ca.cn}, O=SecretHub Test",
        issuer_id: root_record.id
      )

      admin_client =
        intermediate_tmp
        |> generate_client_cert(intermediate, "admin@example.com")
        |> with_certificate_chain([intermediate])

      unlisted_client =
        intermediate_tmp
        |> generate_client_cert(intermediate, "unlisted-admin@example.com")
        |> with_certificate_chain([intermediate])

      store_client_cert!(admin_client, intermediate.cn)
      fingerprint = CertificateIdentity.canonical_fingerprint_from_der(admin_client.der)

      Application.put_env(:secrethub_web, :dev_mode, false)
      Application.put_env(:secrethub_web, :ADMIN_CERT_FINGERPRINTS, [fingerprint])

      on_exit(fn ->
        restore_app_env(:dev_mode, previous_dev_mode)
        restore_app_env(:ADMIN_CERT_FINGERPRINTS, previous_fingerprints)
        File.rm_rf!(intermediate_tmp)
      end)

      {:ok, server} =
        Bandit.start_link(
          plug: SecretHub.Web.Endpoint,
          scheme: :https,
          ip: {127, 0, 0, 1},
          port: 0,
          cipher_suite: :strong,
          certfile: ca.cert_path,
          keyfile: ca.key_path,
          startup_log: false,
          thousand_island_options: [
            transport_options: [
              cacertfile: String.to_charlist(ca.cert_path),
              verify: :verify_peer,
              fail_if_no_peer_cert: true,
              versions: [:"tlsv1.2", :"tlsv1.3"]
            ]
          ]
        )

      {:ok, {_address, port}} = ThousandIsland.listener_info(server)

      assert mtls_get(port, admin_client, "/admin") =~ "location: /admin/dashboard"

      response =
        mtls_get(port, unlisted_client, "/admin", [
          {"x-ssl-client-cert", Base.encode64(root_signed_client.der)}
        ])

      assert response =~ "location: /admin/auth/login"

      assert :ok = assert_client_certificate_required(port)
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

  defp restore_app_env(key, nil), do: Application.delete_env(:secrethub_web, key)
  defp restore_app_env(key, value), do: Application.put_env(:secrethub_web, key, value)

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
