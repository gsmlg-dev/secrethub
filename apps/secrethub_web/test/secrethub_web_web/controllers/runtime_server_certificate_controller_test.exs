defmodule SecretHub.Web.RuntimeServerCertificateControllerTest do
  use SecretHub.Web.ConnCase, async: false

  import ExUnit.CaptureLog

  alias SecretHub.Core.PKI.CA
  alias SecretHub.Core.Repo
  alias SecretHub.Shared.Schemas.Certificate

  @path "/admin/api/pki/runtime-server-certificate"

  setup do
    Repo.update_all(Certificate, set: [revoked: true])
    :ok
  end

  test "requires a valid management CSRF token" do
    assert_raise Plug.CSRFProtection.InvalidCSRFTokenError, fn ->
      build_conn()
      |> put_private(:plug_skip_csrf_protection, false)
      |> post(@path, %{"advertised_host" => "runtime.example.test"})
    end

    assert_raise Plug.CSRFProtection.InvalidCSRFTokenError, fn ->
      build_conn()
      |> put_private(:plug_skip_csrf_protection, false)
      |> put_req_header("x-csrf-token", "invalid-token")
      |> post(@path, %{"advertised_host" => "runtime.example.test"})
    end

    assert Repo.aggregate(Certificate, :count) == 0
  end

  test "issues and renews DNS/IP server material with the active CA and sanitized audit" do
    {:ok, root} = CA.generate_root_ca("Runtime Issuance Test Root", "SecretHub", key_size: 2048)
    ca_before = Repo.get!(Certificate, root.cert_record.id)
    count_before = Repo.aggregate(Certificate, :count)

    params = %{
      "advertised_host" => "runtime.example.test",
      "subject_alt_names" => ["runtime.example.test", "127.0.0.1", "2001:db8::1"],
      "extended_key_usage" => ["clientAuth"]
    }

    log =
      capture_log(fn ->
        conn = management_post(params)
        data = json_response(conn, 201)["data"]
        assert get_resp_header(conn, "cache-control") == ["no-store"]
        assert get_resp_header(conn, "pragma") == ["no-cache"]
        assert data["ca_certificate_pem"] == root.certificate
        assert data["ca_fingerprint"] == ca_before.fingerprint

        cert = X509.Certificate.from_pem!(data["certificate_pem"])
        key = X509.PrivateKey.from_pem!(data["private_key_pem"])
        ca = X509.Certificate.from_pem!(root.certificate)
        assert X509.Certificate.public_key(cert) == X509.PublicKey.derive(key)

        assert :public_key.pkix_verify(
                 X509.Certificate.to_der(cert),
                 X509.Certificate.public_key(ca)
               )

        assert X509.Certificate.subject(cert, "CN") == ["runtime.example.test"]
        assert {:Extension, _, _, sans} = X509.Certificate.extension(cert, :subject_alt_name)

        assert sans == [
                 dNSName: ~c"runtime.example.test",
                 iPAddress: <<127, 0, 0, 1>>,
                 iPAddress: <<0x2001::16, 0xDB8::16, 0::16, 0::16, 0::16, 0::16, 0::16, 1::16>>
               ]

        assert {:Extension, _, _, [{1, 3, 6, 1, 5, 5, 7, 3, 1}]} =
                 X509.Certificate.extension(cert, :ext_key_usage)

        renewed = management_post(params) |> json_response(201) |> Map.fetch!("data")
        refute renewed["certificate_pem"] == data["certificate_pem"]
        refute renewed["private_key_pem"] == data["private_key_pem"]
      end)

    refute log =~ "PRIVATE KEY"
    assert Repo.get!(Certificate, root.cert_record.id) == ca_before
    assert Repo.aggregate(Certificate, :count) == count_before

    audits =
      SecretHub.Core.Audit.search_logs(%{event_type: "system.runtime_server_certificate_issued"})

    assert [first, second] = audits

    for audit <- [first, second] do
      assert audit.actor_type == "admin"
      assert audit.event_data["advertised_host"] == "runtime.example.test"
      assert audit.event_data["ca_fingerprint"] == ca_before.fingerprint
      assert audit.event_data["subject_alt_names"] == params["subject_alt_names"]

      assert Map.keys(audit.event_data) |> Enum.sort() ==
               ~w(advertised_host ca_fingerprint serial_number subject_alt_names)

      refute inspect(audit.event_data) =~ "PRIVATE KEY"
    end
  end

  test "defaults SANs to an advertised IPv6 address" do
    {:ok, _root} = CA.generate_root_ca("IPv6 Runtime Root", "SecretHub", key_size: 2048)
    data = management_post(%{"advertised_host" => "2001:db8::1"}) |> json_response(201)
    cert = X509.Certificate.from_pem!(data["data"]["certificate_pem"])

    assert {:Extension, _, _, [iPAddress: <<0x2001::16, 0xDB8::16, 0::80, 1::16>>]} =
             X509.Certificate.extension(cert, :subject_alt_name)
  end

  test "withholds private material when audit signing is unavailable" do
    {:ok, _root} = CA.generate_root_ca("Audit Failure Runtime Root", "SecretHub", key_size: 2048)
    original_key_id = Application.fetch_env(:secrethub_core, :audit_hmac_key_id)
    Application.put_env(:secrethub_core, :audit_hmac_key_id, "invalid key id")

    on_exit(fn ->
      case original_key_id do
        {:ok, value} -> Application.put_env(:secrethub_core, :audit_hmac_key_id, value)
        :error -> Application.delete_env(:secrethub_core, :audit_hmac_key_id)
      end
    end)

    conn = management_post(%{"advertised_host" => "runtime.example.test"})
    assert %{"error" => "audit_unavailable"} = json_response(conn, 503)
    refute conn.resp_body =~ "PRIVATE KEY"
    assert get_resp_header(conn, "cache-control") == ["no-store"]

    assert SecretHub.Core.Audit.search_logs(%{
             event_type: "system.runtime_server_certificate_issued"
           }) == []
  end

  test "validates advertised hosts and requires a matching SAN before issuing" do
    invalid_params = [
      %{},
      %{"advertised_host" => "https://runtime.example.test"},
      %{"advertised_host" => "*.example.test"},
      %{"advertised_host" => "999.999.999.999"},
      %{"advertised_host" => String.duplicate("x", 254)},
      %{"advertised_host" => "runtime.example.test", "subject_alt_names" => nil},
      %{"advertised_host" => "runtime.example.test/CN=injected"},
      %{"advertised_host" => "runtime.example.test", "subject_alt_names" => []},
      %{"advertised_host" => "runtime.example.test", "subject_alt_names" => ["other.test"]},
      %{"advertised_host" => "runtime.example.test", "subject_alt_names" => [123]},
      %{
        "advertised_host" => "runtime.example.test",
        "subject_alt_names" => "runtime.example.test"
      },
      %{
        "advertised_host" => "runtime.example.test",
        "subject_alt_names" => ["runtime.example.test", "bad host"]
      }
    ]

    for params <- invalid_params do
      assert %{"error" => "invalid_server_names"} = management_post(params) |> json_response(422)
    end
  end

  test "does not bootstrap or regenerate a missing CA" do
    conn = management_post(%{"advertised_host" => "runtime.example.test"})
    assert %{"error" => "no_active_ca"} = json_response(conn, 503)
    refute conn.resp_body =~ "PRIVATE KEY"
    assert Repo.aggregate(Certificate, :count) == 0
  end

  test "does not expose material when the signing key is unavailable" do
    {:ok, root} = CA.generate_root_ca("Unavailable Signing Key", "SecretHub", key_size: 2048)
    Repo.update_all(Certificate, set: [private_key_encrypted: nil])
    conn = management_post(%{"advertised_host" => "runtime.example.test"})
    assert %{"error" => "ca_private_key_unavailable"} = json_response(conn, 503)
    refute conn.resp_body =~ "PRIVATE KEY"
    assert Repo.get!(Certificate, root.cert_record.id).certificate_pem == root.certificate
  end

  defp management_post(params) do
    csrf_conn = get(build_conn(), "/v1/sys/csrf-token")
    csrf_token = json_response(csrf_conn, 200)["csrf_token"]
    refute get_session(csrf_conn, :admin_id)

    csrf_conn
    |> recycle()
    |> put_private(:plug_skip_csrf_protection, false)
    |> put_req_header("x-csrf-token", csrf_token)
    |> post(@path, params)
  end
end
