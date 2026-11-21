defmodule SecretHub.Agent.EndpointManagerTest do
  use ExUnit.Case, async: false

  alias SecretHub.Agent.{EndpointManager, IdentityStore}
  alias X509.Certificate.Extension

  @endpoints [
    "wss://core-0.secrethub.local:4000",
    "wss://core-1.secrethub.local:4000",
    "wss://core-2.secrethub.local:4000"
  ]

  setup do
    original_http_options = Application.get_env(:secrethub_agent, :enrollment_http_options)

    # Stop any existing EndpointManager to avoid name conflicts
    case Process.whereis(EndpointManager) do
      nil -> :ok
      pid -> GenServer.stop(pid, :normal, 1000)
    end

    on_exit(fn ->
      case original_http_options do
        nil -> Application.delete_env(:secrethub_agent, :enrollment_http_options)
        value -> Application.put_env(:secrethub_agent, :enrollment_http_options, value)
      end
    end)

    :ok
  end

  defp start_manager(opts \\ []) do
    defaults = [
      core_endpoints: @endpoints,
      # Use a long interval so the periodic health check does not fire during tests
      health_check_interval: 60_000,
      failover_threshold: 3
    ]

    start_supervised!({EndpointManager, Keyword.merge(defaults, opts)})
  end

  # ------------------------------------------------------------------
  # 1. Initialization
  # ------------------------------------------------------------------
  describe "init/1" do
    test "starts successfully with a list of endpoints" do
      pid = start_manager()
      assert Process.alive?(pid)
    end

    test "stops when no endpoints are configured" do
      # init returns {:stop, :no_endpoints_configured} which sends an EXIT to the caller.
      # Trap exits so we can match the error tuple from start_link.
      Process.flag(:trap_exit, true)

      assert {:error, :no_endpoints_configured} =
               EndpointManager.start_link(core_endpoints: [])
    end

    test "all endpoints begin as healthy" do
      start_manager()

      statuses = EndpointManager.get_health_status()
      assert length(statuses) == 3

      Enum.each(statuses, fn s ->
        assert s.status == :healthy
        assert s.consecutive_failures == 0
        assert s.consecutive_successes == 0
        assert s.last_success == nil
        assert s.last_failure == nil
        assert s.backoff_until == nil
      end)
    end
  end

  # ------------------------------------------------------------------
  # 2. get_next_endpoint/0 — round-robin selection
  # ------------------------------------------------------------------
  describe "get_next_endpoint/0" do
    test "returns the first endpoint on initial call" do
      start_manager()

      assert {:ok, endpoint} = EndpointManager.get_next_endpoint()
      assert endpoint == Enum.at(@endpoints, 0)
    end

    test "cycles through endpoints in round-robin order" do
      start_manager()

      assert {:ok, ep0} = EndpointManager.get_next_endpoint()
      assert {:ok, ep1} = EndpointManager.get_next_endpoint()
      assert {:ok, ep2} = EndpointManager.get_next_endpoint()
      assert {:ok, ep3} = EndpointManager.get_next_endpoint()

      assert ep0 == Enum.at(@endpoints, 0)
      assert ep1 == Enum.at(@endpoints, 1)
      assert ep2 == Enum.at(@endpoints, 2)
      # Wraps around
      assert ep3 == Enum.at(@endpoints, 0)
    end

    test "skips unhealthy endpoints" do
      start_manager()

      # Mark the first endpoint as unhealthy
      EndpointManager.mark_unhealthy(Enum.at(@endpoints, 0))
      # Allow the cast to be processed
      _ = EndpointManager.get_health_status()

      assert {:ok, ep} = EndpointManager.get_next_endpoint()
      assert ep == Enum.at(@endpoints, 1)
    end

    test "returns error when all endpoints are unhealthy" do
      start_manager()

      Enum.each(@endpoints, &EndpointManager.mark_unhealthy/1)
      # Synchronize by issuing a call
      _ = EndpointManager.get_health_status()

      assert {:error, :no_healthy_endpoints} = EndpointManager.get_next_endpoint()
    end

    test "works with a single endpoint" do
      start_manager(core_endpoints: ["wss://single.local:4000"])

      assert {:ok, "wss://single.local:4000"} = EndpointManager.get_next_endpoint()
      assert {:ok, "wss://single.local:4000"} = EndpointManager.get_next_endpoint()
    end
  end

  # ------------------------------------------------------------------
  # 3. report_failure/1
  # ------------------------------------------------------------------
  describe "report_failure/1" do
    test "increments consecutive failure count" do
      start_manager()

      endpoint = Enum.at(@endpoints, 0)
      EndpointManager.report_failure(endpoint)
      # Synchronize
      statuses = EndpointManager.get_health_status()
      status = Enum.find(statuses, &(&1.url == endpoint))

      assert status.consecutive_failures == 1
      assert status.last_failure != nil
    end

    test "marks endpoint as degraded before reaching threshold" do
      start_manager(failover_threshold: 3)

      endpoint = Enum.at(@endpoints, 0)

      EndpointManager.report_failure(endpoint)
      EndpointManager.report_failure(endpoint)
      statuses = EndpointManager.get_health_status()
      status = Enum.find(statuses, &(&1.url == endpoint))

      assert status.status == :degraded
      assert status.consecutive_failures == 2
    end

    test "marks endpoint as unhealthy after reaching failover threshold" do
      start_manager(failover_threshold: 3)

      endpoint = Enum.at(@endpoints, 0)

      for _ <- 1..3, do: EndpointManager.report_failure(endpoint)
      statuses = EndpointManager.get_health_status()
      status = Enum.find(statuses, &(&1.url == endpoint))

      assert status.status == :unhealthy
      assert status.consecutive_failures == 3
      assert status.backoff_until != nil
    end

    test "resets consecutive successes on failure" do
      start_manager()

      endpoint = Enum.at(@endpoints, 0)

      # Build up successes first
      EndpointManager.report_success(endpoint)
      EndpointManager.report_success(endpoint)
      # Synchronize and verify successes
      s1 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s1.consecutive_successes == 2

      # Now report a failure
      EndpointManager.report_failure(endpoint)
      s2 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))

      assert s2.consecutive_successes == 0
      assert s2.consecutive_failures == 1
    end
  end

  # ------------------------------------------------------------------
  # 4. report_success/1
  # ------------------------------------------------------------------
  describe "report_success/1" do
    test "increments consecutive success count" do
      start_manager()

      endpoint = Enum.at(@endpoints, 0)
      EndpointManager.report_success(endpoint)
      statuses = EndpointManager.get_health_status()
      status = Enum.find(statuses, &(&1.url == endpoint))

      assert status.consecutive_successes == 1
      assert status.last_success != nil
    end

    test "resets consecutive failures on success" do
      start_manager()

      endpoint = Enum.at(@endpoints, 0)

      EndpointManager.report_failure(endpoint)
      EndpointManager.report_failure(endpoint)
      s1 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s1.consecutive_failures == 2

      EndpointManager.report_success(endpoint)
      s2 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))

      assert s2.consecutive_failures == 0
      assert s2.consecutive_successes == 1
    end

    test "restores healthy status after 3 consecutive successes" do
      start_manager(failover_threshold: 2)

      endpoint = Enum.at(@endpoints, 0)

      # Drive the endpoint to unhealthy
      for _ <- 1..2, do: EndpointManager.report_failure(endpoint)
      s1 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s1.status == :unhealthy

      # First two successes should leave it as :degraded
      EndpointManager.report_success(endpoint)
      EndpointManager.report_success(endpoint)
      s2 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s2.status == :degraded

      # Third success promotes to :healthy
      EndpointManager.report_success(endpoint)
      s3 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s3.status == :healthy
      assert s3.backoff_until == nil
    end

    test "clears backoff_until on success" do
      start_manager(failover_threshold: 1)

      endpoint = Enum.at(@endpoints, 0)

      # Trigger backoff
      EndpointManager.report_failure(endpoint)
      s1 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s1.backoff_until != nil

      # Success should clear backoff
      EndpointManager.report_success(endpoint)
      s2 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s2.backoff_until == nil
    end
  end

  # ------------------------------------------------------------------
  # 5. get_health_status/0
  # ------------------------------------------------------------------
  describe "get_health_status/0" do
    test "returns a list with one entry per endpoint" do
      start_manager()

      statuses = EndpointManager.get_health_status()
      assert is_list(statuses)
      assert length(statuses) == length(@endpoints)

      urls = Enum.map(statuses, & &1.url) |> Enum.sort()
      assert urls == Enum.sort(@endpoints)
    end

    test "each entry contains expected keys" do
      start_manager()

      expected_keys =
        [
          :url,
          :status,
          :last_success,
          :last_failure,
          :consecutive_failures,
          :consecutive_successes,
          :backoff_until
        ]
        |> Enum.sort()

      for status <- EndpointManager.get_health_status() do
        assert Map.keys(status) |> Enum.sort() == expected_keys
      end
    end

    test "reflects mixed health states across endpoints" do
      start_manager(failover_threshold: 2)

      [ep0, ep1, ep2] = @endpoints

      # ep0 stays healthy (default)
      # ep1 becomes degraded (1 failure, below threshold)
      EndpointManager.report_failure(ep1)
      # ep2 becomes unhealthy (reaches threshold)
      for _ <- 1..2, do: EndpointManager.report_failure(ep2)

      statuses = EndpointManager.get_health_status()

      status_map = Map.new(statuses, fn s -> {s.url, s} end)

      assert status_map[ep0].status == :healthy
      assert status_map[ep1].status == :degraded
      assert status_map[ep2].status == :unhealthy
    end
  end

  # ------------------------------------------------------------------
  # mark_unhealthy/1 and mark_healthy/1 (manual overrides)
  # ------------------------------------------------------------------
  describe "mark_unhealthy/1 and mark_healthy/1" do
    test "mark_unhealthy sets status and consecutive failures to threshold" do
      start_manager(failover_threshold: 3)

      endpoint = Enum.at(@endpoints, 0)
      EndpointManager.mark_unhealthy(endpoint)

      status =
        EndpointManager.get_health_status()
        |> Enum.find(&(&1.url == endpoint))

      assert status.status == :unhealthy
      assert status.consecutive_failures == 3
    end

    test "mark_healthy restores endpoint and clears backoff" do
      start_manager(failover_threshold: 1)

      endpoint = Enum.at(@endpoints, 0)

      # Drive to unhealthy with backoff
      EndpointManager.report_failure(endpoint)
      s1 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))
      assert s1.status == :unhealthy

      EndpointManager.mark_healthy(endpoint)
      s2 = EndpointManager.get_health_status() |> Enum.find(&(&1.url == endpoint))

      assert s2.status == :healthy
      assert s2.consecutive_failures == 0
      assert s2.backoff_until == nil
    end
  end

  # ------------------------------------------------------------------
  # TLS trust for periodic endpoint health probes
  # ------------------------------------------------------------------
  describe "health probe TLS trust" do
    @tag :tmp_dir
    test "fresh private-CA enrollment uses configured enrollment CA", %{tmp_dir: tmp_dir} do
      ca = generate_ca("SecretHub Private Enrollment CA")
      server = start_tls_health_server!(ca, ["localhost"])
      ca_path = Path.join(tmp_dir, "enrollment-ca.pem")
      File.write!(ca_path, ca.cert_pem)

      Application.put_env(:secrethub_agent, :enrollment_http_options,
        ssl: [cacertfile: ca_path, verify: :verify_peer]
      )

      endpoint = "https://localhost:#{server.port}"
      pid = start_manager(core_endpoints: [endpoint], state_dir: Path.join(tmp_dir, "state"))

      status = run_health_probe(pid, endpoint)
      assert status.last_success != nil
      assert status.last_failure == nil
      assert status.consecutive_successes == 1
    end

    @tag :tmp_dir
    test "enrolled/restarted agent uses persisted runtime CA chain without enrollment CA", %{
      tmp_dir: tmp_dir
    } do
      ca = generate_ca("SecretHub Persisted Runtime CA")
      server = start_tls_health_server!(ca, ["localhost"])
      state_dir = Path.join(tmp_dir, "state")
      endpoint = "https://localhost:#{server.port}"

      write_persisted_identity!(
        state_dir,
        ca.cert_pem,
        "wss://localhost:#{server.port}/agent/socket/websocket",
        "localhost"
      )

      Application.put_env(:secrethub_agent, :enrollment_http_options, [])

      pid = start_manager(core_endpoints: [endpoint], state_dir: state_dir)

      status = run_health_probe(pid, endpoint)
      assert status.last_success != nil
      assert status.last_failure == nil
      assert status.consecutive_successes == 1
    end

    @tag :tmp_dir
    test "persisted CA chain is picked up after enrollment completes without restart", %{
      tmp_dir: tmp_dir
    } do
      ca = generate_ca("SecretHub Transition CA")
      server = start_tls_health_server!(ca, ["localhost"])
      state_dir = Path.join(tmp_dir, "state")
      ca_path = Path.join(tmp_dir, "enrollment-ca.pem")
      File.write!(ca_path, ca.cert_pem)

      Application.put_env(:secrethub_agent, :enrollment_http_options,
        ssl: [cacertfile: ca_path, verify: :verify_peer]
      )

      endpoint = "https://localhost:#{server.port}"
      pid = start_manager(core_endpoints: [endpoint], state_dir: state_dir)

      before_enrollment = run_health_probe(pid, endpoint)
      assert before_enrollment.consecutive_successes == 1
      assert before_enrollment.last_failure == nil

      write_persisted_identity!(
        state_dir,
        ca.cert_pem,
        "wss://localhost:#{server.port}/agent/socket/websocket",
        "localhost"
      )

      Application.put_env(:secrethub_agent, :enrollment_http_options, [])

      after_enrollment = run_health_probe(pid, endpoint)
      assert after_enrollment.consecutive_successes == 2
      assert after_enrollment.last_failure == nil
    end

    @tag :tmp_dir
    test "persisted CA applies only to the matching enrolled endpoint", %{tmp_dir: tmp_dir} do
      ca = generate_ca("SecretHub Scoped CA")
      enrolled_server = start_tls_health_server!(ca, ["localhost"])
      other_server = start_tls_health_server!(ca, ["localhost"])
      state_dir = Path.join(tmp_dir, "state")

      enrolled_endpoint = "https://localhost:#{enrolled_server.port}"
      other_endpoint = "https://localhost:#{other_server.port}"

      write_persisted_identity!(
        state_dir,
        ca.cert_pem,
        "wss://localhost:#{enrolled_server.port}/agent/socket/websocket",
        "localhost"
      )

      Application.put_env(:secrethub_agent, :enrollment_http_options, [])

      pid =
        start_manager(
          core_endpoints: [enrolled_endpoint, other_endpoint],
          state_dir: state_dir
        )

      send(pid, :health_check)
      statuses = EndpointManager.get_health_status() |> Map.new(&{&1.url, &1})

      assert statuses[enrolled_endpoint].last_success != nil
      assert statuses[enrolled_endpoint].last_failure == nil
      assert statuses[other_endpoint].last_failure != nil
      assert statuses[other_endpoint].last_success == nil
    end

    @tag :tmp_dir
    test "normal public-CA operation uses default trust store and retains peer verification", %{
      tmp_dir: tmp_dir
    } do
      test_pid = self()
      endpoint = "https://core.public.example:4665"

      transport = fn :get, url, opts ->
        send(test_pid, {:probe_request, url, opts})
        {:ok, HTTP.Response.new(status: 200, headers: HTTP.Headers.new([]), body: "ok")}
      end

      pid =
        start_manager(
          core_endpoints: [endpoint],
          state_dir: Path.join(tmp_dir, "empty-state"),
          http_options: [transport: transport]
        )

      status = run_health_probe(pid, endpoint)
      assert status.last_success != nil

      assert_received {:probe_request, "https://core.public.example:4665/v1/sys/health", opts}
      assert opts[:redirect] == :manual
      ssl_opts = Keyword.fetch!(opts, :ssl)
      assert ssl_opts[:verify] == :verify_peer
      assert Keyword.has_key?(ssl_opts, :customize_hostname_check)
      refute Keyword.has_key?(ssl_opts, :cacertfile)
      refute Keyword.has_key?(ssl_opts, :cacerts)
    end

    @tag :tmp_dir
    test "normal public-CA operation rejects a server signed by an untrusted private CA", %{
      tmp_dir: tmp_dir
    } do
      private_ca = generate_ca("SecretHub Unconfigured Private CA")
      server = start_tls_health_server!(private_ca, ["localhost"])
      endpoint = "https://localhost:#{server.port}"

      Application.put_env(:secrethub_agent, :enrollment_http_options, [])

      pid = start_manager(core_endpoints: [endpoint], state_dir: Path.join(tmp_dir, "state"))

      status = run_health_probe(pid, endpoint)
      assert status.last_failure != nil
      assert status.last_success == nil
      assert status.consecutive_successes == 0
    end

    @tag :tmp_dir
    test "rejects a server signed by an unrelated CA during fresh enrollment and after enrollment",
         %{tmp_dir: tmp_dir} do
      trusted_ca = generate_ca("SecretHub Trusted CA")
      unrelated_ca = generate_ca("Unrelated Rogue CA")
      server = start_tls_health_server!(unrelated_ca, ["localhost"])
      endpoint = "https://localhost:#{server.port}"

      trusted_ca_path = Path.join(tmp_dir, "trusted-ca.pem")
      File.write!(trusted_ca_path, trusted_ca.cert_pem)

      # Fresh enrollment with wrong CA
      Application.put_env(:secrethub_agent, :enrollment_http_options,
        ssl: [cacertfile: trusted_ca_path, verify: :verify_peer]
      )

      fresh_pid =
        start_manager(core_endpoints: [endpoint], state_dir: Path.join(tmp_dir, "fresh-state"))

      fresh_status = run_health_probe(fresh_pid, endpoint)
      assert fresh_status.last_failure != nil
      assert fresh_status.last_success == nil

      :ok = stop_supervised!(EndpointManager)

      # Enrolled state with wrong CA
      enrolled_state_dir = Path.join(tmp_dir, "enrolled-state")

      write_persisted_identity!(
        enrolled_state_dir,
        trusted_ca.cert_pem,
        "wss://localhost:#{server.port}/agent/socket/websocket",
        "localhost"
      )

      Application.put_env(:secrethub_agent, :enrollment_http_options, [])
      enrolled_pid = start_manager(core_endpoints: [endpoint], state_dir: enrolled_state_dir)

      enrolled_status = run_health_probe(enrolled_pid, endpoint)
      assert enrolled_status.last_failure != nil
      assert enrolled_status.last_success == nil
    end

    @tag :tmp_dir
    test "rejects a server with a mismatched hostname even when signed by the trusted CA", %{
      tmp_dir: tmp_dir
    } do
      ca = generate_ca("SecretHub Hostname Check CA")
      server = start_tls_health_server!(ca, ["wrong-host.example.internal"])
      endpoint = "https://localhost:#{server.port}"

      ca_path = Path.join(tmp_dir, "ca.pem")
      File.write!(ca_path, ca.cert_pem)

      # Fresh enrollment hostname check
      Application.put_env(:secrethub_agent, :enrollment_http_options,
        ssl: [cacertfile: ca_path, verify: :verify_peer]
      )

      fresh_pid =
        start_manager(core_endpoints: [endpoint], state_dir: Path.join(tmp_dir, "fresh-state"))

      fresh_status = run_health_probe(fresh_pid, endpoint)
      assert fresh_status.last_failure != nil
      assert fresh_status.last_success == nil

      :ok = stop_supervised!(EndpointManager)

      # Enrolled state hostname check
      enrolled_state_dir = Path.join(tmp_dir, "enrolled-state")

      write_persisted_identity!(
        enrolled_state_dir,
        ca.cert_pem,
        "wss://localhost:#{server.port}/agent/socket/websocket",
        "localhost"
      )

      Application.put_env(:secrethub_agent, :enrollment_http_options, [])
      enrolled_pid = start_manager(core_endpoints: [endpoint], state_dir: enrolled_state_dir)

      enrolled_status = run_health_probe(enrolled_pid, endpoint)
      assert enrolled_status.last_failure != nil
      assert enrolled_status.last_success == nil
    end

    @tag :tmp_dir
    test "retains peer verification even if enrollment_http_options requests verify_none", %{
      tmp_dir: tmp_dir
    } do
      trusted_ca = generate_ca("SecretHub Trusted CA")
      unrelated_ca = generate_ca("Unrelated CA")
      server = start_tls_health_server!(unrelated_ca, ["localhost"])
      endpoint = "https://localhost:#{server.port}"

      ca_path = Path.join(tmp_dir, "ca.pem")
      File.write!(ca_path, trusted_ca.cert_pem)

      Application.put_env(:secrethub_agent, :enrollment_http_options,
        ssl: [cacertfile: ca_path, verify: :verify_none]
      )

      pid = start_manager(core_endpoints: [endpoint], state_dir: Path.join(tmp_dir, "state"))

      status = run_health_probe(pid, endpoint)
      assert status.last_failure != nil
      assert status.last_success == nil
    end
  end

  defp run_health_probe(pid, endpoint) do
    send(pid, :health_check)

    EndpointManager.get_health_status()
    |> Enum.find(&(&1.url == endpoint))
  end

  defp generate_ca(common_name) do
    key = X509.PrivateKey.new_ec(:secp256r1)
    cert = X509.Certificate.self_signed(key, "/CN=#{common_name}", template: :root_ca)

    %{
      key: key,
      cert: cert,
      cert_pem: X509.Certificate.to_pem(cert)
    }
  end

  defp start_tls_health_server!(ca, dns_names) do
    server_key = X509.PrivateKey.new_ec(:secp256r1)

    server_cert =
      server_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/CN=#{hd(dns_names)}",
        ca.cert,
        ca.key,
        extensions: [
          subject_alt_name: Extension.subject_alt_name(dns_names)
        ]
      )

    {:ok, listener} =
      :ssl.listen(0, [
        :binary,
        active: false,
        packet: :raw,
        reuseaddr: true,
        versions: [:"tlsv1.3", :"tlsv1.2"],
        cert: X509.Certificate.to_der(server_cert),
        key: {:PrivateKeyInfo, X509.PrivateKey.to_der(server_key, wrap: true)}
      ])

    {:ok, {_addr, port}} = :ssl.sockname(listener)

    acceptor = spawn(fn -> accept_tls_health_loop(listener) end)

    on_exit(fn ->
      Process.exit(acceptor, :kill)
      :ssl.close(listener)
    end)

    %{port: port, listener: listener}
  end

  defp accept_tls_health_loop(listener) do
    case :ssl.transport_accept(listener, 5_000) do
      {:ok, transport_socket} ->
        spawn(fn -> handle_tls_health_connection(transport_socket) end)
        accept_tls_health_loop(listener)

      {:error, :timeout} ->
        accept_tls_health_loop(listener)

      {:error, _closed} ->
        :ok
    end
  end

  defp handle_tls_health_connection(transport_socket) do
    with {:ok, socket} <- :ssl.handshake(transport_socket, 2_000),
         {:ok, request} <- :ssl.recv(socket, 0, 2_000) do
      response =
        if String.starts_with?(request, "GET /v1/sys/health ") do
          "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 15\r\nconnection: close\r\n\r\n{\"status\":\"ok\"}"
        else
          "HTTP/1.1 404 Not Found\r\ncontent-length: 9\r\nconnection: close\r\n\r\nnot found"
        end

      :ssl.send(socket, response)
      :ssl.close(socket)
    else
      _ -> :ssl.close(transport_socket)
    end
  end

  defp write_persisted_identity!(state_dir, ca_chain_pem, trusted_endpoint, expected_server_name) do
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    private_key_pem = X509.PrivateKey.to_pem(private_key, wrap: true)

    certificate_pem =
      private_key
      |> X509.Certificate.self_signed("/CN=agent-probe-test")
      |> X509.Certificate.to_pem()

    assert :ok =
             IdentityStore.write(state_dir, %{
               agent_id: "agent-probe-test",
               certificate_pem: certificate_pem,
               private_key_pem: private_key_pem,
               ca_chain_pem: ca_chain_pem,
               connect_info: %{
                 "trusted_websocket_endpoint" => trusted_endpoint,
                 "expected_core_server_name" => expected_server_name
               },
               identity: %{
                 "agent_id" => "agent-probe-test",
                 "enrollment_id" => "enrollment-probe-test",
                 "certificate_fingerprint" => "SHA256:probe-test"
               }
             })
  end
end
