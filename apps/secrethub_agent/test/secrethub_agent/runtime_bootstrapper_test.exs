defmodule SecretHub.Agent.RuntimeBootstrapperTest do
  use ExUnit.Case, async: false

  alias SecretHub.Agent.{Connection, IdentityStore, RuntimeBootstrapper}

  @moduletag :tmp_dir

  setup do
    stop_registered_process(Connection)

    on_exit(fn ->
      stop_registered_process(Connection)
    end)

    :ok
  end

  test "plan_start returns ready material when trusted identity exists", %{tmp_dir: tmp_dir} do
    state_dir = Path.join(tmp_dir, "agent-state")
    material = valid_material()

    assert :ok = IdentityStore.write(state_dir, material)

    assert {:ok, :ready_for_runtime, %IdentityStore{} = loaded} =
             RuntimeBootstrapper.plan_start(state_dir)

    assert loaded.agent_id == material.agent_id
    assert loaded.private_key_pem == material.private_key_pem
  end

  test "plan_start keeps pending finalization when trusted identity still has a pending token", %{
    tmp_dir: tmp_dir
  } do
    state_dir = Path.join(tmp_dir, "agent-state")
    material = valid_material()

    pending = %{
      "enrollment_id" => "enrollment-1",
      "pending_token" => "pending-token",
      "enrollment_core_url" => "https://enrolled-core.example"
    }

    assert :ok = IdentityStore.write(state_dir, material)
    assert :ok = File.write(Path.join(state_dir, "pending.json"), Jason.encode!(pending))

    assert {:ok, :ready_for_runtime, %IdentityStore{}, ^pending} =
             RuntimeBootstrapper.plan_start(state_dir)
  end

  test "restart with trusted material and pending token uses the persisted enrollment URL", %{
    tmp_dir: tmp_dir
  } do
    state_dir = Path.join(tmp_dir, "agent-state")

    material =
      valid_material(%{
        "trusted_websocket_endpoint" => "wss://127.0.0.1:1",
        "expected_core_server_name" => "localhost",
        "connect_timeout_ms" => 10_000
      })

    pending = %{
      "enrollment_id" => "enrollment-1",
      "pending_token" => "pending-token",
      "enrollment_core_url" => "https://enrolled-core.example"
    }

    assert :ok = IdentityStore.write(state_dir, material)
    assert :ok = File.write(Path.join(state_dir, "pending.json"), Jason.encode!(pending))

    assert {:noreply, state} =
             RuntimeBootstrapper.handle_continue(:start_runtime, %RuntimeBootstrapper{
               core_url: "https://fallback-core.example",
               state_dir: state_dir,
               legacy_connection_opts: []
             })

    assert state.pending_finalization.core_url == "https://enrolled-core.example"
  end

  test "plan_start returns needs enrollment when trusted identity is missing", %{tmp_dir: tmp_dir} do
    assert {:ok, :needs_enrollment} = RuntimeBootstrapper.plan_start(tmp_dir)
  end

  test "plan_start returns legacy runtime when certificate paths are configured", %{
    tmp_dir: tmp_dir
  } do
    cert_path = Path.join(tmp_dir, "agent-cert.pem")
    key_path = Path.join(tmp_dir, "agent-key.pem")
    ca_path = Path.join(tmp_dir, "ca-chain.pem")

    File.write!(cert_path, "cert")
    File.write!(key_path, "key")
    File.write!(ca_path, "ca")

    opts = [
      agent_id: "legacy-agent",
      core_endpoints: ["wss://core.example/agent/socket/websocket"],
      cert_path: cert_path,
      key_path: key_path,
      ca_path: ca_path
    ]

    assert {:ok, :ready_for_legacy_runtime, ^opts} =
             RuntimeBootstrapper.plan_start(Path.join(tmp_dir, "missing-state"), opts)
  end

  test "converts websocket core URLs to enrollment HTTP URLs" do
    assert {:ok, "http://localhost:4664"} =
             RuntimeBootstrapper.enrollment_core_url("ws://localhost:4664")

    assert {:ok, "https://core.example:4664"} =
             RuntimeBootstrapper.enrollment_core_url("wss://core.example:4664/socket")

    assert {:ok, "https://core.example:4664"} =
             RuntimeBootstrapper.enrollment_core_url("https://core.example:4664")
  end

  test "rejects insecure enrollment URLs unless explicitly allowed" do
    original = Application.get_env(:secrethub_agent, :allow_insecure_enrollment)

    on_exit(fn ->
      restore_env(:allow_insecure_enrollment, original)
    end)

    Application.put_env(:secrethub_agent, :allow_insecure_enrollment, false)

    assert {:error, :insecure_enrollment_url} =
             RuntimeBootstrapper.enrollment_core_url("ws://core.example:4664")

    assert {:error, :insecure_enrollment_url} =
             RuntimeBootstrapper.enrollment_core_url("http://core.example:4664")

    Application.put_env(:secrethub_agent, :allow_insecure_enrollment, true)

    assert {:ok, "http://core.example:4664"} =
             RuntimeBootstrapper.enrollment_core_url("ws://core.example:4664")
  end

  test "builds trusted runtime options from loaded material" do
    private_key_pem = private_key_pem()

    connect_info = %{
      "trusted_websocket_endpoint" => "wss://core.example/agent/socket/websocket",
      "expected_core_server_name" => "core.example"
    }

    material = %IdentityStore{
      agent_id: "agent-1",
      certificate_pem: "agent-cert",
      private_key_pem: private_key_pem,
      ca_chain_pem: "ca-cert",
      connect_info: connect_info
    }

    callback = fn _payload -> :ok end

    assert [
             agent_id: "agent-1",
             connect_info: ^connect_info,
             certificate_pem: "agent-cert",
             private_key_pem: ^private_key_pem,
             ca_pem: "ca-cert",
             on_runtime_accepted: ^callback
           ] = RuntimeBootstrapper.trusted_connection_opts(material, callback)
  end

  test "accepted callback sends the runtime accepted payload to the owner" do
    callback = RuntimeBootstrapper.runtime_accepted_callback(self())
    payload = %{"agent_id" => "agent-1"}

    assert :ok = callback.(payload)
    assert_received {:runtime_accepted, ^payload}
  end

  test "accepted runtime message finalizes enrollment and deletes the pending token", %{
    tmp_dir: tmp_dir
  } do
    Req.Test.verify_on_exit!()

    state_dir = Path.join(tmp_dir, "agent-state")
    pending = %{"enrollment_id" => "enrollment-1", "pending_token" => "pending-token"}
    assert :ok = File.mkdir_p(state_dir)
    assert :ok = File.write(Path.join(state_dir, "pending.json"), Jason.encode!(pending))

    Req.Test.expect(__MODULE__, fn conn ->
      assert conn.method == "POST"
      assert conn.request_path == "/v1/agent/enrollments/enrollment-1/finalize"
      assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer pending-token"]
      assert conn.body_params == %{"status" => "trusted_connected"}

      Req.Test.json(conn, %{"status" => "finalized"})
    end)

    Application.put_env(:secrethub_agent, :enrollment_req_options, plug: {Req.Test, __MODULE__})

    on_exit(fn ->
      Application.delete_env(:secrethub_agent, :enrollment_req_options)
    end)

    timer = Process.send_after(self(), :unused_runtime_accept_timeout, 10_000)

    state = %RuntimeBootstrapper{
      state_dir: state_dir,
      pending_finalization: %{
        core_url: "https://core.example:4664",
        pending: pending,
        timer: timer
      }
    }

    assert {:noreply, next_state} =
             RuntimeBootstrapper.handle_info(
               {:runtime_accepted, %{"agent_id" => "agent-1"}},
               state
             )

    assert next_state.pending_finalization == nil
    refute File.exists?(Path.join(state_dir, "pending.json"))
  end

  test "accepted runtime finalization failure keeps pending state and retry can finalize", %{
    tmp_dir: tmp_dir
  } do
    Req.Test.verify_on_exit!()

    state_dir = Path.join(tmp_dir, "agent-state")
    pending = %{"enrollment_id" => "enrollment-1", "pending_token" => "pending-token"}
    assert :ok = File.mkdir_p(state_dir)
    assert :ok = File.write(Path.join(state_dir, "pending.json"), Jason.encode!(pending))

    {:ok, counter} = Agent.start_link(fn -> 0 end)

    Req.Test.expect(__MODULE__, 2, fn conn ->
      assert conn.method == "POST"
      assert conn.request_path == "/v1/agent/enrollments/enrollment-1/finalize"
      assert conn.body_params == %{"status" => "trusted_connected"}

      Agent.get_and_update(counter, fn count -> {count, count + 1} end)
      |> case do
        0 ->
          conn
          |> Plug.Conn.put_status(503)
          |> Req.Test.json(%{"error" => "temporarily unavailable"})

        1 ->
          Req.Test.json(conn, %{"status" => "finalized"})
      end
    end)

    Application.put_env(:secrethub_agent, :enrollment_req_options, plug: {Req.Test, __MODULE__})

    on_exit(fn ->
      Application.delete_env(:secrethub_agent, :enrollment_req_options)
    end)

    timer = Process.send_after(self(), :unused_runtime_accept_timeout, 10_000)

    state = %RuntimeBootstrapper{
      state_dir: state_dir,
      pending_finalization: %{
        core_url: "https://core.example:4664",
        pending: pending,
        timer: timer,
        phase: :waiting_for_runtime,
        retry_count: 0
      }
    }

    assert {:noreply, retry_state} =
             RuntimeBootstrapper.handle_info(
               {:runtime_accepted, %{"agent_id" => "agent-1"}},
               state
             )

    assert retry_state.pending_finalization.phase == :finalize_success_retry
    assert retry_state.pending_finalization.retry_count == 1
    assert File.exists?(Path.join(state_dir, "pending.json"))

    assert {:noreply, finalized_state} =
             RuntimeBootstrapper.handle_info(:runtime_finalize_success_retry, retry_state)

    assert finalized_state.pending_finalization == nil
    refute File.exists?(Path.join(state_dir, "pending.json"))
  end

  test "trusted runtime start failure keeps pending token and schedules retry", %{
    tmp_dir: tmp_dir
  } do
    Req.Test.verify_on_exit!()

    state_dir = Path.join(tmp_dir, "agent-state")

    pending = %{
      "enrollment_id" => "enrollment-1",
      "pending_token" => "pending-token",
      "enrollment_core_url" => "https://core.example:4664"
    }

    material =
      valid_material(%{
        "trusted_websocket_endpoint" => "wss://127.0.0.1:1",
        "expected_core_server_name" => "localhost",
        "connect_timeout_ms" => 10_000
      })
      |> Map.put(:private_key_pem, "not a private key")

    assert :ok = IdentityStore.write(state_dir, material)
    assert :ok = File.write(Path.join(state_dir, "pending.json"), Jason.encode!(pending))

    Application.put_env(:secrethub_agent, :enrollment_req_options, plug: {Req.Test, __MODULE__})

    on_exit(fn ->
      Application.delete_env(:secrethub_agent, :enrollment_req_options)
    end)

    assert {:noreply, retry_state} =
             RuntimeBootstrapper.handle_continue(:start_runtime, %RuntimeBootstrapper{
               core_url: "https://fallback-core.example",
               state_dir: state_dir,
               legacy_connection_opts: []
             })

    assert retry_state.runtime_pid == nil
    assert retry_state.pending_finalization.phase == :runtime_start_retry
    assert retry_state.pending_finalization.retry_count == 1
    assert File.exists?(Path.join(state_dir, "pending.json"))

    Process.cancel_timer(retry_state.pending_finalization.timer)
  end

  test "runtime accept timeout finalizes enrollment failure", %{tmp_dir: tmp_dir} do
    Req.Test.verify_on_exit!()

    state_dir = Path.join(tmp_dir, "agent-state")
    pending = %{"enrollment_id" => "enrollment-1", "pending_token" => "pending-token"}
    timer = Process.send_after(self(), :unused_runtime_accept_timeout, 10_000)
    assert :ok = IdentityStore.write(state_dir, valid_material())
    assert :ok = File.write(Path.join(state_dir, "pending.json"), Jason.encode!(pending))

    Req.Test.expect(__MODULE__, fn conn ->
      assert conn.method == "POST"
      assert conn.request_path == "/v1/agent/enrollments/enrollment-1/finalize"
      assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer pending-token"]

      assert conn.body_params == %{
               "status" => "trusted_endpoint_failed",
               "error" => %{
                 "phase" => "trusted_runtime_connect",
                 "message" => "timed out waiting for trusted runtime connection"
               }
             }

      Req.Test.json(conn, %{"status" => "failed"})
    end)

    Application.put_env(:secrethub_agent, :enrollment_req_options, plug: {Req.Test, __MODULE__})

    on_exit(fn ->
      Application.delete_env(:secrethub_agent, :enrollment_req_options)
    end)

    state = %RuntimeBootstrapper{
      state_dir: state_dir,
      pending_finalization: %{
        core_url: "https://core.example:4664",
        pending: pending,
        timer: timer
      }
    }

    assert {:stop, :trusted_runtime_connect_timeout, next_state} =
             RuntimeBootstrapper.handle_info(:runtime_accept_timeout, state)

    assert next_state.pending_finalization == nil
    refute File.exists?(Path.join(state_dir, "pending.json"))
    refute File.exists?(Path.join(state_dir, "agent-cert.pem"))
    refute File.exists?(Path.join(state_dir, "agent-key.pem"))
    refute File.exists?(Path.join(state_dir, "ca-chain.pem"))
    refute File.exists?(Path.join(state_dir, "connect-info.json"))
    refute File.exists?(Path.join(state_dir, "identity.json"))
  end

  test "runtime accept timeout clears pending after idempotent failure finalization", %{
    tmp_dir: tmp_dir
  } do
    Req.Test.verify_on_exit!()

    state_dir = Path.join(tmp_dir, "agent-state")
    pending = %{"enrollment_id" => "enrollment-1", "pending_token" => "pending-token"}
    timer = Process.send_after(self(), :unused_runtime_accept_timeout, 10_000)
    assert :ok = File.mkdir_p(state_dir)
    assert :ok = File.write(Path.join(state_dir, "pending.json"), Jason.encode!(pending))

    Req.Test.expect(__MODULE__, fn conn ->
      assert conn.method == "POST"
      assert conn.request_path == "/v1/agent/enrollments/enrollment-1/finalize"
      assert conn.body_params["status"] == "trusted_endpoint_failed"

      Req.Test.json(conn, %{"status" => "trusted_endpoint_failed"})
    end)

    Application.put_env(:secrethub_agent, :enrollment_req_options, plug: {Req.Test, __MODULE__})

    on_exit(fn ->
      Application.delete_env(:secrethub_agent, :enrollment_req_options)
    end)

    state = %RuntimeBootstrapper{
      state_dir: state_dir,
      pending_finalization: %{
        core_url: "https://core.example:4664",
        pending: pending,
        timer: timer
      }
    }

    assert {:stop, :trusted_runtime_connect_timeout, next_state} =
             RuntimeBootstrapper.handle_info(:runtime_accept_timeout, state)

    assert next_state.pending_finalization == nil
    refute File.exists?(Path.join(state_dir, "pending.json"))
  end

  defp valid_material(
         connect_info \\ %{
           "trusted_websocket_endpoint" => "wss://core.example/agent/socket/websocket"
         }
       ) do
    {private_key_pem, certificate_pem} = certificate_material()

    %{
      agent_id: "agent-1",
      certificate_pem: certificate_pem,
      private_key_pem: private_key_pem,
      ca_chain_pem: certificate_pem,
      connect_info: connect_info,
      identity: %{
        "agent_id" => "agent-1",
        "enrollment_id" => "enrollment-1",
        "certificate_fingerprint" => "SHA256:certificate"
      }
    }
  end

  defp private_key_pem do
    {private_key_pem, _certificate_pem} = certificate_material()
    private_key_pem
  end

  defp certificate_material do
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    private_key_pem = X509.PrivateKey.to_pem(private_key, wrap: true)

    certificate_pem =
      private_key
      |> X509.Certificate.self_signed("/CN=agent-1")
      |> X509.Certificate.to_pem()

    {private_key_pem, certificate_pem}
  end

  defp stop_registered_process(name) do
    try do
      case Process.whereis(name) do
        nil -> :ok
        pid -> GenServer.stop(pid, :normal, 1000)
      end
    catch
      :exit, _reason -> :ok
    end
  end

  defp restore_env(key, nil), do: Application.delete_env(:secrethub_agent, key)
  defp restore_env(key, value), do: Application.put_env(:secrethub_agent, key, value)
end
