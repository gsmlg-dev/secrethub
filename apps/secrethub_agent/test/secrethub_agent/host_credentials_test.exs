defmodule SecretHub.Agent.HostCredentialsTest do
  use ExUnit.Case, async: false

  alias SecretHub.Agent.AccessAudit.Journal
  alias SecretHub.Agent.{Cache, CertVerifier, UDSServer}
  alias SecretHub.Agent.CredentialCoreFixture
  alias SecretHub.Agent.HostCredentials.Provider

  @moduletag :tmp_dir
  @entry "11111111-2222-4333-8444-555555555555"

  setup %{tmp_dir: dir} do
    {:ok, _} = Application.ensure_all_started(:telemetry)
    start_supervised!({Journal, state_dir: dir})
    start_supervised!(CertVerifier)
    start_supervised!(Cache)
    start_supervised!({Task.Supervisor, name: SecretHub.Agent.HostCredentials.Tasks})
    start_supervised!({CredentialCoreFixture, owner: self()})
    path = Path.join(System.tmp_dir!(), "sh-hc-#{System.unique_integer([:positive])}.sock")
    on_exit(fn -> File.rm(path) end)
    start_supervised!({UDSServer, socket_path: path, request_timeout: 5_000})
    :ok = UDSServer.configure_runtime("agent-1", 2, ["host_credentials_v1"])
    %{path: path}
  end

  test "credential operations are forwarded with audit correlation and Agent-only identity",
       %{path: path} do
    socket = connect(path)

    reply_with(fn "get", payload ->
      assert payload["namespace"] == "generic" and payload["account"] == "u"
      assert is_binary(payload["audit_request_id"]) and is_binary(payload["audit_attempt_id"])
      refute Map.has_key?(payload, "agent_id")
      {:ok, get_response("v-1", 1, 1)}
    end)

    assert %{"status" => "ok", "data" => %{"value" => "v-1", "username" => "u"}} =
             request(socket, "credential_get", generic())

    await_phases(4)
    assert {:ok, events} = Journal.batch()

    assert Enum.all?(events, fn event ->
             event["schema_version"] == 2 and event["operation"] == "credential_read" and
               event["application_id"] == nil and event["identity_status"] == "unverified"
           end)

    refute Jason.encode!(events) =~ "v-1"
  end

  test "cached values are released only after Core confirms the exact revisions",
       %{path: path} do
    socket = connect(path)
    reply_with(fn "get", _ -> {:ok, get_response("v-1", 1, 4)} end)
    assert %{"data" => %{"value" => "v-1"}} = request(socket, "credential_get", generic())

    reply_with(fn "get", payload ->
      assert payload["known"] == %{
               "entry_id" => @entry,
               "binding_revision" => 1,
               "source_revision" => 4
             }

      {:ok,
       Map.merge(Map.drop(get_response("x", 1, 4), ["value", "username"]), %{
         "not_modified" => true
       })}
    end)

    assert %{"data" => %{"value" => "v-1"}} = request(socket, "credential_get", generic())

    # A later denial never releases the cached plaintext and drops the entry.
    reply_with(fn "get", _ -> {:error, %{"reason" => "FORBIDDEN"}} end)
    assert %{"error" => %{"code" => "FORBIDDEN"}} = request(socket, "credential_get", generic())

    reply_with(fn "get", payload ->
      assert payload["known"] == nil
      {:ok, %{"not_modified" => true, "entry_id" => @entry}}
    end)

    assert %{"error" => %{"code" => "UNAVAILABLE"}} = request(socket, "credential_get", generic())
  end

  test "a cached value is never released while the audit journal is unavailable",
       %{path: path} do
    socket = connect(path)
    reply_with(fn "get", _ -> {:ok, get_response("v-1", 1, 4)} end)
    assert %{"data" => %{"value" => "v-1"}} = request(socket, "credential_get", generic())

    stop_supervised!(Journal)
    reply_with(fn _, _ -> flunk("Core must not be called without audit admission") end)

    response = request(socket, "credential_get", generic())
    assert %{"error" => %{"code" => "AUDIT_UNAVAILABLE"}} = response
    refute Jason.encode!(response) =~ "v-1"
  end

  test "a slow Core call does not stall other clients and replies keep their request ids",
       %{path: path} do
    slow = connect(path)
    fast = connect(path)

    reply_with(fn
      "get", %{"account" => "slow"} ->
        Process.sleep(1_500)
        {:ok, get_response("slow-value", 1, 1)}

      "get", _ ->
        {:ok, get_response("fast-value", 1, 1)}
    end)

    send_frame(slow, "slow-1", "credential_get", Map.put(generic(), "account", "slow"))
    started = System.monotonic_time(:millisecond)

    assert %{"request_id" => "fast-1", "data" => %{"value" => "fast-value"}} =
             request(fast, "credential_get", generic(), "fast-1")

    assert System.monotonic_time(:millisecond) - started < 1_000
    assert %{"request_id" => "slow-1", "data" => %{"value" => "slow-value"}} = recv(slow)
  end

  test "rollback to a v1-only Core retains v2 evidence and obeys journal delivery gates",
       %{path: path, tmp_dir: dir} do
    socket = connect(path)
    reply_with(fn "get", _ -> {:ok, get_response("v-1", 1, 1)} end)
    assert %{"data" => %{"value" => "v-1"}} = request(socket, "credential_get", generic())
    await_phases(4)
    {:ok, events} = Journal.batch()
    ids = Enum.map(events, & &1["event_id"])

    # An older Core rejects schema v2; the Reporter quarantines rather than discards.
    assert :ok = Journal.quarantine(ids, "unsupported_schema")
    assert {:ok, []} = Journal.batch()

    # Evidence survives restart; a full quarantine stops new deliveries.
    stop_supervised!(Journal)
    start_supervised!({Journal, state_dir: dir, max_quarantine: length(ids)})
    assert {:ok, quarantined} = Journal.quarantined()
    assert Enum.sort(Enum.map(quarantined, & &1["event_id"])) == Enum.sort(ids)

    reply_with(fn _, _ -> flunk("Core must not be called while audit admission is closed") end)

    assert %{"error" => %{"code" => "AUDIT_UNAVAILABLE"}} =
             request(socket, "credential_get", generic())

    # After restoring a v2-capable Core, explicit replay restores the originals.
    assert :ok = Journal.replay_quarantined(ids)
    assert {:ok, replayed} = Journal.batch()
    assert Enum.sort_by(replayed, & &1["event_id"]) == Enum.sort_by(events, & &1["event_id"])
    assert Enum.all?(replayed, &(&1["schema_version"] == 2))

    reply_with(fn "get", _ -> {:ok, get_response("v-2", 1, 2)} end)
    assert %{"data" => %{"value" => "v-2"}} = request(socket, "credential_get", generic())
  end

  test "write timeouts are reported as unconfirmed, not as failures", %{path: path} do
    socket = connect(path)
    reply_with(fn "put", _ -> {:error, :timeout} end)
    put = Map.put(generic(), "value", "new")
    assert %{"error" => %{"code" => "UNCONFIRMED"}} = request(socket, "credential_put", put)
  end

  test "invalid requests, missing capability and application connections are refused",
       %{path: path} do
    socket = connect(path)
    reply_with(fn _, _ -> flunk("Core must not be called") end)

    assert %{"error" => %{"code" => "INVALID_REQUEST"}} =
             request(socket, "credential_get", Map.put(generic(), "agent_id", "spoofed"))

    :ok = UDSServer.configure_runtime("agent-1", 2, [])
    other = connect(path)

    assert %{"error" => %{"code" => "INCOMPATIBLE_VERSION"}} =
             request(other, "credential_get", generic())

    :ok = UDSServer.configure_runtime("agent-1", 2, ["host_credentials_v1"])
    app = connect(path)
    request(app, "authenticate", %{"auth_version" => 2, "certificate" => "invalid"})

    assert %{"error" => %{"code" => "AGENT_SCOPE_REQUIRED"}} =
             request(app, "credential_get", generic())
  end

  test "list pages are trimmed to the frame limit without skipping entries", %{path: path} do
    socket = connect(path)

    entries =
      for i <- 1..60 do
        %{
          "entry_id" =>
            "00000000-0000-4000-8000-#{String.pad_leading(Integer.to_string(i), 12, "0")}",
          "namespace" => "generic",
          "service" => String.duplicate("s", 250),
          "context" => "",
          "authority" => "",
          "account" => String.duplicate("a", 500),
          "username" => String.duplicate("a", 500)
        }
      end

    reply_with(fn "list", _ -> {:ok, %{"entries" => entries, "next_cursor" => nil}} end)
    response = request(socket, "credential_list", %{"namespace" => "generic"})
    returned = response["data"]["entries"]
    assert length(returned) < 60
    assert response["data"]["next_cursor"] == List.last(returned)["entry_id"]
    assert returned == Enum.take(entries, length(returned))
  end

  describe "systemd provider" do
    test "writes raw bytes to an allowed peer and nothing on denial", %{tmp_dir: dir} do
      uid = current_uid()

      config = %{
        socket_dir: short_dir(dir),
        allowed_uids: [uid],
        endpoints: [%{name: "db", entry_id: @entry, field: "value", units: []}]
      }

      start_supervised!({Provider, config: config})
      socket_path = Path.join(config.socket_dir, "db.sock")

      reply_with(fn "get", %{"entry_id" => @entry} -> {:ok, get_response("raw\nbytes", 1, 1)} end)
      assert read_all(socket_path) == "raw\nbytes"

      reply_with(fn "get", _ -> {:error, %{"reason" => "FORBIDDEN"}} end)
      assert read_all(socket_path) == ""

      reply_with(fn "get", _ -> {:ok, get_response("", 1, 1)} end)
      assert read_all(socket_path) == ""
    end

    test "refuses peers outside the allowed UIDs without calling Core", %{tmp_dir: dir} do
      config = %{
        socket_dir: short_dir(dir),
        allowed_uids: [current_uid() + 1],
        endpoints: [%{name: "db", entry_id: @entry, field: "value", units: []}]
      }

      start_supervised!({Provider, config: config})
      reply_with(fn _, _ -> flunk("Core must not be called") end)
      assert read_all(Path.join(config.socket_dir, "db.sock")) == ""
    end

    test "configuration accepts only identifiers and bounded names" do
      good =
        Jason.encode!(%{
          "socket_dir" => "/run/secrethub-credentials",
          "providers" => %{"db-password" => %{"entry_id" => @entry, "field" => "value"}}
        })

      assert {:ok, %{allowed_uids: [0], endpoints: [%{name: "db-password"}]}} =
               Provider.parse_config(good)

      for providers <- [
            %{"../x" => %{"entry_id" => @entry, "field" => "value"}},
            %{"db" => %{"entry_id" => "prod.db.password", "field" => "value"}},
            %{"db" => %{"entry_id" => @entry, "field" => "password", "value" => "plain"}}
          ] do
        json = Jason.encode!(%{"socket_dir" => "/run/x", "providers" => providers})
        assert {:error, _} = Provider.parse_config(json)
      end
    end
  end

  describe "static secret publication" do
    setup do
      :ok = UDSServer.configure_runtime("agent-1", 2, ["host_credentials_v1", "secret_write_v1"])
    end

    test "secret_put is forwarded with audit correlation and returns no value", %{path: path} do
      socket = connect(path)

      reply_with(fn "secret:write", payload ->
        assert payload["path"] == "backplane.llm.openai-main"
        assert payload["data"] == %{"api_key" => "sk-canary"}
        assert is_binary(payload["audit_request_id"]) and is_binary(payload["audit_attempt_id"])
        refute Map.has_key?(payload, "expected_version")
        refute Map.has_key?(payload, "agent_id")

        {:ok,
         %{
           "status" => "created",
           "path" => payload["path"],
           "version" => 1,
           "audit_event_id" => Ecto.UUID.generate()
         }}
      end)

      response =
        request(socket, "secret_put", %{
          "path" => "backplane.llm.openai-main",
          "data" => %{"api_key" => "sk-canary"}
        })

      assert %{
               "status" => "ok",
               "data" => %{
                 "status" => "created",
                 "path" => "backplane.llm.openai-main",
                 "version" => 1
               }
             } = response

      await_phases(4)
      assert {:ok, events} = Journal.batch()

      assert Enum.all?(events, &(&1["schema_version"] == 2 and &1["operation"] == "secret_write"))
      assert Enum.any?(events, &(&1["secret_path"] == "backplane.llm.openai-main"))
      refute Jason.encode!([response, events]) =~ "sk-canary"
    end

    test "Core conflicts, denials and lost replies keep distinct codes", %{path: path} do
      socket = connect(path)
      delete = %{"path" => "backplane.llm.openai-main", "expected_version" => 3}

      reply_with(fn "secret:delete", %{"expected_version" => 3} ->
        {:error, %{"reason" => "CONFLICT"}}
      end)

      assert %{"error" => %{"code" => "CONFLICT"}} = request(socket, "secret_delete", delete)

      reply_with(fn "secret:delete", _ -> {:error, %{"reason" => "FORBIDDEN"}} end)
      assert %{"error" => %{"code" => "FORBIDDEN"}} = request(socket, "secret_delete", delete)

      # A mutation whose reply is lost may have been applied.
      reply_with(fn "secret:delete", _ -> {:error, :timeout} end)
      assert %{"error" => %{"code" => "UNCONFIRMED"}} = request(socket, "secret_delete", delete)
    end

    test "invalid requests and unnegotiated Cores never reach Core", %{path: path} do
      socket = connect(path)
      reply_with(fn _, _ -> flunk("Core must not be called") end)

      for params <- [
            %{"path" => "Upper.Case", "data" => %{"k" => "v"}},
            %{"path" => "host-credentials.x.generic", "data" => %{"k" => "v"}},
            %{"path" => "backplane.k", "data" => %{"k" => 1}}
          ] do
        assert %{"error" => %{"code" => "INVALID_REQUEST"}} =
                 request(socket, "secret_put", params)
      end

      :ok = UDSServer.configure_runtime("agent-1", 2, ["host_credentials_v1"])
      socket = connect(path)

      assert %{"error" => %{"code" => "INCOMPATIBLE_VERSION"}} =
               request(socket, "secret_put", %{"path" => "backplane.k", "data" => %{"k" => "v"}})
    end
  end

  ## Helpers

  defp generic,
    do: %{"namespace" => "generic", "service" => "svc", "account" => "u"}

  defp get_response(value, binding, source) do
    %{
      "entry_id" => @entry,
      "namespace" => "generic",
      "source_kind" => "owned",
      "resource" => "host-credentials.agent.generic.#{@entry}",
      "binding_revision" => binding,
      "source_revision" => source,
      "secret_version" => 1,
      "username" => "u",
      "value" => value,
      "audit_event_id" => Ecto.UUID.generate()
    }
  end

  defp reply_with(fun), do: CredentialCoreFixture.set(fun)

  defp connect(path) do
    {:ok, socket} =
      :gen_tcp.connect(
        {:local, to_charlist(path)},
        0,
        [:binary, packet: :line, buffer: 65_536, active: false],
        1000
      )

    on_exit(fn -> :gen_tcp.close(socket) end)
    socket
  end

  defp send_frame(socket, id, action, params) do
    :ok =
      :gen_tcp.send(
        socket,
        Jason.encode!(%{request_id: id, action: action, params: params}) <> "\n"
      )
  end

  defp request(socket, action, params, id \\ Ecto.UUID.generate()) do
    send_frame(socket, id, action, params)
    recv(socket)
  end

  defp recv(socket) do
    {:ok, line} = :gen_tcp.recv(socket, 0, 10_000)
    Jason.decode!(line)
  end

  defp read_all(path) do
    {:ok, socket} =
      :gen_tcp.connect(
        {:local, to_charlist(path)},
        0,
        [:binary, packet: :raw, active: false],
        1000
      )

    read_until_closed(socket, "")
  end

  defp read_until_closed(socket, acc) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, data} -> read_until_closed(socket, acc <> data)
      {:error, :closed} -> acc
    end
  end

  # Unix socket paths are limited to 108 bytes; ExUnit tmp_dir paths are longer.
  defp short_dir(_dir) do
    dir = Path.join(System.tmp_dir!(), "shp-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end

  defp current_uid do
    {:ok, %{uid: uid}} = File.stat("/proc/self")
    uid
  end

  defp await_phases(expected, attempts \\ 300)
  defp await_phases(_, 0), do: flunk("audit phases were not persisted")

  defp await_phases(expected, attempts) do
    case Journal.batch() do
      {:ok, events} when length(events) >= expected ->
        :ok

      _ ->
        Process.sleep(10)
        await_phases(expected, attempts - 1)
    end
  end
end

defmodule SecretHub.Agent.CredentialCoreFixture do
  @moduledoc false
  use GenServer

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: SecretHub.Agent.Connection)

  def set(fun), do: GenServer.call(SecretHub.Agent.Connection, {:set, fun})

  @impl true
  def init(opts), do: {:ok, %{owner: Keyword.fetch!(opts, :owner), reply: nil}}

  @impl true
  def handle_cast({:sync_uds_runtime, _server}, state), do: {:noreply, state}

  @impl true
  def handle_call({:set, fun}, _from, state), do: {:reply, :ok, %{state | reply: fun}}

  # Mirrors Connection: replies are produced concurrently, outside this process.
  def handle_call({:credential_request, operation, payload, _timeout}, from, state) do
    reply = state.reply

    Task.start(fn ->
      result =
        try do
          reply.(operation, payload)
        rescue
          error in ExUnit.AssertionError -> {:error, %{"reason" => inspect(error.message)}}
        end

      GenServer.reply(from, result)
    end)

    {:noreply, state}
  end

  def handle_call({:secret_write_request, operation, payload, timeout}, from, state),
    do: handle_call({:credential_request, "secret:" <> operation, payload, timeout}, from, state)
end
